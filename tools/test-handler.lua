-- Offline classification tests for plugin/handler.lua.
--
-- Runs the real handler under the LuaJIT of the Kong AI Gateway image, with a
-- stubbed Kong PDK and a stubbed Reva, feeds A2A, MCP and OpenAI request shapes
-- through RevaRTG:access / :log, and checks what would be sent to Reva.
--
--   docker run --rm \
--     -v "$PWD/plugin/handler.lua:/h.lua:ro" -v "$PWD/tools/test-handler.lua:/t.lua:ro" \
--     --entrypoint /usr/local/openresty/luajit/bin/luajit \
--     kong/kong-ai-gateway:2.3.0-distroless /t.lua
--
-- Exits non-zero when any check fails.
package.cpath = "/usr/local/openresty/lualib/?.so;" .. package.cpath
local cjson = require "cjson.safe"

-- ── tiny base64 (std alphabet) for the JWT payload ────────────────────────
local B = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64dec(s)
  s = s:gsub("[^" .. B .. "=]", "")
  return (s:gsub(".", function(x)
    if x == "=" then return "" end
    local r, f = "", (B:find(x, 1, true) - 1)
    for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
    if #x ~= 8 then return "" end
    local c = 0
    for i = 1, 8 do c = c + (x:sub(i, i) == "1" and 2 ^ (8 - i) or 0) end
    return string.char(c)
  end))
end
local function b64enc(data)
  return ((data:gsub(".", function(x)
    local r, b = "", x:byte()
    for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and "1" or "0") end
    return r
  end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
    if #x < 6 then return "" end
    local c = 0
    for i = 1, 6 do c = c + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0) end
    return B:sub(c + 1, c + 1)
  end) .. ({ "", "==", "=" })[#data % 3 + 1])
end
local function jwt(sub)
  local function u(s) return (b64enc(s):gsub("+", "-"):gsub("/", "_"):gsub("=", "")) end
  return u('{"alg":"HS256"}') .. "." .. u('{"sub":"' .. sub .. '"}') .. ".c2ln"
end

-- ── per-test state the stubs read ─────────────────────────────────────────
local T = {}
local function reset(t)
  T = t
  T.captured, T.exit, T.buffering, T.invalidated = nil, nil, false, {}
  T.shared = {}
  T.store = {}
  T.calls = {}
end

local fake_httpc = {
  set_timeout = function() end,
  request_uri = function(_, url, opts)
    if url:find("/evaluation", 1, true) then
      T.captured = { url = url, headers = opts.headers, body = cjson.decode(opts.body) }
      T.calls[#T.calls + 1] = T.captured
      -- A Reva that turns away any request carrying context.
      if T.reject_context and T.captured.body["rtg/a2a"].context then
        return { status = 400, body = '{"decision":false,"context":{"reason":"invalid Cedar context"}}' }
      end
      return { status = 200, body = '{"decision":true,"token":"minted-token"}' }
    end
    if url:find("/trace/summarize", 1, true) then
      T.summarize = { url = url, headers = opts.headers, body = cjson.decode(opts.body) }
      return { status = 202, body = "{}" }
    end
    return { status = 202, body = "{}" }
  end,
}
package.loaded["resty.http"] = { new = function() return fake_httpc end }

_G.ngx = {
  null = cjson.null, var = { request_id = "req-1", remote_addr = "127.0.0.1" },
  now = function() return 1700000000.5 end, worker = { pid = function() return 1 end },
  decode_base64 = b64dec, log = function() end, NOTICE = 1, WARN = 2, ERR = 3,
}
local function noop() end
local lg = { debug = noop, info = noop, notice = noop, warn = noop, err = noop }
_G.kong = {
  log = lg,
  ctx = { shared = setmetatable({}, { __index = function(_, k) return T.shared[k] end,
                                       __newindex = function(_, k, v) T.shared[k] = v end }) },
  cache = {
    get = function(_, key, _, loader, arg)
      if T.store[key] == nil then T.store[key] = loader(arg) end
      return T.store[key]
    end,
    invalidate_local = function(_, key) T.invalidated[#T.invalidated + 1] = key; T.store[key] = nil end,
  },
  router = { get_service = function() return { name = "agent-svc", host = "agent.example.com", port = 443, protocol = "https" } end },
  request = {
    get_path = function() return T.path end,
    get_method = function() return T.method or "POST" end,
    get_header = function(n) return T.headers and T.headers[n:lower()] end,
    get_scheme = function() return "https" end,
    get_host = function() return "gw.example.com" end,
    get_body = function()
      local ct = (T.headers["content-type"] or ""):lower()
      if ct:find("application/json", 1, true) == 1 then
        local t = cjson.decode(T.raw)
        if t == nil then return nil, "invalid json body", "application/json" end
        return t, nil, "application/json"
      end
      return nil, "unsupported content type '" .. ct .. "'", ct
    end,
    get_raw_body = function() return T.raw end,
  },
  response = { exit = function(status, body) T.exit = { status = status, body = body } end },
  service = {
    request = {
      set_header = function() end,
      enable_buffering = function() T.buffering = true end,
    },
    response = {
      get_raw_body = function() return T.response_body end,
    },
  },
}

local handler = dofile("/h.lua")
local CONF = { reva_host = "api.example.com", auth_token = "t", ssl_verify = true, monitor_mode = false,
  fail_open = false, deny_status = 403, deny_message = "Blocked by Reva", jwt_user_claim = "sub",
  jwt_groups_claim = "groups", prompt_key = "content", session_key = "X-Reva-Session-Id",
  hop_ttl = 3600, forward_traceparent = true, debug = false }

local pass, fail = 0, 0
local function check(name, cond, detail)
  if cond then pass = pass + 1; print("  ok    " .. name)
  else fail = fail + 1; print("  FAIL  " .. name .. (detail and ("  -> " .. tostring(detail)) or "")) end
end

-- run one request; returns the evaluation body sent to Reva (or nil if none)
local function run(name, req)
  reset({ method = req.method or "POST", path = req.path, raw = req.raw,
          reject_context = req.reject_context,
          headers = { ["x-transaction-token"] = req.txn, ["x-reva-session-id"] = req.thread,
                      ["content-type"] = req.ct or "application/json",
                      authorization = "Bearer " .. jwt("alice"),
                      traceparent = req.traceparent or ("00-" .. string.rep("a", 31) .. tostring(#name % 10) .. "-bbbbbbbbbbbbbbbb-01") } })
  for k, v in pairs(req.extra or {}) do T.headers[k:lower()] = v end
  handler:access(CONF)
  local a = T.captured and T.captured.body and T.captured.body["rtg/a2a"]
  return a, T
end

-- run with conf.session_key set to `key` for the duration of the request
local function run_key(key, name, req)
  local saved = CONF.session_key
  CONF.session_key = key
  local a, t = run(name, req)
  CONF.session_key = saved
  return a, t
end

print("A2A JSON-RPC")
do
  local a, t = run_key("params.message.contextId", "v03-send", { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = "1", method = "message/send",
    params = { message = { kind = "message", messageId = "m", role = "user", contextId = "ctx-1",
      parts = { { kind = "text", text = "hello" } } } } }) })
  check("0.3 message/send evaluated as invokeAgent", a and a.action.name == "invokeAgent", a and a.action.name)
  check("  prompt from text part", a and a.transmission.content == "hello")
  check("  thread id from the configured path params.message.contextId", a and a.threadId == "ctx-1", a and a.threadId)
  check("  resource is the Service URL", a and a.resource.id == "https://agent.example.com")
  check("  non-streaming entry hop buffers the response", t.buffering == true)
  check("  summarize armed", t.shared.reva_summarize == true)

  a, t = run("v03-stream", { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = "1", method = "message/stream",
    params = { message = { contextId = "ctx-2", parts = { { kind = "text", text = "stream me" } } } } }) })
  check("0.3 message/stream evaluated", a and a.transmission.content == "stream me")
  check("  streamed entry hop is NOT buffered", t.buffering == false)
  check("  streamed entry hop is not summarized", t.shared.reva_summarize == nil)
  check("  reservation marked for release", type(t.shared.reva_stream_entry) == "string")
  handler:log(CONF)
  check("  log phase releases the reservation", #t.invalidated == 1, #t.invalidated)

  a, t = run("v10-send", { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = "SendMessage",
    params = { message = { messageId = "m", role = "ROLE_USER", parts = { { text = "one point oh" } } } } }) })
  check("1.0 SendMessage evaluated", a and a.transmission.content == "one point oh")
  check("  1.0 non-streaming buffers", t.buffering == true)

  a, t = run("v10-stream", { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = "SendStreamingMessage",
    params = { message = { messageId = "m", role = "ROLE_USER", parts = { { text = "stream 1.0" } } } } }) })
  check("1.0 SendStreamingMessage evaluated, not buffered", a and a.transmission.content == "stream 1.0" and t.buffering == false)

  a = run_key("params.contextId", "params-ctx", { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = "message/send",
    params = { contextId = "ctx-p", message = { parts = { { type = "text", text = "legacy" } } } } }) })
  check("text part tagged 'type' is read; params.contextId when configured", a and a.threadId == "ctx-p" and a.transmission.content == "legacy")

  a = run("data-part", { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = "message/send",
    params = { message = { parts = { { kind = "text", text = "see data" }, { kind = "data", data = { order = 7 } } } } } }) })
  check("data part sent as JSON text", a and a.transmission.content == 'see data\n{"order":7}', a and a.transmission.content)

  a = run("file-only", { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = "message/send",
    params = { message = { parts = { { kind = "file", file = { uri = "https://x/f.pdf", name = "f.pdf" } } } } } }) })
  check("file-only message still evaluated with placeholder prompt",
        a and a.transmission.content == "invokeAgent https://agent.example.com", a and a.transmission.content)

  a = run("big-data", { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = "message/send",
    params = { message = { parts = { { data = { blob = string.rep("z", 20000) } } } } } }) })
  check("oversized data part is capped", a and #a.transmission.content == 8192, a and #a.transmission.content)

  for _, m in ipairs({ "tasks/get", "tasks/cancel", "tasks/resubscribe", "GetTask", "CancelTask", "SubscribeToTask",
                       "agent/getAuthenticatedExtendedCard", "tasks/pushNotificationConfig/set" }) do
    a = run("other-" .. m, { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = m, params = { id = "t1" } }) })
    check("not evaluated: " .. m, a == nil)
  end
end

print("A2A REST binding")
do
  local msgbody = { message = { messageId = "m", role = "ROLE_USER", contextId = "ctx-r", parts = { { text = "rest hello" } } } }
  local a, t = run_key("message.contextId", "rest-send", { path = "/message:send", raw = cjson.encode(msgbody) })
  check("POST /message:send evaluated", a and a.action.name == "invokeAgent" and a.transmission.content == "rest hello")
  check("  thread id from the configured path message.contextId", a and a.threadId == "ctx-r", a and a.threadId)
  check("  buffers", t.buffering == true)

  a, t = run("rest-v1", { path = "/v1/message:stream", raw = cjson.encode(msgbody) })
  check("POST /v1/message:stream evaluated and not buffered", a and t.buffering == false and t.shared.reva_stream_entry ~= nil)

  a = run("rest-tenant", { path = "/acme/message:send", raw = cjson.encode(msgbody) })
  check("tenant-prefixed path evaluated", a ~= nil)

  a, t = run("rest-a2a-json", { path = "/message:send", ct = "application/a2a+json", raw = cjson.encode(msgbody) })
  check("application/a2a+json body parsed and evaluated", a and a.transmission.content == "rest hello", a)

  a = run("rest-a2a-json-charset", { path = "/message:stream", ct = "application/a2a+json; charset=utf-8", raw = cjson.encode(msgbody) })
  check("media type with parameters parsed", a ~= nil)

  a = run("rpc-a2a-json", { path = "/rpc", ct = "application/jsonrpc+json", raw = cjson.encode({ jsonrpc = "2.0", id = 1,
    method = "SendMessage", params = { message = { parts = { { text = "via +json" } } } } }) })
  check("JSON-RPC sent as application/jsonrpc+json evaluated", a and a.transmission.content == "via +json")

  a = run("rest-nobody", { path = "/message:send", raw = "" })
  check("send path with no usable body still evaluated (placeholder)", a and a.transmission.content == "invokeAgent https://agent.example.com", a and a.transmission.content)

  a = run("rest-get", { method = "GET", path = "/message:send", raw = cjson.encode(msgbody) })
  check("GET not evaluated", a == nil)

  a = run("rest-other-path", { path = "/tasks/t1:cancel", raw = cjson.encode(msgbody) })
  check("task cancel path not evaluated", a == nil)

  a = run("rest-non-a2a", { path = "/something/else", raw = cjson.encode(msgbody) })
  check("body with 'message' on an unrelated path not evaluated", a == nil)

  a = run("text-plain", { path = "/message:send", ct = "text/plain", raw = cjson.encode(msgbody) })
  check("non-JSON media type is not parsed (path still evaluates, with the placeholder prompt)",
        a and a.transmission.content == "invokeAgent https://agent.example.com" and a.threadId == nil,
        a and a.transmission.content)
end

print("Regression: MCP and OpenAI unchanged")
do
  local a = run("mcp", { path = "/mcp/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = "tools/call",
    params = { name = "open_ticket", arguments = { summary = "s" } } }) })
  check("tools/call -> invokeTool open_ticket", a and a.action.name == "invokeTool" and a.resource.id == "open_ticket")
  a = run("mcp-list", { path = "/mcp/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = "tools/list" }) })
  check("tools/list not evaluated", a == nil)
  a = run("llm", { path = "/llm/chat/completions", raw = cjson.encode({ model = "gpt-4o",
    messages = { { role = "system", content = "s" }, { role = "user", content = "hi there" } } }) })
  check("chat -> invokeModel gpt-4o, last user message", a and a.action.name == "invokeModel" and a.transmission.content == "hi there")
  check("  entry hop transmission.role is user",
        a and a.transmission.role == "user", a and a.transmission.role)
  a = run("llm-a2a-ct", { path = "/llm/x", ct = "application/a2a+json", raw = cjson.encode({ model = "m", messages = { { role = "user", content = "x" } } }) })
  check("OpenAI body under a +json media type is also read", a and a.action.name == "invokeModel")
end

print("Thread id lookup: the configured key only, header first, then the body")
do
  local function rpc(params)
    return cjson.encode({ jsonrpc = "2.0", id = 1, method = "message/send", params = params })
  end
  local function msg(extra)
    local m = { parts = { { text = "hi" } } }
    for k, v in pairs(extra or {}) do m[k] = v end
    return m
  end
  local function thread(key, req, name)
    local a = run_key(key, name or ("k-" .. key), req)
    return a and a.threadId
  end

  check("header is read",
        thread("X-Reva-Session-Id", { path = "/a2a/x", raw = rpc({ message = msg() }), thread = "H1" }) == "H1")
  check("header wins over the body",
        thread("X-Reva-Session-Id", { path = "/a2a/x", raw = rpc({ message = msg({ contextId = "B1" }) }), thread = "H2" }) == "H2")
  check("a custom header name",
        thread("X-Acme-Chat", { path = "/a2a/x", raw = rpc({ message = msg() }), extra = { ["x-acme-chat"] = "ACME1" } }) == "ACME1")
  check("  and the default header is then ignored",
        thread("X-Acme-Chat", { path = "/a2a/x", raw = rpc({ message = msg() }), thread = "IGNORED" }) == nil)

  check("no fallback to contextId when the key is a header name",
        thread("X-Reva-Session-Id", { path = "/a2a/x", raw = rpc({ message = msg({ contextId = "C1" }) }) }) == nil)
  check("no fallback to mcp-session-id",
        (function()
          reset({ method = "POST", path = "/a2a/x", raw = rpc({ message = msg() }),
                  headers = { ["content-type"] = "application/json", authorization = "Bearer " .. jwt("alice"),
                              ["mcp-session-id"] = "M1" } })
          handler:access(CONF)
          return T.captured.body["rtg/a2a"].threadId == nil
        end)())

  check("flat key is a top-level field only",
        thread("thread_id", { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = "message/send",
          thread_id = "TOP", params = { message = msg() } }) }) == "TOP")
  check("  and is NOT searched for in params",
        thread("thread_id", { path = "/a2a/x", raw = rpc({ thread_id = "P", message = msg() }) }) == nil)
  check("  nor in params.message.metadata",
        thread("thread_id", { path = "/a2a/x", raw = rpc({ message = msg({ metadata = { thread_id = "M" } }) }) }) == nil)

  check("dotted key: params.thread_id",
        thread("params.thread_id", { path = "/a2a/x", raw = rpc({ thread_id = "P2", message = msg() }) }) == "P2")
  check("dotted key: params.metadata.thread_id",
        thread("params.metadata.thread_id", { path = "/a2a/x", raw = rpc({ metadata = { thread_id = "P3" }, message = msg() }) }) == "P3")
  check("dotted key: params.message.metadata.thread_id",
        thread("params.message.metadata.thread_id", { path = "/a2a/x",
          raw = rpc({ message = msg({ metadata = { thread_id = "P4" } }) }) }) == "P4")
  check("dotted key, deeper: params.context.chat.id",
        thread("params.context.chat.id", { path = "/a2a/x", raw = rpc({ context = { chat = { id = "P5" } }, message = msg() }) }) == "P5")
  check("dotted key on the REST body: message.contextId",
        thread("message.contextId", { path = "/message:send", raw = cjson.encode({ message = msg({ contextId = "R1" }) }) }) == "R1")
  check("a top-level field whose name contains dots is accepted",
        thread("a.b", { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = "message/send",
          ["a.b"] = "LIT", params = { message = msg() } }) }) == "LIT")

  check("a number is accepted",
        thread("params.turn_chat", { path = "/a2a/x", raw = rpc({ turn_chat = 42, message = msg() }) }) == "42")
  check("an object at the path is ignored",
        thread("params.metadata", { path = "/a2a/x", raw = rpc({ metadata = { thread_id = "X" }, message = msg() }) }) == nil)
  check("a boolean at the path is ignored",
        thread("params.flag", { path = "/a2a/x", raw = rpc({ flag = true, message = msg() }) }) == nil)
  check("an empty string is ignored",
        thread("params.thread_id", { path = "/a2a/x", raw = rpc({ thread_id = "", message = msg() }) }) == nil)
  check("a path through a non-object is ignored, not an error",
        thread("params.thread_id.deeper", { path = "/a2a/x", raw = rpc({ thread_id = "str", message = msg() }) }) == nil)
  check("a path that does not exist finds nothing",
        thread("params.metadata.thread_id", { path = "/a2a/x", raw = rpc({ thread_id = "elsewhere", message = msg() }) }) == nil)

  check("works for an MCP tool call",
        (function()
          local a = run_key("params._meta.chat", "k-mcp", { path = "/mcp/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1,
            method = "tools/call", params = { name = "t", arguments = {}, _meta = { chat = "MC1" } } }) })
          return a and a.threadId == "MC1"
        end)())
  check("works for an OpenAI chat body",
        (function()
          local a = run_key("metadata.chat", "k-llm", { path = "/llm/x", raw = cjson.encode({ model = "m",
            messages = { { role = "user", content = "hi" } }, metadata = { chat = "L1" } }) })
          return a and a.threadId == "L1"
        end)())
end

print("Thread id: recorded on the first hop of a turn only")
do
  local function rpc(ctx)
    return cjson.encode({ jsonrpc = "2.0", id = 1, method = "message/send",
      params = { message = { contextId = ctx, parts = { { text = "hi" } } } } })
  end
  local tp = "00-" .. string.rep("c", 32) .. "-dddddddddddddddd-01"
  local function sent_header() return T.captured and T.captured.headers["X-Reva-Thread-Id"] end

  local a = run("th1", { path = "/a2a/x", raw = rpc("A"), thread = "A", traceparent = tp })
  check("first hop sends the thread id three ways",
        a and a.threadId == "A" and a.session and a.session.id == "A" and sent_header() == "A")
  check("  and arms summarize with it", T.shared.reva_thread_id == "A", T.shared.reva_thread_id)
  check("  entry hop transmission.role is user", a and a.transmission.role == "user", a and a.transmission.role)

  a = run("th2", { path = "/a2a/x", raw = rpc("B"), txn = "tok", traceparent = tp })
  check("later hop with a different contextId sends no thread id",
        a and a.threadId == nil and a.session == nil and sent_header() == nil)
  check("  nested hop transmission.role stays agent",
        a and a.transmission.role == "agent", a and a.transmission.role)

  a = run("th3", { path = "/a2a/x", raw = rpc("B"), thread = "A", txn = "tok", traceparent = tp })
  check("later hop forwarding the thread header sends none either",
        a and a.threadId == nil and a.session == nil and sent_header() == nil)

  a = run("th4", { path = "/a2a/x", raw = rpc("A"), thread = "A", txn = "tok", traceparent = tp })
  check("later hop with the same id sends none", a and a.threadId == nil and sent_header() == nil)
  check("  later hop still sends no subject or principal and forwards the token",
        a and a.subject == nil and a.principal == nil and T.captured.headers["X-Transaction-Token"] == "tok")

  a = run("th5", { path = "/mcp/x", raw = cjson.encode({ jsonrpc = "2.0", id = 1, method = "tools/call",
        params = { name = "open_ticket", arguments = { a = "b" } } }), thread = "A", txn = "tok", traceparent = tp })
  check("later tool hop sends no thread id", a and a.threadId == nil and sent_header() == nil)

  a = run("th6", { path = "/a2a/x", raw = rpc(nil), traceparent = tp })
  check("first hop with no thread id anywhere sends none", a and a.threadId == nil and sent_header() == nil)
end

print("Response-phase output extraction for /trace/summarize")
do
  local function arm_and_summarize(name, upstream)
    local a, t = run(name, { path = "/a2a/x", raw = cjson.encode({
      jsonrpc = "2.0", id = 1, method = "message/send",
      params = { message = { contextId = "ctx-out", parts = { { text = "ask" } } } },
    }), thread = "thread-out" })
    check(name .. ": entry hop armed", a and t.shared.reva_summarize == true)
    T.response_body = upstream
    T.summarize = nil
    handler:response(CONF)
    return T.summarize and T.summarize.body
  end

  local body = arm_and_summarize("openai", cjson.encode({
    choices = { { message = { role = "assistant", content = "Lab results for MRN-1002: WBC normal." } } },
  }))
  check("OpenAI chat.completions content is posted as output",
        body and body.output == "Lab results for MRN-1002: WBC normal.", body and body.output)

  body = arm_and_summarize("a2a-rpc-message", cjson.encode({
    jsonrpc = "2.0", id = 1,
    result = { role = "agent", parts = { { kind = "text", text = "Patient labs look normal." } } },
  }))
  check("A2A JSON-RPC Message result.parts is posted as output",
        body and body.output == "Patient labs look normal.", body and body.output)

  body = arm_and_summarize("a2a-rpc-task", cjson.encode({
    jsonrpc = "2.0", id = 1,
    result = {
      id = "task-1",
      status = {
        state = "completed",
        message = { role = "agent", parts = { { text = "Hemoglobin 13.2 g/dL." } } },
      },
    },
  }))
  check("A2A JSON-RPC Task status.message is posted as output",
        body and body.output == "Hemoglobin 13.2 g/dL.", body and body.output)

  body = arm_and_summarize("a2a-rest-message", cjson.encode({
    role = "agent", parts = { { text = "REST answer: creatinine is 0.9." } },
  }))
  check("A2A REST Message body is posted as output",
        body and body.output == "REST answer: creatinine is 0.9.", body and body.output)

  body = arm_and_summarize("a2a-rest-task", cjson.encode({
    id = "task-2",
    artifacts = { { parts = { { text = "Artifact: all labs within range." } } } },
  }))
  check("A2A REST Task artifacts are posted as output",
        body and body.output == "Artifact: all labs within range.", body and body.output)

  body = arm_and_summarize("plain-text", "Plain agent reply without JSON.")
  check("plain-text upstream body is posted as output",
        body and body.output == "Plain agent reply without JSON.", body and body.output)

  body = arm_and_summarize("empty-body", nil)
  check("empty upstream body still summarizes but with no output field",
        body and body.trace_id ~= nil and body.output == nil, body and body.output)
end

print("Context variables")
do
  -- true when `ctx` holds exactly the pairs in `want` (list values compared as JSON)
  local function exactly(ctx, want)
    if type(ctx) ~= "table" then return false end
    for k, v in pairs(want) do
      if type(v) == "table" then
        if cjson.encode(ctx[k]) ~= cjson.encode(v) then return false end
      elseif ctx[k] ~= v then
        return false
      end
    end
    for k in pairs(ctx) do
      if want[k] == nil then return false end
    end
    return true
  end
  local function show(ctx)
    return ctx and cjson.encode(ctx) or "nil"
  end
  local function a2a_request(params)
    return { path = "/a2a/x", raw = cjson.encode({ jsonrpc = "2.0", id = "1", method = "message/send", params = params }) }
  end

  -- A2A: the metadata of the request, the message and every part
  local a = run("ctx-sample", { path = "/a2a/x", raw = [==[{
    "jsonrpc": "2.0", "id": "req-98765", "method": "message/send",
    "params": {
      "message": {
        "kind": "message", "messageId": "msg-001", "contextId": "ctx-session-123",
        "taskId": "task-abc-789", "role": "user",
        "parts": [ { "kind": "text", "text": "Generate the Q3 financial summary report.",
                     "metadata": { "sourceLanguage": "en-US", "priority": "high" } } ],
        "metadata": { "clientTimestamp": "2026-11-18T12:30:00Z", "originatingAgent": "orchestrator-v2" }
      },
      "configuration": { "acceptedOutputModes": ["text/plain", "application/json"], "historyLength": 5 },
      "metadata": { "session_id": "my-session-123", "trace_id": "otel-trace-456", "tenant_id": "org-789" }
    } }]==] })
  check("A2A: request, message and part metadata all become context",
        a and exactly(a.context, {
          clientTimestamp = "2026-11-18T12:30:00Z", originatingAgent = "orchestrator-v2",
          priority = "high", sourceLanguage = "en-US",
          session_id = "my-session-123", trace_id = "otel-trace-456", tenant_id = "org-789" }),
        a and show(a.context))
  check("  only metadata is read: contextId, taskId and configuration are not",
        a and a.context.contextId == nil and a.context.taskId == nil and a.context.historyLength == nil)

  -- A2A: what is kept, flattened, overridden and left out
  a = run("ctx-a2a-rules", a2a_request({
    metadata = { channel = "web", riskLevel = "medium" },
    message = {
      parts = {
        { text = "refund", metadata = { priority = "high" } },
        { text = "again", metadata = { priority = "low" } },
      },
      metadata = {
        riskLevel = "high", department = "finance", amount = 250, approved = false,
        tags = { "refund", "vip" }, customer = { tier = "gold", region = "EU" },
        version = "1.2.3",
        discount = 0.15, note = cjson.null, apiKey = "abc123", ["x-api-key"] = "abc",
        subject = "s", history = "h", on_behalf_of = "u",
        jwtish = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln", bearer = "Bearer abc",
        dotted = "10.20.30", big = 123456789012345,
        emptyObject = {}, emptyList = cjson.empty_array, mixed = { 1, "a" }, objects = { { a = 1 } },
        nested = { password = "p", ok = "fine" },
      },
    },
  }))
  check("A2A: valid pairs are kept, nested objects flattened, a later source overrides",
        a and exactly(a.context, {
          channel = "web", riskLevel = "high", department = "finance", amount = 250, approved = false,
          tags = { "refund", "vip" }, ["customer.tier"] = "gold", ["customer.region"] = "EU",
          priority = "low", version = "1.2.3", ["nested.ok"] = "fine" }),
        a and show(a.context))
  check("  decimals, null, objects in lists, mixed and empty lists, and 15-digit numbers are left out",
        a and a.context.discount == nil and a.context.note == nil and a.context.objects == nil
          and a.context.mixed == nil and a.context.emptyList == nil and a.context.big == nil)
  check("  credential names, reserved names and credential-shaped values are left out",
        a and a.context.apiKey == nil and a.context["x-api-key"] == nil and a.context.subject == nil
          and a.context.history == nil and a.context.on_behalf_of == nil and a.context.jwtish == nil
          and a.context.bearer == nil and a.context.dotted == nil and a.context["nested.password"] == nil)

  a = run("ctx-none", a2a_request({ message = { parts = { { text = "no metadata" } } } }))
  check("no metadata: no context is sent", a and a.context == nil, a and show(a.context))

  a = run("ctx-rest", { path = "/a2a/v1/message:send", raw = cjson.encode({
    metadata = { r = 3 },
    message = { parts = { { text = "hi", metadata = { p = 1 } } }, metadata = { m = 2 } } }) })
  check("A2A HTTP+JSON: body, message and part metadata", a and exactly(a.context, { r = 3, m = 2, p = 1 }),
        a and show(a.context))

  -- MCP: everything in params, arguments and _meta under their own names
  a = run("ctx-mcp", { path = "/mcp/x", txn = "prior-token", raw = cjson.encode({
    jsonrpc = "2.0", id = 7, method = "tools/call",
    params = {
      name = "open_ticket",
      arguments = { title = "VPN down", priority = "high", assignee = "bob", estimate_hours = 4,
                    filter = { status = "open" }, progressToken = "from-arguments" },
      _meta = { progressToken = "p-1", trace = "t-9" },
      task = { ttl = 60000 },
    } }) })
  check("MCP: arguments and _meta are sent under their own names; arguments win a clash",
        a and exactly(a.context, {
          title = "VPN down", priority = "high", assignee = "bob", estimate_hours = 4,
          ["filter.status"] = "open", progressToken = "from-arguments", trace = "t-9",
          ["task.ttl"] = 60000 }), a and show(a.context))
  check("  the tool name is not repeated and nothing is prefixed with _meta",
        a and a.context.name == nil and a.context["_meta.progressToken"] == nil)
  check("  a later hop sends its own context too",
        a and a.subject == nil and a.principal == nil and a.context ~= nil)

  a = run("ctx-mcp-p1", { path = "/mcp/x", raw = cjson.encode({
    jsonrpc = "2.0", id = 7, method = "tools/call",
    params = { name = "t", _meta = { progressToken = "p-1" } } }) })
  check("MCP: _meta.progressToken is sent as progressToken", a and exactly(a.context, { progressToken = "p-1" }),
        a and show(a.context))

  -- LLM: metadata and the call settings
  a = run("ctx-llm", { path = "/llm/x", raw = cjson.encode({
    model = "gpt-4o",
    messages = { { role = "system", content = "be brief" }, { role = "user", content = "Summarise ticket 8841" } },
    temperature = 0.2, max_tokens = 500, stream = false, user = "alice", tool_choice = "auto",
    stop = { "END" }, response_format = { type = "json_object" },
    metadata = { department = "finance", env = "prod" },
    tools = { { type = "function", ["function"] = { name = "lookup_ticket" } } } }) })
  check("LLM: metadata and call settings are sent; decimals, model, messages and tools are not",
        a and exactly(a.context, {
          department = "finance", env = "prod", max_tokens = 500, stream = false, user = "alice",
          tool_choice = "auto", stop = { "END" }, ["response_format.type"] = "json_object" }),
        a and show(a.context))

  a = run("ctx-llm-bare", { path = "/llm/x", raw = cjson.encode({
    model = "gpt-4o", messages = { { role = "user", content = "hi" } } }) })
  check("LLM with nothing but model and messages sends no context", a and a.context == nil, a and show(a.context))

  -- size: whole pairs, in name order, up to 512 bytes
  local many = {}
  for i = 1, 40 do many[string.format("k%02d", i)] = string.rep("v", 20) end
  a = run("ctx-size", a2a_request({ message = { parts = { { text = "x" } }, metadata = many } }))
  local kept, size, last = 0, 2, nil
  for k, v in pairs(a and a.context or {}) do
    kept = kept + 1
    size = size + #k + 2 + 1 + #v + 2 + 1
    if not last or k > last then last = k end
  end
  size = size - 1
  check("size: only the pairs that fit in 512 bytes are sent, the first by name",
        kept == 17 and size <= 512 and last == "k17", kept .. " pairs, " .. size .. " bytes, last " .. tostring(last))

  a = run("ctx-fit", a2a_request({ message = { parts = { { text = "x" } }, metadata = {
    a = string.rep("x", 200), b = string.rep("x", 200), c = string.rep("x", 200), d = "small" } } }))
  check("size: a pair that does not fit is skipped, a later smaller one is still kept",
        a and a.context.a and a.context.b and a.context.c == nil and a.context.d == "small", a and show(a.context))

  a = run("ctx-escapes", a2a_request({ message = { parts = { { text = "x" } }, metadata = {
    quotes = string.rep('"', 300), plain = string.rep("x", 300) } } }))
  check("size: escaped characters are counted as Reva counts them",
        a and a.context.plain ~= nil and a.context.quotes == nil, a and show(a.context))

  -- safety net: Reva turns the request away because of its context
  local t
  a, t = run("ctx-refused", { path = "/a2a/x", reject_context = true, raw = cjson.encode({
    jsonrpc = "2.0", id = "1", method = "message/send",
    params = { message = { parts = { { text = "hi" } }, metadata = { channel = "web" } } } }) })
  check("a request Reva refuses because of its context is evaluated again without it",
        #t.calls == 2 and t.calls[1].body["rtg/a2a"].context ~= nil and t.calls[2].body["rtg/a2a"].context == nil
          and t.exit == nil, #t.calls .. " calls")
end

print(string.format("\n%d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
