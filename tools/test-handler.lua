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
end

local fake_httpc = {
  set_timeout = function() end,
  request_uri = function(_, url, opts)
    if url:find("/evaluation", 1, true) then
      T.captured = { url = url, headers = opts.headers, body = cjson.decode(opts.body) }
      return { status = 200, body = '{"decision":true,"token":"minted-token"}' }
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
  service = { request = {
    set_header = function() end,
    enable_buffering = function() T.buffering = true end,
  } },
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

print(string.format("\n%d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
