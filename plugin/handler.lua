-- kong/plugins/reva-ai-runtime-authorization/handler.lua
--
-- Reva Trust Guardian authorization for Kong Gateway.
--
-- One access-phase handler: read the inbound agent call, translate it into a
-- Reva evaluation request, ask the RTG, and either let the request proxy or
-- terminate it. Everything happens in `access` because the plugin makes the
-- HTTP call to Reva itself rather than delegating it to another plugin.

local http  = require "resty.http"
local cjson = require "cjson.safe"

local kong        = kong
local ngx         = ngx
local type        = type
local ipairs      = ipairs
local tostring    = tostring
local setmetatable = setmetatable
local fmt         = string.format
local concat      = table.concat

local EMPTY_ARRAY = cjson.empty_array
local ARRAY_MT    = cjson.array_mt
local RTG_EVAL_PATH             = "/pdp/v2/ai/evaluation"
local RTG_TIMEOUT_MS            = 5000
local RTG_RETRIES               = 2
local RTG_KEEPALIVE_TIMEOUT     = 60000
local RTG_KEEPALIVE_POOL_SIZE   = 30


local RevaRTG = {
  -- Runs after the bundled authentication plugins (key-auth 1250, jwt 1450,
  -- oauth2 1400) so identity headers are already settled, and before the
  -- transformer plugins (request-transformer 801) so we evaluate the request
  -- as the client actually sent it.
  PRIORITY = 1000,
  VERSION  = "0.1.0",
}


-- ── small helpers ───────────────────────────────────────────────────────────

local seeded = false

local function hex(n)
  local t = {}
  for i = 1, n do
    t[i] = fmt("%02x", math.random(0, 255))
  end
  return concat(t)
end


-- W3C traceparent: version-traceid-spanid-flags
local function mint_traceparent()
  if not seeded then
    math.randomseed(ngx.now() * 1000 + ngx.worker.pid())
    seeded = true
  end
  return "00-" .. hex(16) .. "-" .. hex(8) .. "-01"
end


local function iso_now()
  -- ngx.utctime, not os.date: streamed plugins run in the Lua sandbox, which
  -- does not allow the os library.
  return (ngx.utctime():gsub(" ", "T")) .. "Z"
end


-- kong.request.get_id() and kong.client.get_forwarded_ip() are not present in
-- every Kong version this plugin may be installed on, so both are probed
-- rather than called blind.
local function kong_request_id()
  if kong.request.get_id then
    local id = kong.request.get_id()
    if id then
      return id
    end
  end
  return ngx.var.request_id or ""
end


local function kong_client_ip()
  if kong.client.get_forwarded_ip then
    local ip = kong.client.get_forwarded_ip()
    if ip then
      return ip
    end
  end
  return ngx.var.remote_addr or ""
end


local function truncate(s, limit)
  if limit and limit > 0 and #s > limit then
    return s:sub(1, limit)
  end
  return s
end


-- Encode an array so that an empty one serializes as [] and not {}.
local function as_array(items)
  if #items == 0 then
    return EMPTY_ARRAY
  end
  -- setmetatable is nil under Kong's Lua sandbox (untrusted_lua=sandbox); when
  -- that's the case, skip it and accept cjson may render a single-element
  -- result as {} instead of [] rather than crash the request.
  if ARRAY_MT and setmetatable then
    setmetatable(items, ARRAY_MT)
  end
  return items
end


-- Walk a dotted path through a table. The path is plugin config
-- (a2a_history_path and friends), not request input, so this is a lookup:
-- "params.history" → root.params.history. Missing segments yield nil.
local function get_at_path(root, path)
  if type(root) ~= "table" or type(path) ~= "string" or path == "" then
    return nil
  end
  local cur = root
  for segment in path:gmatch("[^.]+") do
    if type(cur) ~= "table" then
      return nil
    end
    cur = cur[segment]
  end
  return cur
end


-- Resolve the shared dictionary used for hop chains and session history.
--
-- It must NOT be one of Kong's own caches. kong_db_cache is wiped on every
-- config reload, so a Konnect config change silently erases a chat mid
-- conversation: the next message reappears as turn 1 with a fresh startedAt,
-- which reads as the feature not working rather than as state loss.
--
-- Falls back rather than failing, because a gateway that stops authorizing is
-- worse than one that forgets history - but says so, once it matters.
local warned_fallback = false
local function reva_shm(conf)
  -- Streamed plugins under untrusted_lua=lax/strict do not get ngx.shared.
  -- Indexing it is a 500; hop state just goes missing until the DP uses
  -- sandbox + KONG_NGINX_HTTP_LUA_SHARED_DICT.
  local shared = ngx and ngx.shared
  if not shared then
    return nil
  end
  local shm = shared[conf.hop_storage_dict]
  if shm then
    return shm
  end
  shm = shared["kong_db_cache"]
  if shm then
    if not warned_fallback then
      warned_fallback = true
      kong.log.warn("[reva-ai-runtime-authorization] shared dict '", conf.hop_storage_dict,
                    "' not declared; falling back to kong_db_cache, which Kong ",
                    "flushes on every config reload - hop chains and chat ",
                    "history will be lost when config changes. Declare it with ",
                    "KONG_NGINX_HTTP_LUA_SHARED_DICT='", conf.hop_storage_dict, " 64m'")
    end
    return shm
  end
  return nil
end


-- Who is calling, and can we believe them.
--
-- A header is an assertion, not a credential: anyone who can reach the gateway
-- can set X-Reva-Agent-Id to a privileged agent and inherit its policy. The
-- Consumer is different - an authentication plugin resolved it from a real
-- credential before this plugin ran (key-auth is priority 1250, jwt 1450, this
-- is 1000), so it cannot be forged by the caller.
--
-- Returns the agent id, and the source it came from for logging.
local function resolve_agent(conf)
  local src = conf.identity_source or "header"

  if src == "consumer" or src == "consumer_then_header" then
    local consumer = kong.client.get_consumer and kong.client.get_consumer()
    if consumer then
      local id = consumer[conf.consumer_id_field or "username"]
      if id and id ~= "" then
        return tostring(id), "consumer"
      end
    end
    if src == "consumer" then
      -- Asked for the trustworthy source and there isn't one. Falling back to
      -- the header here would quietly undo the whole point of the setting.
      return "", "consumer-missing"
    end
  end

  return kong.request.get_header(conf.agent_header) or "", "header"
end


-- JWT payload without verifying the signature. Kong jwt / openid-connect in
-- front of this plugin is assumed to have already authenticated the token.
-- resty.jwt is not used: streamed custom plugins cannot take extra requires.
local function b64url_decode(s)
  if type(s) ~= "string" or s == "" then
    return nil
  end
  s = s:gsub("-", "+"):gsub("_", "/")
  local pad = #s % 4
  if pad > 0 then
    s = s .. string.rep("=", 4 - pad)
  end
  return ngx.decode_base64(s)
end


local function jwt_payload(token)
  if type(token) ~= "string" then
    return nil
  end
  local payload = token:match("^[^%.]+%.([^%.]+)%.[^%.]+$")
  if not payload then
    return nil
  end
  local raw = b64url_decode(payload)
  if not raw then
    return nil
  end
  local ok, obj = pcall(cjson.decode, raw)
  if ok and type(obj) == "table" then
    return obj
  end
  return nil
end


local function bearer_token()
  local h = kong.request.get_header("authorization") or ""
  local token = h:match("^[Bb]earer%s+(.+)$")
  if not token then
    return nil
  end
  return token:gsub("^%s+", ""):gsub("%s+$", "")
end


local function claim_value(payload, claim)
  if type(payload) ~= "table" or type(claim) ~= "string" or claim == "" then
    return nil
  end
  local v = payload[claim]
  if v == nil then
    v = get_at_path(payload, claim)
  end
  if type(v) == "string" or type(v) == "number" then
    local s = tostring(v)
    if s ~= "" then
      return s
    end
  end
  return nil
end


-- Array-valued claim, e.g. Cognito's "cognito:groups": ["AppAdmin", ...].
-- Non-string entries are dropped rather than failing the whole claim, since a
-- group list a policy doesn't recognize is not a reason to lose the rest.
local function claim_array(payload, claim)
  if type(payload) ~= "table" or type(claim) ~= "string" or claim == "" then
    return nil
  end
  local v = payload[claim]
  if v == nil then
    v = get_at_path(payload, claim)
  end
  if type(v) ~= "table" then
    return nil
  end
  local out = {}
  for _, item in ipairs(v) do
    if type(item) == "string" and item ~= "" then
      out[#out + 1] = item
    end
  end
  if #out == 0 then
    return nil
  end
  return out
end


-- User id for principal (and subject when authorize_agent is false), plus
-- the user's groups if the token carries them (conf.jwt_groups_claim).
-- A three-segment Bearer value is treated as a JWT; the configured user
-- claim is required. No fallback: user identity comes only from the JWT.
local function resolve_user(conf)
  local token = bearer_token()
  if not token then
    return "", "missing Authorization bearer token"
  end
  local payload = jwt_payload(token)
  if not payload then
    return "", "Authorization bearer token is not a JWT"
  end
  local id = claim_value(payload, conf.jwt_user_claim or "sub")
  if not id then
    return "", "jwt claim '" .. tostring(conf.jwt_user_claim or "sub") .. "' is empty"
  end
  return id, nil, claim_array(payload, conf.jwt_groups_claim)
end


-- ── request interpretation ──────────────────────────────────────────────────

-- Index of the last user-authored string in an OpenAI-style messages array.
-- That message is the one under evaluation: it becomes transmission.content.
-- OpenAI allows `content` to be either a string or an array of parts, where a
-- part is { type = "text", text = "..." } alongside images and audio. Reduce
-- both to the sentence being evaluated.
--
-- This is not cosmetic. Skipping array content meant the newest message was
-- passed over and an EARLIER one was evaluated in its place, so an instruction
-- sent as multimodal content was never the thing a policy saw.
local function message_text(m)
  if type(m) ~= "table" then
    return nil
  end
  local c = m.content
  if type(c) == "string" then
    return c
  end
  if type(c) ~= "table" then
    return nil
  end
  local txt = {}
  for _, part in ipairs(c) do
    if type(part) == "table" and type(part.text) == "string" and part.text ~= "" then
      txt[#txt + 1] = part.text
    end
  end
  if #txt == 0 then
    return nil
  end
  return concat(txt, "\n")
end


local function last_user_index(messages)
  local idx = nil
  if type(messages) ~= "table" then
    return nil
  end
  for i, m in ipairs(messages) do
    if type(m) == "table" and m.role == "user" then
      local txt = message_text(m)
      if txt and txt ~= "" then
        idx = i
      end
    end
  end
  return idx
end


-- Non-system {role, content} turns, from either an OpenAI messages array or
-- an A2A-shaped history array.
-- `stop_before`, when given, excludes that index and everything after it.
local function to_history(arr, stop_before)
  local items = {}
  if type(arr) ~= "table" then
    return as_array(items)
  end

  for i, m in ipairs(arr) do
    if stop_before and i >= stop_before then
      break
    end
    if type(m) == "table" and m.content ~= nil then
      local role = m.role or "user"
      -- Array content is flattened rather than dropped; a multimodal turn is
      -- still part of the conversation.
      local content = message_text(m)
      if role ~= "system" and content then
        local item = {
          role    = tostring(role),
          content = content,
        }
        -- A2A gives every message a stable id. chatHistory is exempt from
        -- managed-Cedar validation, so the extra key is carried through rather
        -- than normalized away: it lets a policy refer to a specific message
        -- instead of matching on its text.
        if m.messageId ~= nil and m.messageId ~= "" then
          item.messageId = tostring(m.messageId)
        end
        items[#items + 1] = item
      end
    end
  end

  return as_array(items)
end


-- Pair caller {role, content} history into session.messages request/response
-- turns. A trailing unpaired user message is the current prompt, not history.
local function utterance(role, content, ts)
  return {
    role        = role,
    contentType = "text/plain",
    content     = content,
    timestamp   = ts,
  }
end


local function history_to_session_messages(arr, now, cap)
  local out = {}
  local first_ts = nil
  if type(arr) ~= "table" then
    return out, first_ts
  end
  local pending
  for _, m in ipairs(arr) do
    if type(m) == "table" then
      local role = m.role or "user"
      local content = message_text(m)
      if role ~= "system" and content and content ~= "" then
        local ts = (type(m.timestamp) == "string" and m.timestamp ~= "" and m.timestamp) or now
        if role == "user" then
          pending = { content = content, timestamp = ts }
          if not first_ts then
            first_ts = ts
          end
        elseif (role == "assistant" or role == "agent") and pending then
          out[#out + 1] = {
            turn     = #out + 1,
            request  = utterance("user", pending.content, pending.timestamp),
            response = utterance("assistant", content, ts),
          }
          pending = nil
        end
      end
    end
  end
  cap = cap or 10
  while #out > cap do
    table.remove(out, 1)
  end
  for i, m in ipairs(out) do
    m.turn = i
  end
  return out, first_ts
end


local function a2a_parts_text(value)
  if type(value) == "string" then
    return value
  end
  if type(value) ~= "table" then
    return ""
  end
  local t = {}
  for _, p in ipairs(value) do
    if type(p) == "table" and type(p.text) == "string" then
      t[#t + 1] = p.text
    end
  end
  return concat(t, "\n")
end


-- Flatten A2A-shaped history entries (role + parts) to the role/content
-- pairs to_history() already bounds. Callers that store {role, content}
-- at the same path skip this helper.
local function a2a_messages_to_history(arr)
  if type(arr) ~= "table" then
    return nil
  end
  local out = {}
  for _, m in ipairs(arr) do
    if type(m) == "table" and type(m.parts) == "table" then
      local text = a2a_parts_text(m.parts)
      if text ~= "" then
        out[#out + 1] = {
          role      = m.role or "user",
          content   = text,
          -- carried through so to_history can keep it on the entry
          messageId = m.messageId,
        }
      end
    end
  end
  return out
end


local function starts_with(s, prefix)
  return prefix ~= "" and s:sub(1, #prefix) == prefix
end


local function kong_service()
  if kong.router and kong.router.get_service then
    return kong.router.get_service()
  end
  return nil
end


-- Inbound URL used only when no Kong Service is bound (misconfig).
local function inbound_url()
  local scheme = kong.request.get_scheme and kong.request.get_scheme() or "http"
  local host   = kong.request.get_host and kong.request.get_host() or ""
  return scheme .. "://" .. host
end


-- Agent resource.id: the Kong Service this route proxies to.
-- protocol://host[:port], always — never a path. Two agents are two Kong
-- Services on two hosts in this model, so the host alone already identifies
-- the resource; mixing in the request path just fragments one agent's id
-- across however many route paths happen to reach it.
local function kong_service_url()
  local svc = kong_service()
  if not svc or type(svc.host) ~= "string" or svc.host == "" then
    kong.log.warn("[reva-ai-runtime-authorization] no Kong Service bound; Agent resource id falls back to the inbound URL")
    return inbound_url()
  end
  local scheme = svc.protocol or "http"
  local host   = svc.host
  local port   = tonumber(svc.port)
  local default_port = (scheme == "https" or scheme == "grpcs") and 443 or 80
  if port and port ~= default_port then
    host = host .. ":" .. tostring(port)
  end
  return scheme .. "://" .. host
end


-- MCP sniff uses the Service host, not the gateway Host: a shared tunnel
-- would collapse every tool onto one id.
local function kong_service_host()
  local svc = kong_service()
  if svc and type(svc.host) == "string" and svc.host ~= "" then
    return svc.host
  end
  return (kong.request.get_host and kong.request.get_host()) or "unknown-server"
end


local function classify_llm(body)
  local cur = last_user_index(body.messages)
  local prompt = ""
  if cur then
    prompt = message_text(body.messages[cur]) or ""
  end
  -- `or` does not catch an empty string: in Lua "" is truthy, so a caller
  -- that sends {"model": ""} - which an unset LLM_MODEL env var produces -
  -- would be reported to the Reva Trust Guardian as Model::"", and the
  -- decision log shows a bare "Model::" that no policy can match.
  local model = body.model
  if type(model) ~= "string" or model == "" then
    model = "unknown-model"
  end

  return {
    action     = "invokeModel",
    role       = "agent",
    res_type   = "Model",
    res_id     = model,
    prompt     = prompt,
    history    = to_history(body.messages, cur),
  }
end


local function classify_mcp(body, http_method, server)
  if http_method ~= "POST" then
    return nil, "not an MCP POST"
  end
  if (body.method or "") ~= "tools/call" then
    return nil, "MCP method is not tools/call"
  end

  if type(server) ~= "string" or server == "" then
    server = "unknown-server"
  end

  local tool = body.params and body.params.name
  if type(tool) ~= "string" or tool == "" then
    tool = "unknown-tool"
  end

  local prompt = ""
  local args = body.params and body.params.arguments
  if type(args) == "table" then
    local a = {}
    for k, v in pairs(args) do
      a[#a + 1] = tostring(k) .. "=" .. tostring(v)
    end
    prompt = concat(a, ", ")
  end

  -- A tool call carries no conversation of its own, so the caller has to
  -- supply it. MCP's own `_meta` is the standard slot for request metadata;
  -- `metadata` is accepted too, because that is what A2A callers already use
  -- and having two spellings is cheaper than making every client pick one.
  -- Without this a tool call reaches the RTG looking like the first thing
  -- that ever happened, which is precisely the call a policy most needs
  -- context for: "summarise this invoice" then "refund it" is only alarming
  -- read together.
  local meta = (body.params and (body.params._meta or body.params.metadata)) or nil
  local history = EMPTY_ARRAY
  if type(meta) == "table" and meta.chatHistory then
    history = to_history(meta.chatHistory)
  end

  return {
    action       = "invokeTool",
    role         = "agent",
    input_values = type(args) == "table" and next(args) ~= nil and args or nil,
    res_type     = "Tool",
    res_id       = server .. "/" .. tool,
    prompt       = prompt,
    history      = history,
  }
end


local function classify_a2a(conf, body, http_method)
  if http_method ~= "POST" then
    return nil, "not an A2A POST"
  end
  if (body.method or "") ~= "message/send" then
    return nil, "A2A method is not message/send"
  end

  local msg = (body.params and body.params.message) or {}

  -- Current utterance. Default path is the A2A spec field
  -- params.message.parts; operators can point this at another slot.
  local prompt = a2a_parts_text(get_at_path(body, conf.a2a_content_path))

  -- History and routing are Reva extensions, not A2A fields. The paths are
  -- configurable so a caller that stores them elsewhere can point at them.
  -- Accept either A2A-shaped messages (role + parts) or {role, content}.
  local history = EMPTY_ARRAY
  local raw = (type(msg.metadata) == "table" and msg.metadata.chatHistory) or nil
  if raw == nil then
    raw = get_at_path(body, conf.a2a_history_path)
  end
  local flat = a2a_messages_to_history(raw)
  if flat and #flat > 0 then
    history = to_history(flat)
  elseif type(raw) == "table" then
    history = to_history(raw)
  end

  return {
    action     = "invokeAgent",
    role       = "agent",
    res_type   = "Agent",
    res_id     = kong_service_url(),
    prompt     = prompt,
    history    = history,
    routing    = get_at_path(body, conf.a2a_routing_path),
    -- The chat id. `params.contextId` is where the A2A spec puts it;
    -- `message.contextId` is accepted as well. Without one, every message
    -- looks like a brand new conversation.
    session_id = (body.params and body.params.contextId ~= nil
                  and body.params.contextId ~= "" and body.params.contextId)
              or (msg.contextId ~= nil and msg.contextId ~= "" and msg.contextId)
              or nil,
  }
end


-- JSON-RPC is more specific than a coincidental `messages` key.
local function sniff_kind(body)
  if type(body) ~= "table" then
    return nil
  end
  if body.jsonrpc ~= nil then
    if body.method == "tools/call" then
      return "mcp"
    end
    if body.method == "message/send" then
      return "a2a"
    end
    return nil
  end
  if type(body.messages) == "table" and body.messages[1] ~= nil then
    return "llm"
  end
  return nil
end


-- Work out what the caller is trying to do. Returns a descriptor table, or
-- nil plus a reason when this request is not ours to evaluate.
--
-- Path prefixes, when enabled, are a type hint. If they do not match, or
-- they are off, the body is sniffed: JSON-RPC tools/call, JSON-RPC
-- message/send, then an OpenAI messages array.
local function classify(conf, path, method, body)
  local pid = conf.path_identification or {}
  if pid.enabled ~= false then
    if starts_with(path, pid.llm_path_prefix or "/llm") then
      return classify_llm(body)
    end
    if starts_with(path, pid.mcp_path_prefix or "/mcp/") then
      local prefix = pid.mcp_path_prefix or "/mcp/"
      local server = path:sub(#prefix + 1):match("^([^/]+)")
      return classify_mcp(body, method, server)
    end
    if starts_with(path, pid.a2a_path_prefix or "/a2a/") then
      return classify_a2a(conf, body, method)
    end
  end

  local kind = sniff_kind(body)
  if kind == "mcp" then
    return classify_mcp(body, method, kong_service_host())
  end
  if kind == "a2a" then
    return classify_a2a(conf, body, method)
  end
  if kind == "llm" then
    return classify_llm(body)
  end

  return nil, "payload is not LLM, MCP tools/call, or A2A message/send"
end


-- ── hop chain ───────────────────────────────────────────────────────────────

-- Record this call against the traceparent and return the hops that came
-- BEFORE it. The current call is already fully described by subject / action /
-- resource, so repeating it inside context.hops would double-report it. The
-- first call on a fresh traceparent therefore sends hops: [].
-- Returns the prior chain plus its length. The length comes back separately
-- because an empty chain is a cjson sentinel, which has no `#`.
local function turn_key(traceparent)
  return "reva:turn:" .. traceparent
end


-- Everything recorded against this traceparent so far. `hops` is the path
-- taken; `conversation` is what was said on each of those hops. The RTG treats
-- a difference in their lengths as a defect, so they are always read and
-- written together.
local function read_turn(conf, traceparent)
  local empty = { hops = {}, conversation = {} }
  local shm = reva_shm(conf)
  if not shm then
    return empty
  end
  local raw = shm:get(turn_key(traceparent))
  local t   = raw and cjson.decode(raw) or nil
  if type(t) ~= "table" or type(t.hops) ~= "table" then
    return empty
  end
  t.conversation = type(t.conversation) == "table" and t.conversation or {}
  return t
end


-- Append an authorized hop and the sentence that went with it, in one write.
-- `response` is left empty: Kong authorizes before the upstream has answered,
-- and the guide is explicit that an empty response means "asked, not yet
-- answered", which is true at this point.
local function record_turn(conf, traceparent, hop, exchange)
  local shm = reva_shm(conf)
  if not shm then
    kong.log.warn("[reva-ai-runtime-authorization] shared dict '", conf.hop_storage_dict,
                  "' not found; hop chain will not accumulate")
    return
  end

  local t = read_turn(conf, traceparent)
  hop.seq      = #t.hops + 1
  exchange.seq = #t.conversation + 1
  t.hops[#t.hops + 1] = hop
  t.conversation[#t.conversation + 1] = exchange

  local encoded = cjson.encode({
    hops         = as_array(t.hops),
    conversation = as_array(t.conversation),
  })
  if encoded then
    local ok, err = shm:set(turn_key(traceparent), encoded, conf.hop_ttl)
    if not ok then
      kong.log.warn("[reva-ai-runtime-authorization] could not store turn state: ", err)
    end
  end
end


-- Shape stored hops/conversation for the RTG. Older shm rows used a string
-- action and {prompt} instead of {content, contentType}.
local function hops_for_rtg(entries)
  local out = {}
  if type(entries) ~= "table" then
    return as_array(out)
  end
  for i, h in ipairs(entries) do
    if type(h) == "table" then
      local action = h.action
      if type(action) == "string" then
        action = { name = action }
      elseif type(action) ~= "table" or type(action.name) ~= "string" then
        action = { name = "invokeAgent" }
      else
        action = { name = tostring(action.name) }
      end
      out[#out + 1] = {
        seq      = h.seq or i,
        subject  = h.subject,
        action   = action,
        resource = h.resource,
        time     = h.time,
      }
    end
  end
  return as_array(out)
end


local function conversation_for_rtg(entries)
  local out = {}
  if type(entries) ~= "table" then
    return as_array(out)
  end
  for i, e in ipairs(entries) do
    if type(e) == "table" then
      local role = e.role or "user"
      if role == "agent" then
        role = "assistant"
      end
      out[#out + 1] = {
        seq         = e.seq or i,
        role        = role,
        contentType = e.contentType or "text/plain",
        content     = e.content or e.prompt or "",
        timestamp   = e.timestamp,
      }
    end
  end
  return as_array(out)
end


-- Kept for the no-shm path so callers still get a well-formed empty chain.
local function record_hop(conf, traceparent, hop)
  local shm = reva_shm(conf)
  if not shm then
    kong.log.warn("[reva-ai-runtime-authorization] shared dict '", conf.hop_storage_dict,
                  "' not found; sending empty hop chain")
    return EMPTY_ARRAY, 0
  end

  local key  = "reva:hops:" .. traceparent
  local raw  = shm:get(key)
  local hops = raw and cjson.decode(raw) or nil
  if type(hops) ~= "table" then
    hops = {}
  end

  -- what the RTG sees: the chain as it stood before this call
  local prior = {}
  for i, h in ipairs(hops) do
    prior[i] = h
  end

  hop.seq = #hops + 1
  hops[#hops + 1] = hop

  local encoded = cjson.encode(as_array(hops))
  if encoded then
    local ok, err = shm:set(key, encoded, conf.hop_ttl)
    if not ok then
      kong.log.warn("[reva-ai-runtime-authorization] could not store hop chain: ", err)
    end
  end

  return as_array(prior), #prior
end


-- ── session: the turns of one chat ──────────────────────────────────────────
--
-- `context.hops` and `context.conversation` reset every turn. `session.messages`
-- only ever grows: one entry per EARLIER turn, as a request/response pair, so
-- turn 3 is judged with turns 1 and 2 in view. "Summarise this policy" followed
-- by "now transfer the funds" is only alarming when read together.
--
-- A turn is one user message. We detect the start of one by the hop chain for
-- this traceparent being empty — the app mints a fresh traceparent per message,
-- so an entry hop is a new turn.
--
-- Known limit: this accumulates in the data plane's shared dict, so it is
-- per-node. Two data planes behind a load balancer each see half a chat. The
-- guide's own advice is that the caller should supply session.messages for
-- exactly this reason; doing it here is what makes it work without changing
-- every application, and it is correct for a single gateway.

local function session_key(session_id)
  return "reva:session:" .. session_id
end


local function read_session(conf, session_id)
  local empty = { startedAt = nil, turn = 0, messages = {} }
  if not session_id or session_id == "" then
    return empty
  end
  local shm = reva_shm(conf)
  if not shm then
    return empty
  end
  local raw = shm:get(session_key(session_id))
  local s   = raw and cjson.decode(raw) or nil
  if type(s) ~= "table" then
    return empty
  end
  s.messages = type(s.messages) == "table" and s.messages or {}
  s.turn     = tonumber(s.turn) or 0
  return s
end


-- Open a new turn: bump the counter and record the user's request with an empty
-- response. The response is filled in by close_turn once the upstream answers.
local function open_turn(conf, session_id, content, now)
  local s = read_session(conf, session_id)
  if not session_id or session_id == "" then
    return s
  end
  local shm = reva_shm(conf)
  if not shm then
    return s
  end

  s.startedAt = s.startedAt or now
  s.turn      = s.turn + 1
  s.messages[#s.messages + 1] = {
    turn    = s.turn,
    request = {
      role        = "user",
      contentType = "text/plain",
      content     = content,
      -- Never before the chat began: the RTG refuses the entry hop if
      -- messages[0].request.timestamp precedes session.startedAt.
      timestamp   = (s.startedAt and s.startedAt > now) and s.startedAt or now,
    },
    response = { role = "assistant", contentType = "text/plain", content = "", timestamp = now },
  }

  -- Bound it. The RTG rejects a body over 1 MiB BEFORE authorizing, so an
  -- unbounded history fails every hop of a long chat rather than one.
  local cap = conf.max_session_messages or 10
  while #s.messages > cap + 1 do
    table.remove(s.messages, 1)
  end

  local encoded = cjson.encode(s)
  if encoded then
    local ok, err = shm:set(session_key(session_id), encoded, conf.session_ttl)
    if not ok then
      kong.log.warn("[reva-ai-runtime-authorization] could not store session: ", err)
    end
  end
  return s
end


-- The turns BEFORE this one, which is what session.messages means. The turn now
-- in flight has no response yet, so it is excluded.
local function prior_turns(s, cap)
  local out = {}
  for i = 1, #s.messages - 1 do
    local m = s.messages[i]
    -- A turn whose answer was never captured is not a completed turn, and the
    -- RTG refuses the whole request over it:
    --   400 invalid session: session.messages[N].response.content is required
    -- Dropping it costs one turn of history; sending it costs the call.
    local resp = m.response
    if type(resp) == "table" and type(resp.content) == "string"
       and resp.content ~= "" then
      out[#out + 1] = m
    end
  end
  while #out > cap do
    table.remove(out, 1)
  end
  return out
end


-- ── credential ──────────────────────────────────────────────────────────────

local function rtg_credential(conf)
  if conf.auth_token and conf.auth_token ~= "" then
    return conf.auth_token, nil
  end
  return nil, "no credential configured: set auth_token"
end


-- ── RTG call ────────────────────────────────────────────────────────────────

local function call_rtg(conf, payload, traceparent, request_id)
  local url = conf.reva_host_url:gsub("/+$", "") .. RTG_EVAL_PATH

  local token, terr = rtg_credential(conf)
  if not token then
    return nil, terr
  end

  local opts = {
    method  = "POST",
    body    = payload,
    headers = {
      ["Content-Type"]        = "application/json",
      ["Authorization"]       = "Bearer " .. token,
      ["traceparent"]         = traceparent,
      ["x-ms-correlation-id"] = request_id,
    },
    ssl_verify        = conf.ssl_verify,
    keepalive_timeout = RTG_KEEPALIVE_TIMEOUT,
    keepalive_pool    = RTG_KEEPALIVE_POOL_SIZE,
  }

  local last_err
  for attempt = 0, RTG_RETRIES do
    local httpc, err = http.new()
    if not httpc then
      last_err = err or "could not create http client"

    else
      httpc:set_timeout(RTG_TIMEOUT_MS)

      local res, rerr = httpc:request_uri(url, opts)
      if res then
        return res
      else
        last_err = rerr
        kong.log.warn("[reva-ai-runtime-authorization] RTG call attempt ", attempt + 1, " failed: ", rerr)
      end
    end
  end

  return nil, last_err
end


-- The RTG answers a denial with HTTP 403 and a body carrying decision:false,
-- so a non-2xx status is not automatically a service failure. 200 and 403 are
-- both real decisions; anything else means we could not get one, and the
-- body's reason is surfaced so the cause is diagnosable.
local function decision_from(res)
  local body = res.body
  local decoded = type(body) == "string" and body ~= "" and cjson.decode(body) or nil

  if res.status >= 200 and res.status < 300 then
    if type(decoded) == "table" then
      return decoded.decision == true, nil, decoded
    end
    if type(body) == "string" then
      -- Defensive fallback: the RTG has been seen to return a body that does
      -- not decode cleanly.
      return body:find('"decision"%s*:%s*true') ~= nil, nil, nil
    end
    return nil, "empty RTG response body"
  end

  if res.status == 403 and type(decoded) == "table" and decoded.decision ~= nil then
    return decoded.decision == true, nil, decoded
  end

  local why = fmt("RTG returned HTTP %d", res.status)
  if type(decoded) == "table" then
    local reason = (decoded.context and decoded.context.reason) or decoded.error
    if reason then
      why = why .. ": " .. tostring(reason)
    end
  end
  return nil, why
end


-- ── phase handler ───────────────────────────────────────────────────────────

function RevaRTG:access(conf)
  local path   = kong.request.get_path() or ""
  local method = kong.request.get_method() or "GET"

  local ok, body = pcall(kong.request.get_body)
  if not ok or type(body) ~= "table" then
    body = {}
  end

  local call, skip_reason = classify(conf, path, method, body)
  if not call then
    if conf.debug then
      kong.log.notice("[reva-ai-runtime-authorization] skipping ", method, " ", path, ": ", skip_reason)
    end
    return
  end

  -- Identity. User always comes from the JWT. Agent is required only when
  -- authorize_agent is true.
  local user, user_err, user_groups = resolve_user(conf)
  if user == "" then
    return kong.response.exit(401, {
      message = conf.deny_message,
      reason  = user_err or "missing user identity",
    })
  end

  local agent, agent_src = "", "skipped"
  if conf.authorize_agent then
    agent, agent_src = resolve_agent(conf)
    if agent_src == "consumer-missing" then
      return kong.response.exit(401, {
        message = conf.deny_message,
        reason  = "no authenticated consumer; identity_source is 'consumer' so the caller must be authenticated first",
      })
    end
    if agent == "" then
      if conf.require_identity_headers then
        return kong.response.exit(400, {
          message = conf.deny_message,
          reason  = fmt("missing %s header", conf.agent_header),
        })
      end
      if conf.debug then
        kong.log.notice("[reva-ai-runtime-authorization] no agent identity; skipping evaluation")
      end
      return
    end
  end

  if conf.debug then
    kong.log.notice("[reva-ai-runtime-authorization] user '", user, "' agent '", agent, "' from ", agent_src)
  end

  -- Trace correlation: reuse the caller's traceparent so a multi-agent chain
  -- keeps one id, otherwise mint one for this entry point.
  local traceparent = kong.request.get_header("traceparent")
                   or kong.request.get_header("fly-traceparent")
                   or ""
  if traceparent == "" then
    traceparent = mint_traceparent()
  end

  local request_id = kong.request.get_header("fly-request-id")
                  or kong.request.get_header("x-request-id")
                  or kong_request_id()

  local source_ip = kong.request.get_header("fly-client-ip")
                 or kong_client_ip()

  local now = iso_now()
  -- Session tracking (and the shared-dict storage it costs) is opt-in with
  -- authorize_agent: leave session_id nil and every downstream read/write
  -- of it already no-ops exactly as it does today when a caller sends no
  -- session header at all — open_turn/read_session both treat a missing
  -- session_id as "nothing to look up, nothing to store."
  local session_id
  if conf.authorize_agent then
    -- Prefer an explicit chat id from the caller: it is the only thing that
    -- survives across turns. The others identify a single request, so
    -- falling back to them makes every message look like a brand new chat.
    session_id = kong.request.get_header(conf.session_header)
              or call.session_id
              or kong.request.get_header("mcp-session-id")
              or request_id
  end

  -- The chain as it stood BEFORE this call. This hop is added only after the
  -- RTG authorizes it, so a refused call never appears in the path that later
  -- hops are judged against.
  local turn = read_turn(conf, traceparent)
  local prior_hop_count = #turn.hops
  local hops = hops_for_rtg(turn.hops)
  local conversation = conversation_for_rtg(turn.conversation)

  local prompt = call.prompt or ""
  if prompt == "" then
    prompt = call.action .. " " .. call.res_id
  end

  -- First hop of a turn: the hop chain for this traceparent is still empty.
  local is_entry_hop = (prior_hop_count == 0)

  local sess
  if is_entry_hop then
    sess = open_turn(conf, session_id, prompt, now)
  else
    sess = read_session(conf, session_id)
  end

  local cap = conf.max_session_messages or 10
  local caller_pairs, hist_started = history_to_session_messages(call.history, now, cap)

  local session_block = {
    id        = session_id,
    startedAt = sess.startedAt or now,
  }
  if #caller_pairs > 0 then
    session_block.turn = #caller_pairs + 1
    session_block.startedAt = hist_started or session_block.startedAt
    if session_block.turn >= 2 then
      session_block.messages = caller_pairs
    end
  else
    session_block.turn = (sess.turn and sess.turn > 0) and sess.turn or (prior_hop_count + 1)
    local earlier = prior_turns(sess, cap)
    if #earlier > 0 and session_block.turn >= 2 then
      session_block.messages = earlier
    end
  end

  -- History lives only in session.messages, never duplicated into context.
  -- context.conversation is this turn's own hop-by-hop record; it is not a
  -- second copy of the chat history.
  local context = {
    hops         = hops,
    maxHops      = call.routing and tonumber(call.routing.maxHops) or nil,
    conversation = { messages = conversation },
  }

  -- The entry hop of a trace is the user's own action, whoever relayed it -
  -- rec_hop below already records it this way. Only a later hop, where some
  -- prior hop exists for this traceparent, is a real agent acting on its own.
  local subject
  if conf.authorize_agent and not is_entry_hop then
    subject = { type = "Agent", id = agent }
  else
    subject = { type = "User", id = user }
  end

  local tx = {
    promptKey   = conf.prompt_key,
    role        = is_entry_hop and "user" or "assistant",
    contentType = "text/plain",
  }
  tx[conf.prompt_key or "content"] = prompt

  -- The User's group memberships (e.g. Cognito's "cognito:groups"), as a
  -- Cedar-style entity: the policy resolves group membership by walking
  -- `parents`, not by reading a plain list off the request.
  local entities
  if user_groups and #user_groups > 0 then
    local parents = {}
    for i, group in ipairs(user_groups) do
      parents[i] = { type = "UserGroup", id = group }
    end
    entities = as_array({ {
      uid     = { type = "User", id = user },
      parents = parents,
    } })
  end

  local payload = cjson.encode({
    subject      = subject,
    action       = { name = call.action },
    resource     = { type = call.res_type, id = call.res_id, name = call.res_id },
    principal    = { type = "User", id = user },
    context      = context,
    transmission = tx,
    session      = session_block,
    inputValues  = call.input_values,
    entities     = entities,
  })

  if not payload then
    kong.log.err("[reva-ai-runtime-authorization] could not encode evaluation request")
    if conf.fail_open then
      return
    end
    return kong.response.exit(conf.deny_status, {
      message = conf.deny_message,
      reason  = "could not build authorization request",
    })
  end

  if conf.debug then
    kong.log.notice("[reva-ai-runtime-authorization] evaluating ", call.action, " ", call.res_id,
                    " payload=", payload)
  end

  local started = ngx.now()
  local res, err = call_rtg(conf, payload, traceparent, request_id)
  local elapsed_ms = (ngx.now() - started) * 1000

  local allowed, decision_err, decoded
  if res then
    allowed, decision_err, decoded = decision_from(res)
  else
    decision_err = err or "RTG unreachable"
  end

  kong.ctx.shared.reva_traceparent = traceparent
  kong.ctx.shared.reva_allowed     = allowed
  kong.ctx.shared.reva_latency_ms  = elapsed_ms

  if allowed == nil then
    kong.log.err("[reva-ai-runtime-authorization] no decision (", decision_err, ") after ",
                 fmt("%.1f", elapsed_ms), "ms; fail_open=", tostring(conf.fail_open))
    if conf.fail_open then
      return
    end
    return kong.response.exit(conf.deny_status, {
      message = conf.deny_message,
      reason  = "authorization service unavailable",
    })
  end

  kong.log.info("[reva-ai-runtime-authorization] ", call.action, " ", call.res_id,
                " allowed=", tostring(allowed),
                " status=", res.status,
                " latency_ms=", fmt("%.1f", elapsed_ms))

  if not allowed then
    local reason = (decoded and decoded.context and decoded.context.reason)
                or (decoded and decoded.reason)
                or "authorization denied by policy"

    -- Monitor mode: the decision was real and is logged, but the request is
    -- allowed through anyway. This is how a rollout starts - watch production
    -- traffic against real policy, see what WOULD have been refused, then turn
    -- it off to enforce. Logged at warn so a would-be denial is visible in a
    -- log level that is kept, and marked so nobody reads it as an allow.
    if conf.monitor_mode then
      kong.log.warn("[reva-ai-runtime-authorization] MONITOR would deny ", call.action, " ", call.res_id,
                    " for ", agent, ": ", reason, " (proxying anyway)")
      kong.ctx.shared.reva_monitor_would_deny = true
    else
      return kong.response.exit(conf.deny_status, {
        message = conf.deny_message,
        reason  = reason,
      })
    end
  end

  -- Authorized, so this hop now becomes part of the path that later hops in
  -- the same trace are judged against. A refused call is never recorded.
  local rec_hop, rec_ex
  if conf.authorize_agent then
    if is_entry_hop then
      rec_hop = {
        subject  = { type = "User", id = user },
        action   = { name = "invokeAgent" },
        resource = { type = "Agent", id = agent },
        time     = now,
      }
      rec_ex = utterance("user", prompt, now)
    else
      rec_hop = {
        subject  = { type = "Agent", id = agent },
        action   = { name = call.action },
        resource = { type = call.res_type, id = call.res_id },
        time     = now,
      }
      rec_ex = utterance("assistant", prompt, now)
    end
  else
    rec_hop = {
      subject  = { type = "User", id = user },
      action   = { name = call.action },
      resource = { type = call.res_type, id = call.res_id },
      time     = now,
    }
    rec_ex = utterance(is_entry_hop and "user" or "assistant", prompt, now)
  end
  record_turn(conf, traceparent, rec_hop, rec_ex)

  if conf.forward_traceparent then
    kong.service.request.set_header("traceparent", traceparent)
  end

  -- Only the hop that opened a turn closes it, and only that hop needs the
  -- response body buffered.
  -- Capture the response on every hop of the turn, not only the one that
  -- opened it. The hop that opens a turn is often the model returning a tool
  -- call, and a completion carrying tool_calls has content: null - there is
  -- nothing to record yet. The turn's actual answer arrives on its last hop, so
  -- each hop overwrites the previous one and the final write is the real reply.
  if session_id and session_id ~= "" and sess.turn > 0 then
    kong.ctx.shared.reva_session_id = session_id
    kong.ctx.shared.reva_open_turn  = sess.turn
    -- Ask the upstream not to compress THIS response. body_filter sees the raw
    -- stream, and gzip bytes stored as a turn's answer are unreadable to the
    -- evaluator and inflate the payload toward the RTG's 1 MiB limit. Kong has
    -- no gunzip primitive, so the cheaper fix is to not receive gzip at all.
    -- Scoped to the one hop per turn whose body we actually read.
    kong.service.request.set_header("Accept-Encoding", "identity")
  end
end


-- Buffer the response body, but only for the hop that opened a turn. Every
-- other hop pays nothing.
function RevaRTG:body_filter(conf)
  if not kong.ctx.shared.reva_open_turn then
    return
  end

  local chunk, eof = ngx.arg[1], ngx.arg[2]
  local buf = kong.ctx.shared.reva_body_buf or {}
  if chunk and chunk ~= "" and #buf < 64 then
    buf[#buf + 1] = chunk
    kong.ctx.shared.reva_body_buf = buf
  end
  if eof then
    kong.ctx.shared.reva_body_done = table.concat(buf)
  end
end


-- Close the turn: write the answer into the turn this request opened, so the
-- NEXT turn of the chat carries a complete request/response pair: the broad
-- user query and its response, not a replay of all ten hops in between.
function RevaRTG:log(conf)
  local session_id = kong.ctx.shared.reva_session_id
  local turn_no    = kong.ctx.shared.reva_open_turn
  if not session_id or not turn_no then
    return
  end

  local body = kong.ctx.shared.reva_body_done
  if not body or body == "" then
    return
  end

  -- Pull the assistant's sentence out of an OpenAI-style completion; fall back
  -- to the raw body for anything else. Truncated hard: this is a summary line,
  -- and the whole history ships on every later hop.
  local text
  local ok, decoded = pcall(cjson.decode, body)
  if ok and type(decoded) == "table" then
    local choices = decoded.choices
    if type(choices) == "table" and type(choices[1]) == "table"
       and type(choices[1].message) == "table" then
      text = choices[1].message.content

    -- JSON-RPC, which is what MCP tool results and A2A messages come back as.
    -- Without this branch those turns never record an answer, prior_turns()
    -- drops them as incomplete, and session.messages stays empty for every
    -- call type except the model ones.
    elseif decoded.jsonrpc then
      local r = decoded.result
      if type(r) == "table" then
        -- MCP tools/call: { content = [ { type = "text", text = "..." } ] }
        local parts = type(r.content) == "table" and r.content or nil
        -- A2A message/send: { parts = [ { text = "..." } ] }
        if not parts and type(r.parts) == "table" then
          parts = r.parts
        end
        if parts then
          local acc = {}
          for _, part in ipairs(parts) do
            if type(part) == "table" and type(part.text) == "string" then
              acc[#acc + 1] = part.text
            end
          end
          if #acc > 0 then
            text = concat(acc, "\n")
          end
        end
        -- Anything else structured: report it as JSON rather than nothing. An
        -- absent response costs the turn; a compact encoding of it does not.
        if not text then
          local enc_ok, enc = pcall(cjson.encode, r)
          if enc_ok then
            text = enc
          end
        end
      elseif type(r) == "string" then
        text = r
      elseif type(decoded.error) == "table" then
        -- A failed tool call is still what happened on that turn.
        text = "error: " .. tostring(decoded.error.message or "unknown")
      end
    end
  end

  -- Store nothing rather than something unreadable. A body that did not parse
  -- is compressed, streamed, or some shape we do not know; writing those bytes
  -- in as the turn's answer tells the evaluator the agent said a page of
  -- binary. An absent response honestly means "not captured".
  if type(text) ~= "string" or text == "" then
    if conf.debug then
      kong.log.notice("[reva-ai-runtime-authorization] no readable response for turn ", turn_no,
                      "; leaving it empty")
    end
    return
  end

  local shm = reva_shm(conf)
  if not shm then
    return
  end
  local raw = shm:get(session_key(session_id))
  local s   = raw and cjson.decode(raw) or nil
  if type(s) ~= "table" or type(s.messages) ~= "table" then
    return
  end

  for i = #s.messages, 1, -1 do
    if s.messages[i].turn == turn_no then
      s.messages[i].response = {
        role        = "assistant",
        contentType = "text/plain",
        content     = truncate(text, 2000),
        timestamp   = iso_now(),
      }
      break
    end
  end

  local encoded = cjson.encode(s)
  if encoded then
    shm:set(session_key(session_id), encoded, conf.session_ttl)
  end
end


return RevaRTG
