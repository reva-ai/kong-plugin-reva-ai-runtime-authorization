-- kong/plugins/reva-ai-runtime-authorization/handler.lua
--
-- Reva Trust Guardian authorization for Kong AI Gateway.
--
-- access: classify the call and ask Reva Trust Guardian for a decision. The
-- prompt is at the root of the request and the Reva fields are in their own
-- block; an allow returns a transaction token. A token carried in by an
-- earlier hop goes to Reva as X-Transaction-Token (inbound accepts
-- X-Transaction-Token or X-REVA-TOKEN), and the token returned on an allow is
-- forwarded upstream under both names. When an earlier hop's token is present,
-- no subject or principal is sent, because Reva takes them from the token. The
-- first call of a turn sends the user from the JWT. Authorization is the
-- caller's user JWT; X-API-Token is the gateway credential.
-- response: only the first call of a turn reads the buffered upstream body and
-- reports the turn to Reva when that request completes, i.e. when the turn's
-- answer returns to the caller. Later hops do not report. (No body_filter:
-- streaming forbids combining it with the response phase.)
--
-- A streaming Custom Policy needs KONG_UNTRUSTED_LUA=lax on the data plane so
-- resty.http and kong.cache are allowed (strict blocks both). The first-call
-- reservation uses kong.cache (ngx.shared is nil under lax); ngx.shared remains
-- an optional fallback when untrusted_lua=on.
local cjson = require "cjson.safe"
local http  = require "resty.http"

local kong        = kong
local ngx         = ngx
local type        = type
local ipairs      = ipairs
local tostring    = tostring
local tonumber    = tonumber
local setmetatable = setmetatable
local fmt         = string.format
local concat      = table.concat
local lower       = string.lower
local byte        = string.byte
local sort        = table.sort
local floor       = math.floor

local EMPTY_ARRAY = cjson.empty_array
local ARRAY_MT    = cjson.array_mt
local RTG_EVAL_PATH             = "/pdp/ai/access/ai/evaluation"
local RTG_SUMMARIZE_PATH        = "/pdp/ai/access/ai/trace/summarize"
local RTG_TIMEOUT_MS            = 5000
local RTG_SUMMARIZE_TIMEOUT_MS  = 5000
local RTG_RETRIES               = 2
-- Longest turn output reported to Reva; larger values are rejected.
local RTG_SUMMARIZE_OUTPUT_MAX  = 16 * 1024
-- Fixed nginx shared-dict name (must match KONG_NGINX_HTTP_LUA_SHARED_DICT).
local REVA_SHM_DICT = "reva_ai_runtime_authorization"


-- HTTP call to Reva via resty.http (sandbox-allowed). Returns { status, body } or nil, err.
local function http_request_uri(url, opts)
  opts = opts or {}
  local httpc = http.new()
  httpc:set_timeout(opts.timeout or RTG_TIMEOUT_MS)
  local ssl_verify = opts.ssl_verify
  if ssl_verify == nil then
    ssl_verify = true
  end
  local res, err = httpc:request_uri(url, {
    method = opts.method or "GET",
    body = opts.body,
    headers = opts.headers,
    ssl_verify = ssl_verify,
  })
  if not res then
    return nil, err
  end
  return { status = res.status, body = res.body }
end


local RevaRTG = {
  -- Runs after the bundled authentication plugins (key-auth 1250, jwt 1450,
  -- oauth2 1400) so identity headers are already settled, and before the
  -- transformer plugins (request-transformer 801) so we evaluate the request
  -- as the client actually sent it.
  PRIORITY = 1000,
  VERSION  = "2.1.0",
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
  -- AI Gateway's Lua sandbox omits math.randomseed; guard it.
  if not seeded then
    if type(math.randomseed) == "function" then
    math.randomseed(ngx.now() * 1000 + ngx.worker.pid())
    end
    seeded = true
  end
  return "00-" .. hex(16) .. "-" .. hex(8) .. "-01"
end


-- W3C traceparent → 32-hex trace id (second field). Span id may change per
-- hop; gateway turn state is keyed on trace_id only.
local function trace_id_from_traceparent(traceparent)
  if type(traceparent) ~= "string" or traceparent == "" then
    return nil
  end
  local tid = traceparent:match("^%x%x%-([%x]+)%-")
  if tid and #tid == 32 then
    return tid
  end
  return nil
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


-- Walk a dotted path through a table (e.g. JWT claim "realm_access.roles").
-- Missing segments yield nil.
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


-- Optional ngx.shared fallback when untrusted_lua=on (nil under lax/strict).
local warned_shm_fallback = false
local function reva_shm()
  local shared = ngx and ngx.shared
  if not shared then
    return nil
  end
  local shm = shared[REVA_SHM_DICT]
  if shm then
    return shm
  end
  shm = shared["kong_db_cache"]
  if shm then
    if not warned_shm_fallback then
      warned_shm_fallback = true
      kong.log.warn("[reva-ai-runtime-authorization] shared dict '", REVA_SHM_DICT,
                    "' not declared; falling back to kong_db_cache")
    end
    return shm
  end
  return nil
end

-- Unique id for this Kong request (sandbox may omit ngx.var.request_id).
local function claim_token()
  local rid = ngx.var and ngx.var.request_id
  if type(rid) == "string" and rid ~= "" then
    return rid
  end
  local pid = (ngx.worker and ngx.worker.pid and ngx.worker.pid()) or 0
  return fmt("%.6f:%d:%d", ngx.now(), pid, math.random(1, 2147483647))
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


-- User id for subject/principal, plus the user's groups if the token carries
-- them (conf.jwt_groups_claim). A three-segment Bearer value is treated as a
-- JWT; the configured user claim is required. No fallback: user identity
-- comes only from the JWT.
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


-- Text of an A2A message's parts. Both protocol versions are read:
--   text part  {"text": "..."}, with or without a "kind"/"type" tag
--   data part  {"data": <any JSON>} (0.3: kind "data"), sent as its JSON text,
--              capped so one part cannot swamp the evaluation request
-- File parts carry no readable text and are skipped.
local A2A_DATA_PART_MAX = 8192

local function a2a_parts_text(value)
  if type(value) == "string" then
    return value
  end
  if type(value) ~= "table" then
    return ""
  end
  local t = {}
  for _, p in ipairs(value) do
    if type(p) == "table" then
      if type(p.text) == "string" then
        t[#t + 1] = p.text
      elseif p.data ~= nil and p.data ~= ngx.null then
        local encoded = cjson.encode(p.data)
        if type(encoded) == "string" and encoded ~= "" then
          t[#t + 1] = truncate(encoded, A2A_DATA_PART_MAX)
        end
      end
    end
  end
  return concat(t, "\n")
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


-- ── context variables ───────────────────────────────────────────────────────
--
-- Name/value pairs lifted from the request body and sent to Reva as `context`,
-- so a policy can match on them:
--   A2A  every `metadata` object: the request's, the message's, each part's
--   MCP  everything in params except the tool name: `arguments` and `_meta`,
--        each under its own name
--   LLM  `metadata`, and the call settings at the top of the body
-- A nested object is flattened into dotted names (customer.tier). When two
-- sources carry the same name the later, more specific one wins.
--
-- Reva reads only a small, strict set of pairs and refuses the whole
-- evaluation when one pair falls outside it, so the rules are applied here and
-- anything outside them is left out rather than sent:
--   * a value is a string, true/false, a whole number, or a list of one of
--     those: no null, decimals, objects, empty or mixed lists, and no text that
--     looks like a credential
--   * a name is not one Reva keeps for itself and does not name a credential
--   * at most 64 pairs and 512 bytes of JSON in all; the pairs that fit, in
--     name order, are kept
local CONTEXT_MAX_BYTES     = 512
local CONTEXT_MAX_PAIRS     = 64
local CONTEXT_MAX_KEY_CHARS = 128
local CONTEXT_MAX_DEPTH     = 8
-- cjson writes a number of 15 or more digits in exponent form, which Reva does
-- not read, so a larger whole number is left out.
local CONTEXT_MAX_INT       = 99999999999999
local CONTEXT_NOTES_MAX     = 20

local function name_set(list)
  local set = {}
  for _, name in ipairs(list) do
    set[name] = true
  end
  return set
end

-- Compared with the name lower-cased and reduced to its letters and digits, so
-- "Api-Key", "api_key" and "apiKey" are the same name.
local CONTEXT_RESERVED = name_set({
  "action", "authkey", "endpointtype", "endpointurl", "history", "issuer",
  "onbehalfof", "originurl", "origintype", "principal", "prompt",
  "promptintent", "promptkey", "resource", "rtga2a", "subject", "threadid",
})
local CONTEXT_CREDENTIAL = name_set({
  "accesstoken", "apikey", "authorization", "auth", "bearertoken",
  "clientsecret", "cookie", "credential", "idtoken", "oauthtoken", "password",
  "passwd", "privatekey", "proxyauthorization", "refreshtoken", "secret",
  "secretkey", "sessiontoken", "setcookie", "transactiontoken", "xapikey",
  "xapitoken", "xtransactiontoken",
})


local function fingerprint(name)
  return lower((name:gsub("[^%w\128-\255]", "")))
end


local function rune_count(s)
  local _, continuation = s:gsub("[\128-\191]", "")
  return #s - continuation
end


-- A decoded JSON array: a non-empty table keyed 1..n. (cjson decodes an empty
-- array and an empty object to the same empty table.)
local function is_list(t)
  if #t == 0 then
    return false
  end
  for k in pairs(t) do
    if type(k) ~= "number" then
      return false
    end
  end
  return true
end


local function note(dropped, text)
  if #dropped < CONTEXT_NOTES_MAX then
    dropped[#dropped + 1] = text
  else
    dropped.more = (dropped.more or 0) + 1
  end
end


local function split_dots(s)
  local parts = {}
  for part in (s .. "."):gmatch("([^.]*)%.") do
    parts[#parts + 1] = part
  end
  return parts
end


local function base64url_ok(part, allow_padding)
  local body, padding = part:match("^([%w_%-]*)(=*)$")
  if not body then
    return false
  end
  if padding == "" then
    return #body % 4 ~= 1
  end
  if not allow_padding then
    return false
  end
  local rest = #body % 4
  return (rest == 2 and #padding == 2) or (rest == 3 and #padding == 1)
end


-- Text Reva would take for a credential: a bearer value, or a signed (three
-- parts) or encrypted (five parts) token.
local function looks_like_credential(s)
  local raw = s:match("^%s*(.-)%s*$")
  if lower(raw:sub(1, 7)) == "bearer " then
    return true
  end
  local parts = split_dots(raw)
  if #parts == 3 and parts[1] ~= "" and parts[2] ~= "" then
    local all = true
    for _, part in ipairs(parts) do
      if part ~= "" and not base64url_ok(part, true) then
        all = false
        break
      end
    end
    if all then
      return true
    end
  end
  if #parts == 5 then
    local all = true
    for i, part in ipairs(parts) do
      if not (i == 2 and part == "") and (part == "" or not base64url_ok(part, false)) then
        all = false
        break
      end
    end
    if all then
      return true
    end
  end
  return false
end


-- Returns kind, value for a scalar Reva accepts, or nil, why not.
local function scalar_value(v)
  local t = type(v)
  if t == "string" then
    if #v > CONTEXT_MAX_BYTES - 2 then
      return nil, "too long"
    end
    if looks_like_credential(v) then
      return nil, "looks like a credential"
    end
    return "string", v
  end
  if t == "boolean" then
    return "boolean", v
  end
  if t == "number" then
    if v ~= v or v ~= floor(v) then
      return nil, "not a whole number"
    end
    if v > CONTEXT_MAX_INT or v < -CONTEXT_MAX_INT then
      return nil, "number too large"
    end
    return "integer", (v == 0 and 0 or v)
  end
  if t == "userdata" then
    return nil, "null"
  end
  return nil, "unsupported value"
end


-- v is a scalar or a non-empty list. Returns the value to send, or nil, why not.
local function context_value(v)
  if type(v) ~= "table" then
    local kind, value = scalar_value(v)
    if not kind then
      return nil, value
    end
    return value
  end
  if #v > CONTEXT_MAX_BYTES then
    return nil, "list too long"
  end
  local list, list_kind = {}, nil
  for i = 1, #v do
    local item = v[i]
    if type(item) == "table" then
      return nil, "list of objects or lists"
    end
    local kind, value = scalar_value(item)
    if not kind then
      return nil, value
    end
    if list_kind and list_kind ~= kind then
      return nil, "mixed list"
    end
    list_kind = kind
    list[i] = value
  end
  return list
end


-- nil when the name can be sent, otherwise why not.
local function context_name_problem(name)
  if #name > CONTEXT_MAX_KEY_CHARS * 4 or rune_count(name) > CONTEXT_MAX_KEY_CHARS then
    return "name too long"
  end
  if name == "" or name:find("^%s") or name:find("%s$") then
    return "blank name"
  end
  local whole = fingerprint(name)
  if CONTEXT_RESERVED[whole] then
    return "name reserved"
  end
  if CONTEXT_CREDENTIAL[whole] then
    return "name looks like a credential"
  end
  for segment in name:gmatch("[^.]+") do
    if CONTEXT_CREDENTIAL[fingerprint(segment)] then
      return "name looks like a credential"
    end
  end
  return nil
end


local function flatten_context(source, prefix, out, dropped, depth)
  for k, v in pairs(source) do
    if type(k) == "string" then
      local name = prefix and (prefix .. "." .. k) or k
      if type(v) == "table" and not is_list(v) then
        if next(v) ~= nil then
          if depth >= CONTEXT_MAX_DEPTH then
            note(dropped, name .. " (nested too deep)")
          else
            flatten_context(v, name, out, dropped, depth + 1)
          end
        end
      else
        local value, why = context_value(v)
        if value == nil then
          note(dropped, name .. " (" .. why .. ")")
        else
          local problem = context_name_problem(name)
          if problem then
            note(dropped, name .. " (" .. problem .. ")")
          else
            out[name] = value
          end
        end
      end
    end
  end
end


-- Bytes of a JSON string, with the escapes Reva counts.
local function json_string_len(s)
  local n = #s + 2
  for i = 1, #s do
    local b = byte(s, i)
    if b == 34 or b == 92 or b == 8 or b == 9 or b == 10 or b == 12 or b == 13 then
      n = n + 1
    elseif b < 32 then
      n = n + 5
    end
  end
  return n
end


local function json_value_len(v)
  local t = type(v)
  if t == "string" then
    return json_string_len(v)
  end
  if t == "boolean" then
    return v and 4 or 5
  end
  if t == "number" then
    return #fmt("%d", v)
  end
  local n = 2 + (#v > 1 and #v - 1 or 0)
  for i = 1, #v do
    n = n + json_value_len(v[i])
  end
  return n
end


-- sources: tables of name/value pairs, least specific first. Returns the
-- context table (nil when nothing qualifies) and a list of what was left out.
local function build_context(sources)
  local merged, dropped = {}, {}
  for _, source in ipairs(sources) do
    if next(source) ~= nil and not is_list(source) then
      flatten_context(source, nil, merged, dropped, 1)
    end
  end

  local names = {}
  for name in pairs(merged) do
    names[#names + 1] = name
  end
  sort(names)

  local context, count, size = {}, 0, 2
  for _, name in ipairs(names) do
    local value = merged[name]
    local added = json_string_len(name) + 1 + json_value_len(value) + (count > 0 and 1 or 0)
    if count < CONTEXT_MAX_PAIRS and size + added <= CONTEXT_MAX_BYTES then
      context[name] = value
      count = count + 1
      size = size + added
    else
      note(dropped, name .. " (does not fit)")
    end
  end

  if count == 0 then
    return nil, dropped
  end
  return context, dropped
end


local function add_source(sources, source)
  if type(source) == "table" then
    sources[#sources + 1] = source
  end
end


-- request_meta: the metadata of the request itself (params.metadata over
-- JSON-RPC, the body's metadata over HTTP+JSON); msg: the A2A Message.
local function a2a_context(request_meta, msg)
  local sources = {}
  add_source(sources, request_meta)
  add_source(sources, msg.metadata)
  if type(msg.parts) == "table" then
    for _, part in ipairs(msg.parts) do
      if type(part) == "table" then
        add_source(sources, part.metadata)
      end
    end
  end
  return build_context(sources)
end


-- params: the tools/call params. The tool name is already the resource id.
local function mcp_context(params)
  local sources, rest = {}, {}
  for k, v in pairs(params) do
    if k ~= "name" and k ~= "arguments" and k ~= "_meta" then
      rest[k] = v
    end
  end
  add_source(sources, rest)
  add_source(sources, params._meta)
  add_source(sources, params.arguments)
  return build_context(sources)
end


-- The model and the messages are already the resource and the prompt, and a
-- list of tool definitions is not a name/value pair.
local LLM_NOT_CONTEXT = {
  model = true, messages = true, tools = true, functions = true, metadata = true,
}

local function llm_context(body)
  local sources, settings = {}, {}
  for k, v in pairs(body) do
    if not LLM_NOT_CONTEXT[k] then
      settings[k] = v
    end
  end
  add_source(sources, body.metadata)
  add_source(sources, settings)
  return build_context(sources)
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

  local context, dropped = llm_context(body)
  return {
    action          = "invokeModel",
    role            = "agent",
    res_type        = "Model",
    res_id          = model,
    prompt          = prompt,
    context         = context,
    context_dropped = dropped,
  }
end


local function classify_mcp(body, http_method)
  if http_method ~= "POST" then
    return nil, "not an MCP POST"
  end
  if (body.method or "") ~= "tools/call" then
    return nil, "MCP method is not tools/call"
  end

  -- Tool resource.id is the MCP tool name only (params.name). The Kong
  -- Service host must not be prefixed: Reva resolves the MCP server from
  -- resource.endpoint and names the tool <mcp server>/<tool>.
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

  -- Earlier turns of the chat are kept by Reva, not sent with the tool call.
  local context, dropped = mcp_context(type(body.params) == "table" and body.params or {})
  return {
    action          = "invokeTool",
    role            = "agent",
    res_type        = "Tool",
    res_id          = tool,
    prompt          = prompt,
    context         = context,
    context_dropped = dropped,
  }
end


-- The A2A requests that send a message to an agent, which is what invokes it.
-- Value: true when the response is streamed (server-sent events).
--   JSON-RPC, protocol 0.3 names: message/send, message/stream
--   JSON-RPC, protocol 1.0 names: SendMessage, SendStreamingMessage
-- Task reads and management (tasks/*, push-notification configs, agent cards)
-- send no message and are not evaluated.
local A2A_JSONRPC_SEND = {
  ["message/send"]         = false,
  ["SendMessage"]          = false,
  ["message/stream"]       = true,
  ["SendStreamingMessage"] = true,
}

-- The same two operations in the HTTP+JSON (REST) binding, identified by the
-- end of the request path: the spec puts the operation there, so any prefix
-- (a version such as /v1, or a tenant) is ignored.
local A2A_REST_SEND = {
  { suffix = "/message:send",   streaming = false },
  { suffix = "/message:stream", streaming = true  },
}

-- msg: the A2A Message object ({} when the request carried none)
-- request_meta: the metadata of the request itself, when it has any
local function a2a_call(msg, streaming, request_meta)
  -- Current utterance from the A2A spec field message.parts.
  -- Earlier turns of the chat are kept by Reva, not read from the body. The
  -- thread id is not read here: it comes from conf.session_key (see
  -- resolve_session_id).
  local context, dropped = a2a_context(request_meta, msg)
  return {
    action          = "invokeAgent",
    role            = "agent",
    res_type        = "Agent",
    res_id          = kong_service_url(),
    prompt          = a2a_parts_text(msg.parts),
    streaming       = streaming,
    context         = context,
    context_dropped = dropped,
  }
end


local function classify_a2a(body, http_method)
  if http_method ~= "POST" then
    return nil, "not an A2A POST"
  end
  local streaming = A2A_JSONRPC_SEND[body.method or ""]
  if streaming == nil then
    return nil, "A2A method does not send a message"
  end

  local params = type(body.params) == "table" and body.params or {}
  local msg = type(params.message) == "table" and params.message or {}
  return a2a_call(msg, streaming, params.metadata)
end


-- A2A HTTP+JSON binding: POST .../message:send and .../message:stream. The
-- body is the request itself ({"message": {...}}), with no JSON-RPC envelope.
local function classify_a2a_rest(body, http_method, path)
  if http_method ~= "POST" or type(path) ~= "string" then
    return nil
  end
  for _, op in ipairs(A2A_REST_SEND) do
    local n = #op.suffix
    if #path >= n and path:sub(-n) == op.suffix then
      local msg = type(body.message) == "table" and body.message or {}
      return a2a_call(msg, op.streaming, body.metadata)
    end
  end
  return nil
end


-- Work out what the caller is trying to do from the request body (Kong
-- Service URL for Agent/Tool endpoint; MCP Tool id is params.name only).
-- Path prefixes are not used — LLM / MCP / A2A are distinct Kong entities;
-- the payload shape identifies the call. Returns a descriptor table, or
-- nil plus a reason when this request is not ours to evaluate.
--
-- Order: JSON-RPC tools/call, JSON-RPC A2A send-message methods, the A2A REST
-- send-message paths, then OpenAI messages.
local function classify(conf, method, body, path)
  local unmatched = "payload is not LLM, MCP tools/call, or an A2A send-message request"
  if type(body) ~= "table" then
    return nil, unmatched
  end
  if body.jsonrpc ~= nil then
    if body.method == "tools/call" then
      return classify_mcp(body, method)
    end
    if A2A_JSONRPC_SEND[body.method or ""] ~= nil then
      return classify_a2a(body, method)
    end
    return nil, "JSON-RPC method is not tools/call or an A2A send-message method"
  end
  local rest = classify_a2a_rest(body, method, path)
  if rest then
    return rest
  end
  if type(body.messages) == "table" and body.messages[1] ~= nil then
    return classify_llm(body)
  end

  return nil, unmatched
end


-- ── per-trace reservation + first-call-only report ──────────────────────────
--
-- The key uses the W3C trace id only (the span id may change per hop).
-- First call versus later hop: the reservation is taken BEFORE the evaluation
-- call. The winner is the first call of the turn (it reports the turn when it
-- completes); a loser is a later hop. kong.cache is preferred: get() runs the
-- loader once per key and concurrent waiters share that value, so the first
-- hop wins. Fallback: ngx.shared:add when untrusted_lua=on. hop_ttl expires a
-- reservation whose release never runs. A trace id is always present (created
-- if absent). The reservation is local to one data plane node.

local function entry_key(trace_id)
  return "reva:entry:" .. trace_id
end


-- true = this hop won the claim (entry; summarize on complete).
local function reserve_entry(conf, trace_id)
  local key = entry_key(trace_id)
  local ttl = tonumber(conf.hop_ttl) or 3600

  -- Primary path for AI Gateway lax: kong.cache (not ngx.shared).
  if kong.cache and kong.cache.get then
    local me = claim_token()
    local owner, err = kong.cache:get(
      key,
      { ttl = ttl },
      function(id)
        return id  -- non-nil; first caller stores its token
      end,
      me
    )
    if err then
      kong.log.warn("[reva-ai-runtime-authorization] claim: cache error: ",
                    tostring(err), " — treating as nested")
      return false
    end
    if owner == me then
      kong.log.info("[reva-ai-runtime-authorization] claim: RESERVED entry for ",
                    trace_id, " (kong.cache)")
      return true
    end
    kong.log.info("[reva-ai-runtime-authorization] claim: nested hop for ",
                  trace_id, " (kong.cache)")
    return false
  end

  -- Fallback when sandbox exposes ngx.shared (untrusted_lua=on).
  local shm = reva_shm()
  if shm then
    local ok = shm:add(key, true, ttl)
    if ok then
      kong.log.info("[reva-ai-runtime-authorization] claim: RESERVED entry for ",
                    trace_id, " (shm)")
      return true
    end
    kong.log.info("[reva-ai-runtime-authorization] claim: nested hop for ",
                  trace_id, " (shm)")
    return false
  end

  kong.log.warn("[reva-ai-runtime-authorization] claim: no kong.cache and no ",
                "ngx.shared — cannot know starter; treating as nested")
  return false
end


-- Drop claim when the turn is done (entry hop completed).
local function clear_entry(trace_id)
  if type(trace_id) ~= "string" or trace_id == "" then
    return
  end
  local key = entry_key(trace_id)
  if kong.cache then
    if kong.cache.invalidate_local then
      kong.cache:invalidate_local(key)
    elseif kong.cache.invalidate then
      kong.cache:invalidate(key)
    end
  end
  local shm = reva_shm()
  if shm then
    shm:delete(key)
  end
  kong.log.info("[reva-ai-runtime-authorization] claim: CLEARED entry for ",
                trace_id, " (turn complete)")
end


-- Entry hop only: buffer the upstream body and summarize in the response
-- phase (cosockets allowed there; streaming plugins cannot use ngx.timer).
local function arm_entry_summarize(trace_id, thread_id)
  if type(trace_id) ~= "string" or trace_id == "" then
    return
  end
  kong.ctx.shared.reva_summarize = true
  kong.ctx.shared.reva_trace_id  = trace_id
  kong.ctx.shared.reva_thread_id = thread_id
  kong.service.request.set_header("Accept-Encoding", "identity")
  -- Buffered proxying → kong.service.response.get_raw_body() in :response().
  local ok, err = pcall(function()
    kong.service.request.enable_buffering()
  end)
    if not ok then
    kong.log.warn("[reva-ai-runtime-authorization] enable_buffering failed: ",
                  tostring(err), "; summarize needs buffered response body")
  end
  kong.log.info("[reva-ai-runtime-authorization] armed summarize for trace_id=",
                trace_id, " (will POST in response phase)")
end


-- Entry hop of a turn that was allowed (or is proxied anyway).
--
-- A streamed response (A2A message/stream) is delivered as it is produced, so
-- it must not be buffered: the client would see nothing until the agent
-- finished, and a long stream would run into the proxy read timeout. Such a
-- turn is therefore not summarized (the summary needs the finished body); the
-- reservation is still held until the request ends so nested hops stay nested.
local function arm_entry(call, trace_id, thread_id)
  if call.streaming then
    kong.ctx.shared.reva_stream_entry = trace_id
    kong.log.info("[reva-ai-runtime-authorization] streamed entry hop for ", trace_id,
                  ": response not buffered, turn will not be summarized")
    return
  end
  arm_entry_summarize(trace_id, thread_id)
end


-- ── session id (thread correlation only) ────────────────────────────────────
--
-- Earlier turns of the chat are not stored or forwarded by the policy; Reva
-- keeps them. The policy passes the thread id (threadId and session.id) so Reva
-- can join the call to the right conversation.

-- ── credential ──────────────────────────────────────────────────────────────

local function rtg_credential(conf)
  if conf.auth_token and conf.auth_token ~= "" then
    return conf.auth_token, nil
  end
  return nil, "no credential configured: set auth_token"
end


-- ── Reva call ────────────────────────────────────────────────────────────────

-- Header value with an optional Bearer prefix removed.
local function header_token(name)
  local raw = kong.request.get_header(name)
  if type(raw) ~= "string" then
    return ""
  end
  raw = raw:gsub("^%s+", ""):gsub("%s+$", "")
  local bearer = raw:match("^[Bb]earer%s+(.+)$")
  if bearer then
    raw = bearer:gsub("^%s+", ""):gsub("%s+$", "")
  end
  return raw
end


-- Prior-hop transaction token from the caller. X-Transaction-Token is preferred.
local function inbound_txn_token()
  local txn = header_token("x-transaction-token")
  if txn ~= "" then
    return txn
  end
  return header_token("x-reva-token")
end


-- A string or number as a non-empty string, otherwise nil.
local function scalar_string(v)
  if v == nil or v == "" then
    return nil
  end
  if type(v) == "string" or type(v) == "number" then
    return tostring(v)
  end
  return nil
end


-- Thread id: conf.session_key, and nowhere else.
--   1. the request header of that name;
--   2. the JSON body at that name. A key with dots is a path from the root of
--      the body ("params.thread_id" is body.params.thread_id); a key with none
--      is a top-level field. A top-level field whose name literally contains
--      dots is also accepted.
-- No other part of the request is searched: not the A2A contextId, not
-- mcp-session-id. Point session_key at whichever the caller actually sends,
-- for example "params.message.contextId".
local function resolve_session_id(conf, body)
  local key = conf and conf.session_key
  if type(key) ~= "string" or key == "" then
    key = "X-Reva-Session-Id"
  end

  local from_hdr = scalar_string(kong.request.get_header(key))
  if from_hdr then
    return from_hdr
  end

  if type(body) ~= "table" then
    return nil
  end
  return scalar_string(body[key]) or scalar_string(get_at_path(body, key))
end


local function looks_like_jwt(token)
  return type(token) == "string" and token:match("^[^%.]+%.[^%.]+%.[^%.]+$") ~= nil
end


-- conf.reva_host is optional (schema default api.reva.ai). Host-only values
-- get https:// so resty.http can call them.
local function reva_base_url(conf)
  local host = conf and conf.reva_host
  if type(host) ~= "string" or host == "" then
    host = "api.reva.ai"
  end
  host = host:gsub("/+$", "")
  if not host:find("^https?://") then
    host = "https://" .. host
  end
  return host
end


local function call_rtg(conf, payload, traceparent, request_id, user_bearer, txn_token, thread_id)
  local url = reva_base_url(conf) .. RTG_EVAL_PATH

  local token, terr = rtg_credential(conf)
  if not token then
    return nil, terr
  end

  -- X-API-Token is the gateway credential. X-Reva-Token-Request asks Reva to
  -- return a transaction token on an allow. Authorization is the user access
  -- JWT. An earlier hop's token is sent as X-Transaction-Token; Reva takes the
  -- nested hop's subject (the calling agent) from it.
  local headers = {
      ["Content-Type"]          = "application/json",
    ["X-API-Token"]           = "Bearer " .. token,
    ["X-Reva-Token-Request"]  = "transaction",
      ["traceparent"]           = traceparent,
      ["x-ms-correlation-id"]   = request_id,
  }
  if looks_like_jwt(user_bearer) then
    headers["Authorization"] = "Bearer " .. user_bearer
  end
  if type(txn_token) == "string" and txn_token ~= "" then
    headers["X-Transaction-Token"] = txn_token
  end
  if type(thread_id) == "string" and thread_id ~= "" then
    headers["X-Reva-Thread-Id"] = thread_id
  end

  local opts = {
    method     = "POST",
    body       = payload,
    headers    = headers,
    timeout    = RTG_TIMEOUT_MS,
    ssl_verify = conf.ssl_verify,
  }

  local last_err
  for attempt = 0, RTG_RETRIES do
    local res, rerr = http_request_uri(url, opts)
      if res then
        return res
    end
        last_err = rerr
        kong.log.warn("[reva-ai-runtime-authorization] RTG call attempt ", attempt + 1, " failed: ", rerr)
      end

  return nil, last_err
end


-- Best-effort report of one finished chat turn to Reva. It never fails the
-- client request.
-- Synchronous HTTP (no ngx.timer): streaming Custom Policies forbid timers,
-- and the Kong response phase allows cosockets when buffering is enabled.
local function summarize_trace(conf, trace_id, thread_id, output)
  if conf.debug then
    kong.log.notice("[reva-ai-runtime-authorization] summarize: ENTER trace_id=",
                    tostring(trace_id), " thread_id=", tostring(thread_id),
                    " output_bytes=", tostring(type(output) == "string" and #output or 0))
  end

  if type(trace_id) ~= "string" or trace_id == "" then
    kong.log.warn("[reva-ai-runtime-authorization] summarize: SKIP empty trace_id")
    return
  end

  local token, terr = rtg_credential(conf)
  if not token then
    kong.log.warn("[reva-ai-runtime-authorization] summarize: SKIP no credential: ", terr)
    return
  end

  local body = { trace_id = trace_id }
  if type(thread_id) == "string" and thread_id ~= "" then
    body.thread_id = thread_id
  end
  if type(output) == "string" and output ~= "" then
    body.output = truncate(output, RTG_SUMMARIZE_OUTPUT_MAX)
  end

  local payload = cjson.encode(body)
  if not payload then
    kong.log.warn("[reva-ai-runtime-authorization] summarize: SKIP could not encode body")
    return
  end

  local url = reva_base_url(conf) .. RTG_SUMMARIZE_PATH
  local output_bytes = type(body.output) == "string" and #body.output or 0

  local headers = {
    ["Content-Type"]  = "application/json",
    ["Authorization"] = "Bearer " .. token,
    ["X-API-Origin-App"] = "KONG",
  }
  if body.thread_id then
    headers["X-Reva-Thread-Id"] = body.thread_id
  end

  kong.log.info("[reva-ai-runtime-authorization] summarize: POST ", url,
                " trace_id=", trace_id)

  local res, rerr = http_request_uri(url, {
    method     = "POST",
    body       = payload,
    headers    = headers,
    timeout    = RTG_SUMMARIZE_TIMEOUT_MS,
    ssl_verify = conf.ssl_verify,
  })
  if not res then
    kong.log.warn("[reva-ai-runtime-authorization] summarize: HTTP FAIL ", rerr)
    return
  end
  if res.status == 202 then
    kong.log.info("[reva-ai-runtime-authorization] summarize: ACCEPTED 202 trace_id=",
                  trace_id, " output_bytes=", tostring(output_bytes))
  else
    kong.log.warn("[reva-ai-runtime-authorization] summarize: HTTP ", res.status,
                  " for trace_id=", trace_id, " body=",
                  truncate(tostring(res.body or ""), 300))
  end
end


-- Reva Trust Guardian answers a denial with HTTP 403 and a body carrying decision:false,
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
      -- Defensive fallback for a response body that does not decode cleanly.
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

-- Request body decoded as JSON when its media type is a JSON one that Kong's
-- own parser does not handle (application/a2a+json, application/*+json).
-- Returns nil for anything else, or when the body is unavailable (for example
-- larger than Kong's in-memory buffer) or not a JSON object or array.
local function json_body_from_raw()
  local content_type = kong.request.get_header("content-type")
  if type(content_type) ~= "string" or not content_type:lower():find("json", 1, true) then
    return nil
  end
  local ok, raw = pcall(kong.request.get_raw_body)
  if not ok or type(raw) ~= "string" or raw == "" then
    return nil
  end
  local decoded = cjson.decode(raw)
  if type(decoded) == "table" then
    return decoded
  end
  return nil
end


function RevaRTG:access(conf)
  local path   = kong.request.get_path() or ""
  local method = kong.request.get_method() or "GET"

  local ok, body = pcall(kong.request.get_body)
  if not ok or type(body) ~= "table" then
    -- Kong parses only application/json. A2A over HTTP+JSON uses
    -- application/a2a+json, so read any JSON media type ourselves.
    body = json_body_from_raw() or {}
  end

  local call, skip_reason = classify(conf, method, body, path)
  if not call then
    if conf.debug then
      kong.log.notice("[reva-ai-runtime-authorization] skipping ", method, " ", path, ": ", skip_reason)
    end
    return
  end

  -- Token evaluation takes the user from the JWT as subject/principal.
  local user, user_err = resolve_user(conf)
  if user == "" then
    return kong.response.exit(401, {
      message = conf.deny_message,
      reason  = user_err or "missing user identity",
    })
  end

  -- Trace correlation: reuse the caller's traceparent so a multi-agent chain
  -- keeps one id, otherwise mint one for this entry point. Entry reservation
  -- is keyed on trace-id only — span id may change per hop under W3C.
  local traceparent = kong.request.get_header("traceparent")
                   or kong.request.get_header("fly-traceparent")
                   or ""
  if traceparent == "" then
    traceparent = mint_traceparent()
  end
  local trace_id = trace_id_from_traceparent(traceparent)
  if not trace_id then
    -- Malformed inbound header: mint a valid one so we still have a trace-id.
    traceparent = mint_traceparent()
    trace_id = trace_id_from_traceparent(traceparent)
  end

  local request_id = kong.request.get_header("fly-request-id")
                  or kong.request.get_header("x-request-id")
                  or kong_request_id()

  -- Thread id the caller supplied on this request (not local chat history).
  -- conf.session_key is searched in the request header and the JSON body.
  -- It is only SENT to Reva on the first hop of a turn (see thread_id below).
  local session_id = resolve_session_id(conf, body)

  -- Reserve entry BEFORE the evaluation call so a nested hop cannot steal "first"
  -- while we are still in call_rtg.
  local is_entry_hop = reserve_entry(conf, trace_id)

  local prompt = call.prompt or ""
  if prompt == "" then
    prompt = call.action .. " " .. call.res_id
  end

  -- Token evaluation body: business prompt at the root, Reva fields under rtg/a2a.
  local prompt_key = conf.prompt_key
  if type(prompt_key) ~= "string" or prompt_key == "" then
    prompt_key = "content"
  end

  local resource = { type = call.res_type, id = call.res_id }
  if call.action == "invokeAgent" or call.action == "invokeTool" then
    resource.endpoint = kong_service_url()
  end

  -- Later hops carry X-Transaction-Token; Reva derives the subject (the
  -- token's agent) and the principal from it, so no subject or principal is
  -- sent. The first call of a turn (no prior token) sends the User from the JWT.
  --
  -- transmission.role is the speaker Reva records for the turn. Earlier user
  -- requests are recalled only from hops with role=user, so the first call (the
  -- end user's utterance) is "user". Later hops stay "agent".
  local prior_txn = inbound_txn_token()
  local hop_role = "agent"
  if prior_txn == "" then
    hop_role = "user"
  elseif type(call.role) == "string" and call.role ~= "" then
    hop_role = call.role
  end
  local a2a = {
    action   = { name = call.action },
    resource = resource,
    transmission = {
      promptKey = prompt_key,
      role      = hop_role,
      content   = prompt,
    },
  }
  if prior_txn == "" then
    a2a.subject   = { type = "User", id = user }
    a2a.principal = { type = "User", id = user }
  else
    kong.log.info("[reva-ai-runtime-authorization] nested hop: omitting body subject/principal; ",
                  "prior txn token present (", #prior_txn, " bytes)")
  end
  -- The thread is recorded on the first hop of a turn only. A later hop
  -- carries the prior transaction token and Reva joins it to the thread through
  -- the trace id, so sending the thread id again could only split the thread
  -- when a hop carries a different one.
  --
  -- Reva stamps the decision log's thread id from threadId only. session.id is
  -- kept for callers that still read it; X-Reva-Thread-Id is also set in
  -- call_rtg.
  local thread_id = nil
  if prior_txn == "" and type(session_id) == "string" and session_id ~= "" then
    thread_id = session_id
    a2a.threadId = thread_id
    a2a.session  = { id = thread_id }
  elseif prior_txn ~= "" and type(session_id) == "string" and session_id ~= "" then
    kong.log.info("[reva-ai-runtime-authorization] nested hop: thread id ", session_id,
                  " not sent; Reva joins this hop to its thread through the trace")
  end

  -- Name/value pairs from the request body (see "context variables"). They
  -- describe this call, so every hop sends its own.
  a2a.context = call.context
  local dropped = call.context_dropped
  if conf.debug and dropped and #dropped > 0 then
    kong.log.notice("[reva-ai-runtime-authorization] context pairs not sent: ",
                    concat(dropped, "; "),
                    dropped.more and (" and " .. dropped.more .. " more") or "")
  end

  local root = { ["rtg/a2a"] = a2a }
  root[prompt_key] = prompt
  local payload = cjson.encode(root)

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

  kong.log.notice("[reva-ai-runtime-authorization] evaluating ", call.action, " ", call.res_id,
                  " payload=", payload)

  local started = ngx.now()
  local res, err = call_rtg(conf, payload, traceparent, request_id,
                            header_token("authorization"),
                            prior_txn,
                            thread_id)
  -- Reva turns a whole request away (HTTP 400) when one context pair is outside
  -- what it reads. The pairs are filtered above, but if Reva's rules ever move
  -- ahead of this filter, evaluate the call without them rather than lose the
  -- decision.
  if res and res.status == 400 and a2a.context then
    kong.log.warn("[reva-ai-runtime-authorization] RTG refused the request with context; ",
                  "evaluating again without it")
    a2a.context = nil
    payload = cjson.encode(root)
    res, err = call_rtg(conf, payload, traceparent, request_id,
                        header_token("authorization"),
                        prior_txn,
                        thread_id)
  end
  local elapsed_ms = (ngx.now() - started) * 1000

  local allowed, decision_err, decoded
  if res then
    allowed, decision_err, decoded = decision_from(res)
  else
    decision_err = err or "RTG unreachable"
  end

  kong.ctx.shared.reva_traceparent = traceparent
  kong.ctx.shared.reva_trace_id    = trace_id
  kong.ctx.shared.reva_allowed     = allowed
  kong.ctx.shared.reva_latency_ms  = elapsed_ms

  if allowed == nil then
    kong.log.err("[reva-ai-runtime-authorization] no decision (", decision_err, ") after ",
                 fmt("%.1f", elapsed_ms), "ms; fail_open=", tostring(conf.fail_open))
    if conf.fail_open then
      -- Proxying without a decision: keep reservation so nested hops stay nested.
      if conf.forward_traceparent then
        kong.service.request.set_header("traceparent", traceparent)
      end
      if is_entry_hop then
        arm_entry(call, trace_id, thread_id)
      end
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
                    " for ", user, ": ", reason, " (proxying anyway)")
      kong.ctx.shared.reva_monitor_would_deny = true
    else
      -- No summarize/clear on deny; hop_ttl GC. Next turn mints a new TP.
      return kong.response.exit(conf.deny_status, {
        message = conf.deny_message,
        reason  = reason,
      })
    end
  end

  -- Authorized (or monitor-proxying). Only the entry hop summarizes when this
  -- HTTP request completes (answer back to the turn's caller).
  kong.log.info("[reva-ai-runtime-authorization] after-allow action=", call.action,
                " res=", call.res_id,
                " is_entry_hop=", tostring(is_entry_hop),
                " trace_id=", tostring(trace_id),
                " thread_id=", tostring(thread_id))

  local minted = decoded and decoded.token
  if type(minted) == "string" and minted ~= "" then
    -- Forward under both header names so a caller can pass the next hop on either.
    kong.service.request.set_header("X-Transaction-Token", minted)
    kong.service.request.set_header("X-REVA-TOKEN", minted)
  else
    kong.log.warn("[reva-ai-runtime-authorization] token evaluation allow returned no transaction token for ",
                  call.action, " ", call.res_id)
  end

  if conf.forward_traceparent then
    kong.service.request.set_header("traceparent", traceparent)
  end

  if is_entry_hop then
    arm_entry(call, trace_id, thread_id)
  end
end


-- Text from an A2A Message-shaped table ({parts:[...]} or nested message).
local function a2a_message_text(msg)
  if type(msg) ~= "table" then
    return ""
  end
  local parts = msg.parts
  if type(parts) ~= "table" and type(msg.message) == "table" then
    parts = msg.message.parts
  end
  return a2a_parts_text(parts)
end


-- Final answer from an A2A Task: status.message, then artifacts' parts (in order).
local function a2a_task_text(task)
  if type(task) ~= "table" then
    return ""
  end
  local status = task.status
  if type(status) == "table" then
    local from_status = a2a_message_text(status.message)
    if from_status ~= "" then
      return from_status
    end
  end
  local artifacts = task.artifacts
  if type(artifacts) == "table" then
    local acc = {}
    for _, art in ipairs(artifacts) do
      if type(art) == "table" then
        local t = a2a_parts_text(art.parts)
        if t ~= "" then
          acc[#acc + 1] = t
        end
      end
    end
    if #acc > 0 then
      return concat(acc, "\n")
    end
  end
  return a2a_message_text(task)
end


-- Pull the agent's final answer out of a buffered upstream body. Covers OpenAI
-- chat.completions, MCP tools/call, A2A Message and Task (JSON-RPC and REST),
-- and a few plain agent shapes. Returns nil only when nothing usable is found.
local function extract_assistant_text(body)
  if type(body) ~= "string" or body == "" then
    return nil
  end

  local ok, decoded = pcall(cjson.decode, body)
  if not ok or type(decoded) ~= "table" then
    -- Plain text / non-JSON body: report as-is (capped by summarize_trace).
    return body
  end

  local text

  -- OpenAI chat.completions (content may be a string or a parts array).
  local choices = decoded.choices
  if type(choices) == "table" and type(choices[1]) == "table" then
    local first = choices[1]
    local msg = first.message
    if type(msg) == "table" then
      if type(msg.content) == "string" then
        text = msg.content
      elseif type(msg.content) == "table" then
        text = a2a_parts_text(msg.content)
      end
    end
    if (not text or text == "") and type(first.text) == "string" then
      text = first.text
    end
  end

  -- JSON-RPC: A2A Message/Task in result, or MCP tools/call content.
  if (not text or text == "") and decoded.jsonrpc ~= nil then
    local r = decoded.result
    if type(r) == "string" and r ~= "" then
      text = r
    elseif type(r) == "table" then
      text = a2a_task_text(r)
      if text == "" and type(r.content) == "table" then
        text = a2a_parts_text(r.content)
      elseif text == "" and type(r.content) == "string" then
        text = r.content
      end
      if text == "" then
        local enc_ok, enc = pcall(cjson.encode, r)
        if enc_ok and type(enc) == "string" and enc ~= "" then
          text = enc
        end
      end
    elseif type(decoded.error) == "table" then
      text = "error: " .. tostring(decoded.error.message or "unknown")
    end
  end

  -- A2A REST binding: the Message or Task is the body itself (no JSON-RPC).
  if (not text or text == "") then
    text = a2a_task_text(decoded)
  end

  -- Common agent reply fields (AgentCore / custom gateways).
  if (not text or text == "") then
    for _, key in ipairs({ "message", "reply", "text", "content", "output" }) do
      local v = decoded[key]
      if type(v) == "string" and v ~= "" then
        text = v
        break
      elseif type(v) == "table" then
        local nested = a2a_message_text(v)
        if nested == "" then
          for _, nk in ipairs({ "message", "reply", "text", "content" }) do
            if type(v[nk]) == "string" and v[nk] ~= "" then
              nested = v[nk]
              break
            end
          end
        end
        if nested ~= "" then
          text = nested
          break
        end
      end
    end
  end

  if type(text) == "string" then
    text = text:match("^%s*(.-)%s*$") or text
    if text ~= "" then
      return text
    end
  end

  -- Last resort: keep the raw body so summarize still stores an answer.
  return body
end


-- Summarize here: enable_buffering + get_raw_body. Cosockets are allowed.
-- Streaming forbids implementing response together with body_filter/header_filter.
function RevaRTG:response(conf)
  if not kong.ctx.shared.reva_summarize or kong.ctx.shared.reva_summarized then
    return
  end

  local body
  local ok, raw = pcall(function()
    return kong.service.response.get_raw_body()
  end)
  if ok and type(raw) == "string" then
    body = raw
  end

  local tid = kong.ctx.shared.reva_trace_id
  local thread = kong.ctx.shared.reva_thread_id
  local text = extract_assistant_text(body)
  if conf.debug then
    kong.log.notice("[reva-ai-runtime-authorization] response-phase summarize trace_id=",
                    tostring(tid),
                    " body_bytes=", tostring(body and #body or 0),
                    " output_bytes=", tostring(type(text) == "string" and #text or 0))
  end
  if type(tid) == "string" and tid ~= "" then
    summarize_trace(conf, tid, thread, text)
    kong.ctx.shared.reva_summarized = true
    clear_entry(tid)
  end
end


-- Clear the entry reservation if response never ran (e.g. early abort).
-- No HTTP here — cosockets are disabled in log_by_lua*.
function RevaRTG:log(conf)
  local stream_tid = kong.ctx.shared.reva_stream_entry
  if type(stream_tid) == "string" and stream_tid ~= "" then
    clear_entry(stream_tid)
    return
  end

  if not kong.ctx.shared.reva_summarize or kong.ctx.shared.reva_summarized then
    return
  end

  local tid = kong.ctx.shared.reva_trace_id
  kong.log.warn("[reva-ai-runtime-authorization] log-phase: summarize did not run ",
                "in response phase; clearing entry for ", tostring(tid))
  if type(tid) == "string" and tid ~= "" then
    clear_entry(tid)
  end
end


return RevaRTG
