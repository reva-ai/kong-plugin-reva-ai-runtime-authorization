# Reva AI Runtime Authorization

Kong plugin identifier: `reva-ai-runtime-authorization`

Authorizes agent, MCP, A2A and LLM traffic passing through Kong by evaluating
every call against Reva Trust Guardian, Reva's policy decision point. A call
is proxied only when policy allows it.

Requires Kong Gateway 3.12 or later.

```
kong/plugins/reva-ai-runtime-authorization/
├── handler.lua      what runs on each request
└── schema.lua       what you fill in when configuring the plugin
```

Those two files are the whole plugin. Konnect accepts nothing else for a custom
plugin, so there are no extra modules to require.

See [`INSTALL.txt`](INSTALL.txt) to install and configure it.

## What it does

On every request, in the `access` phase:

1. **Classify the call.** Path prefixes (default `/llm`, `/mcp/<server>/`,
   `/a2a/`) identify the call type while `path_identification` is on. If the
   path matches nothing, or that group is off, the plugin inspects the body
   instead (OpenAI `messages`, MCP `tools/call`, A2A `message/send`). Anything
   that matches none of those shapes is proxied untouched.

2. **Resolve identity.** The user comes from the JWT claim named by
   `jwt_user_claim` (default `sub`). With `authorize_agent` off — the default —
   that user is both `subject` and `principal` on every hop. With it on, the
   entry hop of a turn is still evaluated as the user; only a later hop, made by
   something that already received an authorized hop, is treated as an agent.
   An agent id is required only on those later hops.

3. **Record the hop.** The inbound `traceparent` is reused, or minted when
   absent, and this call is recorded against it, so Reva Trust Guardian sees the
   whole delegation path rather than just the current leg. `context.hops` and
   `context.conversation.messages` carry this turn so far; prior turns of the
   same chat go in `session.messages`. The first call on a fresh `traceparent`
   therefore sends an empty hop chain.

4. **Evaluate.** The plugin POSTs the evaluation request to
   `/pdp/v2/ai/evaluation` on `reva_host_url`.

5. **Enforce.** An allow decision proxies the request upstream with the
   `traceparent` attached. Anything else terminates it with `deny_status`
   (default `403`) and `deny_message`, unless `monitor_mode` is on, in which
   case the would-be denial is logged and the request proxied anyway.

An agent's `resource.id` is the Kong Service URL, never a request path segment.
Two agents are two Kong Services on two hosts, so the host alone identifies the
resource.

## Configuration

`reva_host_url` and `auth_token` are the only required fields; everything else
has a working default. Each field below carries the same description that
Konnect renders in the plugin form.

**Connection**

| Field | Default | Description |
|---|---|---|
| `reva_host_url` | **required** | Base URL of your Reva tenant, for example `https://api.example.reva.ai`. The plugin appends `/pdp/v2/ai/evaluation` and evaluates every matching call there. |
| `auth_token` | **required** | Bearer token Kong presents to Reva Trust Guardian on every evaluation. Find it in the Reva console under Settings. This field is referenceable — store it in a vault rather than inline. |
| `ssl_verify` | `true` | Verify the TLS certificate presented by Reva Trust Guardian. Turn this off only against a test instance with a self-signed certificate. |

**Enforcement**

| Field | Default | Description |
|---|---|---|
| `monitor_mode` | `false` | Evaluate every call and log the verdict, but never block. Use it to see what policy would refuse before you enforce it. |
| `fail_open` | `false` | Proxy the request when Reva Trust Guardian cannot be reached or returns no decision. Off by default, so an outage refuses calls rather than passing them unevaluated. |
| `deny_status` | `403` | HTTP status returned when a call is refused, either by policy or because no decision could be obtained. |
| `deny_message` | `Blocked by Reva` | Message returned to the caller in the response body when a call is refused. The specific reason is returned alongside it. |

**Identity**

| Field | Default | Description |
|---|---|---|
| `authorize_agent` | `false` | Make the calling agent the subject of each evaluation, which requires an agent id on the request. Leave it off to attribute every call to the user from the JWT instead. |
| `jwt_user_claim` | `sub` | JWT claim read from the bearer token to identify the user. Common values are `sub`, `preferred_username` and `cognito:username`. |
| `jwt_groups_claim` | `groups` | JWT claim holding the user's group memberships, sent to Reva Trust Guardian as groups a policy can match. Use `roles` for RBAC tokens, `realm_access.roles` for Keycloak, or `cognito:groups` for Cognito. |
| `agent_header` | `X-Reva-Agent-Id` | Request header carrying the calling agent's id. Read only when `authorize_agent` is on, and only when `identity_source` permits the header. |
| `require_identity_headers` | `true` | Reject a request that is missing the agent id rather than proxying it unevaluated. Applies only when `authorize_agent` is on; the user is always required. |
| `identity_source` | `header` | Where the calling agent's identity comes from. `consumer` reads it from an authenticated Kong Consumer and cannot be forged; `header` trusts the agent header as sent; `consumer_then_header` prefers the Consumer and falls back. |
| `consumer_id_field` | `username` | Which property of the authenticated Kong Consumer names the agent: `username`, `custom_id` or `id`. |

**Call classification**

| Field | Default | Description |
|---|---|---|
| `path_identification` | — | How the plugin decides whether a call is an LLM, MCP or A2A request. |
| &nbsp;&nbsp;`enabled` | `true` | Classify calls by their request path prefix. Turn this off when your LLM, MCP and A2A services share arbitrary URLs; the plugin then inspects the request body instead. |
| &nbsp;&nbsp;`llm_path_prefix` | `/llm` | Requests under this path prefix are treated as OpenAI-style model invocations, such as chat completions. |
| &nbsp;&nbsp;`mcp_path_prefix` | `/mcp/` | MCP tool calls are identified by this path prefix. The next path segment names the MCP server, for example `/mcp/github/`. Only `tools/call` is evaluated. |
| &nbsp;&nbsp;`a2a_path_prefix` | `/a2a/` | A2A agent invocations are identified by this path prefix. The target agent is identified by the Kong Service host, not by the path. Only `message/send` is evaluated. |

**Payload and chat history**

| Field | Default | Description |
|---|---|---|
| `prompt_key` | `content` | Names the field carrying the prompt text in the evaluation request. Must match what your policy expects to read. |
| `a2a_content_path` | `params.message.parts` | Path within the JSON-RPC body to the current A2A message. Each part's text is joined into one prompt. Change it only if your callers place the message elsewhere. |
| `a2a_history_path` | `params.history` | Path within the JSON-RPC body to prior conversation turns. Not part of the A2A specification — point this wherever your callers store history. |
| `a2a_routing_path` | `params.routing` | Path within the JSON-RPC body to the declared hop chain. Not part of the A2A specification — point this wherever your callers declare routing. |
| `session_header` | `X-Reva-Session-Id` | Request header carrying the chat session id, which groups separate requests into one conversation. Without it every request looks like a fresh chat and no history is sent. |
| `max_session_messages` | `10` | How many completed turns to send as chat history, newest kept. Reva Trust Guardian rejects a request body over 1 MiB, so unbounded history would eventually fail every call. |
| `session_ttl` | `86400` | How long a chat's turn history survives on the data plane, in seconds. After this, the next request starts a new conversation. |

**Data plane state and diagnostics**

| Field | Default | Description |
|---|---|---|
| `hop_storage_dict` | `reva_ai_runtime_authorization` | Name of the nginx shared dictionary holding hop chains and chat history. It must be a dictionary you declare for this plugin, not one Kong manages — those are flushed on reload, erasing history mid-conversation. |
| `hop_ttl` | `3600` | How long a hop chain survives on the data plane, in seconds. A chain older than this starts over as a fresh call. |
| `forward_traceparent` | `true` | Pass the `traceparent` used for the authorization decision on to the upstream service, so one trace id spans the gateway and your backend. |
| `debug` | `false` | Log each decision and the request sent to Reva Trust Guardian at notice level. Use it while tuning policy; leave it off in production. |

`auth_token` is `referenceable`: in production, give it a vault reference such
as `{vault://env/reva-ai-runtime-authorization-token}` rather than a literal.

## Request buffering

The plugin reads the request body, so routes it covers need
`request_buffering: true`. MCP endpoints stream over SSE and additionally need
`response_buffering: false`.

## Shared dictionary

The plugin needs an nginx shared dictionary for hop chains and chat history:

```
nginx_http_lua_shared_dict = reva_ai_runtime_authorization 64m
```

It must not be a dictionary Kong manages itself. `kong_db_cache` is flushed on
every configuration reload, which erases conversations in flight. Point
`hop_storage_dict` at the dictionary you declared.

## Packaging for self-hosted Kong

```sh
luarocks make
luarocks pack kong-plugin-reva-ai-runtime-authorization 0.1.0-1
```

Then on each data plane node:

```sh
luarocks install kong-plugin-reva-ai-runtime-authorization-0.1.0-1.all.rock
```

and add `reva-ai-runtime-authorization` to the `plugins` directive in `kong.conf`. In
hybrid mode the plugin code must be present on every data plane node; the
control plane only ever receives `schema.lua`.
