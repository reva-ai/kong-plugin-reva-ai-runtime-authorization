# Reva AI Runtime Authorization

Kong AI Gateway AI Custom Policy: `reva-ai-runtime-authorization`

Authorizes agent, MCP, A2A and LLM traffic passing through Kong AI Gateway by
evaluating every call against Reva Trust Guardian, Reva's policy decision point.
A call is proxied only when policy allows it.

Requires Kong AI Gateway 2.2 or later.

```
kong/plugins/reva-ai-runtime-authorization/
├── handler.lua      what runs on each request
└── schema.lua       what you fill in when configuring the policy
```

Those two files are the whole policy. A custom policy takes nothing else, so
there are no extra modules to require.

See [`INSTALL.txt`](INSTALL.txt) to add and configure it.

## What it does

On every request, in the `access` phase:

1. **Classify the call.** From the request: OpenAI `messages` →
   `invokeModel`, MCP `tools/call` → `invokeTool`, an A2A send-message request
   (see [A2A requests](#a2a-requests)) → `invokeAgent`. A model call's resource
   id is `body.model`, a tool call's is the tool name, and an agent call's is
   the Service URL. Anything that matches none of those shapes is proxied
   untouched.

2. **Resolve identity.** The user comes from the JWT claim named by
   `jwt_user_claim` (default `sub`). On the first call of a turn that user is
   the caller; on a later hop Reva takes the agent and the user from the
   transaction token the call carries.

3. **Correlate the turn.** The inbound `traceparent` is reused, or created when
   absent, and forwarded upstream. Its trace id ties the hops of one turn
   together. The policy keeps no chat history; Reva Trust Guardian does. The
   thread id is read from `session_key` only, on the first call of a turn only.

4. **Evaluate.** The policy sends the call to Reva Trust Guardian on `reva_host`
   and waits for a decision. An allow returns a transaction token.

5. **Enforce.** An allow decision proxies the request upstream with the
   `traceparent` attached. Anything else terminates it with `deny_status`
   (default `403`) and `deny_message`, unless `monitor_mode` is on, in which
   case the would-be denial is logged and the request proxied anyway.

6. **Report the turn.** When the first call of a turn completes, the policy
   reports the turn to Reva Trust Guardian, on a best-effort basis, so later
   turns can be evaluated against it. A streamed A2A response is not reported;
   see [A2A requests](#a2a-requests).

An agent's resource id is the Service URL, never a request path segment.
Two agents are two Services on two hosts, so the host alone identifies the
resource.

A tool appears in a Reva policy and in the decision log as
`<mcp server>/<tool>`, for example `Tool::"ticketing-mcp/open_ticket"`. Register
the MCP server in Reva with the same base URL as its Service.

## What your application must forward

The policy joins the hops of one turn only if every service in the chain passes
on what it received. Each agent must send these headers, spelled as shown, on
every call it makes through the gateway: to a model, to an MCP server and to
another agent.

| Header | Send it | What it does |
|---|---|---|
| `Authorization: Bearer <JWT>` | on every call | Names the user, through `jwt_user_claim`. Forward the end user's token unchanged. A call without it is refused with `401`. |
| `traceparent` | on every call | The W3C trace context. Its trace id makes separate calls one turn. The first service starts one per user message; every later call forwards it unchanged. If it is missing, the policy creates one and Reva cannot link the call to its turn. |
| `X-Transaction-Token` | on every call after the first | Issued by Reva Trust Guardian on an allow and added by the policy to the upstream request. Forward it exactly as received. Its presence marks a later hop. |
| the thread id, at the place `session_key` names (default: header `X-Reva-Session-Id`) | on the first call of a turn only | Groups the turns of one chat. Later hops do not need it. |

A call with no `X-Transaction-Token` is the first call of a turn: the user comes
from the JWT, and the thread id is read. A call that carries one is a later hop:
Reva takes the agent and the user from the token, and no thread id is needed. An
agent that drops the token therefore makes its next call look like a new first
call by the user.

The transaction token is short-lived; Reva sets the lifetime for your
deployment. A service that waits too long between receiving a request and making
its next call finds it expired, and Reva refuses the call. The response carries
`authorization service unavailable` and the data plane log shows
`X-Transaction-Token validation failed`.

## A2A requests

An agent call is any A2A request that sends a message to an agent. The policy
evaluates it in both protocol versions and both bindings:

| Operation | JSON-RPC method, 0.3 | JSON-RPC method, 1.0 | HTTP+JSON path ends with | Response |
|---|---|---|---|---|
| Send a message | `message/send` | `SendMessage` | `/message:send` | one reply |
| Send a message, streamed | `message/stream` | `SendStreamingMessage` | `/message:stream` | server-sent events |

- **HTTP+JSON** is recognized by the end of the path, so a version or tenant
  prefix (`/v1/message:send`, `/acme/message:send`) is fine. The body is the
  request itself, `{"message": {...}}`, with no JSON-RPC envelope.
- **Media type.** A body is read as JSON for any JSON media type, including
  `application/a2a+json`, which A2A 1.0 recommends for HTTP+JSON.
- **What is read.** The text of every text part, with or without a `kind` tag;
  and each data part as its JSON text, up to 8192 bytes. File parts carry no
  readable text and are skipped. A message with no readable content is still
  evaluated, with the prompt `invokeAgent <Service URL>`. The thread id is not
  taken from `contextId` automatically: set `session_key` to where your callers
  put it, for example `params.message.contextId`.
- **Streamed responses** are passed through as they are produced, and the call
  is still evaluated before it is sent. The turn is not reported to Reva Trust
  Guardian when the stream ends.
- **Not evaluated:** requests that read or manage tasks (`tasks/*`, `GetTask`,
  `CancelTask`, `SubscribeToTask`, and the push-notification configuration
  methods), agent-card requests, the gRPC binding, and JSON-RPC batches.

## Configuration

`auth_token` is the only required field; everything else has a working
default. Each field below carries the same description that Konnect renders
in the policy form.

**Connection**

| Field | Default | Description |
|---|---|---|
| `reva_host` | `api.reva.ai` | Host or base URL of your Reva tenant, for example `api.example.reva.ai` or `https://api.example.reva.ai`. A value you set overrides the default. Host-only values are called over HTTPS. |
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
| `jwt_user_claim` | `sub` | JWT claim read from the bearer token to identify the user. Common values are `sub`, `preferred_username` and `cognito:username`. |
| `jwt_groups_claim` | `groups` | JWT claim holding the user's group memberships, sent to Reva Trust Guardian as groups a policy can match. Use `roles` for RBAC tokens, `realm_access.roles` for Keycloak, or `cognito:groups` for Cognito. |

**Payload**

| Field | Default | Description |
|---|---|---|
| `prompt_key` | `content` | Name of the field that carries the prompt text to Reva. Must match what your policy expects to read. |
| `session_key` | `X-Reva-Session-Id` | Where the thread id is read: an HTTP request header of this name first, then the JSON body. Use dots for a nested body field, such as `params.thread_id`. Nothing else is searched. Sent to Reva Trust Guardian on a turn's first call only. |

**Turns and diagnostics**

| Field | Default | Description |
|---|---|---|
| `hop_ttl` | `3600` | How long, in seconds, the policy keeps a turn open when its first call never finishes. Set it longer than your slowest agent turn. |
| `forward_traceparent` | `true` | Pass the `traceparent` used for the authorization decision on to the upstream service, so one trace id spans the gateway and your backend. |
| `debug` | `false` | Log each decision and the request sent to Reva Trust Guardian at notice level. Use it while tuning policy; leave it off in production. |

`auth_token` is `referenceable`: in production, give it a vault reference such
as `{vault://env/reva-ai-runtime-authorization-token}` rather than a literal.

## Request buffering

The policy reads the request body, so routes it covers need
`request_buffering: true` (the default). MCP endpoints stream over SSE and
additionally need `response_buffering: false`.

## Running it as a streaming or an installed policy

Kong AI Gateway runs a custom policy in one of two ways. Reva AI Runtime
Authorization works with either.

**Streaming.** Create the AI Custom Policy with `type` `streaming`, sending the
contents of `schema.lua` as `schema` and `handler.lua` as `handler`. Konnect
sends the handler to every data plane, so the data plane image does not change.
Start each data plane with `KONG_CUSTOM_PLUGIN_STREAMING_ENABLED=on` and
`KONG_UNTRUSTED_LUA=lax`; the policy makes an outbound HTTPS call to Reva Trust
Guardian, which the default `strict` sandbox blocks.

**Installed.** Put the two files on every data plane node and create the AI
Custom Policy with `type` `installed`, sending only `schema.lua` as `schema`:

```sh
luarocks make
luarocks pack kong-plugin-reva-ai-runtime-authorization 2.0.0-1
```

Then on each data plane node:

```sh
luarocks install kong-plugin-reva-ai-runtime-authorization-2.0.0-1.all.rock
```

and add `reva-ai-runtime-authorization` to the `plugins` directive in
`kong.conf` (`KONG_PLUGINS`). The data plane must have the code; the control
plane only ever receives `schema.lua`.
