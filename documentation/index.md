---
title: 'Reva AI Runtime Authorization'
name: 'Reva AI Runtime Authorization'

content_type: plugin

publisher: reva
description: "Authorize every model, tool and agent call passing through your {{site.ai_gateway_name}} against a Reva policy store"

products:
  - gateway
  - ai-gateway

works_on:
  - on-prem
  - konnect

third_party: true

support_url: https://reva.ai
source_code_url: https://github.com/reva-ai/kong-plugin-reva-ai-runtime-authorization

icon: reva-ai-runtime-authorization.svg

search_aliases:
  - reva-ai-runtime-authorization
  - reva-pdp
  - reva
  - reva ai runtime authorization
  - runtime authorization
  - reva authorization
  - agentic authorization
  - agent authorization
  - mcp authorization
  - a2a authorization
  - Reva Trust Guardian
  - Reva Trust Guardian Authorization

tags:
  - ai
  - security

related_resources:
  - text: Reva documentation (access code required)
    url: https://docs.reva.ai/
  - text: Reva
    url: https://reva.ai

min_version:
  gateway: '3.12'
---

**Reva AI Runtime Authorization** authorizes agentic traffic at the gateway. Every
model call, tool call and agent-to-agent hop passing through your
{{site.ai_gateway_name}} is evaluated against a Reva policy store before it
reaches an upstream, and denied calls never leave {{site.base_gateway}}.

Unlike request-level filtering, `reva-ai-runtime-authorization` evaluates the **delegation chain**. It
correlates the hops of one agent turn on a shared `traceparent` and the turns of
one chat on a session id, so a policy can be written against what an agent is
actually doing across a conversation rather than a single request in isolation.

Integrating the Reva plugin into your {{site.ai_gateway}} allows you to:
* **Authorize three kinds of agentic call**: model invocations (`invokeModel`),
  MCP tool calls (`invokeTool`) and A2A agent invocations (`invokeAgent`).
* **Keep credentials off the application**: the application holds no model key
  and no policy credentials. It can only reach a model, a tool or another agent
  through the gateway, so authorization cannot be bypassed by the caller.
* **Fail closed by default**: if the Reva Trust Guardian cannot be reached, the
  request is refused rather than proxied unauthorized.

## Install the Reva AI Runtime Authorization plugin

The plugin is distributed as a LuaRocks module or as a set of Lua source files.

### Prerequisites

Before enabling the plugin, you need the following from Reva:

* The plugin `.rock` file or Lua sources. Contact [info@reva.ai](mailto:info@reva.ai) to obtain them.
* A static **authorization token**, available in the Reva console under
  **Settings → Connect to Reva Trust Guardian**.

## Installation steps

{% navtabs 'deployment' %}
{% navtab "Konnect" %}

{{site.konnect_short_name}} requires the custom plugin's `schema.lua` file to
create a plugin entry in the plugin catalog for your control plane. Upload the
`schema.lua` file to create a configurable entity in
{{site.konnect_short_name}}:

{% include_cached plugins/third-party-konnect-plugin.md %}
1. After uploading a schema to {{site.konnect_short_name}}, install `schema.lua`
   and `handler.lua` on each {{site.base_gateway}} data plane node. A node that
   does not have these files cannot run the plugin, and
   {{site.konnect_short_name}} reports the node as incompatible.
1. Follow the Dockerfile instructions on this page (switch tabs) to install the
   plugin on each node.

You can now configure this plugin like any other plugin in
{{site.konnect_short_name}}.

{% endnavtab %}
{% navtab "Docker" %}

```docker
FROM kong/kong-gateway:latest

USER root

COPY kong/plugins/reva-ai-runtime-authorization /opt/kong/kong/plugins/reva-ai-runtime-authorization
RUN chown -R kong:kong /opt/kong/kong/plugins/reva-ai-runtime-authorization

USER kong

ENV KONG_PLUGINS=bundled,reva-ai-runtime-authorization
ENV KONG_LUA_PACKAGE_PATH="/opt/kong/?.lua;;"

# Hop chains and chat history are held in a shared dictionary. It must be one
# Kong does not manage: kong_db_cache is flushed on every config reload, which
# would erase a conversation mid-flight.
ENV KONG_NGINX_HTTP_LUA_SHARED_DICT="reva_ai_runtime_authorization 64m"
```

{% endnavtab %}
{% navtab "kong.conf" %}

1. Install the plugin:

   ```sh
   luarocks install kong-plugin-reva-ai-runtime-authorization-0.1.0-1.all.rock
   ```

1. Append `reva-ai-runtime-authorization` to the `plugins` field in
   [`kong.conf`](/gateway/configuration/). Make sure the field isn't commented
   out.

   ```yaml
   plugins = bundled,reva-ai-runtime-authorization
   nginx_http_lua_shared_dict = reva_ai_runtime_authorization 64m
   ```

1. Restart {{site.base_gateway}}:

   ```sh
   kong restart
   ```

A plugin code change requires a restart, not only a config reload —
{{site.base_gateway}} loads Lua at worker startup.

{% endnavtab %}
{% endnavtabs %}

## Enabling the plugin

1. [Set up {{site.ai_gateway}}](/ai-gateway/get-started/) by creating a Service
   and a Route for each upstream you want governed.
1. Make sure the routes the plugin covers have `request_buffering` enabled — the
   plugin reads the request body. MCP endpoints stream over SSE and additionally
   need `response_buffering` disabled.
1. [Enable the Reva AI Runtime Authorization plugin](/plugins/reva-ai-runtime-authorization/examples/enable-reva-ai-runtime-authorization/).

## How a call is classified

By default the plugin uses
[`config.path_identification`](./reference/#schema--path-identification)
(a collapsible group, enabled on) to decide the call type from the request path:

| Path | Action | Resource id |
|---|---|---|
| [`config.path_identification.llm_path_prefix`](./reference/#schema--path-identification-llm-path-prefix) (default `/llm`) | `invokeModel` | the `model` in the request body |
| [`config.path_identification.mcp_path_prefix`](./reference/#schema--path-identification-mcp-path-prefix) (default `/mcp/`) | `invokeTool` | `<path-server>/<tool>` from the next path segment and `params.name` |
| [`config.path_identification.a2a_path_prefix`](./reference/#schema--path-identification-a2a-path-prefix) (default `/a2a/`) | `invokeAgent` | the Kong Service URL this route proxies to (`protocol://host[:port]`, never a path) |

Turn path identification off when LLM, MCP and A2A sit on arbitrary URLs. The
plugin then sniffs the body, in this order:

1. JSON-RPC `tools/call` → `invokeTool`, resource id `<Kong Service host>/<tool>`
2. JSON-RPC `message/send` → `invokeAgent`, resource id the Kong Service host
3. an OpenAI `messages` array → `invokeModel`, resource id `body.model`

If path identification is on and the path matches none of the prefixes, the
same sniff runs. Payloads that match none of those shapes are left alone.

Of the MCP methods, only `tools/call` is evaluated, and of the A2A methods
only `message/send`.

An Agent resource id is the Kong Service URL: always `protocol://host[:port]`
alone, never a path — even when the Kong Service has one configured — and never
the inbound request path. A policy therefore matches the host, for example
`Agent::"http://ticketing-agent:8003"`. Two agents are two Kong Services on two
hosts in this model, so the host alone identifies the resource.

## Identity

The human principal is always taken from the inbound `Authorization: Bearer`
JWT. The plugin decodes the payload (it does not verify the signature — put
[jwt](/plugins/jwt/) or [openid-connect](/plugins/openid-connect/) in front of
these routes) and reads [`config.jwt_user_claim`](./reference/#schema--jwt-user-claim)
(default `sub`). Nested claims use a dotted path (`user.id`); Cognito-style
keys such as `cognito:username` are a single claim name.

That value is always sent as `principal: { type: User, id: <claim> }`.

[`config.jwt_groups_claim`](./reference/#schema--jwt-groups-claim) (default
`groups`) is read from the same token and sent as the user's group memberships.
A policy can then be written against a group rather than a person — *anyone in
`Finance` may invoke this agent* — which is what makes a policy store scale past
naming individuals. Cognito-style arrays such as `cognito:groups` work as-is; a
token without the claim simply sends no groups.

A missing token, an unreadable JWT, or an empty claim is refused with `401`
before the Reva Trust Guardian is called. There is no header fallback: the human
principal comes from the token or the request does not proceed.

### `authorize_agent`

[`config.authorize_agent`](./reference/#schema--authorize-agent) defaults to
`false`. Agent-as-subject needs a caller that can send agent identity; until
then every LLM, MCP and A2A hop is still evaluated, with the User as both
`subject` and `principal`.

| `authorize_agent` | `subject` | Agent header |
|---|---|---|
| `false` (default) | `User::<jwt claim>` | not required, ignored if sent |
| `true`, entry hop of a turn | `User::<jwt claim>` | not required for this hop |
| `true`, every later hop | `Agent::<id>` | required via [`config.identity_source`](./reference/#schema--identity-source) |

The entry hop — the first hop of a turn, where no prior hop exists yet for this
`traceparent` — is always evaluated as the User, even with `authorize_agent`
on. It is the user's own action however it was relayed to reach the gateway;
only a later hop, made by something that already received a prior authorized
hop, is a real agent acting on its own. This is what lets a UI process that
merely forwards the user's first message stay a `User` subject on that one
call, with no special-cased routing or Kong configuration needed to achieve
it — the same global plugin instance handles both cases correctly from the
hop count alone.

When `authorize_agent` is true, [`config.require_identity_headers`](./reference/#schema--require-identity-headers)
(the default) refuses a request missing the agent header without calling the
Reva Trust Guardian — on hops where the agent header is actually required, i.e.
every hop after the entry hop.

### Where the agent identity comes from

Used only when `authorize_agent` is true.
[`config.identity_source`](./reference/#schema--identity-source) decides whether
the agent header can be believed:

| Value | Behavior |
|---|---|
| `header` (default) | Take the agent from [`config.agent_header`](./reference/#schema--agent-header) (default `X-Reva-Agent-Id`) as sent. Convenient behind a trusted network. |
| `consumer` | Take it from the Kong Consumer an authentication plugin resolved. A caller cannot forge this. |
| `consumer_then_header` | Prefer the Consumer, fall back to the header. |

[`config.consumer_id_field`](./reference/#schema--consumer-id-field) selects
which Consumer property names the agent: `username`, `custom_id` or `id`.

{:.warning}
> With `identity_source: header`, the agent header is an assertion rather than a
> credential — any caller that can reach the gateway can name a privileged agent
> and inherit its policy. On any gateway reachable from a network you do not
> control, set `identity_source: consumer` and put
> [key-auth](/plugins/key-auth/), [jwt](/plugins/jwt/) or
> [openid-connect](/plugins/openid-connect/) in front of these routes. They run
> before `reva-ai-runtime-authorization`, which has priority 1000, so the credential is resolved
> before this plugin looks at it.

With `identity_source: consumer` and no authenticated Consumer, the request is
refused with `401` rather than falling back to the header.

## Conversation context

Two collections are scoped to a single agent turn (one `traceparent`) and reset
on the next user message:

* `context.hops` — who invoked whom on this turn, excluding the call being
  evaluated. Each entry is `{ seq, subject, action.name, resource, time }`.
* `context.conversation.messages` — what was said on those hops:
  `{ seq, role, contentType, content, timestamp }`. User then assistant as the
  flow goes user → agent → agent.

Both exclude the current call, which is already `subject` / `action` /
`resource` and `transmission`. The first hop of a turn therefore sends
`hops: []` and empty conversation messages. Lengths always match.

When `authorize_agent` is false, every recorded hop's `subject` is the User.
When it is true, the first recorded hop is `User invokeAgent Agent::<id>` and
later hops are `Agent` plus the actual action and resource.

`session` is the **chat history**, not this turn:

* `session.id` — [`config.session_header`](./reference/#schema--session-header)
  (default `X-Reva-Session-Id`), else A2A `contextId`, else `mcp-session-id`.
* `session.turn` — the current turn number (`#pairs + 1`).
* `session.messages` — completed **prior** turns as
  `{ turn, request, response }` with `role` / `contentType` / `content` /
  `timestamp`. `response.role` is `assistant`.

Session correlation is opt-in with `authorize_agent`: with it off, `session`
is never populated and the shared-dict read/write it costs never runs. A
caller that sends no session header gets exactly this behavior already —
turning session tracking off for a plugin instance is the same as every
caller omitting the header, just deliberate rather than incidental.

Caller-supplied `{role, content}` history is paired into `session.messages`.
History lives only there — `context` never carries a second copy of it. On the
first turn of a chat there is no prior history, so `session.messages` is simply
empty; `context.conversation` already describes the turn in progress.

Where caller history is read:

| Call | Read from |
|---|---|
| Model | every entry in the request body's `messages` before the last user message |
| Tool | `params._meta.chatHistory`, or `params.metadata.chatHistory` |
| Agent | `params.message.metadata.chatHistory`, then [`config.a2a_history_path`](./reference/#schema--a2a-history-path) (default `params.history`) |

A tool or agent call carries no conversation of its own, so the caller has to
supply one. Without it the call is evaluated with no run-up — which matters
most for exactly the calls that act: a refund is unremarkable until you can see
the two turns that led to it.

A model message whose `content` is an array of parts rather than a string —
OpenAI's multimodal form — has its text parts joined and evaluated like any
other message. Image and audio parts are not sent to the Reva Trust Guardian.

The current A2A utterance is read from
[`config.a2a_content_path`](./reference/#schema--a2a-content-path)
(default `params.message.parts`, the A2A spec field); each part's `text` is
joined into `transmission` at [`config.prompt_key`](./reference/#schema--prompt-key)
(default `content`).

An agent call's chat id is read from `params.contextId`, falling back to
`params.message.contextId`, before the session header is consulted.
`maxHops` on [`config.a2a_routing_path`](./reference/#schema--a2a-routing-path)
(default `params.routing`) is carried as `context.maxHops`.

Turns are grouped by
[`config.session_header`](./reference/#schema--session-header) (default
`X-Reva-Session-Id`). Without that header every request looks like a new chat.
History is bounded by
[`config.max_session_messages`](./reference/#schema--max-session-messages) — the
Reva Trust Guardian rejects a body over 1 MiB before authorizing, so an
unbounded history would eventually fail every call.
[`config.session_ttl`](./reference/#schema--session-ttl) controls how long a
captured chat survives on the data plane.

A turn whose reply was never captured is left out of shm-built
`session.messages`. The Reva Trust Guardian requires a response on every entry
it is given, and losing one turn of history is better than losing the call.
Caller-supplied history does not have that gap: it is already paired.

## Authenticating to the Reva Trust Guardian

The plugin presents [`config.auth_token`](./reference/#schema--auth-token) on
every evaluation call. It is required.

`auth_token` is referenceable. Store it as a
[vault reference](/gateway/entities/vault/) rather than a literal.

## Monitoring vs enforcing

[`config.monitor_mode`](./reference/#schema--monitor-mode) decides whether a
denial is acted on:

| Value | Behavior |
|---|---|
| `false` (default) | Enforce. A denied call is refused and the upstream is never contacted. |
| `true` | Monitor only. Every call is still evaluated and every verdict still logged, but nothing is blocked. |

Monitor mode is the natural first step of a rollout: point the plugin at real
traffic, see what *would* have been refused, then turn it off to enforce. A
would-be denial is logged at `warn`:

```
[reva-ai-runtime-authorization] MONITOR would deny invokeTool billing-mcp/get_refunds for support-agent:
           authorization denied by policy (proxying anyway)
```

This is separate from
[`config.fail_open`](./reference/#schema--fail-open), which decides what happens
when Reva Trust Guardian cannot be **reached** — not what to do with a decision it
gave.

## What happens on a denial

A denied call is terminated with
[`config.deny_status`](./reference/#schema--deny-status) (default `403`) and
[`config.deny_message`](./reference/#schema--deny-message) (default
`Blocked by Reva`). The upstream is never contacted.

The body carries a `reason` naming the specific case:

| Status | `reason` | Meaning |
|---|---|---|
| `deny_status` | `authorization denied by policy`, or the reason Reva returned | Reva evaluated the call and refused it |
| `deny_status` | `authorization service unavailable` | Reva Trust Guardian could not be reached; no decision was made |
| `deny_status` | `could not build authorization request` | The plugin could not encode the evaluation request |
| `401` | `missing Authorization bearer token` | No bearer token was presented |
| `401` | `Authorization bearer token is not a JWT` | A bearer was presented but could not be decoded as a JWT |
| `401` | ``jwt claim `<claim>` is empty`` | The JWT decoded, but [`config.jwt_user_claim`](./reference/#schema--jwt-user-claim) held no value |
| `401` | `missing user identity` | No user could be resolved for any other reason |
| `401` | `no authenticated consumer; identity_source is 'consumer' so the caller must be authenticated first` | [`config.identity_source`](./reference/#schema--identity-source) is `consumer`, but no authentication plugin resolved one |
| `400` | ``missing `<header>` header`` | [`config.authorize_agent`](./reference/#schema--authorize-agent) and [`config.require_identity_headers`](./reference/#schema--require-identity-headers) are on, and the agent header is absent |

Applications should surface these differently. A policy denial has a
corresponding row in the Reva decision log; the others have none.

The `401` and `400` refusals are raised by the plugin **before** Reva is
called, so they are not affected by
[`config.fail_open`](./reference/#schema--fail-open),
[`config.monitor_mode`](./reference/#schema--monitor-mode) or
[`config.deny_status`](./reference/#schema--deny-status) — only
[`config.deny_message`](./reference/#schema--deny-message) applies to them.

[`config.fail_open`](./reference/#schema--fail-open) controls the
`authorization service unavailable` and `could not build authorization request`
cases. It defaults to `false`: when Reva Trust Guardian is unreachable, the
request is refused. Setting it to `true` proxies unauthorized traffic and should
be a deliberate choice.

## Guardrails

Policies are not the only thing that can refuse a call. A Reva policy store can
also carry **guardrails** — content-level evaluators that run on the same
request, configured in the Reva console rather than in this plugin.

Typical evaluators are an intent-drift check, which compares what the agent is
doing now against the user's originally approved intent and attributes how far
it has diverged, and a jailbreak and prompt-injection detector. Each has its own
score threshold and its own allow or deny verdict, and a guardrail can be set to
observe rather than enforce independently of anything configured here.

**Nothing in this plugin configures them, and nothing needs to.** Guardrails are
evaluated by the Reva Trust Guardian as part of the same call, and their verdict
is folded into the single `decision` the plugin receives. From the gateway's
point of view a guardrail denial is indistinguishable from a policy denial: same
status, same `reason`, same fail-closed behavior.

The distinction is visible where it matters — the Reva decision log records
`Evaluated Policies` and `Evaluated Guardrails` separately for every call, so an
operator can see which of the two refused a request. If a call is being blocked
and no policy explains it, look at the guardrails before changing policy.

## Troubleshooting

Decisions are logged at `info` level, one line per call:

```
[reva-ai-runtime-authorization] invokeModel gpt-4o                        allowed=true  status=200
[reva-ai-runtime-authorization] invokeTool billing-mcp/get_billing_report allowed=true  status=200
[reva-ai-runtime-authorization] invokeModel gpt-4o                        allowed=false status=403
```

Set `KONG_LOG_LEVEL=info` or lower. At `notice` the entire decision trail is
hidden.

### Every request is denied, including ones that should be allowed

**Symptoms:** calls that a policy permits are refused, and the Reva decision log
has no matching rows. The absent rows are the tell — a genuine policy denial
always produces one.

**Possible solutions:**

* Verify [`config.auth_token`](./reference/#schema--auth-token) is still
  accepted. A token issued for the v1 evaluation contract is rejected with
  `401 Unauthorized` against `/pdp/v2/ai/evaluation`, which the plugin always
  calls. That 401 is indistinguishable from an expired credential.
* Check the `reason` in the response body. `authorization service unavailable`
  means no decision was made at all — not a policy problem.

### Plugin not found, or 500 errors after enabling

**Symptoms:** the plugin appears in {{site.konnect_short_name}} but requests fail
with `500`, or data plane logs show `plugin 'reva-ai-runtime-authorization' not found`.

**Possible solutions:**
* Install `handler.lua` and `schema.lua` on **every** data plane node. In hybrid
  mode {{site.konnect_short_name}} only distributes the schema.
* Ensure `KONG_PLUGINS` includes `reva-ai-runtime-authorization`.
* Confirm the plugin is on the search path: `luarocks list | grep reva`.

### Chat history resets mid-conversation

**Symptoms:** `session.turn` returns to `1` and `session.messages` is empty part
way through a chat, often just after a configuration change.

**Possible solutions:**
* Set [`config.hop_storage_dict`](./reference/#schema--hop-storage-dict) to a dictionary
  {{site.base_gateway}} does not manage, and declare it with
  `nginx_http_lua_shared_dict`. `kong_db_cache` is flushed on every config
  reload, which erases conversations in flight.
* Confirm the application sends the same
  [`config.session_header`](./reference/#schema--session-header) value for every
  message of a chat.

### MCP calls fail with "Session terminated"

**Symptoms:** MCP tool calls fail intermittently, more often under load.

**Possible solutions:**
* Enable `request_buffering` on the route: the plugin reads the request body.
* Disable `response_buffering`: MCP streams over SSE.

### Connectivity

**Symptoms:** requests are slow, or the Reva console shows no decisions.

**Possible solutions:**
* Ensure the data plane has outbound HTTPS access to
  [`config.reva_host_url`](./reference/#schema--reva-host-url).
