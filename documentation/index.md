---
title: 'Reva AI Runtime Authorization'
name: 'Reva AI Runtime Authorization'

content_type: plugin

publisher: reva
description: "Authorize every model, tool and agent call passing through your {{site.ai_gateway_name}} against a Reva policy store"

products:
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
  ai-gateway: '2.2'
---

**Reva AI Runtime Authorization** authorizes agentic traffic at the gateway. Every
model call, tool call and agent-to-agent hop passing through your
{{site.ai_gateway_name}} is evaluated against a Reva policy store before it
reaches an upstream, and denied calls never leave {{site.ai_gateway}}.

It is an AI Custom Policy: you register it once, then attach it like any other
AI Policy.

Unlike request-level filtering, `reva-ai-runtime-authorization` evaluates the **delegation chain**. It
correlates the hops of one agent turn on a shared `traceparent` and the turns of
one chat on a session id, so a policy can be written against what an agent is
actually doing across a conversation rather than a single request in isolation.

Adding Reva AI Runtime Authorization to your {{site.ai_gateway}} allows you to:
* **Authorize three kinds of agentic call**: model invocations (`invokeModel`),
  MCP tool calls (`invokeTool`) and A2A agent invocations (`invokeAgent`).
* **Keep credentials off the application**: the application holds no model key
  and no policy credentials. It can only reach a model, a tool or another agent
  through the gateway, so authorization cannot be bypassed by the caller.
* **Fail closed by default**: if the Reva Trust Guardian cannot be reached, the
  request is refused rather than proxied unauthorized.

## Add the Reva AI Runtime Authorization policy

{{site.ai_gateway}} runs a custom policy from two Lua files: `schema.lua`, which
defines its configuration, and `handler.lua`, which does the work. It supports
two ways of running them, and Reva AI Runtime Authorization works with either.

### Prerequisites

Before adding the policy, you need the following from Reva:

* The Lua sources (`schema.lua` and `handler.lua`), or the `.rock` file that
  packs them. Contact [info@reva.ai](mailto:info@reva.ai) to obtain them.
* A static **authorization token**, available in the Reva console under
  **Settings → Connect to Reva Trust Guardian**.

You also need {{site.ai_gateway}} 2.2 or later.

## Installation steps

{% navtabs 'deployment' %}
{% navtab "Streaming" %}

A streaming AI Custom Policy needs no change to your data plane image.
{{site.konnect_short_name}} stores the schema and the handler and sends the
handler to every data plane.

1. Start every data plane with:

   ```sh
   KONG_CUSTOM_PLUGIN_STREAMING_ENABLED=on
   KONG_UNTRUSTED_LUA=lax
   ```

   The policy makes an outbound HTTPS call to the Reva Trust Guardian, which the
   default `strict` Lua sandbox blocks.
1. In {{site.konnect_short_name}}, create an AI Custom Policy from the UI, the
   AI Gateway API (`POST /v1/ai-gateways/{aiGatewayId}/custom-policies`) or
   kongctl, with:

   | Field | Value |
   |---|---|
   | `name` | `reva-ai-runtime-authorization` |
   | `type` | `streaming` |
   | `schema` | the contents of `schema.lua` |
   | `handler` | the contents of `handler.lua` |

   The `name` must match the name declared in the schema. Neither `name` nor
   `type` can be changed afterwards.
1. [Attach the policy](#attaching-the-policy).

{% endnavtab %}
{% navtab "Installed (Docker)" %}

An installed AI Custom Policy runs code that you put on each data plane.
{{site.konnect_short_name}} receives only the schema.

1. Build a data plane image that contains the policy:

   ```docker
   FROM kong/kong-ai-gateway:2.3.0-distroless

   COPY kong/plugins/reva-ai-runtime-authorization /usr/local/share/lua/5.1/kong/plugins/reva-ai-runtime-authorization

   ENV KONG_PLUGINS=bundled,reva-ai-runtime-authorization
   ```

   Run every data plane from this image.
1. In {{site.konnect_short_name}}, create an AI Custom Policy with `name`
   `reva-ai-runtime-authorization`, `type` `installed` and `schema` set to the
   contents of `schema.lua`. Do not send a `handler`.
1. [Attach the policy](#attaching-the-policy).

{% endnavtab %}
{% navtab "Installed (kong.conf)" %}

An installed AI Custom Policy runs code that you put on each data plane.
{{site.konnect_short_name}} receives only the schema.

1. On every data plane node, install the policy:

   ```sh
   luarocks install kong-plugin-reva-ai-runtime-authorization-2.1.0-1.all.rock
   ```

1. Append `reva-ai-runtime-authorization` to the `plugins` field in
   [`kong.conf`](/gateway/configuration/). Make sure the field isn't commented
   out.

   ```yaml
   plugins = bundled,reva-ai-runtime-authorization
   ```

1. Restart the data plane:

   ```sh
   kong restart
   ```

1. In {{site.konnect_short_name}}, create an AI Custom Policy with `name`
   `reva-ai-runtime-authorization`, `type` `installed` and `schema` set to the
   contents of `schema.lua`. Do not send a `handler`.
1. [Attach the policy](#attaching-the-policy).

A code change requires a restart, not only a config reload —
{{site.ai_gateway}} loads Lua at worker startup.

{% endnavtab %}
{% endnavtabs %}

## Attaching the policy

1. [Set up {{site.ai_gateway}}](/ai-gateway/get-started/) with an entity for each
   upstream you want governed: a model, an MCP server or an agent.
1. The policy reads the request body, so request buffering must stay enabled on
   the routes it covers (`request_buffering`, which is on by default). MCP
   endpoints stream over SSE and additionally need `response_buffering`
   disabled.
1. [Attach the Reva AI Runtime Authorization policy](/plugins/reva-ai-runtime-authorization/examples/enable-reva-ai-runtime-authorization/).
   It has no scope restriction: attach it globally, or to an AI Model, AI
   Consumer or AI Consumer Group.

## What your application must forward

The policy can join the hops of one turn only if every service in the chain
passes on what it received. Each agent must send these headers, spelled as
shown, on every call it makes through the gateway: to a model, to an MCP server
and to another agent.

| Header | Send it | What it does |
|---|---|---|
| `Authorization: Bearer <JWT>` | on every call | Names the user. The policy decodes it and reads [`config.jwt_user_claim`](./reference/#schema--jwt-user-claim). Forward the end user's token unchanged; a service token in its place attributes the call to the service. A call without it is refused with `401`. |
| `traceparent` | on every call | The W3C trace context. Its 32-character trace id is what makes separate calls one turn. The first service starts one for each user message, and every later call forwards it unchanged. If it is missing the policy creates one, and Reva cannot link the call to the turn it belongs to. |
| `X-Transaction-Token` | on every call after the first | The Reva Trust Guardian issues it when it allows a call, and the policy adds it to the request it sends upstream. Forward it exactly as received on every call that follows. Its presence tells the policy that the call is a later hop. |
| the thread id, at the place [`config.session_key`](./reference/#schema--session-key) names (default: the header `X-Reva-Session-Id`) | on the first call of a turn only | Groups the turns of one chat. Later hops do not need it. |

For one turn, the calls carry:

```
user  ->  agent A     Authorization: Bearer <JWT>
                      traceparent: 00-<trace id>-<span id>-01
                      X-Reva-Session-Id: <chat id>         (named by session_key)

agent A  ->  agent B  Authorization: Bearer <JWT>          (the same token)
                      traceparent: 00-<trace id>-<span id>-01   (the same trace id)
                      X-Transaction-Token: <token>         (from the request A received)

agent B  ->  model    Authorization: Bearer <JWT>
                      traceparent: 00-<trace id>-<span id>-01
                      X-Transaction-Token: <token>         (from the request B received)
```

`X-Reva-Session-Id` is only the default name. The thread id is read from whatever
[`config.session_key`](./reference/#schema--session-key) names: a header of
another name, or a field in the JSON body such as `params.message.contextId`.
Send it where that setting points.

Each hop passes on the transaction token it received. The policy issues a new
one for every call it allows and puts it on the upstream request, so the value an
agent forwards is always the one on the request it was just handed.

### How the policy tells the first call from a later one

A call that carries no `X-Transaction-Token` is the first call of a turn. A call
that carries one is a later hop. A transaction token exists only because an
earlier call was evaluated and allowed.

| | First call of a turn | Later hop |
|---|---|---|
| Carries `X-Transaction-Token` | no | yes |
| The user | read from the `Authorization` JWT | taken from the transaction token |
| Thread id | read from the place `session_key` names | not needed |

### If a header is missing

None of these produces an error in your application. The turn just becomes harder
for Reva to follow.

| Missing | What happens |
|---|---|
| `Authorization` | The call is refused with `401` and the reason `missing Authorization bearer token`. Reva is not called. |
| `traceparent` | The policy creates a new trace, so Reva cannot link the call to the turn it belongs to. |
| `X-Transaction-Token` on a later hop | The call is treated as the first call of a new turn made by the user, not as a later hop made by the agent. |
| the thread id on the first call | The turn has no thread id, so Reva cannot join it to earlier turns of the chat. |

### Token lifetime

A transaction token is short-lived, and Reva sets the lifetime for your
deployment. A service that waits too long between receiving a request and making
its next call, for example behind a slow model or a cold start, finds the token
expired. Reva then refuses the call: the response carries `authorization service
unavailable`, and the data plane log shows `X-Transaction-Token validation
failed`. Keep the time between hops short rather than retrying with the same
token.

## How a call is classified

Models, MCP servers and agents are separate {{site.ai_gateway}} entities. The
policy does not use path prefixes; it classifies from the request body (and the
Service the call is routed to, for resource identity), in this order:

| Body shape | Action | Resource id |
|---|---|---|
| JSON-RPC `tools/call` | `invokeTool` | the tool name from `params.name`; Reva names the tool `<mcp server>/<tool>` |
| JSON-RPC `message/send`, `message/stream`, `SendMessage` or `SendStreamingMessage`, or an HTTP+JSON `POST` to `…/message:send` or `…/message:stream` | `invokeAgent` | the Service URL (`protocol://host[:port]`) |
| OpenAI `messages` array | `invokeModel` | `body.model` |

Payloads that match none of those shapes are proxied untouched. Of the MCP
methods, only `tools/call` is evaluated.

### A2A requests

An agent call is any A2A request that sends a message to an agent. The policy
evaluates it in both protocol versions and both bindings:

| Operation | JSON-RPC method, 0.3 | JSON-RPC method, 1.0 | HTTP+JSON path ends with | Response |
|---|---|---|---|---|
| Send a message | `message/send` | `SendMessage` | `/message:send` | one reply |
| Send a message, streamed | `message/stream` | `SendStreamingMessage` | `/message:stream` | server-sent events |

* **HTTP+JSON** is recognized by the end of the path, so a version or tenant
  prefix such as `/v1/message:send` or `/acme/message:send` is fine. The body is
  the request itself, `{"message": {...}}`, with no JSON-RPC envelope.
* **Media type.** A body is read as JSON for any JSON media type, including
  `application/a2a+json`, which A2A 1.0 recommends for HTTP+JSON.
* **Streamed responses** are passed through as they are produced, and the call
  is still evaluated before it is sent. The turn is not reported to the Reva
  Trust Guardian when the stream ends.
* **Not evaluated:** requests that read or manage tasks (`tasks/*`, `GetTask`,
  `CancelTask`, `SubscribeToTask`, and the push-notification configuration
  methods), agent-card requests, the gRPC binding, and JSON-RPC batches.

An Agent resource id is the Service URL: always `protocol://host[:port]`
alone, never a path — even when the Service has one configured — and never
the inbound request path. A policy therefore matches the host, for example
`Agent::"http://ticketing-agent:8003"`. Two agents are two Services on two
hosts in this model, so the host alone identifies the resource.

Register each MCP server in Reva with the same base URL as its Service. Reva
names each of its tools `<mcp server>/<tool>`, so a Reva policy matches
`Tool::"ticketing-mcp/open_ticket"`, and the decision log shows the same
resource.

## Identity

The human principal is always taken from the inbound `Authorization: Bearer`
JWT. The policy decodes the payload (it does not verify the signature, so
authenticate callers before their requests reach it) and reads
[`config.jwt_user_claim`](./reference/#schema--jwt-user-claim)
(default `sub`). Nested claims use a dotted path (`user.id`); Cognito-style
keys such as `cognito:username` are a single claim name.

That value identifies the user to Reva.

[`config.jwt_groups_claim`](./reference/#schema--jwt-groups-claim) (default
`groups`) is read from the same token and sent as the user's group memberships.
A Reva policy can then be written against a group rather than a person — *anyone
in `Finance` may invoke this agent* — which is what makes a policy store scale
past naming individuals. Cognito-style arrays such as `cognito:groups` work
as-is; a token without the claim simply sends no groups.

A missing token, an unreadable JWT, or an empty claim is refused with `401`
before the Reva Trust Guardian is called. There is no header fallback: the human
principal comes from the token or the request does not proceed.

On the first call of a turn the user comes from the JWT. A later hop carries a
transaction token, and Reva takes the calling agent and the user from it.

## Conversation context

The policy keeps no conversation state of its own. The Reva Trust Guardian keeps
the history of each chat, so the policy only has to tell it which conversation a
call belongs to:

* **Trace** — the 32-character trace id from the inbound `traceparent`. One
  agent turn is one trace, so every hop that carries the same trace id lands in
  the same turn. The span id may change from hop to hop. If no `traceparent`
  arrives, the policy creates one.
* **Thread** — the chat id, sent **on the first call of a turn only**. Later
  hops are joined to the thread through the trace, so a different id on a later
  hop is ignored. It is read from
  [`config.session_key`](./reference/#schema--session-key) (default
  `X-Reva-Session-Id`) and nowhere else: first as a request header of that
  name, then in the JSON body. A key with dots is a path from the root of the
  body, so `params.thread_id` is `body.params.thread_id`. To use an A2A
  `contextId`, set the key to where the caller puts it: `params.message.contextId`
  for JSON-RPC, or `message.contextId` over HTTP+JSON. A first call that carries
  nothing at that key has no thread id, so the Reva Trust Guardian cannot join it
  to earlier turns.

Where the current utterance is read from:

| Call | Read from |
|---|---|
| Model | the last user message in the request body's `messages` |
| Tool | the tool name and arguments in `params` |
| Agent | the message's `parts` (`params.message.parts`, or `message.parts` over HTTP+JSON): each text part's `text`, and each data part as its JSON text (up to 8192 bytes), joined with newlines. File parts are skipped. |

The utterance is sent to Reva at
[`config.prompt_key`](./reference/#schema--prompt-key) (default `content`). A
model message whose `content` is an array of parts rather than a string —
OpenAI's multimodal form — has its text parts joined and evaluated like any
other message. Image and audio parts are not sent to the Reva Trust Guardian.

When the first call of a turn completes, the policy reports the turn to the
Reva Trust Guardian, on a best-effort basis, so later turns can be evaluated
against it. A streamed A2A response is not reported.

## Context variables

Besides the prompt, the policy sends name/value pairs from the request body to
the Reva Trust Guardian as *context*, so a Reva policy can match on them — for
example, *refuse this tool when `priority` is `high`*. Which fields are read
depends on the call:

| Call | Read from | Sent under |
|---|---|---|
| Agent | every `metadata` object: the request's, the message's and each message part's | the metadata's own names |
| Tool | everything in `params` except the tool name: `arguments` and `_meta` | the field's own name, so `_meta.progressToken` is sent as `progressToken` |
| Model | `metadata`, and the settings at the top of the body, such as `max_tokens`, `stream` and `user` | the field's own name |

`model`, `messages` and `tools` are not sent as context: the model is the
resource and the messages are the prompt. Everything in the fields above goes to
Reva, so keep out of them anything you do not want evaluated.

* A nested object becomes dotted names: `{"customer": {"tier": "gold"}}` is sent
  as `customer.tier`.
* When a name appears more than once, the more specific one wins: a part's
  metadata over the message's over the request's; MCP `arguments` over `_meta`;
  for a model call, a top-level setting over `metadata`.
* Only these values are sent: text, `true` or `false`, whole numbers, and lists
  of one of those. Null, decimals (so `temperature: 0.2`), objects inside lists,
  empty values and lists that mix types are left out.
* Names Reva uses itself (`action`, `subject`, `resource`, `history` and a few
  others), names that look like credentials (`password`, `apiKey`,
  `authorization`, `cookie`), and values that look like a bearer token or a JWT
  are left out.
* A call carries at most 64 pairs and 512 bytes of JSON in all. When there is
  more, the pairs that fit are sent, taken in alphabetical order of name, and
  the rest are left out.
* Context is sent on every call, first or later hop, and describes that call.
* With [`config.debug`](./reference/#schema--debug) on, the data plane log
  lists, by name, the pairs that were left out.

## Authenticating to the Reva Trust Guardian

The policy presents [`config.auth_token`](./reference/#schema--auth-token) on
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

Monitor mode is the natural first step of a rollout: attach the policy to real
traffic, see what *would* have been refused, then turn it off to enforce. A
would-be denial is logged at `warn`:

```
[reva-ai-runtime-authorization] MONITOR would deny invokeTool get_refunds for support-agent:
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
| `deny_status` | `could not build authorization request` | The policy could not encode the evaluation request |
| `401` | `missing Authorization bearer token` | No bearer token was presented |
| `401` | `Authorization bearer token is not a JWT` | A bearer was presented but could not be decoded as a JWT |
| `401` | ``jwt claim `<claim>` is empty`` | The JWT decoded, but [`config.jwt_user_claim`](./reference/#schema--jwt-user-claim) held no value |
| `401` | `missing user identity` | No user could be resolved for any other reason |

Applications should surface these differently. A policy denial has a
corresponding row in the Reva decision log; the others have none.

The `401` refusals are raised by the policy **before** Reva is
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

Reva policies are not the only thing that can refuse a call. A Reva policy store
can also carry **guardrails** — content-level evaluators that run on the same
request, configured in the Reva console rather than in this policy.

Typical evaluators are an intent-drift check, which compares what the agent is
doing now against the user's originally approved intent and attributes how far
it has diverged, and a jailbreak and prompt-injection detector. Each has its own
score threshold and its own allow or deny verdict, and a guardrail can be set to
observe rather than enforce independently of anything configured here.

**Nothing in this policy configures them, and nothing needs to.** Guardrails are
evaluated by the Reva Trust Guardian as part of the same call, and their verdict
is folded into the single `decision` the policy receives. From the gateway's
point of view a guardrail denial is indistinguishable from a policy denial: same
status, same `reason`, same fail-closed behavior.

The distinction is visible where it matters — the Reva decision log records
`Evaluated Policies` and `Evaluated Guardrails` separately for every call, so an
operator can see which of the two refused a request. If a call is being blocked
and no policy explains it, look at the guardrails before changing policy.

## Troubleshooting

Decisions are logged at `info` level, one line per call:

```
[reva-ai-runtime-authorization] invokeModel gpt-4o allowed=true status=200 latency_ms=412.3
[reva-ai-runtime-authorization] invokeTool get_billing_report allowed=true status=200 latency_ms=388.0
[reva-ai-runtime-authorization] invokeModel gpt-4o allowed=false status=403 latency_ms=351.9
```

Set `KONG_LOG_LEVEL=info` or lower. At `notice` the entire decision trail is
hidden.

### Every request is denied, including ones that should be allowed

**Symptoms:** calls that a Reva policy permits are refused, and the Reva
decision log has no matching rows. The absent rows are the tell — a genuine
policy denial always produces one.

**Possible solutions:**

* Verify [`config.auth_token`](./reference/#schema--auth-token) is still
  accepted. A rejected token returns `401 Unauthorized` from
  the Reva Trust Guardian, and that 401 is indistinguishable from an expired
  credential.
* Check the `reason` in the response body. `authorization service unavailable`
  means no decision was made at all — not a policy problem.

### A call late in a turn is refused

**Symptoms:** the first calls of a turn are allowed, a later one is refused with
`authorization service unavailable`, and the data plane log shows
`no decision (RTG returned HTTP 401: ... X-Transaction-Token validation failed)`.

**Possible solutions:**
* The transaction token the service forwarded has expired. Reduce the time
  between hops, for example by keeping slow services warm; see
  [Token lifetime](#token-lifetime).
* Confirm the service forwards the token it was handed on this request, not one
  it kept from an earlier request.

### Policy not found, or 500 errors after attaching

**Symptoms:** the policy appears in {{site.konnect_short_name}} but requests fail
with `500`, or data plane logs show `plugin 'reva-ai-runtime-authorization' not found`.

**Possible solutions:**
* Streaming policy: start every data plane with
  `KONG_CUSTOM_PLUGIN_STREAMING_ENABLED=on` and `KONG_UNTRUSTED_LUA=lax`.
* Installed policy: install `handler.lua` and `schema.lua` on **every** data
  plane node. {{site.konnect_short_name}} only holds the schema.
* Installed policy: ensure `KONG_PLUGINS` includes `reva-ai-runtime-authorization`.

### Turns are not joined into one conversation

**Symptoms:** the hops of a turn, or the turns of a chat, appear separately in
the Reva decision log.

**Possible solutions:**
* Confirm every service forwards `traceparent` and `X-Transaction-Token`
  unchanged; see [What your application must forward](#what-your-application-must-forward).
* Confirm the first call of every turn carries the chat's thread id, at the
  header or body field that [`config.session_key`](./reference/#schema--session-key)
  names. Later hops do not need it.

### MCP calls fail with "Session terminated"

**Symptoms:** MCP tool calls fail intermittently, more often under load.

**Possible solutions:**
* Keep `request_buffering` enabled on the route: the policy reads the request
  body.
* Disable `response_buffering`: MCP streams over SSE.

### Connectivity

**Symptoms:** requests are slow, or the Reva console shows no decisions.

**Possible solutions:**
* Ensure the data plane has outbound HTTPS access to
  [`config.reva_host`](./reference/#schema--reva-host).
