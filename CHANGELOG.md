# Changelog

## 2.1.0

- Sends name/value pairs from the request body to Reva as context: the
  `metadata` of an A2A request, message and message parts, the `arguments` and
  `_meta` of an MCP `tools/call`, and the `metadata` and call settings of a model
  call. Pairs Reva does not accept are left out rather than sent. See
  [Context variables](plugin/README.md#context-variables).
- Installs from the packed rock, `kong-plugin-reva-ai-runtime-authorization-2.1.0-1.all.rock`.

## 2.0.0

Reva AI Runtime Authorization is a policy for Kong AI Gateway 2.2 and later. It
runs as a streaming or an installed AI Custom Policy.

- Authorizes OpenAI-style model calls, MCP `tools/call` requests and A2A
  send-message requests against a Reva policy store before they reach an
  upstream. A2A is supported in both protocol versions and both bindings,
  including streamed responses.
- Joins the hops of one agent turn on the `traceparent` trace id and the
  `X-Transaction-Token` that Reva Trust Guardian issues on an allow.
- Reads the chat's thread id from the header or body field named by
  `session_key`, with dots for a nested body field such as
  `params.message.contextId`, on the first call of a turn.
- Takes the user from the JWT named by `jwt_user_claim`. A call without a
  bearer token is refused with `401`.
- Enforces with `deny_status` and `deny_message`, or only logs with
  `monitor_mode`. `fail_open` decides what happens when no decision can be
  obtained.
- Installs from the packed rock, `kong-plugin-reva-ai-runtime-authorization-2.0.0-1.all.rock`.

See [`plugin/README.md`](plugin/README.md) for the configuration reference and
[`plugin/INSTALL.txt`](plugin/INSTALL.txt) for installation.
