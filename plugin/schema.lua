-- kong/plugins/reva-ai-runtime-authorization/schema.lua
--
-- Configuration surface for the Reva Trust Guardian authorization policy.
--
-- NOTE: this file deliberately contains no `require()` calls. Konnect
-- Dedicated Cloud Gateways reject a schema.lua that requires anything
-- (including kong.db.schema.typedefs), so every field is spelled out by
-- hand. Custom validation lives in handler.lua, not here.

local PLUGIN_NAME = "reva-ai-runtime-authorization"

return {
  name = PLUGIN_NAME,
  fields = {
    { config = {
        type = "record",
        fields = {

          -- Connecting to Reva Trust Guardian ─────────────────────────────
          { reva_host = {
              description = "Host or base URL of your Reva tenant, for example `api.example.reva.ai`. Defaults to `api.reva.ai`; a value you set overrides it. Host-only values are called over HTTPS.",
              type = "string",
              required = false,
              default = "api.reva.ai",
          } },
          { auth_token = {
              description = "Bearer token Kong presents to Reva Trust Guardian on every evaluation. Find it in the Reva console under Settings. This field is referenceable — store it in a vault rather than inline.",
              type = "string",
              required = true,
              referenceable = true,
          } },
          { ssl_verify = {
              description = "Verify the TLS certificate presented by Reva Trust Guardian. Turn this off only against a test instance with a self-signed certificate.",
              type = "boolean",
              default = true,
          } },

          -- Enforcement: what happens to a denied call ────────────────────
          { monitor_mode = {
              description = "Evaluate every call and log the verdict, but never block. Use it to see what policy would refuse before you enforce it.",
              type = "boolean",
              default = false,
          } },
          { fail_open = {
              description = "Proxy the request when Reva Trust Guardian cannot be reached or returns no decision. Off by default, so an outage refuses calls rather than passing them unevaluated.",
              type = "boolean",
              default = false,
          } },
          { deny_status = {
              description = "HTTP status returned when a call is refused, either by policy or because no decision could be obtained.",
              type = "integer",
              default = 403,
              between = { 100, 599 },
          } },
          { deny_message = {
              description = "Message returned to the caller in the response body when a call is refused. The specific reason is returned alongside it.",
              type = "string",
              default = "Blocked by Reva",
          } },

          -- Identity: who the call is attributed to ───────────────────────
          { jwt_user_claim = {
              description = "JWT claim read from the bearer token to identify the user. Common values are `sub`, `preferred_username` and `cognito:username`.",
              type = "string",
              default = "sub",
          } },
          { jwt_groups_claim = {
              description = "JWT claim holding the user's group memberships, sent to Reva Trust Guardian as groups a policy can match. Use `roles` for RBAC tokens, `realm_access.roles` for Keycloak, or `cognito:groups` for Cognito.",
              type = "string",
              default = "groups",
          } },

          -- Reading the payload ───────────────────────────────────────────
          { prompt_key = {
              description = "Name of the field that carries the prompt text to Reva. Must match what your policy expects to read.",
              type = "string",
              default = "content",
          } },
          { session_key = {
              description = "Where the thread id is read: an HTTP request header of this name first, then the JSON body. Use dots for a nested body field, such as `params.thread_id`. Nothing else is searched. Sent to Reva Trust Guardian on a turn's first call only.",
              type = "string",
              default = "X-Reva-Session-Id",
          } },

          -- Turns and diagnostics ─────────────────────────────────────────
          { hop_ttl = {
              description = "How long, in seconds, the policy keeps a turn open when its first call never finishes. Set it longer than your slowest agent turn.",
              type = "integer",
              default = 3600,
              between = { 60, 86400 },
          } },
          { forward_traceparent = {
              description = "Pass the `traceparent` used for the authorization decision on to the upstream service, so one trace id spans the gateway and your backend.",
              type = "boolean",
              default = true,
          } },
          { debug = {
              description = "Log each decision and the request sent to Reva Trust Guardian at notice level. Use it while tuning policy; leave it off in production.",
              type = "boolean",
              default = false,
          } },

        },
      },
    },
  },
}
