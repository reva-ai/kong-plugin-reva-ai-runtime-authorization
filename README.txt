Reva AI Runtime Authorization — Kong Plugin Hub submission
===============================================

documentation/   the doc draft, in the shape of PR Kong/developer.konghq.com#4203

  index.md                          -> app/_kong_plugins/reva-ai-runtime-authorization/index.md
  reference.md                      -> app/_kong_plugins/reva-ai-runtime-authorization/reference.md
  schema.json                       -> app/_kong_plugins/reva-ai-runtime-authorization/schema.json
  enable-reva-ai-runtime-authorization.yaml    -> app/_kong_plugins/reva-ai-runtime-authorization/examples/
  reva-ai-runtime-authorization.svg            -> app/assets/icons/plugins/

  Publisher entry for app/_data/plugin_publishers.yml:

    reva:
      name: Reva

  (that file carries only the display name; support_url is declared in
  index.md frontmatter, and already is)

plugin/          the plugin itself and Kong's archive layout

  handler.lua, schema.lua           the plugin
  ...0.1.0-1.all.rock               installable artifact, builds and installs clean
  ...0.1.0-1.rockspec, INSTALL.txt, README.md

Gateway: tested on Kong Gateway 3.15.0.5, self-managed hybrid data plane on a
Konnect control plane. min_version.gateway declared as 3.12.

The example's `tools:` line lists deck, admin-api, konnect-api, kic and
terraform, so Kong generates those five install snippets from it.
