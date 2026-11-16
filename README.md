# Reva AI Runtime Authorization — Kong AI Gateway policy

AI Custom Policy name: `reva-ai-runtime-authorization`

Authorizes agent, MCP, A2A and LLM traffic passing through Kong AI Gateway by
evaluating every call against [Reva Trust Guardian](https://reva.ai), Reva's
policy decision point. A call is proxied only when policy allows it.

Unlike request-level filtering, this policy evaluates the **delegation chain**:
it correlates the hops of one agent turn on a shared `traceparent` and the turns
of one chat on a session id, so a policy can be written against what an agent is
actually doing across a conversation rather than a single request in isolation.

Requires Kong AI Gateway 2.2 or later.

## What's in this repository

| Path | Contents |
|---|---|
| `plugin/` | The policy: `handler.lua`, `schema.lua`, the rockspec, the packed `.all.rock`, and install instructions |
| `documentation/` | The documentation page sources — `index.md`, `reference.md`, `schema.json`, the config example and the icon |
| `tools/` | Build and verification scripts (see below) |

## Installing

See [`plugin/INSTALL.txt`](plugin/INSTALL.txt). Kong AI Gateway runs a custom
policy in one of two ways; this policy works with either.

**Streaming.** Create an AI Custom Policy in Konnect with `type` `streaming`,
sending `schema.lua` as the schema and `handler.lua` as the handler. Konnect
sends the handler to your data planes, so their image does not change. Start
each data plane with:

```
KONG_CUSTOM_PLUGIN_STREAMING_ENABLED=on
KONG_UNTRUSTED_LUA=lax
```

**Installed.** Put the code on each data plane and send only the schema to
Konnect (`type` `installed`):

```sh
luarocks install kong-plugin-reva-ai-runtime-authorization-2.0.0-1.all.rock
```

then add `reva-ai-runtime-authorization` to the `plugins` directive in
`kong.conf`.

Either way, finish by creating an AI Policy of type
`reva-ai-runtime-authorization`. Nothing else needs to be declared on the data
plane. Configuration reference: [`plugin/README.md`](plugin/README.md).

## Building and verifying

The package is self-checking. Nothing under `documentation/schema.json` or the
packed `.rock` is edited by hand — each is generated, and a gate refuses a
package whose generated artifacts have drifted from their sources.

```sh
python3 tools/check-package.py        # run every check; non-zero on any failure
python3 tools/gen-schema-json.py      # regenerate schema.json from schema.lua
python3 tools/build-rock.py           # repack the .all.rock from plugin/
python3 tools/apply-tooltips.py tools/tooltips.json   # rewrite field descriptions
```

The handler's request classification has an offline test, `tools/test-handler.lua`;
its header gives the `docker run` command that runs it against the Kong AI Gateway image.

`check-package.py` verifies, among other things, that `schema.json` matches
`schema.lua`, that the packed rock matches `plugin/`, that both Lua files
compile under LuaJIT, that the rockspec lints, and that no credential has crept
into a shipping file. Install `luajit` and `luarocks` for
the full set; the Lua checks skip with a note if they are absent.

## Support

Contact [info@reva.ai](mailto:info@reva.ai).
Documentation: [docs.reva.ai](https://docs.reva.ai/) (access code required).

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).
