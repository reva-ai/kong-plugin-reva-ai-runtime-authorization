#!/usr/bin/env python3
"""Rewrite plugin/schema.lua's config field descriptions and field order.

Reads a JSON file of {"field": "new description"} (nested record fields keyed
as "record.field") and a declared field order, then regenerates the config
table. Everything above `return {` in schema.lua -- including the note about
why the file may not require() anything -- is preserved verbatim.

Reordering config fields is presentation-only: Kong addresses configuration by
name in declarative config, the Admin API and defaults, and this schema
declares no entity_checks that could depend on ordering. Konnect renders the
plugin form in declaration order, so this is what controls what an operator
reads first.

Usage:
    python3 tools/apply-tooltips.py tooltips.json
    python3 tools/apply-tooltips.py tooltips.json --dry-run
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from importlib import import_module

gen = import_module("gen-schema-json".replace("-", "_")) if False else None

# gen-schema-json.py is not an importable module name, so load it by path.
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "genschema", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "gen-schema-json.py"))
genschema = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(genschema)

ROOT = genschema.ROOT
LUA = genschema.LUA

# Order the Konnect form presents fields in, grouped by what an operator
# decides in sequence: where Reva is, what to do with a verdict, who the
# caller is, what kind of call it is, how to read the payload, where state
# lives, and finally diagnostics.
SECTIONS = [
    ("Connecting to Reva Trust Guardian",
     ["reva_host_url", "auth_token", "ssl_verify"]),
    ("Enforcement: what happens to a denied call",
     ["monitor_mode", "fail_open", "deny_status", "deny_message"]),
    ("Identity: who the call is attributed to",
     ["authorize_agent", "jwt_user_claim", "jwt_groups_claim", "agent_header",
      "require_identity_headers", "identity_source", "consumer_id_field"]),
    ("Call classification",
     ["path_identification"]),
    ("Reading the payload, and grouping turns into a chat",
     ["prompt_key", "a2a_content_path", "a2a_history_path", "a2a_routing_path",
      "session_header", "max_session_messages", "session_ttl"]),
    ("Data plane state and diagnostics",
     ["hop_storage_dict", "hop_ttl", "forward_traceparent", "debug"]),
]

# Emission order within one field, so every field reads the same way.
KEY_ORDER = ["description", "type", "required", "default", "one_of", "between",
             "referenceable", "match"]

RULE = "─"


def lua_string(s):
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def lua_value(key, v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v) if isinstance(v, float) else str(v)
    if isinstance(v, str):
        return lua_string(v)
    if isinstance(v, tuple):
        kind, body = v
        if kind == "list":
            return "{ %s }" % ", ".join(lua_value(key, x) for x in body)
    raise TypeError("cannot emit %r for key %s" % (v, key))


def emit_field(name, spec, tooltips, indent, prefix=""):
    key = prefix + name
    pad = " " * indent
    inner = " " * (indent + 4)
    out = ["%s{ %s = {" % (pad, name)]

    if key in tooltips:
        spec = dict(spec)
        spec["description"] = tooltips[key]

    for k in KEY_ORDER:
        if k not in spec:
            continue
        if k == "type" and spec[k] == "record":
            continue
        out.append("%s%s = %s," % (inner, k, lua_value(k, spec[k])))

    if spec.get("type") == "record":
        out.append("%stype = \"record\"," % inner)
        out.append("%sfields = {" % inner)
        for sub_name, sub_spec in genschema.field_list(
                genschema.unwrap(spec["fields"])):
            out.append(emit_field(sub_name, sub_spec, tooltips, indent + 8,
                                  prefix=name + "."))
        out.append("%s}," % inner)

    out.append("%s} }," % pad)
    return "\n".join(out)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    tooltips = json.load(open(sys.argv[1], encoding="utf-8"))

    source = open(LUA, encoding="utf-8").read()
    c = genschema.Cursor(source)
    c.i = source.index("return") + len("return")
    root = genschema.unwrap(genschema.parse_table(c))
    config = dict(genschema.field_list(genschema.unwrap(root["fields"])))["config"]
    fields = dict(genschema.field_list(genschema.unwrap(config["fields"])))

    declared = set(fields)
    ordered = [f for _, names in SECTIONS for f in names]
    missing = declared - set(ordered)
    unknown = set(ordered) - declared
    if missing or unknown:
        sys.stderr.write("field order does not cover schema.lua exactly.\n")
        if missing:
            sys.stderr.write("  in schema.lua but unordered: %s\n" % sorted(missing))
        if unknown:
            sys.stderr.write("  ordered but not in schema.lua: %s\n" % sorted(unknown))
        return 1

    known = set()
    for name, spec in fields.items():
        known.add(name)
        if spec.get("type") == "record":
            for sub, _ in genschema.field_list(genschema.unwrap(spec["fields"])):
                known.add("%s.%s" % (name, sub))
    stray = set(tooltips) - known
    if stray:
        sys.stderr.write("tooltips name fields that do not exist: %s\n" % sorted(stray))
        return 1

    body = []
    for title, names in SECTIONS:
        bar = RULE * max(3, 62 - len(title))
        body.append("")
        body.append("          -- %s %s" % (title, bar))
        for name in names:
            body.append(emit_field(name, fields[name], tooltips, 10))

    head = source[:source.index("return {")]
    plugin_name = 'local PLUGIN_NAME = "reva-ai-runtime-authorization"'
    if plugin_name not in head:
        sys.stderr.write("unexpected schema.lua header; refusing to rewrite\n")
        return 1

    rebuilt = (head + "return {\n  name = PLUGIN_NAME,\n  fields = {\n"
               "    { config = {\n        type = \"record\",\n        fields = {\n"
               + "\n".join(body)
               + "\n\n        },\n      },\n    },\n  },\n}\n")

    if "--dry-run" in sys.argv:
        sys.stdout.write(rebuilt)
        return 0

    open(LUA, "w", encoding="utf-8").write(rebuilt)
    applied = sum(1 for k in tooltips if k in known)
    print("rewrote plugin/schema.lua: %d descriptions, %d fields reordered into %d sections"
          % (applied, len(ordered), len(SECTIONS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
