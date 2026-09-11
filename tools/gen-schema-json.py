#!/usr/bin/env python3
"""Generate documentation/schema.json from plugin/schema.lua.

Konnect renders the plugin configuration form from the uploaded schema.lua.
Kong's published configuration reference renders from schema.json. Maintaining
both by hand lets them drift -- they already had, on path_identification -- so
schema.json is generated and must never be edited directly.

Usage:
    python3 tools/gen-schema-json.py            # rewrite documentation/schema.json
    python3 tools/gen-schema-json.py --check    # exit 1 if it is out of date

Parses the deliberately restricted subset of Lua that schema.lua uses: nested
{ name = { key = value } } tables, string/number/boolean literals, and the
list-valued keys one_of and between. schema.lua contains no require() calls and
no expressions (Konnect Dedicated Cloud Gateways reject a schema.lua that
requires anything), which is what makes this parseable without a Lua runtime.
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LUA = os.path.join(ROOT, "plugin", "schema.lua")
JSON_OUT = os.path.join(ROOT, "documentation", "schema.json")

# Kong's Lua type names -> JSON Schema type names used on developer.konghq.com.
TYPE_MAP = {"string": "string", "boolean": "boolean", "integer": "integer",
            "number": "number", "record": "object", "array": "array"}


class Cursor:
    def __init__(self, text):
        self.s = text
        self.i = 0
        # `local PLUGIN_NAME = "reva-ai-runtime-authorization"` and friends.
        self.consts = dict(re.findall(
            r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"', text))

    def skip(self):
        """Advance past whitespace and -- comments."""
        while self.i < len(self.s):
            if self.s[self.i] in " \t\r\n":
                self.i += 1
            elif self.s.startswith("--", self.i):
                self.i = self.s.find("\n", self.i)
                if self.i == -1:
                    self.i = len(self.s)
            else:
                return

    def eat(self, lit):
        self.skip()
        if self.s.startswith(lit, self.i):
            self.i += len(lit)
            return True
        return False

    def expect(self, lit):
        if not self.eat(lit):
            raise SyntaxError("expected %r at offset %d: %r"
                              % (lit, self.i, self.s[self.i:self.i + 60]))


def parse_string(c):
    c.skip()
    if c.s[c.i] != '"':
        raise SyntaxError("expected a string at offset %d" % c.i)
    c.i += 1
    out = []
    while True:
        ch = c.s[c.i]
        if ch == "\\":
            nxt = c.s[c.i + 1]
            out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, nxt))
            c.i += 2
        elif ch == '"':
            c.i += 1
            return "".join(out)
        else:
            out.append(ch)
            c.i += 1


def parse_value(c):
    c.skip()
    ch = c.s[c.i]
    if ch == '"':
        return parse_string(c)
    if ch == "{":
        return parse_table(c)
    m = re.match(r"(true|false|nil|-?\d+\.\d+|-?\d+)\b", c.s[c.i:])
    if m:
        c.i += m.end()
        tok = m.group(1)
        if tok == "true":
            return True
        if tok == "false":
            return False
        if tok == "nil":
            return None
        return float(tok) if "." in tok else int(tok)
    # A bare identifier: schema.lua uses `name = PLUGIN_NAME`, declared as a
    # local string constant above the table. Resolve it when we can so the
    # parse stays faithful; otherwise keep the identifier as its own value,
    # since nothing outside `fields` reaches the generated JSON.
    m = re.match(r"[A-Za-z_][A-Za-z0-9_.]*", c.s[c.i:])
    if not m:
        raise SyntaxError("unparseable value at offset %d: %r"
                          % (c.i, c.s[c.i:c.i + 40]))
    c.i += m.end()
    return c.consts.get(m.group(0), m.group(0))


def parse_table(c):
    """Return ('map', dict) for key=value tables, ('list', list) for arrays.

    schema.lua's field lists are arrays of single-key maps, so both forms occur.
    """
    c.expect("{")
    items, pairs = [], {}
    while True:
        c.skip()
        if c.eat("}"):
            break
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=", c.s[c.i:])
        if m:
            c.i += m.end()
            pairs[m.group(1)] = parse_value(c)
        else:
            items.append(parse_value(c))
        c.skip()
        c.eat(",") or c.eat(";")
    return ("map", pairs) if pairs else ("list", items)


def unwrap(v):
    return v[1] if isinstance(v, tuple) else v


def field_list(entries):
    """[{name: spec}, ...] -> [(name, spec), ...], preserving declared order."""
    out = []
    for entry in entries:
        kind, body = entry
        if kind != "map" or len(body) != 1:
            raise SyntaxError("expected a single-key field table, got %r" % (body,))
        (name, spec), = body.items()
        out.append((name, unwrap(spec)))
    return out


def convert(name, spec):
    """One Lua field spec -> its JSON Schema object, plus whether it's required."""
    node = {}
    if "description" in spec:
        node["description"] = spec["description"]
    lua_type = spec.get("type")
    node["type"] = TYPE_MAP.get(lua_type, lua_type)

    if lua_type == "record":
        props = {}
        for sub_name, sub_spec in field_list(unwrap(spec["fields"])):
            props[sub_name], _ = convert(sub_name, sub_spec)
        node["properties"] = props
        return node, bool(spec.get("required"))

    if "default" in spec:
        node["default"] = spec["default"]
    if "one_of" in spec:
        node["enum"] = unwrap(spec["one_of"])
    if "between" in spec:
        node["between"] = unwrap(spec["between"])
    if spec.get("referenceable"):
        node["referenceable"] = True
    return node, bool(spec.get("required"))


def build():
    c = Cursor(open(LUA, encoding="utf-8").read())
    c.i = c.s.index("return")
    c.i += len("return")
    root = unwrap(parse_table(c))

    config = None
    for name, spec in field_list(unwrap(root["fields"])):
        if name == "config":
            config = spec
    if config is None:
        raise SyntaxError("no config record found in schema.lua")

    properties, required = {}, []
    for name, spec in field_list(unwrap(config["fields"])):
        node, is_required = convert(name, spec)
        properties[name] = node
        if is_required:
            required.append(name)

    return {"config": {"type": "object", "required": required,
                       "properties": properties}}


def main():
    generated = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        current = open(JSON_OUT, encoding="utf-8").read()
        if current != generated:
            sys.stderr.write(
                "schema.json is out of date with schema.lua.\n"
                "Run: python3 tools/gen-schema-json.py\n")
            return 1
        print("schema.json matches schema.lua")
        return 0
    open(JSON_OUT, "w", encoding="utf-8").write(generated)
    print("wrote %s (%d fields)"
          % (os.path.relpath(JSON_OUT, ROOT), len(build()["config"]["properties"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
