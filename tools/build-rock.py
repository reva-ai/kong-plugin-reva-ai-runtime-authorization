#!/usr/bin/env python3
"""Rebuild plugin/kong-plugin-reva-ai-runtime-authorization-<version>.all.rock.

A .all.rock is a zip carrying its own copies of the rockspec, the plugin Lua
and doc/README.md, plus a rock_manifest of MD5 checksums. Those copies are what
LuaRocks installs and what Konnect renders the plugin form from -- so every
edit to schema.lua, handler.lua, the rockspec or README.md is invisible until
the rock is rebuilt. It had silently gone stale once; this script exists so it
cannot again.

Equivalent to `luarocks pack`, but with no luarocks dependency.

Usage:
    python3 tools/build-rock.py            # rebuild the rock
    python3 tools/build-rock.py --check    # exit 1 if the rock is out of date
"""

import hashlib
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(ROOT, "plugin")
NAME = "kong-plugin-reva-ai-runtime-authorization"
VERSION = "0.1.0-1"
PLUGIN_NAME = "reva-ai-runtime-authorization"

ROCKSPEC = "%s-%s.rockspec" % (NAME, VERSION)
ROCK = os.path.join(PLUGIN, "%s-%s.all.rock" % (NAME, VERSION))

LUA_DIR = "lua/kong/plugins/%s" % PLUGIN_NAME

# archive path -> source file on disk
MEMBERS = [
    (ROCKSPEC, os.path.join(PLUGIN, ROCKSPEC)),
    ("%s/handler.lua" % LUA_DIR, os.path.join(PLUGIN, "handler.lua")),
    ("%s/schema.lua" % LUA_DIR, os.path.join(PLUGIN, "schema.lua")),
    ("doc/README.md", os.path.join(PLUGIN, "README.md")),
]

# Directory entries, in the order luarocks emits them.
DIRS = ["lua/", "lua/kong/", "lua/kong/plugins/", "%s/" % LUA_DIR, "doc/"]


def md5(path):
    with open(path, "rb") as fh:
        return hashlib.md5(fh.read()).hexdigest()


def manifest():
    """Emit rock_manifest in luarocks' own formatting: 3-space indent,
    alphabetical keys, bracket-quoted keys that are not bare identifiers."""
    d = md5(os.path.join(PLUGIN, "README.md"))
    r = md5(os.path.join(PLUGIN, ROCKSPEC))
    h = md5(os.path.join(PLUGIN, "handler.lua"))
    s = md5(os.path.join(PLUGIN, "schema.lua"))
    return (
        'rock_manifest = {\n'
        '   doc = {\n'
        '      ["README.md"] = "%s"\n'
        '   },\n'
        '   ["%s"] = "%s",\n'
        '   lua = {\n'
        '      kong = {\n'
        '         plugins = {\n'
        '            ["%s"] = {\n'
        '               ["handler.lua"] = "%s",\n'
        '               ["schema.lua"] = "%s"\n'
        '            }\n'
        '         }\n'
        '      }\n'
        '   }\n'
        '}\n' % (d, ROCKSPEC, r, PLUGIN_NAME, h, s)
    )


# Unix permissions, as luarocks writes them. Python's default (0o600, with no
# file-type bits) extracts directories with no execute bit -- they cannot be
# traversed -- and files only the owner can read, which breaks a plugin
# installed system-wide and read by Kong's worker user.
FILE_ATTR = (0o100644 << 16)          # regular file, rw-r--r--
DIR_ATTR = (0o040755 << 16) | 0x10    # directory, rwxr-xr-x + MS-DOS dir flag


def _info(name, attr):
    info = zipfile.ZipInfo(name)
    info.external_attr = attr
    info.create_system = 3            # Unix
    return info


def build(path):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        def add_file(arc, data):
            z.writestr(_info(arc, FILE_ATTR), data, zipfile.ZIP_DEFLATED)

        add_file(MEMBERS[0][0], open(MEMBERS[0][1], "rb").read())
        for dirname in DIRS[:4]:
            z.writestr(_info(dirname, DIR_ATTR), b"")
        for arc, src in MEMBERS[1:3]:
            add_file(arc, open(src, "rb").read())
        z.writestr(_info(DIRS[4], DIR_ATTR), b"")
        add_file(MEMBERS[3][0], open(MEMBERS[3][1], "rb").read())
        add_file("rock_manifest", manifest())


def check():
    """True when the packed rock matches what is on disk now."""
    if not os.path.exists(ROCK):
        return False, ["rock does not exist"]
    stale = []
    with zipfile.ZipFile(ROCK) as z:
        names = set(z.namelist())
        for arc, src in MEMBERS:
            if arc not in names:
                stale.append("%s missing from rock" % arc)
            elif z.read(arc) != open(src, "rb").read():
                stale.append("%s differs from %s" % (arc, os.path.relpath(src, ROOT)))
        if "rock_manifest" not in names:
            stale.append("rock_manifest missing")
        elif z.read("rock_manifest").decode() != manifest():
            stale.append("rock_manifest checksums are stale")
    return not stale, stale


def main():
    if "--check" in sys.argv:
        ok, why = check()
        if ok:
            print("rock matches plugin/ sources")
            return 0
        for w in why:
            print("  stale: %s" % w)
        print("Run: python3 tools/build-rock.py")
        return 1
    build(ROCK)
    ok, why = check()
    if not ok:
        sys.stderr.write("rebuild did not verify: %s\n" % why)
        return 1
    size = os.path.getsize(ROCK)
    print("wrote %s (%d bytes, %d entries)"
          % (os.path.relpath(ROCK, ROOT), size,
             len(zipfile.ZipFile(ROCK).namelist())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
