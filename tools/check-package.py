#!/usr/bin/env python3
"""Pre-submission gate for the Reva AI Runtime Authorization Kong Plugin Hub package.

Every check here exists because the package failed it at least once. Run it
before handing anything to Kong:

    python3 tools/check-package.py

Exits non-zero if any check fails. Scans the loose files AND the members of
the packed .all.rock, because the rock carries its own copies of the rockspec,
the plugin Lua and doc/README.md -- that is where a stale copy hides.
"""

import io
import json
import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(ROOT, "plugin")
ROCKSPEC_NAME = "kong-plugin-reva-ai-runtime-authorization-0.1.0-1.rockspec"
ROCK_NAME = "kong-plugin-reva-ai-runtime-authorization-0.1.0-1.all.rock"
SKIP_DIRS = {"__pycache__", ".git", "tools"}
SKIP_NAMES = {".DS_Store"}
BINARY_EXT = {".rock", ".pyc", ".png", ".jpg", ".gif"}

failures = []
notes = []


def shipping_files():
    """(label, text) for every shippable text file, rock members included."""
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS
                       and not d.startswith(".bak-")]
        for fn in sorted(filenames):
            if fn in SKIP_NAMES:
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, ROOT)
            ext = os.path.splitext(fn)[1]
            if ext == ".rock":
                try:
                    z = zipfile.ZipFile(path)
                except zipfile.BadZipFile:
                    failures.append(("rock is not a valid zip", rel))
                    continue
                for member in z.namelist():
                    if member.endswith("/"):
                        continue
                    try:
                        yield ("%s!%s" % (rel, member),
                               z.read(member).decode("utf-8"))
                    except UnicodeDecodeError:
                        pass
                continue
            if ext in BINARY_EXT:
                continue
            try:
                yield rel, open(path, encoding="utf-8").read()
            except (UnicodeDecodeError, IsADirectoryError):
                pass


def check(label, pattern, why, flags=re.I, allow=()):
    """Fail if `pattern` matches any shipping file. Multiline by default:
    a line-wrapped 'Reva Trust\\nGateway' evaded a single-line grep once."""
    rx = re.compile(pattern, flags | re.S)
    hits = []
    for rel, text in shipping_files():
        for m in rx.finditer(text):
            frag = " ".join(text[max(0, m.start() - 50):m.end() + 30].split())
            if any(a in frag for a in allow):
                continue
            line = text[:m.start()].count("\n") + 1
            hits.append("%s:%s  ...%s..." % (rel, line, frag))
    if hits:
        failures.append((label, why, hits))
        print("  FAIL  %s (%d)" % (label, len(hits)))
        for h in hits[:6]:
            print("          %s" % h)
        if len(hits) > 6:
            print("          ... and %d more" % (len(hits) - 6))
    else:
        print("  ok    %s" % label)


print("Package gate: %s\n" % ROOT)
print("Content checks")

check("no obsolete product name", r"Trust\s+Gateway",
      "the product is Reva Trust Guardian; 'Trust Gateway' is retired")

check("no retired plugin name",
      r"reva[-_ ]ai[-_ ]governance|Reva\s+AI\s+Governance",
      "the plugin is Reva AI Runtime Authorization; the identifier is "
      "reva-ai-runtime-authorization")

check("no internal hosts", r"\b(?:api\.)?(?:pr0\d|dv0\d)\b[\w.]*",
      "internal preview/dev hosts must be api.example.reva.ai")

check("no internal repo URLs", r"gitlab\.com|\bpm_demo\b",
      "the private monorepo is unreachable to anyone installing this")

check("no internal infrastructure",
      r"\bPDP_check\b|request-callout|reva-guardrail-gateway|konnect-upload|"
      r"konnect-enable|\bdemo-app\b|\bdataplane/|\bngrok\b",
      "internal prototype and demo plumbing must not ship")

check("no project-status language",
      r"\bParked\b|resume trigger|waiting on Reva|One open design decision|"
      r"internal review",
      "status notes belong in the tracker, not in a customer file")

check("no British spellings",
      r"\b\w*(?:behaviour|serialis|normalis|recognis|authoris|organis|initialis)\w*\b",
      "Kong's docs are American English")

check("no credential values",
      r"\beyJ[A-Za-z0-9_-]{10,}", "a token literal must never ship")

print("\nStyle checks")


def check_tooltips():
    """The A3 house rule: a form tooltip is read in isolation, so it never
    uses a bare acronym and never single-quotes a value."""
    schema = json.load(open(os.path.join(ROOT, "documentation", "schema.json")))
    fields = {}

    def walk(props, prefix=""):
        for k, v in props.items():
            fields[prefix + k] = v
            if "properties" in v:
                walk(v["properties"], prefix + k + ".")
    walk(schema["config"]["properties"])

    bad = []
    for name, spec in fields.items():
        d = spec.get("description")
        if not d:
            bad.append("%s has no description" % name)
            continue
        words = len(d.split())
        if "RTG" in d:
            bad.append("%s uses bare 'RTG'" % name)
        if re.search(r"'[\w./:{}\-]+'", d):
            bad.append("%s single-quotes a value (use backticks)" % name)
        if " - " in d:
            bad.append("%s uses a hyphen where an em dash belongs" % name)
        if not d.rstrip().endswith("."):
            bad.append("%s does not end in a period" % name)
        if words > 45:
            bad.append("%s is %d words (cap 45)" % (name, words))
    if bad:
        failures.append(("tooltip house style", bad))
        print("  FAIL  tooltip house style (%d)" % len(bad))
        for b in bad[:8]:
            print("          %s" % b)
    else:
        print("  ok    tooltip house style (%d fields)" % len(fields))


check_tooltips()


def check_anchors():
    idx = os.path.join(ROOT, "documentation", "index.md")
    schema = json.load(open(os.path.join(ROOT, "documentation", "schema.json")))
    valid = set()

    def walk(props, prefix=""):
        for k, v in props.items():
            full = prefix + k
            valid.add(full.replace("_", "-").replace(".", "-"))
            if "properties" in v:
                walk(v["properties"], full + ".")
    walk(schema["config"]["properties"])
    used = set(re.findall(r"#schema--([a-z0-9-]+)", open(idx).read()))
    dangling = sorted(a for a in used if a not in valid)
    if dangling:
        failures.append(("reference anchors", dangling))
        print("  FAIL  reference anchors: %s" % dangling)
    else:
        print("  ok    reference anchors (%d used, all resolve)" % len(used))


check_anchors()


def check_min_version():
    """Three different minimum versions shipped once."""
    # Only claims that declare a supported FLOOR. "tested on 3.15.0.5" is a
    # statement about what was exercised, not a floor, and must not conflict.
    floor_patterns = [
        r"Requires Kong Gateway (\d+\.\d+) or later",
        r"min_version\.gateway declared as (\d+\.\d+)",
        r"gateway:\s*'(\d+\.\d+)'",
    ]
    versions = {}
    for rel, text in shipping_files():
        for pat in floor_patterns:
            for m in re.finditer(pat, text):
                versions.setdefault(m.group(1), []).append(rel)
    floors = {v: sorted(set(f)) for v, f in versions.items()}
    if len(floors) > 1:
        failures.append(("minimum gateway version", floors))
        print("  FAIL  minimum gateway version disagrees: %s"
              % {v: f for v, f in floors.items()})
    else:
        print("  ok    minimum gateway version (%s)"
              % (list(floors) or ["none declared"])[0])


check_min_version()

print("\nConsistency checks (delegated)")
for script, label in [("gen-schema-json.py", "schema.json matches schema.lua"),
                      ("build-rock.py", "packed rock matches plugin/ sources")]:
    rc = os.system("python3 %s --check >/dev/null 2>&1"
                   % os.path.join(ROOT, "tools", script))
    if rc == 0:
        print("  ok    %s" % label)
    else:
        failures.append((label, "run: python3 tools/%s" % script))
        print("  FAIL  %s  ->  python3 tools/%s" % (label, script))


def check_referenced_files():
    missing = []
    for rel, text in shipping_files():
        if not rel.endswith((".md", ".txt")) or "!" in rel:
            continue
        base = os.path.dirname(os.path.join(ROOT, rel))
        # A leading "/" is a Jekyll site-root link (e.g. /plugins/jwt/),
        # resolved when Kong builds the site -- not a file in this package.
        # Skip anything with a URL scheme (https:, mailto:, ...), Kong's
        # generated reference anchors, in-page anchors, and site-root links.
        for m in re.finditer(
                r"\[[^\]]+\]\((?![a-z][a-z0-9+.-]*:|\./reference|#|/)([^)]+)\)", text):
            target = m.group(1).split("#")[0]
            if not target:
                continue
            if not os.path.exists(os.path.join(base, target)):
                missing.append("%s -> %s" % (rel, target))
    if missing:
        failures.append(("referenced files exist", missing))
        print("  FAIL  referenced files exist: %s" % missing)
    else:
        print("  ok    referenced files exist")


check_referenced_files()



def check_lua():
    """Real compile, not a parse. schema.lua and handler.lua ship inside the
    rock too, so the embedded copies are checked as well. Kong runs LuaJIT
    (5.1 semantics), so prefer it; fall back to luac; skip if neither exists."""
    import shutil
    import subprocess
    import tempfile

    if shutil.which("luajit"):
        cmd, label = ["luajit", "-b"], "luajit"
    elif shutil.which("luac"):
        cmd, label = ["luac", "-p"], "luac"
    else:
        notes.append("lua syntax check skipped: install luajit or lua "
                     "(brew install luajit lua luarocks)")
        print("  skip  lua syntax check (no luajit/luac on PATH)")
        return

    def compiles(path):
        args = cmd + [path] + (["/dev/null"] if label == "luajit" else [])
        r = subprocess.run(args, capture_output=True)
        return r.returncode == 0, r.stderr.decode().strip()

    bad = []
    for rel in ["plugin/schema.lua", "plugin/handler.lua"]:
        ok, err = compiles(os.path.join(ROOT, rel))
        if not ok:
            bad.append("%s: %s" % (rel, err))

    rock = os.path.join(PLUGIN_DIR, ROCK_NAME)
    if os.path.exists(rock):
        with zipfile.ZipFile(rock) as z:
            for member in z.namelist():
                if not member.endswith(".lua"):
                    continue
                with tempfile.NamedTemporaryFile(suffix=".lua", delete=False) as tf:
                    tf.write(z.read(member))
                    tmp = tf.name
                ok, err = compiles(tmp)
                os.unlink(tmp)
                if not ok:
                    bad.append("rock!%s: %s" % (member, err))

    if bad:
        failures.append(("lua syntax", bad))
        print("  FAIL  lua syntax (%s)" % label)
        for b in bad:
            print("          %s" % b)
    else:
        print("  ok    lua syntax (%s, loose files + rock members)" % label)


def check_rockspec_lint():
    import shutil
    import subprocess
    if not shutil.which("luarocks"):
        notes.append("rockspec lint skipped: install luarocks")
        print("  skip  rockspec lint (no luarocks on PATH)")
        return
    spec = os.path.join(PLUGIN_DIR, ROCKSPEC_NAME)
    r = subprocess.run(["luarocks", "lint", spec], capture_output=True)
    if r.returncode == 0:
        print("  ok    rockspec lint")
    else:
        failures.append(("rockspec lint", r.stdout.decode() + r.stderr.decode()))
        print("  FAIL  rockspec lint: %s"
              % (r.stdout.decode() + r.stderr.decode()).strip()[:200])


def check_plugin_hub_conventions():
    """Conventions the Plugin Hub itself imposes, measured against Kong's own
    published third-party plugin pages (noma-runtime-protection is the model).
    Getting these wrong does not break our package -- it breaks the rendered
    page in Kong's repo, which is much harder to notice."""
    bad = []
    doc = os.path.join(ROOT, "documentation")

    def frontmatter(path):
        text = open(path, encoding="utf-8").read()
        m = re.match(r"^---\n(.*?)\n---", text, re.S)
        return (m.group(1) if m else None), text

    # index.md frontmatter: the 12 keys every plugin page declares.
    REQUIRED = ["title", "name", "content_type", "publisher", "description",
                "products", "works_on", "third_party", "support_url", "icon",
                "search_aliases", "min_version"]
    fm, text = frontmatter(os.path.join(doc, "index.md"))
    if fm is None:
        bad.append("index.md has no YAML frontmatter")
    else:
        present = {l.split(":")[0] for l in fm.split("\n")
                   if re.match(r"^[a-z_]+:", l)}
        for k in REQUIRED:
            if k not in present:
                bad.append("index.md frontmatter is missing `%s`" % k)
        ct = re.search(r"^content_type:\s*(\S+)", fm, re.M)
        if ct and ct.group(1) != "plugin":
            bad.append("index.md content_type is `%s`, expected `plugin`"
                       % ct.group(1))
        icon = re.search(r"^icon:\s*(\S+)", fm, re.M)
        if icon and not os.path.exists(os.path.join(doc, icon.group(1))):
            bad.append("index.md icon `%s` is not in documentation/"
                       % icon.group(1))

    # reference.md: `content_type: reference` and nothing else. Kong's repo has
    # 149 of these and zero carry a title; `plugin_reference` does not exist.
    rfm, rtext = frontmatter(os.path.join(doc, "reference.md"))
    if rfm is None:
        bad.append("reference.md has no YAML frontmatter")
    else:
        ct = re.search(r"^content_type:\s*(\S+)", rfm, re.M)
        if not ct or ct.group(1) != "reference":
            bad.append("reference.md content_type is `%s`, expected `reference`"
                       % (ct.group(1) if ct else "absent"))
        if re.search(r"^title:", rfm, re.M):
            bad.append("reference.md declares a title; Kong's plugin "
                       "reference pages carry none")

    # Liquid tags must balance or the page renders broken.
    for rel in ["index.md"]:
        t = open(os.path.join(doc, rel), encoding="utf-8").read()
        for open_tag, close_tag in [("navtabs", "endnavtabs"),
                                    ("navtab", "endnavtab")]:
            o = len(re.findall(r"{%-?\s*" + open_tag + r"[\s'\"]", t))
            c = len(re.findall(r"{%-?\s*" + close_tag + r"\s*-?%}", t))
            if o != c:
                bad.append("%s: %d `%s` vs %d `%s`"
                           % (rel, o, open_tag, c, close_tag))

    # The example that Kong turns into five install snippets.
    examples = [f for f in os.listdir(doc) if f.startswith("enable-")
                and f.endswith(".yaml")]
    if not examples:
        bad.append("no enable-<plugin>.yaml example")
    for ex in examples:
        efm, _ = frontmatter(os.path.join(doc, ex))
        etext = open(os.path.join(doc, ex), encoding="utf-8").read()
        src = efm if efm is not None else etext
        present = {l.split(":")[0] for l in src.split("\n")
                   if re.match(r"^[a-z_]+:", l)}
        for k in ["description", "extended_description", "title", "weight",
                  "requirements", "variables", "config", "tools", "min_version"]:
            if k not in present:
                bad.append("%s is missing `%s`" % (ex, k))

    if bad:
        failures.append(("Plugin Hub conventions", bad))
        print("  FAIL  Plugin Hub conventions (%d)" % len(bad))
        for b in bad[:10]:
            print("          %s" % b)
    else:
        print("  ok    Plugin Hub conventions")


print("\nPlugin Hub conventions")
check_plugin_hub_conventions()

print("\nLua toolchain checks")
check_lua()
check_rockspec_lint()

print()
if failures:
    print("FAILED: %d check(s)" % len(failures))
    sys.exit(1)
for n in notes:
    print("note: %s" % n)
print("All checks passed.")
sys.exit(0)
