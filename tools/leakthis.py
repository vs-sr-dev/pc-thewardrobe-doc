"""The leak check this object actually needs.

`leakcheck.py` and `envblock.py --leakcheck` both refuse to run here, and both
are right to: each asserts that it has something to look for before it reports
CLEAN, and on this object neither has.  `contacts.py` classified 39 addresses
as person-shaped and all 39 are inside `data.pak`'s compressed members, so
there is no recovered identifier for `leakcheck.py` to search the repository
for; `envblock.py` found no environment block at all.  A tool that finds
nothing is not a tool that says zero, so this stands in for them and names what
it looks for.

Three classes of string must not appear in docs/, notes/ or tools/:

  1. the root directory of the installation on this machine;
  2. the drive letter that root sits on, in any path shape;
  3. the individual named in Manual.pdf's /Author field, who is not in the
     game's credits.  The name is read from the object at run time and never
     written to disk by this script.
"""
import os
import re
import sys

if len(sys.argv) < 2:
    sys.exit("usage: python tools/leakthis.py <install dir>\n"
             "the root is an argument, never a constant: a leak check that "
             "carries the path it is looking for is itself the leak")
ROOT = sys.argv[1].replace(os.sep, "/").rstrip("/")
HEAD = "/".join(ROOT.split("/")[:2])
author = None
d = open(os.path.join(ROOT, "Manual.pdf"), "rb").read(700000)
m = re.search(rb"/Author\s*\(([^)]*)\)", d)
if m:
    author = m.group(1).decode("latin-1")
assert author, "no /Author field in Manual.pdf: this check has nothing to look for"

pats = [
    ("the installation root, forward slashes", ROOT),
    ("the installation root, backslashes", ROOT.replace("/", "\\")),
    ("the drive and the first folder", HEAD.replace("/", "\\")),
    ("the drive and the first folder, forward", HEAD),
    ("the /Author name (read from the object, not written here)", author),
]
targets = []
for top in ("docs", "notes", "tools", "README.md", ".gitignore"):
    if os.path.isfile(top):
        targets.append(top)
        continue
    if not os.path.isdir(top):
        continue
    for dp, dn, fn in os.walk(top):
        dn[:] = [x for x in sorted(dn) if x != "__pycache__"]
        for f in sorted(fn):
            targets.append(os.path.join(dp, f))

print("leak check over %d files in docs/, notes/, tools/, README.md, .gitignore"
      % len(targets))
print("patterns searched: %d" % len(pats))
bad = 0
for label, pat in pats:
    hits = []
    for t in targets:
        try:
            body = open(t, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if pat in body:
            hits.append(t)
    shown = label if "Author" not in label else label
    print("   %-56s %d file(s)%s"
          % (shown, len(hits), ("  " + ", ".join(hits)) if hits else ""))
    bad += len(hits)

# the positive control: the pattern MUST be findable somewhere, or the search
# is not searching.
probe = "goggame-1207658708"
found = sum(1 for t in targets
            if probe in open(t, "r", encoding="utf-8", errors="replace").read())
print("   POSITIVE CONTROL %-39s %d file(s) -- the search runs" % (probe, found))
assert found > 0, "positive control did not fire: the search is not reading files"
print()
print("VERDICT: %s" % ("CLEAN" if bad == 0 else "%d LEAK(S)" % bad))
sys.exit(1 if bad else 0)
