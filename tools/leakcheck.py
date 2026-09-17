"""leakcheck.py -- final leak check over docs/, notes/, tools/ and README.

The frame is inherited and the identifiers are not, because every object hides
a different thing. Yesterday's version read this machine's installation path,
volume label and NetBIOS name out of a GOG installation and searched for all
three. **This object contains none of them** -- it is a disc image, not an
installation, and it carries nothing about the computer it was read on.

What it does carry is one person's work e-mail address, twice, inside the
compressed video stream of its largest file. So the identifiers are derived
from the object the same way as before -- read out of it here, never typed in,
never printed -- but the derivation is different: instead of parsing a shortcut
and an INI file, this scans the tree for address-shaped strings and classifies
them the way `contacts.py` does, keeping only the ones that look like a person
rather than a role.

The tokens searched for are:

  * every person-shaped address found in the object, in full;
  * its local part alone, since a local part in a document is a leak even
    without the domain attached;
  * the local part with punctuation stripped, which is how such a thing tends
    to survive a careless paraphrase.

The domain is deliberately NOT searched for. `eng.capcom.co.jp` is a company,
not a person, and this repository names it on purpose.

    python tools/leakcheck.py _work/tree
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from contacts import ADDR, classify           # noqa: E402

root = sys.argv[1] if len(sys.argv) > 1 else "_work/tree"

addresses = set()
scanned = 0
for dp, dn, fn in os.walk(root):
    for f in fn:
        p = os.path.join(dp, f)
        scanned += 1
        try:
            data = open(p, "rb").read()
        except OSError:
            continue
        for m in ADDR.finditer(data):
            a = m.group(0).decode("latin-1")
            if classify(a) == "person":
                addresses.add(a)

assert addresses, ("no person-shaped address found in %s; either the object is "
                   "not the one this check was written for, or the classifier "
                   "changed. Refusing to report CLEAN on an empty search."
                   % root)

tokens = []
for a in sorted(addresses):
    local = a.split("@")[0]
    tokens.append(("full address", a))
    tokens.append(("local part", local))
    stripped = re.sub(r"[^A-Za-z0-9]", "", local)
    if stripped and stripped != local:
        tokens.append(("local part, punctuation stripped", stripped))

targets = []
for d in ("docs", "notes", "tools"):
    for dp, dn, fns in os.walk(d):
        for f in fns:
            if f.endswith(".pyc"):
                continue
            targets.append(os.path.join(dp, f))
for f in ("README.md", ".gitignore"):
    if os.path.exists(f):
        targets.append(f)

bad = 0
for kind, tok in tokens:
    hits = []
    for t in targets:
        try:
            s = open(t, encoding="utf-8", errors="replace").read().lower()
        except OSError:
            continue
        if tok.lower() in s:
            hits.append(t)
    print("%-34s %2d character(s), %d file(s) contain it%s"
          % (kind, len(tok), len(hits), (": " + ", ".join(hits)) if hits else ""))
    bad += len(hits)

print()
print("object files scanned  %d" % scanned)
print("addresses derived     %d  (not printed)" % len(addresses))
print("tokens searched       %d" % len(tokens))
print("repository files      %d" % len(targets))
print("VERDICT               %s" % ("CLEAN" if bad == 0 else "LEAK, %d" % bad))
sys.exit(0 if bad == 0 else 2)
