#!/usr/bin/env python3
"""leakhere.py -- the leak check this object actually needs.

Three inherited checks refuse to run here, and all three are right to:

  * `leakcheck.py` and `envblock.py --leakcheck` each assert that they have
    something to look for before reporting CLEAN, and on this object neither
    has: `contacts.py` classified 31 strings as person-shaped and every one of
    them is inside a compressed member of a `.pak`, so there is no recovered
    identifier to search the repository for;
  * `leakthis.py`, written yesterday, looks for the individual named in
    `Manual.pdf`'s `/Author` field. This manual has no `/Author` field, so
    yesterday's tool asserts and stops. A tool that finds nothing is not a tool
    that says zero.

What this object *does* carry, and yesterday's did not, is **a name inside every
one of 1,987 compiled assets**: the `EMDF` header's string table opens with two
fields that look like the login and the surname of whoever exported the asset,
23 distinct values across the archive. Those are the strings that must not reach
`docs/`, `notes/`, `tools/` or `README.md`. They are read from the object at run
time and never written to disk by this script.

Four classes of string are checked:

  1. the root directory of the installation on this machine;
  2. the drive letter that root sits on, in any path shape;
  3. the 23 distinct author fields recovered from the `EMDF` headers;
  4. a positive control that MUST fire, so a clean report means the search ran.

    python tools/leakhere.py "<install dir>"

The root is an argument, never a constant: a leak check that carries the path
it is looking for is itself the leak.
"""
import os
import re
import struct
import sys

if len(sys.argv) < 2:
    sys.exit("usage: python tools/leakhere.py <install dir>")

ROOT = sys.argv[1].replace(os.sep, "/").rstrip("/")
DRIVE = ROOT.split("/")[0]
PAD = re.compile(rb"^(?:ALIGN)*(?:A|AL|ALI|ALIG)?")

# ---- recover the author fields from the object, in memory only ------------
authors = set()
arch = os.path.join(ROOT, "bs4.pak")
if os.path.exists(arch):
    fh = open(arch, "rb")
    magic = fh.read(8)
    assert magic == b"EmPackFi", "%s is not an EmPackFi archive" % arch
    _z, _hend, count, _four = struct.unpack("<IIII", fh.read(16))
    fh.seek(24)
    raw = fh.read(12 * count)
    for i in range(count):
        _n, size, off = struct.unpack_from("<III", raw, i * 12)
        if size < 512:
            continue
        fh.seek(off)
        head = fh.read(512)
        m = 8 if head[8:12] == b"EMDF" else (4 if head[4:8] == b"EMDF" else -1)
        if m < 0:
            continue
        # Field 2 only: the upper-case, surname-shaped one. Field 1 is a short
        # login, and its two- and three-letter cases match ordinary English
        # text -- searching for those turns every file in the repository into
        # a false positive, which is what the first run of this tool did.
        parts = head[m + 304:m + 400].split(b"\x00")
        if len(parts) < 2:
            continue
        v = PAD.sub(b"", parts[1])
        if 5 <= len(v) <= 40 and v.isupper() and v.isalpha():
            authors.add(v.decode("latin-1"))

assert authors, ("no EMDF author fields recovered: this check has nothing to "
                 "look for and will not report CLEAN")

CONTROL = "EmPackFi"          # must appear in the repository, or the search is broken
# The drive letter is only a leak when it is PATH-SHAPED. `F:` on its own
# matches "of:" and "if:" in ordinary prose and in a hundred format strings,
# and the first run of this tool reported 108 such false positives.
needles = [("the installation root", ROOT),
           ("the drive letter, as a path", DRIVE + "/"),
           ("the drive letter, as a path", DRIVE + chr(92))]
needles += [("an EMDF author field", a) for a in sorted(authors)]

targets = []
for d in ("docs", "notes", "tools"):
    for dp, dn, fn in os.walk(d):
        for f in fn:
            if f.endswith((".md", ".txt", ".tsv", ".py")):
                targets.append(os.path.join(dp, f))
if os.path.exists("README.md"):
    targets.append("README.md")

print("root given as an argument : yes")
print("author fields recovered   : %d (not printed)" % len(authors))
print("files searched            : %d" % len(targets))

hits = 0
control_hits = 0
for t in targets:
    try:
        body = open(t, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    if CONTROL in body:
        control_hits += 1
    for label, needle in needles:
        if not needle:
            continue
        if needle.lower() in body.lower():
            hits += 1
            print("   LEAK  %-46s %s" % (t, label))

print()
print("POSITIVE CONTROL: the string %r appears in %d of %d files"
      % (CONTROL, control_hits, len(targets)))
if control_hits == 0:
    sys.exit("the control did not fire -- the search did not run; CLEAN would "
             "be meaningless")
print("needles searched  : %d  (1 root, 1 drive letter, %d author fields)"
      % (len(needles), len(authors)))
print("leaks found       : %d" % hits)
print("verdict           : %s" % ("CLEAN" if hits == 0 else "NOT CLEAN"))
sys.exit(1 if hits else 0)
