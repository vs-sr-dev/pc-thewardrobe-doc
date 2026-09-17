#!/usr/bin/env python3
"""qshell.py -- the shop's layer: its descriptor, its cache, and its footprints.

Three jobs, all of them about who verified what.

`hashdb` reads `goggame-<id>.hashdb`. It is 244 bytes and it is a ZIP; inside is
one member of 2,124 bytes with the same name, and inside that is a header of
twelve bytes and a run of 1,056-byte records: 1,024 of zero-padded name and 32
of hash written in ASCII hexadecimal rather than in binary. The tool checks the
arithmetic (12 + n x 1056 = the member size) and then recomputes every hash
against the file it names.

`webcache` reads `webcache.zip`, whose members are named with 64 hexadecimal
characters. That is the shape of a SHA-256, so the tool tests whether each name
*is* the SHA-256 of the bytes stored under it. A name that is its own checksum
is a third kind of descriptor, and it is worth knowing whether it holds.

`fingerprints` counts -- and refuses to print -- the identifiers belonging to
the machine this copy was installed on. The rule in this branch is that a
personal identifier is counted and not written; the point of doing it in a tool
is that the count is reproducible without the string ever reaching a document.

    python tools/qshell.py hashdb _game
    python tools/qshell.py webcache _game/webcache.zip
    python tools/qshell.py fingerprints _game
"""

import argparse
import hashlib
import io
import os
import re
import sys
import zipfile
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HDR = 12
REC = 1056
NAMELEN = 1024
HASHLEN = 32


def cmd_hashdb(a):
    root = a.root
    cand = [f for f in os.listdir(root) if f.endswith(".hashdb")]
    if not cand:
        print("no .hashdb in %s" % root, file=sys.stderr)
        return 2
    path = os.path.join(root, cand[0])
    outer = open(path, "rb").read()
    print("descriptor          %s" % cand[0])
    print("bytes on disc       %d" % len(outer))
    print("first four bytes    %s  (%s)"
          % (outer[:4].hex(), "a ZIP local file header"
             if outer[:4] == b"PK\x03\x04" else "not a ZIP"))
    z = zipfile.ZipFile(io.BytesIO(outer))
    print("members             %s" % z.namelist())
    inner = z.read(z.namelist()[0])
    print("inflated to         %d bytes" % len(inner))
    print("header              %s" % inner[:HDR].hex(" "))
    n, rem = divmod(len(inner) - HDR, REC)
    print("arithmetic          %d + %d x %d = %d, remainder %d"
          % (HDR, n, REC, HDR + n * REC, rem))
    if rem:
        print("the record size does not divide the payload", file=sys.stderr)
        return 2
    print()
    print("%-4s %-24s %-34s %s" % ("#", "name", "hash as stored", "verdict"))
    ok = 0
    covered = 0
    for i in range(n):
        p = HDR + i * REC
        nm = inner[p:p + NAMELEN].rstrip(b"\x00").decode("utf-8", "replace")
        hx = inner[p + NAMELEN:p + NAMELEN + HASHLEN].decode("ascii", "replace")
        target = os.path.join(root, nm.replace("\\", os.sep))
        if os.path.exists(target):
            covered += os.path.getsize(target)
            h = hashlib.md5()
            with open(target, "rb") as fh:
                while True:
                    b = fh.read(1 << 22)
                    if not b:
                        break
                    h.update(b)
            good = h.hexdigest() == hx.lower()
            ok += good
            v = "md5 verifies" if good else "MD5 DOES NOT MATCH"
        else:
            v = "file not present"
        print("%-4d %-24s %-34s %s" % (i, nm, hx, v))
    total_files = sum(len(fs) for _, _, fs in os.walk(root))
    total_bytes = sum(os.path.getsize(os.path.join(d, f))
                      for d, _, fs in os.walk(root) for f in fs)
    print()
    print("records             %d" % n)
    print("verified            %d" % ok)
    print("coverage by count   %d of %d files = %.4f %%"
          % (n, total_files, 100.0 * n / total_files))
    print("coverage by bytes   %d of %d = %.4f %%"
          % (covered, total_bytes, 100.0 * covered / total_bytes))
    print("hash written as     32 characters of ASCII hexadecimal, i.e. an "
          "md5 at twice its own size")
    return 0


def cmd_webcache(a):
    z = zipfile.ZipFile(a.zip)
    print("members             %d" % len(z.infolist()))
    dates = Counter(i.date_time for i in z.infolist())
    print("member timestamps   %s" % dict(dates))
    named = 0
    verified = 0
    print()
    print("%-46s %9s %9s %s" % ("member", "stored", "deflated", "name is its "
                                "own sha-256"))
    for i in z.infolist():
        b = z.read(i.filename)
        stem = os.path.splitext(i.filename)[0]
        head = stem.split("_")[0]
        v = ""
        if re.fullmatch(r"[0-9a-f]{64}", head):
            named += 1
            v = "yes" if hashlib.sha256(b).hexdigest() == head else "no"
            verified += (v == "yes")
        print("%-46s %9d %9d %s"
              % (i.filename[:46], i.file_size, i.compress_size, v))
    print()
    print("members whose name begins with 64 hex characters: %d" % named)
    print("of those, the name equals the sha-256 of the bytes: %d" % verified)
    print("distinct 64-hex stems: %d"
          % len({os.path.splitext(i.filename)[0].split("_")[0]
                 for i in z.infolist()
                 if re.fullmatch(r"[0-9a-f]{64}",
                                 os.path.splitext(i.filename)[0].split("_")[0])}))
    return 0


def cmd_fingerprints(a):
    """Count what belongs to this machine. Never print it."""
    root = os.path.abspath(a.root)
    # The installation records its own location. Recover the token from the
    # config the installer wrote, then count it everywhere -- without echoing.
    ini = os.path.join(root, "queen.ini")
    tokens = set()
    if os.path.exists(ini):
        for line in open(ini, encoding="latin1"):
            m = re.search(r"(?i)^(path|savepath)\s*=\s*(.+)$", line.strip())
            if m:
                p = m.group(2).strip()
                tokens.add(p)
                tokens.add(p.split(os.sep)[0] if os.sep in p else p[:2])
                tokens.add(p[:2])
    tokens = {t for t in tokens if len(t) >= 2}
    if not tokens:
        print("no installation path recorded in queen.ini")
        return 0
    longest = max(tokens, key=len)
    parts = [x for x in re.split(r"[\\/]", longest) if x]
    drive = parts[0]
    # The token counted below is the directory the game was installed into,
    # without the sub-directory the config appends. It is the longest string
    # that is certainly this machine's and nobody else's, and it never leaves
    # this function.
    stem = chr(92).join(parts[:3]) if len(parts) >= 3 else longest
    print("the installation records its own location; the strings below are")
    print("counted and never written out.")
    print()
    print("%-42s %6s %s" % ("file", "hits", "what is in it"))
    total = 0
    for d, _dn, fns in os.walk(root):
        for fn in sorted(fns):
            p = os.path.join(d, fn)
            if os.path.getsize(p) > 64 * 1024 * 1024:
                continue
            b = open(p, "rb").read()
            hits = 0
            kinds = set()
            for enc, tag in (("latin1", "ansi"), ("utf-16-le", "utf-16")):
                try:
                    pat = stem.lower().encode(enc)
                except Exception:
                    continue
                c = b.lower().count(pat)
                if c:
                    hits += c
                    kinds.add("installation path (%s)" % tag)
            if hits:
                rel = os.path.relpath(p, root).replace(os.sep, "/")
                print("%-42s %6d %s" % (rel, hits, ", ".join(sorted(kinds))))
                total += hits
    print()
    print("occurrences of the installation path: %d" % total)
    print()
    print("two more identifiers live in the shortcut and are of a different")
    print("kind: a volume label and a NetBIOS computer name. They are counted")
    print("here by structure, not by string:")
    lnk = [os.path.join(root, f) for f in os.listdir(root) if f.endswith(".lnk")]
    for p in lnk:
        b = open(p, "rb").read()
        rel = os.path.basename(p)
        # Shell Link: VolumeIDAndLocalBasePath / CommonNetworkRelativeLink
        vol = b.count(b"\x00\x00\x00\x00") and True
        nb = re.findall(rb"[A-Z0-9][A-Z0-9-]{1,14}\x00", b[:400])
        print("  %-40s %d bytes, %d uppercase NetBIOS-shaped tokens in the "
              "first 400" % (rel, len(b), len(nb)))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hashdb")
    h.add_argument("root")
    h.set_defaults(fn=cmd_hashdb)
    w = sub.add_parser("webcache")
    w.add_argument("zip")
    w.set_defaults(fn=cmd_webcache)
    f = sub.add_parser("fingerprints")
    f.add_argument("root")
    f.set_defaults(fn=cmd_fingerprints)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
