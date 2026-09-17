#!/usr/bin/env python3
"""threesets.py -- put a GOG galaxyFileList, a GOG hashdb and a disk against
each other and print all six differences, not three.

Three sessions of this branch have now met a GOG installation.  Deadly
Premonition had only `goggame-galaxyFileList.ini`, the file the Galaxy client
writes when it finishes downloading.  Trails in the Sky FC had only
`goggame-<id>.hashdb`, the file the offline installer leaves behind.  Broken
Sword 3 has both, and they do not declare the same set: one says 6,897, the
other 6,736, and the disk says something else again.

Three sets have seven regions and one of them is empty by construction (the
outside).  This prints the other six, plus the two intersections that matter,
and it does not privilege any of the three as "the object".  Which one is the
denominator is a decision for the prose, not for the tool.

    python tools/threesets.py --root "<install dir>"
    python tools/threesets.py --root "<install dir>" --full

Comparison is case-insensitive with backslashes normalised to forward slashes,
because the manifest is not consistent with the filesystem about either.
Nothing is executed, extracted or written.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gogmanifest
import hashdb


def norm(p):
    return p.replace("\\", "/").lstrip("./").lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--ini", default=None)
    ap.add_argument("--db", default=None)
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()

    ini = a.ini or os.path.join(a.root, "goggame-galaxyFileList.ini")
    if not os.path.exists(ini):
        sys.exit("no galaxyFileList at %s -- this object has only one manifest" % ini)
    db = a.db
    if db is None:
        cands = [f for f in os.listdir(a.root) if f.lower().endswith(".hashdb")]
        if len(cands) != 1:
            sys.exit("expected exactly one .hashdb in the root, found %d: %r"
                     % (len(cands), cands))
        db = os.path.join(a.root, cands[0])

    total, entries, sections = gogmanifest.read_manifest(ini)
    _, _, blob = hashdb.load(db)
    hdr, ver, count, mode, stride, recs, tried = hashdb.parse(blob)

    galaxy = {}
    for e in entries:
        galaxy.setdefault(norm(e), e)
    installer = {}
    for name, rec, n, tail, digest in recs:
        installer.setdefault(norm(name), name)
    disk = {}
    for dirpath, dirnames, filenames in os.walk(a.root):
        dirnames.sort()
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, a.root)
            disk[norm(rel)] = (rel, os.path.getsize(full))

    G, H, D = set(galaxy), set(installer), set(disk)

    def size(keys):
        return sum(disk[k][1] for k in keys if k in disk)

    regions = [
        ("declared by BOTH manifests and present on disk", G & H & D),
        ("declared by BOTH manifests and ABSENT from disk", (G & H) - D),
        ("declared by GALAXY only, present on disk", (G - H) & D),
        ("declared by GALAXY only, ABSENT from disk", (G - H) - D),
        ("declared by the INSTALLER only, present on disk", (H - G) & D),
        ("declared by the INSTALLER only, ABSENT from disk", (H - G) - D),
        ("present on disk, declared by NEITHER", D - G - H),
    ]

    print("galaxyFileList    : %s" % os.path.basename(ini))
    print("   sections       : %s"
          % ", ".join("[%s] %s" % (n, c) for n, c, _ in sections))
    print("   Fn= entries    : %d   distinct %d" % (len(entries), len(G)))
    print("hashdb            : %s" % os.path.basename(db))
    print("   header count   : %d   records read %d   mode %s" % (count, len(recs), mode))
    print("   distinct names : %d" % len(H))
    print("disk              : %d files, %d bytes" % (len(D), size(D)))
    print()
    print("the seven regions of three sets:")
    tot = 0
    for label, keys in regions:
        tot += len(keys)
        print("   %-50s %6d  %14d bytes" % (label, len(keys), size(keys)))
        if keys and (a.full or len(keys) <= 20):
            for k in sorted(keys):
                src = disk.get(k, (galaxy.get(k) or installer.get(k), 0))
                print("        %-56s %12d" % (src[0] if isinstance(src, tuple) else src,
                                              disk[k][1] if k in disk else 0))
    print("   %-50s %6d" % ("-- total accounted for", tot))
    print()
    print("check: |G u H u D| = %d, regions sum to %d -> %s"
          % (len(G | H | D), tot, "OK" if len(G | H | D) == tot else "MISMATCH"))
    print()
    print("the two intersections that decide the denominator:")
    print("   |G n D| = %6d   %14d bytes   (Galaxy, shipped)" % (len(G & D), size(G & D)))
    print("   |H n D| = %6d   %14d bytes   (installer, shipped)" % (len(H & D), size(H & D)))
    print("   |G n H| = %6d                        (the two manifests agreeing)"
          % len(G & H))
    print("   |D|     = %6d   %14d bytes   (the disk)" % (len(D), size(D)))
    print()
    # which section of the galaxyFileList do the shipped ones come from?
    off = 0
    for name, declared, n in sections:
        chunk = [norm(e) for e in entries[off:off + n]]
        off += n
        present = sum(1 for k in chunk if k in D)
        print("   section [%-12s] %5d entries, %5d present, %5d absent"
              % (name, n, present, n - present))


if __name__ == "__main__":
    main()
