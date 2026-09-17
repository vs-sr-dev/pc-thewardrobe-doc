#!/usr/bin/env python3
"""compratio.py -- check a shop's declared download size against what the tree
is actually worth compressed, and say how far apart they are.

Steam's `appmanifest` declares `BytesToDownload` beside `BytesToStage`. The
ratio between them is the only statement the shop makes about its own transfer
format, and it is untested until somebody compresses the tree.

The test is deliberately crude and its crudeness is the point: **compress every
file on its own with LZMA and add the results up.** That is not what Steam
does -- Steam chunks, deduplicates across a depot, and reuses a delta against
whatever the client already has -- so a per-file total is an upper bound on
what a smart packer achieves and a lower bound on nothing. Reporting the gap is
a measurement; calling the gap an error would not be.

`pc-rpgmaker2000-doc/docs/03` ran this arithmetic on its object and closed to
within 0.16 %. Whether that reproduces on a tree with a different mixture of
formats is the question, and the mixture here is very different: more MIDI,
more PNG, and a 6.2 MB help file that is already compressed inside itself.

    python tools/compratio.py <root> --declared 22100528
    python tools/compratio.py <root> --declared 22100528 --by-ext
    python tools/compratio.py --selftest
"""
import argparse
import collections
import lzma
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

FILTERS = [{"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME}]


def squeeze(blob):
    return len(lzma.compress(blob, format=lzma.FORMAT_RAW, filters=FILTERS))


def run(args):
    rows = []
    for dp, _dn, fn in os.walk(args.root):
        for f in sorted(fn):
            path = os.path.join(dp, f)
            blob = open(path, "rb").read()
            rows.append((os.path.relpath(path, args.root).replace(os.sep, "/"),
                         len(blob), squeeze(blob)))
    if not rows:
        raise SystemExit("compratio: no files under %s" % args.root)

    raw = sum(r[1] for r in rows)
    packed = sum(r[2] for r in rows)
    print("files            : %d" % len(rows))
    print("bytes on disk    : %d" % raw)
    print("LZMA, per file   : %d" % packed)
    print("ratio on disk / packed : %.4f" % (raw / packed))
    print()
    if args.declared:
        print("the shop declares BytesToDownload : %d" % args.declared)
        print("             against BytesToStage : %d" % raw)
        print("             a declared ratio of  : %.4f"
              % (raw / args.declared))
        gap = packed - args.declared
        print()
        print("  per-file LZMA total  : %d" % packed)
        print("  declared             : %d" % args.declared)
        print("  difference           : %+d bytes = %+.4f %% of the declared"
              % (gap, 100.0 * gap / args.declared))
        print()
        print("  (a positive difference means the shop ships the tree in")
        print("   FEWER bytes than compressing each file separately, which")
        print("   is what cross-file matching buys. A negative one means the")
        print("   shop's figure includes something this walk does not see.)")
    if args.by_ext:
        print()
        by = collections.defaultdict(lambda: [0, 0, 0])
        for name, n, m in rows:
            e = os.path.splitext(name)[1].lower() or "(none)"
            by[e][0] += 1
            by[e][1] += n
            by[e][2] += m
        print("  %-10s %5s %12s %12s %8s" % ("ext", "files", "on disk",
                                             "LZMA", "ratio"))
        for e, (c, n, m) in sorted(by.items(), key=lambda kv: -kv[1][1]):
            print("  %-10s %5d %12d %12d %8.4f"
                  % (e, c, n, m, (n / m) if m else 0))
    return 0


def selftest():
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    zeros = bytes(100000)
    check("a highly compressible block shrinks a lot",
          squeeze(zeros) < 1000, True)
    noise = os.urandom(100000)
    check("incompressible noise does not shrink",
          squeeze(noise) >= 100000 - 64, True)
    check("an empty file compresses to something small",
          squeeze(b"") < 64, True)
    check("compression is deterministic", squeeze(zeros), squeeze(zeros))
    text = b"the same sentence over and over. " * 3000
    check("repeated text shrinks below a hundredth",
          squeeze(text) * 100 < len(text), True)

    import shutil
    import tempfile
    tmp = tempfile.mkdtemp(prefix="compratio-")
    try:
        os.makedirs(os.path.join(tmp, "sub"))
        open(os.path.join(tmp, "a.bin"), "wb").write(zeros)
        open(os.path.join(tmp, "sub", "b.bin"), "wb").write(noise)
        rows = []
        for dp, _dn, fn in os.walk(tmp):
            for f in sorted(fn):
                p = os.path.join(dp, f)
                blob = open(p, "rb").read()
                rows.append((f, len(blob), squeeze(blob)))
        check("both files are walked", len(rows), 2)
        check("the raw total is the sum of the two",
              sum(r[1] for r in rows), 200000)
        check("the packed total is smaller than the raw",
              sum(r[2] for r in rows) < 200000, True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = 0
    for name, ok, got, want in checks:
        print("  %-48s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad += 1
    print("checks : %d   failures : %d" % (len(checks), bad))
    raise SystemExit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?")
    ap.add_argument("--declared", type=int)
    ap.add_argument("--by-ext", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.root == "selftest":
        return selftest()
    if not args.root:
        raise SystemExit("compratio: a root is required (or --selftest)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
