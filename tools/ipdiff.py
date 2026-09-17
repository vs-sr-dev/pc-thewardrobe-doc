#!/usr/bin/env python3
"""ipdiff.py -- diff two Dreamcast IP.BIN images byte by byte.

An IP.BIN is the first sixteen 2048-byte user blocks of a GD-ROM high-density
area: a 256-byte header carrying the product number, the title and the release
date, followed by 32,512 bytes of bootstrap code and licence logo.

The question this answers is whether that 32,512-byte region is one block
pressed verbatim across the platform. It takes two raw MODE1/2352 track files
(or two already-cooked images) and reports, for the whole file and for the two
regions separately:

    length of the common prefix
    offset of the first difference
    number of differing bytes and the percentage
    the longest common run anywhere, and where it sits in each file
    a map of the differing regions, coalesced

No claim is made about what the bytes mean. This tool measures agreement.

    python tools/ipdiff.py A.bin B.bin --raw2352
    python tools/ipdiff.py a.ipbin b.ipbin --split 256
    python tools/ipdiff.py --selftest
"""

import argparse
import hashlib
import sys

USER = 2048
RAW = 2352
DATA_OFF = 16          # sync(12) + header(4) in a MODE1/2352 sector
IPBIN_BYTES = 16 * USER


def cook_prefix(path, nsectors):
    """Pull the user area out of the first nsectors MODE1/2352 sectors."""
    out = bytearray()
    with open(path, "rb") as fh:
        for i in range(nsectors):
            sec = fh.read(RAW)
            if len(sec) != RAW:
                raise SystemExit(
                    "ipdiff: %s is shorter than %d sectors of %d bytes"
                    % (path, nsectors, RAW))
            if sec[0:12] != b"\x00" + b"\xff" * 10 + b"\x00":
                raise SystemExit(
                    "ipdiff: sector %d of %s does not carry a MODE1 sync "
                    "pattern; is this really a 2352-byte image?" % (i, path))
            out += sec[DATA_OFF:DATA_OFF + USER]
    return bytes(out)


def flat_prefix(path, nbytes):
    with open(path, "rb") as fh:
        b = fh.read(nbytes)
    if len(b) != nbytes:
        raise SystemExit("ipdiff: %s is shorter than %d bytes" % (path, nbytes))
    return b


def common_prefix(a, b):
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i


def longest_common_run(a, b):
    """Longest run of equal bytes at the same offset in both."""
    n = min(len(a), len(b))
    best = bestat = cur = curat = 0
    for i in range(n):
        if a[i] == b[i]:
            if cur == 0:
                curat = i
            cur += 1
            if cur > best:
                best, bestat = cur, curat
        else:
            cur = 0
    return best, bestat


def diff_runs(a, b, coalesce=16):
    """Offsets of differing bytes, coalesced into runs separated by more than
    `coalesce` equal bytes."""
    n = min(len(a), len(b))
    runs = []
    i = 0
    while i < n:
        if a[i] != b[i]:
            start = i
            gap = 0
            end = i
            while i < n:
                if a[i] != b[i]:
                    end = i
                    gap = 0
                else:
                    gap += 1
                    if gap > coalesce:
                        break
                i += 1
            runs.append((start, end - start + 1))
        else:
            i += 1
    return runs


def report(name, a, b, coalesce):
    n = min(len(a), len(b))
    ndiff = sum(1 for i in range(n) if a[i] != b[i])
    cp = common_prefix(a, b)
    lcr, lcrat = longest_common_run(a, b)
    print("--- %s ---" % name)
    print("  lengths                : %d / %d" % (len(a), len(b)))
    print("  sha1 A                 : %s" % hashlib.sha1(a).hexdigest())
    print("  sha1 B                 : %s" % hashlib.sha1(b).hexdigest())
    if a == b:
        print("  IDENTICAL")
        return []
    print("  common prefix          : %d bytes" % cp)
    print("  first difference at    : 0x%04X (%d)" % (cp, cp))
    print("  differing bytes        : %d of %d = %.4f %%"
          % (ndiff, n, 100.0 * ndiff / n))
    print("  agreeing bytes         : %d of %d = %.4f %%"
          % (n - ndiff, n, 100.0 * (n - ndiff) / n))
    print("  longest common run     : %d bytes at 0x%04X" % (lcr, lcrat))
    runs = diff_runs(a, b, coalesce)
    print("  differing runs (gap>%d): %d" % (coalesce, len(runs)))
    for off, ln in runs[:40]:
        sa = bytes(a[off:off + min(ln, 12)])
        sb = bytes(b[off:off + min(ln, 12)])
        print("    0x%05X  %6d bytes   A %-26s  B %-26s"
              % (off, ln, sa.hex(" "), sb.hex(" ")))
    if len(runs) > 40:
        print("    ... %d more runs" % (len(runs) - 40))
    return runs


def selftest():
    a = bytes(range(256)) * 4
    b = bytearray(a)
    b[100] = (b[100] + 1) & 0xFF
    b[900:910] = bytes(10)
    b = bytes(b)
    assert common_prefix(a, a) == len(a), "common_prefix on equal inputs"
    assert common_prefix(a, b) == 100, "common_prefix should stop at 100"
    runs = diff_runs(a, b, coalesce=4)
    assert len(runs) == 2, "expected two coalesced runs, got %d" % len(runs)
    assert runs[0][0] == 100 and runs[0][1] == 1, "first run wrong: %r" % (runs[0],)
    # The longest agreeing run is the stretch between the two injected
    # differences: bytes 101..899 inclusive, which is 799 bytes -- NOT the
    # 114-byte tail after 910. Getting this assertion wrong the first time is
    # exactly what a self-test is for.
    lcr, at = longest_common_run(a, b)
    assert (lcr, at) == (799, 101), "longest run wrong: %d at %d" % (lcr, at)
    # negative control: two byte strings that share nothing must report a
    # common prefix of zero and 100 % difference.
    x = b"\x00" * 64
    y = b"\xff" * 64
    assert common_prefix(x, y) == 0, "negative control: prefix should be 0"
    nd = sum(1 for i in range(64) if x[i] != y[i])
    assert nd == 64, "negative control: all 64 bytes should differ"
    # and a control that must FAIL if the comparison were length-blind
    assert common_prefix(b"abc", b"abcdef") == 3
    print("ipdiff selftest: 6 of 6 assertions passed")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a", nargs="?")
    ap.add_argument("b", nargs="?")
    ap.add_argument("--raw2352", action="store_true",
                    help="inputs are MODE1/2352 track images; cook 16 sectors")
    ap.add_argument("--bytes", type=int, default=IPBIN_BYTES,
                    help="how many bytes to compare (default 32768)")
    ap.add_argument("--split", type=int, default=256,
                    help="boundary between header and bootstrap (default 256)")
    ap.add_argument("--coalesce", type=int, default=16)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.a or not args.b:
        raise SystemExit("ipdiff: need two files, or --selftest")

    if args.raw2352:
        nsec = (args.bytes + USER - 1) // USER
        A = cook_prefix(args.a, nsec)[:args.bytes]
        B = cook_prefix(args.b, nsec)[:args.bytes]
    else:
        A = flat_prefix(args.a, args.bytes)
        B = flat_prefix(args.b, args.bytes)

    print("A = %s" % args.a)
    print("B = %s" % args.b)
    print()
    report("whole image, %d bytes" % args.bytes, A, B, args.coalesce)
    print()
    report("header, 0x0000..0x%04X" % args.split,
           A[:args.split], B[:args.split], args.coalesce)
    print()
    runs = report("bootstrap and logo, 0x%04X..0x%04X" % (args.split, args.bytes),
                  A[args.split:], B[args.split:], args.coalesce)

    if runs is not None and len(runs) == 0 and A[args.split:] != B[args.split:]:
        raise SystemExit("ipdiff: the regions differ but no differing run was "
                         "produced; the run finder is broken")
    return 0


if __name__ == "__main__":
    sys.exit(main())
