#!/usr/bin/env python3
"""casediff.py -- are the disagreements between directory copies ONLY case?

`opercopies.py` finds the groups whose copies disagree and prints the first
two dozen differing bytes of each. That is enough to see a pattern and not
enough to state one. This classifies EVERY differing byte:

    case      the two bytes are the same letter in different case
    other     anything else

and it prints the other ones in full, because those are the interesting ones.

The first 3DO disc had two disagreeing groups: `/System/Folios`, all case,
and `/rom_tags`, eight bytes in two `rt_TypeSpecific` words. If a second disc
shows the same split, the disagreement is a fact about the SDK's disc builder
and not about either studio.

usage: casediff.py IMAGE [--raw 2352] [--off 16]
"""
import argparse
import struct


def block(f, n, raw, off):
    f.seek(n * raw + off)
    return f.read(2048)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--raw", type=int, default=2352)
    ap.add_argument("--off", type=int, default=16)
    ap.add_argument("--groups", nargs="+", required=True,
                    help="name:block,block,... for each group to compare")
    a = ap.parse_args()

    f = open(a.image, "rb")
    grand_case = grand_other = 0
    for g in a.groups:
        name, blocks = g.split(":", 1)
        nums = [int(x) for x in blocks.split(",")]
        base = block(f, nums[0], a.raw, a.off)
        print("=== %s   copies at %s" % (name, ", ".join(str(n) for n in nums)))
        for n in nums[1:]:
            other = block(f, n, a.raw, a.off)
            diffs = [i for i in range(2048) if base[i] != other[i]]
            case = [i for i in diffs
                    if abs(base[i] - other[i]) == 32
                    and chr(base[i]).isalpha() and chr(other[i]).isalpha()]
            rest = [i for i in diffs if i not in set(case)]
            grand_case += len(case)
            grand_other += len(rest)
            print("  copy %d vs %d : %d bytes differ -- %d are a case bit, "
                  "%d are not" % (nums[0], n, len(diffs), len(case), len(rest)))
            if case:
                upper = sum(1 for i in case if chr(base[i]).isupper())
                print("      of the case differences, copy %d holds the "
                      "UPPER-case letter %d times of %d" % (nums[0], upper, len(case)))
            for i in rest:
                print("      +%-6d  %02x %-3s   %02x %-3s"
                      % (i, base[i],
                         repr(chr(base[i])) if 32 <= base[i] < 127 else "",
                         other[i],
                         repr(chr(other[i])) if 32 <= other[i] < 127 else ""))
    print()
    print("TOTAL over every group: %d case-bit differences, %d other"
          % (grand_case, grand_other))


if __name__ == "__main__":
    main()
