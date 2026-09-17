#!/usr/bin/env python3
"""twosimul.py -- Simulman V against 1000 Miglia, file by file and byte by byte.

Why this exists rather than `crossall.py`. crossall reads the `notes/` of every
repository in the collection, harvests 40-hex tokens, and intersects them with
this object's hashes. Run here it reports **0 crossings of 119 hashes against
65 repositories and 41,500 tokens** -- and that number is worthless for the one
comparison this session cares about, because `pc-1000miglia-doc` contains no
SHA-1 anywhere in its notes. It was written before the branch started recording
them. crossall is not wrong; it is answering "does any repository *say* it has
this hash", and the sibling says nothing at all.

So this tool hashes both trees itself, from the material, and intersects. It
also compares by size, because two files of exactly the same length in two
2 MB objects a year apart are worth looking at even when the bytes differ:
2,056,643 / 256^3 puts the chance of a coincidental three-byte string at 0.12,
and the chance of a coincidental exact size match between two small file sets
is not much better.

    python tools/twosimul.py <simulman5root> <1000migliaroot>
"""
import hashlib
import os
import sys
from collections import defaultdict


def census(root):
    out = {}
    for dp, _dd, ff in os.walk(root):
        for n in sorted(ff):
            p = os.path.join(dp, n)
            d = open(p, "rb").read()
            out[os.path.relpath(p, root).replace(os.sep, "/")] = (
                len(d), hashlib.sha1(d).hexdigest())
    return out


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    a, b = sys.argv[1], sys.argv[2]
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    A, B = census(a), census(b)
    assert A and B, "one of the two trees is empty"
    print("Simulman V   : %d files, %d bytes" % (len(A), sum(v[0] for v in A.values())))
    print("1000 Miglia  : %d files, %d bytes" % (len(B), sum(v[0] for v in B.values())))
    print("")

    ha = defaultdict(list)
    for k, (_s, h) in A.items():
        ha[h].append(k)
    hb = defaultdict(list)
    for k, (_s, h) in B.items():
        hb[h].append(k)
    both = sorted(set(ha) & set(hb))
    print("=== files identical byte for byte across the two games ===")
    print("  %d" % len(both))
    for h in both:
        sz = A[ha[h][0]][0]
        print("    %s  %7d bytes" % (h, sz))
        print("       Simulman V  : %s" % ", ".join(ha[h]))
        print("       1000 Miglia : %s" % ", ".join(hb[h]))
    print("")

    sa = defaultdict(list)
    for k, (s, _h) in A.items():
        sa[s].append(k)
    sb = defaultdict(list)
    for k, (s, _h) in B.items():
        sb[s].append(k)
    same = sorted(set(sa) & set(sb))
    print("=== files of exactly the same length, whether or not identical ===")
    print("  %d distinct lengths" % len(same))
    for s in same:
        ident = A[sa[s][0]][1] == B[sb[s][0]][1] if len(sa[s]) == len(sb[s]) == 1 else None
        print("    %7d bytes  %-28s %-28s %s"
              % (s, ",".join(sa[s]), ",".join(sb[s]),
                 "IDENTICAL" if ident else "different bytes" if ident is False else ""))
    print("")

    print("=== the one format the two games share, and how it grew ===")
    print("  A palette is `type=00`, `last`, then 3*(last+1) six-bit RGB bytes.")
    print("  1000 Miglia writes a two-byte header. Simulman V writes five: the")
    print("  same two, plus a u16 first-index and a flag byte. Nothing else")
    print("  changed. Every file below closes on its own last byte under its")
    print("  own header length, which is the whole proof:")
    rows = []
    for root, hdr, tag in ((b, 2, "1000 Miglia"), (a, 5, "Simulman V")):
        for dp, _dd, ff in os.walk(root):
            for n in sorted(ff):
                if not n.upper().endswith(".PAL"):
                    continue
                p = os.path.join(dp, n)
                d = open(p, "rb").read()
                last = d[1]
                want = hdr + 3 * (last + 1)
                rows.append((tag, os.path.relpath(p, root).replace(os.sep, "/"),
                             len(d), hdr, last, want, want == len(d)))
    ok = sum(1 for r in rows if r[6])
    for tag, n, sz, hdr, last, want, good in rows:
        print("    %-12s %-20s %5d bytes  %d + 3*(%3d+1) = %5d  %s"
              % (tag, n, sz, hdr, last, want, "closes" if good else "DOES NOT CLOSE"))
    print("  %d of %d close exactly." % (ok, len(rows)))
    assert ok == len(rows), "the shared palette format no longer closes on every file"
    print("")

    print("=== extensions, side by side ===")
    ea = defaultdict(int)
    for k in A:
        ea[os.path.splitext(k)[1].upper() or "(none)"] += 1
    eb = defaultdict(int)
    for k in B:
        eb[os.path.splitext(k)[1].upper() or "(none)"] += 1
    for e in sorted(set(ea) | set(eb)):
        print("  %-8s Simulman V %3d   1000 Miglia %3d   %s"
              % (e, ea.get(e, 0), eb.get(e, 0),
                 "shared" if ea.get(e) and eb.get(e) else ""))
    print("")
    print("  extensions in both  : %s"
          % sorted(set(ea) & set(eb)))
    print("  extensions in one   : %d in Simulman V only, %d in 1000 Miglia only"
          % (len(set(ea) - set(eb)), len(set(eb) - set(ea))))


if __name__ == "__main__":
    main()
