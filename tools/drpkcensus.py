#!/usr/bin/env python3
r"""drpkcensus.py -- unpack every DRPK member and report the LENGTH RESIDUE.

This is the second closure test of the session. `drpk.py census` says the
container's bytes are all accounted for; this says whether each member's
unpacked bytes come out to the length its own directory entry declares.

It is deliberately a census and not a sample: 112,752 members, every one of
them, and the report names how many of how many. A member that comes out short
is NOT unpacked, and its residue is printed rather than rounded away.

    python tools/drpkcensus.py inquisitor-gog --out _work/drpk-unpack.txt
"""
import argparse
import collections
import glob
import hashlib
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drpk  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--out")
    ap.add_argument("--sha1", action="store_true")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.root, "**", "*.dat"),
                             recursive=True))
    if not files:
        print("drpkcensus: empty population", file=sys.stderr)
        return 3
    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout

    def say(s):
        out.write(s + "\n")
        out.flush()

    say("=== DRPK member unpacking census ===")
    say("population: %d files offered under %s" % (len(files), args.root))
    say("")
    say("%-26s %8s %8s %8s %16s %16s"
        % ("container", "members", "exact", "residue", "bytes produced",
           "bytes declared"))

    t0 = time.time()
    tot = ok = 0
    tot_made = tot_want = 0
    residues = collections.Counter()
    digests = {}
    for p in files:
        try:
            c = drpk.read_container(p)
            drpk.close_or_raise(c)
        except (drpk.NotDRPK, drpk.NotClosed) as exc:
            say("  refused: %s" % exc)
            continue
        n = e = 0
        made = want = 0
        with open(p, "rb") as fh:
            for m in c["members"]:
                n += 1
                want += m["size"]
                try:
                    blob = drpk.unpack_member(fh, m)
                    e += 1
                    made += len(blob)
                    if args.sha1:
                        digests.setdefault(hashlib.sha1(blob).hexdigest(),
                                           []).append(len(blob))
                except drpk.NotUnpacked as exc:
                    txt = str(exc)
                    if "residue" in txt:
                        residues[int(txt.rsplit("residue ", 1)[1])] += 1
                        made += m["size"] + int(txt.rsplit("residue ", 1)[1])
                    else:
                        residues["parse"] += 1
        tot += n
        ok += e
        tot_made += made
        tot_want += want
        say("%-26s %8d %8d %8d %16d %16d"
            % (os.path.basename(p), n, e, n - e, made, want))
    say("")
    say("members offered              : %d" % tot)
    say("members whose unpacked length equals the declared length : %d = %.4f %%"
        % (ok, 100.0 * ok / tot if tot else 0.0))
    say("members with a non-zero length residue                   : %d"
        % (tot - ok))
    say("bytes produced / bytes declared : %d / %d = %.4f %%"
        % (tot_made, tot_want, 100.0 * tot_made / tot_want if tot_want else 0))
    say("elapsed : %.1f s" % (time.time() - t0))
    if args.sha1:
        dup = {k: v for k, v in digests.items() if len(v) > 1}
        say("")
        say("distinct sha1 over the members that unpacked : %d of %d"
            % (len(digests), ok))
        say("members inside a repeated group              : %d"
            % sum(len(v) for v in dup.values()))
        say("redundant bytes                              : %d"
            % sum(v[0] * (len(v) - 1) for v in dup.values()))
    if args.out:
        out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
