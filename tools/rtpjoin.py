#!/usr/bin/env python3
"""rtpjoin.py -- join the LCF database's resource references to the files in the
Run Time Package, and report how many resolve.

WHY THIS IS THE MEASUREMENT THAT MATTERS ON THIS OBJECT
-------------------------------------------------------
`lcf.py` closes a 190,962-byte database on its own arithmetic and `pngcensus.py`
closes 162 images on theirs. Neither says the two are the same product. This
does: the database's records carry **file names**, the Run Time Package holds
**files**, and a name that resolves to a file that exists is a statement one
structure makes and another confirms.

The join is done without a table of field meanings. A `(chunk, field)` pair is
treated as a resource reference when **most of the distinct values it holds are
file stems in one RTP subdirectory** -- the threshold is an argument and the
count is printed either way. That is deliberately a discovered relation rather
than a declared one: nothing here says "field 2 of chunk 14 is the enemy's
graphic", it says "every one of the 45 values in field 2 of chunk 14 is the name
of a file in RTP/Monster, and the odds of that by accident are not worth
discussing".

Field 1 of the same chunks is the DISPLAY name and usually resolves too, because
a stock enemy is generally named after its picture. It is reported separately
and never counted in the join, because a partial match there is a coincidence of
naming and not a reference.

    python tools/rtpjoin.py <root>
    python tools/rtpjoin.py <root> --threshold 0.9
    python tools/rtpjoin.py selftest
"""
import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lcf                                       # noqa: E402


def utf8_stdout():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass


def rtp_stems(root):
    """{subdirectory name: {file stem: file name}} under <root>/RTP."""
    out = {}
    base = os.path.join(root, "RTP")
    if not os.path.isdir(base):
        sys.exit("rtpjoin: no RTP directory under %r" % root)
    for dp, dn, fn in os.walk(base):
        d = os.path.relpath(dp, base).replace(os.sep, "/")
        for f in fn:
            out.setdefault(d, {})[os.path.splitext(f)[0]] = f
    return out


def references(blob):
    """Every (chunk, field) -> list of (record id, ASCII value)."""
    name, chunks, residue = lcf.top_level(blob)
    if residue:
        sys.exit("rtpjoin: the database does not close (residue %d) -- "
                 "refusing to join against a walk that did not finish"
                 % residue)
    out = collections.defaultdict(list)
    shapes = {}
    for c in chunks:
        d = blob[c["offset"]:c["offset"] + c["size"]]
        kind, payload, res, why = lcf.shape(d)
        shapes[c["tag"]] = kind
        if kind.startswith("LIST"):
            src = payload[1]
        elif kind == "RECORD":
            src = [(0, payload)]
        else:
            continue
        for iid, fields in src:
            for t, v in fields:
                if 1 <= len(v) <= 32 and all(32 <= x < 127 for x in v):
                    out[(c["tag"], t)].append((iid, v.decode("ascii")))
    return out, shapes


def run(root, ldb, threshold):
    blob = open(ldb, "rb").read()
    refs, shapes = references(blob)
    stems = rtp_stems(root)
    print("database        : %s (%d bytes)" % (ldb, len(blob)))
    print("RTP directories : %d" % len(stems))
    for d in sorted(stems):
        print("   RTP/%-12s %4d files" % (d, len(stems[d])))
    print()
    print("A (chunk, field) is taken as a RESOURCE REFERENCE when at least")
    print("%.0f %% of its DISTINCT values are file stems in one RTP" % (100 * threshold))
    print("subdirectory. Everything else is printed below the line.")
    print()
    joins = []
    near = []
    for (tag, t), pairs in sorted(refs.items()):
        vals = {v for _, v in pairs}
        best = None
        for d, table in stems.items():
            inter = vals & set(table)
            if best is None or len(inter) > len(best[1]):
                best = (d, inter)
        if not best or not best[1]:
            continue
        share = len(best[1]) / len(vals)
        row = (tag, t, best[0], len(best[1]), len(vals), share, len(pairs),
               sum(1 for _, v in pairs if v in stems[best[0]]))
        (joins if share >= threshold else near).append(row)

    print("  %-12s %-14s %10s %12s %10s"
          % ("chunk.field", "RTP dir", "distinct", "references", "resolved"))
    tot_ref = tot_ok = 0
    for tag, t, d, ni, nv, share, npairs, nok in joins:
        print("  %-12s RTP/%-10s %5d of %-2d %7d      %8d"
              % ("%d.%d" % (tag, t), d, ni, nv, npairs, nok))
        tot_ref += npairs
        tot_ok += nok
    print("  %-12s %-14s %10s %12d %10d"
          % ("TOTAL", "", "", tot_ref, tot_ok))
    print()
    print("  RESOURCE REFERENCES THAT RESOLVE TO A FILE THAT EXISTS : %d of %d"
          % (tot_ok, tot_ref))
    print("  residue : %d" % (tot_ref - tot_ok))
    print()
    print("-- and the limit of the join, stated -------------------------")
    print("  A name resolving proves the file exists. It does not always")
    print("  prove WHICH directory the reference means, because stems repeat.")
    where = collections.defaultdict(set)
    for d, table in stems.items():
        for s in table:
            where[s].add(d)
    dup = {s: v for s, v in where.items() if len(v) > 1}
    print("  distinct file stems under RTP                 : %d" % len(where))
    print("  stems appearing in more than one subdirectory : %d" % len(dup))
    for s, v in sorted(dup.items())[:8]:
        print("     %-14s %s" % (s, ", ".join(sorted(v))))
    if len(dup) > 8:
        print("     ... %d more" % (len(dup) - 8))
    amb = 0
    for tag, t, d, ni, nv, share, npairs, nok in joins:
        for _, v in refs[(tag, t)]:
            if v in dup:
                amb += 1
    print("  joined references whose stem is ambiguous     : %d of %d"
          % (amb, tot_ref))
    print("  (they still resolve; the directory this table names for them")
    print("   is the tool's best match and not a measurement.)")
    print()
    print("-- below the threshold: names that partly coincide, and are NOT")
    print("-- counted, because a display name that matches its own picture is")
    print("-- a naming habit and not a reference")
    for tag, t, d, ni, nv, share, npairs, nok in sorted(near,
                                                        key=lambda r: -r[5]):
        print("  %-12s RTP/%-10s %5d of %-3d = %5.1f %%"
              % ("%d.%d" % (tag, t), d, ni, nv, 100 * share))
    return 0 if tot_ref and tot_ok == tot_ref else 1


def selftest():
    checks = []

    def ok(n, c):
        checks.append((n, bool(c)))

    enc = lcf.enc
    rec = lcf.record
    ch = lcf.chunk

    def db(chunks):
        return (enc(11) + b"LcfDataBase"
                + b"".join(ch(t, d) for t, d in chunks))

    # One chunk, three records, each with a display name (field 1) and a
    # graphic name (field 2). Only field 2 will resolve.
    body = enc(3)
    for i, (disp, gfx) in enumerate([("Slime", "Slime"), ("Ryuu", "Dragon"),
                                     ("Bat", "Bat")], 1):
        body += enc(i) + rec([(1, disp.encode()), (2, gfx.encode())])
    blob = db([(14, body)])
    refs, shapes = references(blob)
    ok("the constructed database is walked", (14, 2) in refs)
    ok("field 2 holds three references", len(refs[(14, 2)]) == 3)
    ok("field 1 holds three display names", len(refs[(14, 1)]) == 3)

    fake = {"Monster": {"Slime": "Slime.png", "Dragon": "Dragon.png",
                        "Bat": "Bat.png"}}
    vals2 = {v for _, v in refs[(14, 2)]}
    vals1 = {v for _, v in refs[(14, 1)]}
    ok("every field-2 value is a file stem",
       vals2 <= set(fake["Monster"]))
    ok("field 1 does NOT fully resolve, because one name is a display name",
       not vals1 <= set(fake["Monster"]))
    ok("and the one that fails is the display name",
       (vals1 - set(fake["Monster"])) == {"Ryuu"})

    ok("a non-ASCII value is not offered as a file name",
       all(all(32 <= ord(c) < 127 for c in v) for _, v in refs[(14, 2)]))

    body2 = enc(1) + enc(1) + rec([(1, "テスト".encode("cp932"))])
    refs2, _ = references(db([(14, body2)]))
    ok("a Shift-JIS field is skipped rather than mangled into a name",
       (14, 1) not in refs2)

    body3 = enc(1) + enc(1) + rec([(1, b"x" * 40)])
    refs3, _ = references(db([(14, body3)]))
    ok("a 40-byte value is too long to be a file stem and is skipped",
       (14, 1) not in refs3)

    try:
        references(db([(14, body)]) + b"\x7f")
    except SystemExit as e:
        ok("a database that does not close is refused, not joined",
           "residue" in str(e) or "close" in str(e))
    except lcf.Bad:
        ok("a database that does not close is refused, not joined", True)
    else:
        ok("a database that does not close is refused, not joined", False)

    width = max(len(n) for n, _ in checks)
    for n, g in checks:
        print("  %-*s %s" % (width, n, "ok" if g else "FAIL"))
    bad = [n for n, g in checks if not g]
    print("%d checks, %d failures" % (len(checks), len(bad)))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--ldb")
    ap.add_argument("--threshold", type=float, default=1.0)
    args = ap.parse_args()
    utf8_stdout()
    if args.root == "selftest":
        return selftest()
    ldb = args.ldb or os.path.join(args.root, "rpg_rt.ldb.dat")
    return run(args.root, ldb, args.threshold)


if __name__ == "__main__":
    sys.exit(main())
