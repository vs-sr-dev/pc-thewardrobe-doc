"""members.py -- read the VT7A member table produced by vt7a.py members and
answer the questions the session actually asks.

    census   <tsv>            signatures, members and bytes, per archive
    dups     <tsv>            members that share bytes, inside and across archives
    twores   <tsv>            graphics_720 vs graphics_1080, every way they can
                              be compared
    thesis   <tsv> --total N  how many bytes are recorded sound and film

Nothing here reads the object; it reads the table.
"""
import sys
import collections


def load(path):
    rows = []
    with open(path) as fh:
        head = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            f = line.rstrip("\n").split("\t")
            rows.append({
                "archive": f[0], "key": int(f[1]), "offset": int(f[2]),
                "size_raw": int(f[3]), "size_stored": int(f[4]),
                "extent": int(f[5]), "sig": f[6], "sha1": f[7],
            })
    return rows


ORDER = ["general.vt7a", "graphics_common.vt7a", "graphics_720.vt7a",
         "graphics_1080.vt7a", "movie.vt7a", "music.vt7a", "sfx.vt7a"]


def census(rows):
    by = collections.defaultdict(lambda: collections.Counter())
    byb = collections.defaultdict(lambda: collections.Counter())
    for r in rows:
        by[r["archive"]][r["sig"]] += 1
        byb[r["archive"]][r["sig"]] += r["extent"]
    print("%-22s %-12s %8s %15s %9s %15s"
          % ("archive", "signature", "members", "bytes on disk", "share",
             "uncompressed"))
    print("-" * 90)
    graw = collections.Counter()
    for a in ORDER:
        tot = sum(byb[a].values())
        raws = collections.Counter()
        for r in rows:
            if r["archive"] == a:
                raws[r["sig"]] += r["size_raw"]
        for s, c in by[a].most_common():
            print("%-22s %-12s %8d %15d %8.4f %% %15d"
                  % (a, s, c, byb[a][s], 100.0 * byb[a][s] / tot, raws[s]))
            graw[s] += raws[s]
        print("%-22s %-12s %8d %15d %8.4f %% %15d"
              % ("", "TOTAL", sum(by[a].values()), tot, 100.0, sum(raws.values())))
        print()
    print("=" * 90)
    allsig = collections.Counter()
    allb = collections.Counter()
    for a in by:
        allsig.update(by[a])
        allb.update(byb[a])
    tot = sum(allb.values())
    print("%-22s %-12s %8s %15s %9s %15s"
          % ("all seven", "signature", "members", "bytes on disk", "share",
             "uncompressed"))
    for s, c in allsig.most_common():
        print("%-22s %-12s %8d %15d %8.4f %% %15d"
              % ("", s, c, allb[s], 100.0 * allb[s] / tot, graw[s]))
    print("%-22s %-12s %8d %15d %8.4f %% %15d"
          % ("", "TOTAL", sum(allsig.values()), tot, 100.0, sum(graw.values())))


def dups(rows):
    byh = collections.defaultdict(list)
    for r in rows:
        byh[r["sha1"]].append(r)
    print("members            : %d" % len(rows))
    print("distinct sha1      : %d" % len(byh))
    rep = {h: v for h, v in byh.items() if len(v) > 1}
    print("sha1 seen more than once : %d" % len(rep))
    extra = sum(len(v) - 1 for v in rep.values())
    extrab = sum(v[0]["extent"] * (len(v) - 1) for v in rep.values())
    print("redundant copies   : %d members, %d bytes" % (extra, extrab))
    print()
    within = collections.Counter()
    across = collections.Counter()
    for h, v in rep.items():
        archs = collections.Counter(r["archive"] for r in v)
        for a, c in archs.items():
            if c > 1:
                within[a] += c - 1
        if len(archs) > 1:
            across[tuple(sorted(archs))] += 1
    print("duplicate members INSIDE one archive:")
    for a in ORDER:
        if within[a]:
            b = sum(v[0]["extent"] * (collections.Counter(
                r["archive"] for r in v)[a] - 1)
                for v in rep.values()
                if collections.Counter(r["archive"] for r in v)[a] > 1)
            print("   %-22s %6d redundant copies, %12d bytes" % (a, within[a], b))
    if not sum(within.values()):
        print("   none")
    print()
    print("the same bytes in MORE THAN ONE archive:")
    if not across:
        print("   none")
    for k, c in across.most_common():
        b = sum(v[0]["extent"] for v in rep.values()
                if tuple(sorted(collections.Counter(
                    r["archive"] for r in v))) == k)
        print("   %-60s %6d members, %12d bytes" % (" + ".join(k), c, b))


def twores(rows):
    a = [r for r in rows if r["archive"] == "graphics_720.vt7a"]
    b = [r for r in rows if r["archive"] == "graphics_1080.vt7a"]
    print("%-34s %16s %16s" % ("", "graphics_720", "graphics_1080"))
    print("%-34s %16d %16d" % ("members", len(a), len(b)))
    ka, kb = set(r["key"] for r in a), set(r["key"] for r in b)
    print("%-34s %16d %16d" % ("distinct keys", len(ka), len(kb)))
    print("%-34s %33d" % ("keys in both", len(ka & kb)))
    ha, hb = set(r["sha1"] for r in a), set(r["sha1"] for r in b)
    print("%-34s %16d %16d" % ("distinct sha1", len(ha), len(hb)))
    print("%-34s %33d" % ("members with identical bytes", len(ha & hb)))
    print()
    sa = collections.Counter(r["sig"] for r in a)
    sb = collections.Counter(r["sig"] for r in b)
    ba = collections.Counter()
    bb = collections.Counter()
    for r in a:
        ba[r["sig"]] += r["extent"]
    for r in b:
        bb[r["sig"]] += r["extent"]
    print("%-14s %9s %9s %7s   %15s %15s %9s"
          % ("signature", "720 n", "1080 n", "delta", "720 bytes",
             "1080 bytes", "x"))
    for s in sorted(set(sa) | set(sb), key=lambda x: -(ba[x] + bb[x])):
        print("%-14s %9d %9d %+7d   %15d %15d %9.4f"
              % (s, sa[s], sb[s], sb[s] - sa[s], ba[s], bb[s],
                 bb[s] / float(ba[s]) if ba[s] else 0))
    print("%-14s %9d %9d %+7d   %15d %15d %9.4f"
          % ("TOTAL", len(a), len(b), len(b) - len(a),
             sum(ba.values()), sum(bb.values()),
             sum(bb.values()) / float(sum(ba.values()))))
    print()
    print("the key is not shared, so try the only other thing a key can be:")
    print("   720  key min %12d max %12d" % (min(ka), max(ka)))
    print("   1080 key min %12d max %12d" % (min(kb), max(kb)))
    print()
    print("uncompressed sizes, which survive the resolution change or do not:")
    ra = collections.Counter(r["size_raw"] for r in a)
    rb = collections.Counter(r["size_raw"] for r in b)
    shared = set(ra) & set(rb)
    print("   distinct size_raw values, 720  : %d" % len(ra))
    print("   distinct size_raw values, 1080 : %d" % len(rb))
    print("   values in both                 : %d" % len(shared))
    n_a = sum(ra[v] for v in shared)
    n_b = sum(rb[v] for v in shared)
    print("   members at a shared size, 720  : %d of %d" % (n_a, len(a)))
    print("   members at a shared size, 1080 : %d of %d" % (n_b, len(b)))


AUDIOVIDEO = {"Ogg/Vorbis", "Ogg/Opus", "Ogg/Theora", "Ogg/other", "WAV"}


def thesis(rows, total):
    print("Recorded sound and film, counted by member signature.")
    print()
    byb = collections.Counter()
    byn = collections.Counter()
    for r in rows:
        byb[r["sig"]] += r["extent"]
        byn[r["sig"]] += 1
    av = sum(byb[s] for s in byb if s in AUDIOVIDEO)
    avn = sum(byn[s] for s in byn if s in AUDIOVIDEO)
    print("%-14s %9s %16s   %s" % ("signature", "members", "bytes", "counted?"))
    for s, b in byb.most_common():
        print("%-14s %9d %16d   %s"
              % (s, byn[s], b, "yes" if s in AUDIOVIDEO else "no"))
    print()
    print("VT7A members that are recorded sound or film : %d, %d bytes"
          % (avn, av))
    print("denominator                                  : %d" % total)
    print("share                                        : %.4f %%"
          % (100.0 * av / total))


def main():
    cmd, path = sys.argv[1], sys.argv[2]
    rows = load(path)
    if cmd == "census":
        return census(rows)
    if cmd == "dups":
        return dups(rows)
    if cmd == "twores":
        return twores(rows)
    if cmd == "thesis":
        return thesis(rows, int(sys.argv[sys.argv.index("--total") + 1]))
    print(__doc__)


if __name__ == "__main__":
    main()
