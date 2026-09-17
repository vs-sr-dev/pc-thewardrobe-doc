#!/usr/bin/env python3
"""lbdates.py -- histograms over the timestamps `lbarc.py` extracted.

The filesystem this object lives on dates 137 of its 141 files to one two-minute
window in 2026. The object answers by dating itself 12,821 times, once per
archive member, in a u32 Unix field. This reads the TSV `lbarc.py --members`
writes and reports the distribution by year, by archive, by member type, by day,
and -- the reason the tool exists -- **by hour of day**.

The hour histogram is not decoration. A Unix timestamp is UTC by definition. If
Falcom's packer wrote honest UTC, a Tokyo working day (JST = UTC+9) lands in the
UTC hours 00:00-13:00. If it wrote local time into a UTC field, the same working
day lands in 09:00-22:00. With 12,821 samples the two are told apart by looking,
which is what four previous sessions of this branch could not do with four.

    python tools/lbdates.py _work/members.tsv
    python tools/lbdates.py _work/members.tsv --hours-by-layer
    python tools/lbdates.py _work/members.tsv --day 2004-06-10
"""
import argparse
import collections
import csv
import datetime
import sys

UTC = datetime.timezone.utc


def load(path):
    rows = []
    with open(path, encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            r["ts"] = int(r["ts"])
            r["size"] = int(r["size"])
            r["offset"] = int(r["offset"])
            r["slot"] = int(r["slot"])
            r["dt"] = datetime.datetime.fromtimestamp(r["ts"], UTC)
            r["ext"] = r["name"].split(".")[-1] if "." in r["name"] else ""
            rows.append(r)
    assert rows, "no rows in %s; refusing to report an empty histogram" % path
    return rows


def bar(n, top, width=44):
    return "#" * int(round(width * n / float(top))) if top else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tsv")
    ap.add_argument("--hours-by-layer", action="store_true")
    ap.add_argument("--day", default=None, help="report one calendar day in detail")
    a = ap.parse_args()

    rows = load(a.tsv)
    n = len(rows)
    lo = min(r["dt"] for r in rows)
    hi = max(r["dt"] for r in rows)
    print("members with a timestamp : %d" % n)
    print("zero timestamps          : %d" % sum(1 for r in rows if not r["ts"]))
    print("range (UTC)              : %s .. %s" % (lo, hi))
    print("distinct calendar days   : %d" % len(set(r["dt"].date() for r in rows)))
    print("distinct seconds         : %d" % len(set(r["ts"] for r in rows)))
    print()

    ys = collections.Counter(r["dt"].year for r in rows)
    yb = collections.Counter()
    for r in rows:
        yb[r["dt"].year] += r["size"]
    top = max(ys.values())
    print("by year of the member's own timestamp:")
    print("  %-6s %7s %8s %16s  %s" % ("year", "members", "pct", "bytes", ""))
    for y in sorted(ys):
        print("  %-6d %7d %7.3f%% %16d  %s"
              % (y, ys[y], 100.0 * ys[y] / n, yb[y], bar(ys[y], top)))
    print()

    days = collections.Counter(str(r["dt"].date()) for r in rows)
    print("the ten busiest days:")
    for d, c in days.most_common(10):
        print("  %s  %6d members  %7.3f%%  %14d bytes"
              % (d, c, 100.0 * c / n, sum(r["size"] for r in rows if str(r["dt"].date()) == d)))
    print()

    print("by archive, oldest and newest member:")
    per = collections.defaultdict(list)
    for r in rows:
        per[r["archive"]].append(r)
    order = sorted(per, key=lambda k: min(x["ts"] for x in per[k]))
    print("  %-12s %6s %-20s %-20s %6s" % ("archive", "n", "oldest", "newest", "days"))
    for k in order:
        v = per[k]
        o = min(x["dt"] for x in v)
        w = max(x["dt"] for x in v)
        print("  %-12s %6d %-20s %-20s %6d"
              % (k, len(v), o.strftime("%Y-%m-%d %H:%M:%S"),
                 w.strftime("%Y-%m-%d %H:%M:%S"),
                 len(set(x["dt"].date() for x in v))))
    print()

    # do the strata interleave? rank by oldest against rank by newest
    by_old = [k for k in sorted(per, key=lambda k: min(x["ts"] for x in per[k]))]
    by_new = [k for k in sorted(per, key=lambda k: max(x["ts"] for x in per[k]))]
    moved = sum(1 for i, k in enumerate(by_old) if by_new.index(k) != i)
    print("archives whose rank changes between the two orderings : %d of %d"
          % (moved, len(per)))
    print()

    print("by member extension, oldest and newest:")
    pe = collections.defaultdict(list)
    for r in rows:
        pe[r["ext"]].append(r)
    for k in sorted(pe, key=lambda k: -len(pe[k])):
        v = pe[k]
        print("  .%-4s %6d  %s .. %s  %14d bytes"
              % (k, len(v),
                 min(x["dt"] for x in v).strftime("%Y-%m-%d"),
                 max(x["dt"] for x in v).strftime("%Y-%m-%d"),
                 sum(x["size"] for x in v)))
    print()

    hrs = collections.Counter(r["dt"].hour for r in rows)
    top = max(hrs.values())
    mean = n / 24.0
    print("by hour of day, as the u32 field reads it (i.e. as UTC):")
    print("  %-5s %7s %7s  %-46s %s" % ("hour", "n", "x mean", "", "JST"))
    for h in range(24):
        c = hrs.get(h, 0)
        jst = (h + 9) % 24
        print("  %02d:00 %7d %7.2f  %-46s %02d:00" % (h, c, c / mean, bar(c, top), jst))
    busiest = max(hrs, key=lambda h: hrs[h])
    print()
    print("  busiest hour            : %02d:00 UTC, %d members, %.2f x the mean"
          % (busiest, hrs[busiest], hrs[busiest] / mean))
    work_utc = sum(hrs.get(h, 0) for h in range(0, 14))     # Tokyo day if honest UTC
    work_loc = sum(hrs.get(h, 0) for h in range(9, 23))     # Tokyo day if local-as-UTC
    print("  in 00:00-13:59 (a Tokyo working day if the field is honest UTC) : %d = %.2f%%"
          % (work_utc, 100.0 * work_utc / n))
    print("  in 09:00-22:59 (a Tokyo working day if the field is local time) : %d = %.2f%%"
          % (work_loc, 100.0 * work_loc / n))
    night_utc = sum(hrs.get(h, 0) for h in list(range(15, 24)) + list(range(0, 6)))
    print("  in 15:00-05:59 UTC = 00:00-14:59 JST if honest UTC              : %d = %.2f%%"
          % (night_utc, 100.0 * night_utc / n))
    print()

    # The second test, independent of the first: a working calendar has weekends.
    names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    wd_utc = collections.Counter(r["dt"].weekday() for r in rows)
    jst = datetime.timezone(datetime.timedelta(hours=9))
    wd_jst = collections.Counter(r["dt"].astimezone(jst).weekday() for r in rows)
    dd_utc = collections.Counter()
    dd_jst = collections.Counter()
    for d in set(r["dt"].date() for r in rows):
        dd_utc[d.weekday()] += 1
    for d in set(r["dt"].astimezone(jst).date() for r in rows):
        dd_jst[d.weekday()] += 1
    print("by weekday (members, then distinct calendar days):")
    print("  %-4s %8s %8s %8s %8s" % ("", "n UTC", "n JST", "days UTC", "days JST"))
    for i, nm in enumerate(names):
        print("  %-4s %8d %8d %8d %8d"
              % (nm, wd_utc.get(i, 0), wd_jst.get(i, 0), dd_utc.get(i, 0), dd_jst.get(i, 0)))
    we_jst = wd_jst.get(5, 0) + wd_jst.get(6, 0)
    print("  weekend share, JST : %d of %d = %.2f%%" % (we_jst, n, 100.0 * we_jst / n))
    print()

    if a.hours_by_layer:
        print("the same histogram, split by decade of the stamp:")
        groups = {"1998-2004": lambda y: y <= 2004,
                  "2010-2013": lambda y: 2010 <= y <= 2013,
                  "2014-2017": lambda y: y >= 2014}
        print("  %-5s %10s %10s %10s" % ("hour", "1998-2004", "2010-2013", "2014-2017"))
        for h in range(24):
            cells = []
            for g in ("1998-2004", "2010-2013", "2014-2017"):
                f = groups[g]
                cells.append(sum(1 for r in rows if r["dt"].hour == h and f(r["dt"].year)))
            print("  %02d:00 %10d %10d %10d" % (h, cells[0], cells[1], cells[2]))
        print()
        for g, f in groups.items():
            sub = [r for r in rows if f(r["dt"].year)]
            if not sub:
                continue
            hh = collections.Counter(r["dt"].hour for r in sub)
            b = max(hh, key=lambda k: hh[k])
            print("  %-10s n=%6d  busiest %02d:00 UTC (%02d:00 JST)  span %02d..%02d"
                  % (g, len(sub), b, (b + 9) % 24, min(hh), max(hh)))
        print()

    if a.day:
        d = datetime.date.fromisoformat(a.day)
        sub = [r for r in rows if r["dt"].date() == d]
        print("== %s : %d members, %d bytes ==" % (d, len(sub), sum(r["size"] for r in sub)))
        pa = collections.Counter(r["archive"] for r in sub)
        for k, c in sorted(pa.items()):
            v = [r for r in sub if r["archive"] == k]
            lo = min(r["dt"] for r in v)
            hi = max(r["dt"] for r in v)
            span = (hi - lo).total_seconds()
            ordered = sorted(v, key=lambda r: r["offset"])
            mono = all(ordered[i]["ts"] <= ordered[i + 1]["ts"] for i in range(len(ordered) - 1))
            print("   %-12s %6d  %s .. %s  span %6.0f s  monotone with offset: %s"
                  % (k, c, lo.strftime("%H:%M:%S"), hi.strftime("%H:%M:%S"), span,
                     "yes" if mono else "no"))
        lo = min(r["dt"] for r in sub)
        hi = max(r["dt"] for r in sub)
        print("   whole day: %s .. %s, span %.0f s = %.2f h"
              % (lo.strftime("%H:%M:%S"), hi.strftime("%H:%M:%S"),
                 (hi - lo).total_seconds(), (hi - lo).total_seconds() / 3600.0))
        print("   distinct seconds in the day : %d" % len(set(r["ts"] for r in sub)))


if __name__ == "__main__":
    main()
