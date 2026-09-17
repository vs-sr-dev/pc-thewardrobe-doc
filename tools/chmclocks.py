#!/usr/bin/env python3
"""chmclocks.py -- put every clock an ITSF container carries side by side,
across several containers, and decompose the gap between them.

WHY
---
`itsf.py internals` prints three clocks for one file: the `/#SYSTEM` code-10
`u32`, the `/#SYSTEM` code-4 `FILETIME`, and the ITSF header's truncated `u32`
at +0x10 paired with that FILETIME's high half.
`pc-rpgmaker2000-doc/docs/08` read the gap between the first two as **how long
the compile took**, on a specimen where it was nine seconds, and two later
specimens agreed at nine and eighteen.

On `pc-rpgmakerxp-doc`'s object the same two clocks are **fifty-seven thousand
six hundred and three point nine five three one two five seconds** apart, which
is not a compile. This tool exists so that the four specimens are compared by
running a command over all four rather than by quoting three earlier
repositories' prose, and so that the gap is DECOMPOSED rather than described:
a gap that is a whole number of hours plus a few seconds is two different
things added together, and the tool says which whole hour it is and what is
left.

    python tools/chmclocks.py a.chm b.chm c.chm
    python tools/chmclocks.py --selftest
"""
import argparse
import datetime
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                              # noqa: E402
import itsf                                                  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def unix_of(v):
    return EPOCH + datetime.timedelta(seconds=v)


def filetime_seconds(v):
    """A Windows FILETIME is 100-nanosecond ticks since 1601-01-01 UTC."""
    return v / 1e7 - 11644473600


def system_entries(blob, head):
    """Walk /#SYSTEM, which lives in the uncompressed content section."""
    parsed = itsf.read_itsp(blob, head["dir_offset"])
    entries, _kinds, refusals = itsf.read_chunks(blob, head["dir_offset"],
                                                 parsed)
    if refusals:
        raise ValueError("the directory did not walk cleanly")
    for e in entries:
        if e.get("index") or e["name"] != "/#SYSTEM":
            continue
        if e["section"] != 0:
            raise ValueError("/#SYSTEM is not in the uncompressed section")
        start = head["content_offset"] + e["offset"]
        data = blob[start:start + e["length"]]
        out = []
        p = 4
        while p + 4 <= len(data):
            code, ln = struct.unpack_from("<HH", data, p)
            out.append((code, data[p + 4:p + 4 + ln]))
            p += 4 + ln
        if p != len(data):
            raise ValueError("/#SYSTEM did not close: %d of %d"
                             % (p, len(data)))
        return out
    raise ValueError("no /#SYSTEM entry")


def clocks(path):
    with open(path, "rb") as fh:
        blob = fh.read()
    head = itsf.read_header(blob)
    ents = dict(system_entries(blob, head))
    code10 = struct.unpack_from("<I", ents[10], 0)[0] if 10 in ents else None
    lcid4 = ft = None
    if 4 in ents and len(ents[4]) >= 28:
        lcid4 = struct.unpack_from("<I", ents[4], 0)[0]
        ft = struct.unpack_from("<Q", ents[4], 20)[0]
    code4 = filetime_seconds(ft) if ft else None
    # The header's truncated u32 joined to the FILETIME's high half. The
    # DIFFERENCE is computed in 100-nanosecond ticks and only then divided,
    # because subtracting two float seconds around 1.1e17 ticks loses the
    # last digits: this pairing is 312,572 ticks = 0.0312572 s exactly, and
    # a float subtraction of the two absolute times prints 0.031258.
    paired = paired_delta = None
    if ft:
        joined = (ft & 0xFFFFFFFF00000000) | head["stamp"]
        paired = filetime_seconds(joined)
        paired_delta = (joined - ft) / 1e7
    title = ents.get(3, b"").rstrip(b"\0").decode("latin-1", "replace")
    hha = ents.get(9, b"").rstrip(b"\0").decode("latin-1", "replace")
    return dict(path=path, bytes=len(blob), header_lcid=head["lcid"],
                system_lcid=lcid4, code10=code10, code4=code4,
                paired=paired, paired_delta=paired_delta, title=title,
                hha=hha)


def decompose(seconds):
    """(whole hours, remainder) for a gap, so that a constant bias and a
    duration are not reported as one number."""
    hours = int(round(seconds / 3600.0))
    if hours and abs(seconds - hours * 3600) < 60:
        return hours, seconds - hours * 3600
    return 0, seconds


def report(paths):
    rows = []
    for p in paths:
        dirguard.want_file(p, "chmclocks")
        try:
            rows.append(clocks(p))
        except (ValueError, itsf.Bad, struct.error) as e:
            print("  %-28s REFUSED: %s" % (os.path.basename(p), e),
                  file=sys.stderr)
    if not rows:
        sys.exit("chmclocks: nothing was read")
    print("  %-22s %9s %-20s %-26s %-26s"
          % ("file", "bytes", "title", "/#SYSTEM code 10",
             "/#SYSTEM code 4 (FILETIME)"))
    for r in rows:
        print("  %-22s %9d %-20s %-26s %-26s"
              % (os.path.basename(r["path"]), r["bytes"], r["title"][:20],
                 unix_of(r["code10"]).strftime("%Y-%m-%d %H:%M:%S")
                 if r["code10"] else "-",
                 unix_of(r["code4"]).strftime("%Y-%m-%d %H:%M:%S.%f")
                 if r["code4"] else "-"))
    print()
    print("  %-22s %-14s %-14s %10s %12s %10s"
          % ("file", "header LCID", "code-4 LCID", "hdr-vs-c4",
             "code10-code4", "remainder"))
    for r in rows:
        pair = r["paired_delta"] if r["paired_delta"] is not None \
            else float("nan")
        gap = (r["code10"] - r["code4"]) if (r["code10"] and r["code4"]) \
            else float("nan")
        hours, rest = decompose(gap)
        print("  %-22s 0x%04X         0x%04X         %9.6f %12.6f %10s"
              % (os.path.basename(r["path"]), r["header_lcid"],
                 r["system_lcid"] or 0, pair, gap,
                 ("%dh + %.6f" % (hours, rest)) if hours
                 else "%.6f" % rest))
    print()
    print("  hdr-vs-c4    : the ITSF header's truncated u32 at +0x10, joined")
    print("                 to the code-4 FILETIME's high half, minus that")
    print("                 FILETIME. Two structures written by one pass.")
    print("  code10-code4 : the gap three earlier specimens read as the")
    print("                 compile duration. Where it is a whole number of")
    print("                 hours plus a few seconds it is DECOMPOSED, because")
    print("                 a constant and a duration are not one quantity.")
    print()
    print("  No time zone in the Windows or IANA databases lies outside")
    print("  -12:00 .. +14:00, so a whole-hour term larger than fourteen")
    print("  cannot be one field being local while the other is UTC.")
    return 0


def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    ok("the FILETIME epoch is 1601 and the offset is 11,644,473,600 s",
       filetime_seconds(116444736000000000) == 0.0,
       str(filetime_seconds(116444736000000000)))
    ok("this object's code-4 FILETIME is 2005-08-30 06:43:56.046875 UTC",
       unix_of(filetime_seconds(0x01C5AD2E317F850E)).strftime(
           "%Y-%m-%d %H:%M:%S.%f") == "2005-08-30 06:43:56.046875",
       unix_of(filetime_seconds(0x01C5AD2E317F850E)).isoformat())
    ok("its code-10 u32 is 2005-08-30 22:44:00 UTC",
       unix_of(1125441840).strftime("%Y-%m-%d %H:%M:%S")
       == "2005-08-30 22:44:00", unix_of(1125441840).isoformat())
    gap = 1125441840 - filetime_seconds(0x01C5AD2E317F850E)
    ok("the gap is 57,603.953125 s", abs(gap - 57603.953125) < 1e-6,
       "%.6f" % gap)
    h, rest = decompose(gap)
    ok("it decomposes to sixteen hours plus 3.953125 s",
       h == 16 and abs(rest - 3.953125) < 1e-6, "%d h + %.6f" % (h, rest))
    ok("57,600 s is sixteen hours exactly", 16 * 3600 == 57600)
    ok("a gap of nine seconds is NOT decomposed into hours",
       decompose(8.44)[0] == 0, str(decompose(8.44)))
    ok("a gap of 3,601 s IS decomposed into one hour",
       decompose(3601.0) == (1, 1.0), str(decompose(3601.0)))
    ok("sixteen hours is outside every real zone offset",
       16 > 14 and -16 < -12)
    ok("doubling Japan's +9 gives eighteen and not sixteen", 2 * 9 == 18)
    ok("doubling +8 gives sixteen", 2 * 8 == 16)
    ft = 0x01C5AD2E317F850E
    joined = (ft & 0xFFFFFFFF00000000) | 0x31844A0A
    ok("the pairing is 312,572 ticks, computed as integers",
       joined - ft == 312572, str(joined - ft))
    ok("which is 0.0312572 s and not the 0.031258 a float subtraction gives",
       abs((joined - ft) / 1e7 - 0.0312572) < 1e-12
       and abs(filetime_seconds(joined) - filetime_seconds(ft) - 0.0312572)
       > 1e-9,
       "%.7f vs %.7f" % ((joined - ft) / 1e7,
                         filetime_seconds(joined) - filetime_seconds(ft)))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.paths:
        sys.exit("chmclocks: at least one .chm is required")
    return report(args.paths)


if __name__ == "__main__":
    sys.exit(main())
