#!/usr/bin/env python3
"""patch_iso9660.py -- the two corrections this object forced on the inherited
ISO 9660 reader, applied with an assertion in front of every one of them.

M1 -- the timezone label was a lie on any disc that had one.
ECMA-119 section 8.4.26.1 defines the offset field as a signed count of
**15-minute intervals** from Greenwich, not a count of hours. Every disc
measured in this branch before this one carried a zero in that byte, so the
label `GMT+0` was right by accident fourteen times. This disc carries 4, and
the tool printed `GMT+4` for a disc mastered in Italy in January, where the
right answer is `GMT+01:00`.

M2 -- `--gaps` reported both root directories as belonging to nobody.
`tree_of()` walks the *contents* of the root and never emits a record for the
root itself, so the root's own extent is never marked used. On a disc with two
namespaces that is two sectors of false positive, and this disc's unclaimed
count read 157 where the truth is 155.

Both patches assert that the text they are replacing exists, and both refuse to
run twice. Run it once:

    python tools/patch_iso9660.py tools/iso9660.py
"""

import sys

TZ_HELPER = '''
def tz_label(off):
    """ECMA-119 8.4.26.1 / 9.1.5: the offset from Greenwich is a signed count
    of FIFTEEN-MINUTE intervals, not of hours. Byte 4 is GMT+01:00, not GMT+4.
    Legal range is -48 (GMT-12:00) to +52 (GMT+13:00)."""
    minutes = off * 15
    sign = "-" if minutes < 0 else "+"
    minutes = abs(minutes)
    return "GMT%s%02d:%02d" % (sign, minutes // 60, minutes % 60)


def dir_datetime(b):'''

PATCHES = [
    # -- M1: insert the helper just before dir_datetime -------------------
    ("\ndef dir_datetime(b):", TZ_HELPER, 1),

    # -- M1: the four volume-descriptor dates -----------------------------
    ('''            print("  %-30s: %-26s GMT%+d  raw %r" % (
                lab + " date", s if s else "(unset)", off, raw))''',
     '''            print("  %-30s: %-26s %-9s raw %r" % (
                lab + " date", s if s else "(unset)", tz_label(off), raw))''',
     1),

    # -- M1: the root directory record in --vd ----------------------------
    ('''        print("  %-30s: extent %d, %d bytes, %s GMT%+d" % (
            "root directory record", struct.unpack_from("<I", rd, 2)[0],
            struct.unpack_from("<I", rd, 10)[0], ts, tz))''',
     '''        print("  %-30s: extent %d, %d bytes, %s %s" % (
            "root directory record", struct.unpack_from("<I", rd, 2)[0],
            struct.unpack_from("<I", rd, 10)[0], ts, tz_label(tz)))''',
     1),

    # -- M1: --tree ------------------------------------------------------
    ('''    print("%-78s %11s %9s  %-21s %s" % ("path", "bytes", "extent",
                                        "recorded", "tz"))''',
     '''    print("%-78s %11s %9s  %-21s %s" % ("path", "bytes", "extent",
                                        "recorded", "offset"))''',
     1),
    ('''        line = "%-78s %11s %9d  %-21s %+d" % (
            full, "" if e["isdir"] else e["size"], e["extent"],
            e["time"], e["tz"])''',
     '''        line = "%-78s %11s %9d  %-21s %s" % (
            full, "" if e["isdir"] else e["size"], e["extent"],
            e["time"], tz_label(e["tz"]))''',
     1),

    # -- M1: --dates -----------------------------------------------------
    ('''    print("%-21s %5s %6s  %-23s %s" % ("as-printed", "tz", "count",
                                       "raw seven bytes", "valid?"))
    for (ts, tz, raw7), n in sorted(c.items(), key=lambda kv: -kv[1]):
        print("%-21s %+5d %6d  %-23s %s" % (
            ts, tz, n, " ".join("%02X" % x for x in raw7),
            "yes" if date_is_valid(raw7) else "NO"))''',
     '''    print("%-21s %-10s %6s  %-23s %s" % ("as-printed", "offset", "count",
                                        "raw seven bytes", "valid?"))
    for (ts, tz, raw7), n in sorted(c.items(), key=lambda kv: -kv[1]):
        print("%-21s %-10s %6d  %-23s %s" % (
            ts, tz_label(tz), n, " ".join("%02X" % x for x in raw7),
            "yes" if date_is_valid(raw7) else "NO"))''',
     1),

    # -- M2: the root blind spot in --gaps -------------------------------
    ('''    for e in entries + jol:
        n = (e["size"] + SECTOR - 1) // SECTOR
        for s in range(e["extent"], min(e["extent"] + n, total)):
            used[s] = 1''',
     '''    # The root directory record lives in the volume descriptor, not in any
    # parent directory, so tree_of() never emits it and its own extent was
    # being counted as unclaimed -- once per namespace. See M2 in
    # docs/19-corrections.md.
    for _sec, b in ((pick(vds, False)), (pick(vds, True))):
        rd = b[156:190]
        rext = struct.unpack_from("<I", rd, 2)[0]
        rlen = struct.unpack_from("<I", rd, 10)[0]
        for s in range(rext, min(rext + (rlen + SECTOR - 1) // SECTOR, total)):
            used[s] = 1
    for e in entries + jol:
        n = (e["size"] + SECTOR - 1) // SECTOR
        for s in range(e["extent"], min(e["extent"] + n, total)):
            used[s] = 1''',
     1),
]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "tools/iso9660.py"
    src = open(path, encoding="utf-8").read()

    if "def tz_label(" in src:
        raise SystemExit("%s already carries tz_label(); refusing to patch "
                         "twice" % path)

    for old, new, want in PATCHES:
        found = src.count(old)
        if found != want:
            raise SystemExit(
                "PATTERN NOT FOUND (or found %d times, wanted %d) in %s:\n%s"
                % (found, want, path, old[:200]))
        src = src.replace(old, new, want)
        print("ok   replaced %d occurrence(s) of: %s..."
              % (want, old.strip().splitlines()[0][:64]))

    open(path, "w", encoding="utf-8").write(src)
    print("wrote %s" % path)


if __name__ == "__main__":
    main()
