#!/usr/bin/env python3
"""tptab.py -- the .TAB index files of Theme Park, which are two formats.

The pre-briefing read every `.TAB` as an array of ascending little-endian
`u32` offsets into its `.DAT` partner and it failed on 19 of 25, with
`0x005A0000` recurring across nine tables of three different sizes. Both
symptoms have the same cause: **the record is not four bytes wide**, and
reading a wider record four bytes at a time drags a neighbouring field into
the top of the offset. `0x005A0000` is the `u16` 90 that sits at the end of a
sound record, read as though it were the high half of an offset.

There are two record shapes and each closes on its own arithmetic.

**The sprite table, 6 bytes.** 19 of the 25 tables in `GAME\\DATA`:

    +0   u32   offset into the .DAT
    +4   u8    width  in pixels
    +5   u8    height in pixels

Record 0 is a null entry -- offset 0, 0x0 -- so index 0 means "no sprite",
and the first real sprite starts at byte 2 of the `.DAT`. Sprite data is
compressed: the gap between consecutive offsets is smaller than `w * h` on
some entries and larger on others, so this tool reports the gaps and does not
pretend to know the codec.

**The sound table, 32 bytes.** The six `SNDS*` and `MUSIC*` tables, and this
one carries NAMES:

    +0   char[18]  member name, NUL-padded -- `BUTTON.RAW`, `RIDE1.HMP`
    +18  u32       offset into the .DAT
    +22  u32       zero on every record in this object
    +26  u32       length in bytes
    +30  u16       90 on every member, 0 on record 0

Record 0 is a header rather than a member: its name is empty, its offset is 0
and its length field holds **the length of the whole `.DAT`**. The members
that follow are contiguous -- each offset is the previous offset plus the
previous length -- and the lengths sum to the `.DAT` size exactly, with
residue 0 on 6 of 6 tables.

So the six sound tables are a directory of 115 named members, which is the
only place in this object where a member has a name.

    python tools/tptab.py validate <file.TAB>
    python tools/tptab.py census   <dir>            both kinds, with closure
    python tools/tptab.py list     <file.TAB>       every record
    python tools/tptab.py selftest
"""
import os
import struct
import sys

SOUND_REC = 32
SPRITE_REC = 6
NAME_LEN = 18


class Refused(Exception):
    pass


def _dat_for(path):
    """The partner file, by stem. `.DAT` first, then `.ANI`."""
    stem = os.path.splitext(path)[0]
    for ext in (".DAT", ".ANI", ".dat", ".ani"):
        if os.path.exists(stem + ext):
            return stem + ext
    return None


def kind(d):
    """Which of the two shapes this is, decided on evidence and not on size.

    A sound table's record 0 holds the .DAT length at +26 and its record 1
    begins with printable ASCII followed by NULs. A sprite table's record 0 is
    six zero bytes and its record 1 has a small offset and non-zero w/h.
    """
    if len(d) < SPRITE_REC or len(d) % SPRITE_REC and len(d) % SOUND_REC:
        raise Refused("length %d is a multiple of neither 6 nor 32" % len(d))
    if len(d) % SOUND_REC == 0 and len(d) >= 2 * SOUND_REC:
        name = d[SOUND_REC:SOUND_REC + NAME_LEN]
        stem = name.split(b"\0")[0]
        if stem and all(32 <= c < 127 for c in stem) and b"." in stem:
            return "sound"
    if len(d) % SPRITE_REC == 0:
        return "sprite"
    raise Refused("neither a named sound table nor a 6-byte sprite table")


def sound_records(d):
    if len(d) % SOUND_REC:
        raise Refused("length %d is not a multiple of %d" % (len(d), SOUND_REC))
    recs = []
    for i in range(0, len(d), SOUND_REC):
        r = d[i:i + SOUND_REC]
        name = r[:NAME_LEN].split(b"\0")[0].decode("latin-1")
        off, zero, size, flag = struct.unpack_from("<IIIH", r, NAME_LEN)
        recs.append({"name": name, "offset": off, "spare": zero,
                     "size": size, "flag": flag})
    if recs[0]["name"]:
        raise Refused("record 0 carries a name, so it is not a header")
    return recs


def sprite_records(d):
    if len(d) % SPRITE_REC:
        raise Refused("length %d is not a multiple of %d" % (len(d), SPRITE_REC))
    recs = []
    for i in range(0, len(d), SPRITE_REC):
        off = int.from_bytes(d[i:i + 4], "little")
        recs.append({"offset": off, "w": d[i + 4], "h": d[i + 5]})
    return recs


def check_sound(recs, datlen):
    """The closure: contiguous offsets and lengths summing to the .DAT."""
    hdr = recs[0]
    members = recs[1:]
    pos = 0
    contiguous = True
    total = 0
    for m in members:
        if m["offset"] != pos:
            contiguous = False
        pos = m["offset"] + m["size"]
        total += m["size"]
    return {"declared": hdr["size"], "sum": total, "end": pos,
            "contiguous": contiguous, "datlen": datlen,
            "residue": (datlen - total) if datlen is not None else None,
            "members": len(members)}


def check_sprite(recs, datlen):
    """Ascending offsets, a null record 0, and the tail after the last one."""
    offs = [r["offset"] for r in recs]
    ascending = all(b > a for a, b in zip(offs[1:], offs[2:])) if len(offs) > 2 else True
    null0 = recs[0]["offset"] == 0 and recs[0]["w"] == 0 and recs[0]["h"] == 0
    inside = sum(1 for o in offs if datlen is not None and o < datlen)
    return {"records": len(recs), "null_record_0": null0,
            "ascending_after_0": ascending, "last": offs[-1],
            "datlen": datlen, "inside": inside,
            "tail": (datlen - offs[-1]) if datlen is not None else None,
            "max_w": max(r["w"] for r in recs),
            "max_h": max(r["h"] for r in recs)}


def cmd_validate(path):
    d = open(path, "rb").read()
    try:
        k = kind(d)
    except Refused as e:
        print("REFUSED  %s: %s" % (os.path.basename(path), e))
        return 1
    dat = _dat_for(path)
    datlen = os.path.getsize(dat) if dat else None
    if k == "sound":
        recs = sound_records(d)
        c = check_sound(recs, datlen)
        print("%s  %d bytes, %d records, SOUND table" % (os.path.basename(path), len(d), len(recs)))
        print("  header declares %d, members sum to %d, partner is %s"
              % (c["declared"], c["sum"], c["datlen"]))
        print("  offsets contiguous : %s" % c["contiguous"])
        print("  residue            : %s" % c["residue"])
    else:
        recs = sprite_records(d)
        c = check_sprite(recs, datlen)
        print("%s  %d bytes, %d records, SPRITE table" % (os.path.basename(path), len(d), len(recs)))
        print("  record 0 null      : %s" % c["null_record_0"])
        print("  ascending after 0  : %s" % c["ascending_after_0"])
        print("  last offset %d, partner %s, tail %s"
              % (c["last"], c["datlen"], c["tail"]))
        print("  largest sprite     : %d x %d" % (c["max_w"], c["max_h"]))
    return 0


def cmd_list(path):
    d = open(path, "rb").read()
    k = kind(d)
    if k == "sound":
        for i, r in enumerate(sound_records(d)):
            print("%4d  %-18s off %9d  len %9d  spare %d  flag %d"
                  % (i, r["name"] or "(header)", r["offset"], r["size"],
                     r["spare"], r["flag"]))
    else:
        recs = sprite_records(d)
        for i, r in enumerate(recs):
            gap = recs[i + 1]["offset"] - r["offset"] if i + 1 < len(recs) else None
            print("%5d  off %9d  %3d x %3d = %6d px   gap %s"
                  % (i, r["offset"], r["w"], r["h"], r["w"] * r["h"], gap))
    return 0


def cmd_census(root):
    tabs = []
    for base, _, names in os.walk(root):
        for n in sorted(names):
            if n.upper().endswith(".TAB"):
                tabs.append(os.path.join(base, n))
    print("%-16s %6s %8s %6s %10s %10s %9s %s"
          % ("table", "bytes", "kind", "recs", "partner", "accounted",
             "residue", "note"))
    closed = 0
    sound_tables = 0
    members = 0
    refused = 0
    for t in tabs:
        d = open(t, "rb").read()
        dat = _dat_for(t)
        datlen = os.path.getsize(dat) if dat else None
        try:
            k = kind(d)
        except Refused as e:
            refused += 1
            print("%-16s %6d %8s %6s %10s %10s %9s %s"
                  % (os.path.basename(t), len(d), "REFUSED", "-", "-", "-", "-", e))
            continue
        if k == "sound":
            recs = sound_records(d)
            c = check_sound(recs, datlen)
            sound_tables += 1
            members += c["members"]
            if c["residue"] == 0 and c["contiguous"]:
                closed += 1
            print("%-16s %6d %8s %6d %10s %10d %9s %s"
                  % (os.path.basename(t), len(d), "sound", len(recs),
                     datlen, c["sum"], c["residue"],
                     "contiguous" if c["contiguous"] else "GAPS"))
        else:
            recs = sprite_records(d)
            c = check_sprite(recs, datlen)
            print("%-16s %6d %8s %6d %10s %10s %9s %s"
                  % (os.path.basename(t), len(d), "sprite", len(recs),
                     datlen, c["last"], c["tail"],
                     "%dx%d max, %s" % (c["max_w"], c["max_h"],
                                        "ascending" if c["ascending_after_0"]
                                        else "NOT ASCENDING")))
    print()
    print("tables %d, refused %d" % (len(tabs), refused))
    print("sound tables closing with residue 0 and contiguous offsets: %d of %d"
          % (closed, sound_tables))
    print("named members in the sound tables: %d" % members)
    return 0


def cmd_selftest():
    cases = []
    # an acceptance: a two-record sound table that closes
    hdr = b"\0" * NAME_LEN + struct.pack("<IIIH", 0, 0, 100, 0)
    m1 = b"A.RAW".ljust(NAME_LEN, b"\0") + struct.pack("<IIIH", 0, 0, 40, 90)
    m2 = b"B.RAW".ljust(NAME_LEN, b"\0") + struct.pack("<IIIH", 40, 0, 60, 90)
    cases.append(("a sound table that closes on 100 bytes", hdr + m1 + m2,
                  "sound", True))
    # an acceptance: a sprite table
    spr = b"\0" * 6 + struct.pack("<IBB", 2, 12, 19) + struct.pack("<IBB", 207, 10, 18)
    cases.append(("a three-record sprite table", spr, "sprite", True))
    # refusals
    cases.append(("a length that is a multiple of neither 6 nor 32",
                  b"\0" * 7, None, False))
    cases.append(("a 32-byte table whose record 0 carries a name",
                  m1 + m2, None, False))
    cases.append(("empty", b"", None, False))
    fails = 0
    for name, data, want_kind, ok in cases:
        try:
            k = kind(data)
            if k == "sound":
                sound_records(data)
            else:
                sprite_records(data)
            got = True
            why = "kind=%s" % k
        except Refused as e:
            got, why = False, str(e)
        except Exception as e:                       # noqa: BLE001
            got, why = False, "unexpected %s" % e
        mark = "ok " if got == ok else "FAIL"
        if got != ok:
            fails += 1
        print("%s  %-48s expected %-7s got %-7s %s"
              % (mark, name, "accept" if ok else "refuse",
                 "accept" if got else "refuse", why))
    # the positive control that has to produce the right arithmetic
    recs = sound_records(cases[0][1])
    c = check_sound(recs, 100)
    good = c["sum"] == 100 and c["contiguous"] and c["residue"] == 0
    print("%s  %-48s %s" % ("ok " if good else "FAIL",
                            "the accepted sound table closes at residue 0",
                            "40 + 60 = 100" if good else repr(c)))
    if not good:
        fails += 1
    print()
    print("%d specimens, %d must be accepted, %d failures"
          % (len(cases) + 1, sum(1 for c in cases if c[3]) + 1, fails))
    return 1 if fails else 0


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "validate":
        return cmd_validate(rest[0])
    if cmd == "list":
        return cmd_list(rest[0])
    if cmd == "census":
        return cmd_census(rest[0])
    if cmd == "selftest":
        return cmd_selftest()
    print("unknown command %r" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
