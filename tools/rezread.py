#!/usr/bin/env python3
"""rezread.py -- the BRGR archive, derived from the bytes of eight files.

Eight files on the third 3DO disc open with the four characters `BRGR`, and they
are exactly `/REZFILE` and the seven `/Levels/*.REZ`. Nothing here is an
expansion of the acronym; an expansion of an acronym is not a measurement. What
follows is the structure, and every clause of it is checked on all eight files.

    +0    char[4]  'BRGR'
    +4    u32      member count
    +8    per member, 12 bytes:
             u32  id
             u32  offset from the start of the file
             u32  length
    members are contiguous and begin at 8 + 12 * count

THREE CHECKS, AND THEY ARE THE REASON TO BELIEVE IT

  * **the directory ends where the first member begins.** 8 + 12 x count equals
    the first member's offset, on 8 files of 8. On `/REZFILE` that is
    8 + 12 x 257 = 3,092 = 0x0C14, which is what the first entry's offset word
    says. This is a quantity encoded twice in two unrelated places.
  * **the members tile the file.** Each member's offset equals the previous
    one's offset plus its length, and the last one ends at end of file or
    within a block of it.
  * **a negative control fails.** Handed anything that is not a BRGR archive,
    including an AIF image and a sector of mastering fill, the reader must
    refuse rather than produce a plausible member list.

usage:
    rezread.py validate
    rezread.py FILE [--members] [--extract DIR]
    rezread.py --list FILE FILE ...      one summary line per archive
"""
import argparse
import collections
import hashlib
import os
import struct


class Bad(Exception):
    pass


def parse(d, name="<data>"):
    if len(d) < 8:
        raise Bad("%d bytes is too short for an 8-byte BRGR header" % len(d))
    if d[0:4] != b"BRGR":
        raise Bad("does not open 'BRGR': %r" % d[0:4])
    count = struct.unpack(">I", d[4:8])[0]
    if count == 0:
        raise Bad("member count is zero")
    if 8 + 12 * count > len(d):
        raise Bad("member count %d needs %d bytes of directory, file is %d"
                  % (count, 8 + 12 * count, len(d)))
    members = []
    for i in range(count):
        p = 8 + 12 * i
        mid, off, ln = struct.unpack(">3I", d[p:p + 12])
        if off + ln > len(d):
            raise Bad("member %d at %d+%d runs past the file (%d bytes)"
                      % (i, off, ln, len(d)))
        members.append((mid, off, ln))
    first = 8 + 12 * count
    if members[0][1] != first:
        raise Bad("directory ends at %d but the first member starts at %d"
                  % (first, members[0][1]))
    return count, members


def validate():
    ok = True
    cases = [
        ("2,048 zero bytes", b"\0" * 2048),
        ("the string iamaduck", b"iamaduck" * 256),
        ("an AIF image", b"\xe1\xa0\x00\x00" * 4 + b"\xef\x00\x00\x11" + b"\0" * 64),
        ("an APPSCRN banner", b"\x01APPSCRN" + b"\0" * 200),
        ("BRGR with a member past the end",
         b"BRGR" + struct.pack(">I", 1) + struct.pack(">3I", 1, 20, 9999)),
        ("BRGR whose directory does not meet its first member",
         b"BRGR" + struct.pack(">I", 1) + struct.pack(">3I", 1, 40, 4) + b"\0" * 60),
    ]
    for name, data in cases:
        try:
            parse(data)
            print("FAIL: %-46s was ACCEPTED" % name)
            ok = False
        except Bad as e:
            print("ok  : %-46s rejected -- %s" % (name, e))
    good = (b"BRGR" + struct.pack(">I", 2)
            + struct.pack(">3I", 0x10001, 32, 8)
            + struct.pack(">3I", 0x10002, 40, 8) + b"A" * 16)
    try:
        c, m = parse(good)
        assert c == 2 and m[0][1] == 32
        print("ok  : %-46s accepted, %d members" % ("positive control", c))
    except (Bad, AssertionError) as e:
        print("FAIL: positive control rejected -- %s" % e)
        ok = False
    return 0 if ok else 1


def report(path, show_members=False, extract=None):
    d = open(path, "rb").read()
    count, members = parse(d, path)
    first = 8 + 12 * count
    contiguous = all(members[i][1] == members[i - 1][1] + members[i - 1][2]
                     for i in range(1, count))
    last_end = members[-1][1] + members[-1][2]
    print("%s" % path)
    print("   bytes                       : %d" % len(d))
    print("   members declared            : %d" % count)
    print("   directory ends at           : %d   first member at %d   equal %s"
          % (first, members[0][1], first == members[0][1]))
    print("   members contiguous          : %s" % contiguous)
    print("   last member ends at         : %d   file %d   slack %d"
          % (last_end, len(d), len(d) - last_end))
    ids = [m[0] for m in members]
    hi = collections.Counter(i >> 16 for i in ids)
    print("   id high halves              : %s"
          % ", ".join("%d (x%d)" % (k, v) for k, v in hi.most_common()))
    print("   id low halves               : %d distinct, %d..%d"
          % (len(set(i & 0xFFFF for i in ids)),
             min(i & 0xFFFF for i in ids), max(i & 0xFFFF for i in ids)))
    print("   ids strictly increasing     : %s"
          % all(ids[i] > ids[i - 1] for i in range(1, count)))
    lens = [m[2] for m in members]
    print("   member lengths              : %d..%d, %d of them zero"
          % (min(lens), max(lens), sum(1 for x in lens if x == 0)))
    magic = collections.Counter(d[m[1]:m[1] + 4] for m in members if m[2] >= 4)
    print("   first four bytes of members : %s"
          % ", ".join("%r x%d" % (k, v) for k, v in magic.most_common(6)))
    if show_members:
        print("   %-10s %-10s %-10s %-10s %s"
              % ("id", "offset", "length", "sha1", "first 8 bytes"))
        for mid, off, ln in members:
            body = d[off:off + ln]
            print("   0x%08x %-10d %-10d %s %s"
                  % (mid, off, ln, hashlib.sha1(body).hexdigest()[:12],
                     " ".join("%02x" % x for x in body[:8])))
    if extract:
        base = os.path.join(extract,
                            os.path.basename(path).replace(".", "_"))
        os.makedirs(base, exist_ok=True)
        for mid, off, ln in members:
            with open(os.path.join(base, "%08x.bin" % mid), "wb") as f:
                f.write(d[off:off + ln])
        print("   extracted %d members to %s" % (count, base))
    return count, members, len(d)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--members", action="store_true")
    ap.add_argument("--extract")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.files == ["validate"]:
        raise SystemExit(validate())
    total = 0
    tbytes = 0
    for p in a.files:
        c, m, n = report(p, a.members, a.extract)
        total += c
        tbytes += n
        print()
    print("%d archive(s), %d members, %d bytes" % (len(a.files), total, tbytes))


if __name__ == "__main__":
    main()
