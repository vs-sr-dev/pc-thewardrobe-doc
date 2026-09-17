"""bank.py -- a reader for the `BANK` archives on the Underground CD-ROM,
derived from the bytes rather than from any published description.

There is no specification for this container. What follows is what the bytes
say, and the `--validate` mode is what makes it a derivation instead of a guess:
it requires the directory to close on the file length **exactly**, with no
slack and no negative remainder, before it will list anything.

The layout, as derived:

    offset  size  meaning
    0       4     the ASCII magic 'BANK'
    4       4     u32, little-endian: the number of members
    8       4     u32, little-endian: the byte offset at which the member data
                  starts, which is also the byte just past the directory
    12      ...   the directory: one record per member,

                      u32  length of the name, in bytes, no terminator
                      char length bytes, the name, uppercase 8.3
                      u32  the length of the member's data

    [8]     ...   the data: the members' bytes, concatenated in directory
                  order, with no padding and no per-member header.

A member's offset is not stored: it is the value at offset 8 plus the sum of
the sizes of every member before it. That is checkable, and it is what makes
the arithmetic close or not close.

Which of the two words is the count was **not** obvious and was not guessed: a
parser told to read the larger one as a count walked off the end of the
directory at exactly record 304 of `2D.DAT` and record 46 of `SUONI.DAT`, at
byte offsets 5877 and 874 -- which are the other word. The two words identify
each other.

Usage:
    python tools/bank.py FILE.DAT --validate
    python tools/bank.py FILE.DAT --list
    python tools/bank.py FILE.DAT --sha1
    python tools/bank.py FILE.DAT --extract OUTDIR
    python tools/bank.py --selftest
"""

import hashlib
import os
import struct
import sys

MAGIC = b"BANK"
HEADER = 12


class BankError(Exception):
    pass


def parse(data, limit=None):
    """Return (a, b, [(name, size, offset), ...]) or raise."""
    if len(data) < HEADER:
        raise BankError("file is shorter than a BANK header (%d bytes)" % len(data))
    if data[:4] != MAGIC:
        raise BankError("magic is %r, not %r" % (data[:4], MAGIC))
    count, datastart = struct.unpack_from("<II", data, 4)
    if count == 0:
        raise BankError("member count is zero")
    if count > len(data):
        raise BankError("member count %d exceeds the file length %d" % (count, len(data)))
    if datastart < HEADER or datastart > len(data):
        raise BankError("data start %d is outside the file (%d bytes)"
                        % (datastart, len(data)))
    a, b = count, datastart
    p = HEADER
    entries = []
    n = limit if limit is not None else count
    for i in range(n):
        if p + 4 > len(data):
            raise BankError("directory ran off the end at record %d (offset %d)" % (i, p))
        (nlen,) = struct.unpack_from("<I", data, p)
        p += 4
        if nlen == 0 or nlen > 255:
            raise BankError("record %d has an implausible name length %d at offset %d"
                            % (i, nlen, p - 4))
        if p + nlen + 4 > len(data):
            raise BankError("record %d name/size ran off the end at offset %d" % (i, p))
        name = data[p:p + nlen]
        p += nlen
        (size,) = struct.unpack_from("<I", data, p)
        p += 4
        try:
            name = name.decode("ascii")
        except UnicodeDecodeError:
            raise BankError("record %d has a non-ASCII name %r" % (i, name))
        entries.append([name, size, None])
    dir_end = p
    if dir_end != datastart:
        raise BankError("the directory ends at %d but the header says the data"
                        " starts at %d -- the two disagree by %d bytes"
                        % (dir_end, datastart, datastart - dir_end))
    off = datastart
    for e in entries:
        e[2] = off
        off += e[1]
    return a, b, entries, dir_end, off


def validate(path):
    with open(path, "rb") as fh:
        data = fh.read()
    print("file                     : %s" % path)
    print("bytes                    : %d" % len(data))
    try:
        a, b, entries, dir_end, end = parse(data)
    except BankError as exc:
        print("PARSE FAILED             : %s" % exc)
        return 1
    print("magic                    : %r" % data[:4])
    print("member count (offset 4)  : %d  (0x%X)" % (a, a))
    print("data start   (offset 8)  : %d  (0x%X)" % (b, b))
    print("records read             : %d" % len(entries))
    print("directory ends at        : %d" % dir_end)
    print("sum of member sizes      : %d" % sum(e[1] for e in entries))
    print("header + directory + data: %d" % end)
    print("file length              : %d" % len(data))
    print("remainder                : %d   <-- must be 0" % (len(data) - end))
    print()
    print("Does word A count anything?")
    exts = {}
    for name, _size, _off in entries:
        exts[name.rsplit(".", 1)[-1] if "." in name else "(none)"] = \
            exts.get(name.rsplit(".", 1)[-1] if "." in name else "(none)", 0) + 1
    print("  distinct extensions    : %d %s" % (len(exts), sorted(exts.items())))
    print("  distinct names         : %d" % len({e[0] for e in entries}))
    stems = {n.rsplit(".", 1)[0].rstrip("0123456789_") for n, _s, _o in entries}
    print("  distinct name stems    : %d  (trailing digits and _ stripped)" % len(stems))
    print("  members of size 0      : %d" % sum(1 for e in entries if e[1] == 0))
    print("  mean bytes per member  : %.1f" % (sum(e[1] for e in entries) / len(entries)))
    print("  largest member         : %s" % max(entries, key=lambda e: e[1])[:2])
    print("  smallest member        : %s" % min(entries, key=lambda e: e[1])[:2])
    return 0 if len(data) == end else 1


def selftest():
    fails = 0
    print("=== NEGATIVE CONTROL 1: wrong magic must raise ===")
    try:
        parse(b"JUNK" + struct.pack("<II", 1, 1) + b"\x01\x00\x00\x00A\x00\x00\x00\x00")
        print("  *** DID NOT RAISE ***")
        fails += 1
    except BankError as exc:
        print("  raised: %s" % exc)

    print("=== NEGATIVE CONTROL 2: a truncated directory must raise ===")
    try:
        parse(MAGIC + struct.pack("<II", 1, 500) + b"\x01\x00\x00\x00A")
        print("  *** DID NOT RAISE ***")
        fails += 1
    except BankError as exc:
        print("  raised: %s" % exc)

    print("=== NEGATIVE CONTROL 3: an absurd name length must raise ===")
    try:
        parse(MAGIC + struct.pack("<II", 1, 22) + struct.pack("<I", 99999) + b"A" * 10)
        print("  *** DID NOT RAISE ***")
        fails += 1
    except BankError as exc:
        print("  raised: %s" % exc)

    print("=== POSITIVE CONTROL: a hand-built two-member bank must close ===")
    body = (MAGIC + struct.pack("<II", 2, 38)
            + struct.pack("<I", 5) + b"A.BMP" + struct.pack("<I", 3)
            + struct.pack("<I", 5) + b"B.WAV" + struct.pack("<I", 4)
            + b"abc" + b"defg")
    a, b, ents, dir_end, end = parse(body)
    ok = (len(body) == end and [e[0] for e in ents] == ["A.BMP", "B.WAV"]
          and [e[1] for e in ents] == [3, 4]
          and body[ents[0][2]:ents[0][2] + 3] == b"abc"
          and body[ents[1][2]:ents[1][2] + 4] == b"defg")
    print("  entries %r closes at %d of %d -> %s"
          % ([(e[0], e[1], e[2]) for e in ents], end, len(body), "ok" if ok else "WRONG"))
    if not ok:
        fails += 1

    print("=== NEGATIVE CONTROL 4: a directory that disagrees with the stated"
          " data start must raise ===")
    try:
        parse(MAGIC + struct.pack("<II", 2, 44)
              + struct.pack("<I", 5) + b"A.BMP" + struct.pack("<I", 3)
              + struct.pack("<I", 5) + b"B.WAV" + struct.pack("<I", 4)
              + b"abc" + b"defg")
        print("  *** DID NOT RAISE ***")
        fails += 1
    except BankError as exc:
        print("  raised: %s" % exc)

    print("=== POSITIVE CONTROL: one byte of trailing junk must break the close ===")
    a, b, ents, dir_end, end = parse(body + b"\x00")
    print("  remainder %d -> %s" % (len(body) + 1 - end,
                                    "ok" if len(body) + 1 - end == 1 else "WRONG"))
    if len(body) + 1 - end != 1:
        fails += 1
    print()
    print("failures: %d" % fails)
    return 1 if fails else 0


def main(argv):
    if "--selftest" in argv:
        return selftest()
    if len(argv) < 3:
        print(__doc__)
        return 2
    path = argv[1]
    if "--validate" in argv:
        return validate(path)

    with open(path, "rb") as fh:
        data = fh.read()
    a, b, entries, dir_end, end = parse(data)
    if end != len(data):
        raise SystemExit("refusing to act on a bank whose arithmetic does not close"
                         " (remainder %d) -- run --validate" % (len(data) - end))

    if "--list" in argv:
        print("%-24s %10s %12s" % ("name", "size", "offset"))
        for name, size, off in entries:
            print("%-24s %10d %12d" % (name, size, off))
        return 0
    if "--sha1" in argv:
        for name, size, off in entries:
            print("%s  %10d  %s"
                  % (hashlib.sha1(data[off:off + size]).hexdigest(), size, name))
        return 0
    if "--extract" in argv:
        out = argv[argv.index("--extract") + 1]
        os.makedirs(out, exist_ok=True)
        for name, size, off in entries:
            with open(os.path.join(out, name), "wb") as fh:
                fh.write(data[off:off + size])
        print("extracted %d members to %s" % (len(entries), out))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
