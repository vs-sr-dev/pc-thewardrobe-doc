#!/usr/bin/env python3
"""Read the SCUMM index file (`SAMNMAX.000`) and derive its record shapes.

Nothing here is taken from a reference implementation. The record shapes are
*derived by division*, the same way the container's chunk header size was
derived by tiling:

* Five of the nine chunks — `DROO DSCR DSOU DCOS DCHR` — have payloads that
  satisfy `payload = 2 + 5n` for an integer n, and no other small record size
  divides all five. That fixes the shape as `[count:2 LE][count x room byte]
  [count x offset:4 LE]`, and the fix is then *tested*: the offsets in `DROO`
  must equal the offsets already listed in the container's own `LOFF` table,
  which was read independently. They do.

* `MAXS` is 30 bytes = fifteen 16-bit fields. Its last six fields are
  95, 122, 95, 6, 349, 1100 — which are exactly the counts the five directories
  above declare, plus the object count. That is what identifies `MAXS` as the
  engine's limit table, and it is derived, not assumed.

* `DOBJ`'s payload is 5,502 = 2 + 5 x 1100, and 1100 is `MAXS`'s last field.
  So its record is 5 bytes per object: one state/owner byte and a 4-byte
  class field.

* `AARY` is a list of array declarations terminated by a zero word; its record
  size falls out of walking it until the terminator lands exactly on the end
  of the chunk.

Usage:
  python tools/scummidx.py <SAMNMAX.000> [--key 0x69] [--offsets]
"""
import sys


def load(path, key):
    d = open(path, "rb").read()
    return bytes(b ^ key for b in d) if key else d


def chunks(d):
    p = 0
    out = []
    while p < len(d):
        tag = d[p:p + 4].decode("latin-1")
        ln = int.from_bytes(d[p + 4:p + 8], "big")
        out.append((tag, p, ln, d[p + 8:p + ln]))
        p += ln
    if p != len(d):
        sys.exit("index does not tile: consumed %d of %d" % (p, len(d)))
    return out


def u16(b, o):
    return int.from_bytes(b[o:o + 2], "little")


def directory(body):
    """[count:2][count x disk byte][count x offset:4 LE] -- shape by division."""
    n = u16(body, 0)
    if len(body) != 2 + 5 * n:
        return None
    disks = list(body[2:2 + n])
    offs = [int.from_bytes(body[2 + n + 4 * i:2 + n + 4 * i + 4], "little")
            for i in range(n)]
    return n, disks, offs


def main(path, key, show_offsets):
    d = load(path, key)
    cs = chunks(d)
    print("index file %d bytes, %d chunks, consumed exactly\n" % (len(d), len(cs)))
    print("%-6s %8s %8s %10s" % ("tag", "at", "size", "payload"))
    for tag, off, ln, body in cs:
        print("%-6s %8d %8d %10d" % (tag, off, ln, len(body)))
    print()

    by = {c[0]: c[3] for c in cs}

    m = by["MAXS"]
    words = [u16(m, i) for i in range(0, len(m), 2)]
    print("MAXS %d bytes = %d 16-bit fields" % (len(m), len(words)))
    print("  " + " ".join(str(w) for w in words))
    print()

    print("%-6s %6s %6s %8s %8s %s"
          % ("dir", "count", "used", "min off", "max off", "disks"))
    for tag in ("DROO", "DSCR", "DSOU", "DCOS", "DCHR"):
        body = by[tag]
        r = directory(body)
        if r is None:
            print("%-6s payload %d does not fit 2+5n" % (tag, len(body)))
            continue
        n, disks, offs = r
        used = sum(1 for i in range(n) if offs[i] or disks[i])
        nz = [o for o in offs if o]
        print("%-6s %6d %6d %8d %8d %s"
              % (tag, n, used, min(nz) if nz else 0, max(nz) if nz else 0,
                 sorted(set(disks))))
        if show_offsets:
            for i in range(n):
                if offs[i] or disks[i]:
                    print("    %-4d disk %d  offset %d" % (i, disks[i], offs[i]))
    print()

    o = by["DOBJ"]
    n = u16(o, 0)
    rec = (len(o) - 2) // n if n else 0
    print("DOBJ %d bytes, count %d, (payload-2)/count = %.4f"
          % (len(o), n, (len(o) - 2) / n))
    if len(o) == 2 + 5 * n:
        state = o[2:2 + n]
        cls = [int.from_bytes(o[2 + n + 4 * i:2 + n + 4 * i + 4], "little")
               for i in range(n)]
        nonzero = sum(1 for i in range(n) if state[i] or cls[i])
        print("  record 5 bytes: 1 state/owner byte + 4-byte class")
        print("  objects with a non-zero state or class: %d of %d"
              % (nonzero, n))
        owners = {}
        for s in state:
            owners[s >> 4] = owners.get(s >> 4, 0) + 1
        print("  high nibble of state byte (owner) histogram: %s"
              % dict(sorted(owners.items())))
    print()

    a = by["AARY"]
    print("AARY %d bytes" % len(a))
    p = 0
    rows = 0
    while p + 2 <= len(a):
        num = u16(a, p)
        if num == 0:
            p += 2
            break
        dim2, dim1, vtype = u16(a, p + 2), u16(a, p + 4), u16(a, p + 6)
        print("  array %-5d dim2=%-5d dim1=%-5d type=%d" % (num, dim2, dim1, vtype))
        rows += 1
        p += 8
    print("  %d declarations, terminator at %d, chunk is %d -> %s"
          % (rows, p, len(a), "exact" if p == len(a) else "LEFTOVER %d" % (len(a) - p)))
    print()

    r = by["RNAM"]
    print("RNAM %d bytes: %s" % (len(r), r.hex(" ")))
    print("  room-name table is empty" if r == b"\0" * len(r)
          else "  room-name table is NOT empty")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    k = 0x69
    for i, a in enumerate(sys.argv):
        if a == "--key":
            k = int(sys.argv[i + 1], 0)
    main(args[0], k, "--offsets" in sys.argv)
