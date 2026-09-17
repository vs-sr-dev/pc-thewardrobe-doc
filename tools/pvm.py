#!/usr/bin/env python3
"""pvm.py -- the PVMH texture archive that comes out of a .PRS, walked and chained.

582 of the 843 .PRS files on this disc decompress to a buffer whose first four
bytes are 'PVMH'. The compressed head said 'PVMH' at offset +1 under a control
byte on 582 of 582, and the decompressed head says it at offset 0 on the same
582, which is a quantity encoded twice in two different ways.

The layout, derived by walking it, not by looking it up:

    +0   4   'PVMH'
    +4   4   u32 LE   bytes of header AFTER this field; the payload starts at
                      this value plus 8
    +8   2   u16 LE   flags. 0x0109 on this disc.
    +10  2   u16 LE   entry count
    +12  n   entries, 34 bytes each while flags == 0x0109:
                        +0  2  u16 LE  entry index
                        +2 28  NUL-padded name, no extension
                       +30  4  u32 LE  global index (the GBIX a loose .PVR
                                       carries as its own chunk)

then the payload: one 'PVRT' chunk per entry, each of which is

    +0   4   'PVRT'
    +4   4   u32 LE   bytes of chunk AFTER this field
    +8   1   u8       pixel format
    +9   1   u8       data format
    +10  2            two bytes of padding, zero on every texture here
    +12  2   u16 LE   width
    +14  2   u16 LE   height
    +16  ..           texture data, (length field - 8) bytes of it

The width and height offsets were got wrong first: read at +10 and +12 the
first texture of ADVSS00.PRS came out 0 x 64 instead of 64 x 64, and the
geometry closed on nothing. The two zero bytes at +10 are the tell.

THE CONTROL, WHICH IS CHAINING AND NOT COUNTING
-----------------------------------------------

The checklist's section 9 says: validate a container by chaining it, walk from
the first chunk to the last and require the final one to end exactly at
end-of-file. Nearly chaining is not understanding. So --validate requires, per
archive:

  * the chunk walk starts exactly at the header's declared payload offset;
  * every chunk is 'PVRT';
  * the number of chunks equals the header's declared entry count;
  * the last chunk ends exactly at the last byte of the decompressed buffer.

Four requirements, and the third and fourth are independent of each other and
of the header arithmetic, which is what makes this a structure and not a sum
that happens to close.

`--geometry` is the separate claim: width x height x bits-per-texel divided by
8, plus 16 bytes of chunk header, must equal the chunk length, or must equal it
under a stated rule (a palettised format, or VQ, which stores a 2,048-byte
codebook and one index per 2x2 texel block). Every data format that does not
close is reported by name and count rather than averaged away.

Usage:
    python tools/pvm.py --validate DIR       # DIR holds .PRS files
    python tools/pvm.py --geometry DIR
    python tools/pvm.py --list FILE.PRS
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prs import decompress                                    # noqa: E402

# ECMA-nothing; these names come from the byte values observed on this disc and
# from the public PVR format description, which is stated rather than assumed.
PIXEL_FORMAT = {
    0x00: "ARGB1555", 0x01: "RGB565", 0x02: "ARGB4444", 0x03: "YUV422",
    0x04: "BUMP", 0x05: "4BPP", 0x06: "8BPP",
}
DATA_FORMAT = {
    0x01: "twiddled", 0x02: "twiddled-mipmap", 0x03: "VQ", 0x04: "VQ-mipmap",
    0x05: "palette4-twiddled", 0x06: "palette4-twiddled-mipmap",
    0x07: "palette8-twiddled", 0x08: "palette8-twiddled-mipmap",
    0x09: "rectangle", 0x0b: "rectangle-stride", 0x0d: "rectangle-twiddled",
    0x10: "small-VQ", 0x11: "small-VQ-mipmap",
}


def parse(buf):
    """Return (header_dict, [chunk_dicts]). Raises ValueError on a broken chain."""
    if buf[:4] != b"PVMH":
        raise ValueError("not a PVMH: head is %r" % bytes(buf[:4]))
    payload = struct.unpack_from("<I", buf, 4)[0] + 8
    flags = struct.unpack_from("<H", buf, 8)[0]
    count = struct.unpack_from("<H", buf, 10)[0]
    names = []
    if flags & 0x08:
        stride = 34 if (flags & 0x01) else 30
        for i in range(count):
            o = 12 + i * stride
            if o + stride > payload:
                break
            names.append(buf[o + 2:o + 30].split(b"\x00")[0].decode("latin-1"))
    chunks = []
    o = payload
    while o < len(buf):
        if buf[o:o + 4] != b"PVRT":
            raise ValueError("chain broke at %d: %r" % (o, bytes(buf[o:o + 8])))
        dl = struct.unpack_from("<I", buf, o + 4)[0]
        pf, df = buf[o + 8], buf[o + 9]
        w = struct.unpack_from("<H", buf, o + 12)[0]
        h = struct.unpack_from("<H", buf, o + 14)[0]
        chunks.append(dict(off=o, length=dl, pf=pf, df=df, w=w, h=h,
                           data=(o + 16, dl - 8)))
        o += 8 + dl
    if o != len(buf):
        raise ValueError("last chunk ends at %d of %d" % (o, len(buf)))
    return dict(payload=payload, flags=flags, count=count, names=names), chunks


def walk(root):
    for dirpath, _dirs, files in os.walk(root):
        for f in sorted(files):
            if f.upper().endswith(".PRS"):
                yield os.path.join(dirpath, f)


def cmd_validate(root):
    files = sorted(walk(root))
    pvm = other = 0
    chain_ok = count_ok = end_ok = 0
    textures = 0
    fails = []
    othertags = {}
    for p in files:
        buf, _ = decompress(open(p, "rb").read())
        if buf[:4] != b"PVMH":
            other += 1
            othertags[bytes(buf[:4])] = othertags.get(bytes(buf[:4]), 0) + 1
            continue
        pvm += 1
        try:
            hdr, chunks = parse(buf)
        except ValueError as e:
            fails.append((os.path.basename(p), str(e)))
            continue
        chain_ok += 1
        end_ok += 1                      # parse() raises unless it ends exactly
        if len(chunks) == hdr["count"]:
            count_ok += 1
        else:
            fails.append((os.path.basename(p),
                          "header declares %d entries, chain walked %d"
                          % (hdr["count"], len(chunks))))
        textures += len(chunks)
    print("=== pvm.py --validate over %s ===" % root)
    print(".PRS files                              : %d" % len(files))
    print("decompress to a PVMH                    : %d" % pvm)
    print("decompress to something else            : %d" % other)
    for t, c in sorted(othertags.items(), key=lambda kv: -kv[1])[:12]:
        print("     %-18r %5d" % (t, c))
    print()
    print("of the %d PVMH archives:" % pvm)
    print("  chain of PVRT chunks is unbroken      : %d" % chain_ok)
    print("  last chunk ends exactly at end of buf : %d" % end_ok)
    print("  chunk count == header's entry count   : %d" % count_ok)
    print("  textures walked                       : %d" % textures)
    if fails:
        print()
        print("THE FAILURES, BY NAME:")
        for nm, why in fails:
            print("  %-30s %s" % (nm, why))
    return 0 if not fails else 1


def bits_per_texel(pf, df):
    if df in (0x05, 0x06):
        return 4
    if df in (0x07, 0x08):
        return 8
    return 16


def expected_bytes(c):
    """Bytes the texture data should occupy, or None when the rule is unstated."""
    w, h, df = c["w"], c["h"], c["df"]
    n = w * h
    if df in (0x03, 0x04, 0x10, 0x11):            # VQ: codebook + 1 index / 2x2
        book = 2048 if df in (0x03, 0x04) else None
        if book is None:
            return None
        return book + (n // 4)
    bpt = bits_per_texel(c["pf"], df)
    base = n * bpt // 8
    if df in (0x02, 0x06, 0x08, 0x04, 0x11):      # mipmapped: 1 + 1/4 + 1/16...
        return None
    return base


def cmd_geometry(root):
    files = sorted(walk(root))
    fmt = {}
    close = 0
    total = 0
    unstated = 0
    misses = {}
    for p in files:
        buf, _ = decompress(open(p, "rb").read())
        if buf[:4] != b"PVMH":
            continue
        try:
            _hdr, chunks = parse(buf)
        except ValueError:
            continue
        for c in chunks:
            total += 1
            key = (c["pf"], c["df"])
            fmt[key] = fmt.get(key, 0) + 1
            exp = expected_bytes(c)
            got = c["length"] - 8            # chunk length minus pf/df/w/h
            if exp is None:
                unstated += 1
            elif exp == got:
                close += 1
            else:
                misses[key] = misses.get(key, 0) + 1
    print("=== pvm.py --geometry over %s ===" % root)
    print("textures                                  : %d" % total)
    print("w * h * bpt / 8 == chunk payload          : %d" % close)
    print("rule not stated here (mipmaps, small VQ)  : %d" % unstated)
    print("stated rule and it does NOT close         : %d" % (total - close - unstated))
    print()
    print("%-10s %-24s %8s %8s" % ("pixel", "data format", "count", "misses"))
    for (pf, df), c in sorted(fmt.items(), key=lambda kv: -kv[1]):
        print("%-10s %-24s %8d %8d" % (
            PIXEL_FORMAT.get(pf, "0x%02x" % pf),
            DATA_FORMAT.get(df, "0x%02x" % df), c, misses.get((pf, df), 0)))
    return 0


def cmd_list(path):
    buf, _ = decompress(open(path, "rb").read())
    hdr, chunks = parse(buf)
    print("%s -> %d bytes, flags 0x%04x, %d entries, payload at %d"
          % (os.path.basename(path), len(buf), hdr["flags"],
             hdr["count"], hdr["payload"]))
    for i, c in enumerate(chunks):
        nm = hdr["names"][i] if i < len(hdr["names"]) else ""
        print("  %3d  %-22s %5dx%-5d %-10s %-22s %8d bytes"
              % (i, nm, c["w"], c["h"],
                 PIXEL_FORMAT.get(c["pf"], "0x%02x" % c["pf"]),
                 DATA_FORMAT.get(c["df"], "0x%02x" % c["df"]), c["length"]))
    return 0


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if len(argv) < 3:
        raise SystemExit(__doc__)
    if argv[1] == "--validate":
        return cmd_validate(argv[2])
    if argv[1] == "--geometry":
        return cmd_geometry(argv[2])
    if argv[1] == "--list":
        return cmd_list(argv[2])
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
