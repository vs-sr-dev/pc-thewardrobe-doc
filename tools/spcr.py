#!/usr/bin/env python3
"""spcr.py -- an FSAS `SPCR` archive (LOST HORIZON, Fusionsphere Systems,
2010): the head, the closure of its three tables, a WALK of the payloads by
magic that needs no directory, and the cheap tests on the directory it
cannot read.

What is read out of the bytes, and what is not
-----------------------------------------------

    +0   "SPCR"
    +4   u32  0
    +8   u32  a word (223, 115, 83, 251, 211 on the six seen)
    +12  u32  0
    +16  u32  0
    +20  3 x (u32 count, u32 offset, u32 size)     three TABLES at the end
    +56  the payloads, one after another, to the first table

THE CLOSURE (free): the three tables tile each other and end at the last
byte, 6 of 6. THE LOCK: the tables are 7.5-8.0 bits per byte -- table 1 is
52 bytes per entry on 6 of 6, table 2 is 8, table 0 is neither -- and no
cheap test opened them (`tables` mode reports each test either way). Nobody
reads the names; the routine that does is 32-bit x86 in `fsasgame.exe`, and
this box has no 32-bit disassembler.

THE WALK (`walk` mode): from +56 to the first table, each payload announces
itself by a public magic and states its own length, so the region can be
tiled without the directory:

    BIKi        Bink: u32 at +4 is the length minus 8        (bink.py)
    OggS        Ogg pages (RFC 3533) to the page flagged EOS   (oggcensus.py)
    \\x1bLuaP    Lua 5.0 chunk: read to closure, the end is the length (luac50.py)
    SLZX        FSAS LZ77 block: decoded to N, the end is the length (slzx.py)
    \\x89PNG     chunks to IEND                                 (pngcensus.py)
    DDS         124-byte header; the mip chain's size is summed
    RIFF        u32 at +4 is the length minus 8
    FF D8 FF    JPEG: marker segments by length, scan data by the stuffing
                rule, to EOI (ITU-T T.81; the walk is jpegcensus.py's)
    Granny      two 16-byte magics THAT granny2.dll CARRIES IN ITS OWN BYTES
                (at 425,440 and 425,472 of the DLL in this object -- the
                selection is a byte of the object, not a table from outside);
                u32 at +36 is the file's total size (read off the two heads
                and closed by the next magic)
    tmi0        engine's own: u32 at +4 is the length minus 12  (closes 6 of 6)
    TPD1        engine's own: u32 at +4 is a count of 24-byte records
    SSHC        engine's own: u32 at +8 is the length minus 20
    TGA         Truevision TGA 2.0: 18-byte header (type 2, 32 bpp), the
                pixels, the 495-byte extension area and the 26-byte footer
                ending `TRUEVISION-XFILE.\0` -- closes by arithmetic
    01 09 ff fe compiled Direct3D effect (D3DX, magic 0xFEFF0901; the
                engine imports d3dx9): NO length of its own is read here --
                the item is BOUNDED BY THE NEXT MAGIC, a weaker closure,
                counted apart as `bounded`
    OLE2        `D0 CF 11 E0 A1 B1 1A E1` compound document (Microsoft
                [MS-CFB]): bounded by the next magic and checked to be a
                whole number of sectors

Between two payloads the walk records a GAP -- the bytes from one end to the
next magic -- and what they are (the same byte repeated, or not). What no
magic claims is RESIDUE, listed with its first bytes. The number the walk
produces is "how much of the payload region the walk tiles", per archive.
An item that a reader refuses is counted as refused and the walk resumes at
the next magic.

    python tools/spcr.py head FILE...          the head, the tables, the closure
    python tools/spcr.py walk FILE [--tsv OUT] [--crc N]   the walk
    python tools/spcr.py tables FILE           the cheap tests, either way
    python tools/spcr.py selftest
"""
import argparse
import collections
import math
import mmap
import os
import re
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                  # noqa: E402
import luac50                                    # noqa: E402
import nameguard                                 # noqa: E402
import oggcensus                                 # noqa: E402
import slzx                                      # noqa: E402

nameguard.guard()

MAGIC = b"SPCR"
HEAD = 56
GRANNY = (bytes.fromhex("b867b0caf86db10f84728c7e5e19001e"),      # version 6
          bytes.fromhex("29de6cc0baa4532b25f5b7a5f666e2ee"))      # version 7
_STRONG = (rb"BIK[a-z]|OggS|\x1bLuaP|SLZX|\x89PNG\r\n\x1a\n|DDS |RIFF|"
           rb"\xff\xd8\xff[\xc0-\xfe]|" + re.escape(GRANNY[0]) + rb"|"
           + re.escape(GRANNY[1]) + rb"|tmi0|TPD1|SSHC|\x01\x09\xff\xfe"
           rb"|\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
# The TGA head has no signature -- `00 00 02 00` and eight zeros is twelve
# bytes that a compiled shader's padding produces 848 times in one run of
# data.spr -- so it is searched for only when the walk is looking for the
# NEXT item, never used to BOUND an item that has no length of its own.
MAGICS = re.compile(_STRONG + rb"|\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00")
STRONG = re.compile(_STRONG)


class Bad(Exception):
    pass


# ------------------------------------------------------------------ head
def head(blob, size):
    """The 56-byte head and the closure. Raises Bad."""
    if blob[:4] != MAGIC:
        raise Bad("no SPCR")
    if size < HEAD:
        raise Bad("shorter than the head")
    z0, word, z1, z2 = struct.unpack_from("<IIII", blob, 4)
    if z0 or z1 or z2:
        raise Bad("the three zero words are %d %d %d" % (z0, z1, z2))
    tables = [struct.unpack_from("<III", blob, 20 + 12 * i) for i in range(3)]
    for count, off, sz in tables:
        if off < HEAD or off + sz > size:
            raise Bad("table (%d, %d, %d) lies outside the file" % (count, off, sz))
    by_off = sorted(tables, key=lambda t: t[1])
    for a, b in zip(by_off, by_off[1:]):
        if a[1] + a[2] != b[1]:
            raise Bad("tables do not tile: %d + %d != %d" % (a[1], a[2], b[1]))
    last = by_off[-1]
    if last[1] + last[2] != size:
        raise Bad("the last table ends at %d, the file at %d" % (last[1] + last[2], size))
    return {"word": word, "tables": tables, "payload": (HEAD, by_off[0][1])}


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def cmd_head(a):
    rc = 0
    for path in a.paths:
        dirguard.want_file(path, "spcr")
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            blob = fh.read(HEAD)
        try:
            h = head(blob, size)
        except Bad as e:
            print("%s: REFUSED: %s" % (nameguard.safe(path), e))
            rc = 1
            continue
        p0, p1 = h["payload"]
        print("%s  %d bytes  word %d  payload %d..%d (%d bytes, %.4f %%)"
              % (nameguard.safe(path), size, h["word"], p0, p1, p1 - p0,
                 100.0 * (p1 - p0) / size))
        with open(path, "rb") as fh:
            for i, (count, off, sz) in enumerate(h["tables"]):
                fh.seek(off)
                t = fh.read(sz)
                per = "%.2f" % (sz / count) if count else "-"
                print("   table %d  count %6d  offset %12d  size %8d  B/entry %6s  "
                      "entropy %.3f" % (i, count, off, sz, per, entropy(t)))
        print("   closure: the three tables tile and end at the last byte")
    return rc


# ------------------------------------------------------------------ items
def _bink(m, at, end):
    if at + 44 > end:
        raise Bad("Bink head cut")
    size, frames, largest, frames2, w, h, num, den, flags, tracks = \
        struct.unpack_from("<10I", m, at + 4)
    if frames != frames2 or den == 0 or w == 0 or h == 0:
        raise Bad("Bink head does not agree with itself")
    stop = at + 8 + size
    if stop > end:
        raise Bad("Bink of %d runs past the region" % (size + 8))
    return stop, {"frames": frames, "w": w, "h": h, "fps": num / den, "tracks": tracks,
                  "sig": bytes(m[at:at + 4]).decode("latin-1")}


def _ogg(m, at, end, want_crc):
    p = at
    pages = 0
    serial0 = None
    ident = None
    vendor = None
    granule = 0
    crc_ok = crc_n = 0
    htype = 0
    while p + 27 <= end and m[p:p + 4] == b"OggS":
        ver, htype, gran, serial, seq, crc, nseg = struct.unpack_from("<BBqIIIB", m, p + 4)
        if ver != 0:
            raise Bad("Ogg page version %d" % ver)
        if serial0 is None:
            serial0 = serial
            if not htype & 2:
                raise Bad("first page is not BOS")
        elif serial != serial0:
            break                                       # another stream begins
        segs = m[p + 27:p + 27 + nseg]
        length = 27 + nseg + sum(segs)
        if p + length > end:
            raise Bad("Ogg page at %d runs past the region" % p)
        if want_crc:
            raw = bytearray(m[p:p + length])
            raw[22:26] = b"\0\0\0\0"
            crc_n += 1
            crc_ok += oggcensus.crc32_ogg(bytes(raw)) == crc
        body = m[p + 27 + nseg:p + length]
        if pages == 0 and body[:7] == b"\x01vorbis":
            _v, ch, rate = struct.unpack_from("<IBI", body, 7)
            ident = (ch, rate)
        if pages == 1 and body[:7] == b"\x03vorbis":
            vl = struct.unpack_from("<I", body, 7)[0]
            vendor = bytes(body[11:11 + vl]).decode("latin-1", "replace")
        if gran > 0:
            granule = gran
        pages += 1
        p += length
        if htype & 4:
            break                                       # EOS
    if pages == 0:
        raise Bad("no page")
    return p, {"pages": pages, "ident": ident, "vendor": vendor, "granule": granule,
               "crc_ok": crc_ok, "crc_n": crc_n, "eos": bool(htype & 4)}


def _lua(m, at, end):
    try:
        h, f, stop = luac50.undump(m, at)
    except luac50.Bad as e:
        raise Bad("Lua: %s" % e)
    if stop > end:
        raise Bad("Lua chunk runs past the region")
    n_fn, n_code, n_k, n_str = luac50.stats(f)
    return stop, {"functions": n_fn, "code": n_code, "k": n_k, "strings": n_str}


def _slzx(m, at, end):
    try:
        text, stop = slzx.decode(m, at)
    except slzx.Bad as e:
        raise Bad("SLZX: %s" % e)
    if stop > end:
        raise Bad("SLZX runs past the region")
    kind, extra = slzx.kind_of(text)
    return stop, {"n": len(text), "kind": kind,
                  "sections": extra if kind == "ini" else None}


def _png(m, at, end):
    p = at + 8
    w = h = depth = colour = None
    while True:
        if p + 8 > end:
            raise Bad("PNG chunk head runs past the region")
        ln, ctype = struct.unpack_from(">I4s", m, p)
        if ctype == b"IHDR":
            w, h, depth, colour = struct.unpack_from(">IIBB", m, p + 8)
        p += 12 + ln
        if p > end:
            raise Bad("PNG chunk runs past the region")
        if ctype == b"IEND":
            break
    if w is None:
        raise Bad("PNG without IHDR")
    return p, {"w": w, "h": h, "depth": depth, "colour": colour}


def _dds(m, at, end):
    if at + 128 > end:
        raise Bad("DDS head cut")
    size, flags, h, w, pitch, depth, mips = struct.unpack_from("<7I", m, at + 4)
    if size != 124:
        raise Bad("DDS header size %d" % size)
    pf_size, pf_flags, fourcc, bpp = struct.unpack_from("<II4sI", m, at + 76)
    mips = max(mips, 1)
    total = 0
    for i in range(mips):
        mw, mh = max(w >> i, 1), max(h >> i, 1)
        if pf_flags & 4:                                      # DDPF_FOURCC
            block = 8 if fourcc == b"DXT1" else 16
            total += max(1, (mw + 3) // 4) * max(1, (mh + 3) // 4) * block
        else:
            total += mw * mh * bpp // 8
    stop = at + 128 + total
    if stop > end:
        raise Bad("DDS of %d runs past the region" % (128 + total))
    return stop, {"w": w, "h": h, "mips": mips,
                  "fourcc": fourcc.decode("latin-1") if pf_flags & 4 else "rgb%d" % bpp}


def _riff(m, at, end):
    size = struct.unpack_from("<I", m, at + 4)[0]
    stop = at + 8 + size
    if stop > end:
        raise Bad("RIFF runs past the region")
    return stop, {"form": bytes(m[at + 8:at + 12]).decode("latin-1")}


def _jpeg(m, at, end):
    """ITU-T T.81 marker walk to EOI, as jpegcensus.walk does it, but stopping
    at EOI instead of demanding that EOI be the last byte."""
    p = at + 2
    w = h = None
    while p < end:
        if m[p] != 0xFF:
            raise Bad("JPEG: expected a marker at %d" % p)
        while p < end and m[p] == 0xFF:
            p += 1
        if p >= end:
            raise Bad("JPEG: fill bytes run to the region's end")
        mk = m[p]
        p += 1
        if mk == 0xD9:
            if w is None:
                raise Bad("JPEG without a frame header")
            return p, {"w": w, "h": h}
        if mk in (0x01,) or 0xD0 <= mk <= 0xD7:
            continue
        if p + 2 > end:
            raise Bad("JPEG: a length runs past the region")
        ln = struct.unpack_from(">H", m, p)[0]
        if ln < 2 or p + ln > end:
            raise Bad("JPEG: marker %02X declares %d bytes" % (mk, ln))
        if mk in (0xC0, 0xC1, 0xC2) and ln >= 7:
            h, w = struct.unpack_from(">HH", m, p + 3)
        p += ln
        if mk == 0xDA:
            while p < end - 1:
                if m[p] == 0xFF:
                    nxt = m[p + 1]
                    if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                        p += 2 if nxt != 0xFF else 1
                        continue
                    break
                p += 1
            else:
                raise Bad("JPEG: the scan runs to the region's end")
    raise Bad("JPEG: no EOI")


def _granny(m, at, end):
    if at + 48 > end:
        raise Bad("Granny head cut")
    hsize, hformat = struct.unpack_from("<II", m, at + 16)
    version, total, crc, sec_off, sec_n = struct.unpack_from("<IIIII", m, at + 32)
    if hformat != 0 or total < 48 or sec_n > 64:
        raise Bad("Granny head does not look like one (format %d, size %d, sections %d)"
                  % (hformat, total, sec_n))
    stop = at + total
    if stop > end:
        raise Bad("Granny of %d runs past the region" % total)
    return stop, {"version": version, "sections": sec_n, "magic": 6 if m[at:at + 16] == GRANNY[0] else 7}


def _tmi0(m, at, end):
    n = struct.unpack_from("<I", m, at + 4)[0]
    stop = at + 12 + n
    if stop > end:
        raise Bad("tmi0 runs past the region")
    return stop, {"n": n}


def _tpd1(m, at, end):
    n = struct.unpack_from("<I", m, at + 4)[0]
    stop = at + 8 + 24 * n
    if stop > end:
        raise Bad("TPD1 runs past the region")
    return stop, {"records": n}


def _sshc(m, at, end):
    n = struct.unpack_from("<I", m, at + 8)[0]
    stop = at + 20 + n
    if stop > end:
        raise Bad("SSHC runs past the region")
    return stop, {"n": n}


def _tga(m, at, end):
    idlen, cmap, itype = m[at], m[at + 1], m[at + 2]
    w, h, bpp, desc = struct.unpack_from("<HHBB", m, at + 12)
    if itype != 2 or cmap != 0 or bpp not in (24, 32) or w == 0 or h == 0:
        raise Bad("TGA head is not an uncompressed truecolour one")
    p = at + 18 + idlen + w * h * (bpp // 8)
    if p > end:
        raise Bad("TGA pixels run past the region")
    # TGA 2.0: optional 495-byte extension area, then the 26-byte footer
    foot = None
    for extra in (495 + 26, 26):
        if p + extra <= end and m[p + extra - 18:p + extra] == b"TRUEVISION-XFILE.\x00":
            foot = extra
            break
    if foot is None:
        raise Bad("TGA without the 2.0 footer (a 1.0 file would have no length of its own)")
    return p + foot, {"w": w, "h": h, "bpp": bpp, "ext": foot == 521}


def _bounded(kind):
    def reader(m, at, end):
        return None, {"bounded": True}
    return reader


def _ole2(m, at, end):
    shift = struct.unpack_from("<H", m, at + 30)[0]
    if shift not in (9, 12):
        raise Bad("OLE2 sector shift %d" % shift)
    return None, {"bounded": True, "sector": 1 << shift}


def item_at(m, at, end, want_crc=False):
    """(kind, stop, info) for the payload whose magic stands at `at`. A stop
    of None means the reader has no length of its own and the walk bounds
    the item by the next magic."""
    four = bytes(m[at:at + 4])
    if four == b"\x01\x09\xff\xfe":
        return ("fxo",) + _bounded("fxo")(m, at, end)
    if bytes(m[at:at + 8]) == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return ("ole2",) + _ole2(m, at, end)
    if bytes(m[at:at + 12]) == b"\x00\x00\x02\x00" + bytes(8):
        return ("tga",) + _tga(m, at, end)
    if four[:3] == b"\xff\xd8\xff":
        return ("jpeg",) + _jpeg(m, at, end)
    if bytes(m[at:at + 16]) in GRANNY:
        return ("granny",) + _granny(m, at, end)
    if four == b"tmi0":
        return ("tmi0",) + _tmi0(m, at, end)
    if four == b"TPD1":
        return ("tpd1",) + _tpd1(m, at, end)
    if four == b"SSHC":
        return ("sshc",) + _sshc(m, at, end)
    if four[:3] == b"BIK":
        return ("bink",) + _bink(m, at, end)
    if four == b"OggS":
        return ("ogg",) + _ogg(m, at, end, want_crc)
    if four == b"\x1bLua":
        return ("lua",) + _lua(m, at, end)
    if four == b"SLZX":
        return ("slzx",) + _slzx(m, at, end)
    if four == b"\x89PNG":
        return ("png",) + _png(m, at, end)
    if four == b"DDS ":
        return ("dds",) + _dds(m, at, end)
    if four == b"RIFF":
        return ("riff",) + _riff(m, at, end)
    raise Bad("no reader for %r" % four)


def walk(m, p0, p1, crc_first=0, on_item=None):
    """Tile [p0, p1) by magic. Returns (items, gaps, refused, residue).
    items: (kind, at, stop, info); gaps: (at, length, same_byte or None);
    refused: (at, magic, reason); residue: (at, length, head bytes)."""
    items, gaps, refused, residue = [], [], [], []
    cur = p0                # every byte below cur is accounted for
    look = p0               # where the next magic search begins
    ogg_seen = 0
    while cur < p1:
        mo = MAGICS.search(m, look, p1)
        if mo is None:
            residue.append((cur, p1 - cur, bytes(m[cur:cur + 16])))
            break
        at = mo.start()
        want_crc = False
        if m[at:at + 4] == b"OggS":
            want_crc = ogg_seen < crc_first
            ogg_seen += 1
        try:
            kind, stop, info = item_at(m, at, p1, want_crc)
        except Bad as e:
            # a magic that does not read: its bytes stay unaccounted until
            # the next item's gap or residue swallows them
            refused.append((at, bytes(m[at:at + 4]), str(e)))
            look = at + 1
            continue
        if stop is None:
            nxt = STRONG.search(m, at + 4, p1)
            stop = nxt.start() if nxt else p1
            if kind == "ole2" and (stop - at) % info["sector"]:
                refused.append((at, bytes(m[at:at + 4]),
                                "OLE2 bounded at %d bytes, not a whole number of sectors" % (stop - at)))
                look = at + 1
                continue
        if at > cur:
            g = bytes(m[cur:at])
            same = g[0] if len(set(g)) == 1 else None
            if len(g) <= 64:
                gaps.append((cur, len(g), same))
            else:
                residue.append((cur, len(g), g[:16]))
        items.append((kind, at, stop, info))
        if on_item:
            on_item(kind, at, stop, info)
        cur = look = stop
    return items, gaps, refused, residue


def cmd_walk(a):
    path = a.paths[0]
    dirguard.want_file(path, "spcr")
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        try:
            h = head(fh.read(HEAD), size)
        except Bad as e:
            sys.exit("spcr: %s: %s" % (nameguard.safe(path), e))
        m = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        p0, p1 = h["payload"]
        tsv = open(a.tsv, "w", encoding="utf-8") if a.tsv else None
        if tsv:
            tsv.write("kind\tat\tlength\tinfo\n")

        def on_item(kind, at, stop, info):
            if tsv:
                tsv.write("%s\t%d\t%d\t%s\n" % (kind, at, stop - at, _info_str(kind, info)))
        items, gaps, refused, residue = walk(m, p0, p1, a.crc, on_item)
        if tsv:
            for at, ln, same in gaps:
                tsv.write("gap\t%d\t%d\t%s\n" % (at, ln, "same 0x%02X" % same if same is not None else "mixed"))
            for at, ln, hd in residue:
                tsv.write("residue\t%d\t%d\t%s\n" % (at, ln, hd.hex()))
            for at, mg, why in refused:
                tsv.write("refused\t%d\t4\t%r %s\n" % (at, mg, why))
            tsv.close()
        report_walk(path, size, h, items, gaps, refused, residue)
        m.close()
    return 0


def _info_str(kind, info):
    if kind == "bink":
        return "%s %d frames %dx%d %.3f fps %d audio" % (info["sig"], info["frames"], info["w"], info["h"], info["fps"], info["tracks"])
    if kind == "ogg":
        ch, rate = info["ident"] or (0, 0)
        secs = info["granule"] / rate if rate else 0
        return "%d pages %dch %dHz %.2fs vendor=%s eos=%s" % (info["pages"], ch, rate, secs, info["vendor"], info["eos"])
    if kind == "lua":
        return "fn %d code %d k %d str %d" % (info["functions"], info["code"], info["k"], info["strings"])
    if kind == "slzx":
        return "n %d %s %s" % (info["n"], info["kind"], ",".join(info["sections"] or [])[:80])
    if kind == "png":
        return "%dx%d depth %d colour %d" % (info["w"], info["h"], info["depth"], info["colour"])
    if kind == "dds":
        return "%dx%d %s mips %d" % (info["w"], info["h"], info["fourcc"], info["mips"])
    if kind == "riff":
        return info["form"]
    if kind == "jpeg":
        return "%dx%d" % (info["w"], info["h"])
    if kind == "granny":
        return "version %d magic v%d sections %d" % (info["version"], info["magic"], info["sections"])
    if kind in ("tmi0", "sshc"):
        return "n %d" % info["n"]
    if kind == "tga":
        return "%dx%d %dbpp ext=%s" % (info["w"], info["h"], info["bpp"], info["ext"])
    if kind in ("fxo", "ole2"):
        return "bounded by the next magic"
    if kind == "tpd1":
        return "records %d" % info["records"]
    return ""


def report_walk(path, size, h, items, gaps, refused, residue):
    p0, p1 = h["payload"]
    region = p1 - p0
    print("%s: %d bytes; payload region %d..%d = %d bytes (%.4f %% of the file)"
          % (nameguard.safe(path), size, p0, p1, region, 100.0 * region / size))
    print("tables: %s (%d entries in table 1)" % (h["tables"], h["tables"][1][0]))
    print()
    by = collections.OrderedDict()
    for kind, at, stop, info in items:
        c, b = by.get(kind, (0, 0))
        by[kind] = (c + 1, b + stop - at)
    tiled = sum(b for c, b in by.values())
    gap_b = sum(g[1] for g in gaps)
    res_b = sum(r[1] for r in residue)
    print("  %-8s %7s %14s %10s" % ("kind", "items", "bytes", "share"))
    for kind, (c, b) in sorted(by.items(), key=lambda kv: -kv[1][1]):
        print("  %-8s %7d %14d %9.4f %%" % (kind, c, b, 100.0 * b / region))
    print("  %-8s %7d %14d %9.4f %%   (<= 64 bytes between two payloads)" % ("gaps", len(gaps), gap_b, 100.0 * gap_b / region))
    print("  %-8s %7d %14d %9.4f %%   (no magic claims them)" % ("residue", len(residue), res_b, 100.0 * res_b / region))
    print("  %-8s %7d" % ("refused", len(refused)))
    bounded = [(k, a, s) for k, a, s, i in items if i.get("bounded")]
    if bounded:
        print("  of the payloads, %d are BOUNDED BY THE NEXT MAGIC and not by a length of "
              "their own (%d bytes): %s" % (len(bounded), sum(s - a for _, a, s in bounded),
                                           dict(collections.Counter(k for k, _, _ in bounded))))
    print("  tiled by payloads %d + gaps %d + residue %d = %d of %d  -> RESIDUE %d"
          % (tiled, gap_b, res_b, tiled + gap_b + res_b, region, region - tiled - gap_b - res_b))
    print("  payloads alone tile %.4f %% of the region" % (100.0 * tiled / region))
    if gaps:
        same = collections.Counter(("same" if g[2] is not None else "mixed") for g in gaps)
        lens = collections.Counter(g[1] for g in gaps)
        print("  gaps: %s; lengths %s" % (dict(same), sorted(lens.items())[:12]))
        al = collections.Counter()
        for kind, at, stop, info in items:
            for k in (4, 8, 16, 32):
                if at % k == 0:
                    al[k] += 1
        print("  payload starts aligned to 4/8/16/32: %s of %d" % ([al[k] for k in (4, 8, 16, 32)], len(items)))
    # per kind
    for kind in by:
        rows = [(at, stop, info) for k, at, stop, info in items if k == kind]
        if kind == "bink":
            frames = sum(i["frames"] for _, _, i in rows)
            secs = sum(i["frames"] / i["fps"] for _, _, i in rows if i["fps"])
            geo = collections.Counter("%dx%d @%.3g" % (i["w"], i["h"], i["fps"]) for _, _, i in rows)
            print("  bink: %d frames, %.1f s = %.1f min; audio tracks %s; geometries %s"
                  % (frames, secs, secs / 60, dict(collections.Counter(i["tracks"] for _, _, i in rows)),
                     geo.most_common(6)))
        elif kind == "ogg":
            pages = sum(i["pages"] for _, _, i in rows)
            secs = sum(i["granule"] / i["ident"][1] for _, _, i in rows if i["ident"] and i["ident"][1])
            idents = collections.Counter(i["ident"] for _, _, i in rows)
            vend = collections.Counter(i["vendor"] for _, _, i in rows)
            eos = sum(1 for _, _, i in rows if i["eos"])
            crc_n = sum(i["crc_n"] for _, _, i in rows)
            crc_ok = sum(i["crc_ok"] for _, _, i in rows)
            print("  ogg: %d pages, %d streams end with EOS of %d, %.1f s = %.1f min by granule; "
                  "(channels, rate) %s; vendors %s; CRC %d of %d pages checked on the first %d streams"
                  % (pages, eos, len(rows), secs, secs / 60, dict(idents), dict(vend), crc_ok, crc_n,
                     sum(1 for _, _, i in rows if i["crc_n"])))
        elif kind == "lua":
            fn = sum(i["functions"] for _, _, i in rows)
            code = sum(i["code"] for _, _, i in rows)
            k = sum(i["k"] for _, _, i in rows)
            s = sum(i["strings"] for _, _, i in rows)
            print("  lua: %d functions, %d instructions, %d constants (%d strings)" % (fn, code, k, s))
        elif kind == "slzx":
            kinds = collections.Counter(i["kind"] for _, _, i in rows)
            n = sum(i["n"] for _, _, i in rows)
            print("  slzx: decoded %d bytes; kinds %s" % (n, dict(kinds)))
        elif kind == "png":
            geo = collections.Counter("%dx%d" % (i["w"], i["h"]) for _, _, i in rows)
            col = collections.Counter("depth %d colour %d" % (i["depth"], i["colour"]) for _, _, i in rows)
            print("  png: %s; geometries %d distinct, top %s" % (dict(col), len(geo), geo.most_common(8)))
        elif kind == "dds":
            print("  dds: %s" % [(_info_str("dds", i)) for _, _, i in rows])
        elif kind == "riff":
            print("  riff: %s" % dict(collections.Counter(i["form"] for _, _, i in rows)))
        elif kind == "jpeg":
            geo = collections.Counter("%dx%d" % (i["w"], i["h"]) for _, _, i in rows)
            print("  jpeg: geometries %d distinct, top %s" % (len(geo), geo.most_common(8)))
        elif kind == "granny":
            print("  granny: versions %s; magics %s; sections %s"
                  % (dict(collections.Counter(i["version"] for _, _, i in rows)),
                     dict(collections.Counter(i["magic"] for _, _, i in rows)),
                     dict(collections.Counter(i["sections"] for _, _, i in rows))))
    if residue:
        print("  residue runs (first 12): ")
        for at, ln, hd in residue[:12]:
            print("    at %12d  %10d bytes  %s" % (at, ln, hd.hex(" ")))
    if refused:
        print("  refused (first 12):")
        for at, mg, why in refused[:12]:
            print("    at %12d  %r  %s" % (at, mg, why))


# ------------------------------------------------------------------ tables
def cmd_tables(a):
    path = a.paths[0]
    dirguard.want_file(path, "spcr")
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        try:
            h = head(fh.read(HEAD), size)
        except Bad as e:
            sys.exit("spcr: %s: %s" % (nameguard.safe(path), e))
        tabs = []
        for count, off, sz in h["tables"]:
            fh.seek(off)
            tabs.append((count, fh.read(sz)))
    word = h["word"]
    print("%s: word %d; the cheap tests, each reported either way"
          % (nameguard.safe(path), word))
    for ti, (count, t) in enumerate(tabs):
        stride = len(t) // count if count and len(t) % count == 0 else None
        print()
        print("table %d: %d entries, %d bytes, stride %s, entropy %.4f"
              % (ti, count, len(t), stride, entropy(t)))
        # 1. inflate
        for wb, name in ((-15, "raw deflate"), (15, "zlib"), (31, "gzip")):
            try:
                out = zlib.decompress(t, wb)
                print("   inflate %-11s : OPENS -> %d bytes  (!)" % (name, len(out)))
            except zlib.error as e:
                print("   inflate %-11s : refused (%s)" % (name, str(e)[:50]))
        # 2. XOR with the head word
        for key, name in ((bytes([word & 0xFF]), "word as a byte"),
                          (struct.pack("<I", word), "word as u32")):
            x = bytes(t[i] ^ key[i % len(key)] for i in range(len(t)))
            pr = sum(1 for c in x if 32 <= c < 127) / len(x)
            print("   xor %-15s : entropy %.4f, printable %.1f %%%s"
                  % (name, entropy(x), 100 * pr, "  (!)" if pr > 0.6 else ""))
        # 3. per-column entropy at the stride (a fixed-field record under a
        #    repeating XOR shows constant columns)
        if stride:
            cols = [entropy(t[j::stride]) for j in range(stride)]
            ceiling = math.log2(count)
            # a column of n records cannot exceed log2(n) bits; a column is
            # "low" only when it sits well under that ceiling
            low = [j for j, e in enumerate(cols) if e < min(4.0, ceiling - 1.5)]
            print("   per-column entropy at stride %d: min %.3f max %.3f mean %.3f "
                  "(ceiling log2(%d) = %.3f); columns well under the ceiling: %s"
                  % (stride, min(cols), max(cols), sum(cols) / len(cols), count,
                     ceiling, low or "none"))
            recs = collections.Counter(bytes(t[i:i + stride]) for i in range(0, len(t), stride))
            print("   distinct records: %d of %d" % (len(recs), count))
        # 4. autocorrelation: equal bytes at lag k vs 1/256 expected
        best = []
        for lag in range(1, min(65, len(t) // 2)):
            eq = sum(1 for i in range(len(t) - lag) if t[i] == t[i + lag])
            best.append((eq / (len(t) - lag), lag))
        best.sort(reverse=True)
        if best:
            print("   equal-byte rate at lags 1..%d: best %s (random 0.0039)"
                  % (len(best), ", ".join("lag %d %.4f" % (l, r) for r, l in best[:3])))
        # 5. byte histogram flatness
        c = collections.Counter(t)
        print("   distinct byte values %d of 256; most common 0x%02X x%d (%.2f %%)"
              % (len(c), c.most_common(1)[0][0], c.most_common(1)[0][1],
                 100.0 * c.most_common(1)[0][1] / len(t)))
        if len(t) <= 96:
            print("   bytes: %s" % t.hex(" "))
    print()
    print("verdict: no cheap test opened a table; the directory is NOT read. The "
          "routine that reads it is 32-bit x86 in fsasgame.exe and this box has "
          "no 32-bit disassembler; writing one is not owed by this session.")
    return 0


# ------------------------------------------------------------------ selftest
def _spcr_blob(payload, t0=b"A" * 30, t1=b"B" * 104, t2=b"C" * 8, word=223):
    """A little archive: head, payload, then t0, t2, t1 (as the object lays
    them) ending at the last byte."""
    o0 = HEAD + len(payload)
    o2 = o0 + len(t0)
    o1 = o2 + len(t2)
    h = MAGIC + struct.pack("<IIII", 0, word, 0, 0)
    h += struct.pack("<III", 3, o0, len(t0))
    h += struct.pack("<III", 2, o1, len(t1))
    h += struct.pack("<III", 1, o2, len(t2))
    return h + payload + t0 + t2 + t1


def _png_blob(w=2, h=2):
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\x10\x20\x30" * w for _ in range(h))
    idat = zlib.compress(raw)

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _ogg_blob(serial=7):
    def page(body, htype, seq, gran):
        segs = bytes([len(body)])
        hdr = b"OggS" + struct.pack("<BBqIIIB", 0, htype, gran, serial, seq, 0, 1) + segs
        raw = bytearray(hdr + body)
        crc = oggcensus.crc32_ogg(bytes(raw))
        raw[22:26] = struct.pack("<I", crc)
        return bytes(raw)
    ident = b"\x01vorbis" + struct.pack("<IBIiiiBB", 0, 2, 44100, 0, 0, 0, 0xB8, 1)
    comm = b"\x03vorbis" + struct.pack("<I", 10) + b"FSASEditor" + struct.pack("<I", 0) + b"\x01"
    return page(ident, 2, 0, 0) + page(comm, 0, 1, 0) + page(b"\x00" * 10, 4, 2, 44100)


def _bink_blob(frames=3, w=64, h=32):
    body = b"\x00" * 100
    hd = b"BIKi" + struct.pack("<10I", 36 + len(body), frames, 50, frames, w, h, 25, 1, 0, 1)
    return hd + body


def cmd_selftest(_a):
    checks = []
    png = _png_blob()
    ogg = _ogg_blob()
    bink = _bink_blob()
    lua = luac50._build()
    slz = slzx._block(b"[Cursor]\r\nX=1\r\n")
    jpg = (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
           b"\xff\xc0\x00\x0b\x08\x00\x02\x00\x03\x01\x01\x11\x00"
           b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + b"\x12\xff\x00\x34" + b"\xff\xd9")
    grn = GRANNY[1] + struct.pack("<IIII", 456, 0, 0, 0) + struct.pack("<IIIII", 7, 100, 0, 48, 8) + b"\x00" * (100 - 52)
    tga = (b"\x00\x00\x02\x00" + bytes(8) + struct.pack("<HHBB", 2, 2, 32, 8) + b"\x01" * 16
           + bytes(495) + bytes(8) + b"TRUEVISION-XFILE.\x00")
    payload = bink + b"\x00" * 3 + ogg + png + lua + slz + jpg + grn + tga + b"\xAA" * 100
    blob = _spcr_blob(payload)
    h = head(blob, len(blob))
    checks.append(("a head whose tables tile to the last byte closes",
                   h["payload"] == (HEAD, HEAD + len(payload)) and h["word"] == 223, str(h)))
    checks.append(("a byte more at the end is REFUSED", _refuses(blob + b"x"), ""))
    checks.append(("a byte less is REFUSED", _refuses(blob[:-1]), ""))
    bad = bytearray(blob)
    bad[12] = 1
    checks.append(("a non-zero third word is REFUSED", _refuses(bytes(bad)), ""))
    checks.append(("'SPCR' followed by prose is REFUSED",
                   _refuses(b"SPCR is not a format" + bytes(60)), ""))
    items, gaps, refused, residue = walk(blob, HEAD, HEAD + len(payload), crc_first=1)
    kinds = [k for k, _, _, _ in items]
    checks.append(("the walk finds bink, ogg, png, lua, slzx, jpeg, granny, tga in order",
                   kinds == ["bink", "ogg", "png", "lua", "slzx", "jpeg", "granny", "tga"], str(kinds)))
    checks.append(("the TGA closes on header + pixels + extension + footer",
                   items[7][2] - items[7][1] == len(tga) and items[7][3]["ext"], str(items[7][3])))
    checks.append(("the JPEG ends at EOI, with a stuffed FF 00 in its scan, and reads 3x2",
                   items[5][2] - items[5][1] == len(jpg) and items[5][3] == {"w": 3, "h": 2}, str(items[5][3])))
    checks.append(("the Granny ends at its total size (+36) and is version 7",
                   items[6][2] - items[6][1] == 100 and items[6][3]["version"] == 7, str(items[6][3])))
    checks.append(("the Bink's length is 8 + its size field",
                   items[0][2] - items[0][1] == len(bink), ""))
    checks.append(("the Ogg stream ends at its EOS page and names its vendor",
                   items[1][2] - items[1][1] == len(ogg) and items[1][3]["vendor"] == "FSASEditor"
                   and items[1][3]["ident"] == (2, 44100) and items[1][3]["eos"], str(items[1][3])))
    checks.append(("the Ogg CRC is checked on the first stream: 3 of 3",
                   items[1][3]["crc_ok"] == 3 and items[1][3]["crc_n"] == 3, str(items[1][3])))
    checks.append(("the PNG ends at IEND", items[2][2] - items[2][1] == len(png), ""))
    checks.append(("the Lua chunk ends where luac50 closes it",
                   items[3][2] - items[3][1] == len(lua), ""))
    checks.append(("the SLZX block ends where slzx closes it",
                   items[4][2] - items[4][1] == len(slz) and items[4][3]["kind"] == "ini", ""))
    checks.append(("three zero bytes between two payloads are a GAP of the same byte",
                   gaps == [(HEAD + len(bink), 3, 0)], str(gaps)))
    checks.append(("100 bytes nothing claims are RESIDUE",
                   len(residue) == 1 and residue[0][1] == 100, str(residue)))
    tiled = sum(s - a for _, a, s, _ in items) + sum(g[1] for g in gaps) + sum(r[1] for r in residue)
    checks.append(("payloads + gaps + residue tile the region exactly",
                   tiled == len(payload), "%d of %d" % (tiled, len(payload))))
    # a false magic ('OggS' in prose) between two payloads is refused AND its
    # bytes still land in the gap
    p2 = bink + b"OggS is a word" + png
    i2, g2, r2, s2 = walk(p2, 0, len(p2))
    t2 = sum(s - a for _, a, s, _ in i2) + sum(g[1] for g in g2) + sum(r[1] for r in s2)
    checks.append(("a refused magic's bytes are still accounted for in the gap",
                   len(r2) == 1 and t2 == len(p2) and g2 == [(len(bink), 14, None)],
                   "%d of %d, gaps %s" % (t2, len(p2), g2)))
    broken = bytearray(payload)
    broken[8:12] = struct.pack("<I", 10 ** 8)           # a Bink that runs past the region
    items2, gaps2, refused2, residue2 = walk(bytes(broken), 0, len(broken))
    checks.append(("a Bink that runs past the region is REFUSED and the walk goes on",
                   len(refused2) == 1 and "ogg" in [k for k, _, _, _ in items2], str(refused2)))
    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL", note))
        failed += 0 if ok else 1
    print()
    print("%d checks, %d failures (0 skipped: the selftest builds its own archive)"
          % (len(checks), failed))
    return 1 if failed else 0


def _refuses(blob):
    try:
        head(blob, len(blob))
    except Bad:
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=("selftest", "head", "walk", "tables"))
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--tsv")
    ap.add_argument("--crc", type=int, default=0,
                    help="check the Ogg CRC on the first N streams (pure Python: slow)")
    a = ap.parse_args()
    if a.mode == "selftest":
        return cmd_selftest(a)
    if not a.paths:
        ap.error("give an archive")
    return {"head": cmd_head, "walk": cmd_walk, "tables": cmd_tables}[a.mode](a)


if __name__ == "__main__":
    sys.exit(main())
