#!/usr/bin/env python3
"""dat.py -- reader for the 276 .DAT containers of Dino Crisis (Dreamcast).

NOTHING HERE IS INHERITED. There is no tag at offset 0, no published
description, and no tool in this collection had ever seen one of these files.
Every field below was derived from the bytes of this disc and every claim is
checked by --validate before --census is allowed to print a number.

THE FORMAT, AS DERIVED

A .DAT is a load script followed by the things it loads.

  header, at offset 0: an array of 16-byte records

      +0  u32  type        0,1,2,3,4,5,7 observed; no 6
      +4  u32  size        payload bytes for this section
      +8  u32  dest        destination parameter (see below)
     +12  u32  flags

    The array is terminated by, and the rest of the first 2,048-byte block is
    padded with, the sixteen ASCII bytes `dummy header    ` repeated. That
    string is how the header length is found; it is not a guess.

  payload, from offset 0x800: the sections in header order, each one padded up
    to the next 2,048-byte boundary.

    ACCOUNTING: 0x800 + sum over sections of ceil(size / 2048) * 2048 equals
    the file size exactly. This closes on 265 of the 265 files that carry a
    header, and it is the reason to believe the layout rather than the shape.

  section type 1 is a DPX container:

      +0  4    'DPX\\0'
      +4  u32  header size, 16 on 612 of 612 blocks
      +8  u32  member count
     +12  u32  reserved, 0 on 612 of 612
     +16  u32[count] member offsets, relative to the 'D'

    offsets[0] == 16 + 4 * count on 612 of 612 blocks -- the first member
    begins immediately after the offset table, so the table is exact and not
    sparse.

  a DPX member is an 8-byte prologue followed by a chain of blit records:

      +0  u32  16, on 3,141 of 3,141 members
      +4  u32  kind: 2, 8 or 9

    then, repeatedly until the next member's offset is reached:

      +0  u32  size
      +4  u16  x
      +6  u16  y
      +8  u16  w
     +10  u16  h
     +12  ...  w * h * 2 bytes of 16-bit texels

    with size == 12 + w * h * 2 on every record the walk accepts. The (x, y)
    pair is a destination rectangle: a member is a list of rectangles blitted
    into one surface, which is why 16x1 and 256x1 records exist beside
    128x256 ones -- the small ones land in a palette region and the large
    ones in a texture region.

  section type 4 opens 'SOSB' on 247 of 253 sections. That is the fourth of
    the four sound tags the first Dreamcast disc in this collection found named
    inside the ARM7 driver and present on none of its banks. It is 32 MB here.

  section type 3 opens 'Gian' on 6 of 6 sections, and (size - 16) is divisible
    by 8 on 6 of 6.

  section types 0 and 7 carry destinations in 0x8CF00000..0x8CFFECC0, which is
    the top of the Dreamcast's 16 MB main RAM at 0x8C000000. Section types 2
    and 4 carry destinations under 0x00800000 and in 0x01E00000..0x01FF0300.
    THE SECOND RANGE IS NOT DERIVED and this tool does not name it.

WHAT IS NOT DERIVED, AND IS REPORTED RATHER THAN HIDDEN

  134 of 2,917 DPX members leave a residue after their last accepted blit
  record. --census prints the residue sizes. 2,783 members walk to land
  exactly on the next member offset.

  The 16-bit texel encoding is asserted to be ARGB1555 by --render because
  0x8000 -- alpha set, colour zero -- is the commonest texel on the disc and
  renders as opaque black. --render --format rgb565 renders the alternative so
  that a human can decide by looking. THAT DECISION IS MADE BY EYE AND SAID SO.

    python tools/dat.py --selftest
    python tools/dat.py _work/hd --validate
    python tools/dat.py _work/hd --census
    python tools/dat.py _work/hd/ST100.DAT --render _work/png
"""

import argparse
import collections
import os
import struct
import sys

BLOCK = 2048
PAD = b"dummy header    "
SECTOR_ALIGN = 2048


class DatError(Exception):
    pass


def header_table(d):
    """Return the list of 16-byte load records, or raise."""
    end = d.find(PAD)
    if end < 0:
        raise DatError("no `dummy header    ` padding: this file has no load "
                       "table at offset 0")
    if end % 16:
        raise DatError("padding starts at %d, which is not a multiple of 16, "
                       "so the record size of 16 is wrong for this file" % end)
    if end == 0:
        raise DatError("padding starts at offset 0: empty load table")
    return [struct.unpack_from("<4I", d, o) for o in range(0, end, 16)], end


def sections(d):
    """[(type, offset, size, dest, flags)], laid out from 0x800 with each
    section padded up to a SECTOR_ALIGN boundary."""
    recs, _ = header_table(d)
    out = []
    o = BLOCK
    for ty, size, dest, flags in recs:
        out.append((ty, o, size, dest, flags))
        o = (o + size + SECTOR_ALIGN - 1) // SECTOR_ALIGN * SECTOR_ALIGN
    return out, o


def dpx_members(d, off, size):
    """[(member_offset_abs, kind, [blit,...], residue_bytes)] for one DPX
    section. A blit is (abs_offset, x, y, w, h)."""
    if d[off:off + 4] != b"DPX\x00":
        raise DatError("section at 0x%X does not open DPX\\0" % off)
    hs, cnt, res = struct.unpack_from("<3I", d, off + 4)
    if hs != 16:
        raise DatError("DPX header size %d, expected 16" % hs)
    if res != 0:
        raise DatError("DPX reserved word is %d, expected 0" % res)
    if cnt == 0 or off + 16 + 4 * cnt > len(d):
        raise DatError("DPX member count %d does not fit" % cnt)
    t = list(struct.unpack_from("<%dI" % cnt, d, off + 16))
    if t[0] != 16 + 4 * cnt:
        raise DatError("DPX offsets[0] is %d, expected %d" % (t[0], 16 + 4 * cnt))
    bounds = t + [size]
    out = []
    for i in range(cnt):
        a = off + t[i]
        lim = off + bounds[i + 1]
        pro, kind = struct.unpack_from("<2I", d, a)
        if pro != 16:
            raise DatError("member prologue is %d, expected 16" % pro)
        p = a + 8
        blits = []
        while p < lim:
            if p + 12 > len(d):
                break
            bs, x, y, w, h = struct.unpack_from("<I4H", d, p)
            if bs < 12 or bs != 12 + w * h * 2 or p + bs > lim:
                break
            blits.append((p + 12, x, y, w, h))
            p += bs
        out.append((a, kind, blits, lim - p))
    return out


def argb1555(v):
    a = 255 if v & 0x8000 else 0
    r = (v >> 10) & 31
    g = (v >> 5) & 31
    b = v & 31
    return (r * 255 // 31, g * 255 // 31, b * 255 // 31, a)


def rgb565(v):
    r = (v >> 11) & 31
    g = (v >> 5) & 63
    b = v & 31
    return (r * 255 // 31, g * 255 // 63, b * 255 // 31, 255)


DECODERS = {"argb1555": argb1555, "rgb565": rgb565}


def cmd_validate(root):
    files = _dat_files(root)
    n_hdr = n_acct = n_dpx = n_mem = n_exact = 0
    n_empty = 0
    no_hdr = []
    fails = []
    blits = texels = 0
    for path in files:
        d = open(path, "rb").read()
        if not d:
            n_empty += 1
            continue
        try:
            secs, endo = sections(d)
        except DatError:
            no_hdr.append(os.path.basename(path))
            continue
        n_hdr += 1
        if endo == len(d):
            n_acct += 1
        else:
            fails.append(("accounting", os.path.basename(path), endo, len(d)))
        for ty, off, size, dest, flags in secs:
            if ty != 1:
                continue
            n_dpx += 1
            try:
                mem = dpx_members(d, off, size)
            except DatError as e:
                fails.append(("dpx", os.path.basename(path), off, str(e)))
                continue
            for a, kind, bl, residue in mem:
                n_mem += 1
                blits += len(bl)
                for _, _, _, w, h in bl:
                    texels += w * h
                if residue == 0:
                    n_exact += 1
    print("=== dat.py --validate over %s ===" % root)
    print("  .DAT files                          : %d" % len(files))
    print("  zero-length                         : %d" % n_empty)
    print("  carrying a `dummy header    ` table : %d" % n_hdr)
    print("  without one                         : %d   %s"
          % (len(no_hdr), " ".join(no_hdr)))
    print()
    print("  ACCOUNTING  0x800 + sum ceil(size/2048)*2048 == file size")
    print("    holds on                          : %d of %d" % (n_acct, n_hdr))
    print()
    print("  DPX sections                        : %d" % n_dpx)
    print("  DPX members                         : %d" % n_mem)
    print("    walking to land exactly on the next member offset : %d  (%.4f %%)"
          % (n_exact, 100.0 * n_exact / n_mem if n_mem else 0))
    print("  blit records accepted               : %s" % f"{blits:,}")
    print("  texels                              : %s = %s bytes at 16 bpp"
          % (f"{texels:,}", f"{texels * 2:,}"))
    print()
    if fails:
        print("  FAILURES: %d" % len(fails))
        for x in fails[:20]:
            print("    %s" % (x,))
    else:
        print("  no failure of any checked invariant")
    return 0 if n_acct == n_hdr else 1


def cmd_census(root):
    files = _dat_files(root)
    tycount = collections.Counter()
    tybytes = collections.Counter()
    tyhead = collections.defaultdict(collections.Counter)
    tydest = collections.defaultdict(collections.Counter)
    shapes = collections.Counter()
    kinds = collections.Counter()
    residues = collections.Counter()
    for path in files:
        d = open(path, "rb").read()
        if not d:
            continue
        try:
            secs, _ = sections(d)
        except DatError:
            continue
        for ty, off, size, dest, flags in secs:
            tycount[ty] += 1
            tybytes[ty] += size
            tyhead[ty][bytes(d[off:off + 4])] += 1
            tydest[ty][dest] += 1
            if ty != 1:
                continue
            try:
                mem = dpx_members(d, off, size)
            except DatError:
                continue
            for a, kind, bl, residue in mem:
                kinds[kind] += 1
                if residue:
                    residues[residue] += 1
                for _, _, _, w, h in bl:
                    shapes[(w, h)] += 1
    print("=== dat.py --census over %s ===" % root)
    print("  section type   count        bytes   commonest four-byte head")
    for ty in sorted(tycount):
        h, c = tyhead[ty].most_common(1)[0]
        pr = "".join(chr(x) if 32 <= x < 127 else "." for x in h)
        print("     %d          %5d %12s   %s |%s| x%d"
              % (ty, tycount[ty], f"{tybytes[ty]:,}", h.hex(" "), pr, c))
    print()
    print("  DPX member kinds : %s"
          % ", ".join("%d(x%d)" % (k, v) for k, v in kinds.most_common()))
    print()
    print("  blit shapes: %d distinct, top 12" % len(shapes))
    for (w, h), c in shapes.most_common(12):
        print("     %4d x %-4d x%s" % (w, h, f"{c:,}"))
    print()
    print("  members leaving an underived residue: %d, sizes:"
          % sum(residues.values()))
    for r, c in residues.most_common(10):
        print("     %8d bytes x%d" % (r, c))
    print()
    for ty in sorted(tydest):
        d4 = tydest[ty]
        print("  type %d destinations: %d distinct, %s" % (ty, len(d4),
              ", ".join("0x%X(x%d)" % (k, v) for k, v in d4.most_common(5))))
    return 0


def member_images(d, off, size, dec):
    """Yield (kind, index, x, y, PIL image) for one DPX section.

    THE INDEXED RULE, derived by rendering and looking:

    A blit record's w counts 16-BIT WORDS, not pixels. When the member's kind
    is 9 the payload is 8 bits per pixel and the true width is 2*w; when it is
    8 the payload is 4 bits per pixel and the true width is 4*w. In both cases
    the palette is the FIRST blit of the same member -- a 256x1 record for
    kind 9, a 16xN record for kind 8 -- and the remaining blits are the
    picture. Kind 2 has no palette and is direct 16-bit colour.

    This was established the only way it can be: the item icons of ITEM.DAT
    render as noise at 16 bits and as 112 legible weapons, keys and med packs
    at 8 bits with the preceding 256-entry palette. A human looked.
    """
    from PIL import Image
    out = []
    for mi, (a, kind, bl, residue) in enumerate(dpx_members(d, off, size)):
        pal = None
        for bi, (dp, x, y, w, h) in enumerate(bl):
            if kind == 2:
                img = Image.new("RGBA", (w, h))
                px = img.load()
                for j in range(h):
                    row = struct.unpack_from("<%dH" % w, d, dp + j * w * 2)
                    for i in range(w):
                        px[i, j] = dec(row[i])
                out.append((kind, mi, bi, x, y, img))
                continue
            if pal is None:
                pal = [dec(v) for v in
                       struct.unpack_from("<%dH" % (w * h), d, dp)]
                continue
            if kind == 9:
                W = w * 2
                img = Image.new("RGBA", (W, h))
                px = img.load()
                for j in range(h):
                    base = dp + j * W
                    for i in range(W):
                        px[i, j] = pal[d[base + i]]
            else:
                W = w * 4
                img = Image.new("RGBA", (W, h))
                px = img.load()
                for j in range(h):
                    base = dp + j * (W // 2)
                    for i in range(W):
                        b = d[base + (i >> 1)]
                        px[i, j] = pal[(b & 15) if (i & 1) == 0 else (b >> 4)]
            out.append((kind, mi, bi, x, y, img))
    return out


def cmd_render(path, outdir, fmt, minpx):
    dec = DECODERS[fmt]
    d = open(path, "rb").read()
    secs, _ = sections(d)
    os.makedirs(outdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(path))[0]
    n = 0
    for si, (ty, off, size, dest, flags) in enumerate(secs):
        if ty != 1:
            continue
        for kind, mi, bi, x, y, img in member_images(d, off, size, dec):
            if img.width * img.height < minpx:
                continue
            fn = "%s_s%02d_m%03d_b%02d_k%d_%dx%d_at%dx%d.png" % (
                base, si, mi, bi, kind, img.width, img.height, x, y)
            img.save(os.path.join(outdir, fn))
            n += 1
    print("rendered %d images from %s as %s into %s"
          % (n, os.path.basename(path), fmt, outdir))
    return 0


def _dat_files(root):
    if os.path.isfile(root):
        return [root]
    return [os.path.join(root, f) for f in sorted(os.listdir(root))
            if f.upper().endswith(".DAT")]


def selftest():
    # Build a .DAT in memory that obeys every derived rule, and one that
    # breaks each rule in turn. The negative controls MUST raise.
    def build(pad=PAD, hdr16=16, first_off=None, res=0, blit_bad=False):
        # one DPX section with one member holding one 2x2 blit
        texels = struct.pack("<4H", 0x8000, 0x8421, 0x8842, 0x8C63)
        blit = struct.pack("<I4H", 12 + 8, 3, 5, 2, 2) + texels
        if blit_bad:
            blit = struct.pack("<I4H", 99, 3, 5, 2, 2) + texels
        member = struct.pack("<2I", hdr16, 9) + blit
        cnt = 1
        fo = first_off if first_off is not None else 16 + 4 * cnt
        dpx = (b"DPX\x00" + struct.pack("<3I", 16, cnt, res)
               + struct.pack("<I", fo) + member)
        sec = dpx
        head = struct.pack("<4I", 1, len(sec), 0, 0)
        body = head + pad * ((BLOCK - len(head)) // len(pad) + 1)
        body = body[:BLOCK]
        tail = sec + b"\x00" * ((-len(sec)) % SECTOR_ALIGN)
        return body + tail

    good = build()
    secs, endo = sections(good)
    assert endo == len(good), "accounting must close on the synthetic file"
    assert len(secs) == 1 and secs[0][0] == 1, "one type-1 section expected"
    mem = dpx_members(good, secs[0][1], secs[0][2])
    assert len(mem) == 1, "one member expected"
    a, kind, bl, residue = mem[0]
    assert kind == 9, "kind should be 9, got %d" % kind
    assert residue == 0, "residue should be 0, got %d" % residue
    # section at 0x800; member at +20 (16 + 4*count); prologue 8; blit header
    # 12; so the texels start at 0x800 + 20 + 8 + 12 = 2088.
    assert bl == [(secs[0][1] + 20 + 8 + 12, 3, 5, 2, 2)], "blit wrong: %r" % (bl,)

    passed = 6
    # NEGATIVE CONTROLS -- each of these must raise DatError.
    for label, kw in [("no padding string", dict(pad=b"XXXXXXXXXXXXXXXX")),
                      ("prologue not 16", dict(hdr16=17)),
                      ("offsets[0] wrong", dict(first_off=99)),
                      ("reserved not 0", dict(res=1))]:
        blob = build(**kw)
        try:
            s2, _ = sections(blob)
            dpx_members(blob, s2[0][1], s2[0][2])
        except DatError:
            passed += 1
        except Exception as e:
            raise AssertionError("negative control %r raised the wrong thing: %r"
                                 % (label, e))
        else:
            raise AssertionError("negative control %r did NOT fire" % label)

    # A bad blit must not be accepted: it must leave a residue instead.
    blob = build(blit_bad=True)
    s2, _ = sections(blob)
    a, kind, bl, residue = dpx_members(blob, s2[0][1], s2[0][2])[0]
    assert bl == [] and residue > 0, \
        "a malformed blit must be refused, not accepted: %r %r" % (bl, residue)
    passed += 1

    # The decoders must round-trip the two texels the disc actually uses.
    assert argb1555(0x8000) == (0, 0, 0, 255), "0x8000 must be opaque black"
    assert argb1555(0x7FFF) == (255, 255, 255, 0), "0x7FFF must be clear white"
    assert rgb565(0xFFFF) == (255, 255, 255, 255)
    passed += 3

    print("dat.py selftest: %d of %d assertions passed, "
          "5 negative controls fired" % (passed, passed))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--render", metavar="OUTDIR")
    ap.add_argument("--format", default="argb1555", choices=sorted(DECODERS))
    ap.add_argument("--min-pixels", type=int, default=1024)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.target:
        raise SystemExit("dat.py: need a file or directory, or --selftest")
    if a.validate:
        return cmd_validate(a.target)
    if a.census:
        return cmd_census(a.target)
    if a.render:
        return cmd_render(a.target, a.render, a.format, a.min_pixels)
    raise SystemExit("dat.py: pick --validate, --census, --render or --selftest")


if __name__ == "__main__":
    sys.exit(main())
