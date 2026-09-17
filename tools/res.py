#!/usr/bin/env python3
"""res.py -- the twelve `.RES` containers of TEENAGENT (Metropolis Software
House, 1994-1995; published by Union Logic Software Publishing Inc.), read
from the bytes and from the unpacked engine, not from any published engine.

THE CONTAINER
-------------
    u32  count
    u32  offset[count + 1]     little-endian, monotonic; offset[0] must be
                               4 + 4 (count + 1) and offset[count] the file
                               length -- member i is [offset[i], offset[i+1])

Twelve files, 1,053 members, twelve closures with residue 0. No name, no
type byte, no signature: what a member IS is known only from its size, its
head, or the code that reads it, and this tool says which of the three it
is using every time it names a kind.

THE MEMBER KINDS THIS TOOL KNOWS, AND BY WHAT WARRANT
------------------------------------------------------
  screen     64,768 = 320 x 200 + 768 bytes: 64,000 8-bit pixels, row-major,
             then a 256 x RGB palette of 6-bit VGA values (every byte of the
             tail <= 63 in every one of the 53 + 1 members that have this
             size, and the head is not). Warrant: arithmetic, then the
             render. ADVERT 11 of 11, OFF 42 of 42, UNLOGIC 1 of 11.
  palette    768 bytes, every byte <= 63.   VARIA[0].
  text-mode  4,000 bytes of char/attribute pairs (80 x 25 x 2), the
             Union Logic order screen.  VARIA[?]. Warrant: size and the
             attribute bytes.
  MMM        begins `MMM`: MMM.RES 11 of 11 -- the music, format not read.
  driver     SDR.RES: 8086 code (`cmp ah,3 ; jz`) with a `(c) Adrian
             M.Chmielarz 1994` string -- the eight sound drivers.
  sprite     ONS (113 of 113) and UNLOGIC's ten: `u16 w, u16 h, u16 screen
             offset (y * 320 + x), w * h pixels`, 0FFh transparent. Warrant:
             the engine's blitter at code 1B10h (`cx=[bx]; dx=[bx+2];
             si=[bx+4]; bx+=6; ... cmp al,0FFh; jz; ... add si,140h`), and
             the arithmetic closes on every member.
  overlay    ON (42 of 42, one per room): `u8 n, u16 offset[n]` (from the
             member's start; offset[0] = 1 + 2n), then n sprites as above.
             A 1-byte member `00` is an empty slot. Warrant: the same
             blitter, called on each entry; closure on every member.
  animation  LAN_000 (168 = 42 rooms x 4 slots) and LAN_500 (492, ids 500
             and up -- the loader at 0ABA9h does `sub cx,1F3h`): `u16 L`
             (= 2 + 3 * steps), steps x (`u8 frame, u16 screen offset`),
             at L: `u8 frames, u16 off[frames]` (1-based, relative to L),
             each frame `u16 w, u16 h, w * h pixels`, 0FFh transparent.
             Warrant: the stepper at code 2D8Bh, read with dosdis.py
             (`bx = 3*step - 1; cmp bx,[0]; cl=[bx]; si=[bx+1]; bx = [0]
             - 1 + 2*cl; bx = [bx] + [0]; w=[bx]; h=[bx+2]; pixels bx+4`);
             closure on all 660 members. `00` (1 byte) is an empty slot.
  font       VARIA[6] (97 glyphs) and VARIA[7] (95): `u16 off[n]` with
             n = off[0] / 2, glyph = `u8 h, u8 w, h * w bytes` of 0 / 1 / 2
             (transparent / ink / shadow), from 20h. The small font puts
             the Polish letters on the punctuation slots (`;` = Ń, `]` = Ł
             ...): read off the render, glyph by glyph. --font N.
  text-mode  VARIA[9], VARIA[10]: 3,680 = 80 x 23 x 2 bytes of character /
             attribute pairs -- the registered and the shareware exit
             screens. --textmode N.
  MMM        MMM.RES 11 of 11: `MMM`, 06h, `u8 n`, n sample numbers in
             BCD (1..51 = SAM_MMM's 51 members, every one named by some
             song), then `Q`,`R`,`S` each with a BCD sample number from the
             song's own list, then the sequence -- NOT decoded. --mmm.
  other      SAM_* (signed 8-bit PCM, the SB DMA driver's `xor [bx],8080h`
             says so; 11,025 Hz is the constant in its time-constant
             arithmetic), VARIA[2] (a 286 x 141 sprite at (17,12): the
             inventory panel), VARIA[5] (320 x 68 raw: the TEENAGENT logo),
             VARIA[8] (a 320-wide raw strip: METROPOLIS software house),
             VARIA[4] (a palette).

    python tools/res.py FILE...                    directory and closure
    python tools/res.py FILE --list                every member: size, head
    python tools/res.py FILE --extract DIR         members as FILE.NNN
    python tools/res.py FILE --render DIR          every screen as a PNG
    python tools/res.py --census Teenagent         the twelve, one table
    python tools/res.py --selftest
"""
import argparse
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402

SCREEN = 320 * 200 + 768
W, H = 320, 200


class ResError(Exception):
    pass


def parse(blob, size=None):
    """The directory. `blob` may be a head; `size` is then the file length."""
    if size is None:
        size = len(blob)
    if len(blob) < 8:
        raise ResError("shorter than a count and one offset")
    n = struct.unpack_from("<I", blob, 0)[0]
    if n < 1 or n > 4096:
        raise ResError("count %d is not in 1..4096" % n)
    need = 4 + 4 * (n + 1)
    if len(blob) < need:
        raise ResError("directory of %d needs %d bytes, have %d"
                       % (n, need, len(blob)))
    offs = struct.unpack_from("<%dI" % (n + 1), blob, 4)
    if offs[0] != need:
        raise ResError("first offset %d != 4 + 4 (count + 1) = %d"
                       % (offs[0], need))
    for i in range(n):
        if offs[i + 1] < offs[i]:
            raise ResError("offset %d (%d) below offset %d (%d)"
                           % (i + 1, offs[i + 1], i, offs[i]))
    if offs[n] != size:
        raise ResError("last offset %d != file length %d" % (offs[n], size))
    return {"count": n, "offsets": offs, "size": size,
            "residue": size - offs[n]}


def looks_like_head(head, size=None):
    """For coverage.py: a directory that closes on the file's length."""
    try:
        parse(head, size)
        return True
    except (ResError, struct.error):
        return False


def members(blob, d):
    for i in range(d["count"]):
        yield i, blob[d["offsets"][i]:d["offsets"][i + 1]]


def is_screen(m):
    return len(m) == SCREEN and max(m[-768:]) <= 63


def is_palette(m):
    return len(m) == 768 and max(m) <= 63


def is_textmode(m):
    """80 columns x 20..25 rows of (character, attribute): every attribute
    byte's blink bit clear and at least one letter in the characters."""
    if len(m) % 160 or not 20 <= len(m) // 160 <= 25:
        return False
    letters = sum(1 for c in m[0::2] if 0x41 <= c <= 0x7A)
    return letters >= 40


def sprite(m, at=0):
    """One `w, h, offset, pixels` record at `at`; raises on overflow."""
    if at + 6 > len(m):
        raise ResError("sprite header at %d runs past %d" % (at, len(m)))
    w, h, off = struct.unpack_from("<HHH", m, at)
    end = at + 6 + w * h
    if end > len(m):
        raise ResError("sprite %dx%d at %d needs %d, member is %d"
                       % (w, h, at, end, len(m)))
    if w > W or h > H or off + (h - 1) * W + w > W * H:
        raise ResError("sprite %dx%d at screen offset %d leaves the screen"
                       % (w, h, off))
    return {"w": w, "h": h, "off": off, "x": off % W, "y": off // W,
            "pixels": m[at + 6:end], "end": end}


def parse_overlay(m):
    """ON: u8 n, u16 offset[n], n sprites; closes on the length."""
    if len(m) == 1 and m[0] == 0:
        return []
    n = m[0]
    if n == 0 or 1 + 2 * n > len(m):
        raise ResError("overlay count %d does not fit %d" % (n, len(m)))
    offs = struct.unpack_from("<%dH" % n, m, 1)
    if offs[0] != 1 + 2 * n:
        raise ResError("overlay: first offset %d != 1 + 2n = %d"
                       % (offs[0], 1 + 2 * n))
    out = []
    for i, o in enumerate(offs):
        nxt = offs[i + 1] if i + 1 < n else len(m)
        try:
            s = sprite(m, o)
        except ResError:
            # VARIA[3] (the inventory items) nests a SEQUENCE in 6 of its
            # 92 entries: u8 k, u16 off[k] into the entry, offsets repeated
            # (a cycle over fewer sprites); the distinct offsets tile the
            # entry from 1 + 2k to its end
            if o >= nxt:
                raise
            s = {"sequence": parse_sequence(m[o:nxt]), "end": nxt}
        if s["end"] != nxt:
            raise ResError("overlay entry %d ends at %d, next at %d"
                           % (i, s["end"], nxt))
        out.append(s)
    return out


def parse_sequence(m):
    """u8 k, u16 off[k] (repeats allowed), sprites tiling the rest."""
    k = m[0]
    if k == 0 or 1 + 2 * k > len(m):
        raise ResError("sequence count %d does not fit %d" % (k, len(m)))
    offs = struct.unpack_from("<%dH" % k, m, 1)
    at = 1 + 2 * k
    sprites = {}
    for o in sorted(set(offs)):
        if o != at:
            raise ResError("sequence sprite at %d, expected %d" % (o, at))
        s = sprite(m, o)
        sprites[o] = s
        at = s["end"]
    if at != len(m):
        raise ResError("sequence sprites end at %d, entry is %d"
                       % (at, len(m)))
    return {"steps": [sprites[o] for o in offs], "sprites": len(sprites)}


def parse_animation(m):
    """LAN: the stepper's grammar; closes on the length."""
    if len(m) == 1 and m[0] == 0:
        return {"steps": [], "frames": []}
    if len(m) < 3:
        raise ResError("animation of %d bytes" % len(m))
    L = struct.unpack_from("<H", m, 0)[0]
    if L < 2 or (L - 2) % 3 or L + 1 > len(m):
        raise ResError("step list length %d is not 2 + 3n inside %d"
                       % (L, len(m)))
    steps = [(m[i], struct.unpack_from("<H", m, i + 1)[0])
             for i in range(2, L, 3)]
    nf = m[L]
    if nf == 0 or L + 1 + 2 * nf > len(m):
        raise ResError("frame count %d does not fit" % nf)
    offs = struct.unpack_from("<%dH" % nf, m, L + 1)
    frames = []
    at = L + 1 + 2 * nf
    for k, o in enumerate(offs):
        if L + o != at:
            raise ResError("frame %d at L + %d = %d, expected %d (frames "
                           "must tile the member)" % (k + 1, o, L + o, at))
        if at + 4 > len(m):
            raise ResError("frame %d header at %d runs past %d"
                           % (k + 1, at, len(m)))
        w, h = struct.unpack_from("<HH", m, at)
        end = at + 4 + w * h
        if end > len(m):
            raise ResError("frame %d %dx%d at %d needs %d, member is %d"
                           % (k + 1, w, h, at, end, len(m)))
        frames.append({"w": w, "h": h, "pixels": m[at + 4:end]})
        at = end
    # LAN_500 member 11 (of 660) ends one byte (1Ah) after its last frame:
    # a residue the engine never reads. One byte is tolerated and reported;
    # more is a refusal.
    if at != len(m) and at + 1 != len(m):
        raise ResError("frames end at %d, member is %d" % (at, len(m)))
    for i, (f, off) in enumerate(steps):
        if f < 1 or f > nf:
            raise ResError("step %d names frame %d of %d" % (i, f, nf))
        fr = frames[f - 1]
        if off + (fr["h"] - 1) * W + fr["w"] > W * H:
            raise ResError("step %d puts frame %d (%dx%d) at %d, off screen"
                           % (i, f, fr["w"], fr["h"], off))
    return {"steps": steps, "frames": frames, "L": L,
            "trailing": len(m) - at}


def kind(m):
    if is_screen(m):
        return "screen"
    if is_palette(m):
        return "palette"
    if is_textmode(m):
        return "text-mode"
    if m[:3] == b"MMM":
        return "MMM"
    if b"Chmielarz" in m:
        return "driver"
    if len(m) == 0 or (len(m) == 1 and m[0] == 0):
        return "empty"
    try:
        s = sprite(m)
        if s["end"] == len(m):
            return "sprite"
    except ResError:
        pass
    try:
        parse_overlay(m)
        return "overlay"
    except ResError:
        pass
    try:
        parse_animation(m)
        return "animation"
    except ResError:
        pass
    try:
        if len(parse_font(m)) >= 32:
            return "font"
    except (ResError, struct.error, IndexError):
        pass
    return "other"


# ------------------------------------------------------------------ PNG
def png(width, height, rgb_rows):
    raw = b"".join(b"\x00" + bytes(c for px in row for c in px)
                   for row in rgb_rows)

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2,
                                         0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def palette6(p):
    """768 bytes of 6-bit VGA -> 256 (r, g, b) at 8 bits, `v << 2 | v >> 4`."""
    return [tuple((v << 2) | (v >> 4) for v in p[i:i + 3])
            for i in range(0, 768, 3)]


def screen_png(m):
    pal = palette6(m[-768:])
    rows = [[pal[m[y * W + x]] for x in range(W)] for y in range(H)]
    return png(W, H, rows)


def sheet_png(screens, per_row=5, scale=1):
    """All the given screens on one image, `per_row` to a row, black gaps."""
    n = len(screens)
    rows_n = (n + per_row - 1) // per_row
    gap = 4
    sw, sh = W * scale + gap, H * scale + gap
    width, height = per_row * sw, rows_n * sh
    pals = [palette6(m[-768:]) for m in screens]
    out = []
    for y in range(height):
        row = []
        ry, yy = divmod(y, sh)
        for x in range(width):
            rx, xx = divmod(x, sw)
            i = ry * per_row + rx
            if i >= n or xx >= W * scale or yy >= H * scale:
                row.append((0, 0, 0))
            else:
                m = screens[i]
                row.append(pals[i][m[(yy // scale) * W + xx // scale]])
        out.append(row)
    return png(width, height, out)


def blit(canvas, pixels, w, h, off):
    """The engine's blitter: w x h at screen offset, 0FFh transparent."""
    for y in range(h):
        row = pixels[y * w:(y + 1) * w]
        base = off + y * W
        for x, c in enumerate(row):
            if c != 0xFF:
                canvas[base + x] = c


def room(root, r, step=0):
    """Room r (1-based): OFF[r-1] + ON[r-1] + LAN_000 slots (r-1)*4 .. +3
    at their `step`-th step. Returns (canvas, palette, notes)."""
    def load(name):
        with open(os.path.join(root, name), "rb") as fh:
            b = fh.read()
        return b, parse(b)
    off, doff = load("OFF.RES")
    on, don = load("ON.RES")
    lan, dlan = load("LAN_000.RES")
    bg = off[doff["offsets"][r - 1]:doff["offsets"][r]]
    canvas = bytearray(bg[:W * H])
    pal = bg[-768:]
    notes = []
    ov = parse_overlay(on[don["offsets"][r - 1]:don["offsets"][r]])
    for s in ov:
        blit(canvas, s["pixels"], s["w"], s["h"], s["off"])
    notes.append("ON[%d]: %d overlay%s" % (r - 1, len(ov),
                                          "" if len(ov) == 1 else "s"))
    for slot in range(4):
        i = (r - 1) * 4 + slot
        a = parse_animation(lan[dlan["offsets"][i]:dlan["offsets"][i + 1]])
        if not a["steps"]:
            notes.append("LAN_000[%d]: empty" % i)
            continue
        f, pos = a["steps"][step % len(a["steps"])]
        fr = a["frames"][f - 1]
        blit(canvas, fr["pixels"], fr["w"], fr["h"], pos)
        notes.append("LAN_000[%d]: %d steps, %d frames, step %d = frame %d "
                     "%dx%d at (%d,%d)"
                     % (i, len(a["steps"]), len(a["frames"]),
                        step % len(a["steps"]), f, fr["w"], fr["h"],
                        pos % W, pos // W))
    return bytes(canvas) + pal, notes


def frames_png(a, pal):
    """Every frame of an animation side by side, magenta gaps."""
    gap = 2
    width = sum(f["w"] for f in a["frames"]) + gap * (len(a["frames"]) + 1)
    height = max(f["h"] for f in a["frames"]) + 2 * gap
    p6 = palette6(pal)
    rows = [[(255, 0, 255)] * width for _ in range(height)]
    x = gap
    for f in a["frames"]:
        for y in range(f["h"]):
            for xx in range(f["w"]):
                c = f["pixels"][y * f["w"] + xx]
                if c != 0xFF:
                    rows[y + gap][x + xx] = p6[c]
        x += f["w"] + gap
    return png(width, height, rows)


def parse_font(m):
    first = struct.unpack_from("<H", m, 0)[0]
    n = first // 2
    offs = struct.unpack_from("<%dH" % n, m, 0)
    glyphs = []
    at = first
    for i, o in enumerate(offs):
        if o != at:
            raise ResError("glyph %d at %d, expected %d" % (i, o, at))
        h, w = m[o], m[o + 1]
        glyphs.append((w, h, m[o + 2:o + 2 + w * h]))
        at = o + 2 + w * h
    if at != len(m):
        raise ResError("glyphs end at %d, member is %d" % (at, len(m)))
    return glyphs


def font_png(glyphs, scale=3, per=16):
    cw = max(g[0] for g in glyphs) + 1
    ch = max(g[1] for g in glyphs) + 1
    rows_n = (len(glyphs) + per - 1) // per
    canvas = [[(255, 0, 255)] * (per * cw * scale)
              for _ in range(rows_n * ch * scale)]
    col = {0: (255, 0, 255), 1: (255, 255, 255), 2: (0, 0, 0)}
    for i, (w, h, px) in enumerate(glyphs):
        cx, cy = (i % per) * cw, (i // per) * ch
        for y in range(h):
            for x in range(w):
                c = col.get(px[y * w + x], (0, 0, 255))
                for dy in range(scale):
                    for dx in range(scale):
                        canvas[(cy + y) * scale + dy][(cx + x) * scale + dx] = c
    return png(per * cw * scale, rows_n * ch * scale, canvas)


def textmode(m, cols=80):
    rows = len(m) // (cols * 2)
    lines = [bytes(m[r * cols * 2:(r + 1) * cols * 2][0::2]).decode("cp437")
             for r in range(rows)]
    attrs = sorted(set(m[1::2]))
    return lines, attrs


def bcd(b):
    return (b >> 4) * 10 + (b & 15)


def parse_mmm(m):
    if m[:3] != b"MMM":
        raise ResError("no MMM tag")
    n = m[4]
    ids = [bcd(b) for b in m[5:5 + n]]
    p = 5 + n
    tags = {}
    while p + 1 < len(m) and chr(m[p]) in "QRS":
        tags[chr(m[p])] = bcd(m[p + 1])
        p += 2
    return {"byte3": m[3], "samples": ids, "tags": tags, "body_at": p,
            "body": m[p:]}


def entries_report(m):
    """An overlay member's entries, one line each; nested lists named."""
    n = m[0]
    offs = struct.unpack_from("<%dH" % n, m, 1)
    out = ["n %d, first offset %d (1 + 2n = %d), %d bytes"
           % (n, offs[0], 1 + 2 * n, len(m))]
    for i, o in enumerate(offs):
        try:
            s = sprite(m, o)
            out.append("%3d at %6d  %3d x %3d at (%3d,%3d)  ends %6d"
                       % (i, o, s["w"], s["h"], s["x"], s["y"], s["end"]))
        except ResError:
            nxt = offs[i + 1] if i + 1 < n else len(m)
            q = parse_sequence(m[o:nxt])
            out.append("%3d at %6d  SEQUENCE of %d steps over %d sprites: %s"
                       % (i, o, len(q["steps"]), q["sprites"],
                          " ".join("%dx%d" % (s["w"], s["h"])
                                   for s in q["steps"][:6])
                          + (" ..." if len(q["steps"]) > 6 else "")))
    return out


def screen_stats(m):
    body = m[:W * H]
    used = sorted(set(body))
    return {"colours": len(used), "lowest": used[0], "highest": used[-1],
            "black_rows_top": next((y for y in range(H)
                                    if any(body[y * W:(y + 1) * W])), H)}


def ascii(m, cell=4):
    """A text render, `cell` x `cell` pixels a character, by luminance."""
    pal = palette6(m[-768:])
    lum = [(r * 30 + g * 59 + b * 11) // 100 for r, g, b in pal]
    ramp = " .:-=+*#%@"
    out = []
    for y in range(0, H, cell):
        row = []
        for x in range(0, W, cell):
            s = 0
            for yy in range(y, min(H, y + cell)):
                for xx in range(x, min(W, x + cell)):
                    s += lum[m[yy * W + xx]]
            s //= cell * cell
            row.append(ramp[min(9, s * 10 // 256)])
        out.append("".join(row))
    return out


# ------------------------------------------------------------------ report
def report(path, blob, listing=False):
    d = parse(blob)
    n = d["count"]
    sizes = [d["offsets"][i + 1] - d["offsets"][i] for i in range(n)]
    kinds = {}
    for i, m in members(blob, d):
        k = kind(m)
        kinds[k] = kinds.get(k, 0) + 1
    print("=== %s ===" % path)
    print("  bytes                    : %d" % len(blob))
    print("  members                  : %d" % n)
    print("  directory                : 4 + 4 x %d = %d bytes; first offset "
          "%d, last %d = file length, monotonic, residue %d"
          % (n + 1, d["offsets"][0], d["offsets"][0], d["offsets"][n],
             d["residue"]))
    print("  member sizes             : %d .. %d, sum %d"
          % (min(sizes), max(sizes), sum(sizes)))
    print("  kinds                    : %s"
          % ", ".join("%s %d" % kv for kv in sorted(kinds.items())))
    if listing:
        for i, m in members(blob, d):
            print("  %4d  %7d  %-9s %s" % (i, len(m), kind(m),
                                          m[:16].hex(" ")))
    return d


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--extract", metavar="DIR")
    ap.add_argument("--render", metavar="DIR")
    ap.add_argument("--ascii", metavar="N", type=int,
                    help="text render of screen member N")
    ap.add_argument("--sheet", metavar="PNG",
                    help="every screen of every input on one PNG")
    ap.add_argument("--room", metavar="R", type=int,
                    help="compose room R (1..42) from OFF, ON and LAN_000 "
                         "under --root; write --out")
    ap.add_argument("--step", type=int, default=0)
    ap.add_argument("--frames", metavar="N", type=int,
                    help="all frames of animation member N of FILE, with the "
                         "palette of --palette-from ROOM (1..42); write --out")
    ap.add_argument("--palette-from", metavar="ROOM", type=int, default=1)
    ap.add_argument("--root", default="Teenagent")
    ap.add_argument("--out", metavar="PNG")
    ap.add_argument("--font", metavar="N", type=int,
                    help="font member N: glyph census; --out writes a PNG")
    ap.add_argument("--textmode", metavar="N", type=int,
                    help="text-mode member N as 80-column text")
    ap.add_argument("--entries", metavar="N", type=int,
                    help="every entry of overlay member N")
    ap.add_argument("--mmm", action="store_true",
                    help="the MMM song headers of FILE")
    ap.add_argument("--census", metavar="ROOT")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.census:
        return census(dirguard.want_tree(args.census, "res.py"))
    if args.room:
        dirguard.want_tree(args.root, "res.py")
        canvas, notes = room(args.root, args.room, args.step)
        for n in notes:
            print("  " + n)
        if args.out:
            with open(args.out, "wb") as out:
                out.write(screen_png(canvas))
            print("  written: %s" % args.out)
        return 0
    if not args.paths:
        ap.error("no input")
    rc = 0
    sheet = []
    for p in args.paths:
        dirguard.want_file(p, "res.py")
        with open(p, "rb") as fh:
            blob = fh.read()
        try:
            d = report(p, blob, args.list)
        except ResError as e:
            print("=== %s ===\n  NOT A .RES CONTAINER: %s" % (p, e))
            rc = 1
            continue
        stem = os.path.splitext(os.path.basename(p))[0]
        if args.extract:
            os.makedirs(args.extract, exist_ok=True)
            for i, m in members(blob, d):
                with open(os.path.join(args.extract, "%s.%03d" % (stem, i)),
                          "wb") as out:
                    out.write(m)
            print("  extracted                : %d members to %s"
                  % (d["count"], args.extract))
        if args.render:
            os.makedirs(args.render, exist_ok=True)
            k = 0
            for i, m in members(blob, d):
                if not is_screen(m):
                    continue
                with open(os.path.join(args.render, "%s-%02d.png" % (stem, i)),
                          "wb") as out:
                    out.write(screen_png(m))
                s = screen_stats(m)
                print("  %s-%02d.png  %3d colours, indices %3d..%3d, "
                      "first non-zero row %d"
                      % (stem, i, s["colours"], s["lowest"], s["highest"],
                         s["black_rows_top"]))
                k += 1
            print("  rendered                 : %d screens to %s"
                  % (k, args.render))
        if args.sheet:
            sheet += [m for _, m in members(blob, d) if is_screen(m)]
        if args.frames is not None:
            m = blob[d["offsets"][args.frames]:d["offsets"][args.frames + 1]]
            a = parse_animation(m)
            with open(os.path.join(args.root, "OFF.RES"), "rb") as fh:
                ob = fh.read()
            od = parse(ob)
            pal = ob[od["offsets"][args.palette_from] - 768:
                     od["offsets"][args.palette_from]]
            print("  member %d: L %d, %d steps, %d frames: %s"
                  % (args.frames, a["L"], len(a["steps"]), len(a["frames"]),
                     " ".join("%dx%d" % (f["w"], f["h"]) for f in a["frames"])))
            print("  steps: %s" % " ".join("%d@(%d,%d)" % (f, o % W, o // W)
                                          for f, o in a["steps"][:24])
                  + (" ..." if len(a["steps"]) > 24 else ""))
            if args.out:
                with open(args.out, "wb") as out:
                    out.write(frames_png(a, pal))
                print("  written: %s" % args.out)
        if args.font is not None:
            m = blob[d["offsets"][args.font]:d["offsets"][args.font + 1]]
            g = parse_font(m)
            vals = set()
            for _w, _h, px in g:
                vals |= set(px)
            print("  member %d: %d glyphs from 20h, pixel values %s, tiles "
                  "the member" % (args.font, len(g), sorted(vals)))
            print("  sizes: " + " ".join("%02X:%dx%d" % (0x20 + i, w, h)
                                          for i, (w, h, _) in enumerate(g)))
            if args.out:
                with open(args.out, "wb") as out:
                    out.write(font_png(g))
                print("  written: %s" % args.out)
        if args.textmode is not None:
            m = blob[d["offsets"][args.textmode]:d["offsets"][args.textmode + 1]]
            lines, attrs = textmode(m)
            print("  member %d: %d bytes = 80 x %d x 2; attributes %s"
                  % (args.textmode, len(m), len(lines),
                     " ".join("%02X" % a for a in attrs)))
            for l in lines:
                print("  |" + l.rstrip() + "|")
        if args.entries is not None:
            m = blob[d["offsets"][args.entries]:d["offsets"][args.entries + 1]]
            for l in entries_report(m):
                print("  " + l)
        if args.mmm:
            used = set()
            for i, m in members(blob, d):
                s = parse_mmm(m)
                used |= set(s["samples"])
                print("  %2d %5d  [3]=%d samples %s  Q/R/S %s  body at %d: %s"
                      % (i, len(m), s["byte3"], s["samples"],
                         [s["tags"].get(k) for k in "QRS"], s["body_at"],
                         s["body"][:8].hex(" ")))
            print("  samples named: %d distinct, %d..%d, missing of 1..51: %s"
                  % (len(used), min(used), max(used),
                     sorted(set(range(1, 52)) - used) or "none"))
        if args.ascii is not None:
            m = blob[d["offsets"][args.ascii]:d["offsets"][args.ascii + 1]]
            if not is_screen(m):
                print("  member %d is not a screen" % args.ascii)
                rc = 1
            else:
                print()
                for line in ascii(m):
                    print("  |" + line + "|")
    if args.sheet:
        with open(args.sheet, "wb") as out:
            out.write(sheet_png(sheet))
        print("sheet                      : %d screens, %d to a row, to %s"
              % (len(sheet), 5, args.sheet))
    return rc


def census(root):
    """The twelve, selected by the directory closure and not by extension."""
    rows = []
    total_m = total_b = 0
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name)
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as fh:
            head = fh.read(4096)
        size = os.path.getsize(p)
        if not looks_like_head(head, size):
            continue
        with open(p, "rb") as fh:
            blob = fh.read()
        d = parse(blob)
        kinds = {}
        for i, m in members(blob, d):
            k = kind(m)
            kinds[k] = kinds.get(k, 0) + 1
        sizes = [d["offsets"][i + 1] - d["offsets"][i]
                 for i in range(d["count"])]
        rows.append((name, size, d["count"], min(sizes), max(sizes), kinds))
        total_m += d["count"]
        total_b += size
    print("%-14s %10s %6s %8s %8s  %s" % ("file", "bytes", "count", "min",
                                          "max", "kinds"))
    for name, size, n, lo, hi, kinds in rows:
        print("%-14s %10d %6d %8d %8d  %s"
              % (name, size, n, lo, hi,
                 ", ".join("%s %d" % kv for kv in sorted(kinds.items()))))
    print("%-14s %10d %6d" % ("%d containers" % len(rows), total_b, total_m))
    return 0


# ------------------------------------------------------------------ selftest
def _container(parts):
    n = len(parts)
    offs = [4 + 4 * (n + 1)]
    for p in parts:
        offs.append(offs[-1] + len(p))
    return struct.pack("<I%dI" % (n + 1), n, *offs) + b"".join(parts)


def selftest():
    nameguard.guard()
    checks = []

    def ok(label, cond, note=""):
        checks.append(cond)
        print("  %-56s %s %s" % (label, "ok" if cond else "FAIL", note))

    scr = bytes((x + y) & 0xFF for y in range(H) for x in range(W)) \
        + bytes(v % 64 for v in range(768))
    c = _container([b"abc", b"", scr, bytes(768), b"MMM\x06"])
    d = parse(c)
    ok("synthetic container of 5 closes", d["count"] == 5 and d["residue"] == 0)
    ok("a head of 4096 bytes closes with the length",
       looks_like_head(c[:4096], len(c)))
    ok("the same head with the wrong length is refused",
       not looks_like_head(c[:4096], len(c) + 1))
    ok("first offset off by one is refused",
       not looks_like_head(c[:4] + struct.pack("<I", 29) + c[8:], len(c)))
    ok("a non-monotonic offset is refused",
       not looks_like_head(c[:12] + struct.pack("<I", 1) + c[16:], len(c)))
    ok("count 0 is refused", not looks_like_head(bytes(8), 8))
    ok("empty member allowed (LAN_000 has size-1 members; ON has size 1)",
       d["offsets"][2] - d["offsets"][1] == 0)
    ks = [kind(m) for _, m in members(c, d)]
    ok("kinds: other, empty, screen, palette, MMM",
       ks == ["other", "empty", "screen", "palette", "MMM"], str(ks))
    ok("a 64,768-byte member whose tail exceeds 63 is not a screen",
       not is_screen(scr[:-1] + b"\x40"))
    p = screen_png(scr)
    ok("screen renders to a PNG of 320 x 200",
       p[:8] == b"\x89PNG\r\n\x1a\n" and struct.unpack_from(">II", p, 16)
       == (320, 200))
    ok("6-bit 63 -> 255, 0 -> 0, 32 -> 130",
       palette6(bytes((63, 0, 32)) + bytes(765))[0] == (255, 0, 130))
    ok("ascii render is 50 lines of 80", len(ascii(scr)) == 50
       and all(len(l) == 80 for l in ascii(scr)))
    fnt = struct.pack("<2H", 4, 4 + 2 + 6) + bytes((2, 3)) + bytes(6) \
        + bytes((1, 1, 2))
    g = parse_font(fnt)
    ok("font: two glyphs, h/w order, tiles", [(w, h) for w, h, _ in g]
       == [(3, 2), (1, 1)])
    try:
        parse_font(fnt + b"\0")
        ok("font with a trailing byte is refused", False)
    except ResError:
        ok("font with a trailing byte is refused", True)
    ok("BCD 0x51 -> 51, 0x10 -> 10", bcd(0x51) == 51 and bcd(0x10) == 10)
    s = parse_mmm(b"MMM\x06\x03\x01\x02\x10Q\x01R\x10S\x02\x00\x2b")
    ok("MMM head: samples [1, 2, 10], Q/R/S, body at 14",
       s["samples"] == [1, 2, 10] and s["tags"] == {"Q": 1, "R": 10, "S": 2}
       and s["body_at"] == 14)
    ov = _container([b""])[:0]  # noqa: F841  (keeps the helper referenced)
    nested = bytes((2,)) + struct.pack("<2H", 5, 5 + 6 + 1) \
        + struct.pack("<3H", 1, 1, 0) + b"\x07" \
        + bytes((3,)) + struct.pack("<3H", 7, 7, 7) \
        + struct.pack("<3H", 1, 1, 0) + b"\x08"
    rep = entries_report(nested)
    ok("entries: a sprite and a SEQUENCE are told apart",
       "1 x   1" in rep[1] and "SEQUENCE of 3 steps over 1 sprites" in rep[2],
       str(rep))
    ok("the same member parses as an overlay with a sequence in entry 1",
       "sequence" in parse_overlay(nested)[1])

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    root = os.path.join(here, "Teenagent")
    skipped = 0
    if os.path.isdir(root):
        found = 0
        screens = 0
        mem = 0
        for name in sorted(os.listdir(root)):
            p = os.path.join(root, name)
            if not os.path.isfile(p):
                continue
            with open(p, "rb") as fh:
                blob = fh.read()
            if not looks_like_head(blob[:4096], len(blob)):
                continue
            found += 1
            d = parse(blob)
            mem += d["count"]
            screens += sum(1 for _, m in members(blob, d) if is_screen(m))
        ok("the object: 12 containers selected by closure", found == 12,
           "%d" % found)
        ok("1,053 members", mem == 1053, "%d" % mem)
        ok("54 screens (ADVERT 11 + OFF 42 + UNLOGIC 1)", screens == 54,
           "%d" % screens)
        ok("no other file in the root closes as a container",
           found == 12)
    else:
        skipped += 4
        print("  (Teenagent/ not here: 4 checks skipped)")
    print("\nres.py selftest: %d of %d ok, %d skipped"
          % (sum(checks), len(checks), skipped))
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
