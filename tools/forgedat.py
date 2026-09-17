#!/usr/bin/env python3
"""forgedat.py -- read GAME.DAT of THE DEMON'S FORGE (Mastertronic, MS-DOS,
1987; "Dos Driver by Mok"): a 160 KB self-booting diskette image behind a
512-byte signature sector, with a 120-entry named directory, two programs, one
raw CGA screen, the intro text, 75 vector room pictures, 28 vector objects,
and ten in-place save-game slots -- decoded with a grammar read out of the
game's own drawing interpreter, not off the bytes.

WHAT THE FILE IS
----------------
    +0x000   512   Mok's sector: "Demon's Forge by Mastertronic. Dos Driver
                   by Mok." then zeros
    +0x200   512   disk sector 1: the diskette's BOOT SECTOR (`* Boot error *`,
                   `Strike any key to reboot`), 8 sectors/track, sector ids
                   0x11.. on every track but the boot sector's own
    +0x400   512   disk sector 2: the DIRECTORY, 12-byte records until an all-
                   zero one:  u16 a0  u16 a1  u16 c0  u16 c1  u8 len  char[3]
                   body = bytes [a0*512+c0, a1*512+c1) -- a = 1-based logical
                   sector on the diskette = 0-based sector of THIS file (Mok's
                   sector shifts by one), c = offset in that sector; the name
                   is a length-prefixed string of at most 3 chars, so `R1T`
                   is "R1" and its T is a leftover
    ...            the bodies, tiling 3072..146679 with no gap, then 0xF6

    164352 = 512 + 163840 = one signature sector + 40 tracks x 8 x 512.

THE ENTRIES (120 with a body; the 121st record is the terminator)
    HEA   2048  MZ, the pre-loader: palette question, credits, loads HDR, FO
    FO   61824  MZ, the engine == FORGE.EXE up to Mok's 151-byte patch
    HDR  16512  a raw 16 KB CGA frame the pre-loader loads at B800:0000 (zeros)
    TXT   2463  the intro text (the King, the gladiator, the rations)
    R1..R76     75 room pictures (R50 absent), vector records, see below
    O1..O28     28 object pictures, same records (O24 is only a terminator)
    STR    225  the initial game state; QUK the QUICKSAVE slot (== STR here)
    FLS    210  ten 21-byte save-slot names: 0xFF + 20 chars
    G0..G9 225  ten SAVE slots; G9 == STR and its FLS name is "Not Saved"

THE PICTURE GRAMMAR, FROM THE ENGINE (FORGE.EXE, graphics module at file
0x6F00 = segment 0610; the interpreter is at 0x717B, the line routine at
0x7290, the fill at 0x7379, the 36 x 4-byte pattern table at 0x866D, the
clear at 0x8775; `dosdis.py` decoded each at 100 % with every branch on an
instruction boundary):

    record = x0 y0 x1 y1 op     (5 bytes)
    op == 0xFF          end
    op bit 1            x0 += 256          op bit 0   x1 += 256
    op bit 2 set        FILL from (x0,y0) with pattern x1:
                          x1 == 0xFE -> `out 3D8h, 0Ah` (CGA colour)
                          x1 == 0xFF -> `out 3D8h, 0Eh` if the user chose
                                        palette 1, else 0Ah (the first record
                                        of every room is one of these two)
                          else       -> span fill: down from the seed while
                                        the seed column is white, each row
                                        left and right to the first non-white
                                        pixel, then up; whole 0xFF bytes take
                                        the pattern byte, edge bytes pixel by
                                        pixel; pattern byte = table[p*4 +
                                        (y&1)*2 + (col&1)]
    op bit 2 clear      LINE (x0,y0)-(x1,y1) in colour op>>6, one step in x
                        OR y per iteration, |dx|+|dy|+1 pixels
    screen              320x200 CGA mode 4; rows 0..159 cleared to WHITE
                        (colour 3) for 280 pixels and BLACK for the last 40;
                        white is the fill's background, so a room is black
                        lines on white, then patterned fills; objects are
                        drawn over the room in white (op 0xC0) and black

    python tools/forgedat.py demons-forge/GAME.DAT                # validate
    python tools/forgedat.py demons-forge/GAME.DAT --dir           # 120 entries
    python tools/forgedat.py demons-forge/GAME.DAT --text          # TXT
    python tools/forgedat.py demons-forge/GAME.DAT --saves         # FLS + G0..G9
    python tools/forgedat.py demons-forge/GAME.DAT --vocab         # verbs and nouns, from FO
    python tools/forgedat.py demons-forge/GAME.DAT --records R2    # the records
    python tools/forgedat.py demons-forge/GAME.DAT --render R2 --out r2.png
    python tools/forgedat.py demons-forge/GAME.DAT --render R60 --objects O20,O21,O22,O23 --out r60.png
    python tools/forgedat.py demons-forge/GAME.DAT --ascii R2 --objects O3   # text render
    python tools/forgedat.py demons-forge/GAME.DAT --sheet rooms.png
    python tools/forgedat.py demons-forge/GAME.DAT --exe demons-forge/FORGE.EXE
    python tools/forgedat.py --selftest [--object demons-forge]

Standard library only; it writes only where --out/--sheet say. The repository
publishes no picture this produces.
"""
import argparse
import collections
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402

SIGNATURE = b"Demon's Forge by Mastertronic. Dos Driver by Mok."
SECTOR = 512
DIR_AT = 0x400
DIR_MAX = 175            # the engine's lookup loop counts 0xAF records
BOOT_STRINGS = (b"* Boot error *", b"Strike any key to reboot")
OBJECT_REL = os.path.join("demons-forge", "GAME.DAT")
EXE_REL = os.path.join("demons-forge", "FORGE.EXE")

# The engine's fill patterns: FORGE.EXE 0x866D, entries of 4 bytes
# [even row, even byte][even row, odd byte][odd row, even][odd row, odd].
# The pictures use indices 0..35; entry 36 is zero and what follows is the
# engine's next data and code. All 256 bytes from 0x866D are carried because
# the engine indexes the table with an 8-bit `shl [1E],1` twice, so a stray
# index -- R46 record 43 carries 0xFD -- wraps to entry 61 and paints code
# bytes, and this reader reproduces that rather than correcting it. The
# constant lets the selftest run without the object; validate() checks the
# copy inside GAME.DAT's FO entry against it.
PATTERNS = bytes.fromhex(
    "00000000aaaaaaaa8282282820200202babaababafaffafa2e2ee2e2e9e99e9e"
    "afaffafaa5a55a5aa0a08282afafbebea5a5a5a525255252c0c00c0cffffffff"
    "cccc3333f0f0c3c3555555554141141410100101757557571d1dd1d150504141"
    "aaaaffffaaaa000066668888bbbbeeee6666888866669999555500005555ffff"
    "2e2ee2e24444111100000000000000000000000000dddd555510019999f77f17"
    "715ff5f77fb11b55557ff7888828824444ffffcccc7887222220029009aaaabf"
    "fb2222fddf50056666d99d66669bb9aaaaeeee71178888f00f00000000000000"
    "002bc0be29002bc98bfe8bd903d8891d83c70881c1a00081f9401f75ed464605")
PATTERN_AT = 0x866D      # file offset in FORGE.EXE == offset in the FO body
N_PATTERNS = 36          # the real patterns; the 256-byte region has 64 slots


def pattern_index(p, y, col):
    # 0x7379: shl [1E],1 twice (8-bit), then 0x7500: or in (y&1)<<1 | (col&1)
    return ((p << 2) & 0xFF) | ((y & 1) << 1) | (col & 1)


WHITE_BYTES = 70         # the clear routine: 70 words of 0xFFFF ...
BLACK_BYTES = 10         # ... then 10 words of 0 per row, 160 rows
PIC_ROWS = 160

# IBM CGA mode 4 colours. 'default' is what the engine gets without touching
# the palette register: background black, palette 1. 'alt' is what it sets
# when the pre-loader's question was answered "1": background 1 (blue) and
# palette 0 via int 10h AH=0Bh. 'bw' is palette 1 with the 3D8h colour-burst
# bit (the FF rooms, on an RGB monitor). None is measured from the object.
PALETTES = {
    "default": [(0, 0, 0), (0, 170, 170), (170, 0, 170), (170, 170, 170)],
    "alt":     [(0, 0, 170), (0, 170, 0), (170, 0, 0), (170, 85, 0)],
    "bw":      [(0, 0, 0), (0, 170, 170), (170, 0, 0), (170, 170, 170)],
}


class DatError(Exception):
    pass


# --------------------------------------------------------------- reading --

def parse(blob, size=None):
    """Directory and shape checks. Raises DatError on anything malformed.
    `size` is the file length when `blob` is only its head (coverage.py hands
    4,096 bytes, which hold the signature, the boot sector and the whole
    directory); bodies are bounds-checked against it."""
    size = len(blob) if size is None else size
    if len(blob) < DIR_AT + 12:
        raise DatError("file is %d bytes, shorter than the directory at 0x%X" % (len(blob), DIR_AT))
    if blob[:len(SIGNATURE)] != SIGNATURE:
        raise DatError("no Mok signature at offset 0 (found %r)" % blob[:24])
    if blob[len(SIGNATURE):SECTOR].strip(b"\0"):
        raise DatError("signature sector is not zero-padded")
    boot = blob[SECTOR:2 * SECTOR]
    for s in BOOT_STRINGS:
        if s not in boot:
            raise DatError("boot sector at 0x200 lacks %r" % s)
    if boot[:1] != b"\xb8":
        raise DatError("boot sector does not start with mov ax,imm16")
    entries = []
    k = 0
    prev_end = None
    while True:
        at = DIR_AT + 12 * k
        rec = blob[at:at + 12]
        if len(rec) < 12:
            raise DatError("directory runs off the file at record %d" % (k + 1))
        if rec == b"\0" * 12:
            break
        if k >= DIR_MAX:
            raise DatError("more than %d directory records without a terminator" % DIR_MAX)
        a0, a1, c0, c1 = struct.unpack("<HHHH", rec[:8])
        ln, tag = rec[8], rec[9:12]
        if not 1 <= ln <= 3:
            raise DatError("record %d: name length %d, wanted 1..3" % (k + 1, ln))
        name = tag[:ln]
        if not all(0x21 <= ch < 0x7F for ch in name):
            raise DatError("record %d: name %r is not printable" % (k + 1, name))
        if c0 >= SECTOR or c1 >= SECTOR:
            raise DatError("record %d (%s): in-sector offset %d/%d >= 512" % (k + 1, name.decode(), c0, c1))
        start, end = a0 * SECTOR + c0, a1 * SECTOR + c1
        if end < start:
            raise DatError("record %d (%s): end %d before start %d" % (k + 1, name.decode(), end, start))
        if end > size:
            raise DatError("record %d (%s): body ends at %d past the file (%d)" % (k + 1, name.decode(), end, size))
        if prev_end is not None and start != prev_end:
            raise DatError("record %d (%s): starts at %d, previous body ended at %d -- the chain is broken"
                           % (k + 1, name.decode(), start, prev_end))
        entries.append({"index": k + 1, "name": name.decode("ascii"), "raw": tag,
                        "a0": a0, "a1": a1, "c0": c0, "c1": c1,
                        "start": start, "end": end, "size": end - start})
        prev_end = end
        k += 1
    if not entries:
        raise DatError("empty directory")
    if entries[0]["start"] < DIR_AT + 12 * (k + 1):
        raise DatError("first body overlaps the directory")
    tail = blob[prev_end:]
    return {"entries": entries, "by_name": {e["name"]: e for e in entries},
            "content_end": prev_end, "tail": size - prev_end,
            "tail_f6": len(blob) == size and tail == b"\xf6" * len(tail)}


def looks_like_head(head, size=None):
    """For coverage.py: the signature sector, the boot sector's two strings
    and a directory whose records chain a*512+c end-to-start down to an
    all-zero terminator, with the last body inside the file's length. A head
    cannot decode a picture; validate() does."""
    try:
        return len(parse(head, size)["entries"]) >= 1
    except (DatError, IndexError, struct.error):
        return False


def body(blob, e):
    return blob[e["start"]:e["end"]]


def is_mz(b):
    return len(b) >= 28 and b[:2] == b"MZ"


def mz_header(b):
    f = struct.unpack("<14H", b[:28])
    return {"cblp": f[1], "cp": f[2], "crlc": f[3], "cparhdr": f[4], "ss": f[7],
            "sp": f[8], "ip": f[10], "cs": f[11], "image": (f[2] - 1) * 512 + f[1] if f[1] else f[2] * 512}


def records(b):
    """The 5-byte records of a picture body, up to and including the 0xFF one."""
    if len(b) % 5:
        raise DatError("picture body is %d bytes, not a multiple of 5" % len(b))
    out = []
    for k in range(0, len(b), 5):
        x0, y0, x1, y1, op = b[k:k + 5]
        out.append((x0, y0, x1, y1, op))
        if op == 0xFF:
            if k + 5 != len(b):
                raise DatError("0xFF record at %d is not the last of %d" % (k // 5, len(b) // 5))
            return out
    raise DatError("picture has no 0xFF record")


def decode(rec):
    """One record -> ('end',) | ('mode', 0xFE|0xFF) | ('fill', x, y, pattern) | ('line', x0,y0,x1,y1,colour)"""
    x0, y0, x1, y1, op = rec
    if op == 0xFF:
        return ("end",)
    if op & 2:
        x0 += 256
    if op & 1:
        x1 += 256
    if op & 4:
        if x1 in (0xFE, 0xFF):
            return ("mode", x1)
        return ("fill", x0, y0, x1)
    return ("line", x0, y0, x1, y1, op >> 6)


# ------------------------------------------------------------ rendering --

class Screen(object):
    """A CGA mode-4 frame buffer, 80 bytes x 200 rows, kept as the card
    holds it so the fill can be the engine's byte algorithm and not a
    pixel-level paraphrase of it."""

    def __init__(self):
        self.rows = [bytearray(80) for _ in range(200)]
        self.ink = [bytearray(320) for _ in range(200)]   # 0 untouched, 1 line, 2 fill
        self.seeds_ok = 0
        self.seeds_on_line = 0      # seed on a pixel a line drew: the engine skips it
        self.seeds_on_fill = 0      # seed on a region already painted: skipped too
        self.seeds_off = 0          # seed in the black strip or off screen
        self.mode = None

    @property
    def seeds_blocked(self):
        return self.seeds_on_line + self.seeds_on_fill + self.seeds_off

    def clear(self):
        for y in range(PIC_ROWS):
            self.rows[y][:WHITE_BYTES] = b"\xff" * WHITE_BYTES
            self.rows[y][WHITE_BYTES:] = b"\0" * BLACK_BYTES

    def pixel(self, x, y):
        return (self.rows[y][x >> 2] >> (6 - 2 * (x & 3))) & 3

    def plot(self, x, y, c):
        if 0 <= y < 200 and 0 <= x < 320:
            sh = 6 - 2 * (x & 3)
            row = self.rows[y]
            row[x >> 2] = (row[x >> 2] & ~(3 << sh) & 0xFF) | ((c & 3) << sh)
            self.ink[y][x] = 1

    def _mark(self, y, col, take):
        for k in range(4):
            if take & (0xC0 >> (2 * k)):
                self.ink[y][col * 4 + k] = 2

    def line(self, x0, y0, x1, y1, c):
        # FORGE.EXE 0x7290: signs and magnitudes, err = |dx| - |dy|,
        # |dx|+|dy|+1 iterations, each moving x OR y.
        dx, dy = abs(x1 - x0), abs(y1 - y0)
        sx = (x1 > x0) - (x1 < x0)
        sy = (y1 > y0) - (y1 < y0)
        err = dx - dy
        n = dx + dy + 1
        x, y = x0, y0
        while True:
            self.plot(x, y, c)
            n -= 1
            if n == 0:
                return
            if err < 0:
                y += sy
                err += dx
            else:
                x += sx
                err -= dy

    def _pat(self, p, y, col):
        return PATTERNS[pattern_index(p, y, col)]

    def _partial(self, y, col, mask, p):
        # 0x74C8: from the pixel `mask` grow right then left while the pixel
        # is white, then write the pattern into exactly those pixels.
        row = self.rows[y]
        inv = row[col] ^ 0xFF
        take = 0
        m = mask
        while m and not (m & inv):
            take |= m
            m >>= 2
        m = mask
        while m and not (m & inv):
            take |= m
            m = (m << 2) & 0xFF
        row[col] = (row[col] & ~take & 0xFF) | (self._pat(p, y, col) & take)
        self._mark(y, col, take)

    def _span(self, y, col, mask, p):
        row = self.rows[y]
        self._partial(y, col, mask, p)
        c = col
        while c > 0:                              # 0x7436, leftwards
            c -= 1
            if row[c] == 0xFF:
                row[c] = self._pat(p, y, c)
                self._mark(y, c, 0xFF)
            else:
                self._partial(y, c, 0x03, p)
                break
        c = col
        while c < 79:                             # 0x7478, rightwards to byte 80
            c += 1
            if row[c] == 0xFF:
                row[c] = self._pat(p, y, c)
                self._mark(y, c, 0xFF)
            else:
                self._partial(y, c, 0xC0, p)
                break

    def fill(self, x, y, p):
        if not (0 <= x < 320 and 0 <= y < 200):
            self.seeds_off += 1
            return
        col, mask = x >> 2, 0xC0 >> (2 * (x & 3))
        if (self.rows[y][col] ^ 0xFF) & mask:     # the engine does nothing here
            if self.ink[y][x] == 1:
                self.seeds_on_line += 1
            elif self.ink[y][x] == 2:
                self.seeds_on_fill += 1
            else:
                self.seeds_off += 1
            return
        self.seeds_ok += 1
        yy = y
        while yy < 200 and not ((self.rows[yy][col] ^ 0xFF) & mask):   # 0x73A9 down
            self._span(yy, col, mask, p)
            yy += 1
        yy = y - 1
        while yy >= 0 and not ((self.rows[yy][col] ^ 0xFF) & mask):    # 0x73F1 up
            self._span(yy, col, mask, p)
            yy -= 1

    def draw(self, recs):
        for rec in recs:
            d = decode(rec)
            if d[0] == "end":
                return
            if d[0] == "mode":
                self.mode = d[1]
            elif d[0] == "fill":
                self.fill(d[1], d[2], d[3])
            else:
                self.line(*d[1:])

    def rgb_rows(self, palette, rows=200, scale=1):
        pal = PALETTES[palette]
        out = []
        for y in range(rows):
            row = bytearray()
            for x in range(320):
                r, g, b = pal[self.pixel(x, y)]
                row += bytes((r, g, b)) * scale
            for _ in range(scale):
                out.append(bytes(row))
        return out


ASCII_INK = {0: "@", 1: ":", 2: "%", 3: " "}   # black fill, colour 1, colour 2, white
ASCII_LINE = "#"


def ascii_rows(scr, cell=4, width=280, rows=PIC_ROWS):
    """One character per cell x cell block: '#' when a LINE drew at least
    `cell` pixels of the block (one pixel per row or column, so a thin line
    survives and a dark dither does not pass for one), otherwise the block's
    most common colour: black fill '@', colour 1 ':', colour 2 '%', white ' '.
    cell 4 -> 70 x 40 characters."""
    out = []
    for y0 in range(0, rows, cell):
        line = []
        for x0 in range(0, width, cell):
            ys = range(y0, min(y0 + cell, rows))
            xs = range(x0, min(x0 + cell, width))
            if sum(1 for y in ys for x in xs if scr.ink[y][x] == 1) >= cell:
                line.append(ASCII_LINE)
                continue
            c = collections.Counter(scr.pixel(x, y) for y in ys for x in xs)
            line.append(ASCII_INK[c.most_common(1)[0][0]])
        out.append("".join(line).rstrip())
    return out


def write_png(path, rgb_rows, width):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    raw = b"".join(b"\0" + r for r in rgb_rows)
    hdr = struct.pack(">IIBBBBB", width, len(rgb_rows), 8, 2, 0, 0, 0)
    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", hdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def render(blob, d, names, palette="default"):
    scr = Screen()
    scr.clear()
    for n in names:
        if n not in d["by_name"]:
            raise DatError("no entry named %s" % n)
        scr.draw(records(body(blob, d["by_name"][n])))
    return scr


# ------------------------------------------------------------- analysis --

def picture_names(d):
    rooms = [e["name"] for e in d["entries"] if e["name"][0] == "R" and e["name"][1:].isdigit()]
    objs = [e["name"] for e in d["entries"] if e["name"][0] == "O" and e["name"][1:].isdigit()]
    return rooms, objs


def picture_stats(blob, d):
    rooms, objs = picture_names(d)
    st = {"rooms": len(rooms), "objects": len(objs), "records": 0, "lines": 0, "fills": 0,
          "modes": collections.Counter(), "colours": collections.Counter(),
          "patterns": collections.Counter(), "xmax": 0, "ymax": 0, "first_is_mode": 0,
          "bad": []}
    for n in rooms + objs:
        try:
            recs = records(body(blob, d["by_name"][n]))
        except DatError as exc:
            st["bad"].append((n, str(exc)))
            continue
        st["records"] += len(recs)
        if recs and decode(recs[0])[0] == "mode":
            st["first_is_mode"] += 1
        for r in recs:
            dd = decode(r)
            if dd[0] == "line":
                st["lines"] += 1
                st["colours"][dd[5]] += 1
                st["xmax"] = max(st["xmax"], dd[1], dd[3])
                st["ymax"] = max(st["ymax"], dd[2], dd[4])
            elif dd[0] == "fill":
                st["fills"] += 1
                st["patterns"][dd[3]] += 1
                st["xmax"] = max(st["xmax"], dd[1])
                st["ymax"] = max(st["ymax"], dd[2])
            elif dd[0] == "mode":
                st["modes"][dd[1]] += 1
    return st


def seed_census(blob, d):
    """Render every room alone and classify its fill seeds: on white (the
    engine fills), on a region already painted or on a line pixel (the engine
    does nothing), off the picture. The decoder was not fitted to this: a
    mis-rasterised line or a wrong op bit moves seeds onto ink."""
    rooms, objs = picture_names(d)
    tot = collections.Counter()
    per = []
    for n in rooms:
        scr = render(blob, d, [n])
        tot["white"] += scr.seeds_ok
        tot["line"] += scr.seeds_on_line
        tot["fill"] += scr.seeds_on_fill
        tot["off"] += scr.seeds_off
        per.append((n, scr.seeds_ok, scr.seeds_blocked))
    return tot, per


def slot_names(blob, d):
    b = body(blob, d["by_name"]["FLS"])
    if len(b) % 21:
        raise DatError("FLS is %d bytes, not a multiple of 21" % len(b))
    out = []
    for k in range(0, len(b), 21):
        if b[k] != 0xFF:
            raise DatError("FLS slot %d does not start with 0xFF" % (k // 21))
        out.append(b[k + 1:k + 21].decode("cp437").rstrip())
    return out


VOCAB_AT = ((0x7635, 100), (0x77F9, 120))   # verbs, nouns: offsets in the engine (FO body == FORGE.EXE)


def vocab(fo):
    """The parser's two word tables inside the engine: WORD + one id byte,
    synonyms sharing an id, each table ending at a zero byte. Read from the
    FO body, whose bytes here equal FORGE.EXE's (outside Mok's patches)."""
    out = []
    for start, limit in VOCAB_AT:
        i, items = start, []
        while True:
            j = i
            while j < len(fo) and 0x41 <= fo[j] <= 0x5A:
                j += 1
            if j == i or j >= len(fo):
                break
            idb = fo[j]
            if idb == 0 or idb > limit:
                break
            items.append((fo[i:j].decode("ascii"), idb))
            i = j + 1
        out.append((start, i, items))
    return out


def cmd_vocab(blob, d):
    fo = body(blob, d["by_name"]["FO"])
    for label, (start, end, items) in zip(("verbs", "nouns"), vocab(fo)):
        ids = collections.Counter(v for _w, v in items)
        syn = collections.defaultdict(list)
        for w, v in items:
            syn[v].append(w)
        print("%s: FO+0x%X..0x%X, %d words, %d ids (%d..%d), %d ids with synonyms"
              % (label, start, end, len(items), len(ids), min(ids), max(ids), sum(1 for v in ids if ids[v] > 1)))
        for v in sorted(syn):
            print("  %3d  %s" % (v, " / ".join(syn[v])))


def exe_compare(blob, d, exe):
    fo = body(blob, d["by_name"]["FO"])
    n = min(len(fo), len(exe))
    diffs = [i for i in range(n) if fo[i] != exe[i]]
    ranges = []
    for i in diffs:
        if ranges and i - ranges[-1][1] <= 4:
            ranges[-1][1] = i + 1
        else:
            ranges.append([i, i + 1])
    return {"fo": len(fo), "exe": len(exe), "diff": len(diffs), "ranges": ranges,
            "fo_tail": fo[len(exe):] if len(fo) > len(exe) else b"",
            "same_header": fo[:28] == exe[:28]}


# --------------------------------------------------------------- output --

def cmd_validate(path, blob, d):
    e = d["entries"]
    print(os.path.basename(path))
    print("  file bytes             : %d = 512 + %d (= %d sectors of 512%s)"
          % (len(blob), len(blob) - 512, (len(blob) - 512) // 512,
             ", a 40 x 8 x 512 single-sided diskette" if len(blob) - 512 == 163840 else ""))
    print("  signature              : %r" % SIGNATURE.decode())
    print("  boot sector at 0x200   : %s" % " / ".join(s.decode() for s in BOOT_STRINGS))
    print("  directory at 0x400     : %d records with a body, record %d is the terminator"
          % (len(e), len(e) + 1))
    print("  bodies                 : tile %d..%d with no gap (a*512+c chains %d/%d)"
          % (e[0]["start"], d["content_end"], len(e) - 1, len(e) - 1))
    print("  tail                   : %d bytes%s" % (d["tail"], " of 0xF6" if d["tail_f6"] else " (NOT all 0xF6)"))
    by = d["by_name"]
    for n in ("HEA", "FO"):
        if n in by:
            b = body(blob, by[n])
            if is_mz(b):
                h = mz_header(b)
                print("  %-3s                    : MZ, %d bytes, image %d, %d relocs, cs:ip %04X:%04X, %d bytes past the image"
                      % (n, len(b), h["image"], h["crlc"], h["cs"], h["ip"], len(b) - h["image"]))
            else:
                print("  %-3s                    : NOT MZ" % n)
    if "FO" in by:
        fo = body(blob, by["FO"])
        same = fo[PATTERN_AT:PATTERN_AT + len(PATTERNS)] == PATTERNS
        print("  pattern table in FO    : %s the %d-byte region this reader carries (%d patterns)"
              % ("matches" if same else "DIFFERS FROM", len(PATTERNS), N_PATTERNS))
    if "HDR" in by:
        b = body(blob, by["HDR"])
        print("  HDR                    : %d bytes, %s" % (len(b), "all zero" if not b.strip(b"\0") else "not all zero"))
    st = picture_stats(blob, d)
    print("  pictures               : %d rooms + %d objects, %d records; %d lines, %d fills, "
          "%d start with a mode record" % (st["rooms"], st["objects"], st["records"], st["lines"],
                                            st["fills"], st["first_is_mode"]))
    print("  mode records           : %s" % ", ".join("0x%02X x%d" % kv for kv in sorted(st["modes"].items())))
    print("  line colours           : %s" % ", ".join("%d x%d" % kv for kv in sorted(st["colours"].items())))
    stray = sorted(p for p in st["patterns"] if p >= N_PATTERNS)
    print("  fill patterns          : %d distinct, %d in the table's 0..%d, stray: %s"
          % (len(st["patterns"]), len(st["patterns"]) - len(stray), N_PATTERNS - 1,
             " ".join("0x%02X x%d" % (p, st["patterns"][p]) for p in stray) or "none"))
    print("  extent                 : x <= %d (clear is white to 279), y <= %d (clear is 160 rows)"
          % (st["xmax"], st["ymax"]))
    for n, why in st["bad"]:
        print("  MALFORMED picture %s : %s" % (n, why))
    tot, _per = seed_census(blob, d)
    print("  fill seeds (rooms)     : %d of %d land on white; %d on a region already painted, "
          "%d on a line pixel, %d in the black strip -- the engine skips those"
          % (tot["white"], sum(tot.values()), tot["fill"], tot["line"], tot["off"]))
    if "STR" in by and "FLS" in by:
        names = slot_names(blob, d)
        s = body(blob, by["STR"])
        same = [k for k in range(10) if "G%d" % k in by and body(blob, by["G%d" % k]) == s]
        print("  save slots             : %d named in FLS; slots equal to STR: %s; QUK %s STR"
              % (len(names), " ".join("G%d (%r)" % (k, names[k]) for k in same) or "none",
                 "==" if "QUK" in by and body(blob, by["QUK"]) == s else "!="))
    verdict = not st["bad"] and tot["line"] * 20 < tot["white"]
    print("  %s" % ("CLOSES" if verdict else "DOES NOT CLOSE"))
    return 0 if verdict else 2


def cmd_dir(blob, d):
    print("  %3s %-4s %3s %6s %6s %6s %-10s %s" % ("#", "name", "len", "start", "end", "bytes", "kind", "head"))
    for e in d["entries"]:
        b = body(blob, e)
        kind = "MZ" if is_mz(b) else ("zero" if b and not b.strip(b"\0") else "")
        if not kind and (e["name"][0] in "RO") and e["name"][1:].isdigit():
            try:
                kind = "pic %d rec" % len(records(b))
            except DatError:
                kind = "pic?"
        print("  %3d %-4s %3d %6d %6d %6d %-10s %s" % (e["index"], e["name"], len(e["name"]), e["start"],
                                                      e["end"], e["size"], kind, b[:8].hex(" ")))


def cmd_records(blob, d, name):
    e = d["by_name"].get(name)
    if not e:
        raise DatError("no entry named %s" % name)
    recs = records(body(blob, e))
    print("%s: %d records" % (name, len(recs)))
    for k, r in enumerate(recs):
        dd = decode(r)
        print("  %4d  %02x %02x %02x %02x %02x   %s" % ((k,) + r + (" ".join(str(v) for v in dd),)))


def cmd_saves(blob, d):
    names = slot_names(blob, d)
    s = body(blob, d["by_name"]["STR"])
    print("  slot  name                  bytes differing from STR")
    for k, n in enumerate(names):
        g = d["by_name"].get("G%d" % k)
        diff = sum(1 for i in range(len(s)) if body(blob, g)[i] != s[i]) if g else "-"
        print("  G%d    %-20r  %s" % (k, n, diff))
    q = body(blob, d["by_name"]["QUK"])
    print("  QUK   (quicksave)         %d" % sum(1 for i in range(len(s)) if q[i] != s[i]))


def cmd_sheet(blob, d, out, palette):
    rooms, _objs = picture_names(d)
    cols = 5
    tiles = []
    for n in rooms:
        tiles.append(render(blob, d, [n]).rgb_rows(palette, rows=PIC_ROWS))
    rows_out = []
    blank = bytes(320 * 3)
    for r in range(0, len(tiles), cols):
        group = tiles[r:r + cols]
        for y in range(PIC_ROWS):
            rows_out.append(b"".join(t[y] for t in group) + blank * (cols - len(group)))
    write_png(out, rows_out, 320 * cols)
    print("wrote %s: %d rooms in %d columns" % (out, len(tiles), cols))


# ------------------------------------------------------------- selftest --

def _synthetic(pics, extra=()):
    """Build a GAME.DAT-shaped blob: signature sector, a boot sector carrying
    the two strings, a directory, and the given bodies."""
    blob = bytearray(SIGNATURE.ljust(SECTOR, b"\0"))
    boot = bytearray(b"\xb8\xc0\x07" + b"\0" * 60 + BOOT_STRINGS[0] + b"\0" + BOOT_STRINGS[1] + b"\0")
    blob += boot.ljust(SECTOR, b"\0")
    names = [n for n, _b in pics] + [n for n, _b in extra]
    bodies = [b for _n, b in pics] + [b for _n, b in extra]
    first = 4 * SECTOR
    dirsec = bytearray()
    pos = first
    for n, b in zip(names, bodies):
        a0, c0 = divmod(pos, SECTOR)
        pos += len(b)
        a1, c1 = divmod(pos, SECTOR)
        dirsec += struct.pack("<HHHHB", a0, a1, c0, c1, len(n)) + n.encode().ljust(3, b"\0")
    dirsec += b"\0" * 12
    blob += dirsec.ljust(2 * SECTOR, b"\0")
    blob += b"".join(bodies)
    blob += b"\xf6" * 100
    return bytes(blob)


def selftest(object_path=None):
    checks = []
    skipped = []
    OBJECT_CHECKS = 15

    def want(label, got, expected):
        checks.append((label, got == expected, "" if got == expected else "got %r wanted %r" % (got, expected)))

    def refused(label, blob, needle):
        try:
            parse(blob)
            checks.append((label, False, "it parsed"))
        except DatError as exc:
            ok = needle in str(exc)
            checks.append((label, ok, "" if ok else "said %r" % str(exc)))

    box = bytes([0, 0, 0xFE, 0, 4,          # mode record
                 10, 10, 60, 10, 0,          # a black 4-connected box 10..60 x 10..40
                 60, 10, 60, 40, 0,
                 60, 40, 10, 40, 0,
                 10, 40, 10, 10, 0,
                 30, 20, 1, 0, 4,            # fill inside with pattern 1 (0xAA = colour 2)
                 200, 5, 15, 0, 4,           # fill outside with pattern 15 (white: no-op visually)
                 0, 0, 0, 0, 0xFF])
    wide = bytes([0, 0, 0xFF, 0, 4, 250, 100, 20, 100, 1, 0, 0, 0, 0, 0xFF])   # x1 = 276
    blob = _synthetic([("R1", box), ("R2", wide), ("O1", b"\0\0\0\0\xff")],
                      extra=[("STR", b"\x01" * 225), ("FLS", (b"\xff" + b"A".ljust(20)) * 10)])
    d = parse(blob)
    want("synthetic directory parses to 5 entries in order", [e["name"] for e in d["entries"]],
         ["R1", "R2", "O1", "STR", "FLS"])
    want("bodies chain and the tail is 0xF6", (d["content_end"] == 4 * SECTOR + len(box) + len(wide) + 5 + 225 + 210,
                                               d["tail_f6"]), (True, True))
    want("a 2-char name in a 3-char field keeps only its length", d["entries"][0]["raw"], b"R1\0")
    recs = records(box)
    want("the box is 8 records ending in 0xFF", (len(recs), recs[-1][4]), (8, 0xFF))
    want("op 4 with x1=0xFE decodes as a mode record", decode(recs[0]), ("mode", 0xFE))
    want("op bit 0 adds 256 to x1, bit 1 to x0", (decode(records(wide)[1])[1:4], decode((5, 0, 6, 0, 2))[1:4]),
         ((250, 100, 276), (261, 0, 6)))
    want("op bits 6-7 are the line colour", decode((1, 2, 3, 4, 0xC0))[5], 3)
    scr = Screen()
    scr.clear()
    scr.line(0, 0, 5, 3, 0)
    want("a line is |dx|+|dy|+1 pixels, one step per iteration",
         sum(1 for y in range(4) for x in range(6) if scr.pixel(x, y) == 0), 9)
    scr = render(blob, d, ["R1"])
    inside = scr.pixel(30, 20)
    outside = scr.pixel(200, 5)
    edge = scr.pixel(10, 20)
    beyond = scr.pixel(290, 20)
    want("the fill paints inside the box with colour 2 and leaves the edge black and the outside white",
         (inside, edge, outside, beyond), (2, 0, 3, 0))
    want("both seeds landed on white; the mode record was seen", (scr.seeds_ok, scr.seeds_blocked, scr.mode), (2, 0, 0xFE))
    scr2 = Screen()
    scr2.clear()
    scr2.fill(30, 20, 5)
    want("pattern bytes alternate by row parity (pattern 5: af/fa)",
         (scr2.rows[20][7], scr2.rows[21][7]), (0xAF, 0xFA))
    scr3 = Screen()
    scr3.clear()
    scr3.plot(30, 20, 0)
    scr3.fill(30, 20, 1)
    want("a seed on ink fills nothing and is counted as on-a-line", (scr3.seeds_on_line, scr3.pixel(31, 20)), (1, 3))
    scr3.fill(100, 100, 1)
    scr3.fill(101, 100, 2)
    want("a second seed in a painted region is counted as on-an-earlier-fill", (scr3.seeds_ok, scr3.seeds_on_fill), (1, 1))
    refused("a wrong signature is refused", b"X" + blob[1:], "signature")
    refused("a boot sector without its strings is refused", blob[:0x200] + b"\0" * 0x200 + blob[0x400:], "boot sector")
    broken = bytearray(blob)
    broken[0x400 + 12 + 4] += 1                         # R2's c0, one byte later
    refused("a broken chain is refused", bytes(broken), "chain")
    past = bytearray(blob)
    past[0x400 + 2] = 0xFF                              # R1's a1 high byte
    refused("a body past the end of the file is refused", bytes(past), "past the file")
    noterm = bytearray(blob)
    noterm[0x400 + 5 * 12 + 8] = 2                      # give the terminator a length
    noterm[0x400 + 5 * 12 + 9:0x400 + 5 * 12 + 11] = b"ZZ"
    refused("a record with a name but zero coordinates breaks the chain", bytes(noterm), "chain")
    try:
        records(box[:-1])
        checks.append(("a body that is not a multiple of 5 is refused", False, "it parsed"))
    except DatError as exc:
        checks.append(("a body that is not a multiple of 5 is refused", "multiple of 5" in str(exc), str(exc)))
    try:
        records(box[:-5])
        checks.append(("a body without 0xFF is refused", False, "it parsed"))
    except DatError as exc:
        checks.append(("a body without 0xFF is refused", "0xFF" in str(exc), str(exc)))
    want("the pattern region is 256 bytes and index 0xFD wraps to entry 61", (len(PATTERNS), pattern_index(0xFD, 0, 0) // 4), (256, 61))
    art = ascii_rows(render(blob, d, ["R1"]))
    want("the text render of the box is 40 rows of 70 with a '%' block inside and a '#' edge",
         (len(art), art[5][7], art[2][5]), (40, "%", "#"))

    # -- the object, when it is beside the box --
    obj = object_path if object_path else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), OBJECT_REL)
    if os.path.isdir(obj):
        obj = os.path.join(obj, "GAME.DAT")
    exe = os.path.join(os.path.dirname(obj), "FORGE.EXE")
    if os.path.isfile(obj):
        before = len(checks)
        real = open(obj, "rb").read()
        rd = parse(real)
        e = rd["entries"]
        want("GAME.DAT is 512 + 163,840 bytes", len(real), 164352)
        want("120 entries with a body, first HEA at 3072, last G9 ending at 146679",
             (len(e), e[0]["name"], e[0]["start"], e[-1]["name"], e[-1]["end"]), (120, "HEA", 3072, "G9", 146679))
        want("the tail is 17,673 bytes of 0xF6", (rd["tail"], rd["tail_f6"]), (17673, True))
        rooms, objs = picture_names(rd)
        want("75 rooms R1..R76 with R50 absent, 28 objects O1..O28",
             (len(rooms), "R50" in rooms, rooms[0], rooms[-1], len(objs), objs[0], objs[-1]),
             (75, False, "R1", "R76", 28, "O1", "O28"))
        want("HEA and FO are MZ; FO's header words equal FORGE.EXE's numbers (349, 121, 776, cs 0964)",
             (is_mz(body(real, rd["by_name"]["HEA"])), is_mz(body(real, rd["by_name"]["FO"])),
              [mz_header(body(real, rd["by_name"]["FO"]))[k] for k in ("cblp", "cp", "crlc", "cs")]),
             (True, True, [349, 121, 776, 0x964]))
        want("FO carries the pattern table at 0x866D byte for byte",
             body(real, rd["by_name"]["FO"])[PATTERN_AT:PATTERN_AT + len(PATTERNS)] == PATTERNS, True)
        want("HDR is 16,512 zero bytes", (rd["by_name"]["HDR"]["size"], not body(real, rd["by_name"]["HDR"]).strip(b"\0")),
             (16512, True))
        st = picture_stats(real, rd)
        want("every room and object body parses; every room opens with a mode record",
             (st["bad"], st["first_is_mode"]), ([], 75))
        want("x never exceeds 280 and y never 159; patterns 0..35 plus the one 0xFD of R46",
             (st["xmax"], st["ymax"], sorted(p for p in st["patterns"] if p >= N_PATTERNS), st["patterns"][0xFD]),
             (280, 159, [0xFD], 1))
        tot, _per = seed_census(real, rd)
        want("of 2,849 room fill seeds 2,647 land on white, 182 on an earlier fill, 18 on a line, 2 in the strip",
             (tot["white"], tot["fill"], tot["line"], tot["off"]), (2647, 182, 18, 2))
        names = slot_names(real, rd)
        s = body(real, rd["by_name"]["STR"])
        want("slot G9 is byte-identical to STR and FLS names it 'Not Saved'; QUK == STR",
             (body(real, rd["by_name"]["G9"]) == s, names[9], body(real, rd["by_name"]["QUK"]) == s),
             (True, "Not Saved", True))
        want("the other nine slots differ from STR", sum(1 for k in range(9) if body(real, rd["by_name"]["G%d" % k]) != s), 9)
        vb, nn = vocab(body(real, rd["by_name"]["FO"]))
        want("the engine's verb table is 84 words for 61 ids and the noun table 94 for 73; RABBIT is noun 28",
             (len(vb[2]), len(set(v for _w, v in vb[2])), len(nn[2]), len(set(v for _w, v in nn[2])),
              [w for w, v in nn[2] if v == 28]), (84, 61, 94, 73, ["RABBIT"]))
        if os.path.isfile(exe):
            cmp_ = exe_compare(real, rd, open(exe, "rb").read())
            want("FORGE.EXE differs from FO in 151 bytes over 15 ranges and FO carries 35 zero bytes past it",
                 (cmp_["diff"], len(cmp_["ranges"]), cmp_["fo_tail"] == b"\0" * 35), (151, 15, True))
        else:
            checks.append(("FORGE.EXE beside GAME.DAT", False, "missing, cannot compare"))
        want("R1's first line record (60 98 60 11 00) decodes to (96,152)-(96,17) in colour 0",
             decode(records(body(real, rd["by_name"]["R1"]))[1]), ("line", 96, 152, 96, 17, 0))
        grew = len(checks) - before
        checks.append(("the object block contributes the %d checks the skip figure promises" % OBJECT_CHECKS,
                       grew == OBJECT_CHECKS, "it contributed %d" % grew))
    else:
        skipped.append((OBJECT_CHECKS, "%s not beside the box; pass --object DIR to run them" % OBJECT_REL))

    checks.append(("dirguard.want_file is imported", hasattr(dirguard, "want_file"), ""))
    checks.append(("nameguard.guard is imported", hasattr(nameguard, "guard"), ""))
    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print("  %-*s  %s%s" % (width, label, "ok" if ok else "FAIL", "" if ok else "   " + detail))
    for count, why in skipped:
        print("  %-*s  SKIP   %d checks: %s" % (width, "(object block)", count, why))
    bad = sum(1 for _l, ok, _d in checks if not ok)
    lost = sum(count for count, _why in skipped)
    print("%d checks, %d failures, %d skipped" % (len(checks), bad, lost))
    return 1 if bad else 0


# ----------------------------------------------------------------- main --

def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?")
    ap.add_argument("--dir", action="store_true", help="list the directory")
    ap.add_argument("--text", action="store_true", help="print the TXT entry (the intro)")
    ap.add_argument("--saves", action="store_true", help="the ten slot names and how far each save is from STR")
    ap.add_argument("--vocab", action="store_true", help="the parser's verb and noun tables, read from the engine in FO")
    ap.add_argument("--records", metavar="NAME", help="decode one picture's records")
    ap.add_argument("--render", metavar="NAME", help="render one room (or object) to --out")
    ap.add_argument("--ascii", metavar="NAME", help="render one room as 70 x 40 characters on stdout")
    ap.add_argument("--objects", default="", help="with --render: comma-separated objects drawn over the room")
    ap.add_argument("--palette", default="default", choices=sorted(PALETTES))
    ap.add_argument("--scale", type=int, default=1)
    ap.add_argument("--out", default=None)
    ap.add_argument("--sheet", metavar="PNG", help="all 75 rooms on one contact sheet")
    ap.add_argument("--extract", metavar="NAME", help="write one body to --out")
    ap.add_argument("--exe", metavar="FORGE.EXE", help="compare the FO entry with the program")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--object", default=None, help="the GAME.DAT (or its folder) for --selftest, when the box has travelled")
    args = ap.parse_args()
    if args.selftest:
        raise SystemExit(selftest(args.object))
    if not args.file:
        ap.error("give a GAME.DAT, or --selftest")
    dirguard.want_file(args.file, "forgedat")
    blob = open(args.file, "rb").read()
    try:
        d = parse(blob)
        if args.dir:
            cmd_dir(blob, d)
        elif args.text:
            sys.stdout.write(body(blob, d["by_name"]["TXT"]).decode("cp437").replace("\r", "\n"))
        elif args.saves:
            cmd_saves(blob, d)
        elif args.vocab:
            cmd_vocab(blob, d)
        elif args.records:
            cmd_records(blob, d, args.records)
        elif args.render:
            if not args.out:
                ap.error("--render needs --out")
            names = [args.render] + [o for o in args.objects.split(",") if o]
            scr = render(blob, d, names, args.palette)
            write_png(args.out, scr.rgb_rows(args.palette, scale=args.scale), 320 * args.scale)
            print("wrote %s: %s, mode 0x%02X, %d fill seeds on white, %d on ink"
                  % (args.out, " + ".join(names), scr.mode or 0, scr.seeds_ok, scr.seeds_blocked))
        elif args.ascii:
            names = [args.ascii] + [o for o in args.objects.split(",") if o]
            scr = render(blob, d, names, args.palette)
            print("%s  (280 x 160 pixels in 4 x 4 cells; # line  @ black  : colour 1  %% colour 2  space white)" % " + ".join(names))
            for line in ascii_rows(scr):
                print("|" + line.ljust(70) + "|")
        elif args.extract:
            if not args.out:
                ap.error("--extract needs --out")
            e = d["by_name"].get(args.extract)
            if not e:
                raise DatError("no entry named %s" % args.extract)
            open(args.out, "wb").write(body(blob, e))
            print("wrote %s: %d bytes" % (args.out, e["size"]))
        elif args.exe:
            dirguard.want_file(args.exe, "forgedat")
            c = exe_compare(blob, d, open(args.exe, "rb").read())
            print("FO %d bytes, %s %d bytes, headers %s, %d differing bytes in %d ranges, FO tail past the EXE: %d bytes%s"
                  % (c["fo"], os.path.basename(args.exe), c["exe"], "equal" if c["same_header"] else "DIFFERENT",
                     c["diff"], len(c["ranges"]), len(c["fo_tail"]), " (all zero)" if c["fo_tail"] and not c["fo_tail"].strip(b"\0") else ""))
            fo = body(blob, d["by_name"]["FO"])
            exe = open(args.exe, "rb").read()
            for s, e2 in c["ranges"]:
                print("  0x%05X..0x%05X %3d B  disk: %s" % (s, e2, e2 - s, fo[s:e2][:16].hex(" ")))
                print("                         exe : %s" % exe[s:e2][:16].hex(" "))
        else:
            raise SystemExit(cmd_validate(args.file, blob, d))
    except DatError as exc:
        sys.exit("forgedat: %s: %s" % (os.path.basename(args.file), exc))


if __name__ == "__main__":
    main()
