#!/usr/bin/env python3
"""flc.py -- read a STANDARD Autodesk Animator Pro FLC (128-byte header),
selected by its magic and by the file length it carries in its first four
bytes, reusing the chunk decoders of `bfflic.py` without touching them.

WHY A SECOND FLC READER
-----------------------
`bfflic.py` was written for Theme Park's seventeen animations, whose header is
the first TWELVE bytes of Autodesk's and whose frames start at offset 12; it
checks `u32 at 0 == 12` and refuses anything else, and its selftest asserts
that a genuine 128-byte-header FLC is refused. That assertion is right for
that tool and must stay. `SWIAT.DAT` of Polanie is the genuine article:

    +0    u32   11,090,932   the file's own length
    +4    u16   0xAF12       Animator Pro FLC
    +6    u16   371          frames, EXCLUDING the ring frame
    +8    u16   320          width
    +10   u16   200          height
    +12   u16   8            depth
    +14   u16   flags
    +16   u32   71           ms per frame (an FLC's speed is in ms)
    +22   u32   created      DOS date/time
    +26   u32   creator      serial of the Animator Pro that wrote it
    +30   u32   updated
    +34   u32   updater
    +38   u16   6, u16 5     aspect dx:dy (Animator Pro's for 320x200)
    +80   u32   oframe1      offset of the FIRST frame (frame 0 here)
    +84   u32   oframe2      offset of the second (frame 1 here)
    +128               a PREFIX chunk (type 0xF100) may sit here; it
                       carries Animator Pro's settings and the file paths
                       of the machine that made it, and it is skipped by
                       its own size. Then the frames (0xF1FA), 16-byte
                       headers, chunks with u32 size and u16 type.

The header is Autodesk's published one and is read as such. The chunk
vocabulary is the same public one `bfflic.py` decodes -- COLOR_256 (4),
DELTA_FLC (7), COLOR_64 (11), DELTA_FLI (12), BLACK (13), BYTE_RUN (15),
LITERAL (16) -- and those functions are IMPORTED from `bfflic.py`, not
copied: one decoder, two headers.

THE CLOSURES
------------
  * `u32 at 0` must equal the file length, and the magic must be 0xAF12;
  * `oframe1`, when non-zero, must be where the walk finds its first frame
    -- i.e. 128 plus the prefix chunk, if any -- and `oframe2` its second
    (the first draft of this tool read them as frames 1 and 2 and SWIAT.DAT
    refused it: the file was right);
  * the chunk walk from 128 must land on the file length, residue 0;
  * the frames walked must be the declared count plus one (the ring frame);
  * every frame's declared size must equal the sum of its chunks.

    python tools/flc.py validate <file>
    python tools/flc.py frames   <file> [n]            the frame table
    python tools/flc.py render   <file> <n> <out.png>  decode frame n
    python tools/flc.py sample   <file> <outdir> [every]  PNGs, every k-th frame
    python tools/flc.py scenes   <file>                palette changes and cuts
    python tools/flc.py selftest
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bfflic     # noqa: E402  the four decoders and write_png
import dirguard   # noqa: E402
import nameguard  # noqa: E402

MAGIC = 0xAF12
MAGIC_FLI = 0xAF11
FRAME_MAGIC = 0xF1FA
PREFIX_MAGIC = 0xF100
HDR_LEN = 128


class Refused(Exception):
    """The file is not one of these. Raised loudly and never swallowed."""


def header(d):
    if len(d) < HDR_LEN + 16:
        raise Refused("shorter than a 128-byte header plus one frame header")
    (size, magic, frames, w, h, depth, flags, speed, _res, created, creator,
     updated, updater, adx, ady) = struct.unpack_from("<IHHHHHHIHIIIIHH", d, 0)
    oframe1, oframe2 = struct.unpack_from("<II", d, 80)
    if magic == MAGIC_FLI:
        raise Refused("magic 0xAF11 is an Animator FLI (1/70 s, 64-colour); "
                      "this reader takes the Pro FLC only")
    if magic != MAGIC:
        raise Refused("magic at offset 4 is 0x%04X, not 0x%04X" % (magic, MAGIC))
    if size == 12:
        raise Refused("u32 at 0 is 12: the truncated 12-byte-header variant, "
                      "which is bfflic.py's")
    if size != len(d):
        raise Refused("u32 at 0 is %d, the file is %d bytes" % (size, len(d)))
    if not (0 < w <= 4096 and 0 < h <= 4096):
        raise Refused("implausible dimensions %dx%d" % (w, h))
    if depth != 8:
        raise Refused("depth %d, not 8" % depth)
    return dict(size=size, magic=magic, frames=frames, w=w, h=h, depth=depth,
                flags=flags, speed=speed, created=created, creator=creator,
                updated=updated, updater=updater, aspect=(adx, ady),
                oframe1=oframe1, oframe2=oframe2)


def walk(d):
    """Every frame by summing chunk lengths. Returns (header, prefix,
    frames, residue). A frame is (offset, declared, true, nchunks,
    [(type, size)]); prefix is (offset, size) or None."""
    h = header(d)
    p = HDR_LEN
    prefix = None
    if p + 6 <= len(d):
        psize, ptype = struct.unpack_from("<IH", d, p)
        if ptype == PREFIX_MAGIC:
            if psize < 6 or p + psize > len(d):
                raise Refused("prefix chunk of %d bytes does not fit" % psize)
            prefix = (p, psize)
            p += psize
    out = []
    while p + 16 <= len(d):
        size, magic, nchunks = struct.unpack_from("<IHH", d, p)
        if magic != FRAME_MAGIC:
            raise Refused("frame %d at %d has magic 0x%04X" % (len(out), p, magic))
        q = p + 16
        chunks = []
        for _ in range(nchunks):
            if q + 6 > len(d):
                raise Refused("chunk header past end at %d" % q)
            csize, ctype = struct.unpack_from("<IH", d, q)
            if csize < 6 or q + csize > len(d):
                raise Refused("chunk of %d bytes at %d does not fit" % (csize, q))
            chunks.append((ctype, csize))
            q += csize
        if size != q - p:
            raise Refused("frame %d declares %d bytes, its chunks sum to %d"
                          % (len(out), size, q - p))
        out.append((p, size, q - p, nchunks, chunks))
        p = q
    if p != len(d):
        raise Refused("walk ends at %d, file is %d: residue %d"
                      % (p, len(d), len(d) - p))
    for k, key in ((0, "oframe1"), (1, "oframe2")):
        if h[key] and len(out) > k and out[k][0] != h[key]:
            raise Refused("%s says frame %d is at %d, the walk found it at %d"
                          % (key, k, h[key], out[k][0]))
    if len(out) != h["frames"] + 1:
        raise Refused("%d frames declared (+1 ring), %d walked"
                      % (h["frames"], len(out)))
    return h, prefix, out, len(d) - p


def apply_frame(d, frame, img, pal, w, ht):
    """One frame's chunks through bfflic's decoders. Returns the image
    (BLACK replaces it) and the set of chunk types met."""
    off, decl, true, n, chunks = frame
    q = off + 16
    seen = set()
    damage = None
    for ctype, csize in chunks:
        buf = d[q + 6:q + csize]
        seen.add(ctype)
        try:
            if ctype == 4:
                bfflic._color256(buf, pal, True)
            elif ctype == 11:
                bfflic._color256(buf, pal, False)
            elif ctype == 15:
                bfflic._byte_run(buf, img, w, ht)
            elif ctype == 16:
                bfflic._literal(buf, img, w, ht)
            elif ctype == 12:
                bfflic._delta_fli(buf, img, w, ht)
            elif ctype == 7:
                bfflic._delta_flc(buf, img, w, ht)
            elif ctype == 13:
                img = bytearray(w * ht)
            elif ctype == 18:
                pass                  # PSTAMP: a thumbnail, not the frame
            else:
                raise Refused("chunk type %d at %d is not in the vocabulary"
                              % (ctype, q))
        except (IndexError, struct.error):
            # A chunk whose packets run past its own end. SWIAT.DAT has ONE
            # (frame 85, a DELTA_FLI whose line 40 skips 241 pixels and
            # whose data is spent at line 166 of 200): the frame is damaged
            # in the file, and an Autodesk player would have painted it as
            # far as the bytes go and read the next frame's bytes as the
            # rest. This keeps what was painted, says so, and goes on; the
            # count of such frames is a measurement of the file, reported
            # by `scenes` and `sample`.
            damage = "%s chunk of %d bytes runs out before its last line" % (
                bfflic.CHUNK_NAMES.get(ctype, ctype), csize)
        q += csize
    return img, seen, damage


def decode(d, upto, callback=None):
    """Decode frames 0..upto inclusive. `callback(i, img, pal, seen, damage)`
    is called after each frame. Returns (image, palette, header, damaged),
    the last a list of (frame, what) for chunks that ran out."""
    h, prefix, frames, residue = walk(d)
    w, ht = h["w"], h["h"]
    img = bytearray(w * ht)
    pal = [(0, 0, 0)] * 256
    damaged = []
    for i, fr in enumerate(frames):
        if i > upto:
            break
        img, seen, damage = apply_frame(d, fr, img, pal, w, ht)
        if damage:
            damaged.append((i, damage))
        if callback:
            callback(i, img, pal, seen, damage)
    return img, pal, h, damaged


def _stamp(v):
    """`created`/`updated`, printed BOTH ways, because the two readings
    disagree and the file cannot say which it meant: Autodesk's text calls
    the field an MS-DOS date/time (time in the low word, date in the high),
    but the value in SWIAT.DAT read as a C `time_t` (seconds since 1970)
    lands on the same day as the object's other 1996 clocks, and read as a
    DOS stamp lands in 2004, a year nothing else in the object names. The
    tool prints both and the reader chooses with the other clocks."""
    import datetime
    t, dt = v & 0xFFFF, v >> 16
    y, mo, da = 1980 + (dt >> 9), (dt >> 5) & 0xF, dt & 0x1F
    hh, mm, ss = t >> 11, (t >> 5) & 0x3F, (t & 0x1F) * 2
    if 1 <= mo <= 12 and 1 <= da <= 31 and hh < 24 and mm < 60 and ss < 60:
        dos = "%04d-%02d-%02d %02d:%02d:%02d" % (y, mo, da, hh, mm, ss)
    else:
        dos = "not a DOS date/time"
    unix = (datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=v)
            ).strftime("%Y-%m-%d %H:%M:%S")
    return "%08Xh = as time_t %s | as DOS stamp %s" % (v, unix, dos)


def cmd_validate(path):
    d = open(path, "rb").read()
    try:
        h, prefix, frames, residue = walk(d)
    except Refused as e:
        print("REFUSED  %s: %s" % (os.path.basename(path), e))
        return 1
    print("%s  %d bytes" % (os.path.basename(path), len(d)))
    print("  u32 at 0        %d  == file length" % h["size"])
    print("  magic           0x%04X  Animator Pro FLC" % h["magic"])
    print("  frames declared %d  (+1 ring frame = %d walked)"
          % (h["frames"], len(frames)))
    print("  dimensions      %d x %d x %d bits, aspect %d:%d"
          % (h["w"], h["h"], h["depth"], h["aspect"][0], h["aspect"][1]))
    print("  speed           %d ms per frame -> %.1f s for %d frames"
          % (h["speed"], h["speed"] * h["frames"] / 1000.0, h["frames"]))
    print("  flags           0x%04X" % h["flags"])
    print("  created         %s" % _stamp(h["created"]))
    print("  updated         %s" % _stamp(h["updated"]))
    print("  creator/updater %08Xh / %08Xh (Animator Pro serials)"
          % (h["creator"], h["updater"]))
    print("  prefix chunk    %s"
          % ("%d bytes at 128 (type F100h)" % prefix[1] if prefix else "none"))
    print("  oframe1/2       %d / %d  (walk: %d / %d)"
          % (h["oframe1"], h["oframe2"], frames[0][0],
             frames[1][0] if len(frames) > 1 else 0))
    print("  chunk walk      128 .. %d, residue %d" % (len(d) - residue, residue))
    tot = {}
    for fr in frames:
        for t, s in fr[4]:
            tot[t] = tot.get(t, 0) + 1
    print("  chunk types     %s"
          % " ".join("%s:%d" % (bfflic.CHUNK_NAMES.get(t, t), c)
                     for t, c in sorted(tot.items())))
    return 0


def cmd_frames(path, limit=None):
    d = open(path, "rb").read()
    h, prefix, frames, residue = walk(d)
    print("%s  %d bytes, %d x %d, %d declared (+1), %d walked, prefix %s"
          % (os.path.basename(path), len(d), h["w"], h["h"], h["frames"],
             len(frames), prefix[1] if prefix else "none"))
    print("%6s %10s %10s  %s" % ("frame", "offset", "size", "chunks"))
    for i, (off, decl, true, n, chunks) in enumerate(frames):
        if limit and i >= limit:
            print("  ... %d more" % (len(frames) - limit))
            break
        cs = " ".join("%s/%d" % (bfflic.CHUNK_NAMES.get(t, str(t)), s)
                      for t, s in chunks)
        print("%6d %10d %10d  %s" % (i, off, decl, cs))
    print("residue after the last frame: %d" % residue)
    return 0


def cmd_scenes(path, threshold=0.5):
    """Decode everything; report every palette chunk and every frame that
    changes more than `threshold` of the pixels -- the cuts."""
    d = open(path, "rb").read()
    h, prefix, frames, residue = walk(d)
    w, ht = h["w"], h["h"]
    prev = None
    rows = []

    def cb(i, img, pal, seen, damage):
        nonlocal prev
        changed = None
        if prev is not None:
            changed = sum(1 for a, b in zip(prev, img) if a != b)
        palchange = bool(seen & {4, 11})
        full = bool(seen & {15, 16, 13})
        rows.append((i, changed, palchange, full, sorted(seen), damage))
        prev = bytes(img)

    decode(d, len(frames), cb)
    n = w * ht
    print("%s: %d frames, cut threshold %.0f %% of %d pixels"
          % (os.path.basename(path), len(rows), threshold * 100, n))
    cuts = 0
    for i, changed, palchange, full, seen, damage in rows:
        flag = []
        if palchange:
            flag.append("PALETTE")
        if full:
            flag.append("FULL")
        if changed is not None and changed >= threshold * n:
            flag.append("CUT")
            cuts += 1
        if damage:
            flag.append("DAMAGED(%s)" % damage)
        if flag or i == 0:
            print("  frame %4d  changed %6s  %s  types %s"
                  % (i, "-" if changed is None else changed, " ".join(flag),
                     " ".join(bfflic.CHUNK_NAMES.get(t, str(t)) for t in seen)))
    quiet = sum(1 for r in rows if r[1] == 0)
    print("  cuts %d, palette chunks %d, full frames %d, frames with 0 "
          "changed pixels %d, damaged frames %d of %d"
          % (cuts, sum(1 for r in rows if r[2]), sum(1 for r in rows if r[3]),
             quiet, sum(1 for r in rows if r[5]), len(rows)))
    hist = {}
    for r in rows:
        if r[1] is not None:
            b = min(r[1] * 10 // n, 9)
            hist[b] = hist.get(b, 0) + 1
    print("  changed-pixel deciles: %s"
          % " ".join("%d0-%d0%%:%d" % (k, k + 1, v) for k, v in sorted(hist.items())))
    return 0


def cmd_sample(path, outdir, every=10, upto=None):
    d = open(path, "rb").read()
    h, prefix, frames, residue = walk(d)
    os.makedirs(outdir, exist_ok=True)
    last = len(frames) - 1 if upto is None else upto
    written = []

    def cb(i, img, pal, seen, damage):
        if i % every == 0 or i == last:
            out = os.path.join(outdir, "frame%04d.png" % i)
            bfflic.write_png(out, img, pal, h["w"], h["h"])
            written.append(out)

    img, pal, h, damaged = decode(d, last, cb)
    print("%d frames of %d written to %s (every %d, and the last); %d "
          "damaged frame(s)%s"
          % (len(written), len(frames), outdir, every, len(damaged),
             ": " + ", ".join("%d (%s)" % x for x in damaged) if damaged
             else ""))
    return 0


# --- selftest -------------------------------------------------------------

def _specimen(frames=None, prefix=b"", size=None, magic=MAGIC, w=320, h=200,
              depth=8, oframe1=None):
    body = prefix + b"".join(frames or [])
    total = HDR_LEN + len(body) if size is None else size
    hdr = bytearray(HDR_LEN)
    struct.pack_into("<IHHHHHHI", hdr, 0, total, magic, max(len(frames or []) - 1, 0),
                     w, h, depth, 3, 71)
    struct.pack_into("<HH", hdr, 38, 6, 5)
    o1 = HDR_LEN + len(prefix)
    o2 = o1 + (len(frames[0]) if frames else 0)
    if oframe1 is not None:
        o1 = oframe1
    struct.pack_into("<II", hdr, 80, o1, o2 if frames and len(frames) > 1 else 0)
    return bytes(hdr) + body


def cmd_selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-56s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    brun = b""
    for _ in range(200):
        brun += bytes([4, 80, 7, 80, 7, 80, 7, 80, 7])
    pal = struct.pack("<H", 1) + bytes([0, 0]) + bytes([255, 0, 0] * 256)
    f0 = bfflic._one_frame([(4, pal), (15, brun)])
    ring = bfflic._one_frame([(13, b"")])
    prefix = struct.pack("<IH", 6 + 40, PREFIX_MAGIC) + b"C:\\SOMEWHERE\\" + b"\0" * 27
    good = _specimen([f0, ring], prefix)
    try:
        h, pfx, frames, residue = walk(good)
        check("a correct file with a prefix chunk walks", True)
        check("prefix chunk seen, 46 bytes", pfx == (128, 46))
        check("two frames (1 declared + ring), residue 0",
              len(frames) == 2 and residue == 0)
        check("oframe1/oframe2 agree with the walk",
              h["oframe1"] == frames[0][0] and h["oframe2"] == frames[1][0])
    except Refused as e:
        check("a correct file with a prefix chunk walks", False, str(e))
    img, palette, h, dmg = decode(good, 0)
    check("frame 0 decodes to index 7 everywhere, 8-bit palette",
          set(img) == {7} and palette[0] == (255, 0, 0) and len(img) == 64000)
    img, palette, h, dmg = decode(good, 1)
    check("the ring BLACK frame clears it, nothing damaged",
          set(img) == {0} and dmg == [])
    # a DELTA_FLI that runs out: painted as far as it goes, counted, not fatal
    short = bfflic._one_frame([(12, struct.pack("<HH", 0, 2)
                                    + bytes([1, 0, 3, 9, 9, 9]))])
    img, palette, h, dmg = decode(_specimen([f0, short], prefix), 1)
    check("a delta chunk that runs out is painted, counted, survived",
          len(dmg) == 1 and dmg[0][0] == 1 and img[0:3] == b"\x09\x09\x09"
          and img[3] == 7)

    refusals = [
        ("the 12-byte-header variant (bfflic's)",
         struct.pack("<IHHHH", 12, MAGIC, 1, 320, 200) + f0 + b"\0" * 200,
         "12"),
        ("u32 at 0 not the file length", _specimen([f0], size=99), "file is"),
        ("magic 0xAF11 (an FLI)", _specimen([f0], magic=MAGIC_FLI), "FLI"),
        ("depth 4", _specimen([f0], depth=4), "depth"),
        ("oframe1 pointing elsewhere", _specimen([f0, ring], oframe1=5000),
         "oframe1"),
        ("a chunk running past the end",
         _specimen([struct.pack("<IHH", 40, FRAME_MAGIC, 1) + b"\0" * 8
                    + struct.pack("<IH", 1 << 20, 15)]), "fit"),
        ("frame size not the sum of its chunks",
         _specimen([struct.pack("<IHH", 40, FRAME_MAGIC, 1) + b"\0" * 8
                    + struct.pack("<IH", 6, 13)]), "sum"),
    ]
    for label, data, needle in refusals:
        try:
            walk(data)
            check("refuses %s" % label, False, "accepted")
        except Refused as e:
            check("refuses %s" % label, needle in str(e), str(e))
    # frame count off by one: fix the declared count so only the walk differs
    bad = bytearray(_specimen([f0, ring, ring]))
    struct.pack_into("<H", bad, 6, 1)
    try:
        walk(bytes(bad))
        check("refuses 1 declared, 3 walked", False)
    except Refused as e:
        check("refuses 1 declared, 3 walked", "walked" in str(e))
    # bfflic must still refuse this file: one decoder, two headers, no leak
    try:
        bfflic.walk(good)
        check("bfflic.py still refuses the 128-byte header", False)
    except bfflic.Refused:
        check("bfflic.py still refuses the 128-byte header", True)
    print("\nflc.py selftest: %d failures, 0 skipped (specimens are built)"
          % fails)
    return 1 if fails else 0


def main(argv):
    nameguard.guard()
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "selftest":
        return cmd_selftest()
    if not rest:
        print("flc.py %s: no input" % cmd)
        return 2
    dirguard.want_file(rest[0], "flc.py")
    if cmd == "validate":
        return cmd_validate(rest[0])
    if cmd == "frames":
        return cmd_frames(rest[0], int(rest[1]) if len(rest) > 1 else None)
    if cmd == "render":
        d = open(rest[0], "rb").read()
        n = int(rest[1])
        img, pal, h, damaged = decode(d, n)
        bfflic.write_png(rest[2], img, pal, h["w"], h["h"])
        print("frame %d of %s -> %s (%dx%d)%s"
              % (n, os.path.basename(rest[0]), rest[2], h["w"], h["h"],
                 "; damaged frames on the way: %s" % damaged if damaged
                 else ""))
        return 0
    if cmd == "sample":
        return cmd_sample(rest[0], rest[1], int(rest[2]) if len(rest) > 2 else 10)
    if cmd == "scenes":
        return cmd_scenes(rest[0])
    print("unknown command %r" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
