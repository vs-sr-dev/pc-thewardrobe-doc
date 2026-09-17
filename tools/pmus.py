#!/usr/bin/env python3
"""pmus.py -- open the two `PMUS` files, which are MPEG under eight bytes of XOR.

Final Fantasy XI ships two video files and neither had been opened:

    FINAL FANTASY XI\\mov\\mov999.pmv                     315,815,512 bytes
    PlayOnlineViewer\\viewer\\data\\system\\Movie\\opening.pms  8,040,456 bytes

Both begin `PMUS`, both are registered by `installscript.vdf` as a DirectShow
media type whose detection string is `0, 4, FFFFFFFF, 504D5553`, and the
filter that decodes them, `polmvfINT.dll`, is packed: its `.text` section has
a raw size of zero and its code lives in a section called `POL1` at entropy
7.3966.  So the decoder was not read.  The bytes were.

HOW IT WAS FOUND, WITHOUT GUESSING

1. `.PMV` has a mean block entropy of **4.9864**, which is impossibly low for
   video, so something in it repeats.

2. The byte histogram says what: the **eight** commonest byte values in
   `mov999.pmv` are `C2 EE 9C D9 BD 6C 4D 72` and each of them is 8.36 % of
   the file -- two thirds of 315 megabytes in eight values, at equal
   frequency.  The same eight dominate `opening.pms`.

3. Eight equifrequent values is the signature of a **repeating eight-byte
   keystream over a plaintext that is mostly one constant byte**.  Taking the
   per-position histogram modulo 8, aligned to file offset 0, each position is
   dominated by exactly one of the eight -- at **81.4 %** in `.pmv` and 18.0 %
   in `.pms` -- and the winners in positional order are

       C2 EE 9C D9 BD 6C 4D 72

   which is therefore the key if the common plaintext byte is 0x00.

4. It is.  XOR the file with that key indexed by absolute offset and byte 4 of
   `mov999.pmv` is `00 00 01 B3`, the MPEG **sequence header** start code, and
   byte 4 of `opening.pms` is `00 00 01 BA`, the MPEG **pack header** start
   code.  The four bytes of `PMUS` are in clear and the keystream runs
   underneath them anyway.

THE CONTROL

The identical procedure -- recover an eight-byte key by per-position histogram,
XOR, look for MPEG start codes -- is run over files that are not `PMUS`.  If it
finds start codes there too, it has found nothing here.

Nothing is executed, nothing is contacted, nothing is written to the object,
and no frame is decoded or shipped: this tool reads structure, not pictures.

usage:
  pmus.py key   FILE [--sample N]
  pmus.py probe FILE [--key HEX] [--limit N]
  pmus.py control ROOT
"""

import argparse
import collections
import os
import struct
import sys

MAGIC = b"PMUS"
KEYLEN = 8

# MPEG-1/2 start codes, ISO/IEC 11172-1 and -2.
START = {
    0x00: "picture",
    0xB3: "sequence header",
    0xB8: "group of pictures",
    0xB9: "sequence end",
    0xBA: "pack header",
    0xBB: "system header",
    0xBD: "private stream 1",
    0xBE: "padding stream",
    0xBF: "private stream 2",
}
FRAME_RATE = {
    1: 24000 / 1001.0, 2: 24.0, 3: 25.0, 4: 30000 / 1001.0,
    5: 30.0, 6: 50.0, 7: 60000 / 1001.0, 8: 60.0,
}
ASPECT = {1: "1.0000 (square)", 2: "0.6735", 3: "0.7031", 4: "0.7615",
          5: "0.8055", 6: "0.8437", 7: "0.8935", 8: "0.9157",
          9: "0.9815", 10: "1.0255", 11: "1.0695", 12: "1.0950",
          13: "1.1575", 14: "1.2015"}


def recover_key(data):
    """Per-position histogram modulo KEYLEN, aligned to offset 0."""
    key = []
    share = []
    for i in range(KEYLEN):
        col = data[i::KEYLEN]
        c = collections.Counter(col)
        b, n = c.most_common(1)[0]
        key.append(b)
        share.append(n / float(len(col)))
    return bytes(key), share


def decrypt(data, key, base=0):
    return bytes(data[i] ^ key[(base + i) % KEYLEN] for i in range(len(data)))


def read_seq_header(x, off):
    """Parse an MPEG video sequence header starting at the byte after
    `00 00 01 B3`."""
    b = x[off:off + 8]
    if len(b) < 8:
        return None
    h = (b[0] << 4) | (b[1] >> 4)
    v = ((b[1] & 0x0F) << 8) | b[2]
    aspect = b[3] >> 4
    rate = b[3] & 0x0F
    bits = (b[4] << 10) | (b[5] << 2) | (b[6] >> 6)
    return {"width": h, "height": v, "aspect": aspect, "rate_code": rate,
            "fps": FRAME_RATE.get(rate), "bitrate_units": bits,
            "bitrate_bps": bits * 400}


def scan(x, counts):
    """Count MPEG start codes in a decrypted buffer."""
    i = 0
    n = len(x)
    first_seq = None
    while True:
        i = x.find(b"\x00\x00\x01", i)
        if i < 0 or i + 3 >= n:
            break
        code = x[i + 3]
        if code in START:
            counts[START[code]] += 1
        elif 0x01 <= code <= 0xAF:
            counts["slice"] += 1
        elif 0xC0 <= code <= 0xDF:
            counts["audio stream"] += 1
        elif 0xE0 <= code <= 0xEF:
            counts["video stream"] += 1
        else:
            counts["other 0x%02X" % code] += 1
        if code == 0xB3 and first_seq is None:
            first_seq = i + 4
        i += 3
    return first_seq


def cmd_key(args):
    with open(args.file, "rb") as fh:
        data = fh.read(args.sample)
    magic = data[:4]
    key, share = recover_key(data)
    print("%s" % args.file)
    print("  size read        : %d" % len(data))
    print("  first four bytes : %r  %s" % (magic,
          "PMUS" if magic == MAGIC else "NOT PMUS"))
    print("  key recovered by per-position histogram, aligned to offset 0:")
    print("    %s" % " ".join("%02X" % b for b in key))
    print("  share of each position taken by its winner:")
    print("    %s" % "  ".join("%.1f%%" % (s * 100) for s in share))
    print("  mean share : %.2f %%" % (100.0 * sum(share) / KEYLEN))
    x = decrypt(data[:64], key)
    print("  first 16 bytes after XOR:")
    print("    %s" % x[:16].hex(" "))
    if x[4:7] == b"\x00\x00\x01":
        print("  -> byte 4 is an MPEG start code 0x%02X (%s)"
              % (x[7], START.get(x[7], "?")))
    else:
        print("  -> byte 4 is NOT an MPEG start code")
    return 0


def cmd_probe(args):
    key = (bytes.fromhex(args.key) if args.key else None)
    size = os.path.getsize(args.file)
    with open(args.file, "rb") as fh:
        head = fh.read(4 << 20)
    if key is None:
        key, _share = recover_key(head)
    print("%s" % args.file)
    print("  size            : %d bytes" % size)
    print("  magic           : %r" % head[:4])
    print("  key             : %s" % " ".join("%02X" % b for b in key))

    counts = collections.Counter()
    zero = 0
    total = 0
    first_seq_off = None
    seq = None
    with open(args.file, "rb") as fh:
        base = 0
        carry = b""
        while True:
            chunk = fh.read(1 << 22)
            if not chunk:
                break
            x = decrypt(chunk, key, base)
            zero += x.count(0)
            total += len(x)
            buf = carry + x
            fs = scan(buf, counts)
            if first_seq_off is None and fs is not None:
                first_seq_off = base - len(carry) + fs
                seq = read_seq_header(buf, fs)
            carry = buf[-3:]
            base += len(chunk)
            if args.limit and base >= args.limit:
                break

    print("  bytes examined  : %d" % total)
    print("  zero bytes after XOR : %d = %.4f %%"
          % (zero, 100.0 * zero / max(1, total)))
    print()
    print("  MPEG start codes:")
    for k, v in counts.most_common(14):
        print("    %-22s %10d" % (k, v))
    if seq:
        print()
        print("  sequence header at offset %d:" % first_seq_off)
        print("    frame size        : %d x %d" % (seq["width"], seq["height"]))
        print("    aspect ratio code : %d  (%s)"
              % (seq["aspect"], ASPECT.get(seq["aspect"], "?")))
        print("    frame rate code   : %d  (%s fps)"
              % (seq["rate_code"],
                 ("%.3f" % seq["fps"]) if seq["fps"] else "?"))
        print("    bit rate          : %d units of 400 = %d bit/s"
              % (seq["bitrate_units"], seq["bitrate_bps"]))
        pics = counts["picture"]
        if seq["fps"] and pics:
            secs = pics / seq["fps"]
            print("    pictures counted  : %d" % pics)
            print("    duration          : %.2f s = %d m %02d s"
                  % (secs, secs // 60, secs % 60))
        if seq["bitrate_bps"]:
            secs2 = size * 8.0 / seq["bitrate_bps"]
            print("    duration from the declared bit rate : %.2f s = %d m %02d s"
                  % (secs2, secs2 // 60, secs2 % 60))
    return 0


def cmd_decrypt(args):
    """Write the plaintext out, for inspection with an ordinary player.

    The output is an MPEG stream and nothing else: no transcoding, no
    remuxing, no frame is decoded here.  It goes wherever the caller says,
    which is never the repository -- `.gitignore` excludes the working
    directory before it excludes anything else.
    """
    size = os.path.getsize(args.file)
    with open(args.file, "rb") as fh:
        head = fh.read(4 << 20)
    key = bytes.fromhex(args.key) if args.key else recover_key(head)[0]
    x = decrypt(head[:8], key)
    kind = START.get(x[7]) if x[4:7] == b"\x00\x00\x01" else None
    if kind is None and not args.force:
        print("byte 4 is not an MPEG start code after XOR; refusing.")
        print("first 8 bytes decrypt to %s" % x.hex(" "))
        return 2
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    # The four bytes of `PMUS` are in clear and the keystream runs underneath
    # them anyway, so decrypting them yields 92 A3 C9 8A -- four bytes of
    # nothing that a player would have to resynchronise past.  The payload
    # starts at 4 and so does the output; the key index stays absolute.
    skip = 4 if magic_is_pmus(args.file) else 0
    kb = key * 4096                       # 32 KiB of keystream, 8-aligned
    written = 0
    with open(args.file, "rb") as fh, open(args.out, "wb") as out:
        base = 0
        while True:
            chunk = fh.read(len(kb))
            if not chunk:
                break
            n = len(chunk)
            k = kb[:n] if n % KEYLEN == 0 else (key * (n // KEYLEN + 1))[:n]
            a = int.from_bytes(chunk, "big")
            b = int.from_bytes(k, "big")
            plain = (a ^ b).to_bytes(n, "big")
            if base < skip:
                plain = plain[skip - base:]
            out.write(plain)
            written += len(plain)
            base += n
    print("%s -> %s" % (args.file, args.out))
    print("  key      : %s" % " ".join("%02X" % c for c in key))
    print("  magic bytes dropped : %d" % skip)
    print("  bytes    : %d of %d" % (written, size))
    print("  starts as: %s  (%s)" % (x[4:8].hex(" "),
                                     kind or "not an MPEG start code"))
    return 0


def magic_is_pmus(path):
    with open(path, "rb") as fh:
        return fh.read(4) == MAGIC


def cmd_control(args):
    """The same procedure over files that are not PMUS."""
    print("CONTROL -- recover an 8-byte key by histogram, XOR, look for MPEG")
    print("start codes, on files that are NOT PMUS.  If this finds them, the")
    print("PMUS result means nothing.")
    print()
    picks = []
    for dirpath, _d, files in os.walk(args.root):
        for fn in files:
            e = os.path.splitext(fn)[1].lower()
            if e in (".dat", ".spw", ".bgw", ".dll", ".exe", ".png", ".chm"):
                picks.append((e, os.path.join(dirpath, fn)))
        if len(picks) > 3000:
            break
    seen = collections.Counter()
    hit = 0
    n = 0
    per_ext = collections.Counter()
    for e, p in picks:
        if seen[e] >= 40:
            continue
        seen[e] += 1
        try:
            data = open(p, "rb").read(1 << 20)
        except OSError:
            continue
        if len(data) < 4096:
            continue
        n += 1
        key, _s = recover_key(data)
        x = decrypt(data[:64], key)
        if x[4:7] == b"\x00\x00\x01" and x[7] in START:
            hit += 1
            per_ext[e] += 1
    print("  files tried                    : %d" % n)
    print("  files that produced a start code: %d" % hit)
    if per_ext:
        print("  by extension: %s" % dict(per_ext))
    print()
    if hit == 0:
        print("  CONTROL PASSES: the procedure finds MPEG in nothing it was")
        print("  not pointed at.")
    else:
        print("  CONTROL FAILS.")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("key")
    p.add_argument("file")
    p.add_argument("--sample", type=int, default=4 << 20)
    p.set_defaults(func=cmd_key)
    p = sub.add_parser("probe")
    p.add_argument("file")
    p.add_argument("--key")
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=cmd_probe)
    p = sub.add_parser("decrypt")
    p.add_argument("file")
    p.add_argument("--out", required=True)
    p.add_argument("--key")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_decrypt)
    p = sub.add_parser("control")
    p.add_argument("root")
    p.set_defaults(func=cmd_control)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
