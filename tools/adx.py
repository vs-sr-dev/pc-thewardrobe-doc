#!/usr/bin/env python3
"""adx.py -- CRI ADX reader and decoder. This is the thesis of the session.

109 loose .ADX files on this disc hold 455,967,110 bytes, 44.6134 % of the
high-density file bytes, and 4,088 more .ADX live inside the two .AFS archives.
455 million bytes is not one second of sound until the header is read.

THE HEADER, DERIVED AND THEN STATED
-----------------------------------

The first eight bytes were in the pre-briefing: 80 00 00 20 03 12 04 02. The
rest was read off the files. All multi-byte fields are BIG-ENDIAN, which is the
finding worth having: the .AFS archive that contains these files stores its
entry table LITTLE-endian on the same disc, from the same vendor, for the same
machine.

    +0   2  u16 BE  0x8000
    +2   2  u16 BE  copyright offset. The six bytes '(c)CRI' sit at this
                    value minus 2; the sample data begins at this value plus 4.
    +4   1          encoding type. 3 = standard ADX ADPCM.
    +5   1          block size in bytes, per channel. 18 on this disc.
    +6   1          bits per sample. 4.
    +7   1          channel count.
    +8   4  u32 BE  sample rate
    +12  4  u32 BE  total samples per channel
    +16  2  u16 BE  high-pass cutoff frequency, which is what the two ADPCM
                    prediction coefficients are computed from
    +18  1          version
    +19  1          flags

One block is 18 bytes and carries 32 samples of one channel: a u16 BE scale
followed by 16 bytes of signed 4-bit deltas. So

    bytes of sample data = ceil(total_samples / 32) * 18 * channels

and after it comes a FOOTER, which was not guessed but read off the tail of
four files and then confirmed on all of them: the two bytes 80 01, a u16 BE
giving the number of padding bytes that follow, and that many bytes. The field
reads 14 on 29 of the 109 loose files and anything from 40 to 2,024 on the
rest, so a fixed 18-byte footer -- which is what this tool assumed first -- is
wrong. The footer describes its own length, and the whole accounting is

    data_start + ceil(samples/32) * block * channels + 4 + pad == file size

and that is the check `--validate` makes. It is a real check and not an
identity, because `total_samples` and the file size are two independent
quantities written by two different parts of the encoder: the count comes from
the source material, the size comes from how much got written.

    duration = total_samples / sample_rate

THE DECODER
-----------

`--decode` writes a 16-bit PCM WAV so a human being can hear one, which is the
last step of every claim about sound in this branch. The prediction filter is
the public CRI one and this tool says so rather than pretending to have derived
it: with s = sqrt(2), z = cos(2*pi*cutoff/rate), a = s - z, b = s - 1,
c = (a - sqrt((a + b) * (a - b))) / b, the two coefficients are 2c and -c*c in
1/4096ths. Each sample is delta * scale + (c1*p1 + c2*p2) / 4096, clamped to
16 bits, and the two previous outputs are carried per channel.

Usage:
    python tools/adx.py --validate DIR
    python tools/adx.py --census DIR
    python tools/adx.py --header FILE
    python tools/adx.py --decode FILE OUT.WAV [--seconds N]
"""
import math
import os
import struct
import sys


class AdxError(Exception):
    pass


def header(b):
    if len(b) < 20 or struct.unpack_from(">H", b, 0)[0] != 0x8000:
        raise AdxError("magic is %r, not 0x8000" % bytes(b[:2]))
    co = struct.unpack_from(">H", b, 2)[0]
    h = dict(copyright_offset=co, encoding=b[4], block=b[5], bits=b[6],
             channels=b[7],
             rate=struct.unpack_from(">I", b, 8)[0],
             samples=struct.unpack_from(">I", b, 12)[0],
             cutoff=struct.unpack_from(">H", b, 16)[0],
             version=b[18] if len(b) > 18 else None,
             flags=b[19] if len(b) > 19 else None,
             data_start=co + 4)
    h["cri"] = bytes(b[co - 2:co + 4]) if co >= 2 and len(b) >= co + 4 else b""
    return h


def expected_data_bytes(h):
    blocks = (h["samples"] + 31) // 32
    return blocks * h["block"] * h["channels"]


FOOTER_TAG = bytes((0x80, 0x01))


def footer(buf, h):
    """Return (padding_bytes, total_size_implied) or None if there is no footer."""
    off = h["data_start"] + expected_data_bytes(h)
    if off + 4 > len(buf) or buf[off:off + 2] != FOOTER_TAG:
        return None
    pad = struct.unpack_from(">H", buf, off + 2)[0]
    return pad, off + 4 + pad


def coefficients(rate, cutoff):
    s = math.sqrt(2.0)
    z = math.cos(2.0 * math.pi * cutoff / rate)
    a = s - z
    b = s - 1.0
    c = (a - math.sqrt((a + b) * (a - b))) / b
    return int(c * 2.0 * 4096), int(-(c * c) * 4096)


def decode(buf, max_samples=None):
    """Return (header, interleaved list of 16-bit ints)."""
    h = header(buf)
    c1, c2 = coefficients(h["rate"], h["cutoff"] or 500)
    ch = h["channels"]
    blk = h["block"]
    p1 = [0] * ch
    p2 = [0] * ch
    out = []
    pos = h["data_start"]
    want = h["samples"] if max_samples is None else min(h["samples"], max_samples)
    done = 0
    n = len(buf)
    while done < want and pos + blk * ch <= n:
        frames = [[] for _ in range(ch)]
        for c in range(ch):
            base = pos + c * blk
            scale = struct.unpack_from(">h", buf, base)[0]
            for i in range(16):
                byte = buf[base + 2 + i]
                for nib in (byte >> 4, byte & 15):
                    d = nib - 16 if nib > 7 else nib
                    v = d * scale + (c1 * p1[c] + c2 * p2[c]) // 4096
                    v = -32768 if v < -32768 else (32767 if v > 32767 else v)
                    p2[c] = p1[c]
                    p1[c] = v
                    frames[c].append(v)
        take = min(32, want - done)
        for i in range(take):
            for c in range(ch):
                out.append(frames[c][i])
        done += take
        pos += blk * ch
    return h, out


def write_wav(path, rate, channels, samples):
    data = struct.pack("<%dh" % len(samples), *samples)
    with open(path, "wb") as f:
        f.write(b"RIFF")
        f.write(struct.pack("<I", 36 + len(data)))
        f.write(b"WAVEfmt ")
        f.write(struct.pack("<IHHIIHH", 16, 1, channels, rate,
                            rate * channels * 2, channels * 2, 16))
        f.write(b"data")
        f.write(struct.pack("<I", len(data)))
        f.write(data)


def walk(root, ext=".ADX"):
    for dirpath, _dirs, files in os.walk(root):
        for f in sorted(files):
            if f.upper().endswith(ext):
                yield os.path.join(dirpath, f)


def cmd_validate(root):
    files = sorted(walk(root))
    if not files:
        raise SystemExit("adx: no .ADX under %r" % root)
    magic = cri = fits = exact = 0
    rates, chans, encs, blocks, bits = {}, {}, {}, {}, {}
    fails = []
    for p in files:
        b = open(p, "rb").read()
        size = len(b)
        try:
            h = header(b)
        except AdxError as e:
            fails.append((os.path.basename(p), str(e)))
            continue
        magic += 1
        if h["cri"] == b"(c)CRI":
            cri += 1
        rates[h["rate"]] = rates.get(h["rate"], 0) + 1
        chans[h["channels"]] = chans.get(h["channels"], 0) + 1
        encs[h["encoding"]] = encs.get(h["encoding"], 0) + 1
        blocks[h["block"]] = blocks.get(h["block"], 0) + 1
        bits[h["bits"]] = bits.get(h["bits"], 0) + 1
        need = h["data_start"] + expected_data_bytes(h)
        if need <= size:
            fits += 1
            ft = footer(b, h)
            if ft and ft[1] == size:
                exact += 1
            else:
                fails.append((os.path.basename(p),
                              "no 80 01 footer closing the file at %d" % need))
        else:
            fails.append((os.path.basename(p),
                          "declares %d samples needing %d bytes, file is %d"
                          % (h["samples"], need, size)))
    print("=== adx.py --validate over %s ===" % root)
    print("files                                        : %d" % len(files))
    print("magic 0x8000                                 : %d" % magic)
    print("'(c)CRI' at copyright_offset - 2             : %d" % cri)
    print("data_start + ceil(samples/32)*block*ch <= size: %d" % fits)
    print("  ... + the self-describing 80 01 footer == size: %d" % exact)
    print()
    for label, d in (("sample rate", rates), ("channels", chans),
                     ("encoding type", encs), ("block size", blocks),
                     ("bits per sample", bits)):
        print("%-16s %s" % (label, ", ".join(
            "%s x%d" % (k, v) for k, v in sorted(d.items(), key=lambda kv: -kv[1]))))
    if fails:
        print()
        print("THE FAILURES, BY NAME:")
        for nm, why in fails[:40]:
            print("  %-30s %s" % (nm, why))
        if len(fails) > 40:
            print("  ... and %d more" % (len(fails) - 40))
    return 0 if not fails else 1


def cmd_census(root):
    files = sorted(walk(root))
    rows = []
    for p in files:
        b = open(p, "rb").read(2200)
        h = header(b)
        rows.append((os.path.basename(p), os.path.getsize(p), h))
    total_bytes = sum(r[1] for r in rows)
    total_sec = sum(r[2]["samples"] / r[2]["rate"] for r in rows)
    print("=== adx.py --census over %s ===" % root)
    print("files            : %d" % len(rows))
    print("bytes            : %d" % total_bytes)
    print("total duration   : %.3f s = %d h %02d m %05.2f s"
          % (total_sec, int(total_sec // 3600),
             int(total_sec % 3600 // 60), total_sec % 60))
    print("mean bytes/second: %.2f" % (total_bytes / total_sec if total_sec else 0))
    print()
    print("%-24s %12s %8s %3s %12s %10s" % (
        "file", "bytes", "rate", "ch", "samples", "seconds"))
    for nm, sz, h in sorted(rows, key=lambda r: -r[1])[:25]:
        print("%-24s %12d %8d %3d %12d %10.3f" % (
            nm, sz, h["rate"], h["channels"], h["samples"],
            h["samples"] / h["rate"]))
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
    if argv[1] == "--census":
        return cmd_census(argv[2])
    if argv[1] == "--header":
        h = header(open(argv[2], "rb").read(64))
        for k in sorted(h):
            print("  %-18s %r" % (k, h[k]))
        print("  %-18s %d" % ("expected data bytes", expected_data_bytes(h)))
        print("  %-18s %d" % ("file size", os.path.getsize(argv[2])))
        print("  %-18s %.3f s" % ("duration", h["samples"] / h["rate"]))
        return 0
    if argv[1] == "--decode":
        secs = float(argv[argv.index("--seconds") + 1]) if "--seconds" in argv else None
        buf = open(argv[2], "rb").read()
        h0 = header(buf)
        h, s = decode(buf, int(secs * h0["rate"]) if secs else None)
        write_wav(argv[3], h["rate"], h["channels"], s)
        print("%s -> %s : %d Hz, %d ch, %d samples, %.3f s"
              % (os.path.basename(argv[2]), argv[3], h["rate"], h["channels"],
                 len(s) // h["channels"], len(s) / h["channels"] / h["rate"]))
        return 0
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
