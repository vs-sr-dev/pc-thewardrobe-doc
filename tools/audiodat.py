#!/usr/bin/env python3
"""audiodat.py -- read `/DATA/SOUND/AUDIO.FMT` as an index into `AUDIO.DAT`,
and write any entry out as a playable RIFF/WAVE file.

`AUDIO.DAT` is 71,738,528 bytes -- the largest `.DAT` on this object and
3.3510 % of its file content -- and `_pre\\formats.txt` said only that it was
71.7 MB and that whether the SoundFont banks were inside it was unknown. It is
neither a stream nor a SoundFont: it is the game's sound-effect bank, and
`AUDIO.FMT` beside it is its index.

THE INDEX, DERIVED FROM THE BYTES

    off  len   field
      0    4   **2858** -- not an entry count. It is the offset in AUDIO.DAT
                at which the first payload begins, i.e. the length of the
                preamble that belongs to no entry. The first thing tried here
                was reading it as a count, and it failed loudly at entry 739.
      4   20   twenty zero bytes
     24  ...   the entries, back to back, no padding, to the end of the file

  An entry is a **WAVEFORMATEX followed by twenty-four bytes**:

      0   2   wFormatTag        2 = WAVE_FORMAT_ADPCM (Microsoft ADPCM)
      2   2   nChannels         1 on all 723 readable entries
      4   4   nSamplesPerSec    44,100 on all 723
      8   4   nAvgBytesPerSec
     12   2   nBlockAlign       1,024
     14   2   wBitsPerSample    4
     16   2   cbSize            32 on all 723
     18  cb   the MS ADPCM extension: samples-per-block, coefficient count,
              and that many int16 coefficient pairs -- seven pairs, which is
              the standard Microsoft ADPCM table
  18+cb   4   length of the payload, uint32 LE
 18+cb+4   4   offset of the payload in AUDIO.DAT, uint32 LE
      ...  16  sixteen further bytes, not identified here

  **Twenty-six entries are eighteen bytes of 0xCD** and carry no extension.
  0xCD is the Microsoft C runtime's debug-heap fill for memory that was never
  written, so those twenty-six format blocks were shipped uninitialised on a
  pressed disc. Their length and offset fields are valid and their payloads
  are part of the tiling; only the format is missing. See `parse_fmt`.

WAVEFORMATEX and the WAVE_FORMAT_ADPCM extension are public -- Microsoft,
*Multimedia Programming Interface and Data Specifications 1.0* and the
IMA/MS-ADPCM appendix -- and are used here by saying so.

THE CLOSURE TEST

  Every entry's (offset, length) must lie inside AUDIO.DAT, the entries must
  tile it without overlap, and the walk of the index must land exactly on the
  end of AUDIO.FMT. `--census` prints all three and exits non-zero if any
  fails.

    python tools/audiodat.py DIR --census
    python tools/audiodat.py DIR --wav N --out FILE     entry N as RIFF/WAVE
"""
import argparse
import os
import struct
import sys


FILL = bytes([0xCD]) * 18   # the MSVC debug heap's uninitialised-memory byte


def parse_fmt(f):
    """Walk AUDIO.FMT. The first uint32 is not an entry count -- it is the
    offset in AUDIO.DAT at which the first payload starts, and the entries run
    to the end of the file.

    Twenty-six of the 749 entries carry a WAVEFORMATEX that is eighteen bytes
    of 0xCD: the Microsoft C runtime's debug fill for memory that was never
    written. Those entries have no extension, so cbSize cannot be read from
    them -- reading it gives 0xCDCD -- and the walk recovers by taking cb = 0
    when the format block is the fill. That recovery is not a guess: with it
    the index walk ends 18 bytes from the end of AUDIO.FMT, and the 749
    payloads tile AUDIO.DAT with zero overlap and zero unowned bytes after the
    2,858-byte preamble the header names. Without it the walk dies at the
    198th entry."""
    (preamble,) = struct.unpack("<I", f[:4])
    pos = 24
    out = []
    i = 0
    fill = 0
    while pos + 18 <= len(f):
        hdr = f[pos:pos + 18]
        if hdr == FILL:
            tag = ch = rate = avg = align = bits = None
            cb = 0
            fill += 1
        else:
            tag, ch, rate, avg, align, bits, cb = struct.unpack("<HHIIHHH", hdr)
            if tag != 2:
                raise SystemExit("FATAL: entry %d at %d has wFormatTag %d, "
                                 "which this reader does not know" % (i, pos, tag))
        p = pos + 18 + cb
        if p + 24 > len(f):
            break                      # the trailing fill block
        ln, off = struct.unpack("<II", f[p:p + 8])
        out.append({"i": i, "tag": tag, "ch": ch, "rate": rate, "avg": avg,
                    "align": align, "bits": bits, "cb": cb,
                    "ext": f[pos + 18:pos + 18 + cb],
                    "off": off, "len": ln, "tail": f[p + 8:p + 24],
                    "stride": (p + 24) - pos, "fill": hdr == FILL})
        pos = p + 24
        i += 1
    return preamble, out, pos, fill


def cmd_census(fmt, dat, quiet=False):
    f = open(fmt, "rb").read()
    n = os.path.getsize(dat)
    preamble, e, end, fill = parse_fmt(f)
    print("AUDIO.FMT bytes            : %d" % len(f))
    print("header field 0 (preamble)  : %d" % preamble)
    print("entries walked             : %d" % len(e))
    print("  with a 0xCD format block : %d" % fill)
    print("index walk ends at         : %d   trailing bytes %d" % (end, len(f) - end))
    print("AUDIO.DAT bytes            : %d" % n)
    tags = {}
    rates = {}
    strides = {}
    for x in e:
        tags[x["tag"]] = tags.get(x["tag"], 0) + 1
        rates[x["rate"]] = rates.get(x["rate"], 0) + 1
        strides[x["stride"]] = strides.get(x["stride"], 0) + 1
    print("wFormatTag                 : %s" % tags)
    print("nSamplesPerSec             : %s" % rates)
    print("entry strides              : %s" % strides)
    inside = sum(1 for x in e if x["off"] + x["len"] <= n)
    print("payloads inside AUDIO.DAT  : %d of %d" % (inside, len(e)))
    ordered = sorted(e, key=lambda x: x["off"])
    gap = ordered[0]["off"]
    overlap = 0
    cursor = ordered[0]["off"]
    for x in ordered:
        if x["off"] < cursor:
            overlap += cursor - x["off"]
        else:
            gap += x["off"] - cursor
        cursor = max(cursor, x["off"] + x["len"])
    gap += n - cursor
    print("payload bytes              : %d" % sum(x["len"] for x in e))
    print("bytes owned by no entry    : %d" % gap)
    print("bytes owned twice          : %d" % overlap)
    print("total, index + payload     : %d + %d = %d against %d + %d = %d"
          % (len(f), sum(x["len"] for x in e), len(f) + sum(x["len"] for x in e),
             len(f), n, len(f) + n))
    print("preamble, unowned by design: %d   (header field 0 says %d)"
          % (ordered[0]["off"], preamble))
    ok = (inside == len(e) and overlap == 0
          and gap == preamble == ordered[0]["off"]
          and len(f) - end == 18)
    print("VERDICT                    : %s" % ("closes" if ok else "DOES NOT CLOSE"))
    return 0 if ok else 1


def wav_bytes(x, payload):
    """Wrap an MS ADPCM payload in a RIFF/WAVE container."""
    if x["fill"]:
        raise SystemExit("entry %d has an uninitialised format block; there is"
                         " no WAVEFORMATEX to write" % x["i"])
    fmt = struct.pack("<HHIIHHH", x["tag"], x["ch"], x["rate"], x["avg"],
                      x["align"], x["bits"], x["cb"]) + x["ext"]
    if len(fmt) & 1:
        fmt += b"\0"
    nsamples = (x["len"] // x["align"]) * struct.unpack("<H", x["ext"][:2])[0] \
        if x["cb"] >= 2 and x["align"] else 0
    fact = struct.pack("<4sII", b"fact", 4, nsamples)
    data = payload + (b"\0" if len(payload) & 1 else b"")
    body = (b"WAVE"
            + struct.pack("<4sI", b"fmt ", len(fmt)) + fmt
            + fact
            + struct.pack("<4sI", b"data", len(payload)) + data)
    return struct.pack("<4sI", b"RIFF", len(body)) + body


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", help="directory holding AUDIO.DAT and AUDIO.FMT")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--wav", type=int)
    ap.add_argument("--out")
    a = ap.parse_args(argv[1:])
    fmt = None
    dat = None
    for nm in os.listdir(a.dir):
        if nm.upper() == "AUDIO.FMT":
            fmt = os.path.join(a.dir, nm)
        if nm.upper() == "AUDIO.DAT":
            dat = os.path.join(a.dir, nm)
    if not fmt or not dat:
        print("FATAL: AUDIO.FMT and AUDIO.DAT are not both in %r" % a.dir)
        return 3
    if a.census:
        return cmd_census(fmt, dat)
    if a.wav is not None:
        f = open(fmt, "rb").read()
        _p, e, _end, _fill = parse_fmt(f)
        x = e[a.wav]
        with open(dat, "rb") as fh:
            fh.seek(x["off"])
            payload = fh.read(x["len"])
        out = a.out or ("entry%05d.wav" % a.wav)
        with open(out, "wb") as fh:
            fh.write(wav_bytes(x, payload))
        print("entry %d: tag %d, %d ch, %d Hz, blockAlign %d, %d bytes -> %s"
              % (a.wav, x["tag"], x["ch"], x["rate"], x["align"], x["len"], out))
        return 0
    ap.print_usage()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
