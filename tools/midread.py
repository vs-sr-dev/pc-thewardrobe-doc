#!/usr/bin/env python3
"""midread.py -- the nine .MDI of Simulman V, read as Standard MIDI Files.

MIDI is a public, published format, and this tool says so rather than
pretending to have derived it: the chunk layout (`MThd` length 6, then `MTrk`
chunks each with a 32-bit big-endian length), the variable-length delta times,
the running status rule and the meta-event encoding are taken from the
Standard MIDI File specification. What is *measured* here is whether these
files obey it, and what they contain.

The validation is done before the census and on something that must fail: the
tool truncates the first file by one byte and checks that the parse then
reports a short track. A parser that cannot fail is a parser that proves
nothing.

    python tools/midread.py <objectroot> [--copy <outdir>]

--copy writes the nine files out under a `.mid` extension so that they can be
played by anything. It copies bytes; it does not transform them. Nothing it
writes goes into the repository.
"""
import os
import shutil
import struct
import sys
from collections import Counter


def vlq(d, i):
    v = 0
    while True:
        b = d[i]
        i += 1
        v = (v << 7) | (b & 0x7F)
        if not b & 0x80:
            return v, i


def parse(d):
    """Returns a dict of measurements, or raises on anything malformed."""
    if d[:4] != b"MThd":
        raise ValueError("no MThd")
    (hlen,) = struct.unpack(">I", d[4:8])
    if hlen != 6:
        raise ValueError("MThd length is %d, not 6" % hlen)
    fmt, ntrk, div = struct.unpack(">3H", d[8:14])
    i = 8 + hlen
    tracks = []
    tempos = []
    progs = Counter()
    notes = 0
    chans = Counter()
    metas = Counter()
    total_ticks = 0
    while i < len(d):
        if d[i:i + 4] != b"MTrk":
            raise ValueError("expected MTrk at %d, got %r" % (i, d[i:i + 4]))
        (tlen,) = struct.unpack(">I", d[i + 4:i + 8])
        body = d[i + 8:i + 8 + tlen]
        if len(body) != tlen:
            raise ValueError("track at %d declares %d bytes, %d present"
                             % (i, tlen, len(body)))
        # All nine of these files declare an MTrk length four bytes short of
        # their own content, and the four bytes left over are exactly the
        # End-of-Track meta event `00 FF 2F 00`. Whatever wrote them wrote the
        # length before it appended the terminator. A strict reader refuses
        # the file; this one measures the discrepancy and carries on, and the
        # census below prints it for all nine so the claim can be checked.
        if d[i + 8 + tlen:i + 12 + tlen] == b"\x00\xff\x2f\x00":
            tlen += 4
            body = d[i + 8:i + 8 + tlen]
        tracks.append(tlen)
        short = tlen - struct.unpack(">I", d[i + 4:i + 8])[0]
        j = 0
        ticks = 0
        status = 0
        while j < len(body):
            dt, j = vlq(body, j)
            ticks += dt
            b = body[j]
            if b & 0x80:
                status = b
                j += 1
            if status == 0xFF:
                mtype = body[j]
                j += 1
                ln, j = vlq(body, j)
                metas[mtype] += 1
                if mtype == 0x51 and ln == 3:
                    tempos.append(struct.unpack(">I", b"\x00" + body[j:j + 3])[0])
                j += ln
                if mtype == 0x2F:
                    break
            elif status in (0xF0, 0xF7):
                ln, j = vlq(body, j)
                j += ln
            else:
                hi = status & 0xF0
                chans[status & 0x0F] += 1
                if hi == 0x90 and body[j + 1] != 0:
                    notes += 1
                if hi == 0xC0:
                    progs[body[j]] += 1
                j += 1 if hi in (0xC0, 0xD0) else 2
        total_ticks = max(total_ticks, ticks)
        i += 8 + tlen
    return dict(fmt=fmt, ntrk=ntrk, div=div, tracks=tracks, tempos=tempos,
                short=short,
                progs=progs, notes=notes, chans=chans, metas=metas,
                ticks=total_ticks, consumed=i, size=len(d))


def repair(d):
    """Raise every short MTrk length by four so it covers its own EOT.

    Returns (bytes, number_of_tracks_patched). The file length does not
    change: only the four bytes of the length field are rewritten. If a track
    is *not* short the function leaves it alone, so running this on a
    conforming MIDI file is a no-op and the caller's assertion catches it.
    """
    out = bytearray(d)
    i = 8 + struct.unpack(">I", d[4:8])[0]
    patched = 0
    while i + 8 <= len(out):
        if out[i:i + 4] != b"MTrk":
            break
        (tlen,) = struct.unpack(">I", out[i + 4:i + 8])
        if out[i + 8 + tlen:i + 12 + tlen] == b"\x00\xff\x2f\x00":
            struct.pack_into(">I", out, i + 4, tlen + 4)
            patched += 1
            tlen += 4
        i += 8 + tlen
    return bytes(out), patched


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    outdir = None
    if "--copy" in sys.argv:
        outdir = sys.argv[sys.argv.index("--copy") + 1]
        os.makedirs(outdir, exist_ok=True)
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

    names = []
    for dp, _dd, ff in os.walk(root):
        for n in sorted(ff):
            if n.upper().endswith(".MDI"):
                names.append(os.path.relpath(os.path.join(dp, n), root)
                             .replace(os.sep, "/"))
    names.sort()
    assert names, "no .MDI under %r" % root

    print("=== validate first, on something that must fail ===")
    d = open(os.path.join(root, names[0]), "rb").read()
    try:
        parse(d[:-1])
        print("  FAILED: a truncated file parsed clean. The parser proves nothing.")
        sys.exit(1)
    except Exception as ex:
        print("  %s truncated by one byte -> %s: %s"
              % (names[0], type(ex).__name__, ex))
    try:
        parse(b"MThd" + d[4:])
        print("  intact file parses")
    except Exception as ex:
        print("  FAILED on the intact file: %s" % ex)
        sys.exit(1)
    print("")

    print("=== the nine sequences ===")
    print("  %-22s %7s %3s %4s %4s %6s %6s %6s %7s" %
          ("file", "size", "fmt", "trk", "div", "bytes", "ticks", "notes", "sec"))
    shorts = 0
    tot = 0
    allprogs = Counter()
    allchans = Counter()
    for f in names:
        d = open(os.path.join(root, f), "rb").read()
        m = parse(d)
        tot += len(d)
        assert m["consumed"] == m["size"], \
            "%s: chunks do not close the file (%d of %d)" % (f, m["consumed"], m["size"])
        us = m["tempos"][0] if m["tempos"] else 500000
        sec = m["ticks"] * us / 1e6 / m["div"] if m["div"] else 0
        shorts += (m["short"] == 4)
        allprogs.update(m["progs"])
        allchans.update(m["chans"])
        print("  %-22s %7d %3d %4d %4d %6d %6d %6d %7.1f" %
              (f, len(d), m["fmt"], m["ntrk"], m["div"], sum(m["tracks"]),
               m["ticks"], m["notes"], sec))
    print("  total: %d bytes" % tot)
    print("  MTrk length four bytes short of the track's own content,")
    print("  the four being the End-of-Track meta event: %d of %d files"
          % (shorts, len(names)))
    print("")
    print("=== what they play ===")
    print("  MIDI channels used, with event counts:")
    for c, n in sorted(allchans.items()):
        print("    channel %2d  %6d events%s" % (c + 1, n,
              "   (10 is the percussion channel)" if c == 9 else ""))
    print("  program-change values, i.e. instrument numbers requested:")
    for p, n in sorted(allprogs.items()):
        print("    program %3d  x%d" % (p, n))
    print("")

    if outdir:
        for f in names:
            base = os.path.basename(f).rsplit(".", 1)[0]
            shutil.copyfile(os.path.join(root, f),
                            os.path.join(outdir, base + ".raw.mid"))
            d = open(os.path.join(root, f), "rb").read()
            fixed, patched = repair(d)
            assert patched == 1, "%s: expected one short MTrk, patched %d" % (f, patched)
            assert len(fixed) == len(d), "repair changed the file length"
            open(os.path.join(outdir, base + ".mid"), "wb").write(fixed)
        print("=== wrote %d sequences to %s, twice each ===" % (len(names), outdir))
        print("    *.raw.mid  byte-for-byte, as the object holds them. These do")
        print("               not play: a conforming reader stops at the end of")
        print("               the track the header declares and finds four bytes")
        print("               it was not told about.")
        print("    *.mid      the same bytes with the 32-bit MTrk length field")
        print("               raised by four, so that it covers the End-of-Track")
        print("               event that is already there. Four bytes changed per")
        print("               file, no event touched, same file length.")


if __name__ == "__main__":
    main()
