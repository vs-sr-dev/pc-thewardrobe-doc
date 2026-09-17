#!/usr/bin/env python3
"""pcspk.py -- render a POP-CORN PC-speaker note table to a WAV file.

WHAT THE ENGINE IS, READ OUT OF THE CODE

`popcorn.exe`, unpacked (see `exepack.py`), contains exactly one routine that
touches the sound hardware -- two `out 42h`, one `out 43h`, six `out 61h` in
the whole image -- and it reads like this, at image offset 109,731:

    b0 b6           mov al, 0B6h        ; PIT channel 2, square wave
    e6 43           out 43h, al
    e4 61 0c 03     in al,61h / or al,3 ; speaker on
    e6 61           out 61h, al
    ...
    8b 36 f6 00     mov si, [00F6]      ; the melody pointer
    ad              lodsw               ; AL = pitch, AH = duration
    0b c0  74 ..    or ax,ax / jz       ; a zero word ends the table
    89 36 f6 00     mov [00F6], si
    88 26 f5 00     mov [00F5], ah      ; duration, in timer ticks
    8a e0           mov ah, al
    b0 01  e6 42    mov al,1 / out 42h  ; PIT divisor LOW byte is always 1
    8a c4  e6 42    mov al,ah / out 42h ; PIT divisor HIGH byte is the table's

**So a note is two bytes: a pitch byte and a duration byte, and the pitch byte
is the HIGH half of the PIT divisor.** The divisor is `pitch * 256 + 1` and the
frequency is `1193182 / (pitch * 256 + 1)`. That is a coarse instrument: pitch
5 gives 932 Hz, pitch 20 gives 233 Hz, and there are only sixteen values in
between. A zero word ends a table.

WHAT IS ACTUALLY THERE

Seven tables, at DS:0200 through DS:0281, **131 bytes and 58 notes in total**.
There is no eighth, and a scan of the whole 133,296-byte image for any longer
run of the same shape finds nothing in the program's own segment past 19 notes.
The durations are in timer ticks; `--tick` sets the rate and defaults to the
stock 18.2 Hz, which is a stated assumption and not a measurement -- if the
game reprograms channel 0 the pitches are right and the tempo is not.

    python pcspk.py IMAGE --offset N --out X.wav
    python pcspk.py IMAGE --tables          list the tables it can find
    python pcspk.py IMAGE --all OUTDIR      render every table it finds

Standard library only (`wave`, `struct`, `math`). It reads the image and
writes only WAV files where told.
"""

import argparse
import math
import os
import struct
import sys
import wave

PIT = 1193182.0
RATE = 44100
TICK = 18.2064  # the stock PC timer, 1193182 / 65536


def notes_at(data, off, maxnotes=4096):
    """Read (pitch, duration) pairs until a zero word. Returns None if the
    very first word does not look like a note, so the caller can scan."""
    out = []
    p = off
    while p + 1 < len(data) and len(out) < maxnotes:
        lo, hi = data[p], data[p + 1]
        if lo == 0 and hi == 0:
            return out if out else None
        if not (1 <= lo <= 255 and 1 <= hi <= 64):
            return None
        out.append((lo, hi))
        p += 2
    return None


def synth(notes, tick, rate=RATE, amp=0.22):
    """A square wave, because that is literally what PIT mode 3 produces.
    A short linear fade at each edge keeps the clicks out; the hardware had
    the clicks and this is a rendering, not an emulation."""
    frames = bytearray()
    phase = 0.0
    for pitch, dur in notes:
        divisor = pitch * 256 + 1
        f = PIT / divisor
        n = int(rate * dur / tick)
        step = f / rate
        fade = min(200, n // 8) or 1
        for i in range(n):
            phase = (phase + step) % 1.0
            v = amp if phase < 0.5 else -amp
            if i < fade:
                v *= i / float(fade)
            elif i > n - fade:
                v *= (n - i) / float(fade)
            frames += struct.pack("<h", int(v * 32767))
    return bytes(frames)


def write_wav(path, frames, rate=RATE):
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(frames)


def find_tables(data, lo=0, hi=None, minnotes=3):
    hi = hi if hi is not None else len(data)
    found = []
    p = lo
    while p < hi - 1:
        n = notes_at(data, p)
        if n and len(n) >= minnotes:
            found.append((p, n))
            p += len(n) * 2 + 2
        else:
            p += 1
    return found


def describe(notes):
    return ", ".join("%d/%.0fHz x%d" % (pt, PIT / (pt * 256 + 1), du)
                     for pt, du in notes)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--offset", type=int)
    ap.add_argument("--out")
    ap.add_argument("--all", metavar="OUTDIR")
    ap.add_argument("--tables", action="store_true")
    ap.add_argument("--from", dest="lo", type=int, default=0)
    ap.add_argument("--to", dest="hi", type=int)
    ap.add_argument("--min-notes", type=int, default=3)
    ap.add_argument("--tick", type=float, default=TICK)
    args = ap.parse_args(argv)

    with open(args.path, "rb") as f:
        data = f.read()

    if args.offset is not None:
        n = notes_at(data, args.offset)
        if not n:
            print("pcspk.py: no note table at %d -- REFUSED" % args.offset)
            return 1
        out = args.out or "table-%d.wav" % args.offset
        write_wav(out, synth(n, args.tick))
        secs = sum(d for _, d in n) / args.tick
        print("pcspk.py: %d notes at %d, %.2f s -> %s"
              % (len(n), args.offset, secs, out))
        print("  %s" % describe(n))
        return 0

    found = find_tables(data, args.lo, args.hi, args.min_notes)
    print("note tables found: %d  (over bytes %d..%d, >= %d notes)"
          % (len(found), args.lo, args.hi or len(data), args.min_notes))
    total = 0
    for off, n in found:
        total += len(n)
        print("  offset %7d  %3d notes  %6.2f s"
              % (off, len(n), sum(d for _, d in n) / args.tick))
    print("  total notes: %d" % total)

    if args.all:
        if not os.path.isdir(args.all):
            os.makedirs(args.all)
        for i, (off, n) in enumerate(found):
            p = os.path.join(args.all, "sound-%02d-at-%d.wav" % (i, off))
            write_wav(p, synth(n, args.tick))
            print("  wrote %s" % p)
        allnotes = []
        for _, n in found:
            allnotes += n + [(1, 8)]
        write_wav(os.path.join(args.all, "sound-all.wav"),
                  synth(allnotes, args.tick))
        print("  wrote %s" % os.path.join(args.all, "sound-all.wav"))
    elif args.tables:
        for off, n in found:
            print("\noffset %d:\n  %s" % (off, describe(n)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
