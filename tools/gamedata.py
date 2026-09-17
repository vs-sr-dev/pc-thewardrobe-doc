#!/usr/bin/env python3
"""gamedata.py -- the four small `GAME.LID` formats that each close on one line
of arithmetic, plus the two files the game itself writes.

NOTHING PUBLIC DESCRIBES ANY OF THESE. Each was measured here. They share a
tool because each is three lines of logic and because the point of every one
of them is a single identity that either closes or does not.

--pal      the seven `BACK*.PAL` members
           768 bytes = 256 x 3, and EVERY BYTE <= 63, which is the VGA DAC's
           six-bit range and not an eight-bit one. The test that could fail is
           the ceiling: an arbitrary 768-byte file does not respect it.

--font     `FONT1.INF`, 11,170 bytes
           +0   u16 LE   payload length
           +2   40 x u16 LE glyph widths
           then payload bytes of glyph pixels, and
               sum(widths) x 16 == payload
           closes exactly, so the font is proportional and sixteen rows tall.
           The 16 is not assumed: it is the only integer that makes the
           identity hold.

--map      the seven `RACE?M` members
           a flat grid of one-byte tile indices into `F1.SBL`, whose single
           bank holds 126 frames of 32 x 12. Two tests:
             * len is divisible by 13, on 7 of 7;
             * every byte is < 126, i.e. a valid index, on 7 of 7.
           13 is the grid height, and it is not this tool's invention: the
           seven per-level records of `RACE.GAM` carry the value 13 in their
           second field, measured independently. The width follows.

--hi       `HI.TBL`, 156 bytes
           six records of 26: char[20] name, u16, u32 score. THE SIX NAME
           FIELDS ARE 120 BYTES OF 0x20 AND CONTAIN NO LETTER. That is the
           measurement the privacy chapter rests on, and this tool exists so
           it can be re-derived by command rather than quoted.

--gam      `RACE.GAM`, 788 bytes -- AND IT DOES NOT CLOSE.
           byte 0, then a 19-byte title, then a settings block, then seven
           per-level records at stride 72 each carrying u16, u16 = 13, u16
           level index and a 14-byte name field holding `BACK1`..`BACK7`.
           The first record starts at 336 and 336 + 7 x 72 = 840, which is 52
           bytes past the 788-byte file: THE LAST RECORD IS CUT SHORT AT 20 OF
           72 BYTES. The stride is measured on 7 of 7 name positions and the
           overrun is reported rather than hidden by shrinking the record.

    python tools/gamedata.py --pal  _work/members/GAME/*.PAL
    python tools/gamedata.py --font _work/members/GAME/FONT1.INF
    python tools/gamedata.py --map  _work/members/GAME/RACE.?M
    python tools/gamedata.py --hi   Skunny/HI.TBL
    python tools/gamedata.py --gam  Skunny/RACE.GAM
"""
import argparse
import collections
import os
import re
import struct
import sys

TILESET_FRAMES = 126
MAP_HEIGHT = 13


def do_pal(paths):
    ok = 0
    for path in sorted(paths):
        blob = open(path, 'rb').read()
        high = sum(1 for byte in blob if byte > 63)
        good = len(blob) == 768 and high == 0
        ok += good
        print('%-14s %4d B  bytes above 63: %3d  %s'
              % (os.path.basename(path), len(blob), high,
                 '256 x 3 six-bit VGA' if good else 'REFUSED'))
    print('\n768 bytes with every value <= 63: %d of %d' % (ok, len(paths)))
    return ok, len(paths)


def do_font(paths):
    ok = 0
    for path in sorted(paths):
        blob = open(path, 'rb').read()
        payload = struct.unpack_from('<H', blob, 0)[0]
        table = len(blob) - payload - 2
        if table < 0 or table % 2:
            print('%-14s REFUSED: header %d leaves %d table bytes'
                  % (os.path.basename(path), payload, table))
            continue
        glyphs = table // 2
        widths = [struct.unpack_from('<H', blob, 2 + 2 * i)[0]
                  for i in range(glyphs)]
        total = sum(widths)
        height = payload // total if total and payload % total == 0 else None
        good = height is not None
        ok += good
        print('%-14s %6d B  payload %6d  %d glyphs  sum(widths) %d  %s'
              % (os.path.basename(path), len(blob), payload, glyphs, total,
                 'sum x %d == payload, CLOSES' % height if good
                 else 'REFUSED: sum does not divide the payload'))
        if good:
            print('     widths: %s' % widths)
    print('\nclosed on sum(widths) x height == payload: %d of %d' % (ok, len(paths)))
    return ok, len(paths)


def do_map(paths):
    ok = 0
    for path in sorted(paths):
        blob = open(path, 'rb').read()
        divides = len(blob) % MAP_HEIGHT == 0
        peak = max(blob)
        good = divides and peak < TILESET_FRAMES
        ok += good
        print('%-14s %6d B  %s  max index %3d of %d tiles  %s'
              % (os.path.basename(path), len(blob),
                 '%d x %d' % (len(blob) // MAP_HEIGHT, MAP_HEIGHT) if divides
                 else 'not divisible by %d' % MAP_HEIGHT,
                 peak, TILESET_FRAMES,
                 'CLOSES' if good else 'REFUSED'))
    print('\ndivisible by %d and every index < %d: %d of %d'
          % (MAP_HEIGHT, TILESET_FRAMES, ok, len(paths)))
    return ok, len(paths)


def do_hi(paths):
    ok = 0
    for path in sorted(paths):
        blob = open(path, 'rb').read()
        if len(blob) % 26:
            print('%-14s REFUSED: %d bytes is not a whole number of 26'
                  % (os.path.basename(path), len(blob)))
            continue
        records = len(blob) // 26
        name_bytes = collections.Counter()
        scores = []
        for i in range(records):
            rec = blob[i * 26:(i + 1) * 26]
            name_bytes.update(rec[:20])
            scores.append(struct.unpack_from('<I', rec, 22)[0])
        ok += 1
        print('%-14s %4d B = %d records of 26' % (os.path.basename(path),
                                                  len(blob), records))
        print('     name-field byte values across all %d name bytes: %s'
              % (records * 20, dict(name_bytes)))
        print('     letters in any name field: %d'
              % sum(n for b, n in name_bytes.items() if 65 <= b <= 122))
        print('     scores: %s   descending: %s'
              % (scores, scores == sorted(scores, reverse=True)))
    return ok, len(paths)


def do_gam(paths):
    ok = 0
    for path in sorted(paths):
        blob = open(path, 'rb').read()
        hits = [m.start() for m in re.finditer(rb'BACK[0-9]', blob)]
        strides = {b - a for a, b in zip(hits, hits[1:])}
        print('%-14s %4d B  byte0 %d  title %r'
              % (os.path.basename(path), len(blob), blob[0],
                 blob[1:20].decode('latin-1')))
        print('     %d level names at %s, strides %s'
              % (len(hits), hits, sorted(strides)))
        if len(strides) == 1:
            stride = strides.pop()
            start = hits[0] - 6
            for hit in hits:
                width, height, index = struct.unpack_from('<3H', blob, hit - 6)
                print('       %-6s  u16 %4d   u16 %3d   index %d'
                      % (blob[hit:hit + 5].decode(), width, height, index))
            need = start + stride * len(hits)
            print('     records span %d..%d but the file is %d -- residue %+d'
                  % (start, need, len(blob), len(blob) - need))
            print('     verdict: %s'
                  % ('closes' if need == len(blob)
                     else 'DOES NOT CLOSE, the last record is cut short at '
                          '%d of %d bytes' % (len(blob) - hits[-1] + 6, stride)))
            ok += 1 if need == len(blob) else 0
    return ok, len(paths)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    for flag in ('pal', 'font', 'map', 'hi', 'gam'):
        ap.add_argument('--' + flag, action='store_true')
    args = ap.parse_args()
    chosen = [f for f in ('pal', 'font', 'map', 'hi', 'gam') if getattr(args, f)]
    if len(chosen) != 1:
        ap.error('pick exactly one of --pal --font --map --hi --gam')
    ok, total = globals()['do_' + chosen[0]](args.files)
    print('')
    print('%s: %d of %d files closed' % (chosen[0], ok, total))
    if ok != total:
        raise SystemExit('FATAL: %d of %d did not close' % (total - ok, total))


if __name__ == '__main__':
    main()
