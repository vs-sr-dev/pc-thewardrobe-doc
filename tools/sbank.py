#!/usr/bin/env python3
"""sbank.py -- read the `S*` sprite banks of Copysoft's MS-DOS engine.

NOTHING PUBLIC DESCRIBES THIS FORMAT. It was measured on the members of
`GAME.LID`, and the arithmetic below is the whole of it.

A member is a CHAIN OF BANKS. Each bank is a 12-byte header followed by a
run of fixed-size uncompressed 8-bit frames:

    +0    u16 LE   width in pixels
    +2    u16 LE   height in pixels
    +4    u16 LE   frame count in this bank
    +6    6 bytes  trailing header field, zero on most members
    +12   frames x width x height bytes, one byte per pixel, no padding,
          no row prefix, no run-length -- a FLAT raster

and the next bank begins immediately after. The chain is walked to end of
file; a member closes when the last bank ends exactly at EOF.

THE 12-BYTE HEADER IS WHY THE `RACE.L*` TABLES CLOSE. Each `RACE.L*` record
carries a u16 payload total and a u16 bank count, and

    member size == payload + 12 x banks

on every record those tables describe. The two numbers were measured
independently -- one by walking the member, one by reading the table -- and
they are the object's third quantity encoded twice.

WHAT IS NOT CLAIMED HERE. The six bytes at +6 are not named. The meaning of
a second bank is not asserted by this tool: it reports the bank count and the
per-bank geometry and leaves the interpretation to a chapter that has looked
at the pixels. And the letters `S`, `HE`, `BA`, `BL`, `PI`, `SO`, `EF`, `WE`
are NOT expanded by this tool.

    python tools/sbank.py --validate _work/members/GAME/*.SHE
    python tools/sbank.py --census   _work/members/GAME/*.SHE
    python tools/sbank.py --render   _work/members/GAME/T1.SHE \\
                          --palette _work/members/GAME/BACK1.PAL --out _work/spr

Validate before census, always. A member that does not close is reported and
never silently truncated.
"""
import argparse
import collections
import os
import struct
import sys
import zlib

BANK_HEADER = 12
# A bank whose geometry exceeds this is treated as a misread rather than as a
# real sprite. Mode 13h is 320x200; the largest real frame measured in
# GAME.LID is 64x36. The ceiling exists so that a file which is NOT this
# format fails loudly on its first bank instead of trying to allocate a
# gigabyte, which is what PANEL.SP did on the first pass.
MAX_DIM = 512
MAX_FRAMES = 4096


class BankError(Exception):
    pass


def walk(path, blob):
    """Walk the bank chain. Returns a list of bank dicts, or raises."""
    banks = []
    pos = 0
    while pos < len(blob):
        if pos + BANK_HEADER > len(blob):
            raise BankError('%s: %d bytes left at offset %d, short of a '
                            '12-byte bank header' % (path, len(blob) - pos, pos))
        width, height, frames = struct.unpack_from('<3H', blob, pos)
        tail = blob[pos + 6:pos + 12]
        if width == 0 or height == 0 or frames == 0:
            raise BankError('%s: bank %d at offset %d has w=%d h=%d frames=%d, '
                            'and a zero in any of the three is not a bank'
                            % (path, len(banks), pos, width, height, frames))
        if width > MAX_DIM or height > MAX_DIM or frames > MAX_FRAMES:
            raise BankError('%s: bank %d at offset %d reads w=%d h=%d frames=%d, '
                            'past the sanity ceiling -- this is not the format'
                            % (path, len(banks), pos, width, height, frames))
        payload = width * height * frames
        end = pos + BANK_HEADER + payload
        if end > len(blob):
            raise BankError('%s: bank %d at offset %d declares %d x %d x %d = %d '
                            'payload bytes and runs %d past the %d-byte member'
                            % (path, len(banks), pos, width, height, frames,
                               payload, end - len(blob), len(blob)))
        banks.append({
            'index': len(banks), 'offset': pos, 'width': width,
            'height': height, 'frames': frames, 'payload': payload,
            'tail': tail, 'data_at': pos + BANK_HEADER,
        })
        pos = end
    if not banks:
        raise BankError('%s: empty member' % path)
    return banks


def write_png(path, width, height, rows, pal):
    raw = bytearray()
    for row in rows:
        raw.append(0)
        raw.extend(row)

    def chunk(tag, payload):
        body = tag + payload
        return (struct.pack('>I', len(payload)) + body
                + struct.pack('>I', zlib.crc32(body) & 0xFFFFFFFF))

    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 3, 0, 0, 0))
    png += chunk(b'PLTE', bytes(pal))
    png += chunk(b'tRNS', b'\x00')
    png += chunk(b'IDAT', zlib.compress(bytes(raw), 9))
    png += chunk(b'IEND', b'')
    with open(path, 'wb') as handle:
        handle.write(png)


def load_palette(path):
    with open(path, 'rb') as handle:
        pal = handle.read()
    if len(pal) != 768:
        raise SystemExit('FATAL: palette %s is %d bytes, not 768'
                         % (path, len(pal)))
    high = sum(1 for byte in pal if byte > 63)
    if high:
        return bytes(pal), high
    return bytes(min(255, byte * 255 // 63) for byte in pal), 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--census', action='store_true')
    ap.add_argument('--render', action='store_true')
    ap.add_argument('--palette', default=None)
    ap.add_argument('--out', default=None)
    ap.add_argument('--sheet', action='store_true',
                    help='render each bank as one strip of its frames')
    args = ap.parse_args()

    if not (args.validate or args.census or args.render):
        ap.error('pick one of --validate --census --render')
    if args.render and not (args.out and args.palette):
        ap.error('--render needs --out and --palette')

    pal = None
    if args.palette:
        pal, high = load_palette(args.palette)
        print('palette %s: %d of 768 bytes above 63, so it is %s'
              % (os.path.basename(args.palette), high,
                 '8-bit and used as is' if high else '6-bit VGA and scaled'))
    if args.render:
        os.makedirs(args.out, exist_ok=True)

    opened = 0
    closed = 0
    total_banks = 0
    total_frames = 0
    total_pixels = 0
    bank_counts = collections.Counter()
    geometries = collections.Counter()
    tails = collections.Counter()
    failures = []

    for path in sorted(args.files):
        with open(path, 'rb') as handle:
            blob = handle.read()
        try:
            banks = walk(path, blob)
        except BankError as exc:
            failures.append(str(exc))
            print('FAIL  %s' % exc)
            continue
        opened += 1
        closed += 1
        total_banks += len(banks)
        bank_counts[len(banks)] += 1
        for bank in banks:
            total_frames += bank['frames']
            total_pixels += bank['payload']
            geometries['%dx%d' % (bank['width'], bank['height'])] += 1
            tails[bank['tail'].hex()] += 1

        if args.census:
            print('%-16s %7d B  %d bank(s): %s'
                  % (os.path.basename(path), len(blob), len(banks),
                     '  '.join('%dx%dx%d' % (b['width'], b['height'], b['frames'])
                               for b in banks)))

        if args.render:
            stem = os.path.splitext(os.path.basename(path))[0]
            ext = os.path.splitext(path)[1].lstrip('.')
            for bank in banks:
                width, height, frames = bank['width'], bank['height'], bank['frames']
                base = bank['data_at']
                if args.sheet:
                    sheet_w = width * frames
                    rows = []
                    for y in range(height):
                        row = bytearray()
                        for frame in range(frames):
                            start = base + frame * width * height + y * width
                            row.extend(blob[start:start + width])
                        rows.append(bytes(row))
                    out = os.path.join(args.out, '%s_%s_b%d.png'
                                       % (stem, ext, bank['index']))
                    write_png(out, sheet_w, height, rows, pal)
                else:
                    for frame in range(frames):
                        start = base + frame * width * height
                        rows = [blob[start + y * width:start + (y + 1) * width]
                                for y in range(height)]
                        out = os.path.join(args.out, '%s_%s_b%d_f%02d.png'
                                           % (stem, ext, bank['index'], frame))
                        write_png(out, width, height, rows, pal)

    print('')
    print('opened %d of %d files' % (opened, len(args.files)))
    print('walked to EOF with residue 0: %d of %d' % (closed, len(args.files)))
    print('%d banks, %d frames, %d payload bytes'
          % (total_banks, total_frames, total_pixels))
    print('banks per member: ' + '  '.join('%d bank(s) x%d' % (key, n)
                                           for key, n in sorted(bank_counts.items())))
    print('distinct geometries: %d' % len(geometries))
    print('header +6 tails: ' + '  '.join('%s x%d' % (key, n) for key, n
                                          in sorted(tails.items())))
    if failures:
        raise SystemExit('FATAL: %d of %d members did not close'
                         % (len(failures), len(args.files)))


if __name__ == '__main__':
    main()
