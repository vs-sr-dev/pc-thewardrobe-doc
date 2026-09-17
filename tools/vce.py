#!/usr/bin/env python3
"""vce.py -- read the twelve `.VCE` members of `VOC.LID`.

THE BLOCK CHAIN IS SOMEBODY ELSE'S FORMAT AND THAT IS SAID OUT LOUD. Creative
Technology published the Creative Voice File layout; the block types, the
24-bit little-endian block length and the time-constant-to-sample-rate formula
below are that public specification and are not a finding of this pipeline.

WHAT IS A FINDING is the four bytes in front of it, and why the previous
pass's negative result was right about the bytes and wrong about the
conclusion. `_pre\\formats.txt` measured that **0 of 12 `.VCE` members begin
with the ASCII `Creative Voice File`** and asked whether they were VOC at all.
They are. A `.VCE` member is:

    +0    u16 LE   a sample rate in Hz, a whole multiple of 1000 on 12 of 12
    +2    u16 LE   a flag, 0 on eleven members and 1 on EX1.VCE
    +4    ...      a Creative VOC BLOCK CHAIN with no 26-byte file header

The prefix was read as a u32 on the first pass and eleven of twelve values
came out round while EX1.VCE read 75,536. 75,536 is 0x00012710 and 0x2710 is
10,000, so the field is two u16 and not one u32 -- the same width error this
pipeline has now made three times, caught here by the one member that made
the wrong width visible. AND THE TWO RATES DISAGREE: the prefix rate and the
rate implied by the block's time constant differ on 8 of 12 members, which is
measured and not explained.

The string the previous pass searched for was never going to be there: the
member begins where a `.VOC` file's twenty-seventh byte begins, and carries a
four-byte prefix of its own. The engine's `_PlayVOCBlock` and `_SetVOCIndex`
symbols name exactly that entry point.

THE BLOCK CHAIN, from the public specification:

    u8    block type      1 = sound data, 0 = terminator (no length field)
    u24   block length    little-endian, payload bytes that follow

    type 1 payload:  u8 time constant, u8 pack type, then samples
                     sample rate = 1000000 / (256 - time constant)
                     pack type 0 = 8-bit unsigned PCM, one byte per sample

A member closes when the chain consumes every byte and ends on a terminator.

    python tools/vce.py --validate _work/members/VOC/*.VCE
    python tools/vce.py --census   _work/members/VOC/*.VCE
    python tools/vce.py --wav      _work/members/VOC/*.VCE --out _work/wav

Validate before census, always.
"""
import argparse
import collections
import os
import struct
import sys

BLOCK_NAMES = {
    0: 'terminator', 1: 'sound data', 2: 'sound continue', 3: 'silence',
    4: 'marker', 5: 'ASCII', 6: 'repeat', 7: 'end repeat', 8: 'extended',
    9: 'new sound data',
}


class VceError(Exception):
    pass


def parse(path, blob):
    if len(blob) < 5:
        raise VceError('%s: %d bytes, too short for a prefix and a block'
                       % (path, len(blob)))
    declared_rate, flag = struct.unpack_from('<2H', blob, 0)
    pos = 4
    blocks = []
    terminated = False
    while pos < len(blob):
        block_type = blob[pos]
        if block_type == 0:
            blocks.append({'type': 0, 'offset': pos, 'length': 0})
            pos += 1
            terminated = True
            break
        if pos + 4 > len(blob):
            raise VceError('%s: block type %d at %d has no 24-bit length'
                           % (path, block_type, pos))
        length = blob[pos + 1] | (blob[pos + 2] << 8) | (blob[pos + 3] << 16)
        body = pos + 4
        if body + length > len(blob):
            raise VceError('%s: block type %d at %d declares %d bytes and runs '
                           '%d past the %d-byte member'
                           % (path, block_type, pos, length,
                              body + length - len(blob), len(blob)))
        entry = {'type': block_type, 'offset': pos, 'length': length,
                 'body': body}
        if block_type == 1:
            if length < 2:
                raise VceError('%s: sound block at %d is %d bytes, shorter than '
                               'its two-byte parameter pair' % (path, pos, length))
            entry['time_constant'] = blob[body]
            entry['pack'] = blob[body + 1]
            entry['samples'] = length - 2
            entry['rate'] = 1000000 // (256 - blob[body]) if blob[body] < 256 else 0
        blocks.append(entry)
        pos = body + length
    if not terminated:
        raise VceError('%s: chain ended at %d of %d without a terminator block'
                       % (path, pos, len(blob)))
    if pos != len(blob):
        raise VceError('%s: terminator at %d leaves %d bytes of residue'
                       % (path, pos - 1, len(blob) - pos))
    return declared_rate, flag, blocks


def write_wav(path, rate, samples):
    data = bytes(samples)
    header = b'RIFF' + struct.pack('<I', 36 + len(data)) + b'WAVEfmt '
    header += struct.pack('<IHHIIHH', 16, 1, 1, rate, rate, 1, 8)
    header += b'data' + struct.pack('<I', len(data))
    with open(path, 'wb') as handle:
        handle.write(header + data)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+')
    ap.add_argument('--validate', action='store_true')
    ap.add_argument('--census', action='store_true')
    ap.add_argument('--wav', action='store_true')
    ap.add_argument('--out', default=None)
    args = ap.parse_args()
    if not (args.validate or args.census or args.wav):
        ap.error('pick one of --validate --census --wav')
    if args.wav and not args.out:
        ap.error('--wav needs --out')
    if args.wav:
        os.makedirs(args.out, exist_ok=True)

    opened = 0
    closed = 0
    round_rates = 0
    types = collections.Counter()
    packs = collections.Counter()
    rates = collections.Counter()
    declared = collections.Counter()
    flags = collections.Counter()
    disagree = 0
    failures = []

    for path in sorted(args.files):
        with open(path, 'rb') as handle:
            blob = handle.read()
        try:
            rate, flag, blocks = parse(path, blob)
        except VceError as exc:
            failures.append(str(exc))
            print('FAIL  %s' % exc)
            continue
        opened += 1
        closed += 1
        if rate % 1000 == 0:
            round_rates += 1
        declared[rate] += 1
        flags[flag] += 1
        for block in [b for b in blocks if b['type'] == 1]:
            if block['rate'] != rate:
                disagree += 1
        sound = [b for b in blocks if b['type'] == 1]
        for block in blocks:
            types[block['type']] += 1
        for block in sound:
            packs[block['pack']] += 1
            rates[block['rate']] += 1

        if args.validate or args.census:
            print('%-12s %6d B  prefix %5d Hz flag %d  %d block(s): %s  '
                  'samples %6d  tc %s -> %s Hz  pack %s'
                  % (os.path.basename(path), len(blob), rate, flag, len(blocks),
                     '+'.join(BLOCK_NAMES.get(b['type'], '?%d' % b['type'])
                              for b in blocks),
                     sum(b['samples'] for b in sound),
                     '/'.join(str(b['time_constant']) for b in sound),
                     '/'.join(str(b['rate']) for b in sound),
                     '/'.join(str(b['pack']) for b in sound)))

        if args.wav:
            samples = bytearray()
            for block in sound:
                samples.extend(blob[block['body'] + 2:
                                    block['body'] + 2 + block['samples']])
            stem = os.path.splitext(os.path.basename(path))[0]
            write_wav(os.path.join(args.out, stem + '.wav'),
                      sound[0]['rate'] if sound else rate, samples)

    print('')
    print('opened %d of %d files' % (opened, len(args.files)))
    print('block chain consumed the member with a terminator and residue 0: '
          '%d of %d' % (closed, len(args.files)))
    print('prefix u16 rate is a whole multiple of 1000: %d of %d'
          % (round_rates, opened))
    print('prefix flag values: ' + '  '.join('%d x%d' % (k, n) for k, n
                                             in sorted(flags.items())))
    print('sound blocks whose time-constant rate differs from the prefix rate: '
          '%d of %d' % (disagree, opened))
    print('block types: ' + '  '.join('%s x%d' % (BLOCK_NAMES.get(k, k), n)
                                      for k, n in sorted(types.items())))
    print('pack types:  ' + '  '.join('%d x%d' % (k, n) for k, n in sorted(packs.items())))
    print('rates from the time constant: '
          + '  '.join('%d x%d' % (k, n) for k, n in sorted(rates.items())))
    print('rates from the u16 prefix:    '
          + '  '.join('%d x%d' % (k, n) for k, n in sorted(declared.items())))
    if failures:
        raise SystemExit('FATAL: %d of %d members did not close'
                         % (len(failures), len(args.files)))


if __name__ == '__main__':
    main()
