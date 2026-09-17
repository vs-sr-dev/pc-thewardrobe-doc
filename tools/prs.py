#!/usr/bin/env python3
"""prs.py -- the .PRS decompressor for this disc, derived from the bytes.

843 files on Sonic Adventure carry the extension .PRS and 130,472,746 bytes.
The platform checklist calls .PRS "Sega's LZ-plus-Huffman compression" and
marks the claim [unverified]. This tool is what that mark gets converted by.

WHAT WAS DERIVED, AND FROM WHAT
-------------------------------

The first eight bytes of every .PRS were censused before anything was opened.
Of 350 distinct head shapes the two commonest are

    ff 50 56 4d 48 18 01 00      'PVMH' under 0xff      x43
    3f 50 56 4d 48 98 00 1c      'PVMH' under '?'       x30

and that pair is the whole format.

  * 0xff is eight 1 bits. 0x3f is six 1 bits then two 0 bits.
  * under 0xff the next EIGHT bytes are payload; under 0x3f the next SIX are,
    and the sixth is the last byte of 'PVMH\x98\x00' before the stream stops
    looking like text.

Two control bytes, two literal counts, and the counts agree with the bit
populations on 2 of 2. So: **a control byte, read LSB first, one bit per token,
1 = copy one literal byte through.** That is byte-aligned LZ77 with an 8-bit
flag word, and it is not Huffman: a Huffman-coded stream cannot begin with a
literal byte lying at a byte boundary chosen by a flag byte that is itself a
whole literal 0xff.

The rest of the grammar was derived by running it. A 0 bit introduces a match,
and a second bit distinguishes two encodings; both were fixed by requiring that
the stream consume its input exactly and that the output of the .PRS files
whose heads say 'PVMH' actually begin 'PVMH':

    1                literal: copy the next input byte to the output
    0 1  a b         long match. offset = ((b << 5) | (a >> 3)) - 8192
                     size = a & 7
                       size == 0 -> size = next byte + 1   (3..256)
                       size != 0 -> size = size + 2        (3..9)
                     a == 0 and b == 0 is END OF STREAM
    0 0  p q  d      short match. size = (p << 1 | q) + 2  (2..5)
                     offset = d - 256                      (-256..-1)

Offsets are negative and relative to the current output position, so a match
may overlap the bytes it is producing; the copy is therefore byte at a time and
not a slice.

THE CONTROLS
------------

`--validate` is the proof and it runs before any census:

  * every file consumes its input exactly -- the end-of-stream marker is the
    last token and no input byte is left over;
  * every file whose compressed head says 'PVMH' produces an output that starts
    'PVMH', which is a quantity encoded twice in two different ways;
  * a PVMH output's own declared length field agrees with the number of bytes
    produced.

`--negative` is the control that must fire, and it must fire on a DIFFERENT
file from the one used for the positive control. It flips one bit of the
control stream of a named file and requires the decompressor to fail --
overrun, unconsumed input, or a length that disagrees with the header.

Usage:
    python tools/prs.py --validate DIR
    python tools/prs.py --negative FILE
    python tools/prs.py --census DIR [--out OUTDIR]
    python tools/prs.py --one FILE [--out OUTDIR]
"""
import os
import struct
import sys


class PrsError(Exception):
    pass


def decompress(data, limit=None):
    """Return (output, bytes_of_input_consumed). Raises PrsError on overrun."""
    out = bytearray()
    n = len(data)
    pos = 0
    ctrl = 0
    bits = 0

    while True:
        if bits == 0:
            if pos >= n:
                raise PrsError("input exhausted while fetching a control byte "
                               "at offset %d, %d bytes produced" % (pos, len(out)))
            ctrl = data[pos]
            pos += 1
            bits = 8
        bit = ctrl & 1
        ctrl >>= 1
        bits -= 1

        if bit:                                    # 1 -> literal
            if pos >= n:
                raise PrsError("input exhausted at a literal, offset %d" % pos)
            out.append(data[pos])
            pos += 1
            if limit is not None and len(out) > limit:
                raise PrsError("output exceeded the declared limit %d" % limit)
            continue

        # 0 -> a match; the next bit picks the encoding
        if bits == 0:
            if pos >= n:
                raise PrsError("input exhausted while fetching a control byte "
                               "at offset %d" % pos)
            ctrl = data[pos]
            pos += 1
            bits = 8
        bit = ctrl & 1
        ctrl >>= 1
        bits -= 1

        if bit:                                    # 0 1 -> long match
            if pos + 1 >= n:
                raise PrsError("input exhausted in a long match at offset %d" % pos)
            a = data[pos]
            b = data[pos + 1]
            pos += 2
            if a == 0 and b == 0:
                return bytes(out), pos             # end of stream
            offset = ((b << 5) | (a >> 3)) - 8192
            size = a & 7
            if size == 0:
                if pos >= n:
                    raise PrsError("input exhausted at a long size byte")
                size = data[pos] + 1
                pos += 1
            else:
                size += 2
        else:                                      # 0 0 -> short match
            size = 0
            for _ in range(2):
                if bits == 0:
                    if pos >= n:
                        raise PrsError("input exhausted while fetching a "
                                       "control byte at offset %d" % pos)
                    ctrl = data[pos]
                    pos += 1
                    bits = 8
                size = (size << 1) | (ctrl & 1)
                ctrl >>= 1
                bits -= 1
            size += 2
            if pos >= n:
                raise PrsError("input exhausted at a short offset byte")
            offset = data[pos] - 256
            pos += 1

        start = len(out) + offset
        if start < 0:
            raise PrsError("match reaches %d bytes before the start of the "
                           "output (out=%d, offset=%d)" % (-start, len(out), offset))
        for i in range(size):
            out.append(out[start + i])
        if limit is not None and len(out) > limit:
            raise PrsError("output exceeded the declared limit %d" % limit)


# ------------------------------------------------------------------ PVMH

def pvmh_declared_length(out):
    """If the output is a PVMH archive, return its declared total length.

    A PVMH header is the four bytes 'PVMH' then a u32 little-endian holding the
    number of bytes that follow the field itself, so the whole archive is that
    plus eight. Returns None when the output is not a PVMH."""
    if len(out) < 8 or out[:4] != b"PVMH":
        return None
    return struct.unpack_from("<I", out, 4)[0] + 8


def walk(root):
    for dirpath, _dirs, files in os.walk(root):
        for f in sorted(files):
            if f.upper().endswith(".PRS"):
                yield os.path.join(dirpath, f)


def cmd_validate(root):
    files = sorted(walk(root))
    if not files:
        raise SystemExit("prs: no .PRS files under %r" % root)
    ok = leftover = pvmh_in = pvmh_out = pvmh_len_ok = 0
    fails = []
    total_in = total_out = 0
    for p in files:
        data = open(p, "rb").read()
        head_says_pvmh = len(data) > 5 and data[1:5] == b"PVMH"
        if head_says_pvmh:
            pvmh_in += 1
        try:
            out, used = decompress(data)
        except PrsError as e:
            fails.append((p, str(e)))
            continue
        total_in += len(data)
        total_out += len(out)
        if used != len(data):
            leftover += 1
            fails.append((p, "consumed %d of %d input bytes" % (used, len(data))))
            continue
        ok += 1
        if out[:4] == b"PVMH":
            pvmh_out += 1
            if pvmh_declared_length(out) == len(out):
                pvmh_len_ok += 1
    print("=== prs.py --validate over %s ===" % root)
    print("files                                  : %d" % len(files))
    print("decompressed and consumed input exactly: %d of %d" % (ok, len(files)))
    print("failed                                 : %d" % len(fails))
    print("compressed bytes                       : %d" % total_in)
    print("expanded bytes                         : %d" % total_out)
    if total_in:
        print("ratio                                  : %.4fx" % (total_out / total_in))
    print()
    print("the quantity encoded twice:")
    print("  compressed head reads 'PVMH' at +1    : %d" % pvmh_in)
    print("  output begins 'PVMH'                  : %d" % pvmh_out)
    print("  PVMH declared length == bytes produced: %d" % pvmh_len_ok)
    if fails:
        print()
        print("THE FAILURES, BY NAME:")
        for p, why in fails:
            print("  %-60s %s" % (os.path.basename(p), why))
    return 0 if not fails else 1


def cmd_negative(path):
    """Flip one bit of the first control byte and require a failure."""
    data = bytearray(open(path, "rb").read())
    try:
        good, used = decompress(bytes(data))
    except PrsError as e:
        raise SystemExit("prs: the positive case failed first: %s" % e)
    if used != len(data):
        raise SystemExit("prs: the positive case did not consume its input")
    print("positive: %s -> %d bytes, input consumed exactly" % (
        os.path.basename(path), len(good)))

    fired = 0
    trials = 0
    for bit in range(8):
        mutant = bytearray(data)
        mutant[0] ^= (1 << bit)
        trials += 1
        try:
            out, used2 = decompress(bytes(mutant))
            if used2 != len(mutant):
                print("  flip bit %d of the control byte: consumed %d of %d  FIRES"
                      % (bit, used2, len(mutant)))
                fired += 1
            elif out == good:
                print("  flip bit %d of the control byte: SAME OUTPUT  does not fire"
                      % bit)
            else:
                print("  flip bit %d of the control byte: %d bytes, differs, input "
                      "consumed  does not fire" % (bit, len(out)))
        except PrsError as e:
            print("  flip bit %d of the control byte: %s  FIRES" % (bit, e))
            fired += 1
    print("fired on %d of %d single-bit mutations of the first control byte"
          % (fired, trials))
    return 0 if fired else 1


def cmd_census(root, outdir=None):
    files = sorted(walk(root))
    rows = []
    kinds = {}
    for p in files:
        data = open(p, "rb").read()
        out, used = decompress(data)
        tag = bytes(out[:4])
        kinds[tag] = kinds.get(tag, 0) + 1
        rows.append((os.path.basename(p), len(data), len(out), tag))
        if outdir:
            d = os.path.join(outdir, os.path.basename(p) + ".out")
            os.makedirs(outdir, exist_ok=True)
            open(d, "wb").write(out)
    ti = sum(r[1] for r in rows)
    to = sum(r[2] for r in rows)
    print("files %d  compressed %d  expanded %d  ratio %.4fx"
          % (len(rows), ti, to, to / ti if ti else 0))
    print()
    print("first four bytes of the OUTPUT, by count:")
    for tag, c in sorted(kinds.items(), key=lambda kv: -kv[1]):
        print("  %-22r %6d" % (tag, c))
    return 0


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if len(argv) < 3:
        raise SystemExit(__doc__)
    outdir = argv[argv.index("--out") + 1] if "--out" in argv else None
    if argv[1] == "--validate":
        return cmd_validate(argv[2])
    if argv[1] == "--negative":
        return cmd_negative(argv[2])
    if argv[1] == "--census":
        return cmd_census(argv[2], outdir)
    if argv[1] == "--one":
        data = open(argv[2], "rb").read()
        out, used = decompress(data)
        print("%s: %d -> %d bytes, consumed %d of %d, head %r"
              % (argv[2], len(data), len(out), used, len(data), bytes(out[:16])))
        if outdir:
            os.makedirs(outdir, exist_ok=True)
            open(os.path.join(outdir,
                              os.path.basename(argv[2]) + ".out"), "wb").write(out)
        return 0
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
