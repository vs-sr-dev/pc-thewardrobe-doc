#!/usr/bin/env python3
"""popmsg.py -- extract the obfuscated credits message from an unpacked
POP-CORN image, and account for every byte of it.

`popcorn.exe` is a Microsoft EXEPACK image (see `exepack.py`). Unpack it and
2,417 bytes near offset 16,158 decode, byte for byte, as CP437 text XORed with
0xAA. It is the game's hidden credits scroller: who wrote the code, who drew
the graphics and with what, the studio's contact details, and two thousand
characters of the two authors arguing with each other at four in the morning.

**None of it is a string in the shipped file** -- `strings` over `popcorn.exe`
finds the interface and not this, because every letter has bit patterns no
printable-run scanner will accept. It is the same lesson the previous object
taught with PCX images: what the program does not say in words it hides
somewhere a grep does not go.

THE ENCODING, WHICH HAS EXACTLY THREE KINDS OF BYTE

    char ^ 0xAA     a CP437 character; 0x8A is a space, 0xCF is 'e'
    0x0A            a literal line feed, NOT XORed
    '23016745'      eight literal ASCII digits, NOT XORed

The third is the interesting one. `23016745` occurs seven times, each followed
by a literal 0x0A, and it sits exactly where the game's own title belongs in
two sentences that otherwise have no subject -- "<token> est un FREEWARE ..."
and "... les secrets de <token>". **It is a substitution token the scroller
replaces, not data and not a telephone number.** The pre-briefing recorded it
as an unread permutation of 0..7; the grammar around it is the evidence.

REDACTION

The message contains an eight-digit French telephone number, given twice, for
a bulletin-board service the authors ran in 1988. `--redact` replaces it with
`[REDACTED: an 8-digit French telephone number, twice]`. **The default is
redacted**, because the default should be the safe one; `--raw` prints the
message as it is on disc and is there for a reader working locally on their own
copy of the object.

    python popmsg.py UNPACKED.bin                 redacted text
    python popmsg.py UNPACKED.bin --accounting    the byte census, no text
    python popmsg.py UNPACKED.bin --raw           unredacted
    python popmsg.py FILE --refuse                assert no message; exit 1 if one

Standard library only. It reads; it never writes.
"""

import argparse
import re
import sys

KEY = 0xAA
TOKEN = b"23016745"
PHONE = re.compile(r"\d\d\.\d\d\.\d\d\.\d\d")
REDACTION = "[REDACTED: an 8-digit French telephone number]"

# The message is found, not assumed: this is the first sentence of it, encoded.
ANCHOR = bytes(c ^ KEY for c in b" est un FREEWARE")


def is_char(b):
    """True if b decodes to a character this message actually uses.

    The range matters, and both edges of it were found by being wrong.

    Too wide: a first draft accepted anything decoding to 0x20 or above, which
    admits 0x00 -- because 0x00 ^ 0xAA is 0xAA, a printable CP437 character --
    and the region grew from 2,417 bytes to 5,203 by eating the zero padding
    on both sides.

    Too narrow: a second draft stopped at 0x8F and cut the message off after
    746 bytes, at the u-grave of "o~", because French needs 0x93, 0x96 and
    0x97 as well.

    So: ASCII 0x20..0x7E, plus the CP437 accented-Latin band 0x80..0x97. It
    stops at 0x97 deliberately. The eight digits of the substitution token
    decode to exactly 0x98..0x9F, and admitting those would let the token be
    silently absorbed as text instead of being counted as a token.
    """
    v = b ^ KEY
    return 0x20 <= v <= 0x7E or 0x80 <= v <= 0x97


def find_region(data):
    """Return (start, end) of the message, or None.

    Found by anchoring on one encoded sentence and then growing outwards while
    every byte is one of the three kinds the encoding has. Growing rather than
    hard-coding an offset is what lets the same tool run against a different
    build of the same program and say honestly that it found nothing.
    """
    a = data.find(ANCHOR)
    if a < 0:
        return None

    def classify_at(i, forward=True):
        if data[i:i + len(TOKEN)] == TOKEN:
            return len(TOKEN)
        b = data[i]
        if b == 0x0A:
            return 1
        return 1 if is_char(b) else 0

    start = a
    while start > 0:
        j = start - 1
        # a token is only recognised on its own left edge
        if data[j - len(TOKEN) + 1:j + 1] == TOKEN:
            start = j - len(TOKEN) + 1
            continue
        if data[j] == 0x0A or is_char(data[j]):
            start = j
            continue
        break
    end = a
    while end < len(data):
        step = classify_at(end)
        if not step:
            break
        end += step
    return start, end


def census(seg):
    counts = {"char ^0xAA": 0, "LF literal": 0, "token %s"
              % TOKEN.decode(): 0, "unclassified": 0}
    i = 0
    bad = []
    while i < len(seg):
        if seg[i:i + len(TOKEN)] == TOKEN:
            counts["token %s" % TOKEN.decode()] += 1
            i += len(TOKEN)
            continue
        b = seg[i]
        if b == 0x0A:
            counts["LF literal"] += 1
        elif is_char(b):
            counts["char ^0xAA"] += 1
        else:
            counts["unclassified"] += 1
            bad.append(i)
        i += 1
    return counts, bad


def decode(seg):
    """Decode to text. The plaintext is code page 437, not Latin-1: the
    accents are at 0x82, 0x85, 0x88 and so on, so `chr(b ^ KEY)` gives the
    wrong letters and, on a Windows console, an exception."""
    out = []
    i = 0
    while i < len(seg):
        if seg[i:i + len(TOKEN)] == TOKEN:
            out.append("<TITLE>")
            i += len(TOKEN)
            continue
        b = seg[i]
        out.append("\n" if b == 0x0A
                   else bytes([b ^ KEY]).decode("cp437"))
        i += 1
    return "".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--raw", action="store_true",
                    help="print the telephone number as it is on disc")
    ap.add_argument("--accounting", action="store_true",
                    help="print the byte census and no message text")
    ap.add_argument("--refuse", action="store_true",
                    help="assert there is NO message here; exit 1 if there is")
    args = ap.parse_args(argv)

    with open(args.path, "rb") as f:
        data = f.read()
    r = find_region(data)

    if args.refuse:
        if r is None:
            print("%s: no XOR-0xAA message (refused, as required)" % args.path)
            return 0
        print("%s: FOUND a message at %d..%d -- CONTROL FAILED"
              % (args.path, r[0], r[1]))
        return 1

    if r is None:
        print("%s: no XOR-0xAA message found" % args.path)
        return 1

    start, end = r
    seg = data[start:end]
    counts, bad = census(seg)
    print("region                 : %d .. %d  = %d bytes"
          % (start, end, len(seg)))
    print("byte before / after    : %02X / %02X"
          % (data[start - 1], data[end] if end < len(data) else 0))
    for k, v in counts.items():
        print("  %-20s : %d" % (k, v))
    total = (counts["char ^0xAA"] + counts["LF literal"]
             + counts["token %s" % TOKEN.decode()] * len(TOKEN)
             + counts["unclassified"])
    print("  %-20s : %d, residue %+d"
          % ("accounted", total, len(seg) - total))
    if bad:
        print("  UNCLASSIFIED AT      : %s" % bad[:20])
        return 1
    if args.accounting:
        return 0

    text = decode(seg)
    if not args.raw:
        text = PHONE.sub(REDACTION, text)
    print()
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
