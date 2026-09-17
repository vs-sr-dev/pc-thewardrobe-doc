#!/usr/bin/env python3
"""hsc.py -- read POP-CORN's `.HSC` high-score table.

**An extension is not a format.** `.HSC` is a well-known AdLib tracker music
format, and `pc-wackywheels-doc/docs/09-skunny-kart.md` records six `.HSC`
files inside Skunny Kart that really are music. `popcorn.hsc` is a
**high-score table**, and `popcorn.doc` says so in its own manifest:
*"POPCORN.HSC : Le fichier des High Scores."* Two products in one collection,
one extension, two unrelated formats -- so this reader tests the shape and
refuses anything that does not fit rather than trusting the name.

    180 bytes = 10 x 18
    +0   12   name, ASCII, space-padded and centred
    +12   6   score, ASCII decimal, zero-padded

Every byte of the file is printable ASCII; there is no header, no count and no
terminator. The empty slot is twelve `-` and `000000`, and the same 180-byte
default is embedded in `popcorn.exe` -- see docs, chapter on the user state --
so the file the game ships is the file the game writes when it has never been
played.

    python hsc.py FILE...
    python hsc.py FILE --validate     exit 1 unless it parses

Standard library only. It reads; it never writes.
"""

import argparse
import os
import sys

RECORD = 18
NAME = 12
SCORE = 6
EMPTY_NAME = b"-" * NAME


class NotHSC(Exception):
    pass


def parse(data):
    if len(data) % RECORD:
        raise NotHSC("%d bytes is not a whole number of %d-byte records"
                     % (len(data), RECORD))
    bad = [i for i, b in enumerate(data) if not (0x20 <= b <= 0x7E)]
    if bad:
        raise NotHSC("byte %d is 0x%02X, not printable ASCII"
                     % (bad[0], data[bad[0]]))
    out = []
    for i in range(len(data) // RECORD):
        r = data[i * RECORD:(i + 1) * RECORD]
        name, score = r[:NAME], r[NAME:]
        if not score.isdigit():
            raise NotHSC("record %d score field %r is not ASCII decimal"
                         % (i, score))
        out.append({
            "index": i,
            "name_raw": name,
            "name": name.decode("ascii").strip(),
            "score": int(score),
            "score_raw": score.decode("ascii"),
            "empty": name == EMPTY_NAME and int(score) == 0,
        })
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--validate", action="store_true")
    a = ap.parse_args(argv)

    failed = 0
    for p in a.paths:
        with open(p, "rb") as f:
            data = f.read()
        try:
            recs = parse(data)
        except NotHSC as e:
            print("%-16s REFUSED: %s" % (os.path.basename(p), e))
            failed += 1
            continue
        live = [r for r in recs if not r["empty"]]
        print("%-16s %d bytes = %d x %d, residue +0, %d of %d slots filled"
              % (os.path.basename(p), len(data), len(recs), RECORD,
                 len(live), len(recs)))
        for r in recs:
            print("   %2d  name %-14r score %s%s"
                  % (r["index"], r["name_raw"].decode("ascii"),
                     r["score_raw"], "" if r["empty"] else "   <-- filled"))
    if a.validate:
        print("\nhsc.py: %d of %d inputs parsed"
              % (len(a.paths) - failed, len(a.paths)))
        return 1 if failed else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
