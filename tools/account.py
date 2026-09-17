#!/usr/bin/env python3
"""account.py -- the coverage figure, on ONE denominator, by command.

REWRITTEN FOR THIS OBJECT, a second session running. The version inherited
from `pc-skunnybacktotheforest-doc` was built for an object with five archives
and two denominators; it walked `_work/members` and allocated archive share
proportionally. **This object has no container of any kind**, so that whole
machine is inapplicable and none of it survives but the shape.

THE RULE, inherited verbatim from
`pc-linksthechallengeofgolf-doc/docs/01-the-object.md` line 121 so that it can
be argued with:

    a record counts as identified when a reader in `tools/` parses it end to
    end with zero residue and every byte lands in a named field.

Reading a file as text counts. **READING AN MZ HEADER AND STOPPING DOES NOT.**

ONE DENOMINATOR, AND THE DECISION IS THE POINT

Every previous object in this series had two denominators, and every one of
them inherited the second from the presence of an archive: D1 was the files on
the disc and D2 was the archive members plus the files that were not archives.
**Nine files, none of which is a container, means the two are the same number**,
and inventing a second denominator here would be inventing a distinction the
object does not have. So:

    D1 = 169,530 bytes, the nine files as they sit in the directory.

The one thing that could have made a second denominator is `popcorn.exe`, which
this session unpacked from 103,336 bytes of EXEPACK'd image to 133,296 bytes of
program. **It is deliberately NOT used as a denominator.** Unpacking a program
does not identify it, and a denominator that grew every time a session
decompressed something would make coverage a measure of effort rather than of
bytes explained.

WHAT THE CEILING IS, AND WHY IT IS NOT A FAILURE

    147,334 of 169,530 bytes = 86.9073 % is executable, and the rule counts an
    executable as unidentified however much of it is read.

So this object's coverage cannot exceed **22,196 / 169,530 = 13.0927 %**, and
that is the number to beat and also the number to stop at. The pre-briefing
stated the same two figures as 86.2 % and "about 13.8 %"; both are wrong and
this tool prints the arithmetic that shows it.

    python tools/account.py
    python tools/account.py --game game --json
"""

import argparse
import json
import os
import sys

# Which reader closes which file, and what it was asked to prove. Every entry
# corresponds to a command in docs/02. A file absent from this table is
# unidentified by definition rather than by oversight, and the tool refuses to
# run if the directory holds a file this table does not mention.
READERS = {
    "popcorn.doc": ("read as code-page-437 text, 121 CRLF lines, no residue",
                    True),
    "pop.bat": ("read as text, 13 bytes, one command line", True),
    "ltf.bat": ("read as text, 16 bytes, one command line", True),
    "popcorn.hsc": ("hsc.py: 10 x 18 records, every byte printable ASCII, "
                    "residue 0", True),
    "poptab.ppc": ("ppc.py: LACRAL + 49 x 176, 8-byte header and 12 x 14 "
                   "grid, residue 0", True),
    "ltf.ppc": ("ppc.py: LACRAL + 49 x 176, 8-byte header and 12 x 14 grid, "
                "residue 0", True),
    "popcorn.exe": ("MZ header and EXEPACK container read; the program is "
                    "not parsed", False),
    "popgen.exe": ("MZ header read; the program is not parsed", False),
    "popspeed.exe": ("MZ header read; the program is not parsed", False),
}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--game", default="game")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if not os.path.isdir(a.game):
        raise SystemExit("account.py: no such directory: %s" % a.game)

    names = sorted(os.listdir(a.game))
    unknown = [n for n in names if n not in READERS]
    missing = [n for n in READERS if n not in names]
    if unknown or missing:
        # Loud, because a silently-skipped file is how a coverage figure
        # becomes a lie. This is the whole reason the table is explicit.
        for n in unknown:
            print("account.py: %s is in %s and not in the READERS table"
                  % (n, a.game))
        for n in missing:
            print("account.py: %s is in the READERS table and not in %s"
                  % (n, a.game))
        return 2

    rows = []
    for n in names:
        size = os.path.getsize(os.path.join(a.game, n))
        why, ident = READERS[n]
        rows.append((n, size, ident, why))

    total = sum(r[1] for r in rows)
    ident = sum(r[1] for r in rows if r[2])
    exe = sum(r[1] for r in rows if r[0].lower().endswith(".exe"))

    if a.json:
        print(json.dumps({"files": len(rows), "D1": total,
                          "identified": ident,
                          "coverage_pct": 100.0 * ident / total}, indent=2))
        return 0

    print("%-16s %9s  %-12s %s" % ("file", "bytes", "counted", "why"))
    for n, size, i, why in rows:
        print("%-16s %9d  %-12s %s"
              % (n, size, "IDENTIFIED" if i else "no", why))
    print()
    print("files                      : %d" % len(rows))
    print("D1, the nine files         : %d bytes" % total)
    print("  of which executable      : %d = %.4f %%"
          % (exe, 100.0 * exe / total))
    print("  the ceiling that leaves  : %d = %.4f %%"
          % (total - exe, 100.0 * (total - exe) / total))
    print("identified                 : %d bytes" % ident)
    print()
    print("COVERAGE ON D1             : %d / %d = %.4f %%"
          % (ident, total, 100.0 * ident / total))
    print()
    print("There is no D2. Nine files, no container: see the docstring.")
    if ident == total - exe:
        print("The figure is AT the ceiling: every non-executable byte closes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
