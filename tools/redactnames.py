#!/usr/bin/env python3
"""redactnames.py -- replace a file NAME in a hashall listing while keeping
its row, its size and its hash.

WHY THIS EXISTS AND WHY `hashall.py --exclude-name` WAS NOT ENOUGH

`hashall.py` grew `--exclude-name` for an Android object whose files held a
live-service account identifier, where the sha1 itself was a lookup key. It
drops the row entirely. On this object the problem is the other way round:

  * the sha1 of a 548-byte player record is not a lookup key for anything;
  * **the file NAME is the personal datum.** This game names a player record
    after the string the player typed, so `notes/sha1-all.txt` would publish
    two names a stranger typed on their own machine in the 1990s simply by
    listing the directory.

Dropping the rows would take the census from 32 files and 1,584,769 bytes to
30 and 1,583,673, and rule 2 of this pipeline exists to stop a count quietly
shrinking. So the row stays, the size and hash stay, and the name is replaced
by a role.

Placeholders are assigned in **sha1 order, not name order**, so that the
listing does not leak the alphabetical position of the withheld strings.

Every failure is fatal:

  * a name given that is not in the listing;
  * a placeholder that would collide with a real name;
  * a change in the number of rows, the total size, or any other row.

    python tools/redactnames.py IN.txt --name a.plr --name b.plr \\
           --placeholder player-record --out notes/sha1-all.txt
"""
import argparse
import os
import re
import sys

ROW = re.compile(r"^([0-9a-f]{8,128})(\s+)(\d+)(\s+)(\S.*)$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("listing")
    ap.add_argument("--name", action="append", default=[], required=True)
    ap.add_argument("--placeholder", default="withheld")
    ap.add_argument("--out")
    a = ap.parse_args()

    lines = open(a.listing, encoding="utf-8").read().splitlines()
    rows = []
    for i, line in enumerate(lines):
        m = ROW.match(line)
        if m:
            rows.append((i, m))
    if not rows:
        raise SystemExit("redactnames: no hash rows matched in %s -- the "
                         "listing shape changed and this tool is now lying"
                         % a.listing)

    want = set(a.name)
    hit = [(i, m) for i, m in rows if m.group(5) in want]
    got = {m.group(5) for _, m in hit}
    missing = want - got
    if missing:
        raise SystemExit("redactnames: these names are not in the listing: %s"
                         % ", ".join(sorted(missing)))

    ext = os.path.splitext(sorted(want)[0])[1]
    hit.sort(key=lambda t: t[1].group(1))           # sha1 order, not name order
    for n, (i, m) in enumerate(hit):
        new = "%s-%s%s" % (a.placeholder, chr(ord("A") + n), ext)
        if any(mm.group(5) == new for _, mm in rows):
            raise SystemExit("redactnames: placeholder %r collides with a real "
                             "name in the listing" % new)
        lines[i] = "%s%s%s%s%s" % (m.group(1), m.group(2), m.group(3),
                                   m.group(4), new)

    before = sum(int(m.group(3)) for _, m in rows)
    out = "\n".join(lines) + "\n"
    after_rows = [ROW.match(l) for l in out.splitlines()]
    after_rows = [m for m in after_rows if m]
    if len(after_rows) != len(rows):
        raise SystemExit("redactnames: row count changed %d -> %d"
                         % (len(rows), len(after_rows)))
    after = sum(int(m.group(3)) for m in after_rows)
    if after != before:
        raise SystemExit("redactnames: total size changed %d -> %d"
                         % (before, after))

    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out)
    print("redactnames: %d of %d rows renamed, %d rows and %d bytes unchanged"
          % (len(hit), len(rows), len(rows), after), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
