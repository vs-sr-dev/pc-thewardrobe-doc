#!/usr/bin/env python3
"""predcount.py -- count the clauses in docs/00-predictions.md and sum the
predicted-score column, by command, out of the document's own text.

Rule 1 of this pipeline requires that the clause count and the score total in
a predictions document be produced by a command rather than by adding up by
hand. The last three sessions did that and the command caught an error every
time; the most recent said 86.0 where the sum was 71.0.

`checkscore.py` counts verdict TABLES in a scoring document. This counts
CLAUSE PARAGRAPHS in a predictions document, which is a different shape:

    **Cnn** `method|content` `inherited|open` -- prose. *Predicted: N.N*

The two totals are reported separately and are never added together, because
`inherited` clauses re-test somebody else's measurement and `open` clauses are
the session's own work. Summing them produces a number that means nothing.

Failure is loud and is the point:

  * a clause whose tags are missing, duplicated or unrecognised is fatal;
  * a clause with no `*Predicted:*` figure is fatal;
  * a gap or a repeat in the Cnn numbering is fatal;
  * a `--expect-count` or `--expect-total` that does not match is fatal.

    python tools/predcount.py
    python tools/predcount.py docs/00-predictions.md
    python tools/predcount.py --expect-count 46 --expect-open-total 24.0
"""
import argparse
import collections
import os
import re
import sys

# A clause runs until the next clause, the next heading, or the next
# horizontal rule -- NOT to end of document. Terminating on \Z alone made the
# last clause swallow the closing section, and since that section contains the
# sentence "every clause carries `method` or `content`", the tool reported a
# duplicate tag on C46 that was its own and not the document's. Caught on the
# first run, which is what a loud failure is for.
CLAUSE = re.compile(
    r"^\*\*(C\d+)\*\*\s+(.+?)(?=^\*\*C\d+\*\*|^#{1,6} |^---\s*$|\Z)",
    re.M | re.S,
)
KIND = re.compile(r"`(method|content)`")
ORIGIN = re.compile(r"`(inherited|open)`")
PREDICTED = re.compile(r"\*Predicted:\s*([0-9]+(?:\.[0-9]+)?)\*")


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?",
                    default=os.path.join(root, "docs", "00-predictions.md"))
    ap.add_argument("--expect-count", type=int)
    ap.add_argument("--expect-open-total", type=float)
    ap.add_argument("--expect-inherited-total", type=float)
    args = ap.parse_args()

    if not os.path.exists(args.path):
        raise SystemExit("predcount: no such file: %s" % args.path)
    text = open(args.path, encoding="utf-8").read()

    rows = []
    errors = []
    for m in CLAUSE.finditer(text):
        tag, body = m.group(1), m.group(2)
        kinds = KIND.findall(body)
        origins = ORIGIN.findall(body)
        preds = PREDICTED.findall(body)
        if len(kinds) != 1:
            errors.append("%s: expected exactly one method/content tag, got %d"
                          % (tag, len(kinds)))
        if len(origins) != 1:
            errors.append("%s: expected exactly one inherited/open tag, got %d"
                          % (tag, len(origins)))
        if len(preds) != 1:
            errors.append("%s: expected exactly one *Predicted:* figure, got %d"
                          % (tag, len(preds)))
        if kinds and origins and preds:
            rows.append((tag, kinds[0], origins[0], float(preds[0])))

    if not rows:
        raise SystemExit("predcount: no clauses matched in %s -- the document "
                         "shape changed and this tool is now lying" % args.path)

    nums = [int(t[0][1:]) for t in rows]
    expected = list(range(1, len(nums) + 1))
    if sorted(nums) != expected:
        missing = sorted(set(expected) - set(nums))
        extra = [n for n, c in collections.Counter(nums).items() if c > 1]
        errors.append("clause numbering is not C01..C%02d: missing %s, "
                      "repeated %s" % (len(nums), missing or "none",
                                       extra or "none"))

    by_origin = collections.Counter(r[2] for r in rows)
    by_kind = collections.Counter(r[1] for r in rows)
    cross = collections.Counter((r[2], r[1]) for r in rows)
    totals = collections.defaultdict(float)
    for r in rows:
        totals[r[2]] += r[3]

    print("document      : %s" % os.path.relpath(args.path, root))
    print("clauses        : %d" % len(rows))
    print("  inherited    : %d" % by_origin["inherited"])
    print("  open         : %d" % by_origin["open"])
    print("  method       : %d" % by_kind["method"])
    print("  content      : %d" % by_kind["content"])
    print()
    print("the cross-tabulation, which is the one that matters:")
    for origin in ("inherited", "open"):
        for kind in ("method", "content"):
            print("  %-9s %-7s : %d" % (origin, kind, cross[(origin, kind)]))
    print()
    print("TWO TOTALS, NEVER SUMMED TOGETHER:")
    print("  inherited predicted : %.2f of %d" %
          (totals["inherited"], by_origin["inherited"]))
    print("  open      predicted : %.2f of %d" %
          (totals["open"], by_origin["open"]))
    print()
    n_open_content = cross[("open", "content")]
    n_open = by_origin["open"] or 1
    print("content share of the open clauses : %d of %d = %.1f %%"
          % (n_open_content, by_origin["open"],
             100.0 * n_open_content / n_open))
    print("  (the prescription in force says write FEWER of these on a")
    print("   container nobody has opened; they score about 68 %.)")

    if args.expect_count is not None and args.expect_count != len(rows):
        errors.append("--expect-count %d but counted %d"
                      % (args.expect_count, len(rows)))
    if (args.expect_open_total is not None
            and abs(args.expect_open_total - totals["open"]) > 1e-9):
        errors.append("--expect-open-total %.2f but summed %.2f"
                      % (args.expect_open_total, totals["open"]))
    if (args.expect_inherited_total is not None
            and abs(args.expect_inherited_total - totals["inherited"]) > 1e-9):
        errors.append("--expect-inherited-total %.2f but summed %.2f"
                      % (args.expect_inherited_total, totals["inherited"]))

    if errors:
        print()
        print("FAILURES (%d):" % len(errors), file=sys.stderr)
        for e in errors:
            print("  %s" % e, file=sys.stderr)
        return 1
    print()
    print("all clauses carry exactly one kind tag, one origin tag and one")
    print("predicted figure, and the numbering is contiguous.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
