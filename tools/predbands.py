#!/usr/bin/env python3
"""predbands.py -- the P11 bands of a predictions document, by command.

`predcount.py` counts clauses and sums the two totals. It knows nothing about
the third tag that P8 introduced and P11 kept: every OPEN CONTENT clause carries
`lands`, `constructs` or `nonnumeric`, and the scoring chapter has to report the
three bands separately. Writing those three sums by hand is exactly the kind of
arithmetic this pipeline gets wrong, so it is a command.

  * a band tag on a clause that is not open content is fatal;
  * an open content clause with no band tag, or with two, is fatal;
  * `--expect-under` checks how many open content clauses are priced below a
    threshold, which is P12's test and must not be satisfiable by accident.

    python tools/predbands.py
    python tools/predbands.py docs/00-predictions.md --expect-under 0.60 5
"""
import argparse
import collections
import os
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CLAUSE = re.compile(
    r"^\*\*(C\d+)\*\*\s+(.+?)(?=^\*\*C\d+\*\*|^#{1,6} |^---\s*$|\Z)",
    re.M | re.S,
)
KIND = re.compile(r"`(method|content)`")
ORIGIN = re.compile(r"`(inherited|open)`")
BAND = re.compile(r"`(lands|constructs|nonnumeric)`")
PREDICTED = re.compile(r"\*Predicted:\s*([0-9]+(?:\.[0-9]+)?)\*")

BANDS = ("lands", "constructs", "nonnumeric")


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?",
                    default=os.path.join(root, "docs", "00-predictions.md"))
    ap.add_argument("--expect-under", nargs=2, metavar=("THRESHOLD", "COUNT"))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if not os.path.exists(args.path):
        raise SystemExit("predbands: no such file: %s" % args.path)
    text = open(args.path, encoding="utf-8").read()

    rows, errors = parse(text)
    if not rows:
        raise SystemExit("predbands: no clauses matched -- the document shape "
                         "changed and this tool is now lying")

    banded = [r for r in rows if r[2] == "open" and r[1] == "content"]
    totals = collections.defaultdict(float)
    counts = collections.Counter()
    members = collections.defaultdict(list)
    for tag, _kind, _origin, band, pred in banded:
        totals[band] += pred
        counts[band] += 1
        members[band].append(tag)

    print("document       : %s" % os.path.relpath(args.path, root))
    print("open content   : %d clauses" % len(banded))
    print()
    for band in BANDS:
        n = counts[band]
        if not n:
            continue
        print("%-11s n=%2d  total %5.2f  mean %.4f   %s"
              % (band, n, totals[band], totals[band] / n,
                 " ".join(members[band])))
    print()
    under = [(t, p) for t, _k, _o, _b, p in banded if p < 0.60]
    print("open content clauses priced below 0.60 : %d   %s"
          % (len(under), " ".join("%s=%.2f" % u for u in under) or "none"))

    if args.expect_under:
        thr, want = float(args.expect_under[0]), int(args.expect_under[1])
        got = [(t, p) for t, _k, _o, _b, p in banded if p < thr]
        if len(got) != want:
            errors.append("--expect-under %.2f %d : got %d (%s)"
                          % (thr, want, len(got),
                             " ".join("%s=%.2f" % g for g in got) or "none"))

    if errors:
        print()
        for e in errors:
            print("FATAL: %s" % e)
        raise SystemExit(1)
    print()
    print("every open content clause carries exactly one band tag, and no "
          "other clause carries one.")


def parse(text):
    rows, errors = [], []
    for m in CLAUSE.finditer(text):
        tag, body = m.group(1), m.group(2)
        kinds = KIND.findall(body)
        origins = ORIGIN.findall(body)
        bands = BAND.findall(body)
        preds = PREDICTED.findall(body)
        if len(kinds) != 1 or len(origins) != 1 or len(preds) != 1:
            errors.append("%s: malformed clause tags" % tag)
            continue
        open_content = origins[0] == "open" and kinds[0] == "content"
        if open_content and len(bands) != 1:
            errors.append("%s: open content clause needs exactly one band "
                          "tag, got %d" % (tag, len(bands)))
            continue
        if not open_content and bands:
            errors.append("%s: band tag on a clause that is not open content"
                          % tag)
            continue
        rows.append((tag, kinds[0], origins[0],
                     bands[0] if bands else None, float(preds[0])))
    return rows, errors


def selftest():
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    good = ("**C01** `content` `open` `lands` -- x. *Predicted: 0.80*\n\n"
            "**C02** `content` `open` `constructs` -- y. *Predicted: 0.40*\n\n"
            "**C03** `content` `inherited` -- z. *Predicted: 0.90*\n\n"
            "**C04** `method` `open` -- w. *Predicted: 0.90*\n")
    rows, errors = parse(good)
    check("four clauses parse", len(rows), 4)
    check("no errors on a good document", errors, [])
    banded = [r for r in rows if r[2] == "open" and r[1] == "content"]
    check("two open content clauses", len(banded), 2)
    check("lands total", sum(p for _t, _k, _o, b, p in banded
                             if b == "lands"), 0.80)
    check("constructs total", sum(p for _t, _k, _o, b, p in banded
                                  if b == "constructs"), 0.40)
    check("below 0.60 count", len([p for _t, _k, _o, _b, p in banded
                                   if p < 0.60]), 1)

    missing = "**C01** `content` `open` -- no band. *Predicted: 0.80*\n"
    _rows, errors = parse(missing)
    check("a missing band tag is fatal", len(errors), 1)

    stray = ("**C01** `content` `inherited` `lands` -- stray. "
             "*Predicted: 0.80*\n")
    _rows, errors = parse(stray)
    check("a band tag outside open content is fatal", len(errors), 1)

    two = ("**C01** `content` `open` `lands` `constructs` -- two. "
           "*Predicted: 0.80*\n")
    _rows, errors = parse(two)
    check("two band tags are fatal", len(errors), 1)

    empty = "nothing here at all\n"
    rows, errors = parse(empty)
    check("an empty document yields no rows", len(rows), 0)

    bad = 0
    for name, ok, got, want in checks:
        print("  %-42s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad += 1
    print("checks : %d   failures : %d" % (len(checks), bad))
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
