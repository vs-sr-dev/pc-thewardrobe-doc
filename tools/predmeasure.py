#!/usr/bin/env python3
"""predmeasure.py -- P21's measurement, by command: how much work does a clause
in each band actually ask for?

WHY THIS EXISTS
---------------
`pc-rpgmakervxace-doc/docs/15` wrote P21. Over-delivery has become a pricing
dial -- `constructs` fell from 84.6 % to 63.6 % when its mean price rose from
0.6908 to 0.8636 -- but nobody has measured whether pricing a band UP makes its
clauses WORSE: smaller, safer, asking for less. A band that stops
over-delivering because its clauses stopped being ambitious is not a calibrated
band, it is a timid one, and the two are indistinguishable from the price alone.

P21 asks for one number per open content clause -- **how many separate
measurements it requires** -- reported by band. This is that number, by command
rather than by hand, because `predcount.py` was written for exactly the reason
that this pipeline gets hand arithmetic wrong.

WHAT A "SEPARATE MEASUREMENT" IS
--------------------------------
A quantity the session must obtain from the object or the box that it does not
already have: one command's output, or one derivation from one command's
output. Three figures pulled out of a single `pngcensus.py` run are three
measurements if the clause requires all three to be right and one if it does
not. That is a judgement, so the clause DECLARES it -- `*Measures: 4*` beside
`*Predicted: 0.85*` -- and this tool checks the declaration against something
it can derive:

    a clause cannot need FEWER measurements than the number of distinct
    commands it names.

A clause naming four tools and declaring two measurements is either
mis-declared or is naming tools it does not use, and either way the tool exits
non-zero and says which clause. That is a weak check and it is a real one; it
is stated as weak here so that the scoring chapter does not treat a declared
count as a measured one.

WHAT THIS TOOL WOULD NOT NOTICE, named in advance per P19
----------------------------------------------------------
**It cannot tell an inflated declaration from an ambitious clause.** The floor
is derivable and the ceiling is not, so a session wanting a flattering P21
number can simply declare larger ones. The check below binds only from
underneath. `--selftest` asserts that: a clause naming one command and
declaring nine measurements is required to PASS, and the assertion is there so
that the hole is on the record rather than in a footnote.

    python tools/predmeasure.py
    python tools/predmeasure.py docs/00-predictions.md --expect-clauses 26
    python tools/predmeasure.py --selftest
"""
import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard

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
MEASURES = re.compile(r"\*Measures:\s*(\d+)\*")
COMMAND = re.compile(r"`(?:python\s+)?(?:[\w./\\-]*[/\\])?(\w+)\.py\b[^`]*`")

BANDS = ("lands", "constructs", "nonnumeric")


def collect(text):
    """Return (rows, aside, errors); `rows` is the OPEN CONTENT population P21
    governs and `aside` is inherited clauses that declare a count anyway.

    An inherited clause may carry a `*Measures:*` tag and it is NEVER counted
    into a band mean. It is reported apart, because on pc-rpgmakermv-doc the
    five heaviest pieces of work were done before the predictions document and
    are therefore inherited by that document's own ruling -- so a P21 figure
    computed over the open band alone is computed over the lighter half, and a
    reader has to be able to see that. Reporting them apart makes the bias
    visible; dropping them would hide it and folding them in would corrupt the
    band means.
    """
    rows, aside, errors = [], [], []
    for cid, body in CLAUSE.findall(text):
        kinds = set(KIND.findall(body))
        origins = set(ORIGIN.findall(body))
        if kinds != {"content"} or origins != {"open"}:
            m = MEASURES.search(body)
            if m and origins == {"inherited"}:
                aside.append((cid, int(m.group(1))))
            elif m:
                errors.append("%s is neither open content nor inherited and "
                              "carries a Measures tag" % cid)
            continue
        bands = set(BAND.findall(body))
        if len(bands) != 1:
            errors.append("%s is open content and carries %d band tags"
                          % (cid, len(bands)))
            continue
        m = MEASURES.search(body)
        if not m:
            errors.append("%s is open content and declares no *Measures:* "
                          "count -- P21 requires one on every such clause"
                          % cid)
            continue
        declared = int(m.group(1))
        if declared < 1:
            errors.append("%s declares %d measurements; a clause requiring "
                          "none is not a content clause" % (cid, declared))
            continue
        cmds = []
        for stem in COMMAND.findall(body):
            if stem not in cmds:
                cmds.append(stem)
        if declared < len(cmds):
            errors.append("%s names %d distinct commands and declares %d "
                          "measurements; a clause cannot need fewer "
                          "measurements than the commands it names"
                          % (cid, len(cmds), declared))
            continue
        p = PREDICTED.search(body)
        rows.append((cid, list(bands)[0], declared, len(cmds),
                     float(p.group(1)) if p else None))
    return rows, aside, errors


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?",
                    default=os.path.join(root, "docs", "00-predictions.md"))
    ap.add_argument("--expect-clauses", type=int)
    ap.add_argument("--expect-total", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    # dirguard, for the same reason regcheck.py carries it: the survey run
    # before this session wrote a tool caught this tool raising on a
    # directory. docs/13 C.4.
    dirguard.want_file(args.path, "predmeasure")
    with open(args.path, "r", encoding="utf-8") as fh:
        text = fh.read()
    rows, aside, errors = collect(text)
    if errors:
        for e in errors:
            print("ERROR: " + e)
        sys.exit(1)
    if not rows:
        sys.exit("predmeasure: no open content clauses found in %s -- "
                 "refusing to report a mean over nothing" % args.path)

    by = collections.defaultdict(list)
    for cid, band, declared, ncmd, price in rows:
        by[band].append((cid, declared, ncmd, price))

    print("open content clauses : %d" % len(rows))
    print("measurements declared, total : %d"
          % sum(r[2] for r in rows))
    print()
    print("  band          n   measures    mean   priced   mean price")
    total_m = 0
    for band in BANDS:
        items = by.get(band, [])
        if not items:
            continue
        m = sum(i[1] for i in items)
        total_m += m
        prices = [i[3] for i in items if i[3] is not None]
        print("  %-11s %3d  %9d  %6.2f   %6.2f   %10.4f"
              % (band, len(items), m, m / len(items),
                 sum(prices), sum(prices) / len(prices) if prices else 0.0))
    print("  %-11s %3d  %9d  %6.2f"
          % ("ALL", len(rows), total_m, total_m / len(rows)))
    print()
    print("  the per-clause floor -- distinct commands named -- is derived and")
    print("  the count itself is declared. See the docstring: this check binds")
    print("  from underneath only.")
    print()
    for band in BANDS:
        items = by.get(band, [])
        if items:
            print("  %-11s %s" % (band, " ".join(
                "%s=%d" % (i[0], i[1]) for i in items)))
    if aside:
        print()
        print("  INHERITED clauses that declare a count -- reported apart and")
        print("  never counted into a band mean:")
        print("    %s" % " ".join("%s=%d" % kv for kv in aside))
        print("    %d clauses, %d measurements, mean %.2f"
              % (len(aside), sum(a[1] for a in aside),
                 sum(a[1] for a in aside) / len(aside)))
        print("  These are the pieces of work this session did BEFORE writing")
        print("  the predictions document, which docs/00 rules inherited. A")
        print("  P21 figure over the open band alone is a figure over the")
        print("  lighter half, and that is what this block is for.")

    if args.expect_clauses is not None and len(rows) != args.expect_clauses:
        sys.exit("predmeasure: --expect-clauses %d but found %d"
                 % (args.expect_clauses, len(rows)))
    if args.expect_total is not None and total_m != args.expect_total:
        sys.exit("predmeasure: --expect-total %d but found %d"
                 % (args.expect_total, total_m))
    return 0


def selftest():
    checks, fails = [], 0

    def ck(name, ok):
        nonlocal fails
        checks.append((name, ok))
        if not ok:
            fails += 1

    good = ("**C01** `content` `open` `constructs` -- `tools/a.py` and "
            "`tools/b.py`. *Predicted: 0.85* *Measures: 4*\n")
    rows, _a, e = collect(good)
    ck("a well-formed open content clause parses", not e and len(rows) == 1)
    ck("its band, count and command floor are read",
       rows[0][1:4] == ("constructs", 4, 2))

    rows, _a, e = collect("**C02** `content` `open` `lands` -- x. "
                      "*Predicted: 0.9*\n")
    ck("a missing Measures tag is an error", len(e) == 1 and not rows)

    rows, _a, e = collect("**C03** `content` `open` `lands` -- `tools/a.py`, "
                      "`tools/b.py`, `tools/c.py`. *Measures: 2*\n")
    ck("declaring fewer measurements than commands is an error",
       len(e) == 1 and not rows)

    rows, _a, e = collect("**C04** `content` `open` `lands` -- `tools/a.py`. "
                      "*Measures: 9*\n")
    ck("THE BLIND SPOT: an inflated declaration passes, by design",
       not e and rows[0][2] == 9)

    rows, aside, e = collect("**C05** `content` `inherited` -- x. "
                             "*Measures: 3*\n")
    ck("an inherited clause carrying a Measures tag is NOT an error",
       not e and not rows)
    ck("but it is held apart and never enters a band",
       aside == [("C05", 3)])
    rows, _a, e = collect("**C99** `method` `open` -- x. *Measures: 3*\n")
    ck("a Measures tag on a clause that is neither is an error", len(e) == 1)

    rows, _a, e = collect("**C06** `content` `inherited` -- x. *Predicted: 1.0*\n")
    ck("an inherited clause without one is simply skipped",
       not e and not rows)

    rows, _a, e = collect("**C07** `method` `open` -- x. *Predicted: 1.0*\n")
    ck("an open method clause is skipped", not e and not rows)

    rows, _a, e = collect("**C08** `content` `open` `lands` `constructs` -- x. "
                      "*Measures: 1*\n")
    ck("two band tags is an error", len(e) == 1)

    rows, _a, e = collect("**C09** `content` `open` `lands` -- x. *Measures: 0*\n")
    ck("zero measurements is an error", len(e) == 1)

    two = good + ("**C10** `content` `open` `lands` -- `tools/z.py`. "
                  "*Predicted: 0.9* *Measures: 3*\n")
    rows, _a, e = collect(two)
    ck("two clauses in two bands both parse",
       not e and len(rows) == 2
       and {r[1] for r in rows} == {"constructs", "lands"})

    for name, ok in checks:
        print("  %-4s %s" % ("ok" if ok else "FAIL", name))
    print("\n%d checks, %d failures" % (len(checks), fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
