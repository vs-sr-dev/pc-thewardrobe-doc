#!/usr/bin/env python3
"""regcheck.py -- P20's membership test for the P17 register, as a program.

WHY THIS EXISTS
---------------
`pc-rpgmakerxp-doc/docs/17` proposed P17: mark every clause whose figure
describes a state the session itself will change, run those commands FIRST,
and commit the output. `pc-rpgmakervxace-doc/docs/15` scored it and found the
mechanism sound and the DISCIPLINE unreliable -- two clauses out of thirty-one
belonged in the register and were not put there, and both failures were about
the register's BOUNDARY rather than about its mechanism. P20 is the
prescription that followed:

  > Derive membership of the register with a program: before writing a clause,
  > pass it to a check that asks whether any command it names reads state this
  > session's own work plan will change, and do not accept the clause until
  > that command's output is committed.

This is that check.

HOW IT WORKS
------------
Three inputs, all of them files under version control:

  1. a WORK PLAN (`notes/workplan.txt`), written before the first clause, which
     names every state the session intends to change and, for each tool, which
     of those states its output depends on;
  2. the PREDICTIONS DOCUMENT, from which every clause and every command named
     inside a clause is extracted by regular expression;
  3. `notes/`, in which a registered figure's committed output must exist.

For each clause the tool computes

     changed_states_read = {states the clause's commands read} & {states the
                            plan says this session will change}

If that set is non-empty the clause is a REGISTER MEMBER and must cite a file
matching `notes/<something>-before.txt` that EXISTS on disk. A member that
cites nothing, or cites a file that is not there, is a failure and the exit
status is non-zero. A clause that cites a `-before` file while reading no
changed state is also a failure, in the other direction: the register is not a
place to put things for safety.

WHAT THIS TOOL WOULD NOT NOTICE, named in advance per P19
----------------------------------------------------------
**It cannot tell that a work plan is incomplete.** Every judgement it makes is
relative to the states the plan declares, so a session that forgets to declare
a change will get a clean report from a check that has been fed the wrong
question. That is P20's own falsification condition restated as a limitation,
and it is why `--selftest` includes a case where a clause reads a state the
plan does NOT mention: the tool is required to pass that clause and the test
asserts it, so the blind spot is demonstrated rather than described.

The second thing it cannot see is a clause that cites a registered figure
CORRECTLY and then goes on to restate this session's own completed work --
which is what sank C31 last session. Membership is necessary and not
sufficient, and no membership test can be sufficient.

    python tools/regcheck.py
    python tools/regcheck.py docs/00-predictions.md --plan notes/workplan.txt
    python tools/regcheck.py --selftest
"""
import argparse
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
# A command inside a clause looks like `tools/x.py ...` or `x.py ...` or
# `python tools/x.py`, always inside backticks. Only the STEM is wanted.
COMMAND = re.compile(r"`(?:python\s+)?(?:[\w./\\-]*[/\\])?(\w+)\.py\b[^`]*`")
BEFORE = re.compile(r"`?(notes/[\w.-]*-before(?:-[\w.-]+)?\.txt)`?")


def read_plan(path):
    """Return (changed_states, {tool: {states}}, {final tools}).

    A `final` line names a tool whose figure describes the state at the END of
    the session rather than before it -- `pathcheck.py` reporting zero
    violations over the finished repository is the case that forced this line
    type into existence, on this tool's first real run. A `-before` output for
    such a tool would not be evidence of anything, so requiring one is the
    check being wrong rather than the clause. Every `final` line has to be
    justified in the plan's prose, because the line is also the obvious way to
    game the check, and that is said here rather than discovered later.

    Malformed lines are fatal.
    """
    changed, reads, final = [], {}, set()
    with open(path, "r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if parts[0] == "change" and len(parts) == 2:
                if parts[1] in changed:
                    sys.exit("regcheck: %s:%d: state %r declared twice"
                             % (path, n, parts[1]))
                changed.append(parts[1])
            elif parts[0] == "reads" and len(parts) == 3:
                if parts[1] in reads:
                    sys.exit("regcheck: %s:%d: tool %r listed twice"
                             % (path, n, parts[1]))
                reads[parts[1]] = set(parts[2].split(","))
            elif parts[0] == "final" and len(parts) == 2:
                final.add(parts[1])
            else:
                sys.exit("regcheck: %s:%d: not a plan line: %r"
                         % (path, n, line))
    if not changed:
        sys.exit("regcheck: %s declares no change; a plan that changes "
                 "nothing cannot decide any clause" % path)
    unknown = sorted({s for v in reads.values() for s in v} - set(changed))
    if unknown:
        sys.exit("regcheck: %s: tools read states the plan never declares "
                 "changed: %s -- either declare them or drop them, because a "
                 "state nobody changes is not a register question"
                 % (path, ", ".join(unknown)))
    both = sorted(final & set(reads))
    if both:
        sys.exit("regcheck: %s: %s are declared both `reads` and `final`; a "
                 "tool cannot report a before-state and an after-state in the "
                 "same plan" % (path, ", ".join(both)))
    return changed, reads, final


def audit(text, changed, reads, repo_root, checked_exists=True):
    """Classify every clause. Returns (rows, failures).

    `repo_root` is the directory the cited `notes/...` paths are relative TO,
    which is the repository root and not `notes/` itself. Getting that wrong is
    what selftest check 6 caught on this tool's first run: the original joined
    `notes/` to `../notes/x.txt` and landed back on the real file every time,
    so the check could not fail. It is recorded in docs/13.
    """
    rows, failures = [], []
    for cid, body in CLAUSE.findall(text):
        tools = []
        for stem in COMMAND.findall(body):
            if stem not in tools:
                tools.append(stem)
        states = set()
        for stem in tools:
            states |= reads.get(stem, set())
        touched = sorted(states & set(changed))
        cited = sorted(set(BEFORE.findall(body)))
        missing = [c for c in cited
                   if checked_exists
                   and not os.path.exists(os.path.join(repo_root, c))]
        if touched and not cited:
            failures.append(
                "%s reads %s, which this session changes, and cites no "
                "committed -before file. P20: register it or do not write it."
                % (cid, "+".join(touched)))
        if cited and not touched:
            failures.append(
                "%s cites %s but names no command that reads a state the "
                "plan changes. The register is not a place to put a figure "
                "for safety." % (cid, ", ".join(cited)))
        if missing:
            failures.append(
                "%s cites %s and that file does not exist."
                % (cid, ", ".join(missing)))
        rows.append((cid, tools, touched, cited))
    return rows, failures


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?",
                    default=os.path.join(root, "docs", "00-predictions.md"))
    ap.add_argument("--plan", default=os.path.join(root, "notes",
                                                   "workplan.txt"))
    ap.add_argument("--expect-members", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    # dirguard, because the survey this session ran BEFORE writing a tool
    # caught this tool raising `PermissionError` on a directory -- the 217th
    # instance of the class `dirguard.py` exists to close, in code written by
    # the session that ran the survey. docs/13 C.4.
    dirguard.want_file(args.path, "regcheck")
    dirguard.want_file(args.plan, "regcheck")
    if not os.path.exists(args.plan):
        sys.exit("regcheck: no such work plan: %s -- P20 needs one, written "
                 "before the first clause" % args.plan)

    changed, reads, final = read_plan(args.plan)
    with open(args.path, "r", encoding="utf-8") as fh:
        text = fh.read()
    rows, failures = audit(text, changed, reads, root)

    print("document : %s" % os.path.relpath(args.path, root).replace("\\", "/"))
    print("plan     : %s" % os.path.relpath(args.plan, root).replace("\\", "/"))
    print("states this session changes : %s" % ", ".join(changed))
    print()
    members = [r for r in rows if r[2]]
    print("clauses            : %d" % len(rows))
    print("REGISTER MEMBERS   : %d" % len(members))
    print()
    for cid, tools, touched, cited in members:
        print("  %-5s reads %-28s cites %s"
              % (cid, "+".join(touched), ", ".join(cited) or "NOTHING"))
    print()
    if failures:
        print("FAILURES : %d" % len(failures))
        for f in failures:
            print("  " + f)
        sys.exit(1)
    print("failures : 0")
    if args.expect_members is not None and len(members) != args.expect_members:
        sys.exit("regcheck: --expect-members %d but found %d"
                 % (args.expect_members, len(members)))
    return 0


def selftest():
    checks, fails = [], 0

    def ck(name, ok):
        nonlocal fails
        checks.append((name, ok))
        if not ok:
            fails += 1

    changed = ["toolbox", "classifier"]
    reads = {"toolsdiff": {"toolbox"}, "coverage": {"classifier"},
             "pngcensus": set()}

    # 1. a clause naming a changed-state command with no register entry fails
    t = "**C01** `content` `open` -- `python tools/toolsdiff.py` says 562.\n"
    rows, f = audit(t, changed, reads, ".", checked_exists=False)
    ck("unregistered changed-state clause fails", len(f) == 1)
    ck("and it is classified a member", rows[0][2] == ["toolbox"])

    # 2. the same clause citing a committed file passes
    t = ("**C01** `content` `open` -- `python tools/toolsdiff.py`, whose "
         "output before this session is `notes/toolsdiff-before.txt`, "
         "says 562.\n")
    rows, f = audit(t, changed, reads, ".", checked_exists=False)
    ck("registered changed-state clause passes", not f)
    ck("and the citation is captured",
       rows[0][3] == ["notes/toolsdiff-before.txt"])

    # 3. a clause reading nothing the plan changes is not a member
    t = "**C02** `content` `open` -- `python tools/pngcensus.py x` says 5578.\n"
    rows, f = audit(t, changed, reads, ".", checked_exists=False)
    ck("unchanged-state clause is not a member", rows[0][2] == [])
    ck("and it does not fail", not f)

    # 4. THE BLIND SPOT, per P19: a command the plan never mentions reads
    #    nothing as far as this tool is concerned, and the tool PASSES it.
    #    That is the limitation, demonstrated rather than described.
    t = "**C03** `content` `open` -- `python tools/nobodydeclared.py` says 1.\n"
    rows, f = audit(t, changed, reads, ".", checked_exists=False)
    ck("an undeclared tool is silently treated as reading nothing",
       rows[0][2] == [] and not f)

    # 5. gratuitous registration fails in the other direction
    t = ("**C04** `content` `open` -- `python tools/pngcensus.py x`, see "
         "`notes/pngcensus-before.txt`.\n")
    rows, f = audit(t, changed, reads, ".", checked_exists=False)
    ck("citing a -before file without reading changed state fails",
       len(f) == 1)

    # 6. a cited file that is not on disk fails, and one that is does not.
    #    Both halves are asserted against a root built for the purpose, so the
    #    check cannot pass by landing on the repository's real notes/.
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        t = ("**C05** `content` `open` -- `python tools/coverage.py tree`, see "
             "`notes/coverage-tree-before.txt`.\n")
        rows, f = audit(t, changed, reads, d, checked_exists=True)
        ck("a missing -before file fails", len(f) == 1)
        os.makedirs(os.path.join(d, "notes"))
        with open(os.path.join(d, "notes", "coverage-tree-before.txt"),
                  "w", encoding="utf-8") as fh:
            fh.write("x")
        rows, f = audit(t, changed, reads, d, checked_exists=True)
        ck("a -before file that exists does not fail", not f)

    # 7. command extraction: three spellings, one stem, counted once
    t = ("**C06** `content` `open` -- `tools/coverage.py tree`, "
         "`python tools/coverage.py ambiguity` and `coverage.py --selftest`.\n")
    rows, _ = audit(t, changed, reads, ".", checked_exists=False)
    ck("three spellings of one tool collapse to one stem",
       rows[0][1] == ["coverage"])

    # 8. plan parsing: a state read but never declared changed is fatal
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "plan.txt")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("change toolbox\nreads coverage classifier\n")
        code = 0
        try:
            read_plan(p)
        except SystemExit:
            code = 1
        ck("a tool reading an undeclared state is a fatal plan error",
           code == 1)

        p2 = os.path.join(d, "empty.txt")
        with open(p2, "w", encoding="utf-8") as fh:
            fh.write("# nothing\n")
        code = 0
        try:
            read_plan(p2)
        except SystemExit:
            code = 1
        ck("a plan that changes nothing is fatal", code == 1)

        p3 = os.path.join(d, "dup.txt")
        with open(p3, "w", encoding="utf-8") as fh:
            fh.write("change toolbox\nchange toolbox\n")
        code = 0
        try:
            read_plan(p3)
        except SystemExit:
            code = 1
        ck("a state declared twice is fatal", code == 1)

        p4 = os.path.join(d, "good.txt")
        with open(p4, "w", encoding="utf-8") as fh:
            fh.write("change toolbox  # prose\n\nreads toolsdiff toolbox\n")
        c, r, fin = read_plan(p4)
        ck("a well-formed plan parses", c == ["toolbox"]
           and r == {"toolsdiff": {"toolbox"}} and fin == set())

        p6 = os.path.join(d, "final.txt")
        with open(p6, "w", encoding="utf-8") as fh:
            fh.write("change toolbox\nfinal pathcheck\n")
        _c, _r, fin2 = read_plan(p6)
        ck("a `final` line parses", fin2 == {"pathcheck"})

        p7 = os.path.join(d, "clash.txt")
        with open(p7, "w", encoding="utf-8") as fh:
            fh.write("change toolbox\nreads x toolbox\nfinal x\n")
        code = 0
        try:
            read_plan(p7)
        except SystemExit:
            code = 1
        ck("a tool declared both `reads` and `final` is fatal", code == 1)

        p5 = os.path.join(d, "junk.txt")
        with open(p5, "w", encoding="utf-8") as fh:
            fh.write("change toolbox\nwibble\n")
        code = 0
        try:
            read_plan(p5)
        except SystemExit:
            code = 1
        ck("a line that is neither change nor reads is fatal", code == 1)

    # 9. a clause with several tools unions their states
    reads2 = dict(reads)
    reads2["refusals"] = {"toolbox", "readers"}
    t = ("**C07** `content` `open` -- `python tools/pngcensus.py x` and "
         "`python tools/coverage.py tree`, see `notes/x-before.txt`.\n")
    rows, f = audit(t, changed, reads2, ".", checked_exists=False)
    ck("states union across a clause's commands",
       rows[0][2] == ["classifier"] and not f)

    # 10. no command at all: not a member, no failure
    t = "**C08** `content` `open` -- sixteen documents were written.\n"
    rows, f = audit(t, changed, reads, ".", checked_exists=False)
    ck("a clause naming no command is not a member",
       rows[0][1] == [] and rows[0][2] == [] and not f)

    for name, ok in checks:
        print("  %-4s %s" % ("ok" if ok else "FAIL", name))
    print("\n%d checks, %d failures" % (len(checks), fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
