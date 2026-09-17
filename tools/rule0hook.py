#!/usr/bin/env python3
"""rule0hook.py -- rule 0, as a program that refuses instead of a rule somebody
has to remember.

WHY THIS EXISTS
---------------
`pc-rpgmaker2003-doc/docs/16` scored P13 and reported its own falsification:
the prohibition on shell heredocs was written into the predictions document,
read aloud, and then violated five times in the same session, plus an uncounted
number of `python -c` invocations that the rule's wording did not even name.
Nobody noticed until the scoring chapter went back and counted.

P16 drew the conclusion: **stop writing rules a person has to remember and
write checks that fire.** This is that check. It is a Claude Code `PreToolUse`
hook on the `Bash`/`PowerShell` tools. It reads the proposed command on stdin,
and it DENIES the call outright when the command carries program text or
document text through the shell:

  * a heredoc (`<<EOF`, `<<'EOF'`, `<<-EOF`) or a here-string (`<<<`);
  * an inline program (`python -c`, `perl -e`, `ruby -e`, `node -e`, ...);
  * an in-place edit script (`sed -i`), which is the same hazard wearing a
    different hat: a backslash in the replacement is eaten by the shell before
    `sed` ever sees it.

The permitted route is the one P13 named and could not enforce: write the file
with the `Write` tool, then execute the file.

WHAT IT LOGS, AND WHY THE LOG IS THE POINT
------------------------------------------
Every decision -- allow or deny -- is appended to `_work/rule0.log` as one
tab-separated line. A rule you have to remember produces violations you do not
notice; this produces violations you cannot help but count, because the count
is a file. The scoring chapter reads the log with `--report` rather than
reconstructing the session from memory, which is what the previous session had
to do.

    python tools/rule0hook.py --selftest
    python tools/rule0hook.py --report
    python tools/rule0hook.py --check "python -c 'print(1)'"

Registration is local to the machine and is not committed: this repository
publishes `README`, `docs/`, `notes/`, `tools/` and `.gitignore` and nothing
else, so `.claude/settings.local.json` names this file and stays untracked.
The hook itself is a tool and is published, because a check nobody can read is
a claim.
"""
import argparse
import json
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "_work", "rule0.log")

# Each rule is (name, compiled pattern, what to do instead). The patterns are
# deliberately narrow: a hook that fires on `grep -e` would be turned off
# within the hour, and a check that gets turned off is worth less than a rule
# that gets forgotten.
RULES = [
    # `<<<` must be tested BEFORE `<<`, because a here-string's own text
    # satisfies the heredoc pattern and would be reported under the wrong name.
    # The selftest asserts the name and not merely the refusal, which is how
    # this ordering bug was found.
    ("here-string",
     re.compile(r"<<<"),
     "write the content to a file with the Write tool, then read the file"),
    ("heredoc",
     re.compile(r"<<-?\s*[\"']?[A-Za-z_]"),
     "write the content to a file with the Write tool, then run the file"),
    ("inline program",
     # `-X utf8 -c` and `-W ignore -c` slipped past the flag skipper on
     # pc-teenagent-doc (a leftover `python -X utf8 -c ""` in a compound
     # command was ALLOWED and logged): flags that take an argument are
     # now skipped with it.
     re.compile(r"(?:^|[|;&(]|\s)(?:python3?|py|perl|ruby|node|php|pwsh|"
                r"powershell)(?:\.exe)?\s+"
                r"(?:-(?:[XW]\s+\S+|[A-Za-z]+)\s+)*"
                r"-(?:c|e|Command|EncodedCommand)(?:\s|$)"),
     "write the program to a scratch .py file with the Write tool, then run it"),
    ("in-place edit script",
     re.compile(r"(?:^|[|;&(]|\s)sed\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*i"),
     "write a substitution script that COUNTS its replacements and fails "
     "loudly on zero, then run it"),
]


def verdict(command):
    """Return (allowed, rule_name, advice) for a proposed shell command."""
    for name, pat, advice in RULES:
        if pat.search(command):
            return False, name, advice
    return True, "", ""


DRIVEPATH = re.compile(r"(?i)[a-z]:[\\/][^\s\"']*")


def scrub(command):
    """Replace every absolute path of this machine with a placeholder.

    Rule 7 of this pipeline forbids this machine's absolute paths in any file
    the repository publishes, **including inside captured tool output under
    `notes/`**, and a log of refused shell commands is exactly that: the
    commands begin `cd "<the project root>" && …`. `pathcheck.py` found three
    such lines on this object -- two of them here -- which is what a checker
    with a positive control is for. The scrub happens both on the way in and
    on the way out, so a log written before this existed is cleaned when it is
    read.
    """
    return DRIVEPATH.sub("<path>", command)


def log(decision, rule, command):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        one_line = scrub(command).replace("\t", " ").replace("\r", " ")
        one_line = one_line.replace("\n", "\\n")[:400]
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write("%s\t%s\t%s\t%s\n"
                     % (time.strftime("%Y-%m-%dT%H:%M:%S"), decision,
                        rule or "-", one_line))
    except OSError:
        # A hook that crashes blocks the session. It must fail open on its own
        # bookkeeping and never on its own decision.
        pass


def hook():
    """Claude Code PreToolUse contract: JSON in on stdin, JSON out on stdout."""
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    tool = payload.get("tool_name", "")
    if tool not in ("Bash", "PowerShell"):
        return 0
    command = (payload.get("tool_input") or {}).get("command", "") or ""
    ok, rule, advice = verdict(command)
    log("ALLOW" if ok else "DENY", rule, command)
    if ok:
        return 0
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason":
                "rule 0 (rule0hook.py): this command carries content through "
                "the shell -- %s. %s. This is P16 of "
                "pc-rpgmaker2003-doc/docs/16 as a program rather than as a "
                "clause; the refusal is the instrument." % (rule, advice),
        }
    }
    json.dump(out, sys.stdout)
    return 0


def report():
    if not os.path.exists(LOG):
        print("rule0.log does not exist -- the hook has never run")
        return 1
    allow = deny = 0
    by_rule = {}
    denials = []
    with open(LOG, encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 4:
                continue
            when, decision, rule = parts[0], parts[1], parts[2]
            cmd = scrub(parts[3])
            if decision == "ALLOW":
                allow += 1
            else:
                deny += 1
                by_rule[rule] = by_rule.get(rule, 0) + 1
                denials.append((when, rule, cmd))
    print("shell calls seen by the hook : %d" % (allow + deny))
    print("  allowed                    : %d" % allow)
    print("  REFUSED as rule-0          : %d" % deny)
    for rule, n in sorted(by_rule.items(), key=lambda kv: -kv[1]):
        print("      %-22s %d" % (rule, n))
    if denials:
        print()
        print("the refusals, in order:")
        for when, rule, cmd in denials:
            print("  %s  %-14s %s" % (when, rule, cmd[:120]))
    print()
    print("A rule 0 violation that reaches the shell is a hook failure.")
    print("A rule 0 violation that is REFUSED is the hook working, and the")
    print("count of refusals is how many times the habit still fired.")
    return 0


def selftest():
    checks = []

    def want(label, command, allowed, rule=None):
        ok, got_rule, _ = verdict(command)
        good = (ok == allowed) and (rule is None or got_rule == rule)
        checks.append((label, good, "" if good else
                       "allowed=%r rule=%r" % (ok, got_rule)))

    # must refuse
    want("a plain heredoc is refused", "cat > f <<EOF\nx\nEOF", False,
         "heredoc")
    want("a quoted heredoc is refused", "cat > f <<'PY'\nprint(1)\nPY", False,
         "heredoc")
    want("a dash heredoc is refused", "cat <<-EOF\nx\nEOF", False, "heredoc")
    want("a here-string is refused", "python x.py <<< 'data'", False,
         "here-string")
    want("python -c is refused", "python -c 'print(1)'", False,
         "inline program")
    want("python3 -c is refused", "python3 -c \"print(1)\"", False,
         "inline program")
    want("a python -c after a pipe is refused", "cat f | python -c 'x'", False,
         "inline program")
    want("a python -c after a semicolon is refused",
         "cd /tmp; python -c 'x'", False, "inline program")
    want("python -X utf8 -c is refused (the pc-teenagent-doc hole)",
         "python -X utf8 -c \"\"", False, "inline program")
    want("python -W ignore -c is refused", "python -W ignore -c 'x'", False,
         "inline program")
    want("perl -e is refused", "perl -e 'print 1'", False, "inline program")
    want("node -e is refused", "node -e 'console.log(1)'", False,
         "inline program")
    want("powershell -Command is refused", "powershell -Command \"ls\"", False,
         "inline program")
    want("sed -i is refused", "sed -i 's/a/b/' f", False,
         "in-place edit script")
    want("sed -i.bak is refused", "sed -i.bak 's/a/b/' f", False,
         "in-place edit script")

    # must NOT refuse -- a hook that fires on ordinary work gets turned off
    want("a plain tool run is allowed",
         "python tools/coverage.py tree --root rpgmakerxp-steam", True)
    want("sed -n is allowed", "sed -n '1,20p' file.txt", True)
    want("grep -e is allowed", "grep -e foo file.txt", True)
    want("a redirection is allowed", "python tools/x.py > _work/x.txt", True)
    want("a less-than redirection is allowed", "python x.py < input.bin", True)
    want("git commit -m is allowed", "git commit -m 'a message'", True)
    want("a path containing the word python is allowed",
         "ls /usr/lib/python3/dist-packages", True)
    want("an ordinary -c flag on another program is allowed",
         "tar -c -f x.tar dir", True)

    # the payload really is the hazard, and the hook says so
    checks.append(("the refusal names what to do instead",
                   verdict("cat <<EOF")[2].startswith("write the content"),
                   verdict("cat <<EOF")[2]))
    checks.append(("an empty command is allowed and does not crash",
                   verdict("")[0] is True, ""))
    checks.append(("an absolute path is scrubbed out of a logged command",
                   scrub('cd "d:/Some/Project" && python x.py')
                   == 'cd "<path>" && python x.py',
                   scrub('cd "d:/Some/Project" && python x.py')))
    checks.append(("a backslash path is scrubbed too",
                   scrub(r"C:\Users\somebody\x.py") == "<path>",
                   scrub(r"C:\Users\somebody\x.py")))
    checks.append(("a relative path is left alone",
                   scrub("python tools/x.py notes/y.txt")
                   == "python tools/x.py notes/y.txt", ""))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL",
                                   note))
        if not ok:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--check", metavar="COMMAND",
                    help="print the verdict for one command and exit non-zero "
                         "if it would be refused")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.report:
        return report()
    if args.check is not None:
        ok, rule, advice = verdict(args.check)
        print("%s : %s" % ("ALLOW" if ok else "DENY", args.check))
        if not ok:
            print("  rule    : %s" % rule)
            print("  instead : %s" % advice)
        return 0 if ok else 1
    return hook()


if __name__ == "__main__":
    sys.exit(main())
