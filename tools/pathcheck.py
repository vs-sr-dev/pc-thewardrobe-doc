#!/usr/bin/env python3
r"""pathcheck.py -- rule 7, by program: no absolute path of THIS machine in any
file this repository publishes.

Rule 7 says no absolute path of the machine the work was done on appears in a
`.md` or in a tool's defaults. It has been checked by eye for several objects
and by eye it missed one: `pc-rpgmaker2000-doc/docs/13` recorded a real
violation **inside a captured traceback committed under `notes/`**, which is a
place nobody was looking because nobody writes those by hand.

So this checks every tracked text file, not the documents, and it distinguishes
two things a naive grep would merge:

  * **this machine's paths**, which are violations. They are recognised by the
    directory names this work actually lives under, given on the command line
    so that the list is visible rather than hidden in the source;
  * **third parties' paths** — `D:\ha\…`, `C:\TMP\UNLHA32.LOG`,
    `C:\Program Files (x86)\Steam\…` quoted as an artefact — which are
    findings and are published. The standing rule is that an artefact from
    somebody else's machine is evidence.

Failure is loud, and the positive control is not optional: the tool plants a
violation in a temporary file and requires the check to fire on it, because a
checker that has never fired is a checker nobody has tested.

    python tools/pathcheck.py --needle <a directory this work lives under>
    python tools/pathcheck.py --selftest

The needles are given on the command line and are NOT written into this
file. A checker that hard-codes the string it is looking for publishes
that string -- which is precisely the defect `redact.py` was found to
have in a neighbouring repository, and it is not going to be repeated
here. The selftest uses a fictional root.
"""
import argparse
import os
import re
import subprocess
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

# Paths belonging to somebody else are artefacts, not violations. Each is here
# with the reason it is allowed, so that adding to this list is a visible act.
ALLOWED = [
    (re.compile(r"[Dd]:\\ha\\", re.I),
     "the editor author's build root, an artefact of rpg2003.exe"),
    (re.compile(r"C:\\TMP\\UNLHA32\.LOG", re.I),
     "a third party's log path inside UNLHA32.DLL"),
    (re.compile(r"karmaflow-steam", re.I),
     "a hard-coded default inside an inherited tool, quoted as a defect"),
    (re.compile(r"%INSTALLDIR%", re.I),
     "a Steam install-script variable, not a path"),
    (re.compile(r"\b(APPDATA|LOCALAPPDATA|USERPROFILE)\b"),
     "an environment VARIABLE NAME in a tool's list, not a path"),
]
TEXT = (".md", ".txt", ".tsv", ".py", ".json", ".yml", ".gitignore")


def tracked(root):
    try:
        out = subprocess.run(["git", "ls-files"], cwd=root,
                             capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        raise SystemExit("pathcheck: git ls-files failed: %s" % e)
    return [p for p in out.stdout.splitlines() if p.strip()]


def excused(line):
    for pat, why in ALLOWED:
        if pat.search(line):
            return why
    return None


def scan_text(text, needles):
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        for needle in needles:
            if needle.lower() in line.lower():
                why = excused(line)
                hits.append((n, needle, line.strip()[:120], why))
    return hits


def run(args):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = tracked(root)
    if not files:
        raise SystemExit("pathcheck: git tracks nothing here -- refusing to "
                         "report a clean sheet over an empty set")
    checked = 0
    violations = []
    excuses = 0
    for rel in files:
        if not rel.lower().endswith(TEXT):
            continue
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            continue
        try:
            text = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        checked += 1
        for n, needle, line, why in scan_text(text, args.needle):
            if why:
                excuses += 1
            else:
                violations.append((rel, n, needle, line))

    # A checker's own output is a tracked file, and on pc-rpgmakervxace-doc
    # this report was the ONLY rule-7 violation in the repository: it echoed
    # its needles verbatim and then planted a path containing one. That is the
    # same defect `pc-rpgmakerxp-doc/docs/14` recorded when the rule-0 hook's
    # log published the paths of the commands it refused, and the same defect
    # this file's own docstring warns about in `redact.py`.
    #
    # So the needles are masked on the way out. They are still what the scan
    # uses; they are no longer what the report says.
    def mask(text):
        out = text
        for i, needle in enumerate(args.needle):
            out = out.replace(needle, "<needle %d>" % (i + 1))
        return out

    print("tracked files            : %d" % len(files))
    print("text files checked       : %d" % checked)
    print("needles                  : %d, masked in this report" %
          len(args.needle))
    print("hits excused as artefacts: %d" % excuses)
    print("VIOLATIONS               : %d" % len(violations))
    for rel, n, needle, line in violations:
        print("   %s:%d  (%s)  %s"
              % (rel, n, mask(needle), mask(line)))

    print()
    print("-- POSITIVE CONTROL, which must fire ---------------------------")
    planted = "see D:\\%s\\pc-rpgmaker2003-doc\\notes\\x.txt for more" \
        % args.needle[0]
    fired = scan_text(planted, args.needle)
    unexcused = [h for h in fired if not h[3]]
    print("   planted line : %s" % mask(planted))
    print("   the check fires on it : %s" % bool(unexcused))
    if not unexcused:
        raise SystemExit("FATAL: the positive control did not fire; this "
                         "check proves nothing")

    print()
    print("-- NEGATIVE CONTROL, which must stay quiet ---------------------")
    quiet = "the build root D:\\ha\\02rpg2000\\2003\\ is a third party's"
    q = [h for h in scan_text(quiet, args.needle + ["D:\\ha\\"]) if not h[3]]
    print("   line : %s" % quiet)
    print("   unexcused hits : %d" % len(q))
    if q:
        raise SystemExit("FATAL: the negative control fired; the allow-list "
                         "is not working")

    return 1 if violations else 0


def selftest():
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    n = ["Fictitious9"]
    check("a this-machine path is a violation",
          [h for h in scan_text("D:\\Fictitious9\\x", n) if not h[3]] != [],
          True)
    check("a line with no needle is clean", scan_text("nothing here", n), [])
    check("the build root is excused",
          scan_text("D:\\ha\\02rpg2000\\2003\\Fictitious9", n)[0][3] is not None,
          True)
    check("the excuse names a reason",
          "build root" in (excused("D:\\ha\\x") or ""), True)
    check("UNLHA32.LOG is excused",
          excused("C:\\TMP\\UNLHA32.LOG") is not None, True)
    check("%INSTALLDIR% is excused",
          excused('"ApplicationPath" "%INSTALLDIR%"') is not None, True)
    check("an unrelated C: path is NOT excused",
          excused("C:\\Users\\somebody\\Fictitious9"), None)
    check("matching is case-insensitive",
          scan_text("d:\\fictitious9\\x", n) != [], True)
    check("the line number is reported",
          scan_text("a\nb\nD:\\Fictitious9\\x", n)[0][0], 3)
    check("two needles both fire",
          len(scan_text("D:\\Fictitious9 and F:\\Imaginary8",
                        ["Fictitious9", "Imaginary8"])), 2)

    bad = 0
    for name, ok, got, want in checks:
        print("  %-46s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad += 1
    print("checks : %d   failures : %d" % (len(checks), bad))
    raise SystemExit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--needle", action="append", default=[])
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.needle:
        raise SystemExit("pathcheck: at least one --needle is required "
                         "(or --selftest)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
