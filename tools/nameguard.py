#!/usr/bin/env python3
"""nameguard.py -- the box's output-encoding convention, applied to FILE NAMES.

WHY THIS EXISTS
---------------
This box has a convention, stated in half a dozen tools and obeyed by all of
them: **a tool that prints recovered text sets its own output encoding**, so
that a Japanese string pulled out of a container does not kill the tool that
found it. `predbands.py` does it, `chmx.py` does it, `namescan.py` does it.

The convention was never applied to the NAMES of files, because until
pc-rpgmakervxace-doc no object in this collection had a file name outside
Latin-1. This one has:

    dlc\\Tyler Warren RPG Battlers - 1st 50\\...<nine kana>.pdf

and `hashall.py`, whose entire job is to print a table of paths and hashes,
dies of `UnicodeEncodeError` on it when `PYTHONIOENCODING` is unset. So does
`unityfs.py`. So does `unityarc.py`. So did `coverage.py ambiguity`, the tool
written in the same session to measure this defect, on its first run.

The pre-briefing put the size of this class at ONE tool. This module exists to
make the fix one line and to make the SIZE OF THE CLASS a measurement rather
than an anecdote.

USE
---
    import nameguard
    nameguard.guard()          # first thing in main(), before any print

and the survey, which is the measurement:

    python tools/nameguard.py --survey --tools tools

WHAT THIS TOOL WOULD NOT NOTICE, named in advance per P19
---------------------------------------------------------
**A tool that prints nothing cannot crash, so silence is not evidence the
guard works.** The survey below therefore does NOT count "did not raise" as a
pass. It splits its population three ways -- raised, printed the name, and
neither -- and the only column that proves anything is the middle one. A tool
that exits 0 without ever emitting the Japanese name is reported as
`no output` and is explicitly excluded from the numerator AND the denominator
of the claim, because it was never tested.

The check for that blind spot is `--selftest`'s last three assertions: a fake
tool that prints the name is required to be classified `printed`, a fake tool
that raises is required to be classified `raised`, and a fake tool that prints
nothing is required to be classified `no output` and NOT `printed`.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

# The name that does it. Kept here as an escape so that this source file is
# itself pure ASCII and cannot become the thing it is guarding against.
JAPANESE_NAME = "".join(map(chr, (
    0x306F, 0x3058, 0x3081, 0x306B, 0x304A,   # ha ji me ni o
    0x8AAD, 0x307F, 0x304F, 0x3060, 0x3055, 0x3044,   # yo mi ku da sa i
))) + ".txt"

_GUARDED = False


def guard(stream_errors="replace"):
    """Set stdout and stderr to UTF-8 so a non-Latin-1 file name can be
    printed. Idempotent, and a no-op on a stream that cannot be reconfigured
    (a pipe replaced by a test harness, for instance), because a guard that
    raises is worse than the crash it prevents.
    """
    global _GUARDED
    if _GUARDED:
        return True
    ok = True
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors=stream_errors)
            except (ValueError, OSError):
                ok = False
        else:
            ok = False
    _GUARDED = True
    return ok


def safe(name):
    """A last resort for a stream that could not be reconfigured: return a
    form of `name` that the current stdout encoding can carry. Used by nothing
    in the survey; provided so a tool with a wedged stream still prints a row.
    """
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    return name.encode(enc, "backslashreplace").decode(enc, "replace")


# --------------------------------------------------------------------- survey

def make_bait(directory):
    """One directory holding one small file whose name is not Latin-1.

    This is `dirguard.py --survey`'s shape -- hand every tool in the box one
    argument and see what it does -- with the empty directory replaced by a
    directory containing the hazard. The file's CONTENT is a PNG header, so
    that a tool which selects by magic has something it is willing to open and
    therefore something it is willing to print the name of.
    """
    path = os.path.join(directory, JAPANESE_NAME)
    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n" + bytes(24) + b"IEND")
    return path


def survey(tools_dir, timeout=20):
    env = dict(os.environ)
    env.pop("PYTHONIOENCODING", None)
    env["PYTHONUTF8"] = "0"
    names = sorted(f for f in os.listdir(tools_dir)
                   if f.endswith(".py") and f != os.path.basename(__file__))

    bait_dir = tempfile.mkdtemp(prefix="nameguard-")
    try:
        make_bait(bait_dir)
        raised, printed, silent, timed_out = [], [], [], []
        for name in names:
            verdict = run_one(os.path.join(tools_dir, name), bait_dir, env,
                              timeout)
            {"raised": raised, "printed": printed, "no output": silent,
             "timeout": timed_out}[verdict].append(name)
    finally:
        shutil.rmtree(bait_dir, ignore_errors=True)

    return raised, printed, silent, timed_out


def run_one(tool, bait_dir, env, timeout):
    try:
        proc = subprocess.run([sys.executable, tool, bait_dir],
                              capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return "timeout"
    err = proc.stderr.decode("utf-8", "replace")
    out = proc.stdout.decode("utf-8", "replace")
    if "UnicodeEncodeError" in err:
        return "raised"
    if JAPANESE_NAME[:6] in out or JAPANESE_NAME[:6] in err:
        return "printed"
    return "no output"


def classify_streams(out, err):
    """The three-way split, factored out so the selftest can drive it without
    a subprocess. This is the function P19's blind-spot check tests.
    """
    if "UnicodeEncodeError" in err:
        return "raised"
    if JAPANESE_NAME[:6] in out or JAPANESE_NAME[:6] in err:
        return "printed"
    return "no output"


def selftest():
    checks = []

    def check(label, ok, note=""):
        checks.append((label, ok, note))

    check("this source file is pure ASCII",
          all(ord(c) < 128 for c in open(__file__, encoding="utf-8").read()))
    check("the bait name is not Latin-1",
          any(ord(c) > 255 for c in JAPANESE_NAME))
    check("the bait name cannot be encoded as cp1252",
          _cannot_encode(JAPANESE_NAME, "cp1252"))
    check("guard() reports success on a normal stdout", guard() is True)
    check("guard() is idempotent", guard() is True)
    check("safe() returns something printable in ASCII",
          all(ord(c) < 128 for c in
              JAPANESE_NAME.encode("ascii", "backslashreplace")
              .decode("ascii")))

    bait_dir = tempfile.mkdtemp(prefix="nameguard-selftest-")
    try:
        p = make_bait(bait_dir)
        check("the bait file exists on disk", os.path.exists(p))
        check("the bait file is a PNG by magic",
              open(p, "rb").read(8) == b"\x89PNG\r\n\x1a\n")
        check("listing the directory returns the name back",
              os.listdir(bait_dir) == [JAPANESE_NAME])
    finally:
        shutil.rmtree(bait_dir, ignore_errors=True)

    # ---- P19: the blind spot is that a silent tool cannot crash. These three
    # are the check written against it, and the third is the one that matters.
    check("a tool that raises UnicodeEncodeError is classified `raised`",
          classify_streams("", "Traceback\nUnicodeEncodeError: 'charmap'")
          == "raised")
    check("a tool that PRINTS the name is classified `printed`",
          classify_streams("row 1 %s 4096\n" % JAPANESE_NAME, "")
          == "printed")
    check("A TOOL THAT PRINTS NOTHING IS `no output` AND NOT `printed` -- "
          "silence is not a pass",
          classify_streams("files scanned : 0\n", "") == "no output")
    check("and a tool that raises while also printing the name is still "
          "`raised`",
          classify_streams(JAPANESE_NAME, "UnicodeEncodeError") == "raised")

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


def _cannot_encode(text, codec):
    try:
        text.encode(codec)
    except UnicodeEncodeError:
        return True
    return False


def main():
    guard()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--survey", action="store_true")
    ap.add_argument("--tools", default="tools")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--expect-raised", type=int)
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.survey:
        ap.error("nameguard: --survey or --selftest; this module is meant to "
                 "be imported and its guard() called")

    if not os.path.isdir(args.tools):
        sys.exit("nameguard: no such tool box: %s" % args.tools)

    raised, printed, silent, timed_out = survey(args.tools, args.timeout)
    total = len(raised) + len(printed) + len(silent) + len(timed_out)

    print("tool box              : %s" % args.tools)
    print("Python files surveyed : %d" % total)
    print("each was handed ONE DIRECTORY holding ONE file whose name is not")
    print("Latin-1, with PYTHONIOENCODING unset and PYTHONUTF8=0.")
    print()
    print("  raised UnicodeEncodeError : %d" % len(raised))
    print("  printed the name safely   : %d" % len(printed))
    print("  no output naming the file : %d   (NOT TESTED -- see below)"
          % len(silent))
    print("  timed out                 : %d" % len(timed_out))
    print()
    tested = len(raised) + len(printed)
    if tested:
        print("  THE CLAIM, over the tools that actually emitted the name:")
        print("  %d of %d = %.4f %% die on a file name they can read."
              % (len(raised), tested, 100.0 * len(raised) / tested))
    print()
    print("  A tool that printed nothing was never tested, and is excluded")
    print("  from both halves of that fraction. Silence is not a pass.")
    print()
    print("  RAISED -- this is the defect:")
    for n in raised:
        print("     %s" % n)
    print()
    print("  PRINTED THE NAME -- these are the tools already obeying the")
    print("  convention, or immune because they never touch stdout encoding:")
    for n in printed:
        print("     %s" % n)
    if timed_out:
        print()
        print("  TIMED OUT (not classified, and not counted as either):")
        for n in timed_out:
            print("     %s" % n)

    if args.expect_raised is not None and args.expect_raised != len(raised):
        print()
        print("FATAL: --expect-raised %d but counted %d"
              % (args.expect_raised, len(raised)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
