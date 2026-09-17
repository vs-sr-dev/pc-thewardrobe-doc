#!/usr/bin/env python3
"""Find the build-machine and source-tree paths that leaked into a shipped build.

The 1992 object in this collection contains **no** absolute path: it was
assembled on a machine whose directory names never reached the output. This one
is the opposite case, and the paths in it are worth separating by whose machine
they name, because a Unity build path and a studio source path are different
findings. Unity's is a leak from the engine vendor; the studio's is a leak from
the people who made the game.

Three classes are collected:

  drive     an absolute path with a drive letter, `C:/BuildAgent/...`
  source    a rooted path through a source tree, `\\Source\\Assets\\Src\\...`,
            with no drive letter
  pdb       a `.pdb` or `.cs` file name, which names a file that did not ship

Both slash directions are accepted everywhere, because this object mixes them.
Binaries are scanned as latin-1 so that a path embedded between arbitrary bytes
is still found; text files are scanned as UTF-8. Nothing is decompressed.

A note on why this file exists rather than a one-line `grep`: the first attempt
at this measurement was written as a shell heredoc, the heredoc ate one
backslash from the character class `[\\/]`, the class collapsed to `[/]`, and
the search reported **zero** source-tree paths in files that visibly contain
them. A tool in a file has a backslash count that can be checked. See
`docs/19-corrections.md`.

Usage:  python tools/paths.py <dir_or_file> [--ext .exe,.dll] [out.txt]
"""
import collections
import os
import re
import sys

SEP = "[\\\\/]"                     # one backslash or one forward slash
BODY = r"[A-Za-z0-9_.\-+()~ ]{1,60}"

# A drive-lettered path. Three guards, each of which removed a class of false
# positive found by running this on the object:
#   (?<![A-Za-z0-9])  the letter must not be the tail of a word -- without it,
#                     every `http://` in the object matches as drive `p:`
#   two components    a bare `C:/x` is not a build path
#   BODY              path components only; a `:` inside kills the match, which
#                     is what separates a real path from a run of binary that
#                     happens to contain a colon and a slash
DRIVE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:" + SEP + BODY
                   + r"(?:" + SEP + BODY + r")+")
SOURCE = re.compile(r"(?<![A-Za-z0-9:])" + SEP
                    + r"(?:Source|Assets|Src|Projects?|svn|git)" + SEP
                    + BODY + r"(?:" + SEP + BODY + r")*")
CSPDB = re.compile(r"[A-Za-z0-9_.\-]{2,60}\.(?:pdb|cs|csproj|sln)\b")

TEXTY = (".xml", ".txt", ".config", ".aspx", ".ini", ".map", ".browser", ".meta")


def scan(path):
    raw = open(path, "rb").read()
    text = raw.decode("latin-1")
    return (DRIVE.findall(text), SOURCE.findall(text), CSPDB.findall(text))


def main(target, exts=None, out=None):
    files = []
    if os.path.isfile(target):
        files = [target]
        root = os.path.dirname(target)
    else:
        root = target
        for dp, dn, fn in os.walk(target):
            dn.sort()
            for n in sorted(fn):
                if exts and os.path.splitext(n)[1].lower() not in exts:
                    continue
                files.append(os.path.join(dp, n))

    lines = []

    def say(s=""):
        # Paths pulled out of a binary can hold bytes the console encoding
        # cannot render; the file always gets the real text.
        sys.stdout.write(s.encode(sys.stdout.encoding or "utf-8",
                                  "backslashreplace").decode(
                                      sys.stdout.encoding or "utf-8") + "\n")
        lines.append(s)

    grand = collections.Counter()
    for f in files:
        rel = os.path.relpath(f, root).replace("\\", "/") or os.path.basename(f)
        drive, source, cspdb = scan(f)
        if not (drive or source):
            continue
        say("%s   %d bytes" % (rel, os.path.getsize(f)))
        say("   drive-lettered paths %d (%d distinct)" % (len(drive), len(set(drive))))
        say("   source-tree paths    %d (%d distinct)" % (len(source), len(set(source))))
        grand["drive"] += len(drive)
        grand["source"] += len(source)
        roots = collections.Counter()
        for p in drive:
            parts = re.split(SEP, p)
            roots["%s/%s" % (parts[0], parts[1] if len(parts) > 1 else "")] += 1
        for r, c in roots.most_common(12):
            say("      %-34s %d" % (r, c))
        for p in sorted(set(source))[:12]:
            say("      SOURCE  %s" % p)
        say("   sample of distinct drive paths:")
        for p in sorted(set(drive))[:6]:
            say("      %s" % p)
        say("")

    say("totals: %d drive-lettered, %d source-tree, over %d files scanned"
        % (grand["drive"], grand["source"], len(files)))
    if out:
        open(out, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    ex = None
    for a in sys.argv[1:]:
        if a.startswith("--ext"):
            ex = set(a.split("=", 1)[1].lower().split(","))
    main(args[0], ex, args[1] if len(args) > 1 else None)
