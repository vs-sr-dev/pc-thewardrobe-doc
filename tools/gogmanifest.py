#!/usr/bin/env python3
"""manifest.py - compare a GOG galaxyFileList manifest against what is on disk.

The manifest is `goggame-<gameId>-galaxyFileList.ini` (here
`goggame-galaxyFileList.ini`): a CRLF INI with one `Fn=path` per entry and a
`files_counter=` line.  Paths are Windows-relative to the install directory
unless they carry a drive letter, in which case they name something GOG put
somewhere else on the machine (its own installer, the DirectX cabs).

Nothing here executes, extracts or writes to the object.  It walks, it stats,
it compares.  The point of the tool is that on this object the manifest is the
*definition*: 'the object' is the set of declared entries, and anything else in
the folder arrived from somewhere the publisher did not put it.

Comparison is case-insensitive because the manifest is not consistent with the
filesystem about case (`configJ.cnf` on disk, `configj.cnf` in some listings)
and NTFS is not case-sensitive.  Directory entries are detected by stat, not
guessed from the name, so a declared entry that is a directory is reported as
such rather than as a missing file.

usage:
    python tools/manifest.py --root <install dir> [--ini <path>] [--full]
"""
import argparse
import os
import sys


def read_manifest(path):
    """Return (total_counter, entries, sections).

    A galaxyFileList may carry MORE THAN ONE section.  Broken Sword 3's has
    three -- [1207658708], [ISI], [DirectX] -- each with its own
    files_counter and its own F0.. run, and the original single-counter
    reading silently reported the LAST counter it saw (157) as if it were the
    manifest's.  sections is a list of (name, declared_counter, n_entries) in
    file order; total_counter is their sum.
    """
    entries = []
    sections = []
    cur = None
    seen_counter = False
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("latin-1")
    for line in text.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = [line[1:-1], None, 0]
            sections.append(cur)
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key.lower() == "files_counter":
            seen_counter = True
            if cur is None:
                cur = ["(no section)", None, 0]
                sections.append(cur)
            cur[1] = int(val.strip())
            continue
        if key.lower().startswith("dir_") or key.lower() == "dirs":
            continue
        if key[:1].upper() == "F" and key[1:].isdigit():
            entries.append(val.strip())
            if cur is None:
                cur = ["(no section)", None, 0]
                sections.append(cur)
            cur[2] += 1
    if not seen_counter:
        raise SystemExit(
            "%s: no files_counter= line found -- this is not a "
            "galaxyFileList, or its shape has changed" % path)
    total = sum(s[1] for s in sections if s[1] is not None)
    return total, entries, [tuple(s) for s in sections]


def is_absolute(p):
    return len(p) >= 2 and p[1] == ":"


def norm(p):
    return p.replace("\\", "/").lstrip("./").lower()


def walk(root):
    """Every file under root, as (relative-posix-path, size).  Directories too."""
    files = {}
    dirs = set()
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root).replace("\\", "/")
        if rel == ".":
            rel = ""
        if rel:
            dirs.add(rel.lower())
        for name in filenames:
            full = os.path.join(dirpath, name)
            key = (rel + "/" + name) if rel else name
            try:
                size = os.path.getsize(full)
            except OSError:
                size = -1
            files[key.lower()] = (key, size)
    return files, dirs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--ini", default=None)
    ap.add_argument("--full", action="store_true",
                    help="print every entry of every class, not just summaries")
    args = ap.parse_args()

    root = args.root
    ini = args.ini or os.path.join(root, "goggame-galaxyFileList.ini")
    counter, entries, sections = read_manifest(ini)

    absolute = [e for e in entries if is_absolute(e)]
    relative = [e for e in entries if not is_absolute(e)]
    rel_norm = {}
    for e in relative:
        rel_norm.setdefault(norm(e), e)

    files, dirs = walk(root)

    declared_present = []
    declared_isdir = []
    declared_absent = []
    for key, orig in sorted(rel_norm.items()):
        if key in files:
            declared_present.append((orig, files[key][1]))
        elif key in dirs:
            declared_isdir.append(orig)
        else:
            declared_absent.append(orig)

    undeclared = []
    for key, (orig, size) in sorted(files.items()):
        if key not in rel_norm:
            undeclared.append((orig, size))

    disk_bytes = sum(s for _, (o, s) in files.items())
    decl_bytes = sum(s for _, s in declared_present)
    und_bytes = sum(s for _, s in undeclared)

    print("manifest                  : %s" % os.path.basename(ini))
    print("sections                   : %d" % len(sections))
    for name, dec, n in sections:
        print("   [%-14s] files_counter=%-6s  Fn= entries %d%s"
              % (name, dec, n, "" if dec == n else "   <-- DISAGREE"))
    print("files_counter, summed      : %s" % counter)
    print("entries parsed             : %d" % len(entries))
    print("  absolute (outside object): %d" % len(absolute))
    print("  relative                 : %d" % len(relative))
    print("  distinct relative        : %d" % len(rel_norm))
    print()
    print("on disk, files             : %d   %d bytes" % (len(files), disk_bytes))
    print("on disk, directories       : %d" % len(dirs))
    print()
    print("declared and present       : %d   %d bytes" % (len(declared_present), decl_bytes))
    print("declared, and is a DIRECTORY: %d" % len(declared_isdir))
    print("declared and truly ABSENT  : %d" % len(declared_absent))
    print("present and NOT declared   : %d   %d bytes" % (len(undeclared), und_bytes))
    print()
    print("check: %d + %d = %d files on disk  -> %s"
          % (len(declared_present), len(undeclared),
             len(declared_present) + len(undeclared),
             "OK" if len(declared_present) + len(undeclared) == len(files) else "MISMATCH"))
    print("check: %d + %d = %d bytes on disk  -> %s"
          % (decl_bytes, und_bytes, decl_bytes + und_bytes,
             "OK" if decl_bytes + und_bytes == disk_bytes else "MISMATCH"))

    if declared_isdir:
        print()
        print("-- declared entries that are directories on disk --")
        for d in declared_isdir:
            key = norm(d)
            n = sum(1 for k in files if k.startswith(key + "/"))
            b = sum(files[k][1] for k in files if k.startswith(key + "/"))
            print("   %-44s %4d files below it, %d bytes" % (d, n, b))

    if declared_absent:
        print()
        print("-- declared and truly absent --")
        for d in declared_absent:
            print("   %s" % d)

    print()
    print("-- present and not declared, by size --")
    for orig, size in sorted(undeclared, key=lambda x: -x[1]):
        print("   %12d  %s" % (size, orig))
    print("   %12d  TOTAL" % und_bytes)

    if args.full:
        print()
        print("-- absolute manifest entries (not part of the object) --")
        for e in absolute:
            print("   %s" % e)

    # top-level branch census, counted rather than subtracted
    print()
    print("-- branches, counted --")
    branch = {}
    for key, (orig, size) in files.items():
        head = orig.split("/")[0] if "/" in orig else "(root)"
        n, b = branch.get(head, (0, 0))
        branch[head] = (n + 1, b + size)
    for d in sorted(dirs):
        if "/" not in d:
            branch.setdefault(d, (0, 0))
    tot_n = tot_b = 0
    for head in sorted(branch, key=lambda h: -branch[h][1]):
        n, b = branch[head]
        tot_n += n
        tot_b += b
        print("   %-14s %4d  %13d  %8.4f %%" % (head, n, b, 100.0 * b / disk_bytes))
    print("   %-14s %4d  %13d  %8.4f %%" % ("TOTAL", tot_n, tot_b, 100.0 * tot_b / disk_bytes))
    print("   residue against the walk: %d bytes, %d files"
          % (disk_bytes - tot_b, len(files) - tot_n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
