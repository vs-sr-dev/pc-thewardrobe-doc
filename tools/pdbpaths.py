#!/usr/bin/env python3
"""pdbpaths.py -- the program-database path every MSVC binary carries, and the
two in this object that name a person.

WHAT IS BEING READ
------------------
A PE built by MSVC carries a **CodeView `RSDS` record** in its debug directory:
a signature, a 16-byte GUID, an age, and then the **absolute path of the `.pdb`
on the machine that linked it**, NUL-terminated. Nobody chooses that string;
the linker writes it. It is the purest form of build-machine reperto there is,
and it is also where a personal name gets into a shipped binary without anyone
deciding that it should.

WHY THIS IS A SEPARATE PROGRAM
------------------------------
Because the redaction has to be done **by a program and not by hand**
(`pc-themepark-doc/docs/12`, applied since). This one publishes the path and
replaces exactly two kinds of component:

  * a Windows **account name** -- the component immediately after `\\Users\\`
    or `\\Documents and Settings\\` -- becomes `<USER>`;
  * a component that is or contains a **machine name** of the form
    `<something>-PC`, `DESKTOP-*` or `<Company>_<Name>-PC_<number>`, becomes
    `<HOST>` with the parts that are not the name kept.

Everything else is published: drive letters, company directories, branch names,
SDK versions and configuration names are settings and reperti, and this
collection has published them for eight objects.

    python tools/pdbpaths.py --selftest
    python tools/pdbpaths.py
    python tools/pdbpaths.py --raw       (refuses; the point is that it cannot)
"""
import argparse
import collections
import os
import re
import struct
import sys

ROOT = "karmaflow-steam"

USERDIR = re.compile(r"(?i)(\\(?:Users|Documents and Settings)\\)([^\\]+)")
HOSTISH = re.compile(r"(?i)(^|_)([A-Za-z][A-Za-z0-9]*)-PC(_\d+)?(?=$|_|\\)")
DESKTOP = re.compile(r"(?i)\bDESKTOP-[A-Z0-9]{7}\b")


class NotPE(Exception):
    pass


def rsds_path(path):
    """Return the .pdb path from the CodeView record, or None."""
    d = open(path, "rb").read()
    if d[:2] != b"MZ":
        raise NotPE("not an MZ image")
    (pe,) = struct.unpack_from("<I", d, 0x3C)
    if d[pe:pe + 4] != b"PE\0\0":
        raise NotPE("no PE signature")
    (_mach, nsec, _ts, _p1, _p2, optsize, _ch) = struct.unpack_from(
        "<HHIIIHH", d, pe + 4)
    opt = pe + 24
    (magic,) = struct.unpack_from("<H", d, opt)
    if magic == 0x10B:
        dir_off = opt + 92
    elif magic == 0x20B:
        dir_off = opt + 108
    else:
        raise NotPE("optional header magic 0x%X" % magic)
    (ndir,) = struct.unpack_from("<I", d, dir_off)
    if ndir < 7:
        return None
    drva, dsize = struct.unpack_from("<II", d, dir_off + 4 + 6 * 8)
    if drva == 0 or dsize == 0:
        return None
    # map the RVA through the section table
    sec = opt + optsize
    off = None
    for i in range(nsec):
        s = sec + i * 40
        vaddr, vsize = struct.unpack_from("<II", d, s + 12)
        rsize, raddr = struct.unpack_from("<II", d, s + 16)
        if vaddr <= drva < vaddr + max(vsize, rsize):
            off = raddr + (drva - vaddr)
            break
    if off is None:
        return None
    for k in range(dsize // 28):
        e = off + k * 28
        if e + 28 > len(d):
            break
        (_ch, _ts, _mj, _mn, typ, sz, _rva, ptr) = struct.unpack_from(
            "<IIHHIIII", d, e)
        if typ != 2:                     # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        blob = d[ptr:ptr + sz]
        if blob[:4] != b"RSDS":
            continue
        tail = blob[24:]
        z = tail.find(b"\x00")
        return tail[:z if z >= 0 else len(tail)].decode("latin-1")
    return None


def redact(p):
    """Replace an account name and a machine name; keep everything else."""
    notes = []
    out = USERDIR.sub(lambda m: m.group(1) + "<USER>", p)
    if out != p:
        notes.append("account name after \\Users\\")
    p2 = out
    out = DESKTOP.sub("<HOST>", out)
    if out != p2:
        notes.append("DESKTOP-shaped host name")
    p3 = out
    out = HOSTISH.sub(lambda m: (m.group(1) or "") + "<HOST>"
                      + (m.group(3) or ""), out)
    if out != p3:
        notes.append("<name>-PC machine name")
    return out, notes


def walk(root):
    for r, _d, fs in os.walk(root):
        for f in sorted(fs):
            if os.path.splitext(f)[1].lower() in (".exe", ".dll"):
                yield os.path.join(r, f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--raw", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.raw:
        print("pdbpaths: there is no --raw. The redaction is the point of "
              "this file, and a switch that turns it off would put the "
              "original into somebody's terminal and then into a document.")
        return 1
    rows = []
    n = 0
    for p in walk(a.root):
        n += 1
        try:
            s = rsds_path(p)
        except NotPE:
            continue
        if not s:
            continue
        red, notes = redact(s)
        rows.append((os.path.relpath(p, a.root).replace("\\", "/"), red, notes))
    print("binaries examined            : %d" % n)
    print("carrying a CodeView RSDS path: %d" % len(rows))
    print("of those, redacted           : %d" % sum(1 for r in rows if r[2]))
    print()
    for rel, red, notes in rows:
        mark = "  <-- REDACTED: " + ", ".join(notes) if notes else ""
        print("%s%s" % (rel, mark))
        print("    %s" % red)
    print()
    roots = collections.Counter(r[1].split("\\")[0] for r in rows)
    print("drive letters : %s" % dict(roots))
    return 0


def selftest():
    cases = [
        ("a Users account name",
         "c:\\Users\\Jane Roe\\Perforce\\Thing\\x.pdb",
         "c:\\Users\\<USER>\\Perforce\\Thing\\x.pdb"),
        ("a Documents and Settings account name",
         "C:\\Documents and Settings\\bob\\a\\b.pdb",
         "C:\\Documents and Settings\\<USER>\\a\\b.pdb"),
        ("a <name>-PC machine name inside a folder",
         "D:\\Karmaflow\\UE3\\Company_Someone-PC_3686\\Engine\\x.pdb",
         "D:\\Karmaflow\\UE3\\Company_<HOST>_3686\\Engine\\x.pdb"),
        ("a DESKTOP-shaped host name",
         "E:\\DESKTOP-AB12CD3\\build\\x.pdb",
         "E:\\<HOST>\\build\\x.pdb"),
        ("a company path with no person in it is untouched",
         "D:\\Basecamp Games\\Projects\\Karmaflow\\Development-UE3\\x.pdb",
         "D:\\Basecamp Games\\Projects\\Karmaflow\\Development-UE3\\x.pdb"),
        ("a build-slave path is untouched",
         "e:\\buildslave\\steam_rel_client_win64\\build\\src\\x.pdb",
         "e:\\buildslave\\steam_rel_client_win64\\build\\src\\x.pdb"),
        ("an SDK path is untouched",
         "r:\\sw\\physx\\apexsdk\\1.2.1\\release\\x.pdb",
         "r:\\sw\\physx\\apexsdk\\1.2.1\\release\\x.pdb"),
    ]
    ok = 0
    print("pdbpaths selftest: %d specimens" % len(cases))
    for name, src, want in cases:
        got, _n = redact(src)
        good = got == want
        ok += 1 if good else 0
        print("  %-52s %s" % (name, "PASS" if good else "FAIL got %r" % got))
    # and the control that matters: the redactor must not be a no-op
    got, _n = redact("c:\\Users\\Jane Roe\\x.pdb")
    control = "Jane Roe" not in got
    ok += 1 if control else 0
    print("  %-52s %s" % ("the original cannot survive the redactor",
                          "PASS" if control else "FAIL"))
    print()
    print("%d of %d behaved as required" % (ok, len(cases) + 1))
    return 0 if ok == len(cases) + 1 else 1


if __name__ == "__main__":
    sys.exit(main())
