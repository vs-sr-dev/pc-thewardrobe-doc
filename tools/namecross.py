"""namecross.py -- cross the name sets of this disc against each other, in
both directions, and print every miss individually.

Five sets of names exist on this disc and they are supposed to agree:

  disc     the 148 file names in the ISO's primary namespace
  bank2d   the 304 member names inside 2D.DAT
  banksnd  the 46 member names inside SUONI.DAT
  mesh     the texture file names the 36 .3DS meshes ask their materials for
  exe      the filename-shaped strings inside UNDER.E_E

The branch's rule is that a cross-reference is only a measurement if the misses
are looked at one at a time, so this tool never prints a summary without also
printing the names behind it. A miss that dissolves on inspection is still a
miss until it has been inspected.

Matching is case-insensitive, because the ISO primary namespace is uppercase,
Joliet is mixed, and the banks contain both.

Usage:
    python tools/namecross.py --manifest notes/manifest.tsv --files _work/files
"""

import os
import re
import struct
import sys

FILENAME = re.compile(rb"[A-Za-z0-9_\-~]{1,8}\.[A-Za-z0-9]{1,3}")
KNOWN_EXT = {"BMP", "WAV", "3DS", "DAT", "AVI", "TXT", "SAV", "EXE", "DLL",
             "INI", "INF", "TAG", "LID", "INS", "ICO", "TTF", "BIN", "CAB",
             "E_E", "EX_"}


def disc_names(manifest):
    out = set()
    with open(manifest, encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 6:
                out.add(p[5].rsplit("/", 1)[-1].upper())
    return out


def bank_names(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"BANK":
        raise SystemExit("%s is not a BANK" % path)
    count, _ds = struct.unpack_from("<II", data, 4)
    p = 12
    out = []
    for _ in range(count):
        (nl,) = struct.unpack_from("<I", data, p)
        p += 4
        out.append(data[p:p + nl].decode("ascii"))
        p += nl + 4
    return out


def mesh_textures(root):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import a3ds
    out = set()
    for f in sorted(os.listdir(root)):
        if f.lower().endswith(".3ds"):
            s, _ = a3ds.read(os.path.join(root, f))
            out.update(t.upper() for t in s["textures"])
    return out


def exe_names(path):
    with open(path, "rb") as fh:
        data = fh.read()
    out = set()
    for m in FILENAME.finditer(data):
        s = m.group(0).decode("ascii")
        if s.rsplit(".", 1)[-1].upper() in KNOWN_EXT:
            out.add(s.upper())
    return out


def show(label, s):
    print("%-34s %d" % (label, len(s)))


def cross(a, an, b, bn):
    only_a = sorted(a - b)
    only_b = sorted(b - a)
    print()
    print("=== %s vs %s ===" % (an, bn))
    print("in both                          : %d" % len(a & b))
    print("in %-14s only          : %d" % (an, len(only_a)))
    for x in only_a:
        print("     %s" % x)
    print("in %-14s only          : %d" % (bn, len(only_b)))
    for x in only_b:
        print("     %s" % x)


def main(argv):
    if "--manifest" not in argv or "--files" not in argv:
        print(__doc__)
        return 2
    manifest = argv[argv.index("--manifest") + 1]
    files = argv[argv.index("--files") + 1]

    disc = disc_names(manifest)
    b2d = {n.upper() for n in bank_names(os.path.join(files, "2D.DAT"))}
    bsnd = {n.upper() for n in bank_names(os.path.join(files, "SUONI.DAT"))}
    mesh = mesh_textures(files)
    exe = exe_names(os.path.join(files, "UNDER.E_E"))

    print("name sets")
    show("  disc file names", disc)
    show("  2D.DAT member names", b2d)
    show("  SUONI.DAT member names", bsnd)
    show("  texture names inside the 36 meshes", mesh)
    show("  filename-shaped strings in UNDER.E_E", exe)
    everything = disc | b2d | bsnd
    print("%-34s %d" % ("  union of the three real sets", len(everything)))

    cross(mesh, "mesh textures", disc | b2d, "disc + 2D.DAT")
    cross(exe, "UNDER.E_E", everything, "disc+2D.DAT+SUONI.DAT")
    cross(b2d, "2D.DAT", disc, "disc")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
