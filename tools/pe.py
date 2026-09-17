#!/usr/bin/env python3
"""pe.py -- a minimal PE64 section / import / resource reader.

Written because this collection has documented twenty-two PC objects and has
never read a PE header. Uses the public PE/COFF layout, and says so: the
structure below is the documented one, and the validation is that the parse
must reproduce facts measured independently (file size, section file offsets).

Usage:
    pe.py --sections FILE
    pe.py --imports  FILE
    pe.py --resources FILE
    pe.py --version  FILE
    pe.py --strings  FILE --section .rdata [--min N]
"""
import argparse
import collections
import math
import re
import struct
import sys


class PE(object):
    def __init__(self, path):
        with open(path, "rb") as fh:
            self.data = fh.read()
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError("%s: not MZ" % path)
        pe_off = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe_off:pe_off + 4] != b"PE\x00\x00":
            raise ValueError("%s: no PE signature at 0x%X" % (path, pe_off))
        self.pe_off = pe_off
        (self.machine, self.nsect, self.timestamp, _, _,
         self.opt_size, self.characteristics) = struct.unpack_from(
            "<HHIIIHH", d, pe_off + 4)
        opt = pe_off + 24
        self.magic = struct.unpack_from("<H", d, opt)[0]
        self.pe32plus = self.magic == 0x20B
        self.image_base = struct.unpack_from(
            "<Q" if self.pe32plus else "<I", d, opt + 24)[0]
        nrva_off = opt + (108 if self.pe32plus else 92)
        self.nrva = struct.unpack_from("<I", d, nrva_off)[0]
        self.dirs = []
        for i in range(self.nrva):
            rva, size = struct.unpack_from("<II", d, nrva_off + 4 + i * 8)
            self.dirs.append((rva, size))
        sect_off = opt + self.opt_size
        self.sections = []
        for i in range(self.nsect):
            o = sect_off + i * 40
            name = d[o:o + 8].rstrip(b"\x00").decode("latin-1")
            vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", d, o + 8)
            chars = struct.unpack_from("<I", d, o + 36)[0]
            self.sections.append(
                {"name": name, "vsize": vsize, "vaddr": vaddr,
                 "rsize": rsize, "raddr": raddr, "chars": chars})

    def rva_to_off(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
                delta = rva - s["vaddr"]
                if delta < s["rsize"]:
                    return s["raddr"] + delta
                return None
        return None

    def cstr(self, off):
        end = self.data.find(b"\x00", off)
        return self.data[off:end].decode("latin-1")

    def section(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def section_bytes(self, name):
        s = self.section(name)
        if not s:
            return b""
        return self.data[s["raddr"]:s["raddr"] + s["rsize"]]

    def versioninfo(self):
        """The VS_VERSIONINFO block as {"strings": [...], "fixed": (...)}.

        Added on pc-streetsofkamurocho-doc. `pecensus.py` has always called
        `p.versioninfo()` and this class has never had it, so every one of its
        rows died in the `except` branch and printed `n/a` for the format and
        an AttributeError in the company column. That was the third of three
        wrong names in a tool whose inherited diagnosis said there was one, and
        the first two hid it: `e_lfanew` raised before `linker` could, and
        `linker` raised before this could. See docs/13.

        The harvest is the same one `--version` prints: the block is UTF-16
        key/value pairs, so every readable run is returned in file order and
        the caller pairs them. Returns None when there is no such resource,
        which is a real answer -- four objects in this collection have had a
        main binary without one.
        """
        rva, size = self.dirs[2] if len(self.dirs) > 2 else (0, 0)
        if not rva:
            return None
        base = self.rva_to_off(rva)
        if base is None:
            return None
        out = []
        walk_res(self, base, base, 0, [], out)
        for path, drva, dsize in out:
            if path and path[0] == 16:
                off = self.rva_to_off(drva)
                blob = self.data[off:off + dsize]
                txt = blob.decode("utf-16-le", "replace")
                runs = [p for p in re.split(r"[\x00-\x08\x0b-\x1f]+", txt)
                        if len(p) > 1]
                fixed = None
                fx = blob.find(b"\xbd\x04\xef\xfe")
                if fx >= 0:
                    fv = struct.unpack_from("<HHHH", blob, fx + 8)
                    pv = struct.unpack_from("<HHHH", blob, fx + 16)
                    fixed = (fv[1], fv[0], fv[3], fv[2],
                             pv[1], pv[0], pv[3], pv[2])
                return {"strings": runs, "fixed": fixed, "bytes": dsize}
        return None


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def show_sections(pe):
    print("machine 0x%04X  PE32+ %s  image base 0x%X  sections %d  timestamp 0x%08X"
          % (pe.machine, pe.pe32plus, pe.image_base, pe.nsect, pe.timestamp))
    print("%-10s %10s %10s %10s %10s %9s %8s"
          % ("name", "vsize", "vaddr", "rawsize", "rawoff", "entropy", "zeros%"))
    for s in pe.sections:
        blob = pe.data[s["raddr"]:s["raddr"] + s["rsize"]]
        z = 100.0 * blob.count(0) / len(blob) if blob else 0
        print("%-10s 0x%08X 0x%08X 0x%08X 0x%08X %9.4f %7.2f%%"
              % (s["name"], s["vsize"], s["vaddr"], s["rsize"], s["raddr"],
                 entropy(blob), z))


def show_imports(pe):
    rva, size = pe.dirs[1] if len(pe.dirs) > 1 else (0, 0)
    if not rva:
        print("no import directory")
        return
    off = pe.rva_to_off(rva)
    if off is None:
        print("import directory RVA 0x%X not in a raw section" % rva)
        return
    total = 0
    i = 0
    while True:
        o = off + i * 20
        lookup, ts, fwd, namerva, iat = struct.unpack_from("<IIIII", pe.data, o)
        if lookup == 0 and namerva == 0 and iat == 0:
            break
        dllname = pe.cstr(pe.rva_to_off(namerva))
        names = []
        table = lookup or iat
        toff = pe.rva_to_off(table)
        j = 0
        # THE THUNK IS THE IMAGE'S WORD, NOT ALWAYS 64 BITS. This reader was
        # written for PE64 and read every thunk as a u64 with the ordinal bit
        # at 63; on a PE32 the thunks are u32 with the bit at 31, so each read
        # fused two entries and the loop ran past the table's zero into
        # whatever followed. On pc-losthorizon-doc that printed "981 imports"
        # for d3d9.dll (there is one) and 102,428 for a packed DLL's
        # KERNEL32. Repaired there; the width follows the optional header.
        width, ordbit, fmt = (8, 1 << 63, "<Q") if pe.pe32plus else (4, 1 << 31, "<I")
        while toff is not None:
            if toff + (j + 1) * width > len(pe.data):
                break
            ent = struct.unpack_from(fmt, pe.data, toff + j * width)[0]
            if ent == 0:
                break
            if ent & ordbit:
                names.append("#%d" % (ent & 0xFFFF))
            else:
                hoff = pe.rva_to_off(ent & 0x7FFFFFFF)
                names.append(pe.cstr(hoff + 2) if hoff else "?")
            j += 1
        total += len(names)
        print("%-24s %4d imports" % (dllname, len(names)))
        for n in names:
            print("      %s" % n)
        i += 1
    print("%d DLLs, %d named imports" % (i, total))


RT = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
      9: "ACCELERATOR", 10: "RCDATA", 12: "GROUP_CURSOR", 14: "GROUP_ICON",
      16: "VERSION", 24: "MANIFEST"}


def walk_res(pe, base, off, depth, path, out):
    d = pe.data
    chars, ts, maj, minr, nnamed, nid = struct.unpack_from("<IIHHHH", d, off)
    for i in range(nnamed + nid):
        e = off + 16 + i * 8
        nameoff, dataoff = struct.unpack_from("<II", d, e)
        if nameoff & 0x80000000:
            noff = base + (nameoff & 0x7FFFFFFF)
            ln = struct.unpack_from("<H", d, noff)[0]
            key = d[noff + 2:noff + 2 + ln * 2].decode("utf-16-le")
        else:
            key = nameoff
        if dataoff & 0x80000000:
            walk_res(pe, base, base + (dataoff & 0x7FFFFFFF), depth + 1,
                     path + [key], out)
        else:
            drva, dsize, cp, _ = struct.unpack_from("<IIII", d, base + dataoff)
            out.append((path + [key], drva, dsize))


def show_resources(pe, want_version=False):
    rva, size = pe.dirs[2]
    base = pe.rva_to_off(rva)
    if base is None:
        print("no resource section")
        return
    out = []
    walk_res(pe, base, base, 0, [], out)
    print("%d resource data entries, directory at file 0x%X (%d bytes)"
          % (len(out), base, size))
    for path, drva, dsize in out:
        t = path[0]
        tn = RT.get(t, str(t)) if isinstance(t, int) else t
        print("  type=%-12s name=%-14s lang=%-6s rva=0x%08X size=%d"
              % (tn, path[1] if len(path) > 1 else "", path[2] if len(path) > 2 else "",
                 drva, dsize))
    if want_version:
        for path, drva, dsize in out:
            if path[0] == 16:
                off = pe.rva_to_off(drva)
                blob = pe.data[off:off + dsize]
                print("\n--- VS_VERSIONINFO, %d bytes ---" % dsize)
                # the block is UTF-16 key/value pairs; pull every readable pair
                txt = blob.decode("utf-16-le", "replace")
                parts = [p for p in re.split(r"[\x00-\x08\x0b-\x1f]+", txt) if len(p) > 2]
                for i, p in enumerate(parts):
                    print("   %s" % p)
                fx = blob.find(b"\xbd\x04\xef\xfe")
                if fx >= 0:
                    fv = struct.unpack_from("<HHHH", blob, fx + 8)
                    pv = struct.unpack_from("<HHHH", blob, fx + 16)
                    print("   FIXEDFILEINFO FileVersion %d.%d.%d.%d  ProductVersion %d.%d.%d.%d"
                          % (fv[1], fv[0], fv[3], fv[2], pv[1], pv[0], pv[3], pv[2]))


def main():
    # A VS_VERSIONINFO block holds UTF-16 and this tool printed it straight to
    # a console whose default encoding on this machine is cp1252, so
    # `--version` died with UnicodeEncodeError on the first non-Latin-1
    # character instead of printing the version resource. See
    # docs/17-corrections.md.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--sections", action="store_true")
    ap.add_argument("--imports", action="store_true")
    ap.add_argument("--resources", action="store_true")
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--strings", action="store_true")
    ap.add_argument("--section", default=".rdata")
    ap.add_argument("--min", type=int, default=5)
    ap.add_argument("file")
    a = ap.parse_args()
    if not (a.sections or a.imports or a.resources or a.version or a.strings):
        # Without a flag this printed nothing and returned 0, which reads
        # as "a PE with nothing in it" to a script. Say what was wanted.
        ap.print_usage()
        print("pe: give at least one of --sections --imports --resources "
              "--version --strings", file=sys.stderr)
        return 2
    pe = PE(a.file)
    if a.sections:
        show_sections(pe)
    if a.imports:
        show_imports(pe)
    if a.resources or a.version:
        show_resources(pe, want_version=a.version)
    if a.strings:
        blob = pe.section_bytes(a.section)
        for m in re.finditer(rb"[\x20-\x7e]{%d,}" % a.min, blob):
            print("%s+0x%06X  %s" % (a.section, m.start(), m.group().decode("latin-1")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
