#!/usr/bin/env python3
"""peimpexp.py -- the import and export directories of a PE32 image.

Written here because `tools/pe.py --imports` is wrong and has been wrong for
three sessions: it reads the import name table at its **file offset taken as
if it were an RVA**, so on any image whose first section is not loaded at the
same delta it prints instruction bytes where names should be. On
`winmm.dll` it reports `1 DLLs, 166 named imports` and every name it prints is
rubbish. That is not a rounding error; it is a tool reporting a number for a
question it did not ask.

This one maps RVAs through the section table, which is the whole of the fix.

    peimpexp.py <file.exe> --imports
    peimpexp.py <file.dll> --exports
    peimpexp.py <file.dll> --exports --grep mci
"""
import argparse
import struct
import sys


class PeError(Exception):
    pass


class PE(object):
    def __init__(self, path):
        self.data = open(path, "rb").read()
        d = self.data
        if d[:2] != b"MZ" and d[:2] != b"ZM":
            raise PeError("%s: not an MZ image" % path)
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe:pe + 4] != b"PE\0\0":
            raise PeError("%s: no PE signature at e_lfanew=%d" % (path, pe))
        (machine, nsec, _stamp, _p1, _p2, optsize,
         _chars) = struct.unpack_from("<HHIIIHH", d, pe + 4)
        self.machine = machine
        opt = pe + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        # PE32+ support, added on pc-karmaflow-doc, which is the first 64-bit
        # object this collection has held and 53 of whose 59 binaries this
        # reader refused outright. The two layouts differ in exactly three
        # places: PE32+ has no BaseOfData, so ImageBase is a QWORD at +24
        # instead of a DWORD at +28, and everything after it shifts by 16.
        if magic == 0x10B:
            self.bits = 32
            self.imagebase = struct.unpack_from("<I", d, opt + 28)[0]
            dir_off = opt + 92
        elif magic == 0x20B:
            self.bits = 64
            self.imagebase = struct.unpack_from("<Q", d, opt + 24)[0]
            dir_off = opt + 108
        else:
            raise PeError("%s: optional header magic 0x%X is neither PE32 "
                          "(0x10B) nor PE32+ (0x20B)" % (path, magic))
        self.magic = magic
        ndir = struct.unpack_from("<I", d, dir_off)[0]
        self.dirs = []
        for i in range(ndir):
            self.dirs.append(struct.unpack_from("<II", d, dir_off + 4 + i * 8))
        self.sections = []
        s = opt + optsize
        for i in range(nsec):
            name, vsize, va, rsize, raw = struct.unpack_from("<8sIIII", d,
                                                             s + i * 40)
            self.sections.append((name.rstrip(b"\0"), va, vsize, raw, rsize))

    def off(self, rva):
        for _name, va, vsize, raw, rsize in self.sections:
            if va <= rva < va + max(vsize, rsize):
                o = raw + (rva - va)
                if o < len(self.data):
                    return o
        return None

    def cstr(self, off):
        if off is None:
            return None
        e = self.data.find(b"\0", off)
        return self.data[off:e]

    def imports(self):
        if len(self.dirs) < 2 or not self.dirs[1][0]:
            return []
        out = []
        p = self.off(self.dirs[1][0])
        if p is None:
            raise PeError("import directory RVA 0x%X is in no section"
                          % self.dirs[1][0])
        while True:
            oft, _t, _f, namerva, first = struct.unpack_from("<5I",
                                                             self.data, p)
            if not (oft or namerva or first):
                break
            dll = self.cstr(self.off(namerva)) or b"?"
            names = []
            thunk = self.off(oft or first)
            if thunk is not None:
                while True:
                    v = struct.unpack_from("<I", self.data, thunk)[0]
                    thunk += 4
                    if v == 0:
                        break
                    if v & 0x80000000:
                        names.append(b"#%d" % (v & 0xFFFF))
                    else:
                        n = self.cstr(self.off(v + 2))
                        names.append(n if n is not None else b"?")
            out.append((dll, names))
            p += 20
        return out

    def exports(self):
        if not self.dirs or not self.dirs[0][0]:
            return None, [], 0, 0
        p = self.off(self.dirs[0][0])
        if p is None:
            raise PeError("export directory RVA 0x%X is in no section"
                          % self.dirs[0][0])
        (_f, _stamp, _mj, _mn, namerva, ordbase, nfunc, nname,
         funcrva, namerva2, ordrva) = struct.unpack_from("<IIHHIIIIIII",
                                                         self.data, p)
        modname = self.cstr(self.off(namerva))
        funcs = self.off(funcrva)
        names = self.off(namerva2)
        ords = self.off(ordrva)
        out = []
        lo, hi = self.dirs[0][0], self.dirs[0][0] + self.dirs[0][1]
        for i in range(nname):
            nrva = struct.unpack_from("<I", self.data, names + i * 4)[0]
            o = struct.unpack_from("<H", self.data, ords + i * 2)[0]
            frva = struct.unpack_from("<I", self.data, funcs + o * 4)[0]
            fwd = None
            if lo <= frva < hi:
                fwd = self.cstr(self.off(frva))
            out.append((self.cstr(self.off(nrva)), o + ordbase, frva, fwd))
        return modname, out, nfunc, nname


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--imports", action="store_true")
    ap.add_argument("--exports", action="store_true")
    ap.add_argument("--grep")
    a = ap.parse_args()
    pe = PE(a.path)
    print("%s : PE%s, image base 0x%08X, %d sections"
          % (a.path, "32+" if pe.bits == 64 else "32", pe.imagebase,
             len(pe.sections)))
    for name, va, vsize, raw, rsize in pe.sections:
        print("   %-10s VA 0x%08X  vsize %8d  raw 0x%08X  rsize %8d"
              % (name.decode("latin-1"), va, vsize, raw, rsize))
    if a.imports:
        imps = pe.imports()
        tot = sum(len(n) for _d, n in imps)
        print()
        print("IMPORTS : %d DLLs, %d names" % (len(imps), tot))
        for dll, names in imps:
            print("   %-20s %d" % (dll.decode("latin-1"), len(names)))
            for n in names:
                if a.grep and a.grep.lower() not in n.decode("latin-1").lower():
                    continue
                print("      %s" % n.decode("latin-1"))
    if a.exports:
        mod, ex, nfunc, nname = pe.exports()
        print()
        print("EXPORTS : module name %r, %d functions, %d by name"
              % (mod.decode("latin-1") if mod else None, nfunc, nname))
        fwd = [e for e in ex if e[3]]
        print("   forwarded to another DLL : %d of %d named" % (len(fwd),
                                                                 len(ex)))
        for n, o, rva, f in ex:
            s = n.decode("latin-1")
            if a.grep and a.grep.lower() not in s.lower():
                continue
            if f:
                print("   %-24s @%-4d -> %s" % (s, o, f.decode("latin-1")))
            else:
                print("   %-24s @%-4d    RVA 0x%08X" % (s, o, rva))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PeError as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        sys.exit(2)
