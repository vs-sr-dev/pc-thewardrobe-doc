#!/usr/bin/env python3
"""ne.py -- read 16-bit New Executable files, because pe.py correctly refuses.

`dati/install/883d.exe` is 3,811,012 bytes, starts `MZ`, and at the offset its
DOS header points to has `NE` rather than `PE`. It is a 16-bit Windows binary
on a CD mastered in October 1999. `pe.py` stops with "no PE signature at
e_lfanew=128", which is the right thing for it to do and is also not an answer,
so this reads the other format.

The NE header (all offsets relative to the `NE` signature, all little-endian):

    0x00 WORD  magic 'NE'          0x02 BYTE  linker version
    0x03 BYTE  linker revision     0x04 WORD  entry table offset
    0x06 WORD  entry table length  0x08 DWORD CRC
    0x0C WORD  flags               0x0E WORD  auto data segment
    0x10 WORD  initial heap        0x12 WORD  initial stack
    0x14 DWORD CS:IP               0x18 DWORD SS:SP
    0x1C WORD  segment count       0x1E WORD  module ref count
    0x20 WORD  non-resident name table length
    0x22 WORD  segment table offset    0x24 WORD resource table offset
    0x26 WORD  resident name table offset
    0x28 WORD  module ref table offset 0x2A WORD imported names table offset
    0x2C DWORD non-resident name table FILE offset  (note: file, not relative)
    0x30 WORD  movable entry count 0x32 WORD  sector alignment shift
    0x34 WORD  resource segment count
    0x36 BYTE  target OS           0x37 BYTE  other flags
    0x3E WORD  expected Windows version

The two tables that answer "who made this":

  * the **resident name table**, whose first entry is the module name;
  * the **non-resident name table**, whose first entry is the module
    *description* -- a free-text string the linker takes from the .DEF file's
    DESCRIPTION line. Installer builders put their own product name there and
    almost never clear it.

Segment offsets in the segment table are in units of 1 << ne_align, which is
why a naive reader that treats them as bytes lands in the middle of nowhere.

    python tools/ne.py FILE
    python tools/ne.py FILE --segments
    python tools/ne.py FILE --resources
    python tools/ne.py FILE --entries
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                              # noqa: E402

TARGET_OS = {0: "unknown", 1: "OS/2", 2: "Windows", 3: "European MS-DOS 4.x",
             4: "Windows 386", 5: "BOSS"}

FLAG_BITS = [
    (0x0001, "SINGLEDATA"), (0x0002, "MULTIPLEDATA"), (0x0800, "SELFLOAD"),
    (0x1000, "LINKERROR"), (0x2000, "LIBMODULE_2"), (0x8000, "LIBMODULE"),
]

SEG_FLAGS = [
    (0x0001, "DATA"), (0x0002, "ALLOCATED"), (0x0004, "LOADED"),
    (0x0010, "MOVEABLE"), (0x0020, "SHAREABLE"), (0x0040, "PRELOAD"),
    (0x0080, "EXECUTEONLY/READONLY"), (0x0100, "RELOCINFO"),
    (0x0200, "CONFORMING"), (0x1000, "DISCARDABLE"),
]

RT_NAMES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
            6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
            10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
            14: "GROUP_ICON", 16: "VERSIONINFO"}


def bits(v, table):
    out = [n for b, n in table if v & b]
    return "|".join(out) if out else "(none)"


class NE(object):
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        d = self.data
        if d[0:2] not in (b"MZ", b"ZM"):
            raise ValueError("no MZ magic: %r" % d[0:2])
        self.e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if d[self.e_lfanew:self.e_lfanew + 2] != b"NE":
            raise ValueError("no NE signature at e_lfanew=%d (found %r)"
                             % (self.e_lfanew, d[self.e_lfanew:self.e_lfanew + 2]))
        h = self.e_lfanew
        self.h = h
        (self.ver, self.rev) = d[h + 2], d[h + 3]
        self.enttab = struct.unpack_from("<H", d, h + 0x04)[0]
        self.cbenttab = struct.unpack_from("<H", d, h + 0x06)[0]
        self.crc = struct.unpack_from("<I", d, h + 0x08)[0]
        self.flags = struct.unpack_from("<H", d, h + 0x0C)[0]
        self.autodata = struct.unpack_from("<H", d, h + 0x0E)[0]
        self.heap = struct.unpack_from("<H", d, h + 0x10)[0]
        self.stack = struct.unpack_from("<H", d, h + 0x12)[0]
        self.csip = struct.unpack_from("<I", d, h + 0x14)[0]
        self.sssp = struct.unpack_from("<I", d, h + 0x18)[0]
        self.cseg = struct.unpack_from("<H", d, h + 0x1C)[0]
        self.cmod = struct.unpack_from("<H", d, h + 0x1E)[0]
        self.cbnrestab = struct.unpack_from("<H", d, h + 0x20)[0]
        self.segtab = struct.unpack_from("<H", d, h + 0x22)[0]
        self.rsrctab = struct.unpack_from("<H", d, h + 0x24)[0]
        self.restab = struct.unpack_from("<H", d, h + 0x26)[0]
        self.modtab = struct.unpack_from("<H", d, h + 0x28)[0]
        self.imptab = struct.unpack_from("<H", d, h + 0x2A)[0]
        self.nrestab = struct.unpack_from("<I", d, h + 0x2C)[0]
        self.cmovent = struct.unpack_from("<H", d, h + 0x30)[0]
        self.align = struct.unpack_from("<H", d, h + 0x32)[0]
        self.cres = struct.unpack_from("<H", d, h + 0x34)[0]
        self.exetyp = d[h + 0x36]
        self.otherflags = d[h + 0x37]
        self.expver = struct.unpack_from("<H", d, h + 0x3E)[0]

    # ---- name tables ------------------------------------------------------

    def _name_table(self, off, limit):
        """Length-prefixed name entries, each followed by a WORD ordinal."""
        out = []
        p = off
        end = min(off + limit, len(self.data)) if limit else len(self.data)
        while p < end:
            n = self.data[p]
            if n == 0:
                break
            name = self.data[p + 1:p + 1 + n]
            ordv = struct.unpack_from("<H", self.data, p + 1 + n)[0] \
                if p + 3 + n <= len(self.data) else 0
            out.append((name, ordv))
            p += 1 + n + 2
        return out

    def resident_names(self):
        return self._name_table(self.h + self.restab, 0)

    def nonresident_names(self):
        return self._name_table(self.nrestab, self.cbnrestab)

    def module_refs(self):
        """Module reference table -> names in the imported-names table."""
        out = []
        for i in range(self.cmod):
            off = struct.unpack_from("<H", self.data, self.h + self.modtab + 2 * i)[0]
            p = self.h + self.imptab + off
            n = self.data[p]
            out.append(self.data[p + 1:p + 1 + n])
        return out

    def segments(self):
        out = []
        shift = self.align or 9
        for i in range(self.cseg):
            e = self.h + self.segtab + 8 * i
            sect, length, flags, minalloc = struct.unpack_from("<HHHH", self.data, e)
            out.append({
                "n": i + 1,
                "sector": sect,
                "file_off": sect << shift,
                "length": length if length else 65536,
                "raw_length": length,
                "flags": flags,
                "minalloc": minalloc,
            })
        return out

    def resources(self):
        """Resource table: type blocks, each with name-info entries."""
        if not self.rsrctab or self.rsrctab == self.restab:
            return None, []
        base = self.h + self.rsrctab
        shift = struct.unpack_from("<H", self.data, base)[0]
        p = base + 2
        types = []
        while p + 8 <= len(self.data):
            tid = struct.unpack_from("<H", self.data, p)[0]
            if tid == 0:
                break
            count = struct.unpack_from("<H", self.data, p + 2)[0]
            p += 8
            entries = []
            for _ in range(count):
                off, length, flags, rid = struct.unpack_from("<HHHH", self.data, p)
                entries.append({"off": off << shift, "len": length << shift,
                                "flags": flags, "id": rid,
                                "name": self.rsrc_name(rid)})
                p += 12
            types.append({"tid": tid, "entries": entries,
                          "name": self.rsrc_name(tid)})
        return shift, types

    def imports(self):
        """Imports by name and by ordinal, out of the per-segment relocation
        records -- which is where a Win16 binary's capability list actually
        lives. The module reference table names the DLLs; only the relocations
        name the *functions*, and the platform notes' promise that "a VIS disc
        gives up its imports for free" is about these.

        A relocation record is 8 bytes: source type, flags, offset within the
        segment, then two words whose meaning depends on flags & 3 --
        0 INTERNALREF, 1 IMPORTORDINAL (module index, ordinal),
        2 IMPORTNAME (module index, offset into the imported-names table),
        3 OSFIXUP. Records live after the segment data when the segment's
        RELOCINFO flag is set."""
        mods = [m.decode("latin-1") for m in self.module_refs()]
        out = []
        for s in self.segments():
            if not (s["flags"] & 0x0100):
                continue
            p = s["file_off"] + s["raw_length"]
            if p + 2 > len(self.data):
                continue
            n = struct.unpack_from("<H", self.data, p)[0]
            p += 2
            for _ in range(n):
                if p + 8 > len(self.data):
                    break
                styp, flags, off, a1, a2 = struct.unpack_from("<BBHHH",
                                                              self.data, p)
                p += 8
                kind = flags & 3
                if kind == 1 and 1 <= a1 <= len(mods):
                    out.append((s["n"], mods[a1 - 1], "@%d" % a2, off))
                elif kind == 2 and 1 <= a1 <= len(mods):
                    q = self.h + self.imptab + a2
                    ln = self.data[q] if q < len(self.data) else 0
                    nm = self.data[q + 1:q + 1 + ln].decode("latin-1")
                    out.append((s["n"], mods[a1 - 1], nm, off))
        return out

    def rsrc_name(self, v):
        """A type or name id with the high bit clear is an OFFSET, from the
        resource table base, to a length-prefixed string. With the high bit
        set it is an integer. Returning the string is the difference between
        printing `0x02F4` and printing `WAVE`."""
        if v & 0x8000:
            return None
        off = self.h + self.rsrctab + (v & 0x7FFF)
        if off >= len(self.data):
            return None
        n = self.data[off]
        if not n or off + 1 + n > len(self.data):
            return None
        return self.data[off + 1:off + 1 + n].decode("latin-1")

    def string_tables(self):
        """RT_STRING (type 6). Each resource is a block of exactly sixteen
        length-prefixed strings; the block's id is 1-based, so the string id
        of entry i in block b is (b - 1) * 16 + i. Empty entries are a length
        byte of zero and are skipped, which is why a block of 512 bytes can
        hold five strings."""
        shift, types = self.resources()
        out = []
        for t in types or []:
            if t["tid"] != (6 | 0x8000):
                continue
            for e in t["entries"]:
                blk = self.data[e["off"]:e["off"] + e["len"]]
                p = 0
                for i in range(16):
                    if p >= len(blk):
                        break
                    n = blk[p]
                    s = blk[p + 1:p + 1 + n]
                    if n:
                        out.append(((e["id"] & 0x7FFF) - 1) * 16 + i)
                        out[-1] = (out[-1], s.decode("latin-1"),
                                   e["id"] & 0x7FFF, i, e["off"] + p)
                    p += 1 + n
        return out

    def validate(self):
        """Quantities this format states twice, or states and can be checked
        against. Every row is one a wrong layout can fail."""
        rows = []
        segs = self.segments()
        # NOT "len(segments()) == ne_cseg": that walks ne_cseg entries and then
        # counts them, so it cannot fail. The checkable version is that the
        # table ne_cseg implies ends where the next table begins.
        seg_end = self.segtab + 8 * self.cseg
        nxt = min(x for x in (self.rsrctab, self.restab, self.modtab,
                              self.imptab, self.enttab) if x > self.segtab)
        rows.append(("segment table of ne_cseg entries ends at or before "
                     "the next table",
                     seg_end <= nxt,
                     "segtab 0x%X + 8*%d = 0x%X, next table at 0x%X"
                     % (self.segtab, self.cseg, seg_end, nxt)))
        inb = all(s["file_off"] + s["raw_length"] <= len(self.data) for s in segs)
        rows.append(("every segment lies inside the file", inb,
                     "%d segments, file is %d bytes" % (len(segs), len(self.data))))
        mods = self.module_refs()
        rows.append(("module ref table entry count == ne_cmod",
                     len(mods) == self.cmod, "%d == %d" % (len(mods), self.cmod)))
        rows.append(("every imported module name is printable ASCII",
                     all(m and all(32 <= c < 127 for c in m) for m in mods),
                     " ".join(m.decode("latin-1") for m in mods)))
        shift, types = self.resources()
        ents = [e for t in (types or []) for e in t["entries"]]
        rows.append(("every resource lies inside the file",
                     all(e["off"] + e["len"] <= len(self.data) for e in ents),
                     "%d resources" % len(ents)))
        rows.append(("resource count == ne_cres, or ne_cres is 0",
                     self.cres in (0, len(ents)),
                     "ne_cres=%d, walked %d" % (self.cres, len(ents))))
        last = max([s["file_off"] + s["raw_length"] for s in segs] or [0])
        first_res = min([e["off"] for e in ents] or [len(self.data)])
        rows.append(("the resource tail begins after the last segment",
                     first_res >= last,
                     "last segment ends %d, first resource at %d" % (last, first_res)))
        e_lfarlc = struct.unpack_from("<H", self.data, 0x18)[0]
        rows.append(("e_lfarlc >= 0x40, so e_lfanew is a real field",
                     e_lfarlc >= 0x40, "e_lfarlc = 0x%X" % e_lfarlc))
        return rows


def describe(ne, show_segments=False, show_resources=False, show_entries=False):
    print("file            : %s" % ne.path)
    print("size            : %d bytes" % len(ne.data))
    print("e_lfanew        : 0x%X" % ne.e_lfanew)
    print("format          : NE (16-bit New Executable)")
    print("linker version  : %d.%02d" % (ne.ver, ne.rev))
    print("target OS       : %d %s" % (ne.exetyp, TARGET_OS.get(ne.exetyp, "?")))
    print("expected Windows: %d.%d" % (ne.expver >> 8, ne.expver & 0xFF))
    print("flags           : 0x%04X  %s" % (ne.flags, bits(ne.flags, FLAG_BITS)))
    print("segments        : %d   module refs: %d   movable entries: %d"
          % (ne.cseg, ne.cmod, ne.cmovent))
    print("segment align   : 1 << %d = %d bytes" % (ne.align, 1 << ne.align))
    print("auto data seg   : %d   heap %d   stack %d"
          % (ne.autodata, ne.heap, ne.stack))
    print("entry CS:IP     : %04X:%04X" % (ne.csip >> 16, ne.csip & 0xFFFF))
    print("initial SS:SP   : %04X:%04X" % (ne.sssp >> 16, ne.sssp & 0xFFFF))
    print("header CRC      : 0x%08X" % ne.crc)

    res = ne.resident_names()
    print()
    print("resident name table (first entry is the module name): %d entries" % len(res))
    for name, ordv in res:
        print("    ord %-5d %s" % (ordv, name.decode("latin-1")))

    nres = ne.nonresident_names()
    print()
    print("non-resident name table (first entry is the module DESCRIPTION): %d entries"
          % len(nres))
    for name, ordv in nres:
        print("    ord %-5d %s" % (ordv, name.decode("latin-1")))

    mods = ne.module_refs()
    print()
    print("imported modules: %d" % len(mods))
    for m in mods:
        print("    %s" % m.decode("latin-1"))

    segs = ne.segments()
    total = sum(s["length"] for s in segs)
    print()
    print("segment table   : %d segments, %d bytes of code/data total"
          % (len(segs), total))
    print("                  that is %.4f %% of the file"
          % (100.0 * total / len(ne.data)))
    if show_segments or True:
        print("%-4s %8s %10s %8s %s" % ("#", "sector", "file off", "length", "flags"))
        for s in segs:
            print("%-4d %8d %10d %8d 0x%04X %s"
                  % (s["n"], s["sector"], s["file_off"], s["length"],
                     s["flags"], bits(s["flags"], SEG_FLAGS)))
        last = max((s["file_off"] + s["length"]) for s in segs) if segs else 0
        print()
        print("last segment ends at byte %d; the file is %d bytes."
              % (last, len(ne.data)))
        print("bytes after the last segment: %d  (%.4f %% of the file)"
              % (len(ne.data) - last, 100.0 * (len(ne.data) - last) / len(ne.data)))

    shift, types = ne.resources()
    print()
    if types is None or not types:
        print("resource table  : empty or absent")
    else:
        print("resource table  : alignment shift %d (%d bytes), %d type blocks"
              % (shift, 1 << shift, len(types)))
        for t in types:
            nm = RT_NAMES.get(t["tid"] & 0x7FFF, "0x%04X" % t["tid"]) \
                if t["tid"] & 0x8000 else (t["name"] or "0x%04X" % t["tid"])
            print("    type %-14s %d entries" % (nm, len(t["entries"])))
            for e in t["entries"]:
                print("        id %-6s offset %-10d length %d"
                      % (e["name"] or (e["id"] & 0x7FFF), e["off"], e["len"]))

    if show_entries:
        print()
        print("entry table     : offset 0x%X, %d bytes" % (ne.enttab, ne.cbenttab))
        print("    %s" % ne.data[ne.h + ne.enttab:
                                 ne.h + ne.enttab + ne.cbenttab].hex(" "))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--segments", action="store_true")
    ap.add_argument("--resources", action="store_true")
    ap.add_argument("--entries", action="store_true")
    ap.add_argument("--imports", action="store_true",
                    help="imports by name and ordinal, from the relocations")
    ap.add_argument("--strings", action="store_true",
                    help="decode every RT_STRING block")
    ap.add_argument("--dump", metavar="DIR",
                    help="write every resource to DIR as TYPE-ID.bin")
    ap.add_argument("--validate", action="store_true",
                    help="check the quantities this format states twice")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass
    # Recorded as correction 27 on pc-rpgmaker2003-doc, AFTER publication, and
    # found again in jpeg.py on the next object: handed a directory this
    # reader raised an uncaught PermissionError instead of refusing. Two
    # instances make a class and the class gets one guard.
    dirguard.want_file(args.file, "ne")
    try:
        ne = NE(args.file)
    except ValueError as exc:
        print("%s: %s" % (args.file, exc))
        return 1

    if args.validate:
        rows = ne.validate()
        print("validate: %s" % args.file)
        bad = 0
        for name, ok, detail in rows:
            print("  %-50s %-4s  %s" % (name, "ok" if ok else "FAIL", detail))
            bad += not ok
        print("  %d of %d checks pass" % (len(rows) - bad, len(rows)))
        return 1 if bad else 0

    if args.imports:
        rows = ne.imports()
        mods = {}
        for seg, mod, nm, off in rows:
            mods.setdefault(mod, {}).setdefault(nm, []).append((seg, off))
        print("imports, from %d relocation records across the segments"
              % len(rows))
        for mod in sorted(mods):
            names = mods[mod]
            print("  %-10s %3d distinct entries, %3d fixups"
                  % (mod, len(names), sum(len(v) for v in names.values())))
            for nm in sorted(names, key=lambda s: (s.startswith("@"), s)):
                print("      %-24s x%d" % (nm, len(names[nm])))
        return 0

    if args.strings:
        rows = ne.string_tables()
        print("RT_STRING: %d non-empty strings in this file" % len(rows))
        for sid, s, blk, i, off in rows:
            print("  %6d  block %-5d slot %-3d file offset %-8d %r"
                  % (sid, blk, i, off, s))
        return 0

    if args.dump:
        import os
        os.makedirs(args.dump, exist_ok=True)
        shift, types = ne.resources()
        n = 0
        for t in types or []:
            tn = RT_NAMES.get(t["tid"] & 0x7FFF, "T%04X" % t["tid"]) \
                if t["tid"] & 0x8000 else (t["name"] or "T%04X" % t["tid"])
            for e in t["entries"]:
                en = e["name"] or str(e["id"] & 0x7FFF)
                out = os.path.join(args.dump, "%s-%s.bin" % (tn, en))
                with open(out, "wb") as fh:
                    fh.write(ne.data[e["off"]:e["off"] + e["len"]])
                n += 1
        print("dumped %d resources from %d type blocks to %s"
              % (n, len(types or []), args.dump))
        return 0

    describe(ne, args.segments, args.resources, args.entries)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
