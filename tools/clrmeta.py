#!/usr/bin/env python3
"""clrmeta.py -- say whether a PE is a managed assembly, and read its CLR
metadata root, its stream directory and its two string heaps.

This collection has never read managed metadata. `pecensus.py` can name a
PE32 and a PE32+ and has no column for *managed*, which on a .NET object is
the distinction that matters: an import table with one entry and one name is
not a bill of materials, it is a stub, and reporting it as though it were is
the defect this tool exists to fix.

What is read, and where it comes from -- ECMA-335 Partition II, a published
standard:

  * optional-header data directory 14 is the CLI header. Zero means native.
  * the CLI header's Metadata RVA points at a root whose first four bytes are
    `BSJB` and which carries a version string -- the runtime the assembly was
    built for.
  * the root's stream directory names `#~` (tables), `#Strings` (type, method
    and field names, UTF-8, NUL-separated), `#US` (the user string heap: every
    string literal in the code, UTF-16), `#GUID` and `#Blob`.

`#Strings` and `#US` are dumped verbatim on request. They are the reason a
managed assembly's `strings` output is not comparable with a native one's:
half the text is UTF-16 and an eight-bit sweep cannot see it.

    python tools/clrmeta.py academagia-steam --census
    python tools/clrmeta.py academagia-steam/Storage.dll --strings
    python tools/clrmeta.py academagia-steam/Storage.dll --userstrings
    python tools/clrmeta.py --selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                          # noqa: E402
import nameguard                                         # noqa: E402

# `--userstrings` prints every literal of the #US heap, and on
# pc-monstrum-doc the ninth one of Assembly-CSharp.dll carries characters
# outside cp1252: without this the tool died of UnicodeEncodeError when
# PYTHONIOENCODING was unset, and the pre-briefing had to set the variable
# to get the 3,015 literals out. The rule is to repair the tool, not the
# environment. One import, one call.
nameguard.guard()


class PeError(Exception):
    pass


class Pe(object):
    def __init__(self, data):
        self.d = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PeError("not an MZ image")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise PeError("no PE signature at e_lfanew")
        self.coff = e_lfanew + 4
        (self.machine, self.nsect, self.timestamp, _, _, self.opt_size,
         self.characteristics) = struct.unpack_from("<HHIIIHH", data, self.coff)
        opt = self.coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic == 0x10B:
            self.format = "PE32"
            dd = opt + 96
        elif magic == 0x20B:
            self.format = "PE32+"
            dd = opt + 112
        else:
            raise PeError("optional header magic %#06x" % magic)
        self.ndd = struct.unpack_from("<I", data, dd - 4)[0]
        self.dd = dd
        self.sections = []
        s = opt + self.opt_size
        for i in range(self.nsect):
            name, vsize, vaddr, rsize, raddr = struct.unpack_from(
                "<8sIIII", data, s + 40 * i)
            self.sections.append((name.rstrip(b"\0"), vaddr, vsize, raddr,
                                  rsize))

    def dir_entry(self, i):
        if i >= self.ndd:
            return 0, 0
        return struct.unpack_from("<II", self.d, self.dd + 8 * i)

    def rva_to_off(self, rva):
        for name, vaddr, vsize, raddr, rsize in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return raddr + (rva - vaddr)
        raise PeError("RVA %#x is in no section" % rva)


class Clr(object):
    def __init__(self, pe):
        rva, size = pe.dir_entry(14)
        self.managed = bool(rva and size)
        self.streams = []
        self.version = None
        self.flags = None
        self.entry = None
        if not self.managed:
            return
        d = pe.d
        off = pe.rva_to_off(rva)
        (cb, major, minor, md_rva, md_size, self.flags,
         self.entry) = struct.unpack_from("<IHHIIII", d, off)
        self.runtime = "%d.%d" % (major, minor)
        m = pe.rva_to_off(md_rva)
        if d[m:m + 4] != b"BSJB":
            raise PeError("CLI header points at %r, not BSJB" % d[m:m + 4])
        vlen = struct.unpack_from("<I", d, m + 12)[0]
        self.version = d[m + 16:m + 16 + vlen].rstrip(b"\0").decode("ascii")
        p = m + 16 + vlen + 2
        nstreams = struct.unpack_from("<H", d, p)[0]
        p += 2
        for _ in range(nstreams):
            soff, ssize = struct.unpack_from("<II", d, p)
            p += 8
            end = d.index(b"\0", p)
            name = d[p:end].decode("ascii")
            p = end + 1
            p = (p + 3) & ~3
            self.streams.append((name, m + soff, ssize))

    def stream(self, pe, name):
        for n, off, size in self.streams:
            if n == name:
                return pe.d[off:off + size]
        return None


def walk(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _, files in os.walk(root):
        for f in sorted(files):
            p = os.path.join(dirpath, f)
            try:
                with open(p, "rb") as fh:
                    if fh.read(2) != b"MZ":
                        continue
            except OSError:
                continue
            yield p


def census(root):
    rows = []
    for p in walk(root):
        with open(p, "rb") as f:
            data = f.read()
        try:
            pe = Pe(data)
        except PeError:
            continue
        try:
            clr = Clr(pe)
        except PeError as e:
            rows.append((p, len(data), "?", "PeError: %s" % e, {}))
            continue
        heaps = {}
        if clr.managed:
            for n, off, size in clr.streams:
                heaps[n] = size
        rows.append((p, len(data), pe.format, clr, heaps))
    managed = [r for r in rows if not isinstance(r[3], str) and r[3].managed]
    native = [r for r in rows if not isinstance(r[3], str) and not r[3].managed]
    print("binaries examined : %d" % len(rows))
    print("managed           : %d" % len(managed))
    print("native            : %d" % len(native))
    print()
    print("%-42s %10s %-6s %-8s %10s %10s" %
          ("file", "bytes", "format", "runtime", "#Strings", "#US"))
    base = root if os.path.isdir(root) else os.path.dirname(root)
    for p, size, fmt, clr, heaps in rows:
        rel = os.path.relpath(p, base)
        if isinstance(clr, str):
            print("%-42s %10d %-6s %s" % (rel, size, fmt, clr))
        elif clr.managed:
            print("%-42s %10d %-6s %-8s %10d %10d" %
                  (rel, size, fmt, clr.version, heaps.get("#Strings", 0),
                   heaps.get("#US", 0)))
        else:
            print("%-42s %10d %-6s %-8s %10s %10s" %
                  (rel, size, fmt, "native", "-", "-"))
    print()
    tot_s = sum(h.get("#Strings", 0) for _, _, _, c, h in rows
                if not isinstance(c, str) and c.managed)
    tot_u = sum(h.get("#US", 0) for _, _, _, c, h in rows
                if not isinstance(c, str) and c.managed)
    print("#Strings total : %d bytes of UTF-8 names" % tot_s)
    print("#US total      : %d bytes of UTF-16 string literals" % tot_u)
    vers = {}
    for _, _, _, c, _ in rows:
        if not isinstance(c, str) and c.managed:
            vers[c.version] = vers.get(c.version, 0) + 1
    print("runtime versions : %s" % dict(sorted(vers.items())))
    return 0


def dump_strings(path, us=False):
    dirguard.want_file(path, "clrmeta")
    with open(path, "rb") as f:
        data = f.read()
    pe = Pe(data)
    clr = Clr(pe)
    if not clr.managed:
        print("%s is not a managed assembly" % path)
        return 1
    if us:
        heap = clr.stream(pe, "#US")
        if heap is None:
            print("no #US heap")
            return 1
        # ECMA-335 II.24.2.4: each blob is a compressed length then UTF-16.
        p = 1
        out = []
        while p < len(heap):
            b = heap[p]
            if b & 0x80 == 0:
                n, p = b, p + 1
            elif b & 0xC0 == 0x80:
                n = ((b & 0x3F) << 8) | heap[p + 1]
                p += 2
            else:
                n = ((b & 0x1F) << 24) | (heap[p + 1] << 16) | \
                    (heap[p + 2] << 8) | heap[p + 3]
                p += 4
            if n == 0:
                continue
            blob = heap[p:p + n]
            p += n
            try:
                out.append(blob[:len(blob) - 1].decode("utf-16-le"))
            except UnicodeDecodeError:
                pass
        print("#US literals : %d" % len(out))
        for s in out:
            print(repr(s))
    else:
        heap = clr.stream(pe, "#Strings")
        names = [x for x in heap.split(b"\0") if x]
        print("#Strings entries : %d" % len(names))
        for x in names:
            print(x.decode("utf-8", "replace"))
    return 0


def selftest():
    ok = 0
    fail = []
    cases = [
        ("empty", b""),
        ("MZ only", b"MZ" + b"\0" * 0x3E),
        ("MZ with a bad e_lfanew", b"MZ" + b"\0" * 0x3A +
         struct.pack("<I", 0x7FFFFF) + b"\0" * 8),
        ("a PNG", b"\x89PNG\r\n\x1a\n" + b"\0" * 64),
        ("text", b"Monstrous Emanations" * 8),
    ]
    for name, blob in cases:
        try:
            Pe(blob)
            fail.append(name)
        except (PeError, struct.error, ValueError, IndexError):
            ok += 1
    # One specimen that must parse: a minimal PE32 built here.
    hdr = bytearray(0x200)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    hdr[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", hdr, 0x98, 0x10B)
    struct.pack_into("<I", hdr, 0x98 + 92, 16)
    struct.pack_into("<8sIIII", hdr, 0x98 + 0xE0, b".text", 0x1000, 0x1000,
                     0x200, 0x200)
    try:
        pe = Pe(bytes(hdr))
        assert pe.format == "PE32" and not Clr(pe).managed
        ok += 1
    except Exception as e:                                   # noqa: BLE001
        fail.append("minimal PE32: %s" % e)
    # The guard: stdout must be able to carry a literal outside the console
    # code page, which is what --userstrings prints. A guarded stream has a
    # UTF-8 encoding or, failing that, a non-strict error handler.
    enc = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "")
    if enc == "utf8" or getattr(sys.stdout, "errors", "strict") != "strict":
        ok += 1
    else:
        fail.append("stdout is not guarded: encoding %r, errors %r"
                    % (sys.stdout.encoding, sys.stdout.errors))
    print("selftest: %d of 7 specimens behaved as required "
          "(5 of the 6 blobs must be refused; stdout must be guarded)" % ok)
    for f in fail:
        print("  FAILED: %s" % f)
    return 0 if not fail else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--strings", action="store_true")
    ap.add_argument("--userstrings", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.path:
        ap.error("give a path or --selftest")
    if a.strings or a.userstrings:
        return dump_strings(a.path, us=a.userstrings)
    return census(a.path)


if __name__ == "__main__":
    sys.exit(main())
