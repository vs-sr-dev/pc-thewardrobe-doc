#!/usr/bin/env python3
"""deps.py - what a PE asks for, import by import, and whether it is there.

"The game does not run on a modern system" is a reputation.  The measurable
form of it is an import table: a list of libraries the loader must find before
a single instruction of the program runs, and a list of the names it must
resolve inside each.  This tool prints that list and then answers, for each
library, three questions that have to be kept apart:

  in the folder     is a file of that name next to the executable?
  a system DLL      is it one of the libraries Windows itself provides?
  in the manifest   does the publisher's own file list name it, anywhere,
                    including outside the install directory?

A library that is in none of the three is a hard dependency on something the
buyer has to have installed already, and the count of *functions* behind it is
how much of the program stops working without it.

The system-DLL list below is a judgement, not a measurement, so it is written
out in full and can be argued with.  Everything else is derived from the bytes.

    python tools/deps.py FILE [FILE ...] --root DIR [--ini MANIFEST]
    python tools/deps.py FILE --names
"""
import argparse
import os
import struct
import sys

SYSTEM = {
    "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "shell32.dll",
    "ole32.dll", "oleaut32.dll", "comctl32.dll", "comdlg32.dll", "shlwapi.dll",
    "winmm.dll", "wsock32.dll", "ws2_32.dll", "version.dll", "winspool.drv",
    "msvcrt.dll", "imm32.dll", "rpcrt4.dll", "gdiplus.dll", "oledlg.dll",
    "msimg32.dll", "setupapi.dll", "crypt32.dll", "userenv.dll", "psapi.dll",
    "dbghelp.dll", "wininet.dll", "iphlpapi.dll", "uxtheme.dll", "ntdll.dll",
    "d3d9.dll", "dinput8.dll", "dsound.dll", "xinput1_3.dll", "opengl32.dll",
}
# d3d9 / dinput8 / dsound ship with Windows; the versioned DirectX SDK
# libraries (d3dx9_NN, X3DAudio1_N, xactengine3_N, XAudio2_N) never did.


def rva_to_off(sections, rva):
    for va, vsz, raw, rsz in sections:
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    return None


def imports(path):
    d = open(path, "rb").read()
    if d[:2] != b"MZ":
        raise ValueError("not MZ")
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    if d[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("not PE")
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    magic = struct.unpack_from("<H", d, pe + 24)[0]
    ddoff = pe + 24 + (96 if magic == 0x10B else 112)
    imp_rva, imp_sz = struct.unpack_from("<II", d, ddoff + 8)
    secoff = pe + 24 + optsz
    sections = []
    for i in range(nsec):
        b = secoff + 40 * i
        vsz, va, rsz, raw = struct.unpack_from("<IIII", d, b + 8)
        sections.append((va, vsz, raw, rsz))
    out = []
    if not imp_rva:
        return out
    base = rva_to_off(sections, imp_rva)
    i = 0
    while True:
        e = base + 20 * i
        oft, ts, fc, namerva, firstthunk = struct.unpack_from("<IIIII", d, e)
        if not (oft or namerva or firstthunk):
            break
        no = rva_to_off(sections, namerva)
        name = d[no:d.index(b"\x00", no)].decode("latin-1")
        thunk = rva_to_off(sections, oft or firstthunk)
        # PE32 thunks are four bytes with the ordinal flag in bit 31; PE32+
        # thunks are EIGHT bytes with the ordinal flag in bit 63.  Reading a
        # 64-bit table four bytes at a time stops at the first zero high half,
        # which is after exactly one entry -- and reports no error.
        wide = (magic == 0x20B)
        step = 8 if wide else 4
        fmt = "<Q" if wide else "<I"
        ordflag = 0x8000000000000000 if wide else 0x80000000
        funcs = []
        j = 0
        while True:
            v = struct.unpack_from(fmt, d, thunk + step * j)[0]
            if v == 0:
                break
            if v & ordflag:
                funcs.append("#%d" % (v & 0xFFFF))
            else:
                fo = rva_to_off(sections, v & 0x7FFFFFFF)
                if fo is None:
                    break
                funcs.append(d[fo + 2:d.index(b"\x00", fo + 2)].decode("latin-1"))
            j += 1
        out.append((name, funcs))
        i += 1
    return out


def manifest_names(ini):
    names = set()
    if not ini or not os.path.exists(ini):
        return names
    for line in open(ini, "rb").read().decode("latin-1").splitlines():
        if "=" in line:
            v = line.split("=", 1)[1].strip()
            names.add(os.path.basename(v).lower())
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--root", default=None)
    ap.add_argument("--ini", default=None)
    ap.add_argument("--names", action="store_true")
    ap.add_argument("--syscheck", nargs="*", default=[],
                    help="directories to actually LOOK IN before saying a DLL "
                         "is absent. Two sessions running, `NOT PRESENT "
                         "ANYWHERE` has meant `not in my hard-coded list`; "
                         "with this flag it means what it says.")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    root = a.root or os.path.dirname(os.path.abspath(a.files[0]))
    present = set(n.lower() for n in os.listdir(root))
    ini = a.ini or os.path.join(root, "goggame-galaxyFileList.ini")
    declared = manifest_names(ini)

    for path in a.files:
        imp = imports(path)
        total = sum(len(f) for _n, f in imp)
        print("######## %s ########" % os.path.basename(path))
        print("%-22s %5s  %-9s %-9s %-11s %s"
              % ("imported DLL", "funcs", "in folder", "system", "in manifest", "verdict"))
        print("-" * 84)
        missing = []
        for name, funcs in imp:
            low = name.lower()
            inf = low in present
            sysd = low in SYSTEM
            man = low in declared
            if inf:
                v = "shipped here"
            elif sysd:
                v = "Windows supplies it"
            elif man:
                v = "GOG installs it elsewhere"
            else:
                found_in = [d for d in a.syscheck
                            if os.path.exists(os.path.join(d, name))]
                if found_in:
                    v = "on THIS machine, in %s" % ", ".join(
                        os.path.basename(x) for x in found_in)
                else:
                    v = "NOT PRESENT ANYWHERE"
                    missing.append((name, len(funcs)))
            print("%-22s %5d  %-9s %-9s %-11s %s"
                  % (name, len(funcs), "yes" if inf else "no",
                     "yes" if sysd else "no", "yes" if man else "no", v))
            if a.names:
                for f in funcs:
                    print("        %s" % f)
        print("-" * 84)
        print("DLLs %d   functions %d" % (len(imp), total))
        if missing:
            mf = sum(n for _x, n in missing)
            # two ratios, never one: a share of libraries and a share of
            # symbols are different numbers and only coincide when the symbol
            # count is wrong.
            print("absent, not system, not in the manifest :")
            print("    %d DLLs of %d       = %.2f %% of the libraries imported"
                  % (len(missing), len(imp), 100.0 * len(missing) / len(imp)))
            print("    %d functions of %d = %.2f %% of the symbols imported"
                  % (mf, total, 100.0 * mf / total))
            for n, c in missing:
                print("    %-22s %d functions" % (n, c))
        else:
            print("every imported DLL is accounted for")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
