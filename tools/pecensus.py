#!/usr/bin/env python3
"""pecensus.py -- one line per binary across a whole tree.

`pe.py` prints everything about one file, which is what you want when there is
one file. This tree has eighteen `.exe`, three `.x32` and one 16-bit `NE`, and
the question is not "what is in this binary" but "how do these binaries relate
to each other" -- which linker, which timestamp, whose company name, and do the
timestamps cluster into build days.

It reuses `pe.py`'s parser rather than reimplementing it, falls back to `ne.py`
for 16-bit files, and prints the COFF timestamp beside the filesystem mtime so
the two clocks can be read on one line.

    python tools/pecensus.py DIR
    python tools/pecensus.py DIR --ext .exe .dll .x32
    python tools/pecensus.py DIR --sort coff
"""
import argparse
import datetime
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pe as pemod            # noqa: E402
import ne as nemod            # noqa: E402
import redact as _redact      # noqa: E402


def version_field(vi, key):
    """Pull one VS_VERSIONINFO string out of pe.py's harvested run list.

    pe.py returns the version block as a flat list of printable UTF-16 runs, in
    file order, so a value is simply the run after its key. Two things make a
    naive lookup wrong and are handled here:

      * the block is emitted twice, once per language sub-block (040904b0 and
        040904E4 on the Macromedia binaries), so the same key appears more than
        once. The first non-empty value wins;
      * padding between a key and its value sometimes produces a short junk run
        (Director's blocks contain runs like "r'"), so a candidate that is
        itself a known key name is skipped.
    """
    if not vi:
        return ""
    strings = vi.get("strings") or []
    KEYS = set(["CompanyName", "FileDescription", "FileVersion", "InternalName",
                "LegalCopyright", "LegalTrademarks", "OriginalFilename",
                "ProductName", "ProductVersion", "Comments", "VarFileInfo",
                "Translation", "StringFileInfo", "VS_VERSION_INFO"])
    for i, s in enumerate(strings):
        if s != key:
            continue
        for j in range(i + 1, min(i + 4, len(strings))):
            cand = strings[j]
            if cand in KEYS or len(cand) < 2:
                continue
            # Redacted by program, on pc-rpgmakerxp-doc, where `SciLexer.dll`
            # put a private individual's e-mail address in `CompanyName` and
            # this tool printed it into a committed note. See the same guard
            # and the same reasoning in `verres.py`.
            out, _n = _redact.redact(cand.encode("utf-8", "surrogatepass"))
            return out.decode("utf-8", "replace")
    return ""


def signature_size(p):
    """Bytes in the PE security data directory -- i.e. is it Authenticode signed?

    Directory index 4 is IMAGE_DIRECTORY_ENTRY_SECURITY. Unlike every other
    data directory its first field is a FILE OFFSET rather than an RVA, which
    does not matter here because only the size is read: a size of zero means no
    certificate table, and any non-zero size means there is one.

    This exists because the chapter that needed it asserted "nothing on this
    disc is signed" before checking, and three files are.
    """
    d = p.data
    # `pe.py` calls this field `pe_off`. This line said `p.e_lfanew`, which is
    # the name the field has in the Windows header and the name it does not
    # have here, so `signature_size` raised AttributeError on every PE it was
    # ever given and the census printed `n/a` for all of them. Diagnosed on
    # pc-twinsensquest-doc (docs/15), carried unrepaired for two sessions,
    # repaired here -- see docs/13. One line, four symptoms.
    oh = p.pe_off + 24
    # FOURTH DEFECT, repaired on pc-themurderofsonicthehedgehog-doc, and it is
    # the same arithmetic as authenticode.py's: 92 and 96 are the PE32
    # offsets of NumberOfRvaAndSizes and the first data directory. A PE32+
    # optional header puts them at 108 and 112. Reading the PE32 offsets out
    # of a PE32+ header lands in the middle of SizeOfHeapReserve and returns
    # rubbish, and on this object it returned zero for all six 64-bit
    # binaries: the tool said 67 files carry a certificate table where a
    # bounds-checked second parse said 71. Four of the six ARE signed.
    try:
        magic = struct.unpack_from("<H", d, oh)[0]
        if magic == 0x20b:
            nd_off, dd_off = oh + 108, oh + 112
        elif magic == 0x10b:
            nd_off, dd_off = oh + 92, oh + 96
        else:
            return 0
        ndirs = struct.unpack_from("<I", d, nd_off)[0]
        if ndirs < 5:
            return 0
        off, size = struct.unpack_from("<II", d, dd_off + 4 * 8)
        # A size with no offset, or a table that runs past the end of the
        # file, is not a signature; it is a misread. Say zero rather than a
        # number, which is what crashed authenticode.py on this object.
        if not off or not size or off + size > len(d):
            return 0
        return size
    except Exception:
        return 0


def stamp_kind(managed, timestamp, coff, mtime):
    """'date' or 'hash'. REPAIRED ON pc-thewardrobe-doc, where this census
    said `impossible mtimes : 136 of 161` and a COFF range to 2104-12-01.
    The arithmetic was right and the label wrong: a managed assembly built
    deterministically carries, in the COFF timestamp field, a hash of the
    build with bit 31 set (Roslyn's `/deterministic`, the default since C# 7
    tooling), so the field reads as a date past 2038-01-19 03:14:07 UTC and
    is not a date at all. A managed PE whose stamp has bit 31 set, or lies
    after the file's own mtime, is a HASH and is counted apart from the
    datable ones; a native PE keeps the old rule (a stamp after the mtime is
    an impossible mtime, and is reported). Controls both ways in --selftest.
    """
    if not managed:
        return 'date'
    if timestamp & 0x80000000:
        return 'hash'
    if coff is not None and mtime is not None and coff > mtime:
        return 'hash'
    return 'date'


def selftest():
    import datetime as _dt
    t0 = _dt.datetime(2026, 6, 5, 17, 2, 28)
    checks = [
        ('a native PE with a 2026 stamp before its mtime is a date',
         stamp_kind(False, 0x69789A60, _dt.datetime(2026, 1, 27, 10, 58, 40), t0) == 'date'),
        ('a managed PE with bit 31 set (2048-04-01) is a hash',
         stamp_kind(True, 0x93265E19, _dt.datetime(2048, 4, 1, 3, 58, 17), t0) == 'hash'),
        ('a managed PE with bit 31 clear and a 2021 stamp is a date (SonyNP, csc 11)',
         stamp_kind(True, 0x61002B8F, _dt.datetime(2021, 7, 27, 14, 43, 43), t0) == 'date'),
        ('a managed PE with bit 31 clear but a stamp after its mtime is a hash',
         stamp_kind(True, 0x70000000, _dt.datetime(2029, 8, 1), t0) == 'hash'),
        ('a NATIVE PE with bit 31 set is still a date (and will be reported as impossible)',
         stamp_kind(False, 0x93265E19, _dt.datetime(2048, 4, 1), t0) == 'date'),
    ]
    bad = 0
    for label, ok in checks:
        print('  %-82s %s' % (label, 'ok' if ok else 'FAIL'))
        bad += not ok
    print()
    print('%d checks, %d failures' % (len(checks), bad))
    return 1 if bad else 0


def classify_non_pe(path):
    """Why this MZ is not a PE, read out of the bytes rather than a message.

    Added when the fifth defect was found: a file that is an `MZ` but not a
    `PE` used to have its own path printed in the CompanyName column, because
    the note was built by splitting an exception message on a colon. This says
    what the file actually is, which on a DOS object is the interesting half.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(0x40)
    except OSError as exc:
        return "unreadable (%s)" % exc.__class__.__name__
    if len(head) < 0x40 or head[:2] not in (b"MZ", b"ZM"):
        return "not an MZ"
    lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if lfanew == 0 or lfanew >= os.path.getsize(path):
        return "real-mode MZ, no extended header"
    try:
        with open(path, "rb") as fh:
            fh.seek(lfanew)
            sig = fh.read(4)
    except OSError:
        return "real-mode MZ"
    for name in (b"LE", b"LX", b"NE", b"PE"):
        if sig[:2] == name:
            return "MZ + %s at 0x%X" % (name.decode(), lfanew)
    return "real-mode MZ, e_lfanew is data"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--ext", nargs="*",
                    default=[".exe", ".dll", ".x32", ".ocx", ".cpl", ".sys"])
    ap.add_argument("--sort", choices=["path", "coff", "mtime", "size"],
                    default="path")
    ap.add_argument("--by-magic", action="store_true",
                    help="census every file that begins with MZ, whatever it "
                         "is called. Broken Sword 4 ships three PE files named "
                         "`.asi`, and an extension filter loses all three.")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

    exts = tuple(e.lower() for e in args.ext)
    rows = []
    for dp, dn, fn in os.walk(args.dir):
        dn.sort()
        for f in sorted(fn):
            full = os.path.join(dp, f)
            if args.by_magic:
                try:
                    with open(full, "rb") as probe:
                        if probe.read(2) != b"MZ":
                            continue
                except OSError:
                    continue
            elif not f.lower().endswith(exts):
                continue
            rel = os.path.relpath(full, args.dir).replace(os.sep, "/")
            st = os.stat(full)
            mt = datetime.datetime.fromtimestamp(st.st_mtime)
            row = {"rel": rel, "size": st.st_size, "mtime": mt,
                   "fmt": "?", "coff": None, "linker": "", "company": "",
                   "managed": False,
                   "product": "", "fileversion": "", "note": "", "signed": None}
            try:
                p = pemod.PE(full)
                # `"PE"` for everything that is not x86 was the third
                # wrong thing in this block, and it stayed invisible for
                # fifteen objects because every one of them was 32-bit.
                # pc-karmaflow-doc is the collection's first 64-bit object
                # and 53 of its 59 binaries came out as a bare `PE`. The
                # name a PE file gives itself is in the optional header's
                # magic word, not in the machine field: 0x10B is PE32 and
                # 0x20B is PE32+.
                _mach = getattr(p, "machine", 0)
                try:
                    _magic = struct.unpack_from("<H", p.data, p.pe_off + 24)[0]
                except Exception:
                    _magic = 0
                row["fmt"] = {0x10B: "PE32", 0x20B: "PE32+"}.get(_magic, "PE?")
                row["machine"] = {0x14C: "i386", 0x8664: "amd64",
                                  0x1C0: "arm", 0x200: "ia64"}.get(
                                      _mach, "0x%X" % _mach)
                row["signed"] = signature_size(p) > 0
                row["coff"] = datetime.datetime(1970, 1, 1) + \
                    datetime.timedelta(seconds=p.timestamp)
                # Second wrong attribute name, found here after the first was
                # repaired: `pe.py` has no `linker`. MajorLinkerVersion and
                # MinorLinkerVersion are bytes 2 and 3 of the optional header,
                # which begins at pe_off + 24. The inherited diagnosis said
                # "one wrong attribute name, four symptoms"; it was two, and
                # the second was invisible because the first raised first.
                row["linker"] = "%d.%02d" % (p.data[p.pe_off + 26],
                                             p.data[p.pe_off + 27])
                # Repaired on pc-academagia-doc, the collection's first .NET
                # object: 17 of its 26 binaries are managed assemblies and the
                # census had no column that could say so. Managed is not a
                # guess from a string search -- optional-header data directory
                # 14 is the CLI header, and it is zero on a native image. The
                # same repair fixes the neighbouring lie: `linker 48.00` on a
                # managed assembly is the C# compiler's marker, not a linker
                # version, and the column now says so instead of implying a
                # 48th generation of link.exe.
                _ddoff = p.pe_off + 24 + (112 if _magic == 0x20B else 96)
                try:
                    _nd = struct.unpack_from("<I", p.data, _ddoff - 4)[0]
                    _clr = struct.unpack_from("<II", p.data, _ddoff + 8 * 14)                         if _nd > 14 else (0, 0)
                except Exception:
                    _clr = (0, 0)
                row["managed"] = bool(_clr[0] and _clr[1])
                if row["managed"]:
                    row["linker"] = "csc " + row["linker"]
                row["stamp"] = stamp_kind(row["managed"], p.timestamp,
                                          row["coff"], row["mtime"])
                vi = p.versioninfo()
                row["company"] = version_field(vi, "CompanyName")
                row["product"] = version_field(vi, "ProductName")
                row["fileversion"] = version_field(vi, "FileVersion")
            except Exception as exc:
                try:
                    n = nemod.NE(full)
                    row["fmt"] = "NE16"
                    row["linker"] = "%d.%02d" % (n.ver, n.rev)
                    res = n.resident_names()
                    nres = n.nonresident_names()
                    row["product"] = res[0][0].decode("latin-1") if res else ""
                    row["company"] = nres[0][0].decode("latin-1") if nres else ""
                    row["note"] = "16-bit"
                except Exception as exc2:
                    row["fmt"] = "n/a"
                    # FIFTH DEFECT, repaired here. The line used to read
                    #     row["note"] = str(exc).split(":")[0][:40]
                    # which assumes the exception message is "reason: detail".
                    # `pe.py` raises "<path> is not a PE", and a RELATIVE path
                    # has no colon, so the split returned the whole path -- and
                    # the row printer prints `company or note` in the
                    # **CompanyName** column. Every non-PE MZ therefore
                    # appeared to declare its own file path as its company.
                    # The repair does not parse a message at all: it reads the
                    # two bytes that decide the question.
                    row["note"] = classify_non_pe(full)
            rows.append(row)

    keys = {"path": lambda r: r["rel"],
            "coff": lambda r: (r["coff"] or datetime.datetime(1970, 1, 1)),
            "mtime": lambda r: r["mtime"],
            "size": lambda r: -r["size"]}
    rows.sort(key=keys[args.sort])

    print("%-46s %6s %8s %10s %10s %-19s %-19s %s"
          % ("path", "fmt", "kind", "bytes", "linker", "COFF (UTC)",
             "mtime (local)", "CompanyName / module"))
    print("-" * 46 + " " + "-" * 6 + " " + "-" * 8 + " " + "-" * 10 + " "
          + "-" * 10 + " " + "-" * 19 + " " + "-" * 19 + " " + "-" * 30)
    for r in rows:
        print("%-46s %6s %8s %10d %10s %-19s %-19s %s"
              % (r["rel"][-46:], r["fmt"],
                 "managed" if r.get("managed") else "native",
                 r["size"], r["linker"],
                 ("hash 0x%08X" % int((r["coff"] - datetime.datetime(1970, 1, 1)).total_seconds())
                  if r.get("stamp") == "hash" else
                  r["coff"].strftime("%Y-%m-%d %H:%M:%S")) if r["coff"] else "-",
                 r["mtime"].strftime("%Y-%m-%d %H:%M:%S"),
                 (r["company"] or ("-- " + r["note"] if r["note"] else ""))[:34]))

    print()
    print("=== files whose mtime PRECEDES their own COFF link timestamp ===")
    print("(a file cannot be written before it is linked; where this happens")
    print(" the mtime is synthetic, or the two clocks are in different zones)")
    print()
    bad = []
    hashes = [r for r in rows if r.get("stamp") == "hash"]
    for r in rows:
        if not r["coff"] or r.get("stamp") == "hash":
            continue
        delta = (r["mtime"] - r["coff"]).total_seconds()
        if delta < 0:
            bad.append((r, delta))
    if not bad:
        print("    none")
    else:
        print("%-46s %-19s %-19s %s"
              % ("path", "COFF (UTC)", "mtime (local)", "mtime - COFF"))
        for r, delta in bad:
            h = delta / 3600.0
            print("%-46s %-19s %-19s %10.0f s = %+.2f h"
                  % (r["rel"][-46:],
                     r["coff"].strftime("%Y-%m-%d %H:%M:%S"),
                     r["mtime"].strftime("%Y-%m-%d %H:%M:%S"), delta, h))
    print()
    print("impossible mtimes : %d of %d datable binaries"
          % (len(bad), sum(1 for r in rows if r["coff"] and r.get("stamp") != "hash")))
    print("deterministic (hash) stamps, not dates, counted apart : %d of %d managed"
          % (len(hashes), sum(1 for r in rows if r.get("managed"))))
    print("  (a managed PE whose COFF field has bit 31 set, or lies after its")
    print("   own mtime, carries Roslyn's build hash; repaired on pc-thewardrobe-doc)")

    print()
    print("binaries        : %d" % len(rows))
    fmts = {}
    for r in rows:
        fmts[r["fmt"]] = fmts.get(r["fmt"], 0) + 1
    print("by format       : %s"
          % ", ".join("%s %d" % (k, v) for k, v in sorted(fmts.items())))
    coffs = sorted(r["coff"] for r in rows if r["coff"] and r.get("stamp") != "hash")
    if coffs:
        print("COFF range      : %s .. %s   (over %d datable stamps; %d hashes excluded)"
              % (coffs[0].strftime("%Y-%m-%d"), coffs[-1].strftime("%Y-%m-%d"),
                 len(coffs), len(hashes)))
        days = sorted({c.date() for c in coffs})
        print("distinct COFF days: %d  %s"
              % (len(days), ", ".join(str(d) for d in days)))
    comps = {}
    for r in rows:
        c = r["company"] or "(none)"
        comps[c] = comps.get(c, 0) + 1
    signed = [r for r in rows if r.get("signed")]
    print()
    print("Authenticode: %d of %d PE files carry a certificate table"
          % (len(signed), sum(1 for r in rows if r["fmt"].startswith("PE"))))
    for r in signed:
        print("    SIGNED  %s" % r["rel"])
    if not signed:
        print("    none")

    print()
    print("CompanyName / module name, by count:")
    for c, n in sorted(comps.items(), key=lambda kv: -kv[1]):
        print("    %-40s %d" % (c[:40], n))


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    main()
