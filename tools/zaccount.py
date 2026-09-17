#!/usr/bin/env python3
"""zaccount.py -- the accounting for an object that is one file with four
layers inside it, each with its own total, none of which may be added to
another.

There is no shop here, no manifest from a storefront, no `SizeOnDisk` and no
depot. Every total below is the object's own arithmetic checked against the
object's own declarations, and each layer closes separately:

    LAYER 1  the object      one ZIP, against PKWARE's published structure
    LAYER 2  the members     twelve files the ZIP holds
    LAYER 3  the containers  four InstallShield containers among those twelve,
                             each against its own header
    LAYER 4  the product     the files those containers hold, against the
                             expanded sizes their entry tables declare

The rule this tool exists to enforce is that a percentage must name its
denominator. There are six populations here -- 1 file, 12 members, 4
containers, 271 recovered files, 256 manifest names, 12 manifest groups -- and
a share quoted without saying which one is meaningless. Every row prints its
own denominator.

    python tools/zaccount.py --zip rpgmaker95-dist/RPG-Maker-95_Win_EN_RPG-Maker-95-v102.zip --members _work/members
    python tools/zaccount.py selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ispkg                                     # noqa: E402
import is32                                      # noqa: E402
import isz                                       # noqa: E402


class AccountError(Exception):
    pass


def zip_closure(path):
    """Re-derive the whole file from PKWARE's structure. Nothing here reads a
    stored total: every term is counted out of the records."""
    d = open(path, "rb").read()
    eocd = d.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise AccountError("no end-of-central-directory record in %s" % path)
    n = struct.unpack_from("<H", d, eocd + 10)[0]
    cdsize = struct.unpack_from("<I", d, eocd + 12)[0]
    cdoff = struct.unpack_from("<I", d, eocd + 16)[0]
    local = data = cd = 0
    p = cdoff
    for i in range(n):
        if d[p:p + 4] != b"PK\x01\x02":
            raise AccountError("central directory record %d is not a record"
                               % i)
        nlen, elen, clen = struct.unpack_from("<3H", d, p + 28)
        comp = struct.unpack_from("<I", d, p + 20)[0]
        lho = struct.unpack_from("<I", d, p + 42)[0]
        if d[lho:lho + 4] != b"PK\x03\x04":
            raise AccountError("local header for member %d is not a header"
                               % i)
        lnlen, lelen = struct.unpack_from("<2H", d, lho + 26)
        local += 30 + lnlen + lelen
        data += comp
        cd += 46 + nlen + elen + clen
        p += 46 + nlen + elen + clen
    eo = len(d) - eocd
    return {"members": n, "local": local, "data": data, "cd": cd,
            "cd_declared": cdsize, "eocd": eo, "length": len(d),
            "total": local + data + cd + eo}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", nargs="?", default="report")
    ap.add_argument("--zip")
    ap.add_argument("--members")
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest()
    if not args.zip or not args.members:
        raise SystemExit("zaccount: --zip and --members are both required")

    failures = []

    def closes(label, got, want, extra=""):
        ok = got == want
        if not ok:
            failures.append(label)
        print("  %-56s %s  %s" % (label, "ok  " if ok else "FAIL",
                                  extra or "%d against %d, residue %d"
                                  % (got, want, want - got)))

    z = zip_closure(args.zip)
    print("LAYER 1 -- THE OBJECT, denominator 1 file")
    print("  %-30s %12d" % ("local file headers", z["local"]))
    print("  %-30s %12d" % ("member data", z["data"]))
    print("  %-30s %12d" % ("central directory", z["cd"]))
    print("  %-30s %12d" % ("end-of-central-directory", z["eocd"]))
    print("  %-30s %12d" % ("TOTAL", z["total"]))
    print("  %-30s %12d" % ("the file on disk", z["length"]))
    print()
    closes("the ZIP closes against PKWARE's structure", z["total"],
           z["length"])
    closes("the central directory is the length the EOCD declares", z["cd"],
           z["cd_declared"])
    print()

    names = sorted(os.listdir(args.members))
    sizes = dict((n, os.path.getsize(os.path.join(args.members, n)))
                 for n in names)
    print("LAYER 2 -- THE MEMBERS, denominator %d files" % len(names))
    print("  %-30s %12d" % ("extracted bytes", sum(sizes.values())))
    print("  %-30s %12d" % ("stored inside the ZIP", z["data"]))
    print()
    closes("every member the ZIP declares is on disk", len(names),
           z["members"], "%d of %d" % (len(names), z["members"]))
    print()

    print("LAYER 3 -- THE CONTAINERS, denominator 4 of those %d members"
          % len(names))
    total_expanded = 0
    n_recovered = 0
    for name in ("_SETUP.1", "_SETUP.LIB", "SETUP.INS"):
        p = os.path.join(args.members, name)
        a = isz.parse(open(p, "rb").read(), p)
        h, e = a["header"], a["entries"]
        first = e[0]["offset"]
        stored = sum(x["stored"] for x in e)
        tot = first + stored + h["dir_table_len"] + h["entry_table_len_true"]
        print("  %-14s %6d members  %d + %d + %d + %d = %d, file %d"
              % (name, len(e), first, stored, h["dir_table_len"],
                 h["entry_table_len_true"], tot, a["length"]))
        closes("    %s closes at residue 0" % name, tot, a["length"])
        total_expanded += sum(x["expanded"] for x in e)
        n_recovered += len(e)
    p = os.path.join(args.members, "_INST32I.EX_")
    c = is32.parse(open(p, "rb").read())
    r = c["records"]
    tot = r[0]["offset"] + sum(x["stored"] for x in r)
    print("  %-14s %6d members  %d + %d = %d, file %d"
          % ("_INST32I.EX_", len(r), r[0]["offset"],
             sum(x["stored"] for x in r), tot, c["length"]))
    closes("    _INST32I.EX_ closes at residue 0", tot, c["length"])
    total_expanded += sum(x["expanded"] for x in r)
    n_recovered += len(r)
    print()

    print("LAYER 4 -- THE PRODUCT, denominator %d recovered files"
          % n_recovered)
    print("  %-30s %12d" % ("bytes the entries declare", total_expanded))
    print()

    pkg = ispkg.parse(open(os.path.join(args.members, "SETUP.PKG"),
                           "rb").read())
    a1 = isz.parse(open(os.path.join(args.members, "_SETUP.1"), "rb").read())
    closes("SETUP.PKG's 256 sizes equal _SETUP.1's stored sizes",
           sum(f["size"] for f in pkg["files"]),
           sum(e["stored"] for e in a1["entries"]))
    closes("SETUP.PKG names the same 256 files, in the same order",
           [f["name"] for f in pkg["files"]] ==
           [e["name"] for e in a1["entries"]], True,
           "%d of %d" % (sum(1 for a, b in zip(pkg["files"], a1["entries"])
                             if a["name"] == b["name"]), len(pkg["files"])))
    closes("_SETUP.1's header declares the sum of its expanded sizes",
           a1["header"]["u16"],
           sum(e["expanded"] for e in a1["entries"]))
    closes("SETUP.PKG's group counts equal _SETUP.1's directory counts",
           [sum(1 for f in pkg["files"] if f["group"] == g)
            for g in range(pkg["group_count"])],
           [d["files"] for d in a1["dirs"]],
           "12 of 12" if [sum(1 for f in pkg["files"] if f["group"] == g)
                          for g in range(pkg["group_count"])] ==
           [d["files"] for d in a1["dirs"]] else "MISMATCH")
    print()
    print("THE FOUR TOTALS, WHICH ARE NEVER ADDED TOGETHER")
    print("  the object                 %12d over  1 file" % z["length"])
    print("  the members                %12d over %2d files"
          % (sum(sizes.values()), len(names)))
    print("  the manifest declares      %12d over %d names"
          % (sum(f["size"] for f in pkg["files"]), pkg["file_count"]))
    print("  the product, expanded      %12d over %d recovered files"
          % (total_expanded, n_recovered))
    print()
    if failures:
        print("FAILURES: %d" % len(failures), file=sys.stderr)
        for f in failures:
            print("  %s" % f, file=sys.stderr)
        return 1
    print("every closure above holds.")
    return 0


def selftest():
    checks = []
    # A ZIP built by the standard library must close the same way.
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", b"hello" * 100)
        zf.writestr("b.bin", bytes(range(256)) * 4)
    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "_account_selftest.zip")
    with open(tmp, "wb") as fh:
        fh.write(buf.getvalue())
    try:
        z = zip_closure(tmp)
        checks.append(("a ZIP this tool did not write closes at residue 0",
                       z["total"] == z["length"],
                       "%d against %d" % (z["total"], z["length"])))
        checks.append(("its member count is what the EOCD declares",
                       z["members"] == 2, str(z["members"])))
        checks.append(("its central directory is the declared length",
                       z["cd"] == z["cd_declared"], ""))
        # A file with no EOCD must raise, not return a wrong total.
        with open(tmp, "rb") as fh:
            body = fh.read()
        bad = body.replace(b"PK\x05\x06", b"PK\x05\x07")
        with open(tmp, "wb") as fh:
            fh.write(bad)
        try:
            zip_closure(tmp)
            checks.append(("a file with no end record is rejected", False,
                           "ACCEPTED"))
        except AccountError as e:
            checks.append(("a file with no end record is rejected", True,
                           str(e)[:50]))
    finally:
        os.remove(tmp)
    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL",
                                   note))
        if not ok:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
