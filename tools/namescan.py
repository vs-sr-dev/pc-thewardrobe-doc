#!/usr/bin/env python3
"""namescan.py -- count a literal name over a tree in BOTH eight-bit and
UTF-16LE form, case-insensitively, and say which pass found it.

WHY IT HAD TO BE WRITTEN
------------------------
`sift.py` searches eight-bit bytes for regular-expression *shapes* and
`utf16sift.py` repeats that pass at sixteen bits. Neither counts a *literal*,
and `sigcount.py` counts a literal but only exactly as given and only in one
encoding.

On `pc-rpgmakerxp-doc`'s object that gap is not academic. The pre-briefing
reported `grep -rlai enterbrain` as **4 of 913 files**, two of them Windows
binaries -- and the place the name sits in those two binaries is a version
resource, which a linker writes in **UTF-16LE**. A `grep` for `enterbrain`
cannot see `E\\0n\\0t\\0e\\0r\\0...`. Either the eight-bit pass was matching
something else in those files, or the count was right by accident. This tool
exists so the question is answered by a measurement rather than by assuming
the brief.

The same defect bit `sift.py` on this object: it reported zero e-mail addresses
where `utf16sift.py` found one, in the same kind of field, in the same DLL.

    python tools/namescan.py rpgmakerxp-steam --name Enterbrain --name KADOKAWA
    python tools/namescan.py rpgmakerxp-steam --name Degica --show
    python tools/namescan.py --selftest
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import redact as redactmod                                   # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def forms(name):
    """The two byte forms of one name, both folded to lower case."""
    low = name.lower()
    return low.encode("latin-1"), low.encode("utf-16-le")


def fold(blob):
    """Case-fold a byte string without changing its length, so that offsets
    stay meaningful and the UTF-16 form keeps its interleaved zeros."""
    return bytes(b + 32 if 65 <= b <= 90 else b for b in blob)


def context(blob, at, wide):
    """The printable run a hit sits inside, so a count can become a quotation.

    A version resource and an About box are both written in UTF-16LE, and a
    hit reported as 'one occurrence in RPGXP.exe' is worth much less than the
    sentence it is part of. The run is extended in both directions while the
    bytes stay printable in the encoding the hit was found in.
    """
    step = 2 if wide else 1
    start = at
    while start - step >= 0:
        if wide:
            if not (32 <= blob[start - 2] < 127 and blob[start - 1] == 0):
                break
        elif not 32 <= blob[start - 1] < 127:
            break
        start -= step
    end = at
    while end + step <= len(blob):
        if wide:
            if end + 1 >= len(blob):
                break
            if not (32 <= blob[end] < 127 and blob[end + 1] == 0):
                break
        elif not 32 <= blob[end] < 127:
            break
        end += step
    # Redacted BY PROGRAM before it can be printed, on the same precedent as
    # `uuidscan.py`'s node field and `verres.py`'s CompanyName. The first run
    # of `--context` on this object printed a private individual's e-mail
    # address into a tracked note within seconds of the flag being added,
    # which is the argument for redacting where the printing happens rather
    # than where the operator remembers.
    raw, _n = redactmod.redact(blob[start:end])
    return raw.decode("utf-16-le" if wide else "latin-1", "replace")


def positions(blob, pat):
    out = []
    at = blob.find(pat)
    while at >= 0:
        out.append(at)
        at = blob.find(pat, at + 1)
    return out


def count(blob, pat):
    n = 0
    at = blob.find(pat)
    while at >= 0:
        n += 1
        at = blob.find(pat, at + 1)
    return n


def scan(root, names, show=False, want_context=False):
    if os.path.isfile(root):
        files = [(os.path.basename(root), root)]
    else:
        files = []
        for dp, _dn, fn in os.walk(root):
            for f in sorted(fn):
                p = os.path.join(dp, f)
                files.append((os.path.relpath(p, root).replace(os.sep, "/"),
                              p))
    if not files:
        sys.exit("namescan: no files under %r -- refusing to report a clean "
                 "table over an empty population" % root)
    rows = {n: {"eight": 0, "wide": 0, "files8": [], "files16": [],
                "quotes": []}
            for n in names}
    pats = {n: forms(n) for n in names}
    total = 0
    for rel, p in files:
        with open(p, "rb") as fh:
            raw = fh.read()
        # The SEARCH is over the case-folded copy so that it is
        # case-insensitive; the QUOTATION is taken from the original, because
        # a credit line printed in lower case is not what the file says.
        blob = fold(raw)
        total += len(blob)
        for n in names:
            eight, wide = pats[n]
            c8 = count(blob, eight)
            c16 = count(blob, wide)
            if c8:
                rows[n]["eight"] += c8
                rows[n]["files8"].append((rel, c8))
            if c16:
                rows[n]["wide"] += c16
                rows[n]["files16"].append((rel, c16))
            if want_context:
                for at in positions(blob, eight):
                    rows[n]["quotes"].append((rel, at, "8-bit",
                                              context(raw, at, False)))
                for at in positions(blob, wide):
                    rows[n]["quotes"].append((rel, at, "UTF-16",
                                              context(raw, at, True)))
    print("files searched : %d   bytes : %d" % (len(files), total))
    print("the search is case-insensitive and is run twice per file: once over")
    print("the bytes as they are, and once for the same text interleaved with")
    print("zeros, which is how a linker writes a version resource.")
    print()
    print("  %-16s %8s %8s %8s %8s"
          % ("name", "8-bit", "files", "UTF-16", "files"))
    for n in names:
        r = rows[n]
        print("  %-16s %8d %8d %8d %8d"
              % (n, r["eight"], len(r["files8"]), r["wide"],
                 len(r["files16"])))
    print()
    for n in names:
        r = rows[n]
        union = sorted({f for f, _c in r["files8"]}
                       | {f for f, _c in r["files16"]})
        print("  %s : %d file(s) carry it in one form or the other"
              % (n, len(union)))
        only16 = sorted({f for f, _c in r["files16"]}
                        - {f for f, _c in r["files8"]})
        if only16:
            print("     of which %d only a UTF-16 pass can see : %s"
                  % (len(only16), ", ".join(only16)))
        if show:
            for f in union:
                c8 = dict(r["files8"]).get(f, 0)
                c16 = dict(r["files16"]).get(f, 0)
                print("       %-46s 8-bit %d   UTF-16 %d" % (f, c8, c16))
        for rel, at, enc, text in r["quotes"]:
            print("       %-30s @%-9d %-7s %r" % (rel, at, enc, text[:160]))
    return 0


def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    eight, wide = forms("Enterbrain")
    ok("the eight-bit form is the lower-cased name",
       eight == b"enterbrain", str(eight))
    ok("the UTF-16 form interleaves zeros",
       wide == b"e\0n\0t\0e\0r\0b\0r\0a\0i\0n\0", str(wide))
    ok("case folding does not change a blob's length",
       len(fold(b"ABCdef\xff\x00")) == 8)
    ok("case folding lower-cases ASCII only",
       fold(b"ABC\xC0") == b"abc\xC0", str(fold(b"ABC\xC0")))
    ok("a UTF-16 needle is not found by an eight-bit search",
       count(fold(b"E\0n\0t\0e\0r\0b\0r\0a\0i\0n\0"), eight) == 0)
    ok("a UTF-16 needle IS found by the wide search",
       count(fold(b"xxE\0n\0t\0e\0r\0b\0r\0a\0i\0n\0yy"), wide) == 1)
    ok("an eight-bit needle is found by the eight-bit search",
       count(fold(b"by ENTERBRAIN, Inc."), eight) == 1)
    ok("two occurrences in one blob are counted twice",
       count(fold(b"degica degica"), forms("Degica")[0]) == 2)
    ok("overlapping occurrences are counted, not merged",
       count(b"aaa", b"aa") == 2)
    blob = b"\0\0" + "Ruby Version 1.8.1".encode("utf-16-le") + b"\0\0"
    at = blob.find("Ruby".encode("utf-16-le"))
    ok("the context of a UTF-16 hit is the whole printable run",
       context(blob, at, True) == "Ruby Version 1.8.1",
       repr(context(blob, at, True)))
    b8 = b"\x00xyz hello world \x01"
    ok("the context of an eight-bit hit stops at a non-printable byte",
       context(b8, b8.find(b"hello"), False) == "xyz hello world ",
       repr(context(b8, b8.find(b"hello"), False)))
    ok("positions() finds every occurrence",
       positions(b"a-a-a", b"a") == [0, 2, 4],
       str(positions(b"a-a-a", b"a")))
    wide = b"\0\0" + "Someone x@y.invalid here".encode("utf-16-le") + b"\0\0"
    q = context(wide, wide.find("Someone".encode("utf-16-le")), True)
    ok("a UTF-16 quotation has its address redacted by program",
       "x@y.invalid" not in q and "redacted" in q, repr(q))
    flat = b"\x00Someone x@y.invalid here\x00"
    q = context(flat, flat.find(b"Someone"), False)
    ok("an eight-bit quotation has its address redacted too",
       "x@y.invalid" not in q and "redacted" in q, repr(q))
    q = context(flat, flat.find(b"Someone"), False)
    ok("and the rest of the run survives the redaction",
       q.startswith("Someone") and q.endswith("here"), repr(q))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", nargs="?")
    ap.add_argument("--name", action="append", default=[])
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--context", action="store_true",
                    help="quote the printable run each hit sits inside, in "
                         "the encoding it was found in")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.root:
        sys.exit("namescan: a root is required")
    if not args.name:
        sys.exit("namescan: at least one --name is required")
    return scan(args.root, args.name, args.show, args.context)


if __name__ == "__main__":
    sys.exit(main())
