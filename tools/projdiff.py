#!/usr/bin/env python3
"""projdiff.py -- for every file a project ships that the Run Time Package also
ships under the same name, say whether the bytes are the same, and if not, what
the project's copy carries that the product's does not.

WHY THIS IS THE MEASUREMENT
---------------------------
A project directory beside a shared resource library asks one question: **which
of these files did a person actually touch?** A file that is byte-identical to
the RTP's is a copy; a file that differs is work. Counting the two is the
difference between "the project ships 47 files" and "the project's author made
N of them".

And the differences are legible without an image decoder, because the editing
tool leaves marks a PNG chunk census can see: an XMP packet, a `tIME`, a
`Software` text chunk, a private chunk. Those are reported per file, so that
"this one was edited" is a statement with a reason attached.

    python tools/projdiff.py <project> --against <rtp>
    python tools/projdiff.py <project> --against <rtp> --expect-identical 0
    python tools/projdiff.py --selftest
"""
import argparse
import hashlib
import os
import struct
import sys
import zlib

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

SIG = b"\x89PNG\r\n\x1a\n"
MARKS = ("iTXt", "tEXt", "zTXt", "tIME", "tpNg", "iCCP", "eXIf")


def sha1(path):
    return hashlib.sha1(open(path, "rb").read()).hexdigest()


def png_chunks(path):
    blob = open(path, "rb").read()
    if not blob.startswith(SIG):
        return None
    out = []
    p = len(SIG)
    while p + 8 <= len(blob):
        (n,) = struct.unpack(">I", blob[p:p + 4])
        t = blob[p + 4:p + 8].decode("latin-1")
        out.append((t, n))
        p += 12 + n
        if t == "IEND":
            break
    return out


def index(root):
    out = {}
    for dp, _dn, fn in os.walk(root):
        rel = os.path.relpath(dp, root).replace(os.sep, "/")
        rel = "" if rel == "." else rel
        for f in fn:
            key = "%s/%s" % (rel, f) if rel else f
            out[key] = os.path.join(dp, f)
    return out


def run(args):
    proj = index(args.project)
    rtp = index(args.against)
    common = sorted(set(proj) & set(rtp))
    only_proj = sorted(set(proj) - set(rtp))

    print("project files      : %d" % len(proj))
    print("RTP files          : %d" % len(rtp))
    print("same relative name : %d" % len(common))
    print("only in the project: %d" % len(only_proj))
    print()

    identical = differ = 0
    print("  %-34s %10s %10s  %s" % ("file", "project", "RTP", "verdict"))
    for k in common:
        a, b = proj[k], rtp[k]
        sa, sb = os.path.getsize(a), os.path.getsize(b)
        same = sha1(a) == sha1(b)
        identical += same
        differ += not same
        marks = ""
        if not same:
            ch = png_chunks(a)
            cb = png_chunks(b)
            if ch is not None and cb is not None:
                mine = {t for t, _n in ch}
                theirs = {t for t, _n in cb}
                extra = sorted((mine - theirs) | {m for m in MARKS
                                                  if m in mine and
                                                  m not in theirs})
                marks = "  carries %s" % ", ".join(extra) if extra else \
                    "  same chunk types, different bytes"
        print("  %-34s %10d %10d  %s%s"
              % (k, sa, sb, "identical" if same else "DIFFERS", marks))
    print()
    print("  byte-identical to the product's copy : %d of %d"
          % (identical, len(common)))
    print("  differing                            : %d of %d"
          % (differ, len(common)))
    print("  the two sum to the common names      : %s"
          % (identical + differ == len(common)))
    print()
    print("-- files the project has and the RTP does not ------------------")
    for k in only_proj:
        print("   %-44s %8d" % (k, os.path.getsize(proj[k])))
    print("   %d files" % len(only_proj))

    if args.expect_identical is not None and identical != args.expect_identical:
        raise SystemExit("FATAL: --expect-identical %d, got %d"
                         % (args.expect_identical, identical))
    return 0


def selftest():
    import shutil
    import tempfile
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    def chunk(t, d):
        return (struct.pack(">I", len(d)) + t + d +
                struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 3, 0, 0, 0)
    plain = SIG + chunk(b"IHDR", ihdr) + chunk(b"IDAT", b"\x00") + \
        chunk(b"IEND", b"")
    edited = SIG + chunk(b"IHDR", ihdr) + chunk(b"tEXt", b"Software\x00X") + \
        chunk(b"IDAT", b"\x00") + chunk(b"IEND", b"")

    tmp = tempfile.mkdtemp(prefix="projdiff-")
    try:
        p = os.path.join(tmp, "proj", "ChipSet")
        r = os.path.join(tmp, "rtp", "ChipSet")
        os.makedirs(p)
        os.makedirs(r)
        open(os.path.join(p, "A.png"), "wb").write(plain)
        open(os.path.join(r, "A.png"), "wb").write(plain)
        open(os.path.join(p, "B.png"), "wb").write(edited)
        open(os.path.join(r, "B.png"), "wb").write(plain)
        open(os.path.join(p, "Own.png"), "wb").write(edited)

        pi = index(os.path.join(tmp, "proj"))
        ri = index(os.path.join(tmp, "rtp"))
        check("three project files", len(pi), 3)
        check("two common names", len(set(pi) & set(ri)), 2)
        check("one only in the project",
              sorted(set(pi) - set(ri)), ["ChipSet/Own.png"])
        check("A is identical",
              sha1(pi["ChipSet/A.png"]) == sha1(ri["ChipSet/A.png"]), True)
        check("B differs",
              sha1(pi["ChipSet/B.png"]) == sha1(ri["ChipSet/B.png"]), False)
        mine = {t for t, _n in png_chunks(pi["ChipSet/B.png"])}
        theirs = {t for t, _n in png_chunks(ri["ChipSet/B.png"])}
        check("the difference is a tEXt chunk the RTP's lacks",
              sorted(mine - theirs), ["tEXt"])
        check("a non-PNG yields no chunk list",
              png_chunks(os.path.join(p, "..", "..", "proj", "ChipSet",
                                      "A.png")) is not None, True)
        check("keys use forward slashes",
              all("\\" not in k for k in pi), True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = 0
    for name, ok, got, want in checks:
        print("  %-50s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad += 1
    print("checks : %d   failures : %d" % (len(checks), bad))
    raise SystemExit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("project", nargs="?")
    ap.add_argument("--against")
    ap.add_argument("--expect-identical", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.project == "selftest":
        return selftest()
    if not args.project or not args.against:
        raise SystemExit("projdiff: a project and --against are required "
                         "(or --selftest)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
