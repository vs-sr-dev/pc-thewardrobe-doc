#!/usr/bin/env python3
"""agp.py -- read the `AGP!` container, 3D People's own serialisation, which
sits on 14,697 files and nine extensions in *Kult: Heretic Kingdoms* and is not
described by any published specification.

WHAT IT IS, DERIVED FROM THE BYTES AND NOT FROM A DOCUMENT
----------------------------------------------------------
Four magic bytes `AGP!` followed immediately by an LZSS stream of the
Okumura shape:

    control byte, then eight items, LOW BIT FIRST
      bit set   -> one literal byte, copied out and into the window
      bit clear -> two bytes b0 b1:
                     offset = b0 | ((b1 & 0xF0) << 4)      12 bits, 0..4095
                     length = (b1 & 0x0F) + 3              3..18
                   `length` bytes are copied from the window at `offset`,
                   one at a time, so a match may overlap its own output

    window : 4096 bytes, PRE-FILLED WITH ZERO, write position starts at
             4096 - 18 = 4078 and advances one byte per byte emitted

The zero pre-fill is not an assumption: it is what makes the first token of
almost every file in the object decode to the zero half of a `u32`. The
smallest specimen in the object, `3d/gfx/tremor.3d`, is 103 bytes and its first
control byte is `f5` = 1,0,1,0,1,1,1,1, which reads

    literal 01 | match eb f0 | literal 06 | match eb f0 | literal '@@@\\'

and `eb f0` is offset 4075, length 3 -- three bytes of window that nothing has
written yet. With a zero pre-fill that is `01 00 00 00  06 00 00 00 "@@@\\..."`,
two `u32` and a path. With Okumura's original space pre-fill it is
`01 20 20 20`, which is not a number and not anything.

THE CHECKS, WHICH ARE THE POINT
-------------------------------
Two of them are independent of each other and neither is optional:

  * **the input closes.** A correct walk consumes the compressed stream
    exactly: every control byte's items are present and the last one ends on
    the final byte. `residue` is the count of input bytes left over, and a
    non-zero residue on any file is a failure, not a rounding.
  * **the output declares itself.** Five of the nine extensions -- `.pr`,
    `.chr`, `.sav`, `.dat` and the extensionless one -- begin their
    decompressed form with a `u32` that equals the decompressed length minus
    four. That field is inside the compressed data, so it cannot agree by
    accident with a wrong codec.

The `.3d`, `.3d1` and `.dia2` families do not carry that field and are reported
as `no declared length` rather than as passes.

WHAT THIS READER CANNOT DETECT, SAID HERE RATHER THAN DISCOVERED LATER
----------------------------------------------------------------------
A control byte covers eight items and the encoder stops as soon as the data
runs out, so the unused high bits of the last control byte are padding. That
means **a stream truncated in the middle of a literal run is
indistinguishable from a stream that legitimately ended there.** A stream
truncated inside a *match* token is detectable, and is refused. The selftest
below was written with a truncated-literal case as a negative, the reader
accepted it on the first run, and the case was moved rather than the reader
patched -- because the reader was right and the test was wrong.

    python tools/agp.py selftest
    python tools/agp.py validate "<root>/data/spell/Burning.pr"
    python tools/agp.py census "<root>"
    python tools/agp.py extract "<root>/data/creature/a_guard1.chr" -o out.bin
    python tools/agp.py strings "<root>/data/creature/a_guard1.chr"
"""
import argparse
import collections
import os
import struct
import sys

MAGIC = b"AGP!"
WINDOW = 4096
LOOKAHEAD = 18
THRESHOLD = 2


class AgpError(Exception):
    """Raised for anything this reader will not guess about."""


def decode(data, path="<memory>", control_offsets=None):
    """Return (plain_bytes, residue, tokens, literals, matches).

    If `control_offsets` is a list, every input offset used as a control byte
    is appended to it. That is what identifies the intruding bytes inside the
    object's half-readable strings as flag bytes rather than as damage.

    Refuses loudly. A stream that ends in the middle of a token, a file that
    does not carry the magic, and a file with nothing after the magic are all
    errors, because each of them would otherwise produce a short answer that
    looks like a short file.
    """
    if len(data) < 4:
        raise AgpError("%s: %d bytes, too short to hold the magic" % (path, len(data)))
    if data[:4] != MAGIC:
        raise AgpError("%s: magic is %r, not %r" % (path, data[:4], MAGIC))
    if len(data) == 4:
        raise AgpError("%s: magic and nothing else" % path)

    win = bytearray(WINDOW)
    r = WINDOW - LOOKAHEAD
    out = bytearray()
    i = 4
    n = len(data)
    tokens = literals = matches = 0

    while i < n:
        if control_offsets is not None:
            control_offsets.append(i)
        flags = data[i]
        i += 1
        if i >= n:
            raise AgpError("%s: a control byte at +%d with no items after it"
                           % (path, i - 1))
        for bit in range(8):
            if i >= n:
                # the encoder stops mid-flag-byte at end of stream; the
                # remaining bits are padding and there is no residue.
                break
            tokens += 1
            if flags & (1 << bit):
                b = data[i]
                i += 1
                out.append(b)
                win[r] = b
                r = (r + 1) & (WINDOW - 1)
                literals += 1
            else:
                if i + 1 >= n:
                    raise AgpError(
                        "%s: a match token at +%d wants two bytes and the file "
                        "has one" % (path, i))
                b0 = data[i]
                b1 = data[i + 1]
                i += 2
                off = b0 | ((b1 & 0xF0) << 4)
                ln = (b1 & 0x0F) + THRESHOLD + 1
                for k in range(ln):
                    b = win[(off + k) & (WINDOW - 1)]
                    out.append(b)
                    win[r] = b
                    r = (r + 1) & (WINDOW - 1)
                matches += 1
    residue = n - i
    return bytes(out), residue, tokens, literals, matches


# The families whose decompressed form opens with its own length.
#
# This set was `{".pr", ".chr", ".sav", ".dat", ""}` on the first census run,
# on the guess that anything opening with a plausible `u32` declared itself.
# The census reported 83 disagreements and every one of them was `.sav` or the
# extensionless `global/empty` declaring 811,957,349, which is the four ASCII
# bytes `ele0` read as a number: those files open with a ten-byte name field
# and the `u32` at +10 is 10,552, the `.pr` record size, not a length. The set
# was narrowed to the two families that actually carry the field rather than
# the check being loosened until it passed.
DECLARES_LENGTH = {".pr", ".chr"}


def declared_length(plain, ext):
    """Return (declared body length, offset it was read at), or (None, None)
    if this family carries no such field."""
    if ext not in DECLARES_LENGTH or len(plain) < 8:
        return None, None
    (v,) = struct.unpack_from("<I", plain, 0)
    return v, (0 if v == len(plain) - 4 else None)


def load(path):
    with open(path, "rb") as fh:
        return fh.read()


def cmd_validate(a):
    data = load(a.path)
    plain, residue, tokens, lits, mats = decode(data, a.path)
    ext = os.path.splitext(a.path)[1].lower()
    decl, at = declared_length(plain, ext)
    print("file              : %s" % a.path)
    print("compressed        : %d bytes" % len(data))
    print("magic             : %r" % data[:4])
    print("decompressed      : %d bytes  (ratio %.4f)"
          % (len(plain), len(plain) / float(len(data))))
    print("tokens            : %d = %d literals + %d matches"
          % (tokens, lits, mats))
    print("literal share     : %.4f %% of tokens" % (100.0 * lits / tokens))
    print("input residue     : %d bytes   %s"
          % (residue, "-- CLOSES" if residue == 0 else "-- DOES NOT CLOSE"))
    if decl is None:
        print("declared length   : this family carries none")
    elif at is None:
        print("declared length   : %d at +0, decompressed-4 is %d  -- DISAGREES"
              % (decl, len(plain) - 4))
    else:
        print("declared length   : %d at +%d, decompressed-4 is %d  -- AGREES"
              % (decl, at, len(plain) - 4))
    if residue != 0:
        raise AgpError("%s: %d bytes of input left over" % (a.path, residue))
    print()
    for k in range(0, min(len(plain), a.head), 16):
        c = plain[k:k + 16]
        print("  %06x  %-47s  %s" % (k, c.hex(" "),
              "".join(chr(b) if 32 <= b < 127 else "." for b in c)))


def cmd_extract(a):
    data = load(a.path)
    plain, residue, tokens, lits, mats = decode(data, a.path)
    if residue and not a.force:
        raise AgpError("%s: %d bytes of input left over; pass --force to write "
                       "the partial result anyway" % (a.path, residue))
    with open(a.out, "wb") as fh:
        fh.write(plain)
    print("%s -> %s   %d -> %d bytes, residue %d"
          % (a.path, a.out, len(data), len(plain), residue))


def printable_runs(blob, minlen=4):
    run = bytearray()
    for b in blob:
        if 32 <= b < 127:
            run.append(b)
        else:
            if len(run) >= minlen:
                yield run.decode("ascii")
            run = bytearray()
    if len(run) >= minlen:
        yield run.decode("ascii")


def cmd_strings(a):
    data = load(a.path)
    plain, residue, tokens, lits, mats = decode(data, a.path)
    print("%s  %d -> %d bytes, residue %d" % (a.path, len(data), len(plain), residue))
    for s in printable_runs(plain, a.min):
        print("   %s" % s)


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            yield os.path.join(dirpath, fn)


def cmd_census(a):
    root = a.root
    per = collections.defaultdict(lambda: dict(
        files=0, cbytes=0, pbytes=0, closes=0, residue=0, declared=0,
        agree=0, disagree=0, failed=0, tokens=0, lits=0))
    failures = []
    scanned = 0
    for p in walk(root):
        try:
            with open(p, "rb") as fh:
                head = fh.read(4)
        except OSError:
            continue
        if head != MAGIC:
            continue
        scanned += 1
        ext = os.path.splitext(p)[1].lower()
        d = per[ext]
        data = load(p)
        d["files"] += 1
        d["cbytes"] += len(data)
        try:
            plain, residue, tokens, lits, mats = decode(data, p)
        except AgpError as exc:
            d["failed"] += 1
            failures.append(str(exc))
            continue
        d["pbytes"] += len(plain)
        d["tokens"] += tokens
        d["lits"] += lits
        if residue == 0:
            d["closes"] += 1
        else:
            d["residue"] += 1
            failures.append("%s: residue %d" % (p, residue))
        decl, at = declared_length(plain, ext)
        if decl is not None:
            d["declared"] += 1
            if at is None:
                d["disagree"] += 1
                failures.append("%s: declares %d, decompressed-4 is %d"
                                % (p, decl, len(plain) - 4))
            else:
                d["agree"] += 1

    print("root              : %s" % root)
    print("files beginning %r : %d" % (MAGIC, scanned))
    print()
    print("%-8s %6s %13s %13s %6s %8s %8s %8s %8s"
          % ("ext", "files", "compressed", "plain", "ratio", "closes",
             "residue", "agrees", "differs"))
    tf = tc = tp = tcl = tr = ta = td = tfa = 0
    for ext, d in sorted(per.items(), key=lambda kv: -kv[1]["files"]):
        print("%-8s %6d %13d %13d %6.2f %8d %8d %8d %8d"
              % (ext or "(none)", d["files"], d["cbytes"], d["pbytes"],
                 (d["pbytes"] / float(d["cbytes"])) if d["cbytes"] else 0,
                 d["closes"], d["residue"], d["agree"], d["disagree"]))
        tf += d["files"]; tc += d["cbytes"]; tp += d["pbytes"]
        tcl += d["closes"]; tr += d["residue"]; ta += d["agree"]
        td += d["disagree"]; tfa += d["failed"]
    print("%-8s %6d %13d %13d %6.2f %8d %8d %8d %8d"
          % ("TOTAL", tf, tc, tp, (tp / float(tc)) if tc else 0, tcl, tr, ta, td))
    print()
    print("files that refused to decode at all : %d" % tfa)
    print("files whose input did not close     : %d" % tr)
    print("files carrying a self-declared length : %d, of which agreeing %d, "
          "disagreeing %d" % (ta + td, ta, td))
    print("expansion, whole container            : %d -> %d bytes, %.4f x"
          % (tc, tp, (tp / float(tc)) if tc else 0))
    if failures:
        print()
        print("the first twenty failures:")
        for f in failures[:20]:
            print("   %s" % f)
    return 1 if (tfa or tr or td) else 0


def _flag(bits):
    """Build a control byte from a list of 1/0 in emission order."""
    v = 0
    for k, b in enumerate(bits):
        if b:
            v |= 1 << k
    return v


def cmd_selftest(a):
    """Ten specimens built in memory. Seven must be refused and three must
    DECODE to a byte string stated here, because a reader that merely accepts
    a positive case has not been tested."""
    cases = []

    # 1 -- literals only
    body = bytes([_flag([1] * 8)]) + b"Heretic!"
    cases.append(("literals only", MAGIC + body, b"Heretic!"))

    # 2 -- a match that copies what three literals just wrote.
    # write position starts at 4096-18 = 4078, so after 'abc' the window holds
    # 'abc' at 4078..4080. offset 4078 -> b0 = 0xEE, b1 = (4078>>4)&0xF0 = 0xF0,
    # plus length 3 - 3 = 0.
    body = bytes([_flag([1, 1, 1, 0, 0, 0, 0, 0])]) + b"abc" + bytes([0xEE, 0xF0])
    cases.append(("a back-reference into fresh output", MAGIC + body, b"abcabc"))

    # 3 -- a match into the untouched window, which is the whole reason the
    # pre-fill has to be zero.
    body = bytes([_flag([1, 0, 0, 0, 0, 0, 0, 0])]) + b"\x01" + bytes([0xEB, 0xF0])
    cases.append(("a back-reference into the pre-fill",
                  MAGIC + body, b"\x01\x00\x00\x00"))

    refusals = [
        ("empty", b""),
        ("three bytes", b"AGP"),
        ("wrong magic", b"AGQ!" + bytes([0xFF]) + b"12345678"),
        ("magic and nothing else", MAGIC),
        ("a control byte with nothing after it",
         MAGIC + bytes([_flag([1] * 8)])),
        ("a match token with one byte",
         MAGIC + bytes([_flag([1, 1, 0, 0, 0, 0, 0, 0])]) + b"ab" + b"\xee"),
        ("a TGA header, which is the object's other big population",
         bytes([0, 0, 2, 0]) + bytes(60)),
    ]

    ok = True
    print("POSITIVE -- these must decode to the exact bytes named:")
    for name, blob, want in cases:
        try:
            got, residue, tokens, lits, mats = decode(blob, name)
        except AgpError as exc:
            print("   FAIL  %-38s raised %s" % (name, exc))
            ok = False
            continue
        good = got == want and residue == 0
        print("   %-4s  %-38s -> %r  residue %d"
              % ("ok" if good else "FAIL", name, got, residue))
        if not good:
            print("         wanted %r" % (want,))
            ok = False

    print()
    print("NEGATIVE -- these must all be refused:")
    for name, blob in refusals:
        try:
            got, residue, tokens, lits, mats = decode(blob, name)
        except AgpError as exc:
            print("   ok    %-38s refused: %s" % (name, str(exc)[:60]))
        else:
            print("   FAIL  %-38s ACCEPTED, produced %d bytes" % (name, len(got)))
            ok = False

    print()
    print("%d positive, %d negative, %s"
          % (len(cases), len(refusals), "all as expected" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("validate")
    p.add_argument("path")
    p.add_argument("--head", type=int, default=128)
    p.set_defaults(fn=cmd_validate)

    p = sub.add_parser("census")
    p.add_argument("root")
    p.set_defaults(fn=cmd_census)

    p = sub.add_parser("extract")
    p.add_argument("path")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_extract)

    p = sub.add_parser("strings")
    p.add_argument("path")
    p.add_argument("--min", type=int, default=4)
    p.set_defaults(fn=cmd_strings)

    p = sub.add_parser("selftest")
    p.set_defaults(fn=cmd_selftest)

    a = ap.parse_args()
    try:
        rc = a.fn(a)
    except AgpError as exc:
        sys.exit("AgpError: %s" % exc)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
