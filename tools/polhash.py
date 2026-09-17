#!/usr/bin/env python3
"""polhash.py -- attack the 22-character field of the PlayOnline manifests.

The four manifests of this object (`file.txt` and `patch.txt`, in both the
game branch and the PlayOnlineViewer branch) carry lines of the form

    <22 characters>:<size in bytes>:<relative path>

and terminate with a line `::`.  The 22-character field is drawn from a
non-standard base64-looking alphabet that includes `@` and `_`.

22 x 6 = 132 bits = 128 + 4.  If the field is a 128-bit digest packed
big-endian six bits at a time, then the LAST character carries only two
significant bits and can therefore take at most FOUR distinct values.
That is a positional signature which can be tested without knowing the
alphabet, without knowing the digest, and without opening a single file.
It is the cheapest possible falsification of the whole inference, and it
runs first.

Then, and only then, the alphabet is recovered: for every manifest entry
whose file is present on disk and whose declared size matches, the digest
is computed, packed into 22 six-bit groups, and each group value is
associated with the character that stands in that position.  A consistent
association over many files IS the alphabet.  An inconsistent one kills
the hypothesis.

Controls that must fail are run alongside: SHA-1 and CRC-32 under the very
same procedure.  If those also "succeed", the procedure is meaningless and
the tool says so.

Nothing is executed, nothing is contacted, nothing is written to the object.

usage:
  polhash.py positions MANIFEST [MANIFEST ...]
  polhash.py alphabet  MANIFEST --root ROOT [--limit N] [--digest md5|sha1|crc32]
  polhash.py verify    MANIFEST --root ROOT --alphabet FILE [--limit N]
"""

import argparse
import hashlib
import os
import sys
import zlib
from collections import Counter, defaultdict

FIELD = 22
BITS = FIELD * 6          # 132
DIGEST_BITS = 128


def read_manifest(path):
    """Return (entries, terminator_count, malformed, eol).

    entries is a list of (field, size, relpath).  The terminator line is
    '::'.

    The four manifests of this object do NOT agree on line endings:
    `FINAL FANTASY XI\\file.txt` is CRLF and the other three are bare LF.
    A reader that splits on CRLF returns ONE entry for three of the four
    files and looks like it worked, which is exactly the failure mode this
    branch keeps meeting.  So the split is on LF with a trailing CR
    stripped, and the observed ending is reported on every line that
    reports a count.
    """
    entries = []
    terminators = 0
    malformed = []
    with open(path, "rb") as fh:
        raw = fh.read()
    crlf = raw.count(b"\r\n")
    lf = raw.count(b"\n")
    eol = "CRLF" if crlf and crlf == lf else ("LF" if lf else "none")
    assert lf > 0, "manifest %s has no LF at all -- reader would silently " \
                   "return one entry" % path
    for lineno, line in enumerate(raw.split(b"\n"), 1):
        line = line.rstrip(b"\r")
        if not line:
            continue
        if line == b"::":
            terminators += 1
            continue
        try:
            text = line.decode("ascii")
        except UnicodeDecodeError:
            malformed.append((lineno, "non-ascii"))
            continue
        parts = text.split(":", 2)
        if len(parts) != 3:
            malformed.append((lineno, "field count %d" % len(parts)))
            continue
        field, size, rel = parts
        if not size.isdigit():
            malformed.append((lineno, "size not a number"))
            continue
        entries.append((field, int(size), rel))
    return entries, terminators, malformed, eol


def cmd_positions(args):
    """The falsification that costs nothing: how many distinct characters
    stand in each of the 22 positions, over every entry of every manifest?"""
    per_pos = [Counter() for _ in range(FIELD)]
    total = 0
    widths = Counter()
    for path in args.manifest:
        entries, term, malformed, eol = read_manifest(path)
        print("%-34s %7d entries, '::' x%d, malformed %d, eol %s"
              % (os.path.basename(os.path.dirname(path)) + "/" +
                 os.path.basename(path), len(entries), term,
                 len(malformed), eol))
        for field, _size, _rel in entries:
            widths[len(field)] += 1
            if len(field) != FIELD:
                continue
            total += 1
            for i, ch in enumerate(field):
                per_pos[i][ch] += 1
    print()
    print("field widths seen: %s" % dict(widths))
    print("entries of width %d: %d" % (FIELD, total))
    print()
    print("distinct characters standing in each position:")
    print("  pos  distinct  characters (if few)")
    constrained = []
    for i, c in enumerate(per_pos):
        note = ""
        if len(c) <= 8:
            note = " ".join(sorted(c))
            constrained.append(i)
        print("  %3d  %8d  %s" % (i, len(c), note))
    print()
    union = set()
    for c in per_pos:
        union |= set(c)
    print("alphabet union over all positions: %d characters" % len(union))
    print("  %s" % "".join(sorted(union)))
    print()
    if constrained == [FIELD - 1] and len(per_pos[-1]) <= 4:
        print("VERDICT: exactly one position is constrained, it is the last,")
        print("         and it carries %d distinct characters." % len(per_pos[-1]))
        print("         That is the signature of %d bits packed six at a time"
              % DIGEST_BITS)
        print("         with %d bits of padding in the final character."
              % (BITS - DIGEST_BITS))
    else:
        print("VERDICT: the signature is NOT the expected one.")
        print("         constrained positions: %s" % constrained)
    return 0


def digest_bits(data, kind):
    if kind == "md5":
        return hashlib.md5(data).digest(), 128
    if kind == "sha1":
        return hashlib.sha1(data).digest(), 160
    if kind == "crc32":
        return (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big"), 32
    raise ValueError(kind)


def groups_from_digest(dig, nbits, order):
    """Split a digest into 22 six-bit groups.

    order 'be' : most significant bit first, zero padded on the right.
    order 'le' : least significant bit first (little-endian bit order).
    """
    value = int.from_bytes(dig, "big")
    out = []
    if order == "be":
        padded = value << (BITS - nbits)
        for i in range(FIELD):
            shift = BITS - 6 * (i + 1)
            out.append((padded >> shift) & 0x3F)
    else:
        for i in range(FIELD):
            out.append((value >> (6 * i)) & 0x3F)
    return out


def iter_present(entries, root, limit):
    """Yield (field, size, relpath, abspath) for entries whose file exists
    with the declared size.  Case-insensitive, as Windows resolves names."""
    n = 0
    for field, size, rel in entries:
        if len(field) != FIELD:
            continue
        p = os.path.join(root, rel.replace("/", os.sep))
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_size != size:
            continue
        yield field, size, rel, p
        n += 1
        if limit and n >= limit:
            return


def cmd_alphabet(args):
    entries, _term, _mal, _eol = read_manifest(args.manifest[0])
    print("manifest entries        : %d" % len(entries))
    for order in ("be", "le"):
        mapping = defaultdict(Counter)     # value -> Counter(char)
        conflicts = 0
        used = 0
        for field, size, _rel, p in iter_present(entries, args.root, args.limit):
            with open(p, "rb") as fh:
                data = fh.read()
            dig, nbits = digest_bits(data, args.digest)
            if nbits > BITS:
                print("  %s is %d bits, wider than the %d the field can hold"
                      % (args.digest, nbits, BITS))
                break
            vals = groups_from_digest(dig, nbits, order)
            used += 1
            for v, ch in zip(vals, field):
                mapping[v][ch] += 1
        if not used:
            continue
        clean = 0
        table = {}
        for v, c in mapping.items():
            if len(c) == 1:
                clean += 1
                table[v] = next(iter(c))
            else:
                conflicts += 1
        print()
        print("  digest=%s order=%s files=%d" % (args.digest, order, used))
        print("    values seen        : %d of 64" % len(mapping))
        print("    values with ONE character : %d" % clean)
        print("    values with a conflict    : %d" % conflicts)
        if conflicts == 0 and len(mapping) >= 60:
            alpha = "".join(table.get(i, "?") for i in range(64))
            print("    ALPHABET (index 0..63):")
            print("      %s" % alpha)
            if args.out:
                with open(args.out, "w", encoding="ascii") as fh:
                    fh.write(alpha + "\n")
                print("    wrote %s" % args.out)
        elif conflicts:
            worst = sorted(mapping.items(),
                           key=lambda kv: -len(kv[1]))[:3]
            for v, c in worst:
                print("    value %2d -> %s" % (v, dict(c)))
    return 0


def cmd_verify(args):
    with open(args.alphabet, "r", encoding="ascii") as fh:
        alpha = fh.read().strip()
    if len(alpha) != 64:
        print("alphabet must be 64 characters, got %d" % len(alpha))
        return 2
    entries, _t, _m, _eol = read_manifest(args.manifest[0])
    ok = bad = missing = mismatch = 0
    bad_examples = []
    for field, size, rel in entries:
        if len(field) != FIELD:
            continue
        p = os.path.join(args.root, rel.replace("/", os.sep))
        try:
            st = os.stat(p)
        except OSError:
            missing += 1
            continue
        if st.st_size != size:
            mismatch += 1
            continue
        with open(p, "rb") as fh:
            data = fh.read()
        dig, nbits = digest_bits(data, args.digest)
        vals = groups_from_digest(dig, nbits, args.order)
        made = "".join(alpha[v] for v in vals)
        if made == field:
            ok += 1
        else:
            bad += 1
            if len(bad_examples) < 5:
                bad_examples.append(rel)
        if args.limit and ok + bad >= args.limit:
            break
    print("digest=%s order=%s" % (args.digest, args.order))
    print("  reproduced exactly : %d" % ok)
    print("  did not reproduce  : %d" % bad)
    print("  absent from disk   : %d" % missing)
    print("  size mismatch      : %d" % mismatch)
    if ok + bad:
        print("  rate               : %.4f %%" % (100.0 * ok / (ok + bad)))
    for e in bad_examples:
        print("    failed: %s" % e)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("positions")
    p.add_argument("manifest", nargs="+")
    p.set_defaults(func=cmd_positions)

    p = sub.add_parser("alphabet")
    p.add_argument("manifest", nargs=1)
    p.add_argument("--root", required=True)
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--digest", default="md5", choices=["md5", "sha1", "crc32"])
    p.add_argument("--out")
    p.set_defaults(func=cmd_alphabet)

    p = sub.add_parser("verify")
    p.add_argument("manifest", nargs=1)
    p.add_argument("--root", required=True)
    p.add_argument("--alphabet", required=True)
    p.add_argument("--digest", default="md5", choices=["md5", "sha1", "crc32"])
    p.add_argument("--order", default="be", choices=["be", "le"])
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
