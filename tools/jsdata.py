#!/usr/bin/env python3
"""jsdata.py -- census the text layer of `data.bin`, a Storage content dump.

What is derived, and how:

  * `data.bin` opens `36 00 | 14 00 00 00 | "Monstrous Emanations"`. The `u32`
    is the byte length of the string that follows and it is exact; the `u16`
    before it is a field tag whose meaning is per-type and is NOT derived here.
  * strings are byte strings, not UTF-16. Most are ASCII; some are UTF-8 --
    `Bensen’s Rules of Civil Conduct` carries a U+2019 as `e2 80 99`.
  * the object framing is per-type and this tool does NOT claim to read it.
    What it censuses is every length-prefixed string, by a greedy left-to-right
    walk that is stated here so that the coverage figure means something:

        at offset i, read L = u32; if 3 <= L <= LMAX and the L bytes decode as
        UTF-8 and contain no control character other than tab/newline/return,
        take it as a string and jump to i+4+L; otherwise advance one byte.

    A greedy walk over-reads: four bytes that happen to be a small integer
    followed by text will be taken as a string. It also under-reads: a string
    holding a byte that is not valid UTF-8 is skipped. Both directions are
    reported and neither is hidden.

    python tools/jsdata.py academagia-steam/OfficialContent/data.bin --census
    python tools/jsdata.py .../data.bin --find "Declare Vendetta"
    python tools/jsdata.py .../data.bin --names academagia-steam/OfficialContent/Resources
    python tools/jsdata.py --selftest
"""
import argparse
import collections
import os
import struct
import sys
import uuid
import zipfile

LMAX = 1 << 17
CTRL = set(range(0, 32)) - {9, 10, 13}


def strings(data, lmax=LMAX, lmin=3):
    """Yield (offset, tag, length, text). Greedy, left to right."""
    n = len(data)
    i = 0
    while i + 4 <= n:
        L = struct.unpack_from("<I", data, i)[0]
        if lmin <= L <= lmax and i + 4 + L <= n:
            blob = data[i + 4:i + 4 + L]
            if not any(b in CTRL for b in blob):
                try:
                    text = blob.decode("utf-8")
                except UnicodeDecodeError:
                    i += 1
                    continue
                tag = struct.unpack_from("<H", data, i - 2)[0] if i >= 2 else None
                yield i, tag, L, text
                i += 4 + L
                continue
        i += 1


def census(data, label):
    total = 0
    covered = 0
    lens = []
    tags = collections.Counter()
    ascii_only = 0
    multibyte = 0
    for off, tag, L, text in strings(data):
        total += 1
        covered += 4 + L
        lens.append(L)
        tags[tag] += 1
        if len(text.encode("ascii", "ignore")) == L:
            ascii_only += 1
        else:
            multibyte += 1
    lens.sort()
    print("file           : %s" % label)
    print("bytes          : %d" % len(data))
    print("strings found  : %d" % total)
    print("bytes in them  : %d = %.4f %% of the file  (length prefix + text)"
          % (covered, 100.0 * covered / len(data)))
    print("text bytes only: %d = %.4f %% of the file"
          % (covered - 4 * total, 100.0 * (covered - 4 * total) / len(data)))
    print("pure ASCII     : %d" % ascii_only)
    print("with a multi-byte UTF-8 sequence : %d" % multibyte)
    if lens:
        print("length min/median/mean/max : %d / %d / %.1f / %d"
              % (lens[0], lens[len(lens) // 2], sum(lens) / len(lens),
                 lens[-1]))
        for cut in (20, 100, 500, 1000):
            print("   longer than %5d bytes : %d" %
                  (cut, sum(1 for x in lens if x > cut)))
    print("distinct preceding u16 tags : %d" % len(tags))
    print("the twelve commonest, with their counts:")
    for t, c in tags.most_common(12):
        print("   0x%04x  %7d" % (t, c))
    return 0


def find(data, needles):
    for needle in needles:
        b = needle.encode("utf-8")
        hits = []
        start = 0
        while True:
            k = data.find(b, start)
            if k < 0:
                break
            hits.append(k)
            start = k + 1
        exact = 0
        for k in hits:
            if k >= 4 and struct.unpack_from("<I", data, k - 4)[0] == len(b):
                exact += 1
        print("%-34s occurrences %5d   of which length-prefixed exactly %d"
              % (repr(needle), len(hits), exact))
    return 0


def names(data, resdir):
    """For every GUID-named file, find its GUID in the dump and read whatever
    length-prefixed string follows it. Reports how many resolve and how many
    do not, because the second number is the one that says what is not read."""
    files = sorted(os.listdir(resdir))
    got = {}
    zero = 0
    absent = 0
    other = 0
    for f in files:
        try:
            g = uuid.UUID(f).bytes_le
        except ValueError:
            continue
        o = data.find(g)
        if o < 0:
            absent += 1
            continue
        L = struct.unpack_from("<I", data, o + 16)[0]
        if L == 0:
            zero += 1
            continue
        if 0 < L <= 400 and o + 20 + L <= len(data):
            blob = data[o + 20:o + 20 + L]
            if not any(b in CTRL for b in blob):
                try:
                    got[f] = blob.decode("utf-8")
                    continue
                except UnicodeDecodeError:
                    pass
        other += 1
    print("GUID-named files      : %d" % len(files))
    print("GUID present in dump  : %d" % (len(files) - absent))
    print("a name follows it     : %d" % len(got))
    print("a zero-length name    : %d" % zero)
    print("something else follows: %d" % other)
    print("not in the dump       : %d" % absent)
    print()
    for f in sorted(got)[:15]:
        print("   %s  %s" % (f, got[f]))
    return 0


def selftest():
    ok = 0
    fail = []
    good = struct.pack("<HI", 0x36, 20) + b"Monstrous Emanations"
    out = list(strings(good[2:] if False else good))
    if any(t == "Monstrous Emanations" for _, _, _, t in out):
        ok += 1
    else:
        fail.append("the file's own first record")
    cases = [
        ("all zeros", b"\x00" * 256, 0),
        ("a PNG", b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 2, None),
        ("a length that runs off the end",
         struct.pack("<I", 1 << 20) + b"abc", 0),
        ("a length of two, below the floor",
         struct.pack("<I", 2) + b"ab", 0),
        ("text with a NUL inside",
         struct.pack("<I", 6) + b"ab\x00def", 0),
        ("invalid UTF-8", struct.pack("<I", 4) + b"\xff\xfe\xfd\xfc", 0),
    ]
    for name, blob, want in cases:
        n = len(list(strings(blob)))
        if want is None or n == want:
            ok += 1
        else:
            fail.append("%s: got %d strings, wanted %d" % (name, n, want))
    utf8 = struct.pack("<I", 9) + "Bensen’s".encode("utf-8")[:9]
    n = len(list(strings(utf8)))
    if n == 1:
        ok += 1
    else:
        fail.append("a UTF-8 apostrophe")
    print("selftest: %d of 8 specimens behaved as required "
          "(5 of the 8 must yield nothing)" % ok)
    for f in fail:
        print("  FAILED: %s" % f)
    return 0 if not fail else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--zip", dest="zippath")
    ap.add_argument("--member", default="new_data.bin")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--find", nargs="+")
    ap.add_argument("--names")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.zippath:
        with zipfile.ZipFile(a.zippath) as z:
            data = z.read(a.member)
        label = "%s :: %s" % (os.path.basename(a.zippath), a.member)
    else:
        if not a.path:
            ap.error("give a path, or --zip, or --selftest")
        with open(a.path, "rb") as f:
            data = f.read()
        label = a.path
    if a.find:
        return find(data, a.find)
    if a.names:
        return names(data, a.names)
    return census(data, label)


if __name__ == "__main__":
    sys.exit(main())
