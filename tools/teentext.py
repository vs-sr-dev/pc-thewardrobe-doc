#!/usr/bin/env python3
"""teentext.py -- the words of TEENAGENT, out of the UNPACKED engine's data
segment, where they live: not in any of the twelve .RES.

WHERE THE WORDS ARE
-------------------
`TEENAGNT.EXE` is LZEXE-packed (tools/lzexe.py); unpacked it is 152,434
bytes of image with a code segment at 0000h (46,368 bytes), a data segment
at 0B52h (59,680 bytes, `mov ax,0B52h; mov ds,ax` is the program's first
instruction) and 46,386 bytes of buffers above the stack. Every message the
game prints is in the data segment as

    line 00 line 00 ... line 00 00

-- lines separated by a single zero, the message closed by a second. A few
messages open with a byte below 20h (a position or colour code the credits
use); the tool keeps it out of the text and counts it.

THE FONT MAP, WHICH IS WHY `DOBRZY;SKI`
---------------------------------------
The game's small font (`VARIA.RES` member 6, 97 glyphs from 20h) puts the
Polish letters on the punctuation slots. `--polish` prints the text the way
the font would draw it:

    # $ % * + ; < = > @ [ \\ ] { | }
    ę ś ł ó Ą Ń ż ń ź ą Ę Ć Ł Ó Ś Ż

so `JAROS]AW WEISS` is Jarosław Weiss and `ANDRZEJ DOBRZY;SKI` is Andrzej
Dobrzyński. The map is read off the rendered font, glyph by glyph; it is
not a code page.

    python tools/teentext.py IMAGE.exe             every message, with offsets
    python tools/teentext.py IMAGE.exe --count     the census only
    python tools/teentext.py IMAGE.exe --polish    with the font map applied
    python tools/teentext.py IMAGE.exe --grep WORD
    python tools/teentext.py --selftest
"""
import argparse
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402

POLISH = dict(zip("#$%*+;<=>@[\\]{|}", "ęśłóĄŃżńźąĘĆŁÓŚŻ"))
DS_PARA = 0x0B52


def load(path):
    with open(path, "rb") as fh:
        d = fh.read()
    if d[:2] != b"MZ":
        raise SystemExit("teentext.py: %s is not an MZ file" % path)
    h = struct.unpack_from("<14H", d, 2)
    hdr = h[3] * 16
    img = d[hdr:]
    ss = h[6]
    if not (0 < DS_PARA * 16 < ss * 16 <= len(img)):
        raise SystemExit("teentext.py: image does not hold a data segment at "
                         "%04Xh below the stack at %04Xh" % (DS_PARA, ss))
    return img, DS_PARA * 16, ss * 16


def messages(img, lo, hi, min_line=2):
    """Blocks of 00-separated printable lines closed by 00 00, inside
    [lo, hi). Returns dicts with offset, lines, prefix."""
    out = []
    i = lo
    n = hi
    while i < n:
        b = img[i]
        if not (0x20 <= b < 0x7F or b < 0x20 and i + 1 < n
                and 0x20 <= img[i + 1] < 0x7F):
            i += 1
            continue
        start = i
        prefix = None
        if b < 0x20:
            prefix = b
            i += 1
        lines = []
        ok = True
        while True:
            j = i
            while j < n and 0x20 <= img[j] < 0x7F:
                j += 1
            line = img[i:j].decode("ascii")
            if j >= n or img[j] != 0:
                ok = False
                break
            lines.append(line)
            if j + 1 < n and img[j + 1] == 0:
                i = j + 2
                break
            i = j + 1
            if i < n and img[i] < 0x20 and i + 1 < n and 0x20 <= img[i + 1] < 0x7F:
                # a coded line head inside the block (the credits use them)
                i += 1
        if ok and lines and len(lines[0]) >= min_line \
                and any(c.isalpha() for l in lines for c in l):
            out.append({"offset": start, "lines": lines, "prefix": prefix})
        if not ok:
            i = max(i, start + 1)
    return out


def polish(s):
    return "".join(POLISH.get(c, c) for c in s)


def census(msgs):
    lines = sum(len(m["lines"]) for m in msgs)
    words = sum(len(l.split()) for m in msgs for l in m["lines"])
    chars = sum(len(l) for m in msgs for l in m["lines"])
    coded = sum(1 for m in msgs if m["prefix"] is not None)
    return {"messages": len(msgs), "lines": lines, "words": words,
            "chars": chars, "coded": coded}


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("image", nargs="?")
    ap.add_argument("--count", action="store_true")
    ap.add_argument("--polish", action="store_true")
    ap.add_argument("--grep")
    ap.add_argument("--min-line", type=int, default=2)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if not a.image:
        ap.error("no image")
    dirguard.want_file(a.image, "teentext.py")
    img, lo, hi = load(a.image)
    msgs = messages(img, lo, hi, a.min_line)
    c = census(msgs)
    print("# %s: data segment %05Xh..%05Xh (%d bytes); %d messages, %d "
          "lines, %d words, %d characters; %d messages with a coded head"
          % (os.path.basename(a.image), lo, hi, hi - lo, c["messages"],
             c["lines"], c["words"], c["chars"], c["coded"]))
    if a.count:
        return 0
    for m in msgs:
        text = " / ".join(m["lines"])
        if a.polish:
            text = polish(text)
        if a.grep and a.grep.lower() not in text.lower():
            continue
        head = "" if m["prefix"] is None else "<%02X>" % m["prefix"]
        print("%05X %s%s" % (m["offset"], head, text))
    return 0


def selftest():
    nameguard.guard()
    checks = []

    def ok(label, cond, note=""):
        checks.append(cond)
        print("  %-56s %s %s" % (label, "ok" if cond else "FAIL", note))

    blob = (b"\0" * 8 + b"Life is brutal.\0\0" + b"\x05Pbackgrounds\0"
            b"iANDRZEJ DOBRZY;SKI\0\0" + b"ab\0" + b"\xff\xfe" + b"x\0\0"
            + b"Two\0lines\0\0" + b"\0" * 4)
    ms = messages(blob, 0, len(blob))
    ok("three messages found (the unterminated `ab` is not one)",
       len(ms) == 3, str([m["lines"] for m in ms]))
    ok("a coded head (05h) is stripped and counted; the printable `P` "
       "and `i` the credits open lines with stay in the text",
       ms[1]["prefix"] == 0x05 and ms[1]["lines"] == ["Pbackgrounds",
                                                       "iANDRZEJ DOBRZY;SKI"])
    ok("two-line message keeps both lines", ms[2]["lines"] == ["Two", "lines"])
    ok("font map: DOBRZY;SKI -> DOBRZYŃSKI, JAROS]AW -> JAROSŁAW",
       polish("DOBRZY;SKI") == "DOBRZYŃSKI" and polish("JAROS]AW") == "JAROSŁAW")
    c = census(ms)
    ok("census: 3 messages, 5 lines, 8 words", (c["messages"], c["lines"],
                                                 c["words"]) == (3, 5, 8),
       str(c))
    print("\nteentext.py selftest: %d of %d ok" % (sum(checks), len(checks)))
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
