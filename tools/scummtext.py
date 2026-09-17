#!/usr/bin/env python3
"""Extract and count the strings of a SCUMM container, and tie them to speech.

Everything here is derived from this object's bytes. The derivations, in the
order they were made:

1. **Where strings live.** They are not in a table. They are inline in script
   chunks (`SCRP LSCR ENCD EXCD VERB`) and in `OBNA` chunks, which hold one
   null-terminated object name each and nothing else.

2. **What introduces a string.** Found by anchoring, not by guessing. Every
   spoken line begins with the same eight bytes -- `FF 0A 0A 00 FF 0A 00 00`
   -- because that is the second half of a voice cue whose size field is
   always 10. Searching the decrypted container for those eight bytes gives
   4,741 hits; taking the byte before each hit's 16-byte cue gives exactly
   three distinct values, `BA`, `BB` and `4B`, and `4B` is always itself
   preceded by one of `B4 B5 B6 B7 B8`. So the introducers are:

       B4..B8 4B   <string>      (the print family, sub-op "text string")
       BA          <string>      (talk)
       BB          <string>      (talk, second form)

   The scanner is **not a disassembler**, so `BA`/`BB` bytes that are operands
   rather than opcodes are false positives. They are counted and reported: a
   candidate that does not parse as a well-formed string is rejected and
   tallied, and the reject rate is printed. This is the guard against
   yesterday's failure mode, where a one-byte boundary error turned 428
   strings into 2,287 fragments without raising anything.

3. **The escapes.** Inside a string, `FF` introduces a code. Codes 01, 02, 03
   and 08 take no argument; 04, 05, 06, 07, 09, 0A, 0C, 0D and 0E take two.
   The argument widths were derived by requiring that every one of the 4,741
   anchored strings parses to a null terminator with no leftover.

4. **The voice cue.** `FF 0A lo hi FF 0A lo2 hi2` -- two 16-bit little-endian
   halves -- gives a 32-bit byte offset into `MONSTER.SOU`, and the second
   pair gives the size of the `VCTL` chunk found there. `--voice` checks every
   distinct offset against `MONSTER.SOU` and reports how many land on a
   literal `VCTL` tag. All of them do.

5. **The codepage.** Not declared anywhere. `--chars` prints the histogram of
   bytes >= 0x80 in the decoded text so the reader can do the deduction with
   the same numbers.

Language classification uses two closed lists of function words, printed by
`--words`, so the reader can disagree with the lists rather than with a
verdict. A string is Italian if it contains more Italian than English markers,
English in the opposite case, and *undecided* when it contains neither -- and
the undecided pile is reported, not hidden.

Usage:
  python tools/scummtext.py strings <SAMNMAX.001> [--key 0x69] [--out F]
  python tools/scummtext.py names   <SAMNMAX.001> [--out F]
  python tools/scummtext.py counts  <SAMNMAX.001> [--chars] [--words]
  python tools/scummtext.py voice   <SAMNMAX.001> <MONSTER.SOU>
"""
import collections
import re
import unicodedata
import sys

SCRIPT_TAGS = (b"SCRP", b"LSCR", b"ENCD", b"EXCD", b"VERB")
CONTAINER_TAGS = (b"LECF", b"LFLF", b"ROOM", b"OBCD", b"OBIM", b"RMIM", b"PALS")
NOARG = {0x01, 0x02, 0x03, 0x08}
TWOARG = {0x04, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0C, 0x0D, 0x0E}

# Two closed lists, printed on request. Words are matched case-folded on the
# CP437-decoded text, whole word only.
IT = set("""che non di il la lo un una uno per sono questo questa mi ti ci vi ho
hai abbiamo ma come se ecco piu' più cosa qui qua quando perche' perché anche
solo tutto tutti niente nulla bene molto adesso allora dove chi mio mia tuo tua
sua suo con del della dei delle nel nella al alla dal dalla sul sulla essere
fare andare voglio posso puoi devo devi siamo sei era erano ora gia' già sempre
mai forse certo grazie prego signore signora ragazzo cosi' così quel quella
questi queste loro noi voi lui lei si no""".split())
EN = set("""the you and of is that this with have what are was for not but your
they there here from can will would could should about which when where who
some other into more than then them him her his out just like get got make
made take took know knew see saw say said think thought going been being does
did done doesn't don't i'm it's isn't we're they're yes no ok okay""".split())


def load(path, key=0x69):
    d = open(path, "rb").read()
    return bytes(b ^ key for b in d) if key else d


def collect(c, tags):
    out = []

    def walk(lo, hi):
        p = lo
        while p < hi:
            t = c[p:p + 4]
            l = int.from_bytes(c[p + 4:p + 8], "big")
            if t in tags:
                out.append((t.decode("latin-1"), p + 8, p + l))
            elif t in CONTAINER_TAGS:
                walk(p + 8, p + l)
            p += l
    walk(0, len(c))
    return out


def read_string(d, i):
    """Return (end_index_of_NUL, printable_count) or (None, 0)."""
    j = i
    np_ = 0
    while j < len(d):
        x = d[j]
        if x == 0:
            return j, np_
        if x == 0xFF:
            if j + 1 >= len(d):
                return None, 0
            code = d[j + 1]
            j += 2
            if code in NOARG:
                continue
            if code in TWOARG:
                j += 2
                continue
            return None, 0
        if 0x20 <= x <= 0xFE:
            np_ += 1
            j += 1
            continue
        return None, 0
    return None, 0


def script_strings(c):
    """Yield (tag, absolute_offset, raw_bytes). Also returns reject counts."""
    out = []
    rejects = collections.Counter()
    for tag, a, b in collect(c, SCRIPT_TAGS):
        d = c[a:b]
        i = 0
        while i < len(d):
            st = None
            if d[i] in (0xB4, 0xB5, 0xB6, 0xB7, 0xB8) and i + 1 < len(d) \
                    and d[i + 1] == 0x4B:
                st = i + 2
            elif d[i] in (0xBA, 0xBB):
                st = i + 1
            if st is not None:
                e, np_ = read_string(d, st)
                if e is not None:
                    out.append((tag, a + st, d[st:e]))
                    i = e + 1
                    continue
                rejects[d[i]] += 1
            i += 1
    return out, rejects


def obna(c):
    out = []
    for tag, a, b in collect(c, (b"OBNA",)):
        s = c[a:b]
        out.append((a, s.split(b"\0")[0]))
    return out


def strip_escapes(raw):
    """Return (visible_text_bytes, escape_counter, voice_offsets)."""
    txt = bytearray()
    esc = collections.Counter()
    voice = []
    i = 0
    pend = []
    while i < len(raw):
        x = raw[i]
        if x == 0xFF:
            code = raw[i + 1]
            esc[code] += 1
            if code in NOARG:
                i += 2
            else:
                arg = int.from_bytes(raw[i + 2:i + 4], "little")
                if code == 0x0A:
                    pend.append(arg)
                i += 4
            continue
        txt.append(x)
        i += 1
    if len(pend) >= 4:
        voice.append((pend[1] << 16 | pend[0], pend[3] << 16 | pend[2]))
    return bytes(txt), esc, voice


def words_of(text):
    return re.findall(r"[A-Za-zÀ-ÿ']+", text)


def classify(text):
    ws = [w.lower() for w in words_of(text)]
    it = sum(1 for w in ws if w in IT)
    en = sum(1 for w in ws if w in EN)
    if it > en:
        return "it"
    if en > it:
        return "en"
    return "?"


def cmd_strings(path, key, out):
    c = load(path, key)
    ss, rej = script_strings(c)
    f = open(out, "w", encoding="utf-8") if out else sys.stdout
    for tag, off, raw in ss:
        txt, esc, voice = strip_escapes(raw)
        v = voice[0][0] if voice else 0
        f.write("%s\t%d\t%d\t%s\n"
                % (tag, off, v, txt.decode("cp437").replace("\n", " ")))
    if out:
        f.close()
        print("wrote %s (%d strings)" % (out, len(ss)))
    sys.stderr.write("rejected candidates: %s\n" % dict(rej))


def cmd_names(path, key, out):
    c = load(path, key)
    ns = obna(c)
    f = open(out, "w", encoding="utf-8") if out else sys.stdout
    for off, s in ns:
        f.write("%d\t%s\n" % (off, s.decode("cp437")))
    if out:
        f.close()
        print("wrote %s (%d names)" % (out, len(ns)))


def cmd_counts(path, key, show_chars, show_words):
    c = load(path, key)
    ss, rej = script_strings(c)
    ns = obna(c)
    esc_tot = collections.Counter()
    hi = collections.Counter()
    lang = collections.Counter()
    nwords = 0
    nchars = 0
    stored = 0
    voiced = 0
    empty = 0
    per_tag = collections.Counter()
    per_tag_w = collections.Counter()
    for tag, off, raw in ss:
        txt, esc, voice = strip_escapes(raw)
        esc_tot.update(esc)
        stored += len(raw) + 1
        s = txt.decode("cp437")
        w = words_of(s)
        if not w:
            empty += 1
        nwords += len(w)
        nchars += len(s)
        per_tag[tag] += 1
        per_tag_w[tag] += len(w)
        lang[classify(s)] += 1
        if voice:
            voiced += 1
        for b in txt:
            if b >= 0x80:
                hi[b] += 1
    print("script strings      %d" % len(ss))
    print("  of which voiced   %d" % voiced)
    print("  with no words     %d" % empty)
    print("rejected candidates %d  %s" % (sum(rej.values()), dict(rej)))
    print("stored bytes        %d" % stored)
    print("visible characters  %d" % nchars)
    print("WORDS               %d" % nwords)
    print()
    print("%-6s %8s %10s" % ("tag", "strings", "words"))
    for t in sorted(per_tag, key=lambda t: -per_tag_w[t]):
        print("%-6s %8d %10d" % (t, per_tag[t], per_tag_w[t]))
    print()
    nw = 0
    nl = collections.Counter()
    hyph = 0
    for off, s in ns:
        t = s.decode("cp437")
        nw += len(words_of(t))
        nl[classify(t)] += 1
        if re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)+", t):
            hyph += 1
        for b in s:
            if b >= 0x80:
                hi[b] += 1
    print("object names        %d, %d words" % (len(ns), nw))
    print("  lowercase-hyphen  %d  (developer identifiers, never displayed"
          " in that form)" % hyph)
    print("  language          %s" % dict(nl))
    print()
    print("TOTAL WORDS         %d" % (nwords + nw))
    print()
    print("string language     %s" % dict(lang))
    print()
    print("escape codes seen (FF xx):")
    for k, v in sorted(esc_tot.items()):
        print("  FF %02X  %6d  %s" % (k, v, "no arg" if k in NOARG else "2-byte arg"))
    if show_chars:
        print("\nbytes >= 0x80 in decoded text, with the CP437 and CP850 glyph:")
        for k, v in sorted(hi.items()):
            a = bytes([k]).decode("cp437")
            b = bytes([k]).decode("cp850")
            # print the Unicode NAME, not the glyph: this tool has to run in a
            # console whose own codepage is not the object's, and printing the
            # glyph is how you get a UnicodeEncodeError instead of a number.
            print("  %02X  %7d  cp437 U+%04X %-24s cp850 U+%04X  %s"
                  % (k, v, ord(a), unicodedata.name(a, "?"), ord(b),
                     "SAME" if a == b else "DIFFER"))
    if show_words:
        print("\nItalian marker list (%d): %s" % (len(IT), " ".join(sorted(IT))))
        print("\nEnglish marker list (%d): %s" % (len(EN), " ".join(sorted(EN))))


def cmd_voice(path, sou, key):
    c = load(path, key)
    sig = b"\xff\x0a\x0a\x00\xff\x0a\x00\x00"
    occ = [m.start() for m in re.finditer(re.escape(sig), c)]
    offs = []
    intro = collections.Counter()
    for o in occ:
        s = o - 8
        if c[s:s + 2] == b"\xff\x0a" and c[s + 4:s + 6] == b"\xff\x0a":
            lo = int.from_bytes(c[s + 2:s + 4], "little")
            hi = int.from_bytes(c[s + 6:s + 8], "little")
            offs.append(hi << 16 | lo)
            intro[c[s - 1]] += 1
    print("voice cues          %d" % len(occ))
    print("well-formed         %d" % len(offs))
    print("distinct offsets    %d" % len(set(offs)))
    print("introducer bytes    %s"
          % {"0x%02X" % k: v for k, v in intro.most_common()})
    f = open(sou, "rb")
    bad = []
    for o in sorted(set(offs)):
        f.seek(o)
        if f.read(4) != b"VCTL":
            bad.append(o)
    print("land on a VCTL tag  %d of %d" % (len(set(offs)) - len(bad), len(set(offs))))
    if bad:
        print("  misses: %s" % bad[:10])
    dup = collections.Counter(offs)
    print("offsets cited once  %d" % sum(1 for v in dup.values() if v == 1))
    print("cited more than one %d" % sum(1 for v in dup.values() if v > 1))
    print("most cited offset   %s" % (dup.most_common(1)))


def main(argv):
    key = 0x69
    out = None
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--key":
            key = int(argv[i + 1], 0); i += 2
        elif argv[i] == "--out":
            out = argv[i + 1]; i += 2
        else:
            rest.append(argv[i]); i += 1
    c = rest[0]
    if c == "strings":
        cmd_strings(rest[1], key, out)
    elif c == "names":
        cmd_names(rest[1], key, out)
    elif c == "counts":
        cmd_counts(rest[1], key, "--chars" in argv, "--words" in argv)
    elif c == "voice":
        cmd_voice(rest[1], rest[2], key)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
