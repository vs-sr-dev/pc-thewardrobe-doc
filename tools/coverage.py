#!/usr/bin/env python3
"""coverage.py -- what share of an object is in a format somebody published,
stated over a named denominator.

This repository's coverage figure has always been a share of bytes whose
format has a published specification. On this object that figure is different
at every layer, so the tool takes the layer as an argument and prints the
denominator on the same line as the share. A coverage number without its
denominator is not a measurement.

    members  the twelve files the ZIP holds
    product  the files the four InstallShield containers hold, by the expanded
             size each container's own entry table declares
    tree     every file under a directory, classified BY MAGIC and not by
             extension, into FOUR buckets

THE FOURTH BUCKET, AND WHY IT HAD TO EXIST
------------------------------------------
The three buckets below were written for an object whose unopened remainder was
either vendor-specified or described by nobody at all. They do not fit an object
whose whole unopened remainder is **publicly reverse-engineered and never
specified by its vendor** -- Microsoft's ITSF, and RPG Maker's own LCF. Calling
those `published` would claim a warrant that does not exist; calling them
`neither` would deny work other people did in public and that anybody can check.
So there are four, and each has a membership test somebody who disagrees can
apply:

  SPECIFIED  a document describing the format was published by the party that
             created it, or by a standards body that adopted it, and that
             document is what an implementer works from.
  DECODED    no such document exists, and an independent published third-party
             reverse engineering does -- one this repository can name.
  DERIVED    this session worked it out of the bytes and can name no public
             account of it.
  OPAQUE     none of the above.

**The bucket describes the FORMAT's public standing, not this session's route
to it.** ITSF and LCF are DECODED here even though every field this repository
uses was derived from the bytes, because the question a bucket answers is
"could a stranger check this against something", and for those two the answer
is yes and the something is not this repository.

**And the buckets are never summed into a coverage figure.** They may be summed
into an ACCOUNTING figure -- do the bytes add up to the object -- because that
is a question about bytes. Coverage is a question about warrant, and warrants
of different kinds do not add.

A format counts as PUBLISHED when a specification exists outside this
repository: PKWARE's APPNOTE for ZIP, Microsoft's NE and PE, the MIDI
Manufacturers Association's Standard MIDI File, Microsoft's BMP and RIFF WAVE,
and plain text. It counts as DERIVED when this session worked it out of the
bytes: InstallShield's Z archive, its `_INST32I` container and its `.PKG`
manifest. It counts as NEITHER when nobody here opened it and nobody outside
has written it down: WinHelp 3.x, and RPG Maker's own `.DAT` and `.ATR`.

The three buckets are printed separately and are never merged, because
"derived by this session" is a weaker claim than "published by a vendor" and
folding them together would hide that.

    python tools/coverage.py members --members _work/members
    python tools/coverage.py product --members _work/members
    python tools/coverage.py selftest

Repaired on pc-losthorizon-doc: `_utf16_text` before `_mpeg_audio`, an MPEG
probe that wants the second frame, and `_spcr` on the three tables' closure.
"""
import argparse
import collections
import os
import struct
import sys
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import adlibbnk                                  # noqa: E402
import bmb                                       # noqa: E402
import bumlevel                                  # noqa: E402
import bumpack                                   # noqa: E402
import bumsprite                                 # noqa: E402
import carfont                                   # noqa: E402
import comunpack                                 # noqa: E402
import fnt                                       # noqa: E402
import forgedat                                  # noqa: E402
import graf                                      # noqa: E402
import hxg                                       # noqa: E402
import hxgsave                                   # noqa: E402
import is32                                      # noqa: E402
import isz                                       # noqa: E402
import nameguard                                 # noqa: E402
import pes                                       # noqa: E402
import pif                                       # noqa: E402
import res                                       # noqa: E402
import vecscreen                                 # noqa: E402

# This object is the first in the collection with a file name outside Latin-1,
# and `ambiguity` mode prints file names. The box's convention -- a tool that
# prints recovered text sets its own output encoding -- had never been applied
# to NAMES, and this tool died on its own first run for exactly that reason.
nameguard.guard()

PUBLISHED = {
    "MID": "Standard MIDI File (MMA RP-001)",
    "BMP": "Windows bitmap (Microsoft)",
    "WAV": "RIFF WAVE (Microsoft and IBM)",
    "EXE": "NE and PE (Microsoft)",
    "DLL": "NE and PE (Microsoft)",
    "TXT": "plain text",
    "INI": "plain text",
    "DIZ": "plain text; CP437 and CP866 render it identically",
    "ID": "plain text",
}
DERIVED = {
    "1": "InstallShield Z archive, derived here",
    "LIB": "InstallShield Z archive, derived here",
    "INS": "InstallShield Z archive, derived here",
    "EX_": "InstallShield _INST32I container, derived here",
    "PKG": "InstallShield manifest, derived here",
}
NEITHER = {
    "HLP": "WinHelp 3.x, no published specification",
    "DAT": "RPG Maker's own, no published specification",
    "ATR": "RPG Maker's own, no published specification",
    "INS_product": "InstallShield compiled setup script, not opened here",
}


def ext_of(name):
    base = name.rsplit("\\", 1)[-1]
    if "." in base[1:]:
        return base.rsplit(".", 1)[-1].upper()
    return "(none)"


def bucket(ext, mode="members"):
    # `.INS` is a Z archive at the member layer and a compiled setup script
    # at the product layer. Same three letters, two different things, and
    # one table must not silently claim the other was opened.
    if ext == "INS" and mode == "product":
        return "neither", NEITHER["INS_product"]
    if ext in PUBLISHED:
        return "published", PUBLISHED[ext]
    if ext in DERIVED:
        return "derived", DERIVED[ext]
    if ext in NEITHER:
        return "neither", NEITHER[ext]
    return "neither", "not identified in this session"


def population(mode, members):
    rows = []
    if mode == "members":
        for n in sorted(os.listdir(members)):
            rows.append((n, os.path.getsize(os.path.join(members, n))))
        return rows, "the twelve files the ZIP holds"
    for name in ("_SETUP.1", "_SETUP.LIB", "SETUP.INS"):
        p = os.path.join(members, name)
        for e in isz.parse(open(p, "rb").read(), p)["entries"]:
            rows.append((e["name"], e["expanded"]))
    p = os.path.join(members, "_INST32I.EX_")
    for r in is32.parse(open(p, "rb").read())["records"]:
        rows.append((r["name"], r["expanded"]))
    return rows, "the files the four containers hold, at their declared " \
                 "expanded sizes"


def report(rows, label, mode="members"):
    total = sum(s for _, s in rows)
    cnt = collections.Counter()
    byt = collections.Counter()
    for n, s in rows:
        e = ext_of(n)
        cnt[e] += 1
        byt[e] += s
    print("denominator : %d files, %d bytes -- %s" % (len(rows), total, label))
    print()
    print("  %-8s %6s %12s  %-10s %s"
          % ("ext", "files", "bytes", "bucket", "format"))
    for e, c in cnt.most_common():
        b, why = bucket(e, mode)
        print("  %-8s %6d %12d  %-10s %s" % (e, c, byt[e], b, why))
    print()
    sums = collections.Counter()
    counts = collections.Counter()
    for e in cnt:
        b, _ = bucket(e, mode)
        sums[b] += byt[e]
        counts[b] += cnt[e]
    for b in ("published", "derived", "neither"):
        print("  %-10s %4d files %12d bytes   %8.4f %% of %d"
              % (b, counts[b], sums[b], 100.0 * sums[b] / total if total else 0,
                 total))
    print("  %-10s %4d files %12d bytes"
          % ("SUM", sum(counts.values()), sum(sums.values())))
    if sum(sums.values()) != total:
        print("  THE BUCKETS DO NOT SUM TO THE DENOMINATOR", file=sys.stderr)
        return 1
    return 0


# ------------------------------------------------------------------ by magic
#
# The `tree` mode classifies a file by its leading bytes, because this object
# ships two Windows executables named `.dat` and an extension table would put
# 1,498,112 bytes in the wrong row.

def _printable(b):
    if not b:
        return False
    return all(32 <= x < 127 or x in (9, 10, 13) for x in b[:512])


def _is(prefix):
    return lambda b: b.startswith(prefix)


# cp437's shading blocks and line-drawing set, which is one contiguous band.
CP437_BOX_LOW, CP437_BOX_HIGH = 0xB0, 0xDF
# cp437's accented letters: Ç ü é â ä à å ç ê ë è ï î ì Ä Å É æ Æ ô ö ò û ù ÿ
# Ö Ü at 80h..9Ah and á í ó ú ñ Ñ at A0h..A5h. The Greek block E0h..EFh is
# left out on purpose: it is Shift-JIS's second lead-byte range and no
# French, Spanish, Italian or German text needs it.
CP437_LETTERS = frozenset(range(0x80, 0x9B)) | frozenset(range(0xA0, 0xA6))
# cp437's single-byte signs that sit between words: ¢ £ ¥ ₧ ƒ (9Bh..9Fh),
# ª º ¿ ⌐ ¬ ½ ¼ ¡ « » (A6h..AFh), ≡ ± ≥ ≤ ⌠ ⌡ ÷ ≈ ° ∙ · √ ⁿ ² ■ (F0h..FEh)
# and the non-breaking space FFh, which `echo ÿ` prints a blank line with.
CP437_SIGNS = (frozenset(range(0x9B, 0xA0)) | frozenset(range(0xA6, 0xB0))
               | frozenset(range(0xF0, 0x100)))
DOS_EOF = 0x1A


def _cp437_scan(b):
    """The measurement the two cp437 probes share.

    THE DEFECT THIS REPAIRS, WHICH IS THE FOURTH OF ITS CLASS
    ---------------------------------------------------------
    `pc-hexxagon-doc`'s `COME.SEE` is an advertisement for a bulletin board in
    Ohio, in English, drawn in cp437 frames. This table filed it as
    **plain text, Shift-JIS**, because `_cp932_text` asked the only question it
    can ask -- does this decode without an illegal sequence -- and the answer
    was yes. Shift-JIS gives 0xA1..0xDF to single-byte half-width katakana;
    cp437 puts its blocks and frames at 0xB0..0xDF. **Two codepages share a
    byte range and mean different things in it**, and no decode test can
    separate them, because both decodes are legal.

    The first repair (on Hexxagon) accepted a file whose high bytes were ALL
    in the band 0xB0..0xDF and nothing else. On `pc-bumpy-doc` that failed
    twice in one folder: Fairlight's `FLT.NFO` has 2,139 high bytes, 2,138 in
    the band and ONE outside it -- the `·` (FAh) of `ANSi·JED` -- and went to
    Shift-JIS again; and `INSTALL.BAT`, French with `é` (82h), `è` (8Ah) and
    two `ÿ` (FFh) and no frame at all, went OPAQUE. So the probe now reads
    cp437 as a codepage and not as a band: frames and shading (the band),
    the accented letters, the signs, and a DOS end-of-file mark (1Ah) as the
    last byte.

    What still separates cp437 from Shift-JIS is the SHAPE of the high bytes,
    not their values, and two rules carry it:

      * a letter in 80h..9Ah is never followed by another high byte. In
        Shift-JIS, 81h..9Fh are lead bytes and about half of all trail bytes
        are >= 80h, so kanji and kana text trips this within a few
        characters; in a French or German text an accented letter is
        followed by a plain one (`répertoire`, `Création`);
      * letters and signs together are at most a quarter of the ASCII
        letters and digits. Katakana whose trail bytes happen to be ASCII
        (`ア` = 83h 41h) would pass the first rule and are one high byte per
        ASCII byte, which fails the second.

    And what it cannot notice, said here rather than found later: Japanese
    written only in half-width katakana (A1h..DFh, single bytes) satisfies
    the band and is filed as cp437 art; a text whose only accents are among
    Mazovia's eighteen bytes is filed as Mazovia, because that probe stands
    first (Spanish `á í ó ú ñ` are all eighteen-shared -- a Spanish DOS text
    is filed as Polish, and that is the order's cost); and a file that
    decodes as UTF-8 is handed to the UTF-8 probe before anything here is
    asked, because `é` in UTF-8 is C3h A9h -- a band byte and a sign -- and
    would otherwise be art.

    Returns (band, word, alnum) or None.
    """
    if not b or not any(x >= 0x80 for x in b):
        return None
    if _utf8_text(b):
        return None
    band = word = alnum = 0
    last = len(b) - 1
    prev_lead = False
    for i, x in enumerate(b):
        if x < 0x80:
            prev_lead = False
            if 32 <= x < 127:
                if chr(x).isalnum():
                    alnum += 1
            elif x in (9, 10, 13) or (x == DOS_EOF and i == last):
                pass
            else:
                return None
            continue
        if prev_lead:
            return None
        if CP437_BOX_LOW <= x <= CP437_BOX_HIGH:
            band += 1
            prev_lead = False
        elif x in CP437_LETTERS or x in CP437_SIGNS:
            word += 1
            prev_lead = x < 0xA0
        else:
            return None
    if word * 4 > alnum:
        return None
    return band, word, alnum


def _cp437_art(b):
    """cp437 text that draws: at least one byte of the box-and-shading band."""
    r = _cp437_scan(b)
    return bool(r) and r[0] > 0


def _cp437_text(b):
    """cp437 text that only writes: accented letters or signs, no frames.
    Stands AFTER `_mazovia_text` in MAGICS -- see `_cp437_scan`."""
    r = _cp437_scan(b)
    return bool(r) and r[0] == 0 and r[1] > 0


def _hxg(b):
    """The HXG container of HEXXAGON (Argo Games, 1993), by its arithmetic.

    The format carries no textual magic. It carries something better: a `u16`
    count, `count` records of fourteen bytes, and three closures that a file
    does not satisfy by accident -- the directory ends exactly where the data
    begins, every member's offset plus its stored length is the next member's
    offset, and the last member ends on the last byte of the file. On
    `GRAPHICS.HXG` that is 452 records and 451 chained links at residue zero
    twice.

    The bucket is **DERIVED**, and the reason is worth stating because the
    object argues the other way. `HEXXAGON.DOC` has a section called
    TECH-WEENIE STUFF in which the programmer names the four tools he wrote and
    describes his own compressor as using "a vaguely LZSS-like method". That is
    a named producer, contactable in 1993, writing about his own format -- and
    **it is still not a specification.** It names no field, no offset and no
    byte. Prose about a format is evidence; a document an implementer can work
    from is a warrant. The DERIVED test asks whether this session can name a
    public account of the format, and the answer here is no. See
    `tools/hxg.py`, whose docstring carries the grammar and the counts.

    NOTE THE WEAKER WARRANT. This classifier reads a 512-byte head, which is
    36 records and 35 links. That is the first closure and every link that
    fits, and it is NOT the third closure, which needs the file's length.
    `hxg.py --validate` is the full test; this is what a head-reading
    classifier can honestly claim, and the difference is said out loud rather
    than papered over.
    """
    return hxg.looks_like_hxg_head(b)


def _pif(b):
    """A Windows 3.x Program Information File, by its section chain.

    369 bytes of standard section, then a chain of 22-byte headers beginning
    with `MICROSOFT PIFEX`, whose lengths account for every byte of the file.
    `HEXX.PIF` is 995 bytes and closes exactly; `pc-baronbaldric-doc/docs/04`
    did the same arithmetic on a 545-byte one.

    The bucket is SPECIFIED, and the warrant is **cited and not
    re-established here**: `pc-baronbaldric-doc/docs/04` states that the PIF
    layout is published by Microsoft and reads every field from it. This
    repository holds no copy of that document and does not claim to have
    checked one. See `tools/pif.py`, which is that repository's parser.
    """
    return pif.is_pif(b)


def _hxg_board(b):
    """A HEXXAGON board file, by its own arithmetic.

    1,690 bytes of 169 ten-byte records, of which exactly 108 carry the
    off-board sentinel in word 3 -- leaving 61, which is the number of hexes
    on a Hexxagon board. **The extension does not decide anything**: these are
    called `.HXG` and so is the 626 KB container, and `_hxg` and this test
    refuse each other's files. DERIVED, for the same reason as `_hxg`: the
    game wrote these and nobody described them. See `tools/hxgsave.py`.
    """
    return hxgsave.is_board(b)


def _hxg_config(b):
    """HEXXAGON's 22-byte settings file: `HXG\\0`, seven little-endian words,
    `HXG\\0`. A format that brackets itself, and 4 + 14 + 4 = 22 with no
    residue. DERIVED. What the seven words mean is not established anywhere,
    and `hxgsave.py` says so when it prints them."""
    return hxgsave.is_config(b)


def _bmb(b, size=None):
    """A Tecnoart `.BMB` image or `.BMA` animation (BIANCO NATALE, 1994), by
    the arithmetic in `tools/bmb.py`: `u16 w`, `u16 h`, a flag byte that is
    the ASCII letter y or n, a frame count on the animation, then w x h x
    frames bytes of 8-bit pixels, a 768-byte 6-bit VGA palette if the flag
    says y, and a four- or six-byte trailer -- and the sum lands on the last
    byte of the file, on 16 of 16 files in the object.

    THE WEAKER WARRANT, STATED. A 320 x 200 `.BMB` is 64,777 bytes and this
    classifier reads a 4,096-byte head. From the head alone it can check five
    bytes: two sides that fit a VGA screen and a flag byte that is y or n.
    **That is the whole head-only test**, and it cannot tell one image from a
    strip of frames. This probe therefore asks the classifier for the file's
    length as well -- the first probe in this table to do so, and the
    mechanism is the `wants_size` mark below -- and with the length it makes
    the closure, which decides `.BMB` against `.BMA` and refuses a file one
    byte off. What it still cannot see is the palette (every byte <= 0x3F)
    and the trailer. `bmb.py --validate` is the full test.

    The bucket is DERIVED. Nobody published this format; the only account of
    it outside this repository is the symbol names the producer's linker left
    behind in `BN.EXE` (`_BMBimage_in`, `save_pal`, `x_bob`, `y_bob`), and a
    name in a symbol table is not a specification.
    """
    return bmb.looks_like_head(b, size)


_bmb.wants_size = True


def _fnt(b, size=None):
    """FONT8X12.FNT of BIANCO NATALE: 96 cells of 8 x 12 at one byte per
    pixel, three byte values, cell 0 blank. See `tools/fnt.py`. The head is
    4,096 of 9,216 bytes; with the length the probe insists on 9,216, and
    without it on the three values and the blank first cell over what it was
    given. DERIVED, for the same reason as `_bmb`."""
    return fnt.looks_like_head(b, size)


_fnt.wants_size = True


def _mz(b, size=None):
    """An MZ executable, by the header behind the two letters and not by the
    letters alone.

    THE DEFECT THIS REPAIRS, WHICH IS THE OPPOSITE OF THE LAST ONE. On
    `pc-bianconatale-doc` the `.BMB` magic was too WEAK to fire from a head
    and was given the file's length. On `pc-outrun-doc` `_is(b"MZ")` fired on
    `CORV.PES`, `CHEVY.PES` and `BEETLE.PES`, three files with sprite names,
    and the pre-briefing filed the hit as a false positive: two ASCII bytes,
    a test too STRONG. It was not a false positive. All three ARE MZ images
    -- Microsoft EXEPACK'd, Microsoft C, the game's three video engines
    (docs/03) -- and the classifier was right for the wrong reason: a test
    that fires on two letters would have said the same of a text file that
    begins "MZ". So this probe reads what the letters promise: `e_cblp` below
    512, `e_cp` above 0, a header of at least 28 bytes that also holds the
    relocation table (`e_lfarlc + 4 * e_crlc <= header`), and a declared
    image at least as long as the header and -- when the length is handed
    over -- no longer than the file. OUTRUN.EXE and the three engines pass;
    "MZ" followed by prose does not, and the selftest fires that control.
    """
    if len(b) < 0x1c or b[:2] != b"MZ":
        return False
    e_cblp, e_cp, e_crlc, e_cparhdr = struct.unpack_from("<4H", b, 2)
    e_lfarlc = struct.unpack_from("<H", b, 0x18)[0]
    hdr = e_cparhdr * 16
    if e_cblp >= 512 or e_cp == 0 or hdr < 0x1c:
        return False
    declared = (e_cp - 1) * 512 + e_cblp if e_cblp else e_cp * 512
    if declared < hdr:
        return False
    if e_lfarlc < 0x1c or e_lfarlc + 4 * e_crlc > hdr:
        return False
    if size is not None and declared > size:
        return False
    return True


_mz.wants_size = True


def _pes(b, size=None):
    """The .PES / .PCS shape container of OUT RUN (SEGA / Unlimited Software
    Inc., 1989), by `tools/pes.py`: bit 7 of byte 0 set and a stage count of
    1 or 2 under it, a first stage of pack type 1 or 2, and -- for type 2,
    which every member here uses -- a canonical Huffman count table whose
    Kraft sum is exactly 1.0 over distinct symbols. THE WEAKER WARRANT: a
    head cannot run the two decompression stages to the declared sizes;
    `pes.py --census` does, 93 of 93. DERIVED: the grammar was read out of
    the game's own decoder in the unpacked EGA engine (docs/04), and nobody
    published it."""
    return pes.looks_like_head(b, size)


_pes.wants_size = True


def _forgedat(b, size=None):
    """GAME.DAT of THE DEMON'S FORGE (Mastertronic, 1987; "Dos Driver by
    Mok"), by `tools/forgedat.py`: a 49-byte ASCII signature at 0, a boot
    sector at 0x200 carrying `* Boot error *`, and at 0x400 a directory of
    12-byte records whose bodies chain a*512+c end-to-start to an all-zero
    terminator, the last inside the file's length. The 4,096-byte head holds
    the whole 121-record directory. DERIVED: the picture grammar was read out
    of the game's own drawing interpreter (docs/03); nobody published it."""
    return forgedat.looks_like_head(b, size)


_forgedat.wants_size = True


def _res(b, size=None):
    """The .RES container of TEENAGENT (Metropolis Software House, 1994-1995;
    Union Logic Software Publishing), by `tools/res.py`: `u32 count`, then
    `count + 1` monotonic u32 offsets whose first is 4 + 4 (count + 1) and
    whose last is the file's length. The 4,096-byte head holds a directory
    of up to 1,022 members (the largest here, LAN_500.RES, has 492). A head
    cannot decode a member; `res.py --census` does, 1,053 of 1,053 named by
    kind. DERIVED: the engine's loader at code 0B0D4h reads the same two
    offsets (docs/03); nobody published the container."""
    return res.looks_like_head(b, size)


_res.wants_size = True


# ---------------------------------------------------------------------------
# Four probes added on pc-polanie-doc. The object was 91.2838 % OPAQUE with
# a full table at residue 0: one Autodesk FLC of 11,090,932 bytes (74.15 %
# alone), eighteen Scream Tracker 3 modules, the game's own 6-byte-head
# pictures, a packed .COM, and a text file in the Mazovia code page. Two of
# the four are public formats and file as SPECIFIED; two are this session's
# and file as DERIVED. PAL.DAT and SETUP.PAL (768 n bytes of palette, no
# magic) stay OPAQUE on purpose: a probe that fires on "a multiple of 768"
# is not a probe.
# ---------------------------------------------------------------------------

def _flc(b, size=None):
    """Autodesk Animator Pro FLC (public): u32 at 0 = the file length, magic
    0xAF12 at 4, 128-byte header, depth 8. `flc.py` walks the frames; this
    only reads the head, and the length closure is what makes the magic a
    magic and not two bytes. The 12-byte-header variant (u32 = 12) is
    bfflic.py's and is NOT this."""
    if len(b) < 128 or size is None:
        return False
    length, magic = struct.unpack_from("<IH", b, 0)
    return magic == 0xAF12 and length == size and length > 128


_flc.wants_size = True


def _s3m(b):
    """Scream Tracker 3 module (public): `SCRM` at 2Ch, 1Ah at 1Ch, type 16
    at 1Dh. What follows the module's own bytes is not the probe's business;
    on Polanie it is a copy of the packed engine, which `s3m.py` reads."""
    return len(b) >= 0x30 and b[0x2C:0x30] == b"SCRM" and b[0x1C] == 0x1A \
        and b[0x1D] == 16


def _graf(b, size=None):
    """The 6-byte-head raw 8-bit picture of Polanie (1996), by `graf.py`:
    u16 L = 6 + (w+1)(h+1), u16 w (the stride), u16 h; one image closing on
    the file, or 33,000-byte slots. DERIVED: no signature, no published
    description; the stride was settled by rendering (docs/04)."""
    return graf.looks_like_head(b, size)


_graf.wants_size = True


def _comstub(b):
    """A .COM packed by the stub read out of Polanie's CRACK.COM (jmp 015Fh,
    161 bytes of loader and LZ decoder at 015Fh), by `comunpack.py`.
    DERIVED: the stub carries no name and none is claimed."""
    try:
        comunpack.parse(b)
    except comunpack.Refused:
        return False
    return True


# ---------------------------------------------------------------------------
# Nine probes added on pc-bumpy-doc (Loriciel, 1992): six for formats read
# out of the game's own loader and blitter, three for release furniture.
# ---------------------------------------------------------------------------

def _bumpack(b):
    """The 12-byte compressed head of BUMPY's .VEC/.BUM/.DEC/.PAV, read out
    of the decompressor at 0C28h:0000 of BUMPY.EXE by `bumpack.py`: u32 BE
    unpacked length, u32 BE, u16 BE method (4 or 12, bit 15 = last stage),
    u16 BE = the XOR of the five words. DERIVED: the XOR closes on 38 of 38
    files in that object and on nothing else this table has met."""
    return bumpack.looks_like_head(b)


def _vecscreen(b, size=None):
    """BUMPY's 32,099-byte screen in the clear (SCORE.VEC): 51 zero bytes,
    48 DAC bytes all below 64, then 32,000 bytes of four EGA planes.
    DERIVED from the palette loader at 0AB9h:0677h and the first render."""
    if size != vecscreen.SCREEN or len(b) < 99:
        return False
    return not any(b[:51]) and all(v < 64 for v in b[51:99]) and any(b[51:99])


_vecscreen.wants_size = True


def _bumsprite(b, size=None):
    """BUMPY's sprite bank (BUMSPJEU.BIN, FLECHE.BIN): a 512-entry u32 BE
    table whose first entry is 12, then a record head at 2,048 whose h1 is
    3 and whose h4 is a multiple of 4 -- as the bank setup at 0CECh:0C34h
    reads it (`bumsprite.py`). DERIVED."""
    if size is None or size < 2060 or len(b) < 2060:
        return False
    if struct.unpack_from(">I", b, 0)[0] != 12:
        return False
    h = struct.unpack_from(">6H", b, 2048)
    return h[1] == 3 and h[4] % 4 == 0 and h[4] and h[5] and 2060 + h[4] * 2 * h[5] <= size


_bumsprite.wants_size = True


def _carfont(b):
    """BUMPY's .CAR font: first char, last char, cell w and h in 1..16, and
    the first u16 BE offset equal to the end of the offset table. DERIVED;
    read by `carfont.py`."""
    if len(b) < 8 or b[1] < b[0] or not (1 <= b[2] <= 16 and 1 <= b[3] <= 16):
        return False
    n = b[1] - b[0] + 1
    return struct.unpack_from(">H", b, 6)[0] == 6 + 2 * n


def _bumlevel(b, size=None):
    """BUMPY's level grid left in the clear (D6.BUM, D9.BUM): 2 + n x 194
    bytes, n in 1..32, every byte of the first platform's three 8 x 6
    tables below 64. DERIVED, and weak: it is a length and a value range,
    which is why it stands last among the binary probes."""
    if size is None or size < 196 or (size - 2) % bumlevel.BUM_REC:
        return False
    n = (size - 2) // bumlevel.BUM_REC
    return 1 <= n <= 32 and all(v < 64 for v in b[2:146])


_bumlevel.wants_size = True


def _queldisk(b, size=None):
    """BUMPY's QUELDISK: the letter of the disk in the drive and a DOS
    end-of-file mark. The loader at cs:74D5 reads it and compares byte 0
    with the record's disk letter; 'z' means never ask. DERIVED."""
    return size == 2 and len(b) == 2 and b[0] in b"abz" and b[1] == 0x1A


_queldisk.wants_size = True


def _thedraw(b):
    """A screen compiled to a .COM by TheDraw (TheSoft Programming Services,
    a published DOS tool): a short jump and the text `TheDraw COM file
    Screen` at offset 9."""
    return b[:1] == b"\xEB" and b[9:32] == b"TheDraw COM file Screen"


def _cpav_chklist(b, size=None):
    """Central Point Anti-Virus's CHKLIST.CPS: 27-byte records of an 8.3
    name, NUL-padded to 10, and 17 bytes of checksum ending FF FF. The
    record's arithmetic is not published and not derived: DERIVED on the
    shape alone, one record per 27 bytes."""
    if size is None or size % 27 or size == 0 or len(b) < 27:
        return False
    name = b[:10]
    return (b"." in name and name.rstrip(b"\0").isascii() and name[-1] == 0
            and b[25:27] == b"\xff\xff")


_cpav_chklist.wants_size = True


def _adlibbnk(b, size=None):
    """An Ad Lib instrument bank (Ad Lib Inc., published): `ADLIB-` at 2,
    and the offsets and counts closing on the file: names at 28, data at
    28 + 12 x total, end at data + 30 x total."""
    if len(b) < 28 or b[2:8] != b"ADLIB-" or size is None:
        return False
    used, total, on, od = struct.unpack_from("<HHII", b, 8)
    return on == 28 and od == 28 + 12 * total and size == od + 30 * total and used <= total


_adlibbnk.wants_size = True


_MAZOVIA = frozenset((0x86, 0x8D, 0x91, 0x92, 0xA4, 0xA2, 0x9E, 0xA6, 0xA7,
                      0x8F, 0x95, 0x90, 0x9C, 0xA5, 0xA3, 0x98, 0xA0, 0xA1))


def _mazovia_text(b):
    """Text whose only high bytes are the eighteen Polish letters of the
    Mazovia code page (a public DOS code page; `level.py` decodes it). The
    test that makes it a probe: at least one such byte, and NO high byte
    outside the eighteen -- cp852 puts ą at A5h and ć at 86h, so a cp852
    file with both fails here on its ą."""
    if not b or not any(x >= 0x80 for x in b):
        return False
    return all(32 <= x < 127 or x in (9, 10, 13) or x in _MAZOVIA for x in b)


def _text_ok(s):
    """Every character of a decoded head is printable, a tab / CR / LF, or a
    Unicode SPACE SEPARATOR (general category Zs).

    THE DEFECT THIS REPAIRS, THE SIXTH OF ITS CLASS (a codec probe that
    cannot fail, or here: one that fails on a character that is text)
    ----------------------------------------------------------------------
    On pc-thewardrobe-doc five UTF-8 XML files carry U+00A0 NO-BREAK SPACE
    (French typography puts one before `?`, `!` and `:`; `fra\\dialogs\\
    morpheus.xml`, `fra\\locations\\cripta.xml`, `fra\\locations\\studio.xml`,
    `fra\\objects\\viagra.xml`, `deu\\dialogs\\morpheus.xml`). `'\\xa0'.
    isprintable()` is False -- Python's definition of printable excludes
    every separator but U+0020 -- so the three text probes, which demanded
    that every character be printable or one of `\\t\\r\\n` and U+3000, refused
    the five. Two went OPAQUE; three were then handed to `_cp437_art`, where
    `C2 A0` is a box-drawing byte and a letter, and were filed as cp437 art.
    The byte-order-mark repair on pc-rpgmakermv-doc was the same defect one
    code point over, and it was repaired for that one code point only.

    The repair admits the whole category rather than one more literal: Zs
    is U+0020, U+00A0, U+1680, U+2000..U+200A, U+202F, U+205F and U+3000 --
    seventeen code points that are spaces by the Unicode Character
    Database. Line and paragraph separators (Zl, Zp) and the format
    characters (Cf: U+200B ZERO WIDTH SPACE, U+FEFF) are NOT admitted: a
    U+FEFF anywhere but the head still counts against the file, as before.
    All three text probes (`_cp932_text`, the UTF-16 probe, `_codec_text`)
    now share this one test, so the next such character is one edit.
    """
    return all(c.isprintable() or c in "\t\r\n"
               or unicodedata.category(c) == "Zs" for c in s)


def _cp932_text(b):
    """Text in a multi-byte codepage, and the test is that the codec REFUSES
    other things.

    A single-byte codepage cannot fail, so cp437 or cp866 "decoding" a file is
    no evidence at all. cp932 is a multi-byte codec with illegal sequences: a
    file of 8,899 high bytes that decodes under it with no illegal sequence,
    and whose decoded text is printable, is a Shift-JIS document, and a random
    byte stream is not. That asymmetry is the whole test and it is why this
    probe names cp932 and not the single-byte candidates.
    """
    if not b or not any(x >= 0x80 for x in b):
        return False
    try:
        s = b.decode("cp932")
    except UnicodeDecodeError as e:
        # A probe reads a fixed-size head, so the last sequence may be cut in
        # half. That is the probe's fault and not the file's: retry once
        # without the truncated tail. A failure anywhere earlier is the file's
        # and stands.
        if e.start < len(b) - 2:
            return False
        try:
            s = b[:e.start].decode("cp932")
        except UnicodeDecodeError:
            return False
    return _text_ok(s)


# Ruby's Marshal type characters, one byte each. A document is `04 08` -- major
# 4, minor 8 -- followed by exactly one of these. Two bytes alone are far too
# weak a signature to file 503,787 bytes on, so the probe reads the third byte
# too and rejects anything the grammar cannot start with. This is the same
# discipline as the length-prefixed LCF probes below and for the same reason.
MARSHAL_TYPES = set(b"0TFilfu:;\"I[{}oUCSc/me@dM'")


def _marshal48(b):
    return len(b) >= 3 and b[0] == 0x04 and b[1] == 0x08 and b[2] in MARSHAL_TYPES


def _ogg(b):
    # RFC 3533: a page begins 'OggS', then a version byte which is 0 in every
    # Ogg ever shipped. Checking it costs one byte and stops a file that merely
    # opens with the four letters.
    return b.startswith(b"OggS") and len(b) > 4 and b[4] == 0


# ---------------------------------------------------------------------------
# Five binary magics and two text codecs added on pc-rpgmakervxace-doc, where
# their absence put 44,113,740 bytes -- 12.8716 % of the object -- in the
# OPAQUE bucket, AND put one 328,733-byte PDF in the SPECIFIED bucket under the
# name `plain text, Shift-JIS`. That is the THIRD appearance of this table's
# defect and the FIRST in which it produced a confident wrong answer rather
# than a silence, which is a different and worse failure.
#
# THE ORDERING RULE, which is the actual repair:
#
#   every binary signature is tested before every text codec.
#
# A single-byte-per-char text codec cannot fail on arbitrary bytes, and a
# multi-byte one fails only on illegal sequences -- and a PDF header is 512
# bytes of ASCII punctuation that cp932 accepts without one. So a text probe
# placed above a binary signature does not merely miss: it CLAIMS. The rule is
# enforced by `_ordering_ok()` below and asserted in the selftest, so that a
# future edit that appends a magic after the text probes fails loudly.

def _sfnt(b):
    """A TrueType/OpenType font.

    `00 01 00 00` is sfnt version 1.0. THE HAZARD IS ONE BYTE AWAY: a Windows
    icon begins `00 00 01 00`, which is already in this table, and a careless
    probe swaps them. Both orderings are asserted in the selftest.
    """
    return (b.startswith(b"\x00\x01\x00\x00")
            or b.startswith(b"OTTO")
            or b.startswith(b"true")
            or b.startswith(b"ttcf"))


def _bmp(b):
    """A Windows bitmap.

    `BM` alone is two ASCII letters and would claim any text file beginning
    'BMW'. The header carries its own file size at offset 2 as a little-endian
    u32 and a reserved u32 of zero at offset 6; requiring the reserved field to
    be zero and the declared size to be at least the 14-byte file header makes
    the signature six bytes instead of two.
    """
    if not b.startswith(b"BM") or len(b) < 14:
        return False
    size = int.from_bytes(b[2:6], "little")
    reserved = int.from_bytes(b[6:10], "little")
    return reserved == 0 and size >= 14


def _pdf(b):
    return b.startswith(b"%PDF-")


def _zip(b):
    # PKWARE APPNOTE: local file header, central directory, or empty archive.
    return (b.startswith(b"PK\x03\x04")
            or b.startswith(b"PK\x05\x06")
            or b.startswith(b"PK\x07\x08"))


def _utf16_text(b):
    """UTF-16 text behind a byte-order mark, little- or big-endian.

    THE DEFECT THIS REPAIRS, THE FIFTH OF ITS CLASS (cp932 on pc-bumpy-doc,
    pc-hexxagon-doc, ...): on pc-losthorizon-doc three UTF-16LE text files
    (`configtool.dat`, `errormsg.dat`, `version.dat` -- `FF FE 43 00 6F 00`,
    "Co...") were filed as `MPEG-1/2 Audio`, because a `FF FE` byte-order mark
    has eleven set bits in a row and the MPEG probe below asked for nothing
    beyond one frame header. A codec probe that cannot fail is not a probe.

    Two repairs, and this is the first: a UTF-16 probe that stands BEFORE the
    MPEG one. It is a SIGNATURE probe (the BOM is required) and not a text
    codec, which is why it lives among the binary magics and not after the
    text-codec line: `FF FE` and `FE FF` collide with no signature in this
    table. WHAT IT CANNOT NOTICE (P19): a UTF-16 file WITHOUT a BOM is not
    claimed and falls through (to OPAQUE, usually); and a random binary that
    opens `FF FE` and whose every 16-bit word is a printable code point would
    be claimed -- over a 4,096-byte head that is 2,047 words, and the CJK
    blocks make a single random word printable more often than not, so the
    hazard is real only for files of a few bytes.
    """
    if len(b) < 4:
        return False
    if b[:2] == b"\xff\xfe":
        codec = "utf-16-le"
    elif b[:2] == b"\xfe\xff":
        codec = "utf-16-be"
    else:
        return False
    body = b[2:]
    if len(body) % 2:
        body = body[:-1]                     # a head cut in the middle of a word
    try:
        s = body.decode(codec)
    except UnicodeDecodeError as e:
        if e.start < len(body) - 4:          # not a surrogate cut by the head
            return False
        try:
            s = body[:e.start].decode(codec)
        except UnicodeDecodeError:
            return False
    if not s:
        return False
    return _text_ok(s)


# MPEG-1/2 Audio frame arithmetic (ISO/IEC 11172-3 / 13818-3): the second
# repair for the `FF FE` misfiling is that the probe now COMPUTES the length
# of the frame the header describes and wants another sync word there.
_MPEG_BITRATES = {
    # (version index, layer index) -> kbit/s by bitrate index 1..14
    (3, 3): (32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448),
    (3, 2): (32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384),
    (3, 1): (32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
    (2, 3): (32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256),
    (2, 2): (8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
    (2, 1): (8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
}
_MPEG_RATES = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000),
               0: (11025, 12000, 8000)}


def _mpeg_frame_length(b, at=0):
    """The byte length of the MPEG audio frame whose header is at `at`, or 0
    when the four bytes there are not a legal header. Version 01 (reserved),
    layer 00, bitrate 0000 (free) and 1111, sampling-rate 11 are refused."""
    if len(b) < at + 4 or b[at] != 0xFF or (b[at + 1] & 0xE0) != 0xE0:
        return 0
    version = (b[at + 1] >> 3) & 0x03
    layer = (b[at + 1] >> 1) & 0x03
    bitrate = (b[at + 2] >> 4) & 0x0F
    rate = (b[at + 2] >> 2) & 0x03
    padding = (b[at + 2] >> 1) & 0x01
    if version == 1 or layer == 0 or bitrate in (0, 15) or rate == 3:
        return 0
    kbps = _MPEG_BITRATES[(3 if version == 3 else 2, layer)][bitrate - 1]
    hz = _MPEG_RATES[version][rate]
    if layer == 3:                                       # Layer I
        return (12 * kbps * 1000 // hz + padding) * 4
    if layer == 2 or version == 3:                       # Layer II, MPEG-1 Layer III
        return 144 * kbps * 1000 // hz + padding
    return 72 * kbps * 1000 // hz + padding              # MPEG-2/2.5 Layer III


def _mpeg_audio(b, size=None):
    """MPEG-1/2 Audio, with or without an ID3v2 tag in front of it.

    An ID3v2 tag is a published container (`ID3`, a version byte below 0xFF,
    flags, and a syncsafe size whose four bytes each have bit 7 clear). A bare
    stream begins with a frame header whose first eleven bits are set. Eleven
    set bits alone occur once every 2,048 random bytes, so the probe checks the
    four fields that CANNOT hold their reserved value in a real frame: version
    01, layer 00, bitrate index 1111 and sampling rate 11 are all illegal.

    AND THAT WAS NOT ENOUGH. On pc-losthorizon-doc a UTF-16 byte-order mark
    `FF FE` followed by an ASCII letter passed all four field tests (version
    11, layer 11, bitrate 5, rate 2 for `FF FE 5B`) and three text files were
    filed as audio. A frame header states its own length; a real stream has
    another header exactly there. So a bare stream is now accepted only when
    a second legal header with the same version and layer bits stands at the
    length the first one computes -- or, when the file's length is known, when
    the first frame ends exactly at the last byte (a one-frame file). A header
    with nothing after it is refused. `_utf16_text` also stands before this
    probe in MAGICS; both repairs are asserted in the selftest.
    """
    if b.startswith(b"ID3") and len(b) >= 10:
        if b[3] == 0xFF or b[4] == 0xFF:
            return False
        return all(x < 0x80 for x in b[6:10])
    n = _mpeg_frame_length(b, 0)
    if n == 0:
        return False
    if size is not None and n == size:
        return True
    if _mpeg_frame_length(b, n) == 0:
        return False
    return (b[1] & 0x1E) == (b[n + 1] & 0x1E)            # same version and layer


_mpeg_audio.wants_size = True


def _spcr(b, size=None):
    """An FSAS `SPCR` archive (Fusionsphere Systems' engine, LOST HORIZON,
    2010), selected by the ONE closure its head offers for free.

    56-byte head: `SPCR`, u32 0, u32 (a word: 223, 115, 83, 251, 211 on the
    six seen), u32 0, u32 0, then three (u32 count, u32 offset, u32 size)
    triples naming three tables that sit at the END of the file. The closure:
    every table begins at or after +56, the three tile each other (sorted by
    offset, each begins where the previous ends) and the last ends exactly at
    the file's last byte -- true on 6 of 6 archives, 4,030,829,851 bytes,
    99.75 % of that object. The payloads from +56 to the first table are what
    `spcr.py` walks by magic (Bink, Ogg, Lua 5.0, PNG, DDS, SLZX).

    WHAT THIS PROBE DOES NOT SAY, and the docs must not say either: that the
    archive is READ. The three tables are high-entropy bytes (7.5-8.0 bits per
    byte) and nobody has decoded them; the closure is a statement about where
    they are, not what they hold. The bucket is DERIVED because the shape was
    worked out of the bytes on that object and no public account of the FSAS
    `.spr` is known to this box. It asks for the file's length because a head
    cannot see the last byte.
    """
    if size is None or len(b) < 56 or not b.startswith(b"SPCR"):
        return False

    def u32(o):
        return int.from_bytes(b[o:o + 4], "little")

    if u32(4) != 0 or u32(12) != 0 or u32(16) != 0:
        return False
    tables = [(u32(20 + 12 * i), u32(24 + 12 * i), u32(28 + 12 * i))
              for i in range(3)]
    for _count, off, sz in tables:
        if off < 56 or off + sz > size:
            return False
    by_offset = sorted(tables, key=lambda t: t[1])
    for prev, nxt in zip(by_offset, by_offset[1:]):
        if prev[1] + prev[2] != nxt[1]:
            return False
    last = by_offset[-1]
    return last[1] + last[2] == size


_spcr.wants_size = True


def _codec_text(codec, need_high=True):
    """A text probe for one multi-byte codec, built the same way `_cp932_text`
    is built and for the same reason: the test is that the codec REFUSES other
    things.

    WHAT THIS PROBE CANNOT NOTICE, named in advance per P19: **a codec
    accepting a file is not proof the file is in that codec.** EUC-JP and cp932
    overlap -- EUC-JP's lead bytes 0xA1..0xFE are cp932's single-byte
    half-width katakana -- so a EUC-JP document decodes under cp932 without one
    illegal sequence, into nonsense. No probe of this shape can tell them
    apart, and the order of the three text codecs in MAGICS is therefore a
    DECISION and not a measurement. `coverage.py ambiguity --root R` counts how
    many files more than one codec accepts, so that the decision's cost is a
    published number rather than a hidden one.
    """
    def probe(b):
        if not b:
            return False
        if need_high and not any(x >= 0x80 for x in b):
            return False
        try:
            s = b.decode(codec)
        except UnicodeDecodeError as e:
            if e.start < len(b) - 5:
                return False
            try:
                s = b[:e.start].decode(codec)
            except UnicodeDecodeError:
                return False
        if not s:
            return False
        # THE ONE-CHARACTER DEFECT, repaired on pc-rpgmakermv-doc.
        # U+FEFF is a byte-order mark, `'﻿'.isprintable()` is False, and
        # a UTF-8 file carrying one therefore failed this probe on its first
        # character. On that object it filed 190 files and 1,108,362 bytes as
        # OPAQUE and 0 of 190 got through, so the failure was total for that
        # population rather than partial. A leading byte-order mark is a
        # signature and not a character: it is removed before the text is
        # judged, and a U+FEFF anywhere else still counts against the file.
        if s[:1] == "﻿":
            s = s[1:]
        if not s:
            return False
        # THE SEVENTEEN-CHARACTER DEFECT, repaired on pc-thewardrobe-doc:
        # see `_text_ok`. U+00A0 is a space and `isprintable()` says no.
        return _text_ok(s)
    return probe


_utf8_text = _codec_text("utf-8")
_eucjp_text = _codec_text("euc_jp")


# ---------------------------------------------------------------------------
# Five magics added on pc-rpgmakermv-doc. Four of the five are for formats no
# object in this collection had produced in seventy-nine objects -- MPEG-4
# audio, ELF, Mach-O and the Unix archive -- and together with the fifth they
# were 875,590,414 bytes of the OPAQUE bucket while the tool closed at residue
# 0 and printed a full table. Third appearance of that shape of defect.
# ---------------------------------------------------------------------------

def _mp4(b):
    """ISO/IEC 14496-12: a big-endian box size, then the four bytes `ftyp`.

    Four letters at offset 4 is a weaker signature than any other entry in this
    table, so the size word in front of them is checked too. A File Type Box
    carries a major brand, a minor version and at least one compatible brand,
    which is 16 bytes at the very least, and no File Type Box in the wild is a
    kilobyte long.
    """
    if len(b) < 12 or b[4:8] != b"ftyp":
        return False
    size = int.from_bytes(b[:4], "big")
    return 16 <= size <= 1024


def _elf(b):
    """The System V ABI's `e_ident`: the magic, then class, data and version.

    Reading three bytes past the magic costs nothing and refuses a file that
    merely opens with 7F 45 4C 46: EI_CLASS is 1 or 2, EI_DATA is 1 or 2, and
    EI_VERSION has been 1 since the standard was written.
    """
    return (len(b) >= 7 and b[:4] == b"\x7fELF"
            and b[4] in (1, 2) and b[5] in (1, 2) and b[6] == 1)


_MACHO_THIN = (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
               b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
_MACHO_FAT = (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")


def _macho(b):
    """Mach-O, in its four thin forms and its two fat ones.

    THE ONE-BYTE HAZARD OF THIS OBJECT, and it is a four-byte one: the
    universal binary's magic **0xCAFEBABE is also a Java class file's**. They
    are separated by the next four bytes and by nothing else. Mach-O puts
    `nfat_arch` there -- the number of architectures in the archive, which is
    one or two in practice and has never been twenty. A class file puts
    `minor_version` then `major_version`, read together as a big-endian word;
    `major_version` has been at least 45 since Java 1.0 in 1996, so the
    smallest class file value is 45 and the ranges do not touch.

    A tool that filed a Java class file as a Mach-O executable would be wrong
    in a way that no byte count would reveal, which is why this is a check and
    not a comment.
    """
    if len(b) < 8:
        return False
    if b[:4] in _MACHO_THIN:
        return True
    if b[:4] in _MACHO_FAT:
        order = "big" if b[0] == 0xCA else "little"
        return 1 <= int.from_bytes(b[4:8], order) <= 20
    return False


def _ar(b):
    """The Unix archive, POSIX.1-2017 and SVR4, unchanged since 1978."""
    return b.startswith(b"!<arch>\n")


def _chromium_pak(b):
    """Chromium's `.pak` resource container, checked by its own arithmetic.

    The whole signature is a small integer in the first four bytes, which on
    its own would match a great many files. What makes it a signature is that
    the header declares how many entries follow and the entry table's first
    offset must therefore be exactly where the header ends:

        v4   9 + (resources + 1) * 6
        v5  12 + (resources + 1) * 6 + aliases * 4

    Both layouts end with a sentinel entry, which is where the `+ 1` comes
    from, and both index tables are (u16 id, u32 offset). On this object that
    equation holds on 222 of 222 files, so the probe is a structural check and
    not a four-byte guess.

    The bucket is DECODED and the argument is in docs/04: the format is read by
    published source and by several independent third-party implementations,
    and no specification of it exists.
    """
    if len(b) < 20:
        return False
    ver = int.from_bytes(b[:4], "little")
    if ver == 5:
        if b[4] != 1 or b[5:8] != b"\x00\x00\x00":
            return False
        nres = int.from_bytes(b[8:10], "little")
        nali = int.from_bytes(b[10:12], "little")
        if nres == 0:
            return False
        return int.from_bytes(b[14:18], "little") == 12 + (nres + 1) * 6 \
            + nali * 4
    if ver == 4:
        nres = int.from_bytes(b[4:8], "little")
        if b[8] != 1 or nres == 0 or nres > (1 << 20):
            return False
        return int.from_bytes(b[11:15], "little") == 9 + (nres + 1) * 6
    return False


# One magic added on pc-ilgrandegiocoditangentopoli-doc, where its absence put
# 413,058 bytes -- 89.5389 % of the object, the largest opaque share this
# table has ever left standing as a fraction -- in the OPAQUE bucket while the
# tool closed at residue 0 and printed a full table. Fourth appearance of that
# shape of defect, and the first one where the missing format had no
# specification, no vendor and no name outside this repository.
# ---------------------------------------------------------------------------

def _px(b):
    """The `PX` screen format of *Il grande gioco di Tangentopoli*.

    Two letters would be a guess: `PX` turns up by chance in a few kilobytes.
    What makes this a signature is that the geometry is stated TWICE, once in
    the raw header and once inside the compressed stream, and the probe
    decodes far enough to compare them.

        +0   2B   'PX'
        +2   u16  width          +4   u16  height
        +6   ...  a run-length stream, `FF <count> <byte>` or a literal,
                  whose first ten decoded bytes are five little-endian words
                  and whose fourth and fifth words repeat width and height

    Reading ten bytes out of the stream costs nothing and refuses a file whose
    first two bytes happen to spell `PX`. The format has no published
    description, no vendor and no named producer, so the bucket is DECODED and
    the argument for it is in docs/03 -- the DECODED test asks whether the
    PRODUCER published a description, and this object has no producer who
    could have.
    """
    if len(b) < 32 or b[:2] != b"PX":
        return False
    width = b[2] | (b[3] << 8)
    height = b[4] | (b[5] << 8)
    if not (0 < width <= 4096 and 0 < height <= 4096):
        return False
    out = bytearray()
    pos = 6
    while pos < len(b) and len(out) < 10:
        if b[pos] == 0xFF:
            if pos + 2 >= len(b):
                return False
            out.extend(bytes([b[pos + 2]]) * b[pos + 1])
            pos += 3
        else:
            out.append(b[pos])
            pos += 1
    if len(out) < 10:
        return False
    return (out[6] | (out[7] << 8)) == width and \
           (out[8] | (out[9] << 8)) == height


def _ilbm(b):
    """EA IFF 85 / ILBM, and the signature is a STRUCTURE and not four letters.

    `FORM` on its own is a four-byte string that occurs by accident, so what
    is checked here is the whole opening grammar: `FORM`, a big-endian length,
    a known form type, and then a first chunk whose own length fits inside
    that length. Electronic Arts published this in January 1985 and there have
    been independent readers of it for thirty years, so the bucket is
    SPECIFIED -- which is the exact opposite of the `_px` argument three
    entries below, where the format had no vendor who could have published
    anything. `tools/ilbm.py` is this repository's reader.
    """
    if len(b) < 20 or b[:4] != b"FORM":
        return False
    if b[8:12] not in (b"ILBM", b"PBM "):
        return False
    declared = int.from_bytes(b[4:8], "big")
    if declared < 12 or declared > (1 << 31):
        return False
    first = int.from_bytes(b[16:20], "big")
    return 8 <= first + 8 <= declared


def _carte40(b):
    """`CARTE.IMG`: forty Italian cards, four planes of 64 x 101, plane-major.

    THIS ENTRY HAS NO MAGIC NUMBER AND SAYS SO. The file has no header of any
    kind, so what is tested is the SHAPE of its first plane: eight-byte rows,
    a blank first row, and then five rows each of which is one contiguous run
    of set bits whose left edge only moves left and whose right edge only
    moves right. That is the top edge of a rounded rectangle 64 pixels
    across, which is what the top of a playing card looks like from inside.

    The bucket is **DERIVED**, which is the weakest of the three and the right
    one: there is no vendor, no document and no producer -- so SPECIFIED is
    out and so is DECODED, whose test asks whether the producer published a
    description -- and the only warrant this file has is this session's own
    reader, `tools/carte.py`, whose argument is that 129,280 divides by forty
    at residue zero and that the pictures that come out are a Neapolitan deck.

    `--selftest` requires this to REFUSE every other file in the object,
    because a shape test that fires on a palette is worth nothing.
    """
    if len(b) < 48:
        return False
    rows = [b[i * 8:(i + 1) * 8] for i in range(6)]
    if any(byte for byte in rows[0]):
        return False
    left = right = None
    for row in rows[1:]:
        bits = "".join(format(byte, "08b") for byte in row)
        one = bits.find("1")
        if one < 0:
            return False
        last = bits.rfind("1")
        if "0" in bits[one:last]:       # not a single contiguous run
            return False
        if left is not None and (one > left or last < right):
            return False
        left, right = one, last
    return right - left + 1 >= 56


# Added on pc-monstrum-doc (Team Junkfish, Unity 5.5.0f3, 2018): what a
# Unity player build and a GOG Galaxy install leave on disk. `unityfs.py`
# had read the first of these formats since android-talesofluminaria-doc
# and sat in this folder while this table filed 98.28 % of a 2.5 GB object
# as opaque -- nineteen serialized files, seven `.resS` and four
# `.resource` sidecars, a minidump, a Mono symbol file, two Inno leftovers
# and a shortcut, none with a probe. The buckets are decided by the
# format's public standing and say so in each docstring.

def _unity_serialized(b, size=None):
    """A Unity SerializedFile, by its header's own arithmetic and not by a
    name (there is no magic: the file begins with a big-endian metadata
    size).

    Header (versions 5..21, the 32-bit one): u32 BE metadataSize, u32 BE
    fileSize, u32 BE version, u32 BE dataOffset, u8 endianness (0 or 1),
    three reserved bytes, then (version >= 7) the engine version as a C
    string at +20. Version 22 and later move fileSize to an i64 at +24 and
    dataOffset to +32, zeroing the originals; both shapes are read.

    THE CLOSURE is `fileSize == the file's own length`, the free positive
    control this repository asks every container for and that Unity
    supplies on every one; it needs the length, so the probe asks for it.
    Without a length (a bare `classify(blob)`) the probe settles for the
    version range, the endianness byte, dataOffset inside fileSize and an
    engine-version string of digits, dots and one of `abfpx` -- `5.5.0f3`,
    `2019.4.16f1` -- which is what keeps a big-endian integer that happens
    to be small out of this bucket.

    DECODED, not specified: Unity has never published the format; the
    public accounts are third parties' (AssetStudio, UnityPy, disunity),
    and `unityfs.py` beside this file is this box's own reading of it.
    """
    if len(b) < 24:
        return False
    meta, fsize, version, doff = struct.unpack_from(">IIII", b, 0)
    if not 5 <= version <= 30 or b[16] not in (0, 1):
        return False
    if version >= 22:
        if len(b) < 48:
            return False
        meta = struct.unpack_from(">I", b, 20)[0]
        fsize, doff = struct.unpack_from(">qq", b, 24)
        vpos = 48
    else:
        vpos = 20
    if fsize <= 0 or doff <= 0 or doff > fsize or meta == 0:
        return False
    if size is not None and fsize != size:
        return False
    if version >= 7:
        e = b.find(b"\0", vpos)
        if e < vpos + 3 or e > vpos + 40:
            return False
        v = b[vpos:e]
        if not (v[:1].isdigit() and b"." in v
                and all(c in b"0123456789.abfpx" for c in v)):
            return False
    return True


_unity_serialized.wants_size = True


def _fsb5(b, size=None):
    """FMOD Sample Bank 5, by its magic and the header's arithmetic.

    `FSB5`, u32 version (0 or 1), u32 sample count, u32 sample-header
    size, u32 name-table size, u32 data size, u32 codec (0..17 known); the
    header is 60 bytes at version 1 and 64 at version 0, and 60 (or 64) +
    the three sizes is the bank's length. The sample-header block holds at
    least one 64-bit word per sample, so it is at least 8 x the count.

    What the probe closes on with a length: the FIRST bank fits the file.
    A Unity `.resource` file is many banks laid end to end, one per
    AudioClip, and only `fsb5.py walk` can say that the chain ends exactly
    at the file's last byte; this probe says the file begins with a bank
    whose declared length lies inside it, and the docstring says that is
    all it says.

    DECODED: the format is FMOD's and FMOD has not published it; the
    public accounts are third parties' (python-fsb5, vgmstream), and
    `fsb5.py` beside this file reads it from them.
    """
    if len(b) < 64 or b[:4] != b"FSB5":
        return False
    version, n, hdr, names, data, codec = struct.unpack_from("<6I", b, 4)
    if version not in (0, 1) or n == 0 or codec > 17:
        return False
    if hdr < 8 * n:
        return False
    declared = (60 if version == 1 else 64) + hdr + names + data
    if size is not None and declared > size:
        return False
    return True


_fsb5.wants_size = True


def _fev_bank(b, size=None):
    """An FMOD Studio bank: `RIFF`, u32 length, form `FEV `, then chunks.

    THE DEFECT THIS REPAIRS: the RIFF probe above asks for form `WAVE`, and
    a RIFF whose form is anything else fell through to OPAQUE. On
    pc-thewardrobe-doc that was 482 files and 13.09 % of the object -- every
    voice, effect and music bank of the game -- called "not identified" by
    a table that had walked them (`riffwalk.py`: 482 of 482 at residue 0).

    What the probe checks: the four letters, the form, the RIFF length
    equal to the file's length minus eight (a closure on the file, not on
    the head), and a chunk walk over as much of the top level as the head
    reaches -- every chunk id four printable ASCII bytes, every chunk that
    begins in the head ending inside the RIFF length, and the first chunk
    `FMT ` (eight bytes on every bank of that object, sixty of which are
    494-byte shells with no `SND `). What it cannot see, said here: whether
    the walk closes at the LAST byte (the head is 4,096 bytes and a bank is
    up to 86 MB; `riffwalk.py` and `fevbank.py` say that), and whether the
    `SND ` chunk's FSB5 closes (`fevbank.py` hands the offset to
    `fsb5.py`).

    DECODED, and the reason is the FSB5's: the format is FMOD's and FMOD
    has not published it; public third-party readers exist (vgmstream's
    `fsb5_fev` meta reads the `SND ` chunk of exactly this container), and
    `fevbank.py` beside this file reads the chunk tree from the bytes. A
    RIFF `WAVE` is still a WAVE: that probe stands first.
    """
    if len(b) < 20 or b[:4] != b"RIFF" or b[8:12] != b"FEV ":
        return False
    ln = struct.unpack_from("<I", b, 4)[0]
    if size is not None and ln + 8 != size:
        return False
    end = ln + 8
    off, first = 12, None
    while off + 8 <= min(len(b), end):
        cid = b[off:off + 4]
        if not all(32 <= c < 127 for c in cid):
            return False
        cl = struct.unpack_from("<I", b, off + 4)[0]
        if off + 8 + cl > end:
            return False
        if first is None:
            first = cid
        off += 8 + cl + (cl & 1)
    return first == b"FMT "


_fev_bank.wants_size = True


def _mdmp(b, size=None):
    """A Windows minidump (`MINIDUMP_HEADER`, minidumpapiset.h in the
    Windows SDK): `MDMP`, u32 version whose low 16 bits are
    MINIDUMP_VERSION 0xA793 (the high 16 are the writer's), u32 stream
    count, u32 RVA of the stream directory, u32 checksum, u32 time stamp,
    u64 flags. Each directory entry is u32 type, u32 size, u32 RVA.

    With a length: the directory and every stream it lists lie inside the
    file. Without one: the version word and a directory RVA past the
    32-byte header.

    SPECIFIED: Microsoft publishes the structures in the SDK header and
    on its documentation site. `mdmp.py` beside this file lists the
    streams.
    """
    if len(b) < 32 or b[:4] != b"MDMP":
        return False
    version, nstreams, rva = struct.unpack_from("<III", b, 4)
    if version & 0xFFFF != 0xA793 or nstreams == 0 or nstreams > 64:
        return False
    if rva < 32:
        return False
    if size is not None:
        if rva + 12 * nstreams > size:
            return False
        end = min(len(b), rva + 12 * nstreams)
        for i in range(rva, end - 11, 12):
            _t, sz, r = struct.unpack_from("<III", b, i)
            if r + sz > size:
                return False
    return True


_mdmp.wants_size = True


def _mono_mdb(b):
    """A Mono symbol file (`.mdb`): i64 magic 0x45E82623FD7FA614, i32 major
    version 50, i32 minor version 0, then a 16-byte GUID and the offset
    table. The layout is in Mono's own published source
    (`MonoSymbolFile.cs`, `MonoSymbolTable.cs`), which is why it is filed
    as SPECIFIED -- the creator published it, as code and not as a
    document, and that is the whole of the warrant.
    """
    if len(b) < 28:
        return False
    magic, major, minor = struct.unpack_from("<qii", b, 0)
    return magic == 0x45E82623FD7FA614 and major == 50 and minor == 0


def _shllink(b):
    """A Windows Shell Link (`.lnk`): HeaderSize 0x4C, then the CLSID
    00021401-0000-0000-C000-000000000046. SPECIFIED: Microsoft's
    [MS-SHLLINK] open specification.
    """
    return (len(b) >= 0x4C and b[:4] == b"L\0\0\0"
            and b[4:20] == bytes.fromhex("0114020000000000c000000000000046"))


def _inno_unins_log(b):
    """Inno Setup's uninstall log (`unins000.dat`): the 64-byte ID
    `Inno Setup Uninstall Log (b)` (`(b)` = 32-bit records; `(b) (u)`
    for Unicode), NUL-padded, then the 128-byte AppId. SPECIFIED as
    published source: jrsoftware's `Struct.pas`, `TUninstallLogHeader`.
    """
    if len(b) < 64 or not b.startswith(b"Inno Setup Uninstall Log ("):
        return False
    e = b.find(b"\0", 26)
    return 0 < e <= 63 and b[e:64] == bytes(64 - e)


def _inno_msgs(b):
    """Inno Setup's compiled messages (`unins000.msg`): the 64-byte ID
    `Inno Setup Messages (5.6.2) (u)` and, after it, the header of counts
    and a CRC. SPECIFIED as published source: jrsoftware's `Struct.pas`,
    `TMessagesHeader`.
    """
    if len(b) < 64 or not b.startswith(b"Inno Setup Messages ("):
        return False
    e = b.find(b"\0", 21)
    return 0 < e <= 63 and b[e:64] == bytes(64 - e)


def _sidecar_records(body, class_id, names):
    """The (offset, size) stream records in one serialized object's body
    that name one of `names` -- a sibling file ending `.resS` or
    `.resource`.

    Texture2D (28) and Mesh (43) keep `m_StreamData` as u32 offset, u32
    size, then the path as an aligned length-prefixed string, so the two
    words sit at -12 and -8 from the string. AudioClip (83) keeps
    `m_Resource` as the path first, then u64 offset and u64 size after the
    string's 4-byte alignment. The string's own length prefix has to equal
    the name's length, which is what keeps a name that merely occurs in a
    byte sequence from becoming a record. Returns {name: [(offset, size)]}.
    """
    out = {}
    for name in names:
        nb = name.encode("utf-8")
        start = 0
        while True:
            p = body.find(nb, start)
            if p < 0:
                break
            start = p + 1
            if p < 4 or struct.unpack_from("<i", body, p - 4)[0] != len(nb):
                continue
            if class_id == 83:
                q = (p + len(nb) + 3) & ~3
                if q + 16 > len(body):
                    continue
                off, sz = struct.unpack_from("<QQ", body, q)
            else:
                if p < 12:
                    continue
                off, sz = struct.unpack_from("<II", body, p - 12)
            out.setdefault(name, []).append((off, sz))
    return out


def _unity_sidecar_refs(dirpath):
    """Every stream record of every serialized file in one directory that
    names a `.resS` or `.resource` sibling: {sibling: [(offset, size)]}.

    This is the pass that lets a file with NO magic -- a `.resS` begins
    with whatever the first texture's first block is, on this object
    sixty-four zero bytes -- be filed by what names it rather than left
    opaque. `unityfs.py` reads the object tables; this function only walks
    them for classes 28, 43 and 83 and asks `_sidecar_records`.
    """
    import unityfs
    try:
        names = [n for n in os.listdir(dirpath)
                 if n.endswith(".resS") or n.endswith(".resource")]
    except OSError:
        return {}
    refs = {}
    if not names:
        return refs
    for n in sorted(os.listdir(dirpath)):
        p = os.path.join(dirpath, n)
        if not os.path.isfile(p) or not unityfs.is_serialized(p):
            continue
        try:
            sf = unityfs.load(p)
        except (ValueError, struct.error, IndexError):
            continue
        for o in sf.objects:
            cid = sf.class_of(o)
            if cid not in (28, 43, 83):
                continue
            for k, v in _sidecar_records(sf.body(o), cid, names).items():
                refs.setdefault(k, []).extend(v)
    return refs


def sidecar_pass(rows, root, refs_fn=None):
    """Refile the still-opaque files that a sibling serialized file's
    stream records name and whose records all lie inside them. DERIVED:
    the warrant is this session's reading of the records, and the bucket
    name says so. Returns the rows with those entries replaced. `refs_fn`
    is `_unity_sidecar_refs` unless the selftest hands in its own.
    """
    refs_fn = refs_fn or _unity_sidecar_refs
    cache = {}
    out = []
    for rel, size, buck, name in rows:
        if buck == "opaque" and (rel.endswith(".resS")
                                 or rel.endswith(".resource")):
            d = os.path.dirname(os.path.join(root, rel))
            if d not in cache:
                cache[d] = refs_fn(d)
            recs = cache[d].get(os.path.basename(rel))
            if recs:
                far = max(o + s for o, s in recs)
                if far <= size:
                    buck = "derived"
                    name = ("Unity streamed sidecar -- no magic; named by "
                            "m_StreamData / m_Resource records of sibling "
                            "serialized files, every record inside the file "
                            "(unityfs.py)")
        out.append((rel, size, buck, name))
    return out


MAGICS = [
    (_mz, "specified", "PE / MZ executable (Microsoft) -- header arithmetic checked, not the two letters alone"),
    (_ilbm, "specified", "EA IFF 85 / ILBM (Electronic Arts, published 1985)"),
    (_carte40, "derived",
     "40-card planar sheet -- NO signature; selected by the shape of its "
     "first card and read only by this session"),
    (_px, "decoded",
     "PX 320x200 screen -- no specification, no vendor, no named producer; "
     "read on this object"),
    (_is(b"\x89PNG\r\n\x1a\n"), "specified", "PNG (W3C / ISO 15948)"),
    (lambda b: b.startswith(b"RIFF") and b[8:12] == b"WAVE",
     "specified", "RIFF WAVE (Microsoft and IBM)"),
    (_fev_bank, "decoded",
     "FMOD Studio bank -- RIFF form `FEV `, length closed on the file, "
     "FMT then LIST PROJ then one SND holding an FSB5 (fevbank.py; the "
     "format is FMOD's, unpublished, read by third parties)"),
    (_is(b"MThd"), "specified", "Standard MIDI File (MMA RP-001)"),
    (_is(b"\x00\x00\x01\x00"), "specified", "Windows icon"),
    (_is(b"ITSF"), "decoded",
     "Microsoft ITSF -- no vendor specification; chmlib and 7-Zip"),
    (lambda b: b[:1] == b"\x0b" and b[1:12] == b"LcfDataBase",
     "decoded", "LCF database -- no vendor specification; the EasyRPG project"),
    # Three magics added on pc-rpgmaker2003-doc, where their absence put
    # 67,623 bytes in the OPAQUE bucket and the tool still closed at residue 0
    # and printed a full table. A classifier that is silently wrong is worse
    # than one that refuses, so these are here with the same length-prefixed
    # shape as LcfDataBase above and not a substring search.
    (lambda b: b[:1] == b"\x0a" and b[1:11] == b"LcfMapUnit",
     "decoded", "LCF map unit -- no vendor specification; the EasyRPG project"),
    (lambda b: b[:1] == b"\x0a" and b[1:11] == b"LcfMapTree",
     "decoded", "LCF map tree -- no vendor specification; the EasyRPG project"),
    (_is(b"8BPS"), "specified", "Adobe Photoshop PSD (Adobe, published)"),
    # Three magics added on pc-rpgmakerxp-doc, where their absence put
    # 10,966,146 bytes -- 40.7430 % of the object -- in the OPAQUE bucket while
    # the tool closed at residue 0 and printed a full table. Second appearance
    # of that defect and 162 times the first. Two of the three are for formats
    # this box has had readers for since long before the object arrived
    # (`oggmeta.py`, `jpeg.py`): the gap was in this table and nowhere else.
    (_ogg, "specified", "Ogg container (IETF RFC 3533; Vorbis I by Xiph.Org)"),
    (_is(b"\xff\xd8\xff"), "specified",
     "JPEG / JFIF (ITU-T T.81; ISO/IEC 10918)"),
    # The bucket is argued in docs/04 and not chosen here: Ruby publishes a
    # description of this format in its own source tree (doc/marshal.rdoc), and
    # the DECODED bucket's membership test begins "no such document exists".
    # The RGSS object model the format CARRIES is a separate question with a
    # separate answer, exactly as a PNG's subject matter is separate from PNG.
    (_marshal48, "specified",
     "Ruby Marshal 4.8 object serialisation (Ruby, doc/marshal.rdoc)"),
    # Five binary magics added on pc-rpgmakervxace-doc. Every one of these
    # formats is published, and two of them (ZIP, BMP) already had readers in
    # this box -- `zaccount.py` and `bmp.py` -- while the table that decides
    # what is readable had not been told. That is the gap, and it is in this
    # list and nowhere else.
    # Added on pc-losthorizon-doc, and it MUST stand before `_mpeg_audio`:
    # a `FF FE` byte-order mark is eleven set bits, and three UTF-16 text
    # files of that object were filed as audio. The selftest asserts the
    # order.
    (_utf16_text, "specified",
     "plain text, UTF-16 with a byte-order mark (Unicode; RFC 2781)"),
    (_mpeg_audio, "specified",
     "MPEG-1/2 Audio (ISO/IEC 11172-3); ID3v2 tag (id3.org)"),
    (_sfnt, "specified",
     "sfnt / TrueType outline font (Apple; Microsoft OpenType)"),
    (_bmp, "specified", "Windows BMP (Microsoft, published)"),
    (_pdf, "specified", "PDF (ISO 32000; Adobe)"),
    (_zip, "specified", "ZIP archive (PKWARE APPNOTE)"),
    # Five magics added on pc-rpgmakermv-doc. Four of the formats had never
    # appeared in this collection; the fifth is the first DECODED candidate
    # since pc-rpgmaker2003-doc and its bucket is argued in docs/04.
    (_mp4, "specified",
     "MPEG-4 / ISO base media (ISO/IEC 14496-12; 14496-14 for M4A)"),
    (_elf, "specified", "ELF (System V ABI / Tool Interface Standard 1.2)"),
    (_macho, "specified", "Mach-O (Apple, OS X ABI Mach-O File Format)"),
    (_ar, "specified", "Unix archive (POSIX.1-2017 ar; SVR4 variant)"),
    (_chromium_pak, "decoded",
     "Chromium .pak resource container -- no specification; the Chromium "
     "source and third-party readers"),
    # Added on pc-hexxagon-doc, where its absence put 626,424 bytes --
    # 48.2668 % of the object -- in the OPAQUE bucket. The bucket is DERIVED
    # and the argument is in `_hxg`'s docstring and in docs/04: the producer
    # wrote three paragraphs about his own compressor in the user manual, and
    # prose is not a specification.
    (_hxg, "derived",
     "HXG resource container (Argo Games, 1993) -- NO signature and no "
     "published description; selected by three arithmetic closures and read "
     "only by this session"),
    (_hxg_board, "derived",
     "HEXXAGON board -- 169 ten-byte cells of which 108 are off-board "
     "sentinels, leaving the 61 hexes of the game; written by the program"),
    (_hxg_config, "derived",
     "HEXXAGON settings -- 22 bytes bracketed by HXG\\0 at both ends; "
     "written by the program"),
    (_pif, "specified",
     "Windows 3.x Program Information File (Microsoft; layout cited from "
     "pc-baronbaldric-doc/docs/04, not re-established here)"),
    # Added on pc-bianconatale-doc, where their absence put 1,366,363 bytes
    # -- 95.1162 % of the object, the lowest opening figure this collection
    # has measured -- in the OPAQUE bucket. Both are DERIVED, both are
    # arithmetic and not a signature, and both ask for the file's length
    # because their closure is what selects them and a head cannot see it.
    (_bmb, "derived",
     "Tecnoart .BMB image / .BMA frame strip (BIANCO NATALE, 1994) -- NO "
     "signature and no published description; 5- or 7-byte header, raw "
     "8-bit pixels, optional 6-bit VGA palette, closing on the length; "
     "read only by this session"),
    (_fnt, "derived",
     "Tecnoart 8 x 12 font, 96 cells at one byte per pixel (BIANCO NATALE, "
     "1994) -- no signature; read only by this session"),
    # Added on pc-outrun-doc: 93 files, 306,825 bytes, 51.2416 % of that
    # object, two compression stages deep. The probe reads the outer header
    # and the Huffman table; the closure is pes.py's.
    (_pes, "derived",
     "OUT RUN .PES/.PCS shape container (SEGA / Unlimited Software Inc., "
     "1989) -- packed bit, stage count, canonical Huffman table with Kraft "
     "sum 1; two-stage grammar read from the game's own decoder by pes.py"),
    # Added on pc-demonsforge-doc: one file, 164,352 bytes, 72.6768 % of that
    # object -- a 160 KB self-booting diskette behind Mok's signature sector.
    # The probe closes the directory chain; forgedat.py decodes the pictures.
    (_forgedat, "derived",
     "THE DEMON'S FORGE GAME.DAT (Mastertronic, 1987; Dos Driver by Mok) -- "
     "signature sector, boot sector, 12-byte directory records chaining "
     "a*512+c to a zero terminator; vector-picture grammar read from the "
     "game's own interpreter by forgedat.py"),
    # Added on pc-teenagent-doc: twelve files, 15,309,492 bytes, 16.4292 % of
    # that object. The probe closes the directory on the length; res.py reads
    # the members (screens, sprites, overlays, animations, fonts, music
    # headers, drivers) with the grammar read from the unpacked engine.
    (_res, "derived",
     "TEENAGENT .RES container (Metropolis Software House, 1994-1995) -- "
     "u32 count, count+1 monotonic offsets, first 4+4(count+1), last = the "
     "length; member grammars read from the game's own engine by res.py"),
    # Added on pc-polanie-doc: one FLC of 11,090,932 bytes (74.1501 % of
    # that object), 18 S3M, 34 six-byte-head pictures in 4 files, 1 .COM,
    # 1 Mazovia text -- see the block of four probes above.
    (_flc, "specified",
     "Autodesk Animator Pro FLC animation (Autodesk, 1991) -- 128-byte "
     "header, u32 at 0 = the file length, 0xAF12; frames walked by flc.py"),
    (_s3m, "specified",
     "Scream Tracker 3 module (Future Crew, 1994) -- `SCRM` at 2Ch; header "
     "and instruments read by s3m.py"),
    (_graf, "derived",
     "POLANIE 6-byte-head 8-bit picture (1996) -- u16 L = 6 + (w+1)(h+1), "
     "u16 stride w, u16 h; one image or 33,000-byte slots; no signature; "
     "read only by this session (graf.py)"),
    (_comstub, "derived",
     "packed .COM with the self-relocating LZ stub read out of POLANIE's "
     "CRACK.COM -- jmp 015Fh, 161 stub bytes; unpacked by comunpack.py"),
    # Added on pc-bumpy-doc (Loriciel, 1992): the game's own formats, read
    # out of its loader, and three pieces of release furniture.
    (_adlibbnk, "specified",
     "Ad Lib instrument bank (Ad Lib Inc., .BNK v1.0) -- ADLIB- signature, "
     "offsets and counts close on the file; adlibbnk.py"),
    (_thedraw, "specified",
     "TheDraw COM-file screen (TheSoft, DOS) -- jump and the tool's banner"),
    (_bumpack, "derived",
     "BUMPY 12-byte compressed head (Loriciel, 1992) -- u32 BE length, u16 BE "
     "method 4/12, u16 BE XOR check; read out of BUMPY.EXE by bumpack.py"),
    (_bumsprite, "derived",
     "BUMPY sprite bank -- 512 x u32 BE table, 12-byte BE record heads; "
     "read out of the bank setup by bumsprite.py"),
    (_carfont, "derived",
     "BUMPY .CAR proportional font -- 20h..FFh, 7 x 8 cell, u16 BE absolute "
     "offsets; carfont.py"),
    (_vecscreen, "derived",
     "BUMPY 32,099-byte screen in the clear -- 51 zeros, 48 DAC bytes, four "
     "EGA planes; vecscreen.py"),
    (_queldisk, "derived",
     "BUMPY QUELDISK -- disk letter and Ctrl-Z, read by the loader at cs:74D5"),
    (_cpav_chklist, "derived",
     "Central Point Anti-Virus CHKLIST.CPS -- 27-byte records, 8.3 name and "
     "17 bytes ending FF FF; the checksum arithmetic is not derived"),
    (_bumlevel, "derived",
     "BUMPY level grid in the clear -- 2 + n x 194 bytes, three 8 x 6 tables "
     "below 64; bumlevel.py (a length and a range, the weakest probe here)"),
    # Added on pc-monstrum-doc (Unity 5.5.0f3, GOG Galaxy): see the
    # docstrings for which bucket and why.
    (_unity_serialized, "decoded",
     "Unity SerializedFile -- no magic; version 5..30, endianness byte, "
     "fileSize == the file (unityfs.py; the format is Unity's, unpublished, "
     "read by third parties)"),
    (_fsb5, "decoded",
     "FMOD Sample Bank 5 (FSB5) -- magic, version 0/1, first bank inside the "
     "file (fsb5.py; FMOD's, unpublished, read by third parties)"),
    (_mdmp, "specified",
     "Windows minidump (MINIDUMP_HEADER, Windows SDK minidumpapiset.h) -- "
     "version word, stream directory inside the file (mdmp.py)"),
    (_mono_mdb, "specified",
     "Mono symbol file .mdb (Mono, published as source: MonoSymbolFile.cs) "
     "-- magic and version 50.0"),
    (_shllink, "specified",
     "Windows Shell Link .lnk (Microsoft [MS-SHLLINK])"),
    (_inno_unins_log, "specified",
     "Inno Setup uninstall log (jrsoftware, published as source: Struct.pas "
     "TUninstallLogHeader) -- 64-byte ID"),
    (_inno_msgs, "specified",
     "Inno Setup compiled messages (jrsoftware, published as source: "
     "Struct.pas TMessagesHeader) -- 64-byte ID"),
    # Added on pc-losthorizon-doc, where its absence put 4,030,829,851 bytes
    # -- 99.7513 % of the object, the highest opening figure this collection
    # has measured -- in the OPAQUE bucket. The bucket is DERIVED, the warrant
    # is the closure in `_spcr`'s docstring, and the tables are NOT read.
    (_spcr, "derived",
     "FSAS SPCR archive (Fusionsphere Systems, LOST HORIZON, 2010) -- 56-byte "
     "head, three (count, offset, size) tables tiling the tail to the last "
     "byte; payloads walked by magic by spcr.py; the tables themselves are "
     "high-entropy and not decoded; no signature but the closure; read only "
     "by this session"),
    # ------------------------------------------------------------------
    # EVERYTHING BELOW THIS LINE IS A TEXT CODEC AND NOTHING BINARY MAY BE
    # ADDED AFTER IT. `_ordering_ok()` enforces this and the selftest asserts
    # it. The 328,733-byte PDF that this table filed as `plain text, Shift-JIS`
    # is what the rule is made of.
    # ------------------------------------------------------------------
    (_printable, "specified", "plain text, ASCII"),
    # This must stand BEFORE _cp932_text and does: cp437's box-drawing band
    # 0xB0..0xDF sits inside Shift-JIS's single-byte half-width katakana range
    # 0xA1..0xDF, both decodes are legal, and the file that provoked this is
    # an English BBS advertisement filed as Japanese. See `_cp437_art`.
    (_cp437_art, "specified",
     "plain text, cp437 with box-drawing art (IBM PC codepage 437)"),
    # Before the multi-byte codecs: Mazovia's letters 0xA2/0xA4/0xA6/0xA7
    # are cp932 half-width katakana and 0x86..0x9E are cp932 lead bytes, so
    # a Polish file would otherwise be filed as Japanese.
    (_mazovia_text, "specified",
     "plain text, Mazovia (Polish DOS code page, 1980s)"),
    # After Mazovia (whose eighteen letters are all cp437 letters or signs
    # too) and before UTF-8 (which `_cp437_scan` asks first anyway): cp437
    # text with accents and no frames -- pc-bumpy-doc's French INSTALL.BAT.
    (_cp437_text, "specified",
     "plain text, cp437 with accented letters (IBM PC codepage 437)"),
    (_utf8_text, "specified", "plain text, UTF-8 (Unicode; IETF RFC 3629)"),
    (_eucjp_text, "specified",
     "plain text, EUC-JP (JIS X 0208; Unix Japanese encoding)"),
    (_cp932_text, "specified",
     "plain text, Shift-JIS (JIS X 0208; Microsoft cp932)"),
]

# The probes that are text codecs, by identity. Anything not in this set is a
# binary signature and must sort before all of them.
TEXT_PROBES = (_printable, _cp437_art, _mazovia_text, _cp437_text, _utf8_text,
               _eucjp_text, _cp932_text)


def _ordering_ok(magics=None):
    """Every binary signature is tested before every text codec.

    Returns True when the rule holds. This is not decoration: the whole repair
    of the misfiled PDF is that a signature which was absent is now present AND
    is tested first. A future edit that appends `(_is(b"CAFEBABE"), ...)` to
    the end of MAGICS would be silently shadowed by three text probes, and this
    is the check that refuses to let that happen quietly.
    """
    seen_text = False
    for probe, _buck, _name in (magics if magics is not None else MAGICS):
        if probe in TEXT_PROBES:
            seen_text = True
        elif seen_text:
            return False
    return True


# How much of a file the classifier looks at.
#
# This was 512 and is 4,096, and the reason is a class of magic 512 cannot
# serve. Some formats close on their own LENGTH -- HEXXAGON's board file is
# 1,690 bytes of 169 records and a file of 1,700 is not one -- and a probe
# handed a fixed-size head cannot tell 1,690 bytes from the first 1,690 bytes
# of something longer. Reading MORE than the format's size settles it for
# free: ask for 4,096 and get 1,690 back, and the file is 1,690 bytes.
#
# It costs eight times the bytes per file and buys the length closures. It
# does not help formats larger than the head -- `_hxg` documents the weaker
# warrant it has to live with -- and raising it further would only move the
# same line.
#
# THE LENGTH, AS A SECOND CHANNEL. Added on pc-bianconatale-doc, where a
# 64,777-byte `.BMB` closes on its length and nothing in a 4,096-byte head
# can see that. A probe marked `wants_size = True` is called as
# `probe(head, size)` with the file's length; every other probe is called as
# before, with the head alone, and `classify(blob)` with no length still
# works for every caller that has it (`chpak.py` is one). The length is not
# the head, it is a property of the file, and a probe that uses it says so in
# its docstring together with what it still cannot see. Nothing was removed.
HEAD = 4096


def classify(blob, size=None):
    for probe, buck, name in MAGICS:
        try:
            if getattr(probe, "wants_size", False):
                hit = probe(blob, size)
            else:
                hit = probe(blob)
            if hit:
                return buck, name
        except (IndexError, TypeError):
            continue
    return "opaque", "not identified by any signature this tool knows"


def tree_rows(root):
    rows = []
    for dp, dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            with open(p, "rb") as fh:
                head = fh.read(HEAD)
            size = os.path.getsize(p)
            buck, name = classify(head, size)
            rows.append((os.path.relpath(p, root).replace(os.sep, "/"),
                         size, buck, name))
    if not rows:
        sys.exit("coverage: no files under %r -- refusing to report a clean "
                 "table over an empty population" % root)
    return sidecar_pass(rows, root)


def report_tree(root):
    rows = tree_rows(root)
    total = sum(r[1] for r in rows)
    cnt = collections.Counter()
    byt = collections.Counter()
    for _, size, buck, name in rows:
        cnt[(buck, name)] += 1
        byt[(buck, name)] += size
    print("denominator : %d files, %d bytes -- every file under %s, "
          "classified BY MAGIC" % (len(rows), total, root))
    print()
    print("  %-10s %6s %12s %10s  %s"
          % ("bucket", "files", "bytes", "share", "format"))
    order = {"specified": 0, "decoded": 1, "derived": 2, "opaque": 3}
    for (buck, name), c in sorted(cnt.items(),
                                  key=lambda kv: (order[kv[0][0]],
                                                  -byt[kv[0]])):
        print("  %-10s %6d %12d %9.4f %%  %s"
              % (buck, c, byt[(buck, name)],
                 100.0 * byt[(buck, name)] / total, name))
    print()
    sums = collections.Counter()
    counts = collections.Counter()
    for (buck, name), c in cnt.items():
        sums[buck] += byt[(buck, name)]
        counts[buck] += c
    for b in ("specified", "decoded", "derived", "opaque"):
        print("  %-10s %4d files %12d bytes   %8.4f %% of %d"
              % (b, counts[b], sums[b], 100.0 * sums[b] / total if total else 0,
                 total))
    print("  %-10s %4d files %12d bytes   %8.4f %%"
          % ("SUM", sum(counts.values()), sum(sums.values()),
             100.0 * sum(sums.values()) / total))
    print("  against the denominator %d          RESIDUE %d"
          % (total, sum(sums.values()) - total))
    print()
    print("  The SUM row is an ACCOUNTING figure and not a coverage figure.")
    print("  It answers 'do the bytes add up to the object'. It does not")
    print("  answer 'how much of this can be checked against something outside")
    print("  it', because SPECIFIED and DECODED carry warrants of different")
    print("  strength and DERIVED carries none but this session's.")
    if sum(sums.values()) != total:
        print("  THE BUCKETS DO NOT SUM TO THE DENOMINATOR", file=sys.stderr)
        return 1
    return 0


def selftest():
    checks = []
    checks.append(("every extension falls in exactly one bucket",
                   len(set(PUBLISHED) & set(DERIVED)) == 0
                   and len(set(PUBLISHED) & set(NEITHER)) == 0
                   and len(set(DERIVED) & set(NEITHER)) == 0, ""))
    checks.append(("an unknown extension is not counted as published",
                   bucket("QQQ")[0] == "neither", str(bucket("QQQ"))))
    checks.append(("INS is derived at the member layer and neither at the "
                   "product layer",
                   bucket("INS")[0] == "derived"
                   and bucket("INS", "product")[0] == "neither", ""))
    checks.append(("a name with a path separator takes the last component",
                   ext_of("themes\\global\\a.BMP") == "BMP", ""))
    checks.append(("a dotfile is not given an extension",
                   ext_of(".profile") == "(none)", ext_of(".profile")))
    checks.append(("a name with no dot is not given an extension",
                   ext_of("README") == "(none)", ""))
    checks.append(("HLP is NOT counted as published",
                   bucket("HLP")[0] == "neither", ""))
    checks.append(("the Z archive is derived and not published",
                   bucket("1")[0] == "derived", ""))
    # -- ILBM and the 40-card sheet, added on pc-rovescino-doc --------------
    _bmhd = bytes(20)
    _ilbm_head = (b"FORM" + (100).to_bytes(4, "big") + b"ILBM"
                  + b"BMHD" + (20).to_bytes(4, "big") + _bmhd)
    checks.append(("an ILBM is SPECIFIED",
                   classify(_ilbm_head)[0] == "specified", ""))
    checks.append(("a PBM  is SPECIFIED too",
                   classify(_ilbm_head.replace(b"ILBM", b"PBM ", 1))[0]
                   == "specified", ""))
    checks.append(("FORM with an unknown type is NOT an ILBM",
                   classify(b"FORM" + (100).to_bytes(4, "big") + b"AIFF"
                            + bytes(20))[0] != "specified"
                   or "ILBM" not in classify(
                       b"FORM" + (100).to_bytes(4, "big") + b"AIFF"
                       + bytes(20))[1], ""))
    checks.append(("the word FORM in the middle of a file is not an ILBM",
                   not _ilbm(b"xxFORM" + (100).to_bytes(4, "big") + b"ILBM"
                             + bytes(20)), ""))
    # The 40-card shape test: the real top edge, then five refusals built to
    # look like near misses. A shape test that cannot say no is not a test.
    _card = (bytes(8)
             + bytes.fromhex("0fffffffffffffe0")
             + bytes.fromhex("3ffffffffffffff8")
             + bytes.fromhex("3ffffffffffffff8")
             + bytes.fromhex("7ffffffffffffffc")
             + bytes.fromhex("7ffffffffffffffc"))
    checks.append(("the top edge of a card is DERIVED",
                   classify(_card)[0] == "derived", ""))
    checks.append(("a card whose first row is not blank is refused",
                   not _carte40(b"\x01" + _card[1:]), ""))
    checks.append(("a band that NARROWS is refused",
                   not _carte40(bytes(8)
                                + bytes.fromhex("7ffffffffffffffc")
                                + bytes.fromhex("3ffffffffffffff8")
                                + bytes.fromhex("3ffffffffffffff8")
                                + bytes.fromhex("0fffffffffffffe0")
                                + bytes.fromhex("0fffffffffffffe0")), ""))
    checks.append(("a row with a hole in it is refused",
                   not _carte40(bytes(8)
                                + bytes.fromhex("0ffffff00fffffe0")[:8]
                                + _card[16:]), ""))
    checks.append(("forty-eight zero bytes are refused",
                   not _carte40(bytes(48)), ""))
    checks.append(("a narrow band is refused",
                   not _carte40(bytes(8) + bytes.fromhex("0000ff0000000000")
                                * 5), ""))
    # The four-bucket classifier, which is new and is the point of `tree`.
    # An MZ header whose arithmetic holds: 144 bytes in the last page, one
    # page, no relocations, a 32-byte header, relocation table at 0x1c.
    _mz_head = (b"MZ" + struct.pack("<13H", 144, 1, 0, 2, 0, 0xffff, 0, 0x80,
                                    0, 0, 0, 0x1c, 0) + bytes(36))
    checks.append(("an MZ header whose arithmetic holds is SPECIFIED",
                   classify(_mz_head)[0] == "specified", ""))
    checks.append(("an MZP stub is SPECIFIED too: the P is e_cblp's low byte",
                   classify(b"MZP\x00" + _mz_head[4:])[0] == "specified", ""))
    # The repair made on pc-outrun-doc: the letters alone no longer fire.
    checks.append(("MZ followed by prose is OPAQUE: two letters are not a header",
                   classify(b"MZ is also two letters, and this is a sentence "
                            b"that begins with them" + bytes(20))[0]
                   == "opaque", ""))
    checks.append(("an MZ header declaring more image than the file has is "
                   "OPAQUE", classify(_mz_head, 100)[0] == "opaque", ""))
    checks.append(("an MZ header whose relocation table overruns its header "
                   "is OPAQUE",
                   classify(b"MZ" + struct.pack("<13H", 144, 1, 9, 2, 0, 0xffff,
                                                 0, 0x80, 0, 0, 0, 0x1c, 0)
                            + bytes(36))[0] == "opaque", ""))
    checks.append(("the MZ header of OUTRUN.EXE, quoted, is SPECIFIED at its "
                   "length 17,832",
                   classify(bytes.fromhex("4d5ab0001b00010020000000ffff2303"
                                          "8000000000000000220000000100fb20")
                            + bytes(32), 17832)[0] == "specified", ""))
    checks.append(("the MZ header of CORV.PES, quoted, is SPECIFIED at its "
                   "length 75,747: the classifier was right about it",
                   classify(bytes.fromhex("4d5ae30194000000" "2200e504e504b715"
                                          "800000001200e811" "1e00000001000000")
                            + bytes(32), 75747)[0] == "specified", ""))
    checks.append(("a PNG is SPECIFIED",
                   classify(b"\x89PNG\r\n\x1a\n" + bytes(20))[0]
                   == "specified", ""))
    checks.append(("a RIFF that is not WAVE is not counted as WAVE",
                   classify(b"RIFF\x00\x00\x00\x00AVI ")[1]
                   != "RIFF WAVE (Microsoft and IBM)", ""))
    checks.append(("a RIFF WAVE is SPECIFIED",
                   classify(b"RIFF\x00\x00\x00\x00WAVEfmt ")[0]
                   == "specified", ""))
    checks.append(("an ITSF container is DECODED, not specified",
                   classify(b"ITSF\x03\x00\x00\x00" + bytes(40))[0]
                   == "decoded", ""))
    checks.append(("an LCF database is DECODED, not specified",
                   classify(b"\x0bLcfDataBase\x0b\xae\x11")[0]
                   == "decoded", ""))
    checks.append(("a file merely CONTAINING LcfDataBase is not one",
                   classify(b"xxxx\x0bLcfDataBase")[0] != "decoded", ""))
    checks.append(("an LcfMapUnit is DECODED",
                   classify(b"\x0aLcfMapUnit\x01\x01\x04")[0]
                   == "decoded", ""))
    checks.append(("an LcfMapTree is DECODED",
                   classify(b"\x0aLcfMapTree\x04\x00\x01")[0]
                   == "decoded", ""))
    checks.append(("the two map variants are told apart",
                   classify(b"\x0aLcfMapUnit\x01")[1]
                   != classify(b"\x0aLcfMapTree\x04")[1], ""))
    checks.append(("a wrong length prefix on LcfMapUnit is not one",
                   classify(b"\x0bLcfMapUnit\x01")[0] != "decoded", ""))
    checks.append(("a PSD is SPECIFIED, because Adobe published the format",
                   classify(b"8BPS\x00\x01" + bytes(20))[0]
                   == "specified", ""))
    checks.append(("a PSD is named as Adobe's",
                   "Adobe" in classify(b"8BPS\x00\x01" + bytes(20))[1], ""))
    # The three magics added on pc-rpgmakerxp-doc. Two of these checks MUST
    # fail on their fixtures, because a magic that cannot say no is not a
    # magic: the first version of the Marshal probe was two bytes long and
    # would have accepted any file at all that happened to begin 04 08.
    checks.append(("an Ogg page is SPECIFIED",
                   classify(b"OggS\x00\x02" + bytes(20))[0] == "specified",
                   ""))
    checks.append(("an Ogg is named as the IETF's and Xiph.Org's",
                   "RFC 3533" in classify(b"OggS\x00\x02" + bytes(20))[1],
                   ""))
    checks.append(("a file merely CONTAINING OggS is not an Ogg",
                   classify(b"xxxxOggS\x00\x02")[0] != "specified"
                   or "Ogg" not in classify(b"xxxxOggS\x00\x02")[1], ""))
    checks.append(("OggS with a non-zero version byte is not an Ogg",
                   "Ogg" not in classify(b"OggS\x09\x02" + bytes(20))[1], ""))
    checks.append(("a JPEG is SPECIFIED",
                   classify(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00")[0]
                   == "specified", ""))
    checks.append(("a JPEG is named as ITU-T T.81 / ISO 10918",
                   "T.81" in classify(b"\xff\xd8\xff\xe0")[1], ""))
    checks.append(("FF D8 without the third byte is not a JPEG",
                   "JPEG" not in classify(b"\xff\xd8\x00\x00")[1], ""))
    checks.append(("a Ruby Marshal 4.8 array is SPECIFIED",
                   classify(b"\x04\x08[\x0e")[0] == "specified", ""))
    checks.append(("a Ruby Marshal 4.8 object and hash are the same format",
                   classify(b"\x04\x08o:\x0f")[1]
                   == classify(b"\x04\x08{\x06")[1], ""))
    checks.append(("Marshal is named as Ruby's own",
                   "Ruby" in classify(b"\x04\x08[\x0e")[1], ""))
    checks.append(("04 08 followed by a byte the grammar cannot start with "
                   "is NOT Marshal",
                   "Marshal" not in classify(b"\x04\x08\x99\x01")[1], ""))
    checks.append(("a two-byte file of 04 08 is not Marshal either",
                   "Marshal" not in classify(b"\x04\x08")[1], ""))
    checks.append(("a Marshal minor other than 8 is not claimed as 4.8",
                   "Marshal" not in classify(b"\x04\x07[\x0e")[1], ""))
    checks.append(("plain text is SPECIFIED",
                   classify(b"383730\n")[0] == "specified", ""))
    checks.append(("Shift-JIS text is SPECIFIED, not opaque",
                   classify("Ｍｉｃｃｏ (Feb.3,2003)".encode("cp932"))[0]
                   == "specified", ""))
    checks.append(("and it is named as Shift-JIS rather than as ASCII",
                   "Shift-JIS" in
                   classify("Ｍｉｃｃｏ".encode("cp932"))[1], ""))
    checks.append(("a byte string cp932 REFUSES is not called text",
                   _cp932_text(bytes([0x81, 0x20, 0xFF, 0x81])) is False, ""))
    checks.append(("a head cut mid-sequence is still recognised as text",
                   _cp932_text("Ｍｉｃｃｏ".encode("cp932")[:-1]) is True, ""))
    checks.append(("but a bad sequence in the MIDDLE is not forgiven",
                   _cp932_text("Ｍ".encode("cp932") + b"\xff\xfe"
                               + "ｏｏｏ".encode("cp932")) is False, ""))
    checks.append(("pure ASCII does not reach the Shift-JIS probe",
                   _cp932_text(b"hello") is False, ""))
    # ------------------------------------------------------------------
    # The five binary magics and two text codecs added on
    # pc-rpgmakervxace-doc. Six of these twenty-two checks assert a REFUSAL or
    # a non-confusion rather than an acceptance, because the defect this
    # repairs was not a probe that said no: it was a probe that said yes.
    checks.append(("THE ORDERING RULE: every binary signature is tested "
                   "before every text codec",
                   _ordering_ok() is True, ""))
    checks.append(("and the rule is falsifiable -- a binary probe moved "
                   "below a text codec is REFUSED",
                   _ordering_ok([(_printable, "specified", "t"),
                                 (_pdf, "specified", "b")]) is False, ""))
    checks.append(("THE MISFILING: a PDF header is a PDF and not Shift-JIS "
                   "text",
                   classify(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n")[1]
                   .startswith("PDF"), ""))
    checks.append(("and the cp932 probe WOULD have taken it, which is why "
                   "the order matters",
                   _cp932_text(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\n"
                               + "Ｍ".encode("cp932")) is True, ""))
    checks.append(("an sfnt font is SPECIFIED",
                   classify(b"\x00\x01\x00\x00\x00\x0e\x00\x80")[0]
                   == "specified", ""))
    checks.append(("THE ONE-BYTE HAZARD: 00 01 00 00 is a font",
                   "sfnt" in classify(b"\x00\x01\x00\x00" + bytes(12))[1], ""))
    checks.append(("THE ONE-BYTE HAZARD: 00 00 01 00 is an icon and is NOT "
                   "called a font",
                   classify(b"\x00\x00\x01\x00" + bytes(12))[1]
                   == "Windows icon", ""))
    checks.append(("an OpenType CFF font is SPECIFIED too",
                   "sfnt" in classify(b"OTTO" + bytes(12))[1], ""))
    checks.append(("a BMP is SPECIFIED",
                   classify(b"BM\x36\x10\x00\x00\x00\x00\x00\x00\x36\x00"
                            b"\x00\x00")[0] == "specified", ""))
    checks.append(("'BMW' followed by text is NOT claimed as a BMP",
                   "BMP" not in classify(b"BMW cars are made in Munich, "
                                         b"and this is a text file.\n")[1],
                   ""))
    checks.append(("a BMP whose reserved u32 is not zero is REFUSED",
                   _bmp(b"BM\x36\x10\x00\x00\x01\x00\x00\x00\x36\x00\x00\x00")
                   is False, ""))
    checks.append(("a ZIP local header is SPECIFIED",
                   classify(b"PK\x03\x04\x14\x00\x00\x00\x08\x00")[0]
                   == "specified", ""))
    checks.append(("an empty ZIP end-of-central-directory is one too",
                   "ZIP" in classify(b"PK\x05\x06" + bytes(18))[1], ""))
    checks.append(("'PKZIP is a program' is NOT claimed as a ZIP",
                   "ZIP" not in classify(b"PKZIP is a program written by "
                                         b"Phil Katz.\n")[1], ""))
    checks.append(("an ID3v2.3 tag is MPEG audio",
                   "MPEG" in classify(b"ID3\x03\x00\x00\x00\x00\x1f\x76"
                                      + bytes(8))[1], ""))
    checks.append(("an ID3 tag whose size bytes are not syncsafe is REFUSED",
                   _mpeg_audio(b"ID3\x03\x00\x00\x00\x00\xff\x76") is False,
                   ""))
    # `FF FB 90 64`: MPEG-1 Layer III, 128 kbit/s, 44,100 Hz, no padding ->
    # a 417-byte frame. The second header stands at +417.
    _frame = b"\xff\xfb\x90\x64" + bytes(413)
    checks.append(("a bare MPEG frame followed by a second header at the "
                   "length the first computes (417) is MPEG audio",
                   "MPEG" in classify(_frame + _frame)[1], ""))
    checks.append(("the first frame's computed length is 417",
                   _mpeg_frame_length(_frame) == 417,
                   str(_mpeg_frame_length(_frame))))
    checks.append(("a one-frame file whose frame ends at its last byte is "
                   "MPEG audio",
                   _mpeg_audio(_frame, 417) is True, ""))
    checks.append(("a bare sync word with NOTHING at the computed length is "
                   "REFUSED (the pc-losthorizon-doc defect)",
                   _mpeg_audio(b"\xff\xfb\x90\x64" + bytes(20)) is False
                   and _mpeg_audio(b"\xff\xfb\x90\x64" + bytes(20), 24)
                   is False, ""))
    checks.append(("a second header with a different layer is REFUSED",
                   _mpeg_audio(_frame + b"\xff\xfd\x90\x64") is False, ""))
    _bom_le = b"\xff\xfe" + "ConfigTool\t\r\nIDOK\tSave\r\n".encode("utf-16-le")
    checks.append(("UTF-16LE text with a BOM is SPECIFIED and named UTF-16",
                   classify(_bom_le)[0] == "specified"
                   and "UTF-16" in classify(_bom_le)[1], str(classify(_bom_le))))
    checks.append(("and a FF FE BOM is NOT filed as MPEG audio (eleven set "
                   "bits are not a frame)",
                   "MPEG" not in classify(_bom_le)[1]
                   and _mpeg_audio(_bom_le) is False, ""))
    checks.append(("UTF-16BE text with a BOM is SPECIFIED too",
                   "UTF-16" in classify(b"\xfe\xff"
                                        + "Tooltips\r\n".encode("utf-16-be"))[1],
                   ""))
    checks.append(("a BOM over control bytes is REFUSED",
                   _utf16_text(b"\xff\xfe\x01\x00\x02\x00\x03\x00") is False,
                   ""))
    checks.append(("a BOM cut one byte into a word still passes",
                   _utf16_text(b"\xff\xfe" + "abc".encode("utf-16-le") + b"d")
                   is True, ""))
    checks.append(("UTF-16 without a BOM is NOT claimed by this probe",
                   _utf16_text("abc".encode("utf-16-le")) is False, ""))
    checks.append(("the UTF-16 probe stands BEFORE the MPEG probe in MAGICS",
                   [m[0] for m in MAGICS].index(_utf16_text)
                   < [m[0] for m in MAGICS].index(_mpeg_audio), ""))
    # --- SPCR: the closure, added on pc-losthorizon-doc ------------------
    # 100 bytes of payload from +56, then t0 at 156 (30 B), t2 at 186 (8 B),
    # t1 at 194 (104 B): the tables tile to 298.

    def _spcr_head(t0=(3, 156, 30), t1=(2, 194, 104), t2=(1, 186, 8)):
        h = b"SPCR" + (0).to_bytes(4, "little") + (223).to_bytes(4, "little")
        h += bytes(8)
        for t in (t0, t1, t2):
            for v in t:
                h += v.to_bytes(4, "little")
        return h + bytes(100)
    checks.append(("a SPCR head whose three tables tile to the last byte is "
                   "DERIVED",
                   classify(_spcr_head(), 298)[0] == "derived"
                   and "SPCR" in classify(_spcr_head(), 298)[1],
                   str(classify(_spcr_head(), 298))))
    checks.append(("a SPCR whose tables end one byte SHORT of the file is "
                   "REFUSED",
                   _spcr(_spcr_head(), 299) is False, ""))
    checks.append(("a SPCR whose tables overrun the file is REFUSED",
                   _spcr(_spcr_head(), 297) is False, ""))
    checks.append(("a SPCR with a gap between two tables is REFUSED",
                   _spcr(_spcr_head(t2=(1, 187, 7)), 298) is False, ""))
    checks.append(("a SPCR with a table inside the head is REFUSED",
                   _spcr(_spcr_head(t0=(3, 40, 146)), 298) is False, ""))
    checks.append(("a SPCR head WITHOUT the file's length is not claimed "
                   "(the closure is the whole warrant)",
                   classify(_spcr_head())[0] == "opaque", ""))
    checks.append(("'SPCR' followed by prose is REFUSED",
                   _spcr(b"SPCR is not a format anybody published." + bytes(40),
                         80) is False, ""))
    checks.append(("eleven set bits with an ILLEGAL layer are REFUSED",
                   _mpeg_audio(b"\xff\xe1\x90\x64") is False, ""))
    checks.append(("eleven set bits with bitrate index 1111 are REFUSED",
                   _mpeg_audio(b"\xff\xfb\xf0\x64") is False, ""))
    checks.append(("UTF-8 text with a multi-byte character is SPECIFIED",
                   classify("Grassland|草原|Prairie|Wiese|Prado\n"
                            .encode("utf-8"))[0] == "specified", ""))
    checks.append(("and it is named UTF-8 rather than Shift-JIS",
                   "UTF-8" in classify("草原|Prairie\n".encode("utf-8"))[1],
                   ""))
    checks.append(("EUC-JP text is SPECIFIED and named EUC-JP",
                   "EUC-JP" in classify("日本語のテキストです。\n"
                                        .encode("euc_jp"))[1], ""))
    checks.append(("a byte string UTF-8 refuses is not called UTF-8",
                   _utf8_text(bytes([0xC3, 0x28, 0xA0, 0xA1])) is False, ""))
    checks.append(("pure ASCII does not reach the UTF-8 probe",
                   _utf8_text(b"hello") is False, ""))
    # --- the byte-order-mark repair, pc-rpgmakermv-doc -------------------
    # Two checks, and the first one FAILS without the one-line repair. That is
    # the whole point: the defect was invisible because nothing asserted the
    # negative. `'﻿'.isprintable()` is False and the probe demanded that
    # every character be printable.
    _bom = "﻿".encode("utf-8")
    checks.append(("U+FEFF is not printable, which is what caused the defect",
                   "﻿".isprintable() is False, ""))
    checks.append(("THE REPAIR: UTF-8 text WITH a byte-order mark is "
                   "SPECIFIED", classify(_bom + "草原|Prairie\n"
                                         .encode("utf-8"))[0] == "specified",
                   "0 of 190 got through before this"))
    checks.append(("and it is still named UTF-8",
                   "UTF-8" in classify(_bom + "草原|Prairie\n"
                                       .encode("utf-8"))[1], ""))
    checks.append(("a BOM followed by ASCII is UTF-8 and not ASCII, because "
                   "the mark is a high byte",
                   classify(_bom + b"hello world\n")[1]
                   == "plain text, UTF-8 (Unicode; IETF RFC 3629)", ""))
    checks.append(("the same text WITHOUT a mark is still accepted",
                   classify("草原|Prairie\n".encode("utf-8"))[0]
                   == "specified", ""))
    checks.append(("a BOM followed by BINARY is still refused -- the repair "
                   "strips a signature, it does not excuse a file",
                   _utf8_text(_bom + bytes([0, 1, 2, 3, 27, 200])) is False,
                   ""))
    checks.append(("a lone byte-order mark and nothing else is NOT text",
                   _utf8_text(_bom) is False, ""))
    checks.append(("a U+FEFF in the MIDDLE of a file still counts against it",
                   _utf8_text("ok".encode("utf-8") + _bom
                              + "more".encode("utf-8")) is False, ""))
    # --- MPEG-4, ELF, Mach-O, ar, .pak -----------------------------------
    checks.append(("an MPEG-4 file type box is SPECIFIED",
                   classify(b"\x00\x00\x00\x20ftypM4A \x00\x00\x00\x00"
                            b"M4A mp42isom")[0] == "specified", ""))
    checks.append(("and `mp42` as major brand is the same format",
                   "MPEG-4" in classify(b"\x00\x00\x00\x18ftypmp42"
                                        b"\x00\x00\x00\x00mp42isom")[1], ""))
    checks.append(("`ftyp` at offset 4 with an ABSURD size word is REFUSED",
                   _mp4(b"\x7f\xff\xff\xffftypM4A \x00\x00\x00\x00") is False,
                   "the size is the check, not the four letters"))
    checks.append(("an ELF64 shared object is SPECIFIED",
                   classify(b"\x7fELF\x02\x01\x01\x00" + bytes(8))[0]
                   == "specified", ""))
    checks.append(("an ELF whose EI_VERSION is not 1 is REFUSED",
                   _elf(b"\x7fELF\x02\x01\x09\x00") is False, ""))
    checks.append(("an ELF whose EI_CLASS is 0 is REFUSED",
                   _elf(b"\x7fELF\x00\x01\x01\x00") is False, ""))
    checks.append(("a 64-bit Mach-O is SPECIFIED",
                   classify(b"\xcf\xfa\xed\xfe\x07\x00\x00\x01"
                            + bytes(8))[0] == "specified", ""))
    checks.append(("a 32-bit big-endian Mach-O is too",
                   "Mach-O" in classify(b"\xfe\xed\xfa\xce"
                                        + bytes(12))[1], ""))
    checks.append(("THE FOUR-BYTE HAZARD: a Mach-O universal binary with "
                   "nfat_arch 2 is a Mach-O",
                   "Mach-O" in classify(b"\xca\xfe\xba\xbe\x00\x00\x00\x02"
                                        + bytes(8))[1], ""))
    checks.append(("and a JAVA CLASS FILE, major 52, is NOT called a Mach-O",
                   "Mach-O" not in classify(b"\xca\xfe\xba\xbe\x00\x00\x004"
                                            + bytes(8))[1],
                   "0xCAFEBABE is both; nfat_arch <= 20 < 45 <= major"),)
    checks.append(("nor is a class file at Java 1.0's major 45",
                   _macho(b"\xca\xfe\xba\xbe\x00\x00\x00\x2d" + bytes(8))
                   is False, ""))
    checks.append(("a Unix archive is SPECIFIED",
                   classify(b"!<arch>\n/               0           0     0"
                            b"     0       8         `\n")[0] == "specified",
                   ""))
    checks.append(("`!<arch>` without the newline is REFUSED",
                   _ar(b"!<arch> not really") is False, ""))
    checks.append(("a Chromium .pak v5 whose entry table starts where the "
                   "header ends is DECODED",
                   classify(b"\x05\x00\x00\x00\x01\x00\x00\x00"
                            b"\x02\x00\x01\x00"
                            b"\x90\x01\x22\x00\x00\x00" + bytes(8))[0]
                   == "decoded", "12 + 3*6 + 1*4 = 34 = 0x22"),)
    checks.append(("a .pak v4 does the same arithmetic without aliases",
                   classify(b"\x04\x00\x00\x00\x02\x00\x00\x00\x01"
                            b"\x90\x01\x1b\x00\x00\x00" + bytes(8))[0]
                   == "decoded", "9 + 3*6 = 27 = 0x1b"),)
    checks.append(("a .pak whose first offset does NOT match the header is "
                   "REFUSED",
                   _chromium_pak(b"\x05\x00\x00\x00\x01\x00\x00\x00"
                                 b"\x02\x00\x01\x00"
                                 b"\x90\x01\x63\x00\x00\x00" + bytes(8))
                   is False, "this is the whole signature"))
    checks.append(("a four-byte little-endian 5 followed by nothing "
                   "structural is REFUSED",
                   _chromium_pak(b"\x05\x00\x00\x00" + bytes(24)) is False,
                   ""))
    checks.append(("a .pak of version 3 is REFUSED",
                   _chromium_pak(b"\x03\x00\x00\x00\x01\x00\x00\x00"
                                 b"\x02\x00\x01\x00"
                                 b"\x90\x01\x22\x00\x00\x00") is False, ""))
    # --- PX, added on pc-ilgrandegiocoditangentopoli-doc ------------------
    # The signature is two letters plus an arithmetic agreement, so the checks
    # that matter are the REFUSALS: three of the six below must say no, and
    # the first of them is a file that begins `PX` and is not one.
    _pxgood = (b"PX\x40\x01\xc8\x00"
               b"\xf7\xff\x05\x00\x40\x01\xc8"
               b"\xff\x06\x00" + bytes(64))
    checks.append(("a PX whose stream repeats its own geometry is DECODED",
                   classify(_pxgood)[0] == "decoded",
                   "320 and 200 in the header, 320 and 200 in the preamble"))
    checks.append(("a file that merely BEGINS `PX` is REFUSED",
                   _px(b"PX" + bytes(60)) is False,
                   "this is the whole point of decoding ten bytes"))
    checks.append(("a PX whose preamble geometry DISAGREES is REFUSED",
                   _px(b"PX\x40\x01\xc8\x00"
                       b"\xf7\xff\x05\x00\x41\x01\xc8"
                       b"\xff\x06\x00" + bytes(64)) is False,
                   "321 in the preamble against 320 in the header"))
    checks.append(("a PX with a zero dimension is REFUSED",
                   _px(b"PX\x00\x00\xc8\x00" + bytes(60)) is False, ""))
    checks.append(("a PX too short to decode ten bytes is REFUSED",
                   _px(b"PX\x40\x01\xc8\x00\xff") is False, ""))
    checks.append(("PX is tested before every text codec",
                   _ordering_ok() is True,
                   "a binary magic appended after the codecs is shadowed"))

    # -- the two Tecnoart formats, and the length channel ------------------
    _screen = b"\x40\x01\xc8\x00y" + bytes(4091)
    checks.append(("a 320 x 200 y head with its 64,777-byte length is DERIVED",
                   classify(_screen, 64777)[0] == "derived", ""))
    checks.append(("and is named as a Tecnoart picture",
                   "Tecnoart .BMB" in classify(_screen, 64777)[1], ""))
    checks.append(("the same head with a length one byte off is OPAQUE",
                   classify(_screen, 64778)[0] == "opaque", ""))
    checks.append(("the same head with NO length passes on five bytes only, "
                   "the head-only warrant",
                   classify(_screen)[0] == "derived", ""))
    _strip = b"\x39\x00\x30\x00y\x56\x00" + bytes(4089)
    checks.append(("a 57 x 48 head with count 86 and length 236,077 is the "
                   "animation", classify(_strip, 236077)[0] == "derived", ""))
    checks.append(("a flag byte that is not y or n is OPAQUE",
                   classify(b"\x40\x01\xc8\x00x" + bytes(4091), 64777)[0]
                   == "opaque", ""))
    checks.append(("an MZ head with a picture's length is still the "
                   "executable when its header holds, because MZ is tested "
                   "first",
                   classify(_mz_head + bytes(4096 - len(_mz_head)), 64777)[0]
                   == "specified", ""))
    checks.append(("but MZ\\x36\\x01y over zeros -- the two letters and no "
                   "header behind them -- is now OPAQUE, not the executable",
                   classify(b"MZ\x36\x01y" + bytes(4091), 64777)[0]
                   == "opaque", ""))
    _font = bytes([1]) * 4096
    checks.append(("a blank-celled three-value head at length 9,216 is the "
                   "font", "font" in classify(_font, 9216)[1], ""))
    checks.append(("the same head at another length is OPAQUE",
                   classify(_font, 9217)[0] == "opaque", ""))
    checks.append(("the font probe is tested after the picture probe and "
                   "before every text codec",
                   _ordering_ok() is True
                   and [m[0] for m in MAGICS].index(_bmb)
                   < [m[0] for m in MAGICS].index(_fnt), ""))
    # Nineteen since pc-losthorizon-doc: `_mpeg_audio` (a one-frame file
    # closes on its length) and `_spcr` (the tables close on the last byte).
    # Twenty since pc-thewardrobe-doc: `_fev_bank` (the RIFF length closes
    # on the file).
    checks.append(("exactly twenty probes ask for the length, and all say "
                   "so",
                   sorted(m[0].__name__ for m in MAGICS
                          if getattr(m[0], "wants_size", False))
                   == ["_adlibbnk", "_bmb", "_bumlevel", "_bumsprite",
                       "_cpav_chklist", "_fev_bank", "_flc", "_fnt",
                       "_forgedat", "_fsb5", "_graf", "_mdmp", "_mpeg_audio",
                       "_mz", "_pes", "_queldisk", "_res", "_spcr",
                       "_unity_serialized", "_vecscreen"], ""))
    # --- the two repairs of pc-thewardrobe-doc ---------------------------
    # 1. the no-break space. The first check FAILS without the repair and
    #    is the reason the repair exists; the cause is asserted beside it.
    checks.append(("U+00A0 is not printable, which is what caused the defect",
                   "\u00a0".isprintable() is False, ""))
    _nbsp = "<voice ID=\"Piante\u00a0?\" name=\"Plantes\u00a0?\"/>\n".encode("utf-8")
    checks.append(("THE REPAIR: UTF-8 text WITH a no-break space is SPECIFIED",
                   classify(_nbsp)[0] == "specified",
                   "2 opaque + 3 cp437 art of 1,208 XML before this"))
    checks.append(("and it is named UTF-8, not cp437 art",
                   "UTF-8" in classify(_nbsp)[1], classify(_nbsp)[1]))
    checks.append(("the cp437 art probe still refuses it",
                   _cp437_art(_nbsp) is False, ""))
    checks.append(("a U+FEFF that is not at the head still counts against "
                   "the file",
                   _utf8_text("ab\ufeffcd".encode("utf-8")) is False, ""))
    checks.append(("a zero-width space (Cf, not Zs) is still refused",
                   _utf8_text("ab\u200bcd".encode("utf-8")) is False, ""))
    checks.append(("the ideographic space U+3000 is still admitted, now by "
                   "category",
                   _utf8_text("ab\u3000cd".encode("utf-8")) is True, ""))
    checks.append(("cp932 text with an ideographic space (81 40) is still "
                   "cp932, by the shared test",
                   _cp932_text("\u30a2\u3000\u30a4".encode("cp932")) is True,
                   "cp932 has no U+00A0 to test with"))
    # 2. the FMOD Studio bank. A 494-byte shell is built by hand from the
    #    sixty on the object: FMT 8, LIST PROJ, no SND.
    _proj = b"PROJ" + b"BNKI" + struct.pack("<I", 32) + bytes(32)
    _fev = (b"RIFF" + struct.pack("<I", 4 + 8 + 8 + 8 + len(_proj))
            + b"FEV " + b"FMT " + struct.pack("<I", 8) + bytes(8)
            + b"LIST" + struct.pack("<I", len(_proj)) + _proj)
    checks.append(("a RIFF `FEV ` whose length closes on the file is DECODED",
                   classify(_fev, len(_fev))[0] == "decoded",
                   "482 files, 13.09 %, were OPAQUE before this"))
    checks.append(("and is named an FMOD Studio bank",
                   "FMOD Studio" in classify(_fev, len(_fev))[1], ""))
    checks.append(("a RIFF `FEV ` whose length does NOT close on the file "
                   "is OPAQUE",
                   classify(_fev, len(_fev) + 1)[0] == "opaque", ""))
    checks.append(("a RIFF `FEV ` whose first chunk is not FMT is OPAQUE",
                   classify(_fev[:12] + b"XMT " + _fev[16:], len(_fev))[0]
                   == "opaque", ""))
    checks.append(("a RIFF `FEV ` with a chunk running past the RIFF length "
                   "is OPAQUE",
                   classify(_fev[:16] + struct.pack("<I", 9999) + _fev[20:],
                            len(_fev))[0] == "opaque", ""))
    checks.append(("a RIFF WAVE is still a WAVE and SPECIFIED",
                   classify(b"RIFF\x00\x00\x00\x00WAVEfmt " + bytes(20),
                            32)[1] == "RIFF WAVE (Microsoft and IBM)", ""))
    checks.append(("the FEV probe stands before every text codec",
                   _ordering_ok() is True
                   and [m[0] for m in MAGICS].index(_fev_bank)
                   < [m[0] for m in MAGICS].index(_printable), ""))
    # -- the four probes added on pc-polanie-doc ---------------------------
    _flc_head = struct.pack("<IHHHHHHI", 5000, 0xAF12, 3, 320, 200, 8, 3, 71) \
        + bytes(128 - 20)
    checks.append(("an FLC head whose u32 is the file length is SPECIFIED",
                   classify(_flc_head, 5000)[1].startswith("Autodesk"), ""))
    checks.append(("the same head at another length is OPAQUE",
                   classify(_flc_head, 5001)[0] == "opaque", ""))
    checks.append(("the 12-byte-header variant (u32 = 12) is NOT an FLC here",
                   classify(struct.pack("<IHHHH", 12, 0xAF12, 3, 320, 200)
                            + bytes(200), 212)[0] == "opaque", ""))
    _s3m_head = bytearray(0x60)
    _s3m_head[0x1C], _s3m_head[0x1D] = 0x1A, 16
    _s3m_head[0x2C:0x30] = b"SCRM"
    checks.append(("SCRM at 2Ch with 1Ah/16 before it is SPECIFIED",
                   classify(bytes(_s3m_head), 0x60)[1].startswith("Scream"), ""))
    _s3m_bad = bytearray(_s3m_head)
    _s3m_bad[0x1D] = 17
    checks.append(("SCRM with type 17 is OPAQUE",
                   classify(bytes(_s3m_bad), 0x60)[0] == "opaque", ""))
    _graf_head = struct.pack("<3H", 6 + 320 * 101, 319, 100) + bytes(100)
    checks.append(("a 6-byte head closing on 32,326 bytes is DERIVED",
                   classify(_graf_head, 32326)[1].startswith("POLANIE"), ""))
    checks.append(("the same head in 30 slots of 33,000 is DERIVED",
                   classify(_graf_head, 990000)[1].startswith("POLANIE"), ""))
    checks.append(("the same head at 32,327 bytes is OPAQUE",
                   classify(_graf_head, 32327)[0] == "opaque", ""))
    _com = b"\xe9\x5c\x00" + bytes(0x15F - 0x103) + comunpack.STUB + bytes(64)
    checks.append(("a .COM with CRACK.COM's stub at 015Fh is DERIVED",
                   classify(_com, len(_com))[1].startswith("packed .COM"), ""))
    _com_bad = bytearray(_com)
    _com_bad[0x5F + 20] ^= 1
    checks.append(("the same .COM with one stub byte changed is OPAQUE",
                   classify(bytes(_com_bad), len(_com))[0] == "opaque", ""))
    checks.append(("ASCII with Mazovia's ł (92h) and ą (86h) is Mazovia text",
                   classify(b"Miros\x92aw, Bidzi\x86ski\r\n", 22)[1]
                   .startswith("plain text, Mazovia"), ""))
    checks.append(("ASCII with cp852's ę (A9h) is NOT Mazovia text",
                   not classify(b"za\xa9b\r\n", 6)[1]
                   .startswith("plain text, Mazovia"), ""))
    checks.append(("pure ASCII is not Mazovia text (it is plain text, ASCII)",
                   classify(b"plain\r\n", 7)[1] == "plain text, ASCII", ""))
    # -- the cp437 probes, repaired on pc-bumpy-doc ------------------------
    # The shapes are the object's: an NFO of frames with ONE middle dot
    # (FAh) in a byline, and a French batch with é/è (82h/8Ah), `echo ÿ`
    # (FFh) and no frame.
    _nfo = (b"\xda\xc4\xc4\xc4\xbf  ANSi\xfaJED  \xdc\xdf\xdb\xdb\xdf\xdc\r\n"
            b"\xb3 Fairlight presents \xb3 a great arcade game\r\n"
            b"\xc0\xc4\xc4\xc4\xd9  release date 07/18/92\r\n")
    checks.append(("cp437 frames with ONE middle dot (FAh) are cp437 art, "
                   "not Shift-JIS",
                   classify(_nfo, len(_nfo))[1]
                   .startswith("plain text, cp437 with box-drawing"), ""))
    checks.append(("the same art with a DOS end-of-file mark (1Ah) LAST "
                   "is still cp437 art",
                   classify(_nfo + b"\x1a", len(_nfo) + 1)[1]
                   .startswith("plain text, cp437 with box-drawing"), ""))
    checks.append(("but a 1Ah anywhere else is not text",
                   classify(_nfo[:10] + b"\x1a" + _nfo[10:], len(_nfo) + 1)[0]
                   == "opaque", ""))
    _bat = (b"@echo off\r\necho Cr\x82ation du r\x82pertoire C:\\BUMPY\r\n"
            b"echo \xff\r\necho termin\x82e avec succ\x8as !\r\n")
    checks.append(("French cp437 with \xe9/\xe8 and `echo \xff` and no frame "
                   "is cp437 accented text",
                   classify(_bat, len(_bat))[1]
                   .startswith("plain text, cp437 with accented"), ""))
    checks.append(("and it is SPECIFIED, not opaque",
                   classify(_bat, len(_bat))[0] == "specified", ""))
    checks.append(("Shift-JIS full-width text (\uff2d\uff49\uff43\uff43\uff4f) "
                   "is still Shift-JIS: a lead byte followed by a high byte",
                   "Shift-JIS" in classify("\uff2d\uff49\uff43\uff43\uff4f (Feb.3,2003)\n"
                                           .encode("cp932"))[1], ""))
    checks.append(("katakana whose trail bytes are ASCII (\u30a2\u30a4\u30a6 = "
                   "83h 41h ...) is NOT cp437: one high byte per letter",
                   _cp437_scan("\u30a2\u30a4\u30a6\n".encode("cp932")) is None, ""))
    checks.append(("UTF-8 \xe9 (C3h A9h: a band byte and a sign) is UTF-8, "
                   "not cp437 art",
                   "UTF-8" in classify("r\xe9pertoire cr\xe9\xe9\n"
                                       .encode("utf-8"))[1], ""))
    checks.append(("Polish in Mazovia is still Mazovia, not cp437 text",
                   classify(b"Miros\x92aw, Bidzi\x86ski\r\n", 22)[1]
                   .startswith("plain text, Mazovia"), ""))
    checks.append(("a Greek-block byte (E1h) is outside both cp437 probes",
                   _cp437_scan(b"stra\xe1e\r\n") is None, ""))
    checks.append(("pure ASCII reaches neither cp437 probe",
                   _cp437_art(b"hello\r\n") is False
                   and _cp437_text(b"hello\r\n") is False, ""))
    checks.append(("an empty blob reaches neither cp437 probe",
                   _cp437_art(b"") is False and _cp437_text(b"") is False, ""))
    # -- pc-bumpy-doc's nine probes ---------------------------------------
    _bh = bumpack._head(100, 0x1234, 12) + bytes(20)
    checks.append(("a BUMPY 12-byte head whose XOR closes is DERIVED",
                   classify(_bh, len(_bh)) == ("derived", MAGICS[[m[0] for m in MAGICS].index(_bumpack)][2]), ""))
    checks.append(("the same head with one bit of the check flipped is OPAQUE",
                   classify(_bh[:11] + bytes([_bh[11] ^ 1]) + _bh[12:], len(_bh))[0] == "opaque", ""))
    _sc = bytes(51) + bytes([1, 2, 3] * 16) + bytes(32000)
    checks.append(("a 32,099-byte screen in the clear is DERIVED",
                   "screen in the clear" in classify(_sc[:HEAD], len(_sc))[1], ""))
    checks.append(("32,099 bytes with a DAC byte of 64 are not a screen",
                   "screen" not in classify(bytes(51) + bytes([64] * 48) + bytes(32000), 32099)[1], ""))
    _sp = bumsprite._bank([(16, 4, 5)])
    checks.append(("a sprite bank by its table and first head is DERIVED",
                   "sprite bank" in classify(_sp[:HEAD], len(_sp))[1], ""))
    checks.append(("a sprite bank whose first entry is not 12 is not one",
                   "sprite" not in classify(b"\x00\x00\x00\x10" + _sp[4:HEAD], len(_sp))[1], ""))
    _cf = carfont._font([(2, 8, b""), (4, 0, b"\x60" * 7)])
    checks.append(("a .CAR font by its first offset is DERIVED",
                   ".CAR" in classify(_cf, len(_cf))[1], ""))
    checks.append(("a .CAR head whose first offset misses the table is not one",
                   ".CAR" not in classify(_cf[:6] + b"\x00\x0F" + _cf[8:], len(_cf))[1], ""))
    _lv = b"\x10\x0E" + bytes(194 * 15)
    checks.append(("2 + 15 x 194 bytes below 64 are a level grid (DERIVED, weak)",
                   "level grid" in classify(_lv[:HEAD], len(_lv))[1], ""))
    checks.append(("2 + 15 x 194 + 1 bytes are not",
                   "level grid" not in classify(_lv[:HEAD], len(_lv) + 1)[1], ""))
    checks.append(("QUELDISK: 'z' and Ctrl-Z is DERIVED",
                   "QUELDISK" in classify(b"z\x1a", 2)[1], ""))
    checks.append(("two other bytes are not QUELDISK",
                   "QUELDISK" not in classify(b"z\x1b", 2)[1], ""))
    _td = b"\xEB\x3D\x90\x00\x4F\x03\x02\x00\x00TheDraw COM file Screen" + bytes(40)
    checks.append(("a TheDraw .COM screen is SPECIFIED",
                   classify(_td, len(_td)) [0] == "specified" and "TheDraw" in classify(_td, len(_td))[1], ""))
    _ck = b"BUMPY.EXE\x00" + bytes(15) + b"\xff\xff"
    checks.append(("a 27-byte CHKLIST.CPS record is DERIVED",
                   "CHKLIST" in classify(_ck, 27)[1], ""))
    checks.append(("26 bytes are not a CHKLIST record",
                   "CHKLIST" not in classify(_ck[:26], 26)[1], ""))
    _bk = adlibbnk._bank(3, 5)
    checks.append(("an Ad Lib bank whose offsets close is SPECIFIED",
                   "Ad Lib" in classify(_bk[:HEAD], len(_bk))[1], ""))
    checks.append(("the same bank one byte longer is not",
                   "Ad Lib" not in classify(_bk[:HEAD], len(_bk) + 1)[1], ""))
    # -- the .RES probe, added on pc-teenagent-doc -------------------------
    # A head built here: three members of 10, 0 and 5 bytes.
    _res_head = struct.pack("<I4I", 3, 20, 30, 30, 35) + bytes(15)
    checks.append(("a .RES directory of 3 that closes on its length is DERIVED",
                   classify(_res_head, 35)[1].startswith("TEENAGENT .RES"), ""))
    checks.append(("the same head at the wrong length is OPAQUE",
                   classify(_res_head, 36)[0] == "opaque", ""))
    checks.append(("the same head with a non-monotonic offset is OPAQUE",
                   classify(_res_head[:12] + struct.pack("<I", 19)
                            + _res_head[16:], 35)[0] == "opaque", ""))
    checks.append(("the same head with the first offset off by one is OPAQUE",
                   classify(_res_head[:4] + struct.pack("<I", 21)
                            + _res_head[8:], 35)[0] == "opaque", ""))
    checks.append(("the .RES probe is tested after the GAME.DAT probe and "
                   "before every text codec",
                   _ordering_ok() is True
                   and [m[0] for m in MAGICS].index(_forgedat)
                   < [m[0] for m in MAGICS].index(_res), ""))
    # -- the GAME.DAT probe, added on pc-demonsforge-doc -------------------
    # A head built here: signature, boot strings, two chained records and a
    # terminator; the bodies are 100 + 50 bytes from 2048 on.
    _df_head = bytearray(forgedat.SIGNATURE.ljust(512, b"\0"))
    _df_head += (b"\xb8\xc0\x07" + b"\0" * 40 + b"* Boot error *\0Strike any key to reboot\0").ljust(512, b"\0")
    _df_head += struct.pack("<HHHHB3s", 4, 4, 0, 100, 2, b"R1\0")
    _df_head += struct.pack("<HHHHB3s", 4, 4, 100, 150, 3, b"STR")
    _df_head += b"\0" * 12
    _df_head = bytes(_df_head.ljust(4096, b"\0"))
    checks.append(("a GAME.DAT head whose two records chain and end inside "
                   "the length is DERIVED",
                   classify(_df_head, 2198)[1].startswith("THE DEMON'S FORGE"), ""))
    checks.append(("the same head at a length short of its last body is OPAQUE",
                   classify(_df_head, 2100)[0] == "opaque", ""))
    checks.append(("the same head with the second record's start moved off "
                   "the first's end is OPAQUE",
                   classify(_df_head[:0x400 + 12 + 4] + b"\x65" + _df_head[0x400 + 12 + 5:], 2198)[0]
                   == "opaque", ""))
    checks.append(("the same head without the boot strings is OPAQUE",
                   classify(_df_head[:0x200] + bytes(512) + _df_head[0x400:], 2198)[0] == "opaque", ""))
    checks.append(("the GAME.DAT probe is tested after the .PES probe and "
                   "before every text codec",
                   _ordering_ok() is True
                   and [m[0] for m in MAGICS].index(_pes)
                   < [m[0] for m in MAGICS].index(_forgedat), ""))
    # -- the .PES / .PCS probe, added on pc-outrun-doc --------------------
    # The 96-byte header of STUMP.PES, quoted: 82, final 564, two stages,
    # type 2, out 411, nine counts (Kraft 1.0), 78 distinct symbols.
    _pes_head = bytes.fromhex(
        "82340200029b01000900010002061008131a000114020307081630050a0b0c0e0f"
        "1017182048505368707311151a34408087bf04131b1c28313233357f8fc0cfe7f0"
        "f7fcfeff06090d12191d373a3f444c6065698388979fa0a6acbbc7e0eff8")
    checks.append(("the 96-byte header of STUMP.PES, quoted, is DERIVED at "
                   "its length 360",
                   classify(_pes_head + bytes(264), 360)[1]
                   .startswith("OUT RUN .PES"), ""))
    checks.append(("the same head with one Huffman count changed (Kraft sum "
                   "not 1) is OPAQUE",
                   classify(_pes_head[:9] + b"\x01" + _pes_head[10:]
                            + bytes(264), 360)[0] == "opaque", ""))
    checks.append(("the same head at a length far above its declared final "
                   "size is OPAQUE",
                   classify(_pes_head + bytes(264), 5000)[0] == "opaque", ""))
    checks.append(("a stage count of 3 under the packed bit is OPAQUE",
                   classify(b"\x83" + _pes_head[1:] + bytes(264), 360)[0]
                   == "opaque", ""))
    checks.append(("a pack type of 3 at +4 is OPAQUE",
                   classify(_pes_head[:4] + b"\x03" + _pes_head[5:]
                            + bytes(264), 360)[0] == "opaque", ""))
    checks.append(("the .PES probe is tested after the font probe and before "
                   "every text codec",
                   _ordering_ok() is True
                   and [m[0] for m in MAGICS].index(_fnt)
                   < [m[0] for m in MAGICS].index(_pes), ""))
    checks.append(("a probe that does not ask for the length is never "
                   "handed one: the ZIP magic still fires with a length",
                   classify(b"PK\x03\x04\x14\x00\x00\x00\x08\x00", 1000)[0]
                   == "specified", ""))


    # -- the seven probes and the sidecar pass added on pc-monstrum-doc ---
    def _sf_head(version=17, fsize=4096, doff=4096, endian=0, ver=b"5.5.0f3"):
        h = struct.pack(">IIII", 1292, fsize, version, doff)
        h += bytes([endian, 0, 0, 0]) + ver + b"\0"
        return h + bytes(64 - len(h))
    checks.append(("a Unity SerializedFile whose fileSize is the file is "
                   "DECODED",
                   classify(_sf_head(), 4096) == ("decoded", [m[2] for m in
                                                            MAGICS if m[0] is
                                                            _unity_serialized][0]),
                   str(classify(_sf_head(), 4096))))
    checks.append(("a SerializedFile whose fileSize is NOT the file is OPAQUE",
                   classify(_sf_head(), 4097)[0] == "opaque", ""))
    checks.append(("a SerializedFile with a version below 5 is OPAQUE",
                   classify(_sf_head(version=4), 4096)[0] == "opaque", ""))
    checks.append(("a SerializedFile with an endianness byte of 2 is OPAQUE",
                   classify(_sf_head(endian=2), 4096)[0] == "opaque", ""))
    checks.append(("a SerializedFile whose dataOffset is past fileSize is "
                   "OPAQUE",
                   classify(_sf_head(doff=5000), 4096)[0] == "opaque", ""))
    checks.append(("a SerializedFile with prose where the engine version "
                   "goes is OPAQUE",
                   classify(_sf_head(ver=b"hello world"), 4096)[0] == "opaque",
                   ""))
    checks.append(("a SerializedFile with no length handed over still needs "
                   "the version string",
                   _unity_serialized(_sf_head()) is True
                   and _unity_serialized(_sf_head(ver=b"x")) is False, ""))
    _v22 = (struct.pack(">IIII", 0, 0, 22, 0) + bytes([0, 0, 0, 0])
            + struct.pack(">I", 100) + struct.pack(">qq", 8192, 4096)
            + bytes(8) + b"2022.3.1f1\0")
    _v22 += bytes(96 - len(_v22))
    checks.append(("a version-22 SerializedFile (sizes at +24/+32) is DECODED",
                   classify(_v22, 8192)[0] == "decoded"
                   and classify(_v22, 8000)[0] == "opaque", ""))

    def _fsb(version=1, n=1, hdr=8, names=0, data=100, codec=2):
        h = b"FSB5" + struct.pack("<6I", version, n, hdr, names, data, codec)
        return h + bytes(64 - len(h))
    checks.append(("an FSB5 bank whose first bank fits the file is DECODED",
                   classify(_fsb(), 168)[0] == "decoded"
                   and classify(_fsb(), 100000)[0] == "decoded", ""))
    checks.append(("an FSB5 whose declared length runs past the file is "
                   "OPAQUE",
                   classify(_fsb(), 167)[0] == "opaque", ""))
    checks.append(("an FSB5 with a codec above 17 is OPAQUE",
                   classify(_fsb(codec=18), 168)[0] == "opaque", ""))
    checks.append(("an FSB5 with fewer than 8 header bytes per sample is "
                   "OPAQUE",
                   classify(_fsb(n=2, hdr=8), 168)[0] == "opaque", ""))
    checks.append(("an FSB5 at version 2 is OPAQUE",
                   classify(_fsb(version=2), 168)[0] == "opaque", ""))

    def _md(version=0xA0EEA793, n=1, rva=32, sz=16, srva=44):
        h = b"MDMP" + struct.pack("<IIIIIQ", version, n, rva, 0, 0, 0)
        h += struct.pack("<III", 7, sz, srva)
        return h + bytes(64 - len(h))
    checks.append(("a minidump whose directory and stream lie inside the "
                   "file is SPECIFIED",
                   classify(_md(), 64)[0] == "specified", ""))
    checks.append(("a minidump whose stream runs past the file is OPAQUE",
                   classify(_md(sz=40), 64)[0] == "opaque", ""))
    checks.append(("MDMP with the wrong low version word is OPAQUE",
                   classify(_md(version=0xA0EE0000), 64)[0] == "opaque", ""))
    checks.append(("MDMP with zero streams is OPAQUE",
                   classify(_md(n=0), 64)[0] == "opaque", ""))

    _mdb = struct.pack("<qii", 0x45E82623FD7FA614, 50, 0) + bytes(16)
    checks.append(("a Mono .mdb by magic and version 50.0 is SPECIFIED",
                   classify(_mdb + bytes(32))[0] == "specified", ""))
    checks.append(("the .mdb magic with version 49 is OPAQUE",
                   classify(struct.pack("<qii", 0x45E82623FD7FA614, 49, 0)
                            + bytes(48))[0] == "opaque", ""))
    _lnk = (b"L\0\0\0" + bytes.fromhex("0114020000000000c000000000000046")
            + bytes(0x4C - 20))
    checks.append(("a Shell Link by header size and CLSID is SPECIFIED",
                   classify(_lnk)[0] == "specified", ""))
    checks.append(("L\\0\\0\\0 with another CLSID is OPAQUE",
                   classify(b"L\0\0\0" + bytes(16) + bytes(0x4C - 20))[0]
                   == "opaque", ""))
    _ulog = b"Inno Setup Uninstall Log (b)"
    _ulog += bytes(64 - len(_ulog)) + b"1950261263" + bytes(118)
    checks.append(("the Inno uninstall log ID is SPECIFIED",
                   classify(_ulog)[0] == "specified", ""))
    checks.append(("the Inno uninstall log ID with a dirty pad is OPAQUE",
                   classify(_ulog[:40] + b"x" + _ulog[41:])[0] == "opaque",
                   ""))
    _umsg = b"Inno Setup Messages (5.6.2) (u)"
    _umsg += bytes(64 - len(_umsg)) + bytes(64)
    checks.append(("the Inno messages ID is SPECIFIED",
                   classify(_umsg)[0] == "specified", ""))
    checks.append(("the seven Monstrum probes all stand before every text "
                   "codec",
                   _ordering_ok() is True
                   and max([m[0] for m in MAGICS].index(p) for p in
                           (_unity_serialized, _fsb5, _mdmp, _mono_mdb,
                            _shllink, _inno_unins_log, _inno_msgs))
                   < [m[0] for m in MAGICS].index(_printable), ""))
    # the sidecar pass, on hand-built bodies: a Texture2D record, an
    # AudioClip record, and a name that occurs without its length prefix
    _tex = (b"\x08\0\0\0UISprite" + bytes(60)
            + struct.pack("<II", 5460, 5460) + b"\x19\0\0\0"
            + b"sharedassets0.assets.resS" + bytes(3))
    _clip = (b"\x04\0\0\0clip" + bytes(40) + b"\x16\0\0\0"
             + b"sharedassets3.resource" + bytes(2)
             + struct.pack("<QQ", 262944, 13632) + bytes(4))
    _fake = b"xx" + b"sharedassets0.assets.resS" + bytes(8)
    _names = ["sharedassets0.assets.resS", "sharedassets3.resource"]
    checks.append(("a Texture2D m_StreamData record is read at -12/-8 from "
                   "the path",
                   _sidecar_records(_tex, 28, _names)
                   == {"sharedassets0.assets.resS": [(5460, 5460)]},
                   str(_sidecar_records(_tex, 28, _names))))
    checks.append(("an AudioClip m_Resource record is read as two u64 after "
                   "the aligned path",
                   _sidecar_records(_clip, 83, _names)
                   == {"sharedassets3.resource": [(262944, 13632)]},
                   str(_sidecar_records(_clip, 83, _names))))
    checks.append(("a sibling's name without its length prefix is NOT a "
                   "record",
                   _sidecar_records(_fake, 28, _names) == {}, ""))
    _refs = lambda d: {"a.resS": [(0, 5460), (5460, 5460)],
                       "b.resource": [(0, 20)]}
    _rows = [("d/a.resS", 10920, "opaque", "n"),
             ("d/b.resource", 19, "opaque", "n"),
             ("d/c.resS", 10, "opaque", "n"),
             ("d/a.txt", 3, "specified", "plain text, ASCII")]
    _after = sidecar_pass(_rows, ".", _refs)
    checks.append(("the sidecar pass refiles a .resS whose records end at "
                   "its last byte as DERIVED",
                   _after[0][2] == "derived" and "sidecar" in _after[0][3],
                   str(_after[0][2:])))
    checks.append(("the sidecar pass leaves a sidecar alone when a record "
                   "runs one byte past the file",
                   _after[1][2] == "opaque", str(_after[1][2])))
    checks.append(("the sidecar pass leaves a sidecar nobody names OPAQUE",
                   _after[2][2] == "opaque", str(_after[2][2])))
    checks.append(("the sidecar pass does not touch a row already filed",
                   _after[3] == _rows[3], ""))
    checks.append(("the sidecar pass asks the directory once per directory",
                   (lambda c: (sidecar_pass(_rows, ".", lambda d: c.append(d)
                                            or {}) and len(c) == 1))([]),
                   ""))

    checks.append(("a random binary is OPAQUE",
                   classify(bytes([7, 200, 3, 99, 250]))[0] == "opaque", ""))
    checks.append(("an empty file is OPAQUE and does not crash",
                   classify(b"")[0] == "opaque", ""))
    checks.append(("the classifier emits only bucket names the report knows",
                   {m[1] for m in MAGICS} | {"opaque"}
                   <= {"specified", "decoded", "derived", "opaque"}, ""))
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


def report_ambiguity(root):
    """How many files more than one text codec accepts.

    The order of the three text codecs in MAGICS is a decision, not a
    measurement: EUC-JP's lead bytes are cp932's half-width katakana, so a
    EUC-JP document decodes under cp932 into nonsense without one illegal
    sequence. This mode publishes the cost of that decision instead of hiding
    it, which is the only honest thing a probe of this shape can do.
    """
    probes = (("utf-8", _utf8_text), ("euc_jp", _eucjp_text),
              ("cp932", _cp932_text))
    rows, multi = [], 0
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            with open(p, "rb") as fh:
                head = fh.read(HEAD)
            takers = [n for n, pr in probes if pr(head)]
            if not takers:
                continue
            rows.append((os.path.relpath(p, root).replace(os.sep, "/"),
                         takers))
            if len(takers) > 1:
                multi += 1
    if not rows:
        sys.exit("coverage: no file under %r is accepted by any multi-byte "
                 "text codec -- refusing to report a clean ambiguity table "
                 "over an empty population" % root)
    print("files accepted by at least one multi-byte text codec : %d" %
          len(rows))
    print("files accepted by MORE THAN ONE                      : %d" % multi)
    print()
    combos = {}
    for _p, takers in rows:
        combos["+".join(takers)] = combos.get("+".join(takers), 0) + 1
    for k in sorted(combos, key=lambda k: (-combos[k], k)):
        print("  %-24s %4d" % (k, combos[k]))
    print()
    print("  the codec MAGICS names first wins, and that order is a decision:")
    print("  utf-8, then euc_jp, then cp932. Every file in a row with a '+'")
    print("  in it could have been filed under another name.")
    for p, takers in rows:
        if len(takers) > 1:
            print("    %-58s %s" % (p, "+".join(takers)))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=("members", "product", "tree",
                                     "ambiguity", "selftest"))
    ap.add_argument("--members", default="_work/members")
    ap.add_argument("--root")
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest()
    if args.mode == "ambiguity":
        if not args.root:
            sys.exit("coverage: ambiguity mode needs --root")
        return report_ambiguity(args.root)
    if args.mode == "tree":
        if not args.root:
            sys.exit("coverage: tree mode needs --root")
        return report_tree(args.root)
    rows, label = population(args.mode, args.members)
    return report(rows, label, args.mode)


if __name__ == "__main__":
    sys.exit(main())
