#!/usr/bin/env python3
"""sift.py -- count named byte patterns over every file of a tree, and over
every leaf inside every `.LGP` archive, with the chance rate printed beside
every count.

`protscan.py` searched 0 files of 8 on this object because its extension list
knows `.exe` and the object is `.bin`; the zero was honest and was about the
tool. This one takes no extension list: it reads every file it is pointed at,
in full, and says how many it read out of how many exist. **A census that
filters its own population reports its filter's denominator and not the
object's**, which is `dos-platformnotes-doc` section 4 and the reason this tool
exists rather than another `--ext` flag.

Three pattern groups ship with it and each is named where it is used:

  region     the words and codes that separate a North American from a
             European release: the two spellings of half a dozen words,
             currency signs and names, language identifiers, and the
             publishers' own web addresses.
  personal   what P.1 requires be searched for before a zero is reported: an
             e-mail shape, a post-box, a telephone shape, and an absolute
             path with a user directory in it.
  buildpath  absolute paths of the form `X:\\...` and `/usr/...`, which is what
             `pc-finalfantasy8-doc/docs/16` found 31,737 of on the next game.

THE CHANCE RATE IS PRINTED FIRST AND IS NOT OPTIONAL. On this object a
four-byte needle is expected 0.4984 times in the 2,140,541,877 bytes of file
content, so a single four-byte hit is what chance produces. Every pattern below
is at least six bytes long except where marked, and the marked ones carry their
rate on the same line.

Every run prints a POSITIVE CONTROL: a pattern that must be found, and a
pattern that must not. A scan with no control is a scan you cannot read.

    python tools/sift.py ROOT --group region
    python tools/sift.py ROOT --group personal --show
    python tools/sift.py ROOT --pattern "squaresoft" --show
    python tools/sift.py ROOT --group region --leaves      also inside .LGP
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lgp  # noqa: E402

GROUPS = {
    "region": [
        # (name, regex, case-insensitive)
        ("colour", rb"colour", True),
        ("color", rb"color", True),
        ("licence", rb"licence", True),
        ("license", rb"license", True),
        ("centre", rb"centre", True),
        ("center", rb"center", True),
        ("organisation", rb"organisation", True),
        ("organization", rb"organization", True),
        ("synthesiser", rb"synthesiser", True),
        ("synthesizer", rb"synthesizer", True),
        ("catalogue", rb"catalogue", True),
        ("catalog", rb"catalog", True),
        ("United States", rb"United States", True),
        ("United Kingdom", rb"United Kingdom", True),
        ("England", rb"England", True),
        ("Europe", rb"Europe", True),
        ("squaresoft.com", rb"squaresoft\.com", True),
        ("eidosinteractive.com", rb"eidosinteractive\.com", True),
        ("eidos.co.uk", rb"eidos\.co\.uk", True),
        ("ff7pc.com", rb"ff7pc\.com", True),
        ("Square Soft, Inc", rb"Square ?Soft,? Inc", True),
        ("Square Co", rb"Square Co", True),
        ("Eidos Interactive", rb"Eidos Interactive", True),
        ("deflang1033", rb"deflang1033", False),
        ("deflang2057", rb"deflang2057", False),
        ("lang code 0409 text", rb"0x0409", True),
        ("lang code 0809 text", rb"0x0809", True),
        ("pounds sterling word", rb"pounds", True),
        ("dollars", rb"dollars", True),
        ("Deutsche", rb"Deutsch", True),
        ("Francais", rb"Fran[c\xe7]ais", True),
        ("Italiano", rb"Italiano", True),
        ("Espanol", rb"Espa[n\xf1]ol", True),
        ("Svenska", rb"Svenska", True),
    ],
    "personal": [
        ("e-mail shape", rb"[A-Za-z0-9._%+-]{3,}@[A-Za-z0-9.-]{3,}\.[A-Za-z]{2,4}",
         False),
        ("P.O. Box", rb"P\.? ?O\.? ?Box", True),
        ("telephone shape", rb"\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}", False),
        ("Documents and Settings", rb"Documents and Settings", True),
        ("home dir", rb"[A-Za-z]:\\(Users|WINDOWS\\Profiles|home)\\", True),
        ("/home/", rb"/home/[a-z]", False),
        ("Copyright <name>", rb"Copyright \(c\) 19\d\d [A-Z][a-z]+ [A-Z][a-z]+",
         False),
        # ADDED ON pc-rovescino-doc, AND THE REASON IS A ZERO THIS TOOL GOT
        # WRONG. That object's executable carries a line of the shape
        #     Via <street> n.<number> 89100 Reggio Calabria.
        # -- a named private individual's full street address; the street
        # itself is deliberately not written here, because a scanner that
        # quotes the string it hunts for publishes it -- and the seven
        # patterns above returned 0 on it with BOTH controls firing. A scan
        # that passes its own controls and misses the thing it exists to find
        # is the P19 blind spot in its purest form, so the gap is closed here
        # rather than written up as an anecdote.
        #
        # These two are deliberately LOOSE. In a scan whose whole purpose is
        # to stop a private address being republished by accident, a false
        # positive costs somebody thirty seconds of looking and a false
        # negative costs somebody their address, and those are not the same
        # price. Both are reported with their hits so a reader can dismiss
        # them; neither is quiet.
        # AND THE SECOND ORDER, ADDED ON pc-hexxagon-doc, WHERE THE FIRST GAVE
        # ZERO ON AN OBJECT CONTAINING FOUR STREET ADDRESSES.
        #
        # The branch above wants the thoroughfare word FIRST and the number
        # LAST -- `Via <name> n.<number>` -- which is the Italian order and the
        # order of the object it was written for. The Anglo-American order is
        # the opposite: `26 Harris St.`, number first and thoroughfare word
        # last. `HEXXAGON`'s publisher's address appears four times across
        # `LICENSE.DOC`, `ORDERFRM.DOC` and `VENDOR.DOC` and this pattern
        # reported **0**, with both controls firing.
        #
        # That is the same shape as the defect the pattern was written to fix,
        # one object later: **a repair that closed the form it was shown and
        # did not ask what the other forms were.** It cost nothing here --
        # these are a company's own published order-form addresses, which this
        # box's doctrine does not redact -- and the next object it meets may
        # be a person's.
        ("street address shape",
         rb"(?:"
         rb"(?i:\b(?:via|viale|vicolo|piazza|corso|strada|str\.|street|"
         rb"avenue|ave\.|road|rue|calle|stra[sz]e)\b[ .]{0,2}"
         rb"[A-Za-z.'\- ]{2,30}\bn?[.]? ?\d{1,4}\b)"
         rb"|"
         rb"\b\d{1,5} +[A-Z][A-Za-z.'\-]{1,20}(?: +[A-Z][A-Za-z.'\-]{1,20})"
         rb"{0,3} +(?i:st|street|ave|avenue|rd|road|blvd|boulevard|dr|drive|"
         rb"ln|lane|way|ct|court|pl|place|sq|square|hwy|highway|pkwy|"
         rb"parkway)\b\.?"
         rb")", False),
        # DELIBERATELY LOOSE, AND NOW MEASURED. On `pc-hexxagon-doc` this
        # returns 10 hits of which 1 is an address -- `01510  Online`, the
        # publisher's postcode in Clinton, Massachusetts -- and 9 are a
        # modem speed (`2400 BAUD`), a Minitel code (`3615 RUSTY`), a fax
        # number and six rows of a packing list (`42309  Main`). That is a
        # 1-in-10 signal rate and it is the first real measurement of the
        # trade this pattern's comment above declares. It is left loose: nine
        # dismissals cost a reader half a minute and the tenth is the point.
        ("postal code and town",
         rb"\b\d{4,5} +[A-Z][A-Za-z]{2,}", False),
    ],
    "buildpath": [
        ("drive-letter path", rb"[A-Za-z]:\\[A-Za-z0-9_.~\\-]{6,}", False),
        ("unix build path", rb"/[a-z0-9_]{2,}/[a-z0-9_]{2,}/[a-z0-9_./]{4,}\.[ch]",
         False),
    ],
}

# A pattern that must be found on this object and one that must not.
#
# The positive control used to be the literal string `Final Fantasy`, hard
# coded, because that is what the object in front of the author happened to
# contain. On the very next object it did not fire and the tool announced that
# the scan was broken -- and the scan was fine. A control that only works on
# the author's object is not a control; it is a memory of one.
#
# The fix is that the positive control is now DERIVED FROM THE POPULATION: the
# first run of printable bytes long enough to be distinctive, taken from the
# first blob the walker yields. It is by construction present, so if it does
# not fire the scan really is broken. Pass --control to override it.
CONTROL_MISS = ("CONTROL must-miss 'zzqxjvwk'", rb"zzqxjvwk", False)
CONTROL_MIN = 8


def derive_control(first_blob, override=None):
    """Return (label, pattern, ignore_case) for a control that must fire."""
    if override:
        return ("CONTROL must-hit %r (given)" % override,
                override.encode("latin-1"), False)
    run = bytearray()
    for c in first_blob:
        if 0x20 <= c < 0x7F and c not in b"\\^$.|?*+()[]{}":
            run.append(c)
            if len(run) >= CONTROL_MIN:
                pat = bytes(run)
                return ("CONTROL must-hit %r (derived from the population)"
                        % pat.decode("latin-1"), pat, False)
        else:
            run = bytearray()
    return ("CONTROL must-hit (none derivable)", b"\x00" * CONTROL_MIN, False)


def compile_group(items):
    out = []
    for name, pat, ci in items:
        out.append((name, re.compile(pat, re.I if ci else 0)))
    return out


def blobs(root, leaves):
    """Yield (label, bytes). Every file, in full, plus LGP leaves if asked."""
    for r, dirs, names in os.walk(root):
        dirs.sort()
        for nm in sorted(names):
            p = os.path.join(r, nm)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            with open(p, "rb") as fh:
                data = fh.read()
            yield rel, data
            if leaves and nm.upper().endswith(".LGP"):
                _c, entries, _l, _cf, _t, _a = lgp.parse(data, p)
                for e in entries:
                    yield (rel + "#" + e["name"],
                           data[e["data"]:e["data"] + e["length"]])


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--group", choices=sorted(GROUPS))
    ap.add_argument("--pattern")
    ap.add_argument("--ignore-case", action="store_true")
    ap.add_argument("--show", action="store_true",
                    help="print the files each pattern was found in")
    ap.add_argument("--leaves", action="store_true",
                    help="also search inside every .LGP member")
    ap.add_argument("--context", type=int, default=0)
    ap.add_argument("--control",
                    help="literal text the scan MUST find; when omitted the "
                         "control is derived from the population itself")
    a = ap.parse_args(argv[1:])

    if a.pattern:
        items = [("--pattern " + a.pattern, a.pattern.encode("latin1"),
                  a.ignore_case)]
    elif a.group:
        items = GROUPS[a.group]
    else:
        ap.error("give --group or --pattern")
    walker = blobs(a.root, a.leaves)
    try:
        first = next(walker)
    except StopIteration:
        print("sift: empty population -- nothing to search", file=sys.stderr)
        return 3
    control_hit = derive_control(first[1], a.control)
    pats = compile_group(items + [control_hit, CONTROL_MISS])

    hits = {name: [] for name, _ in pats}
    counts = {name: 0 for name, _ in pats}
    nfiles = 0
    nbytes = 0
    import itertools
    for label, data in itertools.chain([first], walker):
        nfiles += 1
        nbytes += len(data)
        for name, rx in pats:
            found = rx.findall(data)
            if found:
                counts[name] += len(found)
                hits[name].append((label, len(found),
                                   [m for m in found[:3]]))
    print("root                : %s" % a.root)
    print("blobs searched      : %d   (%d of %d -- nothing was filtered out)"
          % (nfiles, nfiles, nfiles))
    print("bytes searched      : %d" % nbytes)
    print("chance rate in this haystack, per needle width:")
    for w in (2, 4, 6, 8):
        print("    %d bytes  %14.6f expected occurrences"
              % (w, nbytes / (256.0 ** w)))
    print()
    print("%-34s %8s %8s" % ("pattern", "hits", "blobs"))
    print("-" * 54)
    for name, _rx in pats:
        print("%-34s %8d %8d" % (name, counts[name], len(hits[name])))
    print("-" * 54)
    ctl_hit = counts[control_hit[0]]
    ctl_miss = counts[CONTROL_MISS[0]]
    print("positive control fired : %s (%d hits)"
          % ("YES" if ctl_hit else "NO -- THE SCAN IS BROKEN", ctl_hit))
    print("negative control quiet : %s"
          % ("YES" if ctl_miss == 0 else "NO -- THE SCAN IS BROKEN"))
    if a.show:
        print()
        for name, _rx in pats:
            if not hits[name] or name.startswith("CONTROL"):
                continue
            print("=== %s ===" % name)
            for label, n, sample in hits[name][:40]:
                print("    %-52s x%-5d %s" % (label, n,
                      b" | ".join(s if isinstance(s, bytes) else s[0]
                                 for s in sample)[:80]))
            if len(hits[name]) > 40:
                print("    ... and %d more blobs" % (len(hits[name]) - 40))
    return 0 if ctl_hit and ctl_miss == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
