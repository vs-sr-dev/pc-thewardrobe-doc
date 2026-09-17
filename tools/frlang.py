#!/usr/bin/env python3
"""frlang.py - which language is inside the `.FR` members?

The extension says French. Seven `.FR` members are stored uncompressed inside
the volumes and read as English without decompressing anything, which is the
warning this object gives about trusting extensions. This tool settles the
other seventy-nine.

Method, stated so the number can be argued with: every printable run of eight
characters or more that contains a space is pulled out of the member, lowercased,
and split on non-letters. Two closed word lists - French function words and
English function words, disjoint by construction - are counted over the tokens.
A member is called `en` or `fr` by which list wins, `?` when neither scores or
they tie. Accented Latin-1 letters are counted separately, because French text
that survived a translation pass keeps its accents and English never grows them.

This is a classifier, not a reading. Its output is a count with a denominator,
and the disagreements are printed one by one so a person can read them.

Usage:
    frlang.py <dir>                 classify every .FR under a root
    frlang.py <dir> --show          also print every string it found
    frlang.py --selftest            positive and negative controls
"""
import sys
import os
import re
import glob
import argparse

FRENCH = set("""le la les un une des du de et est sont dans pour avec qui que
quoi sur sous par pas plus tout tous toute rien ne se ce cette cet mais ou ici
vous nous ils elle elles je tu moi toi son sa ses mon ma mes votre notre leur
il y a au aux en est-ce peut faire fait vais dois puis dit dire voir prendre
porte rien jamais toujours encore bien tres etre avoir monsieur madame
mademoiselle oui non merci bonjour cadavre bateau chambre""".split())

ENGLISH = set("""the you and of to is it in on with this that there have has had
was were are be been will would can could should must not no yes any some
what where when who why how examine take open close look talk give use put
door room ship body dead nothing something everything about from into out
your my his her their they we i am hello thanks sir madam miss""".split())

ACCENTS = set("àâäçèéêëîï"
              "ôöùûüÀÇÈÉÊ")

RUN = re.compile(rb"[\x20-\x7e\xa0-\xff]{8,}")


def strings_of(data):
    out = []
    for m in RUN.finditer(data):
        s = m.group().decode("latin-1")
        if " " in s:
            out.append(s)
    return out


def classify(data):
    strs = strings_of(data)
    text = " ".join(strs)
    toks = [t for t in re.split(r"[^a-zA-ZÀ-ÿ]+", text.lower()) if t]
    fr = sum(1 for t in toks if t in FRENCH)
    en = sum(1 for t in toks if t in ENGLISH)
    acc = sum(1 for c in text if c in ACCENTS)
    if fr == 0 and en == 0:
        lang = "?"
    elif en > fr:
        lang = "en"
    elif fr > en:
        lang = "fr"
    else:
        lang = "?"
    return lang, en, fr, acc, len(toks), strs


def cmd_run(args):
    root = args.path
    files = sorted(glob.glob(os.path.join(root, "**", "*.FR"), recursive=True))
    seen = {}
    for f in files:
        seen.setdefault(os.path.basename(f), f)
    print("%-14s %-4s %5s %5s %5s %6s" %
          ("member", "lang", "en", "fr", "acc", "words"))
    tally = {"en": 0, "fr": 0, "?": 0}
    accented = 0
    empty = 0
    for name in sorted(seen):
        data = open(seen[name], "rb").read()
        lang, en, fr, acc, n, strs = classify(data)
        tally[lang] += 1
        if acc:
            accented += 1
        if not strs:
            empty += 1
        print("%-14s %-4s %5d %5d %5d %6d" % (name, lang, en, fr, acc, n))
        if args.show:
            for s in strs:
                print("        %s" % s)
    print()
    print("distinct .FR members : %d (of %d entries)" % (len(seen), len(files)))
    print("classified English   : %d" % tally["en"])
    print("classified French    : %d" % tally["fr"])
    print("undecided            : %d" % tally["?"])
    print("carrying accented Latin-1 letters : %d" % accented)
    print("with no readable sentence at all  : %d" % empty)
    return 0


def cmd_selftest(args):
    cases = [
        ("English narration", b"It was on a cold spring morning that the body "
                              b"was found in the room", "en"),
        ("French narration", b"C'est dans la chambre que le cadavre a ete "
                             b"trouve par les invites du bateau", "fr"),
        ("no words at all", bytes(200), "?"),
        ("short runs only", b"ab\x00cd\x00ef\x00", "?"),
    ]
    fired = 0
    for label, blob, want in cases:
        got = classify(blob)[0]
        ok = got == want
        fired += ok
        print("%-22s wanted %-3s got %-3s  %s"
              % (label, want, got, "ok" if ok else "<<< FAIL"))
    print()
    print("controls that behaved: %d of %d" % (fired, len(cases)))
    return 0 if fired == len(cases) else 1


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return cmd_selftest(args)
    if not args.path:
        ap.error("a directory is required unless --selftest is given")
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
