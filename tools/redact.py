#!/usr/bin/env python3
"""redact.py -- remove routable personal contacts from a text file, by
program, and fail loudly when it removes nothing.

THE RULE THIS TOOL IMPLEMENTS, which is argued in the personal-data chapter:

    In a signature block its author wrote in order to be credited and
    contacted, PUBLISH what claims credit and REDACT what routes a message.

    Credit is authorship: names, handles, the studio, the thanks, the version,
    the project page. Routing is anything a stranger can use TODAY to reach a
    private individual: an e-mail address, an account on a service that is
    still running, a private person's telephone number.

    A company's published support line is not a private individual's contact
    and is not redacted.

What that came to on `pc-rpgmaker95-doc`: one e-mail address removed, and
everything else in the same paragraph published -- the six aliases, the name,
the ICQ number on a service that closed in 2024, and the URL of a host that no
longer exists.

THE AMENDMENT `pc-rpgmaker2000-doc` ADDED, because the rule met a case it was
not written for. There, the author had put his address in his own product and
asked to be written to. Here the addresses are a THIRD PARTY's, in the manual of
a library he wrote, shipped unmodified inside somebody else's product fifteen
years later; and one of the two is a member ID on a service whose survival this
repository could not establish either way. So:

    Where the rule cannot establish that an address has stopped routing,
    it redacts. The burden runs that way and not the other, because the
    cost of being wrong is not symmetric: publishing a live address harms
    a person, and withholding a dead one costs a reader a string that the
    chapter tells them how to find.

    And consent to be contacted about one's own work in one's own release
    is not consent to be listed, decades later, in a third party's
    documentation of somebody else's product.

Both addresses are therefore redacted, and the author's NAME, his company, his
copyright line, his version number and his manual's own date are published.

THE LIMIT, STATED RATHER THAN HIDDEN. The address is reconstructable from what
this repository publishes, because one of the author's own aliases is its local
part. This redaction is against automated harvesting of the literal string, not
against a reader who wants it. A redaction that claimed more than that would be
a lie.

Failure is loud and is the point. `--expect N` makes the count part of the
contract, and a run that replaces nothing when something was expected returns
non-zero rather than quietly copying the file through.

    python tools/redact.py notes/sift-personal.txt --in-place --expect 1
    python tools/redact.py notes/sift-personal.txt --check
    python tools/redact.py selftest
"""
import argparse
import os
import re
import sys

# Deliberately narrow. A wide pattern would eat the vendor telephone numbers,
# the URL and the version strings, all of which this repository publishes.
EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TOKEN = b"[e-mail redacted: see docs on the personal data]"

# THE SIXTEEN-BIT PASS, ADDED ON pc-rpgmakerxp-doc.
#
# For five objects this tool's eight-bit pattern was enough, because every
# address it met was in somebody's plain-text manual. On this object the
# address is in `SciLexer.dll`'s `CompanyName`, and a version resource is
# written by the linker in UTF-16LE. Pointed at that file with `--expect 1`,
# this tool reported **0 replaced and failed loudly** -- which is what
# `--expect` is for, and it is the tool catching its own limit rather than a
# person noticing it.
#
# `sift.py` has the same eight-bit blindness and `pc-rpgmaker2003-doc/docs/13`
# listed it as "carried, quiet". It is not quiet here: on this object the
# eight-bit pass cannot see the address, cannot see `Yoji Ojima` and cannot
# see `Neil Hodgson`, all three of which live in version resources.
#
# The wide replacement is written back as UTF-16LE so the result stays
# well-formed. It is not the same length as what it replaces, which does not
# matter because this repository never writes to the object -- the object is
# opened read-only and only `notes/` is ever rewritten in place.
EMAIL16 = re.compile(
    rb"(?:[A-Za-z0-9._%+-]\x00)+@\x00(?:[A-Za-z0-9.-]\x00)+\.\x00"
    rb"(?:[A-Za-z]\x00){2,}")
TOKEN16 = TOKEN.decode("ascii").encode("utf-16-le")

# THE POSTAL PASS, ADDED ON pc-rovescino-doc.
#
# For nine objects every routable contact this tool met was an e-mail address,
# so an e-mail address is all it could remove. Then it met a 1992 public-
# domain DOS game whose credits screen reads
#
#     PROGRAMMA DI PUBLIC DOMAIN by <name>
#     Via <street> n.<number> <postcode> <town>.
#
# and this tool, pointed at it with `--expect 1`, replaced **nothing**. So did
# `sift.py --group personal`, whose seven patterns are all e-mail, telephone
# or Windows profile paths. A redactor that cannot redact the only kind of
# address its object contains is not narrow, it is blind, and the rule at the
# top of this file -- publish credit, redact routing -- had nothing to bite on.
#
# WHAT IS REDACTED AND WHAT IS NOT, and the line is drawn deliberately:
#
#   * the THOROUGHFARE and the HOUSE NUMBER are removed. Together they are
#     the part a stranger can put on an envelope today, and the amendment
#     above says that where this repository cannot establish that an address
#     has stopped routing, it redacts. A 1992 street address cannot be shown
#     to have stopped routing and thirty-three years is not proof.
#   * the POSTCODE and the TOWN are kept. They do not route to a person, they
#     are geography, and on this object they are load-bearing: the town in the
#     address and the town in the credits are different towns, and that
#     difference is the finding.
#   * the NAME is kept, because credit is the whole reason the line exists.
#
# The pattern stops at the house number for exactly that reason. `--check`
# will show what it matched, and it is a substitution and not a deletion, so
# a reader can see that something was taken out.
STREET = re.compile(
    rb"(?i)\b(?:via|viale|vicolo|piazza|piazzale|corso|largo|strada|contrada|"
    rb"street|avenue|road|rue|calle|stra[sz]e)\b[ .]{0,2}"
    rb"[A-Za-z.'\-]+(?: [A-Za-z.'\-]+){0,4}[, ]{0,2}"
    rb"\b(?:n|no|nr|num)?[.]? ?\d{1,4}\b")
STREET_TOKEN = b"[street address redacted: see docs on the personal data]"


def redact(data):
    """Returns (new_bytes, count). Bytes in, bytes out: the files this is
    pointed at hold CP437 and CP866 fragments and must not be decoded.

    All three passes are swept and the counts are added, so `--expect` counts
    addresses and not passes."""
    out, n8 = EMAIL.subn(TOKEN, data)
    out, n16 = EMAIL16.subn(TOKEN16, out)
    out, nst = STREET.subn(STREET_TOKEN, out)
    return out, n8 + n16 + nst


def counts(data):
    """(eight-bit, UTF-16, postal) separately, for a report that has to say
    which pass found what."""
    return (len(EMAIL.findall(data)), len(EMAIL16.findall(data)),
            len(STREET.findall(data)))


def cmd_run(args):
    if not os.path.exists(args.path):
        raise SystemExit("redact: no such file: %s" % args.path)
    with open(args.path, "rb") as fh:
        data = fh.read()
    out, n = redact(data)
    n8, n16, nst = counts(data)
    print("file      : %s" % args.path)
    print("bytes     : %d" % len(data))
    print("addresses : %d replaced" % n)
    print("  of which the eight-bit pass found : %d" % n8)
    print("  of which only a UTF-16 pass finds : %d" % n16)
    print("  of which the postal pass found    : %d" % nst)
    if args.expect is not None and n != args.expect:
        print("redact: FAILED -- expected %d and replaced %d"
              % (args.expect, n), file=sys.stderr)
        return 1
    if args.check:
        # Counted over the INPUT, unchanged from the behaviour five objects
        # have used: `--check` answers "does this file still carry an
        # address", so a file that does exits non-zero and says so.
        print("check     : %d address-shaped strings remain in the file "
              "(%d eight-bit, %d UTF-16, %d postal)"
              % (n8 + n16 + nst, n8, n16, nst))
        return 1 if (n8 + n16 + nst) else 0
    if args.in_place:
        with open(args.path, "wb") as fh:
            fh.write(out)
        print("written   : %s" % args.path)
    else:
        sys.stdout.write(out.decode("latin-1"))
    return 0


def cmd_selftest(args):
    checks = []

    # The specimen used to be the real address this tool exists to remove.
    # `pc-rpgmaker2000-doc` found it here: that repository redacted the
    # address from every chapter and every file under `notes\`, and left it
    # written out twice inside the source of the tool that does the
    # redacting -- a file which is committed and published. The specimen is
    # now `.invalid`, a top-level domain RFC 2606 reserves so that it can
    # never resolve, and a check below asserts that no address in this file's
    # own source is anything else.
    body = b"ICQ UIN #2444691       E-mail: someone@example.invalid\n"
    out, n = redact(body)
    checks.append(("an address is replaced and the count is 1",
                   n == 1 and b"@" not in out, out.decode("latin-1").strip()))
    checks.append(("the ICQ number beside it survives",
                   b"2444691" in out, ""))

    survivors = [
        (b"http://www.chat.ru/~rpgmaker", "a project URL"),
        (b"(847) 240-9111", "a company support line"),
        (b"Don_Miguel aka BMV aka Mummy aka GrEeZlY", "the alias list"),
        (b"Created by Miguel Bratous aka Don Miguel", "the author's name"),
        (b"RPG Maker 95+ v 1.02", "a version string"),
        (b"C:\\Program Files\\RPG95", "a path with an @-free colon"),
    ]
    for text, label in survivors:
        out, n = redact(text)
        checks.append((label + " is NOT touched", n == 0 and out == text,
                       "" if n == 0 else "replaced %d" % n))

    # Things that must be caught, including shapes the object does not have.
    catches = [
        b"a@b.invalid", b"first.last+tag@sub.domain.example",
        b"SOMEONE@EXAMPLE.INVALID",
    ]
    for text in catches:
        out, n = redact(text)
        checks.append(("%s is caught" % text.decode(), n == 1, ""))

    # THE CHECK THAT WOULD HAVE CAUGHT THE LEAK. Every address-shaped string
    # in this file's own source must sit in a domain that cannot resolve --
    # `.invalid` or `.example`, both reserved by RFC 2606 -- so that the tool
    # which removes contacts can never itself be the thing that publishes one.
    src = open(os.path.abspath(__file__), "rb").read()
    found = EMAIL.findall(src)
    leaked = [a for a in found
              if not a.lower().endswith((b".invalid", b".example"))]
    checks.append(("no address in this tool's own source is routable",
                   not leaked,
                   "LEAKED: %s" % b", ".join(leaked).decode("latin-1")
                   if leaked else "%d specimens, all reserved" % len(found)))

    # A file with nothing to redact must be reported as zero, not as success.
    out, n = redact(b"no contacts here at all")
    checks.append(("a file with no address reports zero rather than one",
                   n == 0, ""))

    # Bytes in, bytes out: high bytes must survive untouched.
    high = bytes([0xE1, 0xE7, 0xA8]) + b" x@y.invalid " + bytes([0xCD, 0xB3])
    out, n = redact(high)
    checks.append(("high bytes either side of an address are preserved",
                   n == 1 and out.startswith(bytes([0xE1, 0xE7, 0xA8]))
                   and out.endswith(bytes([0xCD, 0xB3])), ""))

    # The UTF-16 pass, added on pc-rpgmakerxp-doc. Two of these must FAIL to
    # be caught by the eight-bit pattern, because "the eight-bit pass cannot
    # see it" is the whole reason the second pattern exists.
    wide = "somebody@example.invalid".encode("utf-16-le")
    checks.append(("a UTF-16 address is invisible to the eight-bit pattern",
                   len(EMAIL.findall(wide)) == 0, ""))
    out, n = redact(wide)
    checks.append(("a UTF-16 address IS replaced, and counted once",
                   n == 1, str(n)))
    checks.append(("its replacement is written back as UTF-16",
                   out == TOKEN16, out[:20].hex()))
    n8, n16, nst = counts(b"a@b.invalid " + wide)
    checks.append(("the three passes are counted separately",
                   (n8, n16, nst) == (1, 1, 0), str((n8, n16, nst))))

    # -- THE POSTAL PASS, added on pc-rovescino-doc ------------------------
    # THE FIXTURE'S STREET IS FICTIONAL AND THAT IS NOT FUSSINESS.
    # The first draft of this selftest used the real street this pass was
    # written for, so `redact.py` -- the tool whose whole job is to keep a
    # street address out of a published repository -- published one, in its
    # own source, in the check that proves it removes them. That is the exact
    # defect the docstring above records `pathcheck.py` having had. The
    # postcode and the town are real because this repository publishes them
    # deliberately and the checks below are about their SURVIVING.
    line = b"PROGRAMMA DI PUBLIC DOMAIN by A Name\r\nVia Di Prova n.8 " \
           b"89100 Reggio Calabria."
    out, n = redact(line)
    checks.append(("a street address is replaced, and counted once",
                   n == 1, str(n)))
    checks.append(("the AUTHOR'S NAME survives the redaction",
                   b"by A Name" in out, out.decode("latin-1")))
    checks.append(("the POSTCODE survives the redaction",
                   b"89100" in out, out.decode("latin-1")))
    checks.append(("the TOWN survives the redaction",
                   b"Reggio Calabria" in out, out.decode("latin-1")))
    checks.append(("the STREET does not survive the redaction",
                   b"Prova" not in out, out.decode("latin-1")))
    checks.append(("the HOUSE NUMBER does not survive the redaction",
                   b"n.8" not in out, out.decode("latin-1")))
    checks.append(("the eight-bit e-mail pattern cannot see a street at all",
                   len(EMAIL.findall(line)) == 0, ""))
    for quiet in (b"Turbo C++ - Copyright 1990 Borland Intl.",
                  b"89100 Reggio Calabria.",
                  b"PROGRAMMA DI PUBLIC DOMAIN by A Name",
                  b"the road ahead",
                  b"Divide error"):
        _o, n = redact(quiet)
        checks.append(("the postal pass leaves %r alone"
                       % quiet[:28].decode("latin-1"), n == 0, str(n)))
    inside = ("CompanyName\0Neil Hodgson x@y.invalid\0"
              .encode("utf-16-le"))
    _o, n = redact(inside)
    checks.append(("an address inside a version resource is found",
                   n == 1, str(n)))
    ascii_only = b"CompanyName\x00Neil Hodgson\x00"
    _o, n = redact(ascii_only)
    checks.append(("a name with no address is not touched by either pass",
                   n == 0, str(n)))
    checks.append(("a bare '@' between two wide runs is not an address",
                   len(EMAIL16.findall("no at sign here".encode("utf-16-le")))
                   == 0, ""))

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


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", help="a file, or the word selftest")
    ap.add_argument("--in-place", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--expect", type=int)
    args = ap.parse_args()
    if args.path == "selftest":
        return cmd_selftest(args)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
