#!/usr/bin/env python3
"""contacts.py -- address-shaped strings in a tree, counted and classified,
and by default not printed.

An at-sign inside 634 MB of compressed video is common. A scan for e-mail
addresses over this kind of object returns mostly noise, and the noise is not
harmless: printing it all is how a real address ends up in a repository beside
thirty fake ones. So this tool separates three things and treats them
differently:

  **function addresses** -- a role, not a person: `webmaster@`, `support@`,
    `info@`, `sales@`, `CPS-requests@`, anything whose local part is a listed
    role word. Printed in full, because naming a company's support address is
    not naming anybody.

  **person-shaped addresses** -- a local part that looks like an individual
    (an initial and a surname, a first-name-dot-surname, a surname alone) at a
    corporate domain. **Counted, and printed only as a shape**: the domain, the
    number of distinct addresses, the number of occurrences, and where. The
    local part never reaches the output. This is the branch's standing rule and
    it is enforced here rather than remembered.

  **noise** -- a run of bytes that happens to contain an at-sign. The test is
    whether the local part and the domain look like language: a domain whose
    labels have no vowel, or repeat one character, or contain a character no
    hostname may contain, is noise. Counted, and a sample of the *shapes* is
    printed so the reader can see why they were rejected.

The raw hit count -- what a naive scanner prints -- is always reported beside
the classified counts, because that is the number a reader will get if they run
a naive scanner, and the difference between the two is the finding.

    python tools/contacts.py DIR
    python tools/contacts.py DIR --show-noise
    python tools/contacts.py DIR --urls
    python tools/contacts.py DIR --reveal    # requires --i-am-sure
"""

import argparse
import collections
import os
import re

ADDR = re.compile(rb"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{2,64}\.[A-Za-z]{2,10}")
URL = re.compile(rb"(?:https?|ftp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{4,200}")
TELFAX = re.compile(rb"(?i)\b(?:tel|fax|phone)[:.]?\s?[+0-9][0-9 ()\-.]{6,}")

ROLES = {"webmaster", "support", "info", "sales", "admin", "postmaster",
         "help", "service", "contact", "sysop", "abuse", "noreply",
         "no-reply", "cps-requests", "hostmaster", "marketing", "press",
         "techsupport", "tech", "customerservice", "orders"}

VOWELS = set("aeiouAEIOU")


def plausible_domain(dom):
    labels = dom.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if not tld.isalpha() or not (2 <= len(tld) <= 6):
        return False
    for lab in labels:
        if not lab or lab.startswith("-") or lab.endswith("-"):
            return False
        if not re.fullmatch(r"[A-Za-z0-9\-]+", lab):
            return False
    body = "".join(labels[:-1])
    if not body:
        return False
    if not any(c in VOWELS for c in body):
        return False
    if len(set(body.lower())) <= 2:
        return False
    # A domain that is all upper case with no vowel pattern is usually a run of
    # video bytes; one that is all digits is not a domain.
    if body.isdigit():
        return False
    return True


def plausible_local(loc):
    if not loc or len(loc) > 40:
        return False
    if not any(c in VOWELS for c in loc):
        return False
    if len(set(loc.lower())) <= 2:
        return False
    return True


# A file whose whole content is a licence text.  An address printed inside one
# was published by its owner, on purpose, in a document meant to travel with
# the software.  The list is deliberately short and is matched on the file
# name only: nothing found inside a container can be promoted this way.
LICENCE_FILES = {"legal.txt", "license.txt", "licence.txt", "licenses.txt",
                 "copying", "copying.txt", "notice.txt", "third-party.txt",
                 "thirdparty.txt", "credits.txt"}


def classify(addr, where=None):
    """where: the set (or list) of file names the address was found in.

    Three classes were not enough for this object.  An address in an
    open-source licence is neither a role nor a leak: its owner published it,
    and it has been in every copy of that library for years.  It is counted as
    `published`, and like `person` it is never printed."""
    loc, _, dom = addr.partition("@")
    if not plausible_domain(dom) or not plausible_local(loc):
        return "noise"
    if loc.lower() in ROLES:
        return "function"
    if where:
        names = {os.path.basename(str(w)).lower() for w in where}
        if names and names <= LICENCE_FILES:
            return "published"
    return "person"


def shape(loc):
    """Describe a local part without reproducing it."""
    if re.fullmatch(r"[A-Za-z]-[A-Za-z]{2,}", loc):
        return "<initial>-<surname>"
    if re.fullmatch(r"[A-Za-z]+\.[A-Za-z]+", loc):
        return "<name>.<name>"
    if re.fullmatch(r"[A-Za-z]+_[A-Za-z]+", loc):
        return "<name>_<name>"
    if re.fullmatch(r"[A-Za-z]+[0-9]+", loc):
        return "<word><digits>"
    if re.fullmatch(r"[A-Za-z]+", loc):
        return "<single word>"
    return "<mixed, %d characters>" % len(loc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--show-noise", action="store_true")
    ap.add_argument("--urls", action="store_true")
    ap.add_argument("--reveal", action="store_true")
    ap.add_argument("--i-am-sure", action="store_true")
    a = ap.parse_args()

    if a.reveal and not a.i_am_sure:
        raise SystemExit("--reveal prints personal data; pass --i-am-sure too, "
                         "and do not paste the result anywhere")

    files = []
    for dp, dn, fn in os.walk(a.root):
        for f in sorted(fn):
            files.append(os.path.join(dp, f))

    raw = 0
    hits = collections.defaultdict(list)     # addr -> [paths]
    urls = collections.defaultdict(list)
    telfax = []
    nbytes = 0
    for p in files:
        data = open(p, "rb").read()
        nbytes += len(data)
        rel = os.path.relpath(p, a.root).replace(os.sep, "/")
        for m in ADDR.finditer(data):
            raw += 1
            hits[m.group(0).decode("latin-1")].append(rel)
        for m in URL.finditer(data):
            urls[m.group(0).decode("latin-1").rstrip(".,)\"'")].append(rel)
        for m in TELFAX.finditer(data):
            telfax.append((rel, m.group(0).decode("latin-1")))

    print("files searched        : %d" % len(files))
    print("bytes searched        : %d" % nbytes)
    print()
    print("=" * 68)
    print("ADDRESS-SHAPED STRINGS")
    print("raw occurrences (what a naive scanner prints) : %d" % raw)
    print("raw distinct                                  : %d" % len(hits))

    buckets = collections.defaultdict(dict)
    for addr, where in hits.items():
        buckets[classify(addr, where)][addr] = where
    for k in ("function", "person", "published", "noise"):
        n = len(buckets[k])
        occ = sum(len(v) for v in buckets[k].values())
        print("  %-9s : %3d distinct, %3d occurrences" % (k, n, occ))
    print()

    print("-- function addresses (a role, not a person: printed) ---------------")
    for addr, where in sorted(buckets["function"].items()):
        c = collections.Counter(where)
        print("   %-34s x%-3d  %s"
              % (addr, len(where),
                 ", ".join("%s%s" % (p, "" if n == 1 else " x%d" % n)
                           for p, n in c.most_common(3))))
    print()

    print("-- person-shaped addresses (COUNTED, NOT PRINTED) -------------------")
    if not buckets["person"]:
        print("   none")
    bydom = collections.defaultdict(lambda: [0, 0, set()])
    for addr, where in buckets["person"].items():
        loc, _, dom = addr.partition("@")
        e = bydom[dom]
        e[0] += 1
        e[1] += len(where)
        e[2].update(where)
    for dom, (nd, occ, files_) in sorted(bydom.items()):
        print("   domain %-28s %d distinct address(es), %d occurrence(s)"
              % (dom, nd, occ))
        for f in sorted(files_):
            print("        in %s" % f)
        for addr in sorted(buckets["person"]):
            if addr.endswith("@" + dom):
                loc = addr.split("@")[0]
                print("        local part shape: %s   (not reproduced)"
                      % shape(loc))
                if a.reveal:
                    print("        REVEALED: %s" % addr)
    print()

    print("-- published addresses (printed in a licence by their own owner:")
    print("   COUNTED, NOT PRINTED) ---------------------------------------------")
    if not buckets["published"]:
        print("   none")
    for addr, where in buckets["published"].items():
        loc, _, dom = addr.partition("@")
        print("   domain %-30s in %s"
              % (dom, ", ".join(sorted(os.path.basename(str(w))
                                       for w in where))))
    print()
    print("-- noise (an at-sign inside something else) -------------------------")
    print("   %d distinct in %d occurrences"
          % (len(buckets["noise"]), sum(len(v) for v in buckets["noise"].values())))
    bysrc = collections.Counter()
    for addr, where in buckets["noise"].items():
        for w in where:
            bysrc[w] += 1
    for f, n in bysrc.most_common(10):
        print("      %-46s %d" % (f, n))
    if a.show_noise:
        for addr in sorted(buckets["noise"])[:40]:
            print("      %s" % addr)
    print()

    print("=" * 68)
    print("TEL / FAX PATTERN : %d occurrences" % len(telfax))
    for rel, s in telfax[:12]:
        print("   %-40s %s" % (rel, s.strip()))
    print()

    if a.urls:
        print("=" * 68)
        print("URLS : %d distinct, %d occurrences"
              % (len(urls), sum(len(v) for v in urls.values())))
        for u, where in sorted(urls.items()):
            print("   %-52s x%-3d %s" % (u, len(where), sorted(set(where))[0]))


if __name__ == "__main__":
    main()
