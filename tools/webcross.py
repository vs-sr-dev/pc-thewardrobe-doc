#!/usr/bin/env python3
"""webcross.py -- the website inside the disc, crossed against the file system.

Sonic Adventure carries 19 .HTM, 701 .GIF and 7 .JPG in /SONICADV: a set of
hint pages meant to be read on a PC, pressed onto a console disc. This tool
answers three questions the object can answer and a briefing cannot:

  * how many URLs the pages cite, and to where;
  * how many of the images on the disc any page actually names;
  * how many names the pages cite that no file on the disc satisfies.

WHY THIS IS A FILE AND NOT A ONE-LINE grep
------------------------------------------

Twice in this session a `\\` inside a shell heredoc was eaten before Python saw
it, once silently. The rule of this branch is that anything containing a
backslash goes in a file. This tool contains three.

WHAT THE REGULAR EXPRESSION MEASURES
------------------------------------

The last session's name census produced 616 strings of which 65 were an
artefact of the pattern: a census that extracts names and counts them is
measuring its own regular expression. So this tool prints, beside every count,
the number of raw attribute values it started from and the number that survived
each filter, and `--dump` prints every one of them so the arithmetic can be
audited by eye rather than trusted.

Usage:
    python tools/webcross.py DISCROOT
    python tools/webcross.py DISCROOT --dump
"""
import collections
import os
import re
import sys

ATTR = re.compile(rb'''(?:src|href|background|lowsrc)\s*=\s*["']?([^"'>\s]+)''',
                  re.I)
URLRE = re.compile(rb'''[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+''')


def files_under(root):
    out = {}
    for dirpath, _d, fs in os.walk(root):
        for f in fs:
            out.setdefault(f.upper(), []).append(os.path.join(dirpath, f))
    return out


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if len(argv) < 2:
        raise SystemExit(__doc__)
    root = argv[1]
    dump = "--dump" in argv
    allfiles = files_under(root)
    htm = sorted(p for names in allfiles.values() for p in names
                 if p.upper().endswith(".HTM"))
    gif = {k for k in allfiles if k.endswith(".GIF")}
    jpg = {k for k in allfiles if k.endswith(".JPG")}

    heads = collections.Counter()
    raw = []
    urls = collections.Counter()
    local = collections.Counter()
    bare_urls = collections.Counter()
    for p in htm:
        d = open(p, "rb").read()
        heads[d[:8]] += 1
        for m in URLRE.finditer(d):
            bare_urls[m.group().decode("latin-1")] += 1
        for m in ATTR.finditer(d):
            v = m.group(1).decode("latin-1")
            raw.append((os.path.basename(p), v))
            if "://" in v or v.lower().startswith("mailto:"):
                urls[v] += 1
            else:
                nm = v.replace("\\", "/").split("/")[-1]
                nm = nm.split("#")[0].split("?")[0]
                if nm:
                    local[nm.upper()] += 1

    print("=== webcross.py over %s ===" % root)
    print(".HTM pages                          : %d" % len(htm))
    print(".GIF on the disc                    : %d" % len(gif))
    print(".JPG on the disc                    : %d" % len(jpg))
    print()
    print("first eight bytes of the pages:")
    for k, v in heads.most_common():
        print("   %-24r x%d" % (k, v))
    print()
    print("raw src/href/background values      : %d" % len(raw))
    print("   of which absolute URLs           : %d (%d distinct)"
          % (sum(urls.values()), len(urls)))
    print("   of which local names             : %d (%d distinct)"
          % (sum(local.values()), len(local)))
    print("bare URLs anywhere in the page text : %d (%d distinct)"
          % (sum(bare_urls.values()), len(bare_urls)))
    print()
    print("every distinct URL cited, with its count:")
    for u, c in sorted(bare_urls.items(), key=lambda kv: (-kv[1], kv[0])):
        print("   %-60s x%d" % (u, c))
    for u, c in sorted(urls.items(), key=lambda kv: (-kv[1], kv[0])):
        if u.encode("latin-1") not in b" ".join(k.encode("latin-1")
                                                for k in bare_urls) :
            print("   %-60s x%d  (attribute only)" % (u, c))
    print()
    cited = set(local)
    print("local names cited                   : %d" % len(cited))
    print("   that name a file on this disc    : %d" % len(cited & set(allfiles)))
    print("   that name NO file on this disc   : %d" % len(cited - set(allfiles)))
    for n in sorted(cited - set(allfiles)):
        print("        %s" % n)
    print()
    print("GIFs named by at least one page     : %d of %d" % (len(cited & gif), len(gif)))
    print("GIFs named by no page               : %d" % (len(gif - cited)))
    print("JPGs named by at least one page     : %d of %d" % (len(cited & jpg), len(jpg)))
    if dump:
        print()
        print("EVERY RAW ATTRIBUTE VALUE:")
        for page, v in raw:
            print("   %-16s %s" % (page, v))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
