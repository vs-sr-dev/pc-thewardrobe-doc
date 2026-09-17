#!/usr/bin/env python3
"""pdfmeta.py -- the document information dictionary of a PDF, and nothing else.

Twenty-two PDFs on this object: seventeen price lists, three articles, one
subscription form and one manual for a game that is not here. Each carries a
`/Info` dictionary that the producing application filled in, and that
dictionary is a clock and a signature: `/Producer` names the library, `/Creator`
names the application the author used, `/CreationDate` and `/ModDate` are
timestamps in the PDF's own `D:YYYYMMDDHHmmSSOHH'mm'` form -- with a timezone,
which the ISO 9660 directory records also have and almost nothing else on a CD
does.

This reads only the top-level dictionaries; it does not render, decode fonts, or
extract text, because none of that is needed to answer "who made this file, with
what, and when".

Page count is taken from the highest `/Count` on a `/Pages` node, and checked
against the number of `/Type /Page` objects. Where they disagree, both are
printed: a PDF with an object stream can hide pages from a naive count and
saying so is better than picking one.

    python tools/pdfmeta.py FILE
    python tools/pdfmeta.py TREE --census
"""

import argparse
import os
import re
import sys
from collections import Counter

KEYS = ("Title", "Author", "Subject", "Keywords", "Creator", "Producer",
        "CreationDate", "ModDate")


def unescape(v):
    if v.startswith(b"<") and v.endswith(b">"):
        h = re.sub(rb"[^0-9A-Fa-f]", b"", v[1:-1])
        try:
            b = bytes.fromhex(h.decode("ascii"))
        except Exception:
            return v.decode("latin-1")
        if b[:2] in (b"\xfe\xff",):
            return b[2:].decode("utf-16-be", "replace")
        return b.decode("latin-1")
    s = v[1:-1] if v.startswith(b"(") else v
    s = re.sub(rb"\\([nrtbf()\\])", lambda m: {
        b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b",
        b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}[m.group(1)], s)
    if s[:2] == b"\xfe\xff":
        return s[2:].decode("utf-16-be", "replace")
    return s.decode("latin-1")


def value_re(key):
    # a PDF string is either (...) with backslash escapes, or <hex>
    return re.compile(rb"/" + key.encode() + rb"\s*(\([^)]*(?:\\\)[^)]*)*\)|<[0-9A-Fa-f\s]*>)")


def meta(path):
    b = open(path, "rb").read()
    out = {"bytes": len(b), "version": b[:8].decode("latin-1", "replace")}
    for k in KEYS:
        m = value_re(k).search(b)
        if m:
            out[k] = unescape(m.group(1)).strip()
    counts = [int(x) for x in re.findall(rb"/Count\s+(\d+)", b)]
    out["count_max"] = max(counts) if counts else None
    out["page_objs"] = len(re.findall(rb"/Type\s*/Page[^s]", b))
    out["encrypted"] = b"/Encrypt" in b
    out["linearized"] = b"/Linearized" in b
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--census", action="store_true")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    if not a.census:
        m = meta(a.path)
        print("file        %s" % a.path)
        for k in ("bytes", "version", "count_max", "page_objs", "encrypted",
                  "linearized"):
            print("  %-12s %s" % (k, m.get(k)))
        for k in KEYS:
            if m.get(k):
                print("  %-12s %s" % (k, m[k]))
        return

    prod = Counter()
    crea = Counter()
    rows = []
    for dp, _dn, fn in os.walk(a.path):
        for f in sorted(fn):
            if not f.lower().endswith(".pdf"):
                continue
            p = os.path.join(dp, f)
            m = meta(p)
            rel = os.path.relpath(p, a.path).replace(os.sep, "/")
            rows.append((rel, m))
            prod[m.get("Producer", "(none)")] += 1
            crea[m.get("Creator", "(none)")] += 1
    print("%-46s %9s %5s  %-22s %s"
          % ("path", "bytes", "pages", "created", "producer"))
    for rel, m in rows:
        print("%-46s %9d %5s  %-22s %s"
              % (rel[-46:], m["bytes"],
                 m.get("count_max") if m.get("count_max") is not None
                 else m["page_objs"],
                 (m.get("CreationDate") or "")[:22],
                 (m.get("Producer") or "")[:36]))
    print()
    print("PDFs: %d" % len(rows))
    print("producers:")
    for k, v in prod.most_common():
        print("   %-52s %3d" % (k[:52], v))
    print("creators:")
    for k, v in crea.most_common():
        print("   %-52s %3d" % (k[:52], v))


if __name__ == "__main__":
    main()
