#!/usr/bin/env python3
"""rxscripts.py -- walk RPG Maker XP's Scripts.rxdata, and tell the difference
between a count and a scan.

WHAT THE FILE IS
----------------
`Scripts.rxdata` is one Ruby Marshal document whose root is an Array. Every
element is itself an Array of three: an integer id, a String name, and a String
holding a raw Deflate stream. Inflating the third gives Ruby source with its
comments intact.

WHY THIS TOOL EXISTS RATHER THAN A GREP
---------------------------------------
The pre-briefing of this object found the file by scanning for the two bytes
`78 9c` and reported **92 candidate headers of which 90 inflate**. Scanning for
a two-byte value inside compressed data finds coincidences: Deflate output is
close to uniform, so `78 9c` turns up about once every 65,536 bytes by chance
alone, and 109,299 bytes of it should be expected to produce one or two.

**The number that means anything comes from walking the Array.** This tool does
both and prints them side by side, and `--scan` names the offset of every
coincidence and the entry it falls inside, so that "begins with" and "contains"
is a measurement here rather than an assertion. `sigcount.py` has made exactly
this distinction on eight objects; this is the same distinction inside one file.

NOTHING IS EXECUTED
-------------------
The recovered text is Ruby source and this pipeline does not run the objects it
documents. `extract` writes files and prints text; there is no mode that
evaluates anything, and there is no import of any Ruby machinery.

    python tools/rxscripts.py list    <Scripts.rxdata>
    python tools/rxscripts.py scan    <Scripts.rxdata>
    python tools/rxscripts.py extract <Scripts.rxdata> --out _work/scripts
    python tools/rxscripts.py show    <Scripts.rxdata> --index 0 --lines 12
    python tools/rxscripts.py selftest
"""
import argparse
import collections
import hashlib
import os
import re
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import marshal48                                            # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BANNER = re.compile(rb"^#=+\s*$", re.M)


class NotScripts(Exception):
    pass


def entries(path):
    """Return [(index, id, name, deflate_bytes)] by WALKING the Marshal
    document, plus the reader, so the caller can state the closure too."""
    data = open(path, "rb").read()
    root, reader = marshal48.load(data, path)
    if not isinstance(root, list):
        raise NotScripts("%s: the root is %s and not an Array"
                         % (path, type(root).__name__))
    out = []
    for i, e in enumerate(root):
        if isinstance(e, marshal48.RWithIvars):
            e = e.value
        if not isinstance(e, list) or len(e) != 3:
            raise NotScripts("%s: entry %d is not a three-element Array"
                             % (path, i))
        rid, name, blob = e
        if isinstance(name, marshal48.RWithIvars):
            name = name.value
        if isinstance(blob, marshal48.RWithIvars):
            blob = blob.value
        if not isinstance(name, marshal48.RString) \
                or not isinstance(blob, marshal48.RString):
            raise NotScripts("%s: entry %d is not (id, String, String)"
                             % (path, i))
        out.append((i, rid, name.text(), blob.raw))
    return out, reader, data


def inflate_all(rows):
    good, bad, total = [], [], 0
    for i, rid, name, blob in rows:
        try:
            src = zlib.decompress(blob)
        except zlib.error as e:
            bad.append((i, name, str(e)))
            continue
        total += len(src)
        good.append((i, rid, name, blob, src))
    return good, bad, total


def cmd_list(path):
    rows, reader, data = entries(path)
    good, bad, total = inflate_all(rows)
    print("file            : %s" % os.path.basename(path))
    print("bytes on disk   : %d" % len(data))
    print("the Marshal walk consumed %d of %d, residue %d"
          % (reader.p, len(data), len(data) - reader.p))
    print("root            : Array of %d, WALKED" % len(rows))
    print("every entry is a three-element Array : %s"
          % ("yes, %d of %d" % (len(rows), len(rows))))
    print()
    compressed = sum(len(b) for _i, _r, _n, b in rows)
    print("  %-4s %-6s %-28s %9s %9s %6s"
          % ("#", "id", "name", "deflate", "source", "ratio"))
    empty = 0
    banners = 0
    for i, rid, name, blob, src in good:
        if not src.strip():
            empty += 1
        if BANNER.search(src):
            banners += 1
        print("  %-4d %-6d %-28s %9d %9d %6.2f"
              % (i, rid, name if name else "(no name)", len(blob), len(src),
                 len(src) / len(blob) if blob else 0))
    for i, name, err in bad:
        print("  %-4d %-6s %-28s %9s %9s  DID NOT INFLATE: %s"
              % (i, "?", name, "-", "-", err))
    print()
    print("entries walked            : %d" % len(rows))
    print("entries that inflate      : %d" % len(good))
    print("Deflate bytes in the file : %d" % compressed)
    print("source bytes recovered    : %d" % total)
    print("ratio                     : %.4f" % (total / compressed))
    print("entries whose source is empty or blank : %d" % empty)
    print("entries carrying a #==== banner comment : %d" % banners)
    print("distinct names            : %d" % len({r[2] for r in rows}))
    print("distinct ids              : %d" % len({r[1] for r in rows}))
    return 0 if not bad else 1


def cmd_scan(path):
    """The trap, measured. A raw scan for the Deflate header the walk found is
    compared against the walk, and every extra hit is located."""
    rows, _reader, data = entries(path)
    good, _bad, _total = inflate_all(rows)
    # where the walk says each stream begins
    starts = {}
    pos = 0
    for _i, _rid, _name, blob in rows:
        at = data.find(blob, pos)
        if at < 0:
            at = data.find(blob)
        starts[at] = (_i, _name, len(blob))
        pos = at + len(blob)
    hits = []
    at = data.find(b"\x78\x9c")
    while at >= 0:
        hits.append(at)
        at = data.find(b"\x78\x9c", at + 1)
    print("a raw scan for the two bytes 78 9c   : %d hits" % len(hits))
    print("streams the WALK reports             : %d" % len(rows))
    print("streams that inflate                 : %d" % len(good))
    print()
    real = set(starts)
    extra = [h for h in hits if h not in real]
    missed = [s for s in real if s not in hits]
    print("scan hits that ARE a stream start    : %d" % (len(hits)
                                                         - len(extra)))
    print("scan hits that are NOT               : %d" % len(extra))
    print("stream starts the scan MISSED        : %d" % len(missed))
    print()
    if extra:
        print("  the coincidences, with the entry each falls inside:")
        for h in extra:
            owner = None
            for s, (i, name, n) in starts.items():
                if s <= h < s + n:
                    owner = (i, name, h - s, n)
                    break
            if owner:
                print("    offset %-8d inside entry %-3d %-26s at byte %d "
                      "of %d" % (h, owner[0], owner[1], owner[2], owner[3]))
            else:
                print("    offset %-8d not inside any stream" % h)
    if missed:
        print("  stream starts a scan for 78 9c cannot see:")
        for s in sorted(missed):
            i, name, n = starts[s]
            print("    offset %-8d entry %-3d %-26s first two bytes %s"
                  % (s, i, name, data[s:s + 2].hex()))
    print()
    print("A scan measures its own pattern. The walk measures the file.")
    return 0


def cmd_extract(path, out):
    rows, _reader, _data = entries(path)
    good, bad, total = inflate_all(rows)
    os.makedirs(out, exist_ok=True)
    written = 0
    for i, _rid, name, _blob, src in good:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "unnamed"
        p = os.path.join(out, "%03d-%s.rb" % (i, safe))
        with open(p, "wb") as fh:
            fh.write(src)
        written += 1
    print("wrote %d files to %s, %d bytes of Ruby source"
          % (written, out, total))
    print("NOT EXECUTED. This pipeline reads the objects it documents.")
    if bad:
        print("entries that did not inflate : %d" % len(bad), file=sys.stderr)
        return 1
    return 0


def cmd_show(path, index, lines):
    rows, _reader, _data = entries(path)
    good, _bad, _total = inflate_all(rows)
    for i, rid, name, blob, src in good:
        if i != index:
            continue
        print("entry %d   id %d   name %r   deflate %d   source %d"
              % (i, rid, name, len(blob), len(src)))
        print("sha1 of the recovered source : %s"
              % hashlib.sha1(src).hexdigest())
        print()
        text = src.decode("utf-8", "replace").splitlines()
        for ln in text[:lines]:
            print("  " + ln)
        if len(text) > lines:
            print("  ... %d more lines" % (len(text) - lines))
        return 0
    sys.exit("rxscripts: no entry with index %d" % index)


def cmd_names(path):
    rows, _reader, _data = entries(path)
    good, _bad, _total = inflate_all(rows)
    sizes = {i: len(s) for i, _r, _n, _b, s in good}
    for i, rid, name, _blob in rows:
        print("%3d  %-8d %-30s %8d" % (i, rid, name, sizes.get(i, -1)))
    print()
    counts = collections.Counter(n for _i, _r, n, _b in rows)
    dup = {k: v for k, v in counts.items() if v > 1}
    print("names %d   distinct %d   repeated %s"
          % (len(rows), len(counts), dup or "none"))
    return 0


def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    # Build a Marshal document of the same shape by hand, so the reader is
    # tested against a specimen whose answer is known rather than against the
    # object it is meant to measure.
    def rstr(b):
        return b'"' + bytes([len(b) + 5]) + b

    src = b"# ** Fixture\nclass A\nend\n"
    comp = zlib.compress(src)
    entry = b"[\x08" + b"i\x0a" + rstr(b"Fixture") + rstr(comp)
    doc = b"\x04\x08[\x06" + entry

    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "_rxscripts_fixture.bin")
    with open(tmp, "wb") as fh:
        fh.write(doc)
    try:
        rows, reader, data = entries(tmp)
        ok("the fixture walks to one entry", len(rows) == 1, str(len(rows)))
        ok("the fixture closes at residue 0", reader.p == len(data),
           "%d of %d" % (reader.p, len(data)))
        ok("the entry's id is read", rows[0][1] == 5, str(rows[0][1]))
        ok("the entry's name is read", rows[0][2] == "Fixture", rows[0][2])
        good, bad, total = inflate_all(rows)
        ok("the entry inflates", len(good) == 1 and not bad)
        ok("the inflated bytes are the original", good[0][4] == src)
        ok("the recovered total is the source length", total == len(src))

        # a document of the right format but the wrong shape must be refused
        bad_doc = b"\x04\x08[\x06i\x06"
        with open(tmp, "wb") as fh:
            fh.write(bad_doc)
        try:
            entries(tmp)
            ok("an Array of non-triples is refused", False, "it was accepted")
        except NotScripts:
            ok("an Array of non-triples is refused", True)

        # a document whose root is not an Array must be refused
        with open(tmp, "wb") as fh:
            fh.write(b"\x04\x08i\x06")
        try:
            entries(tmp)
            ok("a non-Array root is refused", False, "it was accepted")
        except NotScripts:
            ok("a non-Array root is refused", True)

        # a stream that is not Deflate must be reported, not crashed on
        with open(tmp, "wb") as fh:
            fh.write(b"\x04\x08[\x06[\x08i\x0a" + rstr(b"X")
                     + rstr(b"not deflate"))
        rows, _r, _d = entries(tmp)
        good, bad, total = inflate_all(rows)
        ok("a stream that is not Deflate is reported and not raised",
           len(bad) == 1 and len(good) == 0 and total == 0)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    # the coincidence rate the scan is up against, stated rather than assumed
    ok("78 9c is one value of 65,536 and a 109,299-byte file expects ~1.67",
       abs(109299 / 65536 - 1.6678) < 1e-3, "%.4f" % (109299 / 65536))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good_, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good_ else "FAIL",
                                   note))
        if not good_:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode",
                    choices=("list", "scan", "extract", "show", "names",
                             "selftest"))
    ap.add_argument("path", nargs="?")
    ap.add_argument("--out", default="_work/scripts")
    ap.add_argument("--index", type=int, default=0)
    ap.add_argument("--lines", type=int, default=12)
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest()
    if not args.path:
        sys.exit("rxscripts: %s needs a path to Scripts.rxdata" % args.mode)
    if os.path.isdir(args.path):
        sys.exit("rxscripts: %s is a directory; this reader wants the file "
                 "Scripts.rxdata" % args.path)
    if not os.path.isfile(args.path):
        sys.exit("rxscripts: no such file: %s" % args.path)
    if args.mode == "list":
        return cmd_list(args.path)
    if args.mode == "scan":
        return cmd_scan(args.path)
    if args.mode == "extract":
        return cmd_extract(args.path, args.out)
    if args.mode == "names":
        return cmd_names(args.path)
    return cmd_show(args.path, args.index, args.lines)


if __name__ == "__main__":
    sys.exit(main())
