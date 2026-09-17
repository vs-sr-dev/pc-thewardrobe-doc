#!/usr/bin/env python3
"""lcfdiff.py -- compare two LCF databases chunk by chunk, record by record,
and field by field, and say what a person changed.

WHY THIS EXISTS
---------------
This object ships two `LcfDataBase` files: the editor's default at 388,574
bytes and a real project's at 374,229. Both close at residue 0 on 22 chunks
with the same three shapes. **Nobody has ever compared them**, and the
comparison needs no new format work at all -- it is 762,803 bytes of structure
`lcf.py` already walks.

The comparison is the closest this collection gets to seeing what a human being
does with the tool: the default database is what Kadokawa shipped, the
project's is what somebody saved after working, and every difference between
them is an edit.

WHAT IT REPORTS, AT THREE DEPTHS
--------------------------------
  1. **chunks** -- present on both sides, byte-identical or not, with both
     lengths. A chunk that is byte-identical is reported as such, because a
     zero difference measured is a finding and an absence of material is not;
  2. **records** -- for chunks that `lcf.py` reads as a LIST, which record ids
     exist on each side and which of the common ones differ;
  3. **fields** -- for differing records, which field tags differ, with both
     values rendered as text where they are text and as integers where they are
     one or two bytes.

`--only-text` restricts the field report to values that decode cleanly, which
is what makes a diff of 762,803 bytes readable.

    python tools/lcfdiff.py <a.ldb> <b.ldb>
    python tools/lcfdiff.py <a.ldb> <b.ldb> --chunk 11 --codec cp932
    python tools/lcfdiff.py <a.ldb> <b.ldb> --expect-identical 14
    python tools/lcfdiff.py selftest
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lcf                                       # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")


def chunks_of(path):
    blob = open(path, "rb").read()
    try:
        name, chunks, residue = lcf.top_level(blob)
    except lcf.Bad as e:
        raise SystemExit("lcfdiff: %s does not walk (%s) -- refusing to diff "
                         "a walk that did not finish" % (path, e))
    if residue:
        raise SystemExit("lcfdiff: %s does not close (residue %d) -- refusing "
                         "to diff a walk that did not finish" % (path, residue))
    out = {}
    for c in chunks:
        out[c["tag"]] = blob[c["offset"]:c["offset"] + c["size"]]
    return name, out, len(blob)


def records(data):
    """{record id: {tag: value}} when the chunk reads as a LIST, else None."""
    kind, payload, _res, _why = lcf.shape(data)
    if not kind.startswith("LIST"):
        return None
    out = {}
    for iid, fields in payload[1]:
        out[iid] = {}
        for t, v in fields:
            out[iid][t] = v
    return out


def record_fields(data):
    """{tag: value} when the chunk reads as a RECORD, else None."""
    kind, payload, _res, _why = lcf.shape(data)
    if kind != "RECORD":
        return None
    return {t: v for t, v in payload}


def render(v, codec):
    if not v:
        return "(empty)"
    # A one- or two-byte value is rendered as a number FIRST. Decoding it as
    # text first was a real defect in this tool: two numeric bytes decode
    # under cp932 into a plausible kanji, and the first run of this diff
    # printed one field as 'A 猫  B 輩' -- a cat and a fellow, invented by the
    # renderer out of a counter. Short values get the number, and the text
    # only when it is unambiguous ASCII.
    if len(v) <= 2:
        n = int.from_bytes(v, "little")
        if all(32 <= c < 127 for c in v):
            return "%d (bytes %s)" % (n, v.decode("ascii"))
        return str(n)
    if all(32 <= c < 127 for c in v) and len(v) <= 64:
        return repr(v.decode("ascii"))
    try:
        s = v.decode(codec)
        if all(ord(c) >= 32 or c in "\r\n\t" for c in s) and len(v) <= 64:
            return repr(s)
    except Exception:
        pass
    if len(v) <= 4:
        return str(int.from_bytes(v, "little"))
    return "<%d bytes>" % len(v)


def is_text(v, codec):
    if not v or len(v) > 64:
        return False
    if all(32 <= c < 127 for c in v):
        return True
    try:
        v.decode(codec)
        return True
    except Exception:
        return False


def run(args):
    na, ca, la = chunks_of(args.a)
    nb, cb, lb = chunks_of(args.b)
    print("A : %-40s %s  %d bytes" % (os.path.basename(args.a), na, la))
    print("B : %-40s %s  %d bytes" % (os.path.basename(args.b), nb, lb))
    print()

    tags = sorted(set(ca) | set(cb))
    identical = differ = only_a = only_b = 0
    print("  %-5s %12s %12s   %s" % ("chunk", "A bytes", "B bytes", "verdict"))
    for t in tags:
        if t not in cb:
            only_a += 1
            print("  %-5d %12d %12s   ONLY IN A" % (t, len(ca[t]), "-"))
            continue
        if t not in ca:
            only_b += 1
            print("  %-5d %12s %12d   ONLY IN B" % (t, "-", len(cb[t])))
            continue
        same = ca[t] == cb[t]
        if same:
            identical += 1
        else:
            differ += 1
        print("  %-5d %12d %12d   %s" % (t, len(ca[t]), len(cb[t]),
                                         "identical" if same else "DIFFERS"))
    print()
    print("  chunks in both        : %d" % len(set(ca) & set(cb)))
    print("  byte-identical        : %d" % identical)
    print("  differing             : %d" % differ)
    print("  only in A / only in B : %d / %d" % (only_a, only_b))
    print("  the four sum to the union of tags : %s"
          % (identical + differ + only_a + only_b == len(tags)))
    print()

    todo = [args.chunk] if args.chunk else \
        [t for t in tags if t in ca and t in cb and ca[t] != cb[t]]
    for t in todo:
        if t not in ca or t not in cb:
            continue
        ra, rb = records(ca[t]), records(cb[t])
        print("-- chunk %d ----------------------------------------------" % t)
        if ra is None or rb is None:
            # A chunk lcf.py reads as a RECORD has no ids: it is one bag of
            # fields. Diff it field by field rather than reporting "not a
            # LIST" and stopping, which is what the first version of this tool
            # did -- and chunk 22 is where the system graphic changes.
            fa, fb = record_fields(ca[t]), record_fields(cb[t])
            if fa is None or fb is None:
                print("   neither a LIST nor a RECORD on at least one side; "
                      "%d and %d bytes" % (len(ca[t]), len(cb[t])))
                continue
            ftags = sorted(set(fa) | set(fb))
            diffs = [ft for ft in ftags if fa.get(ft) != fb.get(ft)]
            print("   a RECORD on both sides : A %d fields, B %d fields, "
                  "differing %d" % (len(fa), len(fb), len(diffs)))
            for ft in diffs:
                print("      field %-4d  A %-30s  B %s"
                      % (ft, render(fa.get(ft, b""), args.codec),
                         render(fb.get(ft, b""), args.codec)))
            continue
        ids = sorted(set(ra) | set(rb))
        common = sorted(set(ra) & set(rb))
        changed = [i for i in common if ra[i] != rb[i]]
        print("   records : A %d, B %d, common %d, only A %d, only B %d, "
              "common but changed %d"
              % (len(ra), len(rb), len(common), len(set(ra) - set(rb)),
                 len(set(rb) - set(ra)), len(changed)))
        if args.chunk is None and not args.verbose:
            shown = changed[:args.limit]
        else:
            shown = changed
        for i in shown:
            fa, fb = ra[i], rb[i]
            ftags = sorted(set(fa) | set(fb))
            diffs = [ft for ft in ftags if fa.get(ft) != fb.get(ft)]
            if args.only_text:
                diffs = [ft for ft in diffs
                         if is_text(fa.get(ft, b""), args.codec)
                         or is_text(fb.get(ft, b""), args.codec)]
            if not diffs:
                continue
            print("   record %d :" % i)
            for ft in diffs:
                print("      field %-4d  A %-30s  B %s"
                      % (ft, render(fa.get(ft, b""), args.codec),
                         render(fb.get(ft, b""), args.codec)))
        extra = len(changed) - len(shown)
        if extra > 0:
            print("   ... %d further changed records not shown "
                  "(--verbose shows all)" % extra)
        for i in sorted(set(ra) - set(rb))[:args.limit]:
            nm = ra[i].get(1, b"")
            print("   record %d is only in A : name %s"
                  % (i, render(nm, args.codec)))
        for i in sorted(set(rb) - set(ra))[:args.limit]:
            nm = rb[i].get(1, b"")
            print("   record %d is only in B : name %s"
                  % (i, render(nm, args.codec)))

    if args.expect_identical is not None and identical != args.expect_identical:
        raise SystemExit("FATAL: --expect-identical %d, got %d"
                         % (args.expect_identical, identical))
    if args.expect_differing is not None and differ != args.expect_differing:
        raise SystemExit("FATAL: --expect-differing %d, got %d"
                         % (args.expect_differing, differ))
    return 0


def selftest():
    import shutil
    import tempfile
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    enc = lcf.enc

    def field(tag, data):
        return enc(tag) + enc(len(data)) + data

    def listing(entries):
        out = enc(len(entries))
        for iid, fs in entries:
            out += enc(iid) + b"".join(field(t, v) for t, v in fs) + b"\x00"
        return out

    def db(chunks):
        out = enc(11) + b"LcfDataBase"
        for t, d in sorted(chunks.items()):
            out += enc(t) + enc(len(d)) + d
        return out

    tmp = tempfile.mkdtemp(prefix="lcfdiff-")
    try:
        same = listing([(1, [(1, b"Alex")]), (2, [(1, b"Brian")])])
        a = db({11: listing([(1, [(1, b"Alex"), (2, b"Hero")])]),
                12: same})
        b = db({11: listing([(1, [(1, b"Brian"), (2, b"Hero")]),
                             (2, [(1, b"Added")])]),
                12: same})
        pa = os.path.join(tmp, "a.ldb")
        pb = os.path.join(tmp, "b.ldb")
        open(pa, "wb").write(a)
        open(pb, "wb").write(b)

        _na, ca, _la = chunks_of(pa)
        _nb, cb, _lb = chunks_of(pb)
        check("both databases close and yield two chunks",
              (sorted(ca), sorted(cb)), ([11, 12], [11, 12]))
        check("chunk 12 is byte-identical", ca[12] == cb[12], True)
        check("chunk 11 differs", ca[11] != cb[11], True)

        ra, rb = records(ca[11]), records(cb[11])
        check("A has one record", sorted(ra), [1])
        check("B has two records", sorted(rb), [1, 2])
        check("the common record's field 1 changed",
              (ra[1][1], rb[1][1]), (b"Alex", b"Brian"))
        check("its field 2 did not", ra[1][2] == rb[1][2], True)
        check("record 2 is only in B", sorted(set(rb) - set(ra)), [2])

        # a RECORD-shaped chunk must be diffed field by field, not skipped
        recdata = b"".join(field(t, v) for t, v in
                           [(19, b"SystemC"), (91, b"\x94\x82")]) + b"\x00"
        check("a RECORD chunk yields its fields",
              record_fields(recdata), {19: b"SystemC", 91: b"\x94\x82"})
        check("a LIST chunk is not a RECORD",
              record_fields(listing([(1, [(1, b"x")])])) is None
              or records(listing([(1, [(1, b"x")])])) is not None, True)

        check("render decodes ascii", render(b"Alex", "cp932"), "'Alex'")
        check("render reads a one-byte integer", render(b"\x04", "cp932"), "4")
        check("two numeric bytes are a number, not a kanji",
              render(b"\x94\x82", "cp932"), "33428")
        check("two ASCII bytes give both readings",
              render(b"AB", "cp932"), "16961 (bytes AB)")
        check("render summarises a long blob",
              render(bytes(600), "cp932"), "<600 bytes>")
        check("is_text is false for a long blob",
              is_text(bytes(600), "cp932"), False)

        # a database that does not close must be refused rather than diffed
        bad = os.path.join(tmp, "bad.ldb")
        open(bad, "wb").write(a + b"\x99")
        try:
            chunks_of(bad)
            got = "no exception"
        except SystemExit:
            got = "SystemExit"
        except Exception:
            got = "other"
        check("a database that does not close is refused", got, "SystemExit")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = 0
    for name, ok, got, want in checks:
        print("  %-48s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad += 1
    print("checks : %d   failures : %d" % (len(checks), bad))
    raise SystemExit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a", nargs="?")
    ap.add_argument("b", nargs="?")
    ap.add_argument("--chunk", type=int)
    ap.add_argument("--codec", default="cp932")
    ap.add_argument("--limit", type=int, default=6)
    ap.add_argument("--only-text", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--expect-identical", type=int)
    ap.add_argument("--expect-differing", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.a == "selftest":
        return selftest()
    if not args.a or not args.b:
        raise SystemExit("lcfdiff: two databases are required (or --selftest)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
