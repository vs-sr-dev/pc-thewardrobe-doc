#!/usr/bin/env python3
"""jingles.py -- re-derive, from one object's own MIDI library, whether a `J`
marks a short piece, and test the split on three populations instead of
asserting it on one.

WHAT THIS RE-DERIVES, AND WHY IT IS NOT A CITATION
--------------------------------------------------
`pc-rpgmaker2000-doc/docs/06` found that a `J` inside a MIDI file's internal
Shift-JIS sequence name separated seventeen short pieces from seventy-five long
ones, with the two duration ranges **disjoint**. The `J` was in no file name
there. In this object it is in the file names.

Quoting that number here would be citing a neighbour. This tool re-derives the
split from **this** object's files, on both axes -- the file name and the
internal sequence name -- and reports the verdict per population:

    ALL       every MIDI in the tree
    INHERITED the ones whose sha1 appears in the other object's hash list
    NEW       the ones whose sha1 does not

The test is stated before it is run and **it is allowed to fail**:

    max(duration of the J files) < min(duration of the rest)   -> DISJOINT

A rule that holds on one population and breaks on another is a finding about
the two populations. Reporting only the population where it holds would not be.

The sequence name is track 0's meta 0x03, decoded cp932; the copyright is meta
0x02 wherever it occurs. Neither is assumed to exist.

    python tools/jingles.py <root> --tsv notes/smfcensus.tsv
    python tools/jingles.py <root> --tsv notes/smfcensus.tsv \\
        --crossing notes/crossnames-crossing.txt
    python tools/jingles.py --selftest
"""
import argparse
import collections
import hashlib
import os
import re
import struct
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

SEQ_NAME = 0x03
COPYRIGHT = 0x02
END_OF_TRACK = 0x2F
HASH_ROW = re.compile(r"^([0-9a-f]{40})\s+\d+\s+(.*)$")


class Bad(Exception):
    pass


def varlen(body, q):
    v = 0
    while q < len(body):
        b = body[q]
        v = (v << 7) | (b & 0x7F)
        q += 1
        if not b & 0x80:
            return v, q
    raise Bad("a variable-length quantity ran off the end")


def meta_events(blob):
    """Yield (track index, meta type, data) for every meta event."""
    if blob[:4] != b"MThd":
        raise Bad("no MThd")
    (hl,) = struct.unpack(">I", blob[4:8])
    p = 8 + hl
    track = 0
    while p + 8 <= len(blob):
        tag = blob[p:p + 4]
        (tl,) = struct.unpack(">I", blob[p + 4:p + 8])
        body = blob[p + 8:p + 8 + tl]
        if tag == b"MTrk":
            q = 0
            running = None
            while q < len(body):
                _delta, q = varlen(body, q)
                if q >= len(body):
                    break
                ev = body[q]
                if ev == 0xFF:
                    mtype = body[q + 1]
                    ln, q2 = varlen(body, q + 2)
                    data = body[q2:q2 + ln]
                    q = q2 + ln
                    yield track, mtype, data
                    if mtype == END_OF_TRACK:
                        break
                elif ev in (0xF0, 0xF7):
                    ln, q2 = varlen(body, q + 1)
                    q = q2 + ln
                elif ev & 0x80:
                    running = ev
                    n = 1 if (ev & 0xF0) in (0xC0, 0xD0) else 2
                    q += 1 + n
                else:
                    if running is None:
                        raise Bad("running status with no status byte")
                    n = 1 if (running & 0xF0) in (0xC0, 0xD0) else 2
                    q += n
            track += 1
        p += 8 + tl


def facts(path):
    blob = open(path, "rb").read()
    seq = None
    copy = None
    for track, mtype, data in meta_events(blob):
        if mtype == SEQ_NAME and track == 0 and seq is None:
            seq = data
        elif mtype == COPYRIGHT and copy is None:
            copy = data
    return {"sha1": hashlib.sha1(blob).hexdigest(), "seq": seq or b"",
            "copyright": copy or b""}


def read_tsv(path):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) == len(header):
                rows.append(dict(zip(header, parts)))
    if not rows:
        raise SystemExit("jingles: no rows in %s" % path)
    return rows


def read_hashes(path):
    out = set()
    for line in open(path, encoding="utf-8", errors="replace"):
        m = HASH_ROW.match(line.rstrip("\n"))
        if m:
            out.add(m.group(1))
    if not out:
        raise SystemExit("jingles: no hashes in %s" % path)
    return out


def verdict(rows, key, label, indent="   "):
    a = [r for r in rows if key(r)]
    b = [r for r in rows if not key(r)]
    da = sorted(float(r["seconds"]) for r in a)
    db = sorted(float(r["seconds"]) for r in b)
    print("%s%-46s with %3d (%7.3f..%8.3f)  without %3d (%7.3f..%8.3f)"
          % (indent, label, len(a), da[0] if da else 0, da[-1] if da else 0,
             len(b), db[0] if db else 0, db[-1] if db else 0), end="")
    if not da or not db:
        print("   -- one side empty")
        return None
    ok = max(da) < min(db)
    print("   -> %s" % ("DISJOINT" if ok else "OVERLAPPING"))
    if not ok:
        offenders = sorted((float(r["seconds"]), os.path.basename(r["path"]))
                           for r in b if float(r["seconds"]) <= max(da))
        for sec, nm in offenders:
            print("%s      on the wrong side : %-26s %8.3f s"
                  % (indent, nm, sec))
    return ok


def run(args):
    rows = read_tsv(args.tsv)
    for r in rows:
        r.update(facts(os.path.join(args.root,
                                    r["path"].replace("/", os.sep))))
    print("MIDI files : %d" % len(rows))
    seqs = sum(1 for r in rows if r["seq"])
    print("track-0 sequence names recovered : %d of %d" % (seqs, len(rows)))
    print()

    def by_name(r):
        return os.path.basename(r["path"]).startswith("J")

    def by_seq(r):
        try:
            return "J" in r["seq"].decode("cp932")
        except Exception:
            return b"J" in r["seq"]

    agree = sum(1 for r in rows if by_name(r) == by_seq(r))
    print("the two axes agree on %d of %d files" % (agree, len(rows)))
    disagree = [r for r in rows if by_name(r) != by_seq(r)]
    for r in disagree:
        print("   they disagree on %-28s name %-5s seq %r"
              % (os.path.basename(r["path"]), by_name(r),
                 r["seq"].decode("cp932", "replace")))
    print()

    pops = [("ALL", rows)]
    if args.crossing:
        cross = read_hashes(args.crossing)
        pops.append(("INHERITED (its sha1 is in the other object)",
                     [r for r in rows if r["sha1"] in cross]))
        pops.append(("NEW (its sha1 is not)",
                     [r for r in rows if r["sha1"] not in cross]))

    results = {}
    for label, pop in pops:
        print("-- %s : %d files" % (label, len(pop)))
        if not pop:
            print("   empty")
            continue
        results[(label, "name")] = verdict(pop, by_name,
                                           "a leading J in the FILE NAME")
        results[(label, "seq")] = verdict(pop, by_seq,
                                          "a J in the SEQUENCE NAME")
        print()

    print("-- the composers, counted -------------------------------------")
    comp = collections.Counter(r["copyright"] for r in rows)
    for c, n in comp.most_common():
        print("   %4d  %s" % (n, c.decode("cp932", "replace") if c
                              else "(no copyright event)"))
    print()
    print("-- the J files, by composer -----------------------------------")
    jc = collections.Counter(r["copyright"] for r in rows if by_name(r))
    for c, n in jc.most_common():
        print("   %4d  %s" % (n, c.decode("cp932", "replace") if c
                              else "(no copyright event)"))

    n_j = sum(1 for r in rows if by_name(r))
    if args.expect_j is not None and n_j != args.expect_j:
        raise SystemExit("FATAL: --expect-j %d, got %d" % (args.expect_j, n_j))
    return 0


def selftest():
    import shutil
    import tempfile
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    def vlq(n):
        out = bytearray([n & 0x7F])
        n >>= 7
        while n:
            out.insert(0, (n & 0x7F) | 0x80)
            n >>= 7
        return bytes(out)

    def meta(mtype, data):
        return b"\x00\xff" + bytes([mtype]) + vlq(len(data)) + data

    def track(*events):
        body = b"".join(events) + meta(END_OF_TRACK, b"")
        return b"MTrk" + struct.pack(">I", len(body)) + body

    def smf(*tracks):
        head = struct.pack(">HHH", 1, len(tracks), 96)
        return (b"MThd" + struct.pack(">I", len(head)) + head +
                b"".join(tracks))

    name = "RPG2000 BGM J戦闘終了1".encode("cp932")
    blob = smf(track(meta(SEQ_NAME, name),
                     meta(COPYRIGHT, b"(C)2000 by ASCII Corp./Y.Kitagami"),
                     b"\x00\x90\x40\x40", b"\x00\x80\x40\x40"))
    tmp = tempfile.mkdtemp(prefix="jingles-")
    try:
        p = os.path.join(tmp, "JEnd of Battle 1.mid")
        open(p, "wb").write(blob)
        f = facts(p)
        check("the sequence name is recovered", f["seq"], name)
        check("the copyright is recovered", f["copyright"],
              b"(C)2000 by ASCII Corp./Y.Kitagami")
        check("the sha1 is the file's",
              f["sha1"], hashlib.sha1(blob).hexdigest())
        check("a J is found in the decoded sequence name",
              "J" in f["seq"].decode("cp932"), True)

        plain = smf(track(meta(SEQ_NAME, "RPG2000 BGM 城1".encode("cp932"))))
        p2 = os.path.join(tmp, "Castle 1.mid")
        open(p2, "wb").write(plain)
        f2 = facts(p2)
        check("a file with no copyright yields empty", f2["copyright"], b"")
        check("a name with no J is not marked",
              "J" in f2["seq"].decode("cp932"), False)

        rows = [{"path": "JA.mid", "seconds": "5.0"},
                {"path": "B.mid", "seconds": "60.0"}]
        check("a disjoint split is reported as such",
              verdict(rows, lambda r: r["path"].startswith("J"), "test"), True)
        rows2 = rows + [{"path": "C.mid", "seconds": "4.0"}]
        check("an overlapping split is reported as such",
              verdict(rows2, lambda r: r["path"].startswith("J"), "test"),
              False)

        try:
            list(meta_events(b"not a midi"))
            got = "no exception"
        except Bad:
            got = "Bad"
        check("a file with no MThd is refused", got, "Bad")

        h = os.path.join(tmp, "h.txt")
        open(h, "w").write("%s      100  x.mid\n" % ("a" * 40))
        check("a hash listing parses", read_hashes(h), {"a" * 40})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = 0
    for nm, ok, got, want in checks:
        print("  %-48s %s" % (nm, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad += 1
    print("checks : %d   failures : %d" % (len(checks), bad))
    raise SystemExit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?")
    ap.add_argument("--tsv")
    ap.add_argument("--crossing", help="a hash listing of the other object")
    ap.add_argument("--expect-j", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.root == "selftest":
        return selftest()
    if not args.root or not args.tsv:
        raise SystemExit("jingles: a root and --tsv are required "
                         "(or --selftest)")
    try:
        return run(args)
    except Bad as e:
        raise SystemExit("jingles: REFUSED: %s" % e)


if __name__ == "__main__":
    sys.exit(main())
