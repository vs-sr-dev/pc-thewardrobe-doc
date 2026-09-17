#!/usr/bin/env python3
"""lgp.py -- a reader for the `.LGP` container, derived from the bytes of this
object because nothing in this collection had ever opened one.

`.LGP` is 49 files and 913,361,406 bytes here -- 42.6696 % of the object's file
bytes -- and the string `LGP` does not appear in any chapter of any repository
in this collection. There was no magic number to look up, no header length, no
member count and no prior art. What follows was derived from
`/FF7/MINIGAME/SUB.LGP`, the smallest of the forty-nine at 666,982 bytes, and
then tested for exact closure on all forty-nine.

THE LAYOUT, AS DERIVED, WITH THE EVIDENCE FOR EACH FIELD

    off  len              field
      0   12   creator string. On every archive here it is the twelve bytes
                 00 00 'SQUARESOFT'
               -- two NULs and ten letters. It is treated as twelve opaque
               bytes and printed, not asserted, because two of the twelve are
               not letters and a reader that assumed a ten-byte magic would
               have been off by two.
     12    4   member count, uint32 little-endian. On SUB.LGP this is 10 and
               ten directory records follow with no slack, which is what
               fixes both the width and the field.
     16   27N  the directory. Each record:
                  0  20  member name, NUL-padded ASCII, lower case
                 20   4  offset of the member's data header, uint32 LE
                 24   1  a small integer. Two values occur on this object,
                         11 and 14, and `--census` prints which -- see below
                 25   2  conflict-table index, uint16 LE, 0 where the name is
                         unambiguous
               27 is fixed by arithmetic and not by assumption: the second
               record of SUB.LGP begins at 16 + 27 = 43, and 'hudb.tex' is at
               offset 43.
   16+27N 3600  a lookup table of **900 cells of two uint16**. Each cell is
               (first directory-record index, record count), and the claim is
               checkable: on FLEVEL.LGP 100 of the 900 cells are non-zero and
               their counts sum to **729**, which is that archive's member
               count exactly. What the 900 cells are keyed BY is not asserted
               here -- 900 = 30 x 30 invites a two-character alphabet reading
               and this tool does not make it. The length is 3600 on all 49
               and it is fixed by the closure arithmetic below.
   +3600    2  conflict count, uint16 LE, followed by that many conflict
               records. It is zero on 48 of the 49 archives and **652** on
               `MAGIC.LGP`, which is the archive that made the first draft of
               this reader fail to close by 319,804 bytes. A conflict record
               is
                  0   2  location count k, uint16 LE
                  2  130k  k records of (128-byte NUL-padded path, uint16 LE
                           directory index)
               and the paths are the ORIGINAL BUILD TREE:
               `ff7/data/battle/magic/bio4`, `ff7/data/battle/limit2/tifa1`.
               The directory holds one flat 20-character namespace; when two
               source files in different directories carried the same name,
               this table kept the directories. It is a listing of the
               studio's own tree, shipped inside the archive.
               `2 + sum(2 + 130k)` walks to the first member's offset with
               delta 0 on MAGIC.LGP: 2 + 1,304 + 318,500 = 319,806.
     ...        the member data area. Each member is
                  0  20  member name again, NUL-padded ASCII -- and the case
                         DIFFERS from the directory's: the directory says
                         'hud.tex' and the data header says 'hud.TEX'. Two
                         spellings of one name inside one archive.
                 20   4  member length, uint32 LE
                 24   n  the member, stored, not compressed
   size-14  14  the trailer, the fourteen bytes 'FINAL FANTASY7'.

THE CLOSURE TEST, WHICH IS THE WHOLE POINT

    12 + 4 + 27*N + 3600 + 2 + sum(24 + len_i) + 14  ==  file size

On SUB.LGP: 286 + 3602 + 663,080 + 14 = 666,982, residue 0. That equation is
what makes the layout a measurement rather than a reading; a field guessed
wrong leaves a residue. `--validate` prints it term by term.

WHAT THIS READER DOES NOT CLAIM

  * it does not decode a member. A `.TEX`, a `.P` model or a field map is a
    format inside the format and this tool hands over bytes;
  * it does not assert what byte 24 of a directory record means. Exactly two
    values occur across all 82,479 records on this object -- 11 and 14 -- and
    that is a measurement of this object and not a definition. This tool
    prints the distinct values it saw and their counts, and says nothing more;
  * it asserts the conflict-record layout on one archive of 49, because that
    is the whole population. The claim is testable and it is tested: the walk
    has to land exactly on the first member's offset, and `--conflicts` prints
    the paths.

Usage:
    python tools/lgp.py FILE --validate         the byte accounting, term by term
    python tools/lgp.py FILE --list             the members
    python tools/lgp.py FILE --sha1             the members with their digests
    python tools/lgp.py FILE --extract DIR
    python tools/lgp.py DIR  --census           every .LGP under DIR
    python tools/lgp.py FILE --conflicts        the build-tree paths
    python tools/lgp.py --selftest              refuse four specimens, one per guard

Exit status: 0 when everything asked for closed with residue 0, 1 when a file
failed to close or was not an LGP, 3 when a population was empty.
"""
import argparse
import hashlib
import os
import struct
import sys

CREATOR_LEN = 12
REC = 27
LOOKUP = 3600          # 30 * 30 cells of 4 bytes
CONFLICT_LEN = 2
DATA_HDR = 24          # 20-byte name + uint32 length
TRAILER = b"FINAL FANTASY7"


class NotLGP(Exception):
    pass


def _name(raw):
    return raw.split(b"\0")[0].decode("latin1")


def parse(data, path="<bytes>"):
    """Return (creator, entries, lookup, conflicts, trailer_ok, accounting).

    entries is a list of dicts. Raises NotLGP with a reason rather than
    returning something plausible.
    """
    if len(data) < CREATOR_LEN + 4 + LOOKUP + CONFLICT_LEN + len(TRAILER):
        raise NotLGP("%s: %d bytes is shorter than an empty archive" %
                     (path, len(data)))
    creator = data[:CREATOR_LEN]
    (count,) = struct.unpack("<I", data[CREATOR_LEN:CREATOR_LEN + 4])
    toc_end = CREATOR_LEN + 4 + REC * count
    if count == 0 or toc_end + LOOKUP + CONFLICT_LEN > len(data):
        raise NotLGP("%s: member count %d does not fit in %d bytes"
                     % (path, count, len(data)))
    entries = []
    for i in range(count):
        o = CREATOR_LEN + 4 + REC * i
        rec = data[o:o + REC]
        offset, check, conflict = struct.unpack("<IBH", rec[20:27])
        entries.append({
            "name": _name(rec[:20]),
            "offset": offset,
            "check": check,
            "conflict": conflict,
            "index": i,
        })
    lookup = data[toc_end:toc_end + LOOKUP]
    cpos = toc_end + LOOKUP
    (nconflict,) = struct.unpack("<H", data[cpos:cpos + CONFLICT_LEN])
    # The conflict table. Length is not fixed: it is 2 + sum(2 + 130k) and it
    # has to be walked. Getting this wrong is what made the first draft of this
    # reader miss MAGIC.LGP's closure by exactly the table's length.
    q = cpos + CONFLICT_LEN
    conflicts = []
    for _ in range(nconflict):
        if q + 2 > len(data):
            raise NotLGP("%s: conflict table runs past end of file" % path)
        (k,) = struct.unpack("<H", data[q:q + 2])
        q += 2
        locs = []
        for _j in range(k):
            if q + 130 > len(data):
                raise NotLGP("%s: conflict record runs past end of file" % path)
            locs.append((_name(data[q:q + 128]),
                         struct.unpack("<H", data[q + 128:q + 130])[0]))
            q += 130
        conflicts.append(locs)
    conflict_bytes = q - cpos
    # Fill in each member's data header and length.
    for e in entries:
        o = e["offset"]
        if o + DATA_HDR > len(data):
            raise NotLGP("%s: member %r offset %d past end of file"
                         % (path, e["name"], o))
        e["data_name"] = _name(data[o:o + 20])
        (e["length"],) = struct.unpack("<I", data[o + 20:o + DATA_HDR])
        e["data"] = o + DATA_HDR
        if e["data"] + e["length"] > len(data):
            raise NotLGP("%s: member %r runs %d bytes past end of file"
                         % (path, e["name"],
                            e["data"] + e["length"] - len(data)))
    trailer_ok = data[-len(TRAILER):] == TRAILER
    acc = {
        "creator": CREATOR_LEN,
        "count_field": 4,
        "toc": REC * count,
        "lookup": LOOKUP,
        "conflict_table": conflict_bytes,
        "members": sum(DATA_HDR + e["length"] for e in entries),
        "trailer": len(TRAILER),
    }
    acc["total"] = sum(acc.values())
    acc["file"] = len(data)
    acc["residue"] = len(data) - acc["total"]
    acc["conflicts"] = nconflict
    acc["locations"] = sum(len(c) for c in conflicts)
    return creator, entries, lookup, conflicts, trailer_ok, acc


def load(path):
    with open(path, "rb") as fh:
        return fh.read()


def cmd_validate(path):
    data = load(path)
    creator, entries, lookup, conflicts, trailer_ok, acc = parse(data, path)
    print("file            : %s" % os.path.basename(path))
    print("bytes           : %d" % acc["file"])
    print("creator         : %r" % creator)
    print("members         : %d" % len(entries))
    print("conflict records: %d in %d locations, %d bytes"
          % (acc["conflicts"], acc["locations"], acc["conflict_table"]))
    print("trailer         : %s" % ("'FINAL FANTASY7'" if trailer_ok
                                    else "MISSING -- %r" % data[-14:]))
    print()
    print("  creator string          %12d" % acc["creator"])
    print("  member count field      %12d" % acc["count_field"])
    print("  directory %5d x %2d    %12d" % (len(entries), REC, acc["toc"]))
    print("  lookup table 30x30x4    %12d" % acc["lookup"])
    print("  conflict table          %12d" % acc["conflict_table"])
    print("  member headers+payload  %12d" % acc["members"])
    print("  trailer                 %12d" % acc["trailer"])
    print("                          ------------")
    print("  accounted               %12d" % acc["total"])
    print("  file                    %12d" % acc["file"])
    print("  RESIDUE                 %12d" % acc["residue"])
    checks = sorted({e["check"] for e in entries})
    print()
    print("distinct byte-24 values : %s" % checks)
    print("names whose data-header spelling differs from the directory: %d of %d"
          % (sum(1 for e in entries if e["data_name"] != e["name"]),
             len(entries)))
    gaps = walk_gaps(entries, acc)
    print("gap between members     : %d bytes" % gaps)
    return 0 if acc["residue"] == 0 and trailer_ok else 1


def walk_gaps(entries, acc):
    """Bytes inside the data area that belong to no member."""
    ordered = sorted(entries, key=lambda e: e["offset"])
    if not ordered:
        return 0
    start = (acc["creator"] + acc["count_field"] + acc["toc"]
             + acc["lookup"] + acc["conflict_table"])
    cursor = start
    gap = 0
    for e in ordered:
        gap += e["offset"] - cursor
        cursor = e["data"] + e["length"]
    gap += (acc["file"] - acc["trailer"]) - cursor
    return gap


def cmd_conflicts(path):
    """The build-tree paths kept because two source files shared a name."""
    data = load(path)
    creator, entries, lookup, conflicts, trailer_ok, acc = parse(data, path)
    if not conflicts:
        print("no conflict records in %s" % os.path.basename(path))
        return 0
    dirs = {}
    for locs in conflicts:
        for p_, idx in locs:
            d = p_.rsplit("/", 1)[0] if "/" in p_ else ""
            dirs[d] = dirs.get(d, 0) + 1
    for locs in conflicts[:20]:
        print("  %d locations: %s" % (len(locs), ", ".join(p_ for p_, _ in locs)))
    print("...")
    print("conflict records : %d" % len(conflicts))
    print("locations        : %d" % sum(len(c) for c in conflicts))
    print("distinct source directories : %d" % len(dirs))
    for d in sorted(dirs, key=lambda x: -dirs[x]):
        print("  %-44s %6d" % (d, dirs[d]))
    return 0


def cmd_list(path, with_sha1):
    data = load(path)
    creator, entries, lookup, conflicts, trailer_ok, acc = parse(data, path)
    for e in sorted(entries, key=lambda x: x["offset"]):
        line = "%-22s %10d  @%-10d" % (e["name"], e["length"], e["offset"])
        if with_sha1:
            h = hashlib.sha1(data[e["data"]:e["data"] + e["length"]])
            line += "  " + h.hexdigest()
        print(line)
    print("%d members, %d bytes, residue %d"
          % (len(entries), sum(e["length"] for e in entries), acc["residue"]))
    return 0 if acc["residue"] == 0 else 1


def cmd_extract(path, out):
    data = load(path)
    creator, entries, lookup, conflicts, trailer_ok, acc = parse(data, path)
    os.makedirs(out, exist_ok=True)
    n = 0
    for e in entries:
        dest = os.path.join(out, e["name"])
        with open(dest, "wb") as fh:
            fh.write(data[e["data"]:e["data"] + e["length"]])
        n += 1
    print("extracted %d members, %d bytes, to %s"
          % (n, sum(e["length"] for e in entries), out))
    return 0 if acc["residue"] == 0 else 1


def find(root):
    out = []
    for r, dirs, names in os.walk(root):
        for nm in sorted(names):
            if nm.upper().endswith(".LGP"):
                out.append(os.path.join(r, nm))
    return sorted(out)


def cmd_census(root):
    paths = find(root)
    if not paths:
        print("FATAL: no .LGP found under %r -- this census has nothing to do"
              % root)
        return 3
    print("%-46s %12s %7s %12s %8s %6s" %
          ("path", "bytes", "members", "member bytes", "residue", "gap"))
    print("-" * 100)
    bad = 0
    tot_members = tot_bytes = tot_member_bytes = 0
    nconflict = 0
    nloc = 0
    checks = {}
    for p in paths:
        data = load(p)
        try:
            creator, entries, lookup, conflicts, trailer_ok, acc = parse(data, p)
        except NotLGP as exc:
            print("%-46s  REFUSED: %s" % (rel(p, root), exc))
            bad += 1
            continue
        gap = walk_gaps(entries, acc)
        print("%-46s %12d %7d %12d %8d %6d" %
              (rel(p, root), acc["file"], len(entries),
               sum(e["length"] for e in entries), acc["residue"], gap))
        if acc["residue"] != 0 or not trailer_ok:
            bad += 1
        nconflict += acc["conflicts"]
        nloc += acc["locations"]
        for e in entries:
            checks[e["check"]] = checks.get(e["check"], 0) + 1
        tot_members += len(entries)
        tot_bytes += acc["file"]
        tot_member_bytes += sum(e["length"] for e in entries)
    print("-" * 100)
    print("archives          : %d" % len(paths))
    print("archive bytes     : %d" % tot_bytes)
    print("members           : %d" % tot_members)
    print("member bytes      : %d" % tot_member_bytes)
    print("overhead          : %d bytes = %.4f %%"
          % (tot_bytes - tot_member_bytes,
             100.0 * (tot_bytes - tot_member_bytes) / tot_bytes))
    print("archives not closing with residue 0 : %d of %d" % (bad, len(paths)))
    print("conflict records, all archives      : %d in %d locations"
          % (nconflict, nloc))
    print("byte-24 values seen, with counts    : %s"
          % ", ".join("%d x%d" % (k, checks[k]) for k in sorted(checks)))
    return 1 if bad else 0


def rel(p, root):
    r = os.path.relpath(p, root).replace(os.sep, "/")
    return r if len(r) <= 46 else "..." + r[-43:]


def cmd_selftest():
    """Four specimens that must be refused, each by a DIFFERENT check.

    A self-test whose specimens all fail the same length guard proves that one
    guard works and says nothing about the others. These are padded past the
    minimum length on purpose, so that each one reaches the check it is meant
    to exercise: the length guard, the count guard, the offset guard and the
    run-past-end guard, in that order.
    """
    pad = b"\0" * 8192

    def toc(name, offset, length_at=None, blob_len=8192):
        """One well-formed header and directory, with a planted fault."""
        body = bytearray(b"\0\0SQUARESOFT" + struct.pack("<I", 1))
        rec = bytearray(20)
        rec[:len(name)] = name
        body += rec + struct.pack("<IBH", offset, 14, 0)
        body += b"\0" * (LOOKUP + CONFLICT_LEN)
        body += b"\0" * blob_len
        if length_at is not None:
            o = offset
            body[o:o + 20] = rec
            body[o + 20:o + 24] = struct.pack("<I", length_at)
        return bytes(body) + TRAILER

    cases = [
        ("eight zero bytes -- the length guard", b"\0" * 8),
        ("a real creator and a count that cannot fit -- the count guard",
         b"\0\0SQUARESOFT" + struct.pack("<I", 0xFFFFFF) + pad),
        ("a member whose offset is past the end -- the offset guard",
         toc(b"a.tex", 1 << 30)),
        ("a member whose declared length runs past the end -- the run guard",
         toc(b"a.tex", 4000, length_at=1 << 30)),
    ]
    ok = 0
    for label, blob in cases:
        try:
            parse(blob, label)
            print("NOT REFUSED: %s -- the test failed" % label)
        except NotLGP as exc:
            print("refused: %s" % exc)
            ok += 1
    print("%d of %d refused" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--sha1", action="store_true")
    ap.add_argument("--extract")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--conflicts", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv[1:])
    if a.selftest:
        return cmd_selftest()
    if not a.path:
        ap.print_usage()
        return 2
    try:
        if a.census:
            return cmd_census(a.path)
        if a.validate:
            return cmd_validate(a.path)
        if a.conflicts:
            return cmd_conflicts(a.path)
        if a.extract:
            return cmd_extract(a.path, a.extract)
        if a.list or a.sha1:
            return cmd_list(a.path, a.sha1)
    except NotLGP as exc:
        print("REFUSED: %s" % exc)
        return 1
    ap.print_usage()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
