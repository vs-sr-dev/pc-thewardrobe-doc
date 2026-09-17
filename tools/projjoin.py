#!/usr/bin/env python3
"""projjoin.py -- join a whole RPG Maker PROJECT's resource references to the
files, and say for each one whether it resolves inside the project, inside the
Run Time Package, or nowhere.

WHY THIS IS NOT rtpjoin.py
--------------------------
`rtpjoin.py` joins one database against one `RTP\\` and answers "do these names
name files". A project asks a different question, because a project has **two**
places a name can live: its own directories and the shared RTP. Where a name
resolves is the measurement -- it says whether the person who made this project
drew anything or only arranged what the product shipped.

And a project's references are not all in the database. Three sources:

  * `RPG_RT.lmt`   -- each map entry's field 12 is a nested record whose field 1
                      is a **music or sound stem**;
  * `Map*.lmu`     -- each event's field 5 is a list of pages, and a page's
                      field 21 is a **character graphic stem**;
  * `RPG_RT.ldb`   -- everything `rtpjoin.py` already discovers, plus the one
                      relation a stem-matching threshold cannot find: a map's
                      field 1 is a **chipset id**, an index into database chunk
                      20, whose entry's field 2 is the graphic stem. That is an
                      id resolved through a table into a name resolved into a
                      file, and it is checked here explicitly.

THE DISCOVERY RULE IS THE SAME ONE, AND IT IS STATED
-----------------------------------------------------
A `(source, field)` pair is taken as a resource reference when at least
`--threshold` of its distinct values are file stems in one directory. Nothing
below the threshold is counted, and it is printed anyway. Display names are not
references even when they resolve.

    python tools/projjoin.py <project-dir> --rtp <root>/RTP
    python tools/projjoin.py <project-dir> --rtp <root>/RTP --expect-unresolved 0
    python tools/projjoin.py selftest
"""
import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lcf                                       # noqa: E402
import lcfmap                                    # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

MUSIC_FIELD = 12
EVENTS_FIELD = 81
PAGES_FIELD = 5
CHIPSET_ID_FIELD = 1
CHIPSET_CHUNK = 20
CHIPSET_GRAPHIC_FIELD = 2


def stems(base, label):
    """{subdirectory: {stem: filename}} under base, one level of walk."""
    out = {}
    if not os.path.isdir(base):
        raise SystemExit("projjoin: no such directory: %s" % base)
    for dp, _dn, fn in os.walk(base):
        d = os.path.relpath(dp, base).replace(os.sep, "/")
        d = "" if d == "." else d
        for f in fn:
            out.setdefault("%s/%s" % (label, d) if d else label,
                           {})[os.path.splitext(f)[0]] = f
    return out


def ascii_values(fields):
    for f in fields:
        v = f["data"] if isinstance(f, dict) else f[1]
        t = f["tag"] if isinstance(f, dict) else f[0]
        if 1 <= len(v) <= 32 and all(32 <= x < 127 for x in v):
            yield t, v.decode("ascii")


def gather(project):
    """{(source, field): [values]} plus the chipset chain, from a project."""
    refs = collections.defaultdict(list)
    chip_ids = {}

    lmt = os.path.join(project, "RPG_RT.lmt")
    if os.path.exists(lmt):
        p = lcfmap.parse(lmt)
        for eid, fs in p["entries"]:
            for f in fs:
                if f["tag"] != MUSIC_FIELD:
                    continue
                inner, _end = lcfmap.read_fields(f["data"], 0, len(f["data"]))
                for t, v in ascii_values(inner):
                    refs[("lmt", "12.%d" % t)].append(v)

    for name in sorted(os.listdir(project)):
        if not name.lower().endswith(".lmu"):
            continue
        p = lcfmap.parse(os.path.join(project, name))
        cid = [f["data"] for f in p["fields"] if f["tag"] == CHIPSET_ID_FIELD]
        chip_ids[name] = int.from_bytes(cid[0], "little") if cid else 1
        rows, _res, _c = lcfmap.events_of(p)
        for _eid, fs in rows:
            for f in fs:
                if f["tag"] != PAGES_FIELD:
                    continue
                pages, _q, _c2 = lcfmap.read_list(f["data"], 0,
                                                  len(f["data"]))
                for _pid, pfs in pages:
                    for t, v in ascii_values(pfs):
                        refs[("lmu", "81.5.%d" % t)].append(v)

    ldb = os.path.join(project, "RPG_RT.ldb")
    chipset_table = {}
    if os.path.exists(ldb):
        blob = open(ldb, "rb").read()
        _nm, chunks, residue = lcf.top_level(blob)
        if residue:
            raise SystemExit("projjoin: the project database does not close "
                             "(residue %d)" % residue)
        for c in chunks:
            d = blob[c["offset"]:c["offset"] + c["size"]]
            kind, payload, _res, _why = lcf.shape(d)
            if kind.startswith("LIST"):
                src = payload[1]
            elif kind == "RECORD":
                src = [(0, payload)]
            else:
                continue
            for iid, fields in src:
                for t, v in ascii_values([(a, b) for a, b in fields]):
                    refs[("ldb", "%d.%d" % (c["tag"], t))].append(v)
                if c["tag"] == CHIPSET_CHUNK:
                    for t, v in fields:
                        if t == CHIPSET_GRAPHIC_FIELD:
                            chipset_table[iid] = v.decode("ascii", "replace")
    return refs, chip_ids, chipset_table


def resolve(value, tables):
    for label, table in tables:
        if value in table:
            return label, table[value]
    return None, None


def run(args):
    project = args.project
    own = stems(project, "project")
    rtp = stems(args.rtp, "RTP")
    tables = sorted(own.items()) + sorted(rtp.items())

    refs, chip_ids, chipset_table = gather(project)

    print("project : %s" % os.path.basename(os.path.normpath(project)))
    print("its own directories carrying files : %d" % len(own))
    for d in sorted(own):
        print("   %-28s %4d files" % (d, len(own[d])))
    print("RTP directories carrying files     : %d" % len(rtp))
    print()
    print("A (source, field) is a RESOURCE REFERENCE when at least %.0f %% of "
          "its" % (100 * args.threshold))
    print("distinct values are file stems somewhere. Everything else is below "
          "the line.")
    print()

    joined, near = [], []
    for key, vals in sorted(refs.items()):
        distinct = sorted(set(vals))
        hits = [v for v in distinct if resolve(v, tables)[0]]
        share = len(hits) / len(distinct) if distinct else 0.0
        (joined if share >= args.threshold else near).append(
            (key, distinct, vals, share))

    in_project = in_rtp = nowhere = 0
    print("  %-10s %-12s %8s  %s" % ("source", "field", "refs", "where"))
    for key, distinct, vals, share in joined:
        where = collections.Counter()
        for v in vals:
            label, _fn = resolve(v, tables)
            if label is None:
                nowhere += 1
                where["(nowhere)"] += 1
            elif label.startswith("project"):
                in_project += 1
                where[label] += 1
            else:
                in_rtp += 1
                where[label] += 1
        print("  %-10s %-12s %8d  %s"
              % (key[0], key[1], len(vals),
                 ", ".join("%s %d" % (k, n) for k, n in where.most_common())))

    total = in_project + in_rtp + nowhere
    print()
    print("  references counted                 : %d" % total)
    print("  resolve INSIDE the project         : %d" % in_project)
    print("  resolve into the shared RTP        : %d" % in_rtp)
    print("  resolve NOWHERE                    : %d" % nowhere)
    print("  the three sum to the total         : %s"
          % (in_project + in_rtp + nowhere == total))
    print()

    print("-- the chipset chain, which no stem threshold can find ---------")
    print("  a map's field 1 is an index into database chunk %d, whose"
          % CHIPSET_CHUNK)
    print("  entry's field %d is a graphic stem." % CHIPSET_GRAPHIC_FIELD)
    chip_ok = chip_total = 0
    for name in sorted(chip_ids):
        cid = chip_ids[name]
        graphic = chipset_table.get(cid)
        label, fn = resolve(graphic, tables) if graphic else (None, None)
        chip_total += 1
        if label:
            chip_ok += 1
        print("  %-14s chipset id %d -> %-10s -> %s"
              % (name, cid, graphic or "(none)",
                 "%s/%s" % (label, fn) if label else "NOWHERE"))
    print("  chipset chains that resolve : %d of %d" % (chip_ok, chip_total))
    print()

    print("-- below the threshold, and NOT counted ------------------------")
    for key, distinct, vals, share in sorted(near, key=lambda r: -r[3]):
        print("  %-10s %-12s %4d distinct, %5.1f %% resolve"
              % (key[0], key[1], len(distinct), 100 * share))

    if args.expect_unresolved is not None and nowhere != args.expect_unresolved:
        raise SystemExit("FATAL: --expect-unresolved %d, got %d"
                         % (args.expect_unresolved, nowhere))
    return 0 if nowhere == 0 else 1


def selftest():
    import shutil
    import tempfile
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    enc = lcfmap._enc

    def field(tag, data):
        return enc(tag) + enc(len(data)) + data

    tmp = tempfile.mkdtemp(prefix="projjoin-")
    try:
        proj = os.path.join(tmp, "Proj")
        os.makedirs(os.path.join(proj, "ChipSet"))
        rtp = os.path.join(tmp, "RTP")
        os.makedirs(os.path.join(rtp, "Music"))
        os.makedirs(os.path.join(rtp, "CharSet"))
        open(os.path.join(proj, "ChipSet", "World.png"), "wb").write(b"x")
        open(os.path.join(rtp, "Music", "Song 1.mid"), "wb").write(b"x")
        open(os.path.join(rtp, "CharSet", "Object1.png"), "wb").write(b"x")

        # a map tree naming one music stem that lives in the RTP
        music = field(1, b"Song 1") + b"\x00"
        e0 = enc(0) + field(1, b"Root") + field(12, music) + b"\x00"
        lmt = enc(10) + b"LcfMapTree" + enc(1) + e0 + enc(1) + enc(0) + b"\x00"
        open(os.path.join(proj, "RPG_RT.lmt"), "wb").write(lmt)

        # a map with a chipset id of 1 and one event page naming a charset
        page = enc(1) + enc(1) + field(21, b"Object1") + b"\x00"
        evs = enc(1) + enc(1) + field(1, b"EV0001") + field(2, enc(3)) + \
            field(3, enc(4)) + field(5, page) + b"\x00"
        lmu = enc(10) + b"LcfMapUnit" + field(1, enc(1)) + \
            field(71, bytes(600)) + field(72, bytes(600)) + \
            field(81, evs) + b"\x00"
        open(os.path.join(proj, "Map0001.lmu"), "wb").write(lmu)

        # a database whose chunk 20 entry 1 has graphic stem World
        entry = enc(1) + field(1, b"Basic") + field(2, b"World") + b"\x00"
        chunk20 = enc(1) + entry
        ldb = enc(11) + b"LcfDataBase" + enc(20) + enc(len(chunk20)) + chunk20
        open(os.path.join(proj, "RPG_RT.ldb"), "wb").write(ldb)

        refs, chip_ids, table = gather(proj)
        check("the map tree music reference is found",
              refs[("lmt", "12.1")], ["Song 1"])
        check("the event page graphic is found",
              refs[("lmu", "81.5.21")], ["Object1"])
        check("the chipset id is read", chip_ids["Map0001.lmu"], 1)
        check("the chipset table resolves the id", table.get(1), "World")

        own = stems(proj, "project")
        rt = stems(rtp, "RTP")
        tables = sorted(own.items()) + sorted(rt.items())
        check("a project stem resolves inside the project",
              resolve("World", tables)[0], "project/ChipSet")
        check("an RTP stem resolves in the RTP",
              resolve("Song 1", tables)[0], "RTP/Music")
        check("an unknown stem resolves nowhere",
              resolve("Nope", tables)[0], None)
        check("a stem with a space is not split",
              resolve("Song 1", tables)[1], "Song 1.mid")

        try:
            stems(os.path.join(tmp, "absent"), "x")
            got = "no exception"
        except SystemExit:
            got = "SystemExit"
        check("a missing directory is fatal", got, "SystemExit")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = 0
    for name, ok, got, want in checks:
        print("  %-46s %s" % (name, "ok" if ok else
                              "FAIL got %r want %r" % (got, want)))
        if not ok:
            bad += 1
    print("checks : %d   failures : %d" % (len(checks), bad))
    raise SystemExit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("project", nargs="?")
    ap.add_argument("--rtp")
    ap.add_argument("--threshold", type=float, default=0.75)
    ap.add_argument("--expect-unresolved", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.project == "selftest":
        return selftest()
    if not args.project or not args.rtp:
        raise SystemExit("projjoin: a project directory and --rtp are "
                         "required (or --selftest)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
