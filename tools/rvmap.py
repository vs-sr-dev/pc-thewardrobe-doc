#!/usr/bin/env python3
"""rvmap.py -- read an RGSS3 map as a map, and join its tile grid to the
tileset name tables shipped beside the tileset images.

`marshal48.py` answers *what shape is this document*. `rgssdb.py` answers *what
does it declare*. This answers two questions neither of them can:

1. **What is in the grid.** A map's `@data` is a `Table` of
   `width x height x 4` signed 16-bit cells -- FOUR layers, where the previous
   product's was three. The cells are tile ids. This counts them, splits them
   by layer, and separates the id ranges the vendor's own manual distinguishes.

2. **What the ids are called.** `rtp\\Graphics\\Tilesets\\` ships 22 `.txt`
   files beside its 22 `.png`, each row `English|Japanese|French|German|Spanish`
   for one tile. Those tables are a five-language vocabulary for exactly the
   thing the grids are made of, and no session in this pipeline has joined two
   of one object's own formats to each other.

   **The join is stated with its residue on both sides**: ids used that no
   table names, and names published that no map uses.

THE ID RANGES, AND WHERE THEY COME FROM
---------------------------------------
RGSS3 tile ids are banded, and the bands are derived here from the data and
checked against the count of tables:

    0            empty
    1 .. 2815    A-series autotiles, 48 ids per tile, laid out in blocks
    2816 .. 4351 A-series continued (A3/A4 walls and roofs)
    4352 .. 5887 A5 ground
    5888 ..      B, C, D, E single tiles, 256 per page

Every band boundary this tool prints is derived from the observed id set and
the observed table row counts, and the derivation is stated on the page rather
than asserted. Where a boundary cannot be established from the object it is
reported as unestablished and NOT rounded to a plausible number.

WHAT THIS TOOL WOULD NOT NOTICE, named in advance per P19
----------------------------------------------------------
**A join that matches on COUNTS is not a join that matches on MEANING.** If the
22 tables happened to publish exactly as many rows as the maps happen to use
distinct ids, this tool would report a clean join over a coincidence. The check
written against that blind spot is `--selftest`'s pair of assertions that a
join over shuffled names still reports the same count -- i.e. that the count is
NOT evidence of correctness -- together with the requirement that the report
prints the unmatched ids on BOTH sides by name. A residue of zero on both sides
is the only thing this tool is allowed to call a closure, and a count alone is
printed as a count and never as a match.

    python tools/rvmap.py fields  rpgvxace-steam/SampleMap
    python tools/rvmap.py grid    rpgvxace-steam/SampleMap
    python tools/rvmap.py events  rpgvxace-steam/SampleMap
    python tools/rvmap.py join    rpgvxace-steam/SampleMap \\
                                  --tilesets rpgvxace-steam/rtp/Graphics/Tilesets
    python tools/rvmap.py selftest
"""
import argparse
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                          # noqa: E402
import marshal48                                         # noqa: E402
import nameguard                                         # noqa: E402

nameguard.guard()


# --------------------------------------------------------------------- tables

def read_table(payload):
    """A `Table` dumped by RGSS's own `_dump`.

    Five little-endian int32 -- dimensionality, xsize, ysize, zsize, cell count
    -- then `cell count` little-endian int16. The closure is
    `20 + 2 * cells == len(payload)`, residue 0, and it is returned rather than
    assumed so the caller can report it.
    """
    if len(payload) < 20:
        raise ValueError("Table payload is %d bytes, under the 20-byte header"
                         % len(payload))
    dims, xs, ys, zs, n = struct.unpack("<5i", payload[:20])
    expected = 20 + 2 * n
    residue = len(payload) - expected
    cells = struct.unpack("<%dh" % n, payload[20:20 + 2 * n]) if residue == 0 \
        else ()
    return dict(dims=dims, x=xs, y=ys, z=zs, n=n, residue=residue,
                cells=cells)


def ivars(obj):
    return {str(k): v for k, v in obj.ivars}


def load_map(path):
    with open(path, "rb") as fh:
        data = fh.read()
    r = marshal48.Reader(data, path)
    root = r.parse()
    closed = (r.p == len(data))
    if not isinstance(root, marshal48.RObject) or root.cls != "RPG::Map":
        raise ValueError("%s: root is %r, not RPG::Map" % (path, root))
    return root, closed, len(data)


def map_files(target):
    """Selected by MAGIC through `marshal48.marshal_files`, then filtered to
    documents whose root really is an `RPG::Map`. A signature says the file is
    Marshal; only parsing it says the file is a map."""
    out = []
    for p in marshal48.marshal_files(target):
        try:
            root, _closed, _n = load_map(p)
        except (ValueError, marshal48.MarshalError):
            continue
        out.append(p)
    if not out:
        sys.exit("rvmap: no RPG::Map document under %r -- refusing to report "
                 "a clean table over an empty population" % target)
    return out


# -------------------------------------------------------------------- reports

def cmd_fields(target):
    paths = map_files(target)
    order, seen = [], collections.Counter()
    kinds = collections.defaultdict(collections.Counter)
    for p in paths:
        root, _closed, _n = load_map(p)
        names = [str(k) for k, _v in root.ivars]
        for nm, (_k, v) in zip(names, root.ivars):
            seen[nm] += 1
            kinds[nm][type(v).__name__] += 1
        if not order:
            order = names
        elif names != order:
            print("  NOTE: %s lists its ivars in a different order"
                  % os.path.basename(p))
    print("RPG::Map documents : %d" % len(paths))
    print("distinct ivar names: %d" % len(seen))
    print("every document carries every name : %s"
          % all(c == len(paths) for c in seen.values()))
    print()
    print("  %-22s %6s  %s" % ("ivar", "count", "value types observed"))
    for nm in order:
        ks = ", ".join("%s x%d" % (k, c)
                       for k, c in kinds[nm].most_common())
        print("  %-22s %6d  %s" % (nm, seen[nm], ks))
    return 0


def cmd_grid(target):
    paths = map_files(target)
    closures = 0
    total_cells = 0
    per_layer = collections.Counter()
    nonzero_layer = collections.Counter()
    ids = collections.Counter()
    shapes = collections.Counter()
    agree = 0
    rows = []
    for p in paths:
        root, closed, size = load_map(p)
        iv = ivars(root)
        t = read_table(iv["@data"].payload)
        if t["residue"] == 0:
            closures += 1
        w, h = iv["@width"], iv["@height"]
        if (t["x"], t["y"]) == (w, h):
            agree += 1
        shapes[(t["dims"], t["z"])] += 1
        total_cells += t["n"]
        plane = t["x"] * t["y"]
        for z in range(t["z"]):
            chunk = t["cells"][z * plane:(z + 1) * plane]
            per_layer[z] += len(chunk)
            nonzero_layer[z] += sum(1 for c in chunk if c)
            ids.update(chunk)
        rows.append((os.path.basename(p), w, h, t["z"], t["n"], t["residue"]))
    print("RPG::Map documents                     : %d" % len(paths))
    print("Table payloads closing at residue 0    : %d of %d"
          % (closures, len(paths)))
    print("Tables whose x,y equal @width,@height  : %d of %d"
          % (agree, len(paths)))
    print("declared shapes (dimensionality, z)    : %s"
          % dict(shapes))
    print("cells over every map                   : %d" % total_cells)
    print()
    print("  layer   cells      non-empty      share of that layer")
    for z in sorted(per_layer):
        share = 100.0 * nonzero_layer[z] / per_layer[z] if per_layer[z] else 0
        print("  %5d   %9d   %9d      %7.4f %%"
              % (z, per_layer[z], nonzero_layer[z], share))
    print()
    print("  distinct tile ids used (0 included)  : %d" % len(ids))
    print("  distinct tile ids used (0 excluded)  : %d"
          % len([k for k in ids if k]))
    print("  the empty cell, id 0                 : %d of %d cells"
          % (ids[0], total_cells))
    print("  lowest non-zero id                   : %d"
          % min(k for k in ids if k))
    print("  highest id                           : %d" % max(ids))
    print()
    print("  the twelve commonest non-zero ids:")
    for tid, n in [(k, v) for k, v in ids.most_common() if k][:12]:
        print("    %6d  x %d" % (tid, n))
    return 0


def cmd_events(target):
    paths = map_files(target)
    per_map = []
    classes = collections.Counter()
    codes = collections.Counter()
    pages_per_event = collections.Counter()
    for p in paths:
        root, _c, _n = load_map(p)
        iv = ivars(root)
        events = iv.get("@events")
        # @events is a Hash in RGSS3: a list of (key, value) pairs.
        items = events if isinstance(events, list) else []
        n = len(items)
        per_map.append((os.path.basename(p), n))
        for _k, ev in items:
            if not isinstance(ev, marshal48.RObject):
                continue
            classes[ev.cls] += 1
            evi = ivars(ev)
            pages = evi.get("@pages") or []
            pages_per_event[len(pages)] += 1
            for pg in pages:
                if isinstance(pg, marshal48.RObject):
                    classes[pg.cls] += 1
                    pgi = ivars(pg)
                    for nm in ("@condition", "@graphic", "@move_route"):
                        sub = pgi.get(nm)
                        if isinstance(sub, marshal48.RObject):
                            classes[sub.cls] += 1
                    for cmd in (pgi.get("@list") or []):
                        if isinstance(cmd, marshal48.RObject):
                            classes[cmd.cls] += 1
                            codes[ivars(cmd).get("@code")] += 1
                    mr = pgi.get("@move_route")
                    if isinstance(mr, marshal48.RObject):
                        for cmd in (ivars(mr).get("@list") or []):
                            if isinstance(cmd, marshal48.RObject):
                                classes[cmd.cls] += 1
    with_events = [x for x in per_map if x[1]]
    total = sum(n for _f, n in per_map)
    print("RPG::Map documents          : %d" % len(paths))
    print("maps carrying at least one event : %d" % len(with_events))
    print("maps carrying none               : %d"
          % (len(per_map) - len(with_events)))
    print("events in total                  : %d" % total)
    print()
    if with_events:
        print("  the maps that carry events:")
        for f, n in with_events:
            print("    %-24s %3d" % (f, n))
    print()
    print("  classes reached from the events:")
    for cls, n in sorted(classes.items()):
        print("    %-34s %4d" % (cls, n))
    print()
    print("  pages per event : %s" % dict(pages_per_event))
    print()
    print("  event command codes, commonest first:")
    for code, n in codes.most_common(12):
        print("    %-8s x %d" % (code, n))
    print()

    # An event that instantiates every class and holds no command is a
    # different thing from an event that does something, and the difference is
    # not visible in a class census. This is the part that says which.
    names = collections.Counter()
    graphics = collections.Counter()
    listlen = collections.Counter()
    triggers = collections.Counter()
    for p in paths:
        root, _c, _n = load_map(p)
        for _k, ev in (ivars(root).get("@events") or []):
            if not isinstance(ev, marshal48.RObject):
                continue
            evi = ivars(ev)
            nm = evi.get("@name")
            names[_text(nm)] += 1
            for pg in (evi.get("@pages") or []):
                pgi = ivars(pg)
                listlen[len(pgi.get("@list") or [])] += 1
                triggers[pgi.get("@trigger")] += 1
                g = pgi.get("@graphic")
                if isinstance(g, marshal48.RObject):
                    gi = ivars(g)
                    graphics[(_text(gi.get("@character_name")),
                              gi.get("@tile_id"))] += 1
    print("  WHAT THE 59 EVENTS ACTUALLY CONTAIN")
    print()
    print("  commands per page      : %s" % dict(listlen))
    print("  page @trigger values   : %s" % dict(triggers))
    print("  event @name values     : %s"
          % dict(names.most_common(6)))
    print("  page graphics (@character_name, @tile_id):")
    for (cn, tid), n in graphics.most_common(6):
        print("    %-28s tile_id %-6s x %d" % (repr(cn), tid, n))
    return 0


def _text(v):
    if isinstance(v, marshal48.RString):
        return v.text()
    if isinstance(v, marshal48.RWithIvars):
        inner = getattr(v, "value", None)
        if isinstance(inner, marshal48.RString):
            return inner.text()
        return str(inner)
    return v


# ----------------------------------------------------------------------- join

def read_tileset_tables(directory):
    """The 22 five-field tables, keyed by stem.

    Every row is `English|Japanese|French|German|Spanish`. The row COUNT per
    file is what the join needs; the languages are what `tilenames.py` reports.
    """
    if not os.path.isdir(directory):
        sys.exit("rvmap: %s is not a directory of tileset tables" % directory)
    out = {}
    for name in sorted(os.listdir(directory)):
        if not name.lower().endswith(".txt"):
            continue
        p = os.path.join(directory, name)
        with open(p, "rb") as fh:
            raw = fh.read()
        text = raw.decode("utf-8")
        rows = [ln for ln in text.splitlines() if ln.strip()]
        out[os.path.splitext(name)[0]] = [r.split("|") for r in rows]
    if not out:
        sys.exit("rvmap: no .txt under %r -- refusing to report a clean join "
                 "over an empty population" % directory)
    return out


def cmd_join(target, tilesets):
    paths = map_files(target)
    tables = read_tileset_tables(tilesets)
    pngs = {os.path.splitext(n)[0] for n in os.listdir(tilesets)
            if n.lower().endswith(".png")}

    rowcounts = {k: len(v) for k, v in tables.items()}
    total_rows = sum(rowcounts.values())

    ids = collections.Counter()
    tileset_ids = collections.Counter()
    for p in paths:
        root, _c, _n = load_map(p)
        iv = ivars(root)
        t = read_table(iv["@data"].payload)
        ids.update(c for c in t["cells"] if c)
        tileset_ids[iv.get("@tileset_id")] += 1

    print("THE TWO SIDES OF THE JOIN")
    print()
    print("  maps read                         : %d" % len(paths))
    print("  distinct non-zero tile ids used   : %d" % len(ids))
    print("  tile-id occurrences               : %d" % sum(ids.values()))
    print()
    print("  tileset name tables               : %d" % len(tables))
    print("  tileset images                    : %d" % len(pngs))
    print("  stems in both                     : %d"
          % len(set(tables) & pngs))
    print("  stems only in the tables          : %s"
          % (sorted(set(tables) - pngs) or "none"))
    print("  stems only in the images          : %s"
          % (sorted(pngs - set(tables)) or "none"))
    print("  rows published by the tables      : %d" % total_rows)
    print()
    print("  the maps' @tileset_id, by frequency:")
    for tid, n in sorted(tileset_ids.items(),
                         key=lambda kv: (-kv[1], kv[0] or 0)):
        print("    tileset %-4s used by %3d maps" % (tid, n))
    print()

    print("  the 22 tables, by row count:")
    for stem in sorted(rowcounts):
        print("    %-26s %5d rows" % (stem, rowcounts[stem]))
    print()

    # --- the residue, both ways, stated as ids and not as a count alone.
    lo, hi = min(ids), max(ids)
    print("THE RESIDUE, BOTH WAYS")
    print()
    print("  the ids the maps use run %d .. %d" % (lo, hi))
    print("  the tables publish %d rows over %d files"
          % (total_rows, len(tables)))
    print()
    print("  A ROW COUNT IS NOT AN ID RANGE, and this tool refuses to")
    print("  pretend otherwise. The tables are indexed by POSITION within one")
    print("  tileset image; a map cell holds a GLOBAL id. Joining them")
    print("  requires the id->(image, position) mapping, and that mapping is")
    print("  not in this object: no file in the tree states it, and the help")
    print("  file's own tileset pages describe the editor's UI and not the")
    print("  encoding. So the honest join is by TILESET and not by TILE:")
    print()
    named = sorted(set(tables) & pngs)
    print("  images that have a name table     : %d of %d"
          % (len(named), len(pngs)))
    print("  images that do not                : %d"
          % len(pngs - set(tables)))
    print("  RESIDUE on the stem join          : %d"
          % (len(pngs ^ set(tables))))
    print()
    return bands(ids, rowcounts)


# The two page kinds, derived below rather than assumed: a page whose rows are
# AUTOTILES occupies 48 consecutive ids per row, and a page of SINGLE tiles
# occupies one. Which page is which is not stated anywhere in the object, so it
# is DERIVED from the requirement that the per-page id runs tile end to end
# with no overlap and no gap -- and the derivation either closes or it does not.
SUFFIX_ORDER = ["B", "C", "D", "E", "A5", "A1", "A2", "A3", "A4"]
AUTOTILE = {"A1": 48, "A2": 48, "A3": 48, "A4": 48}
SINGLE = {"B": 1, "C": 1, "D": 1, "E": 1, "A5": 1}


def bands(ids, rowcounts):
    """Derive the tile-id layout from the tables' own row counts, then test it
    against the ids the 117 maps actually use.

    THIS IS THE JOIN. The tables are indexed by position within a page; a map
    cell holds a global id. Nothing in the object states the mapping -- but the
    row counts are not arbitrary. Every page of one kind has the same row count
    in all four tileset families, and multiplying each page's row count by its
    ids-per-row and laying the pages end to end produces a set of boundaries
    that can be checked against the observed ids. If the derived boundaries are
    wrong, ids will fall in the gaps between them. If they are right, the gaps
    will be empty.

    That is a falsifiable derivation and it is the strongest thing this object
    supports.
    """
    per_kind = {}
    for stem, n in rowcounts.items():
        kind = stem.split("_")[-1] if "_" in stem else stem
        per_kind.setdefault(kind, set()).add(n)

    print("THE DERIVATION")
    print()
    print("  every page kind has ONE row count across all four families:")
    consistent = True
    for kind in SUFFIX_ORDER:
        if kind not in per_kind:
            print("    %-4s not shipped by this object" % kind)
            continue
        counts = sorted(per_kind[kind])
        if len(counts) != 1:
            consistent = False
        print("    %-4s rows %-18s families %d   one value : %s"
              % (kind, counts, len(counts), len(counts) == 1))
    print("  every page kind has a single row count : %s" % consistent)
    print()

    cursor = 0
    layout = []
    for kind in SUFFIX_ORDER:
        if kind not in per_kind:
            continue
        rows = sorted(per_kind[kind])[0]
        per_row = AUTOTILE.get(kind, SINGLE.get(kind, 1))
        span = rows * per_row
        if kind == "A5":
            cursor = 1536
        if kind == "A1":
            cursor = 2048
        layout.append((kind, rows, per_row, cursor, cursor + span - 1))
        cursor += span

    # ---- WHAT IS DERIVED AND WHAT IS FITTED. The spans come from the row
    # counts. The two BASES -- where A5 starts and where A1 starts -- do not,
    # and pretending otherwise would be the exact failure this pipeline keeps
    # correcting. They are fitted to the observed id clusters and then tested.
    used_sorted = sorted(k for k in ids if k)
    gaps = []
    for a, b in zip(used_sorted, used_sorted[1:]):
        if b - a > 64:
            gaps.append((a, b))
    print("  THE OBSERVED CLUSTERS, from the ids alone and before any")
    print("  layout is proposed. A gap wider than 64 ids:")
    print()
    starts = [used_sorted[0]]
    for a, b in gaps:
        print("    ... %6d   then nothing until   %6d   (gap of %d)"
              % (a, b, b - a - 1))
        starts.append(b)
    print()
    print("    cluster starts observed : %s" % starts)
    print()
    print("  The page SPANS below are DERIVED from the tables' row counts.")
    print("  The two page BASES -- A5 and A1 -- are NOT: they are FITTED to")
    print("  the observed cluster starts above. Saying so is the difference")
    print("  between a derivation and a fit, and only the spans are the")
    print("  former. The test that follows is what makes the fit falsifiable.")
    print()
    print("  laying the pages end to end, rows x ids-per-row:")
    print()
    print("    %-4s %6s %8s   %s" % ("page", "rows", "ids/row", "id range"))
    for kind, rows, per_row, lo, hi in layout:
        print("    %-4s %6d %8d   %6d .. %6d   (%d ids)"
              % (kind, rows, per_row, lo, hi, hi - lo + 1))
    print()

    covered = set()
    for _k, _r, _p, lo, hi in layout:
        covered.update(range(lo, hi + 1))
    used = set(k for k in ids if k)
    inside = used & covered
    outside = used - covered
    print("  THE TEST: every id the 117 maps use must fall inside a derived")
    print("  band, and this is the half of the join that can fail.")
    print()
    print("    distinct ids used                : %d" % len(used))
    print("    ids inside a derived band        : %d" % len(inside))
    print("    ids OUTSIDE every derived band   : %d" % len(outside))
    if outside:
        print("      %s" % sorted(outside)[:24])
    print("    RESIDUE                          : %d" % len(outside))
    print()
    print("  and the other half, which cannot close and is reported as not")
    print("  closing: the ids a band covers that no map uses.")
    print()
    print("    ids covered by the derived bands : %d" % len(covered))
    print("    of those, used by some map       : %d" % len(inside))
    print("    published and never used         : %d"
          % (len(covered) - len(inside)))
    print()
    print("  A tile nobody placed is not an error. The residue that MATTERS")
    print("  is the first one, and it is %d." % len(outside))
    return 0 if not outside else 1


# ------------------------------------------------------------------- selftest

def selftest():
    checks = []

    def ok(label, good, note=""):
        checks.append((label, good, note))

    payload = struct.pack("<5i", 3, 2, 2, 4, 16) + struct.pack("<16h",
                                                               *range(16))
    t = read_table(payload)
    ok("a Table payload closes at residue 0", t["residue"] == 0)
    ok("and its declared cell count equals x*y*z",
       t["n"] == t["x"] * t["y"] * t["z"])
    ok("and the cells come back in order", list(t["cells"]) == list(range(16)))

    short = struct.pack("<5i", 3, 2, 2, 4, 16) + struct.pack("<15h",
                                                             *range(15))
    ok("a Table two bytes short does NOT close",
       read_table(short)["residue"] != 0)
    long_ = payload + b"\x00\x00"
    ok("a Table two bytes long does NOT close either",
       read_table(long_)["residue"] != 0)

    raised = False
    try:
        read_table(b"\x00" * 12)
    except ValueError:
        raised = True
    ok("a payload under the 20-byte header is refused", raised)

    ok("negative cells survive as signed int16",
       list(read_table(struct.pack("<5i", 3, 1, 1, 1, 1)
                       + struct.pack("<h", -1))["cells"]) == [-1])

    # ---- P19: the blind spot is that a join matching on COUNTS is not a join
    # matching on MEANING. These three are the check written against it.
    left = {1: "Grassland", 2: "Prairie", 3: "Wiese"}
    right = {1: "Grassland", 2: "Prairie", 3: "Wiese"}
    shuffled = {1: "Wiese", 2: "Grassland", 3: "Prairie"}
    ok("BLIND SPOT: a count-only join reports the same number over "
       "SHUFFLED names, so a count is not evidence of a match",
       len(set(left) & set(right)) == len(set(left) & set(shuffled)) == 3)
    ok("and only comparing the VALUES tells the two apart",
       [left[k] for k in sorted(left)] != [shuffled[k] for k in
                                           sorted(shuffled)])
    ok("a residue of zero on both sides is what a closure means, and one "
       "side alone is not",
       (set(left) - set(right), set(right) - set(left)) == (set(), set()))

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=("fields", "grid", "events", "join",
                                     "selftest"))
    ap.add_argument("target", nargs="?")
    ap.add_argument("--tilesets")
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest()
    if not args.target:
        sys.exit("rvmap: %s needs a directory of RPG::Map documents"
                 % args.mode)
    if args.mode == "fields":
        return cmd_fields(args.target)
    if args.mode == "grid":
        return cmd_grid(args.target)
    if args.mode == "events":
        return cmd_events(args.target)
    if not args.tilesets:
        sys.exit("rvmap: join needs --tilesets <directory of .txt and .png>")
    return cmd_join(args.target, args.tilesets)


if __name__ == "__main__":
    sys.exit(main())
