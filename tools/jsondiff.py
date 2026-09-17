#!/usr/bin/env python3
"""jsondiff.py -- two directories of JSON documents, joined by key.

WHY THIS EXISTS
---------------
`pc-rpgmakermv-doc` ships its starter project twice, once in English and once
in Japanese: `NewData_FantasyEN\\data\\` and `NewData_FantasyJP\\data\\`, nine
files each under the same nine names. Eight of the nine agree on how many
records they hold. **`Items.json` has thirty-six in English and thirty-one in
Japanese**, and which five is a `json.load` and a set subtraction.

`pc-rpgmakerxp-doc/docs/06` and `pc-rpgmakervxace-doc/docs/06` did this kind of
comparison against a Ruby `Marshal` dump and needed a reader written for the
purpose. This object's database is JSON and the reader is the standard library,
so what is left is the join -- which is the part that was always the work.

WHAT IT DOES
------------
For every file name present in both directories:

  * parse both, refusing rather than guessing on a document that will not
    parse under UTF-8;
  * establish the record key. RPG Maker's database arrays are 1-based with
    `null` at index 0, and every record carries an `id` that equals its index.
    **The key is the `id` field and the check is that it equals the index**;
    a file where that fails is reported and not joined, because a join on a
    key that is not a key is a table of coincidences;
  * report counts, the ids on each side only, and for the ids in both, how
    many records differ field by field and which fields.

WHAT THIS TOOL WOULD NOT NOTICE, named in advance per P19
----------------------------------------------------------
**Two records with the same id are not the same record.** These are two
LANGUAGES of one database, so nearly every record differs in `name`, `note` and
`description` by construction, and a field-level difference count is therefore
a measure of translation and not of divergence. The tool cannot tell "this item
was translated" from "this item was replaced". It therefore reports the
difference set **split by field**, so that a record differing only in the text
fields can be distinguished from one differing in a numeric one -- and
`--selftest` asserts that a record differing only in a numeric field is
reported separately from one differing only in a string field, because
collapsing them is exactly the mistake that would make the output useless.

    python tools/jsondiff.py A/data B/data
    python tools/jsondiff.py A/data B/data --file Items.json --show-only
    python tools/jsondiff.py --selftest
"""
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nameguard


def load(path):
    """Parse one JSON document, or raise ValueError with the reason."""
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as e:
        raise ValueError("not UTF-8: %s" % e)
    except json.JSONDecodeError as e:
        raise ValueError("not one JSON document: %s" % e)


def records(doc):
    """(records_by_id, notes) for a database array.

    RPG Maker's convention -- `null` at index 0, `id` equal to the index -- is
    checked and not assumed, and what the check found is returned beside the
    records so the caller can print it.
    """
    notes = []
    if not isinstance(doc, list):
        return None, ["root is %s and not a list" % type(doc).__name__]
    if not doc:
        return {}, ["the array is empty"]
    if doc[0] is not None:
        notes.append("element 0 is NOT null, against the convention")
    body = doc[1:] if doc[0] is None else doc
    by = {}
    bad = 0
    for i, r in enumerate(body, 1 if doc[0] is None else 0):
        if not isinstance(r, dict) or "id" not in r:
            bad += 1
            continue
        if r["id"] != i:
            bad += 1
        by[r["id"]] = r
    if bad:
        notes.append("%d of %d records have no id or an id that is not their "
                     "index" % (bad, len(body)))
    if len(by) != len(body):
        notes.append("%d records collapse to %d distinct ids"
                     % (len(body), len(by)))
    return by, notes


def field_diff(a, b):
    """{field: 'A only' | 'B only' | 'differ'} for two records."""
    out = {}
    for k in sorted(set(a) | set(b)):
        if k not in b:
            out[k] = "A only"
        elif k not in a:
            out[k] = "B only"
        elif a[k] != b[k]:
            out[k] = "differ"
    return out


def compare_file(pa, pb):
    """Everything this tool can say about one pair of documents."""
    try:
        da = load(pa)
    except ValueError as e:
        return dict(name=os.path.basename(pa), refused="A: %s" % e)
    try:
        db = load(pb)
    except ValueError as e:
        return dict(name=os.path.basename(pa), refused="B: %s" % e)
    ra, na = records(da)
    rb, nb = records(db)
    if ra is None or rb is None:
        return dict(name=os.path.basename(pa),
                    refused="not a record array: %s %s" % (na, nb))
    only_a = sorted(set(ra) - set(rb))
    only_b = sorted(set(rb) - set(ra))
    both = sorted(set(ra) & set(rb))
    differ = []
    fields = collections.Counter()
    numeric_only = 0
    string_only = 0
    for i in both:
        d = field_diff(ra[i], rb[i])
        if not d:
            continue
        differ.append(i)
        for k in d:
            fields[k] += 1
        kinds = {type(ra[i].get(k)).__name__ for k in d if k in ra[i]}
        if kinds and kinds <= {"int", "float", "bool", "list", "dict"}:
            numeric_only += 1
        elif kinds == {"str"}:
            string_only += 1
    return dict(name=os.path.basename(pa), a=len(ra), b=len(rb),
                bytes_a=os.path.getsize(pa), bytes_b=os.path.getsize(pb),
                only_a=only_a, only_b=only_b, both=len(both),
                differ=differ, fields=fields,
                numeric_only=numeric_only, string_only=string_only,
                notes_a=na, notes_b=nb, ra=ra, rb=rb)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a", nargs="?")
    ap.add_argument("b", nargs="?")
    ap.add_argument("--file", help="restrict to one file name")
    ap.add_argument("--show-only", action="store_true",
                    help="print the records that exist on one side only")
    ap.add_argument("--expect-agreeing", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.a or not args.b:
        ap.error("two directories are required")
    for d in (args.a, args.b):
        if not os.path.isdir(d):
            sys.exit("jsondiff: %s is not a directory; this tool compares two "
                     "directories of JSON documents" % d)
    nameguard.guard()

    na = {f for f in os.listdir(args.a) if f.lower().endswith(".json")}
    nb = {f for f in os.listdir(args.b) if f.lower().endswith(".json")}
    common = sorted(na & nb)
    if not common:
        sys.exit("jsondiff: no .json name is present in both %s and %s -- "
                 "refusing to report a clean comparison over an empty "
                 "population" % (args.a, args.b))
    names = [args.file] if args.file else common
    print("A : %s   %d JSON documents" % (args.a, len(na)))
    print("B : %s   %d JSON documents" % (args.b, len(nb)))
    print("names in both : %d   only A : %d   only B : %d"
          % (len(common), len(na - nb), len(nb - na)))
    print()
    print("  %-16s %6s %6s %6s %6s %8s %8s  %s"
          % ("file", "A recs", "B recs", "same", "A only", "B only",
             "differ", "bytes A / B"))
    agreeing = 0
    rows = []
    for f in names:
        r = compare_file(os.path.join(args.a, f), os.path.join(args.b, f))
        rows.append(r)
        if "refused" in r:
            print("  %-16s REFUSED  %s" % (f, r["refused"]))
            continue
        same = r["a"] == r["b"]
        agreeing += 1 if same else 0
        print("  %-16s %6d %6d %6s %6d %8d %8d  %d / %d"
              % (f, r["a"], r["b"], "yes" if same else "**NO**",
                 len(r["only_a"]), len(r["only_b"]), len(r["differ"]),
                 r["bytes_a"], r["bytes_b"]))
    print()
    print("files whose record COUNT agrees : %d of %d" % (agreeing, len(names)))
    tot_a = sum(r.get("a", 0) for r in rows)
    tot_b = sum(r.get("b", 0) for r in rows)
    print("records, A %d   B %d   difference %d" % (tot_a, tot_b, tot_a - tot_b))
    print()
    for r in rows:
        if "refused" in r or (not r["only_a"] and not r["only_b"]):
            continue
        print("  %s -- ids on one side only:" % r["name"])
        print("    A only : %s" % r["only_a"])
        print("    B only : %s" % r["only_b"])
        if args.show_only:
            for i in r["only_a"]:
                print("      A #%d  %s" % (i, nameguard.safe(
                    json.dumps(r["ra"][i], ensure_ascii=False)[:400])))
            for i in r["only_b"]:
                print("      B #%d  %s" % (i, nameguard.safe(
                    json.dumps(r["rb"][i], ensure_ascii=False)[:400])))
    print()
    print("  the records present in both, by how they differ:")
    print("  %-16s %8s %10s %10s  %s"
          % ("file", "differ", "numeric", "string only", "commonest fields"))
    for r in rows:
        if "refused" in r:
            continue
        top = ", ".join("%s %d" % kv for kv in r["fields"].most_common(4))
        print("  %-16s %8d %10d %10d  %s"
              % (r["name"], len(r["differ"]), r["numeric_only"],
                 r["string_only"], top))
    print()
    print("  A record that differs only in string fields is a TRANSLATION.")
    print("  A record that differs in a numeric or structural field is not,")
    print("  and the two columns are apart for that reason.")
    for r in rows:
        for side, notes in (("A", r.get("notes_a")), ("B", r.get("notes_b"))):
            for n in notes or []:
                print("  NOTE %s %s: %s" % (side, r["name"], n))
    if args.expect_agreeing is not None and agreeing != args.expect_agreeing:
        sys.exit("jsondiff: --expect-agreeing %d but %d agree"
                 % (args.expect_agreeing, agreeing))
    return 0


def selftest():
    import tempfile
    checks, fails = [], 0

    def ck(name, ok, note=""):
        nonlocal fails
        checks.append((name, ok, note))
        if not ok:
            fails += 1

    doc_a = [None,
             {"id": 1, "name": "Potion", "price": 50},
             {"id": 2, "name": "Sword", "price": 100},
             {"id": 3, "name": "Extra", "price": 7}]
    doc_b = [None,
             {"id": 1, "name": "ポーション", "price": 50},
             {"id": 2, "name": "Sword", "price": 250}]

    with tempfile.TemporaryDirectory() as d:
        a, b = os.path.join(d, "A"), os.path.join(d, "B")
        os.makedirs(a)
        os.makedirs(b)
        for p, doc in ((a, doc_a), (b, doc_b)):
            with open(os.path.join(p, "Items.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(doc, fh, ensure_ascii=False)
        r = compare_file(os.path.join(a, "Items.json"),
                         os.path.join(b, "Items.json"))
        ck("the two record counts are read", (r["a"], r["b"]) == (3, 2))
        ck("the id present on one side only is found", r["only_a"] == [3])
        ck("and nothing is on the other side only", r["only_b"] == [])
        ck("the records in both are counted", r["both"] == 2)
        ck("both of them differ", len(r["differ"]) == 2)
        ck("THE SPLIT: one differs only in a string field", r["string_only"] == 1,
           "id 1, a translation")
        ck("and one differs only in a numeric field", r["numeric_only"] == 1,
           "id 2, price 100 against 250")
        ck("the differing fields are counted",
           dict(r["fields"]) == {"name": 1, "price": 1}, str(dict(r["fields"])))

        # the null-at-zero convention is checked, not assumed
        with open(os.path.join(a, "Bad.json"), "w", encoding="utf-8") as fh:
            json.dump([{"id": 0, "name": "x"}, {"id": 1, "name": "y"}], fh)
        with open(os.path.join(b, "Bad.json"), "w", encoding="utf-8") as fh:
            json.dump([None, {"id": 1, "name": "y"}], fh)
        r2 = compare_file(os.path.join(a, "Bad.json"),
                          os.path.join(b, "Bad.json"))
        ck("an array whose element 0 is not null is REPORTED",
           any("NOT null" in n for n in r2["notes_a"]), str(r2["notes_a"]))

        # an id that is not its index is reported and not joined on silently
        with open(os.path.join(a, "Sk.json"), "w", encoding="utf-8") as fh:
            json.dump([None, {"id": 9, "name": "x"}], fh)
        with open(os.path.join(b, "Sk.json"), "w", encoding="utf-8") as fh:
            json.dump([None, {"id": 1, "name": "x"}], fh)
        r3 = compare_file(os.path.join(a, "Sk.json"),
                          os.path.join(b, "Sk.json"))
        ck("an id that is not its index is REPORTED",
           any("not their index" in n for n in r3["notes_a"]),
           str(r3["notes_a"]))

        # concatenated JSON is refused with the reason, not guessed at
        with open(os.path.join(a, "Cat.json"), "wb") as fh:
            fh.write(b'{"id":1}{"id":2}')
        with open(os.path.join(b, "Cat.json"), "wb") as fh:
            fh.write(b'[null,{"id":1}]')
        r4 = compare_file(os.path.join(a, "Cat.json"),
                          os.path.join(b, "Cat.json"))
        ck("a file of concatenated JSON is REFUSED with its reason",
           "refused" in r4 and "Extra data" in r4["refused"],
           r4.get("refused", ""))

        # a record whose fields are a superset is reported as A only
        d1 = {"id": 1, "name": "x", "note": "n"}
        d2 = {"id": 1, "name": "x"}
        fd = field_diff(d1, d2)
        ck("a field present on one side only is labelled",
           fd == {"note": "A only"}, str(fd))
        ck("identical records produce an empty diff",
           field_diff(d1, dict(d1)) == {})

        # a root that is not a list
        with open(os.path.join(a, "Obj.json"), "w", encoding="utf-8") as fh:
            json.dump({"a": 1}, fh)
        with open(os.path.join(b, "Obj.json"), "w", encoding="utf-8") as fh:
            json.dump({"a": 1}, fh)
        r5 = compare_file(os.path.join(a, "Obj.json"),
                          os.path.join(b, "Obj.json"))
        ck("a document whose root is an object is REFUSED for this join",
           "refused" in r5)

        # two directories with no name in common refuse rather than report 0
        empty = os.path.join(d, "E")
        os.makedirs(empty)
        code = 0
        try:
            sys.argv = ["jsondiff.py", a, empty]
            main()
        except SystemExit as e:
            code = 1 if e.code else 0
        ck("no shared file name is a refusal and not a clean zero", code == 1)

    width = max(len(c[0]) for c in checks)
    for name, ok, note in checks:
        print("  %-*s  %s   %s" % (width, name, "ok  " if ok else "FAIL", note))
    print()
    print("%d checks, %d failures" % (len(checks), fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
