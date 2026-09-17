#!/usr/bin/env python3
"""gogplan.py -- read what a GOG offline installer would write, without
installing anything.

WHY THIS EXISTS
--------------------------------------------------------------------------
`inno56.py` opens the Inno Setup container and hands back 1,121 file entries.
On this object **not one of them names a game file.** GOG compiles its
installers so that every payload member is extracted under a
content-addressed temporary name:

    {tmp}/16/35\\1635942627ae7f0e39464608a71b36b3

Two hex digits, two more, then thirty-two -- the MD5 of the bytes stored in
the slice, fanned out over 256 x 256 directories. Reading the Inno layer and
stopping therefore gives a complete file list with **no file names in it**,
which is a different and much smaller result than it looks.

The real names are one layer up, in the Pascal Script callbacks Inno attaches
to each entry. GOG puts them in `BeforeInstall` and `AfterInstall`, and it
puts them in the wrong order, which is worth stating because a reader that
trusts the field names gets them backwards:

    BeforeInstall : after_install ('<md5>', <stored size>, <real size>)
    AfterInstall  : before_install('<md5>', '<the real relative path>', <n>)

The `<md5>` in both is the digest of the **installed** file, and it is not the
digest in the temporary name, which is the digest of the **stored** bytes.
Every member is a zlib stream, so those are two different things and both are
checkable.

WHAT THAT MAKES AVAILABLE
--------------------------------------------------------------------------
Four independent content descriptors over four different populations, which
is the largest number this collection has met on one object:

    #GOGCRCSTRING       1 MD5      the whole 2.89 GB slice
    Inno SHA1Sum        1,105      each member as stored
    the temporary name  911 MD5    each member as stored, again
    after_install(...)  757 MD5    each installed file, decompressed

and a complete installed tree -- names, directories, sizes -- derived from an
installer that was never run.

    python tools/gogplan.py plan    SETUP.EXE
    python tools/gogplan.py tree    SETUP.EXE
    python tools/gogplan.py extract SETUP.EXE --slice S-1.bin --out DIR
    python tools/gogplan.py verify  SETUP.EXE --slice S-1.bin
    python tools/gogplan.py selftest

`verify` checks all four descriptors and prints four rates with four
denominators, because they are four measurements and not one.
"""
import argparse
import collections
import hashlib
import os
import re
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import inno56

CALL_AFTER = re.compile(
    r"^after_install(_dependency)?\(\s*'([0-9a-fA-F]{32})'\s*,"
    r"\s*(\d+)\s*,\s*(\d+)\s*\)\s*$")
CALL_BEFORE = re.compile(
    r"^before_install(_dependency)?\(\s*'([0-9a-fA-F]{32})'\s*,"
    r"\s*'(.*)'\s*,\s*(-?\d+)\s*\)\s*$")
HEXSET = set("0123456789abcdef")
SEP = chr(92)


class PlanError(Exception):
    pass


def temp_digest(dest):
    """Return the 32-hex digest in a content-addressed temporary name, or
    None if the name is a real one."""
    p = dest.replace("/", SEP).split(SEP)
    if (len(p) == 4 and p[0] == "{tmp}" and len(p[1]) == 2 and len(p[2]) == 2
            and len(p[3]) == 32 and set(p[1] + p[2] + p[3]) <= HEXSET):
        return p[3]
    return None


def build_plan(o):
    """Turn Inno entries into installed-tree rows.

    A file larger than 10,485,760 bytes is split, and the split is visible in
    the callbacks rather than anywhere in the Inno records:

      * the FIRST part carries both callbacks, and its `before_install` gives
        the whole file's digest, its path, and the number of parts `n`;
      * the remaining n-1 parts carry only `after_install`, with their own
        part digest and part size, and an EMPTY AfterInstall;
      * the parts occupy consecutive location indices.

    That was derived here and it closes: 628 files with a path plus 129
    continuation parts is 757, which is exactly the number of entries whose
    Check is `check_if_install(...)`. A reader that treats every callback pair
    as one file loses the 129 and reports the wrong installed size.

    Refuses loudly rather than guessing: a callback that does not parse is
    counted and named, and a continuation part that arrives with no file open
    is an error."""
    files = []
    unparsed = []
    pending = None      # (row, parts_left)
    for e in o["entries"]:
        b, a = e["before"], e["after"]
        if not b and not a:
            continue
        mb = CALL_AFTER.match(b)
        if not mb:
            unparsed.append((e["dest"], b[:70], a[:70]))
            continue
        part = {"entry": e, "location": e["location"],
                "part_md5": mb.group(2).lower(),
                "stored_size": int(mb.group(3)),
                "part_size": int(mb.group(4)),
                "temp_md5": temp_digest(e["dest"])}
        if a:
            ma = CALL_BEFORE.match(a)
            if not ma:
                unparsed.append((e["dest"], b[:70], a[:70]))
                continue
            if pending is not None and pending[1] > 0:
                raise PlanError("a new file starts while %d parts of %r are "
                                "still outstanding"
                                % (pending[1], pending[0]["path"]))
            row = {"path": ma.group(3), "md5": ma.group(2).lower(),
                   "parts": [part], "n": int(ma.group(4)),
                   "dependency": bool(ma.group(1))}
            files.append(row)
            pending = (row, row["n"] - 1)
        else:
            if pending is None or pending[1] <= 0:
                raise PlanError("a continuation part at location %d belongs "
                                "to no open file" % e["location"])
            pending[0]["parts"].append(part)
            pending = (pending[0], pending[1] - 1)
    if pending is not None and pending[1] > 0:
        raise PlanError("%d parts of %r never arrived"
                        % (pending[1], pending[0]["path"]))
    for r in files:
        r["real_size"] = sum(p["part_size"] for p in r["parts"])
        r["stored_size"] = sum(p["stored_size"] for p in r["parts"])
        if len(r["parts"]) != r["n"]:
            raise PlanError("%r declares %d parts and got %d"
                            % (r["path"], r["n"], len(r["parts"])))
        # A one-part file's part digest and whole-file digest are the same
        # digest of the same bytes, so they must agree. They do on all 598
        # such rows of this object, and a disagreement means the two
        # callbacks have been paired with the wrong entry.
        if r["n"] == 1 and r["parts"][0]["part_md5"] != r["md5"]:
            raise PlanError("%r is one part but its two digests differ, "
                            "%s and %s"
                            % (r["path"], r["parts"][0]["part_md5"], r["md5"]))
    return files, unparsed


def _split(path):
    p = path.replace("/", SEP)
    parts = p.split(SEP)
    top = parts[0] if len(parts) > 1 else "(root)"
    base = parts[-1]
    ext = ("." + base.rsplit(".", 1)[1].lower()) if "." in base else "(none)"
    return top, ext


def cmd_plan(args):
    o = inno56.load(args.path)
    rows, unparsed = build_plan(o)
    locs = o["locations"]
    parts = sum(len(r["parts"]) for r in rows)
    print("file entries                : %d" % len(o["entries"]))
    print("entries with a callback     : %d" % (parts + len(unparsed)))
    print("callbacks NOT parsed        : %d" % len(unparsed))
    for d, b, a in unparsed[:10]:
        print("    %s | %s | %s" % (d[:40], b, a))
    print("installed files             : %d" % len(rows))
    print("   of which dependencies    : %d" % sum(1 for r in rows if r["dependency"]))
    print("   of which the game        : %d" % sum(1 for r in rows if not r["dependency"]))
    print("parts they are made of      : %d" % parts)
    print("files split into parts      : %d" % sum(1 for r in rows if r["n"] > 1))
    print("installed bytes             : %d" % sum(r["real_size"] for r in rows))
    print("   the game only            : %d"
          % sum(r["real_size"] for r in rows if not r["dependency"]))
    print("stored bytes (their members): %d"
          % sum(r["stored_size"] for r in rows))
    named = sum(1 for r in rows for p in r["parts"] if p["temp_md5"])
    print("parts that are content-addressed : %d" % named)
    bad = 0
    for r in rows:
        for p in r["parts"]:
            if (p["location"] >= 0
                    and locs[p["location"]]["original_size"] != p["stored_size"]):
                bad += 1
    print("parts whose declared stored size differs from the member : %d"
          % bad)
    tops = collections.Counter()
    topb = collections.Counter()
    exts = collections.Counter()
    extb = collections.Counter()
    for r in rows:
        t, x = _split(r["path"])
        tops[t] += 1
        topb[t] += r["real_size"]
        exts[x] += 1
        extb[x] += r["real_size"]
    total = sum(topb.values()) or 1
    print("=== by top-level directory ===")
    for k, n in tops.most_common(20):
        print("  %-40s %5d %13d  %7.3f%%"
              % (k, n, topb[k], 100.0 * topb[k] / total))
    print("=== by extension ===")
    for k, n in exts.most_common(20):
        print("  %-40s %5d %13d  %7.3f%%"
              % (k, n, extb[k], 100.0 * extb[k] / total))
    print("=== the ten largest ===")
    for r in sorted(rows, key=lambda r: -r["real_size"])[:10]:
        print("  %13d  %s" % (r["real_size"], r["path"]))


def cmd_tree(args):
    o = inno56.load(args.path)
    rows, _u = build_plan(o)
    for r in sorted(rows, key=lambda r: r["path"].lower()):
        print("%13d  %s  %2d  %s"
              % (r["real_size"], r["md5"], r["n"], r["path"]))


def _member_bytes(f, locs, part):
    body = inno56.read_member(f, locs[part["location"]])
    try:
        return body, zlib.decompress(body)
    except zlib.error:
        return body, None


def cmd_extract(args):
    o = inno56.load(args.path)
    rows, _u = build_plan(o)
    f, _h = inno56.open_slice(args.slice)
    locs = o["locations"]
    os.makedirs(args.out, exist_ok=True)
    n = 0
    total = 0
    for r in rows:
        if args.only and args.only.lower() not in r["path"].lower():
            continue
        dest = os.path.join(args.out, r["path"].replace("/", os.sep)
                            .replace(SEP, os.sep))
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as g:
            for p in r["parts"]:
                _body, data = _member_bytes(f, locs, p)
                if data is None:
                    data = _body
                g.write(data)
                total += len(data)
        n += 1
    f.close()
    print("files written : %d" % n)
    print("bytes written : %d" % total)


def cmd_verify(args):
    o = inno56.load(args.path)
    rows, _u = build_plan(o)
    locs = o["locations"]
    f, _h = inno56.open_slice(args.slice)

    sha_ok = sha_bad = 0
    sha_bad_names = []
    tmp_ok = tmp_bad = tmp_na = 0
    part_ok = part_bad = 0
    whole_ok = whole_bad = 0
    inner_total = 0
    zlib_ok = zlib_no = 0
    checked = 0
    limit = args.limit or len(rows)
    for r in rows[:limit]:
        whole = hashlib.md5()
        for p in r["parts"]:
            l = locs[p["location"]]
            body, data = _member_bytes(f, locs, p)
            checked += 1
            if hashlib.sha1(body).digest() == l["sha1"]:
                sha_ok += 1
            else:
                sha_bad += 1
                sha_bad_names.append((l["index"], r["path"],
                                      ",".join(inno56.flag_words(l["flags"]))))
            if p["temp_md5"]:
                if hashlib.md5(body).hexdigest() == p["temp_md5"]:
                    tmp_ok += 1
                else:
                    tmp_bad += 1
            else:
                tmp_na += 1
            if data is None:
                zlib_no += 1
                data = body
            else:
                zlib_ok += 1
            inner_total += len(data)
            if hashlib.md5(data).hexdigest() == p["part_md5"]:
                part_ok += 1
            else:
                part_bad += 1
            whole.update(data)
        if whole.hexdigest() == r["md5"]:
            whole_ok += 1
        else:
            whole_bad += 1
    f.close()
    print("files checked                      : %d" % min(limit, len(rows)))
    print("parts read                         : %d" % checked)
    print()
    print("descriptor 1 -- Inno SHA1Sum, over the stored member")
    print("    verified : %d of %d = %.4f %%"
          % (sha_ok, sha_ok + sha_bad,
             100.0 * sha_ok / max(1, sha_ok + sha_bad)))
    for i, name, fl in sha_bad_names[:20]:
        print("      %5d  %-52s %s" % (i, name[:52], fl))
    print()
    print("descriptor 2 -- the MD5 in the temporary name, over the same bytes")
    print("    verified : %d of %d = %.4f %%   (no such name: %d)"
          % (tmp_ok, tmp_ok + tmp_bad,
             100.0 * tmp_ok / max(1, tmp_ok + tmp_bad), tmp_na))
    print()
    print("descriptor 3 -- the MD5 in after_install(), over each PART")
    print("    verified : %d of %d = %.4f %%"
          % (part_ok, part_ok + part_bad,
             100.0 * part_ok / max(1, part_ok + part_bad)))
    print()
    print("descriptor 4 -- the MD5 in before_install(), over the WHOLE file")
    print("    verified : %d of %d = %.4f %%"
          % (whole_ok, whole_ok + whole_bad,
             100.0 * whole_ok / max(1, whole_ok + whole_bad)))
    print()
    print("parts that are a zlib stream       : %d" % zlib_ok)
    print("parts that are not                 : %d" % zlib_no)
    print("bytes after the inner decompression: %d" % inner_total)


def cmd_selftest(args):
    results = []

    def check(label, fn, must_fail):
        try:
            fn()
            results.append((label, not must_fail, "accepted"))
        except Exception as exc:
            results.append((label, must_fail, "REFUSED: %s" % str(exc)[:64]))

    good = {"before": "after_install('0123456789abcdef0123456789abcdef', 1, 2)",
            "after": ("before_install('0123456789abcdef0123456789abcdef', "
                      "'a" + SEP + "b.txt', 1)"),
            "dest": "{tmp}/01/23" + SEP + "0123456789abcdef0123456789abcdef",
            "location": 0}
    for k in ("source", "font", "assembly", "components", "tasks",
              "languages", "check"):
        good[k] = ""

    def one(entry):
        o = {"entries": [entry]}
        rows, un = build_plan(o)
        if un:
            raise PlanError("callback did not parse: %r" % (un[0],))
        return rows

    check("a well-formed pair of callbacks (must be accepted)",
          lambda: one(dict(good)), False)

    mism = dict(good)
    mism["after"] = ("before_install('ffffffffffffffffffffffffffffffff', "
                     "'a.txt', 1)")
    check("a one-part file whose two digests differ",
          lambda: one(mism), True)

    orphan = dict(good)
    orphan["after"] = ""
    check("a continuation part with no file open",
          lambda: one(orphan), True)

    short = dict(good)
    short["after"] = ("before_install('0123456789abcdef0123456789abcdef', "
                      "'a.txt', 3)")
    check("a file that declares 3 parts and gets 1",
          lambda: one(short), True)

    trunc = dict(good)
    trunc["before"] = "after_install('0123', 1, 2)"
    check("a digest that is not 32 hex characters",
          lambda: one(trunc), True)

    empty = dict(good)
    empty["after"] = "something_else('x')"
    check("a callback this reader does not know",
          lambda: one(empty), True)

    check("a temporary name that is not content-addressed",
          lambda: (_ for _ in ()).throw(PlanError("not content-addressed"))
          if temp_digest("{app}" + SEP + "gog.ico") is None else None, True)
    check("a temporary name that is (must be accepted)",
          lambda: (_ for _ in ()).throw(PlanError("unexpected"))
          if temp_digest(good["dest"]) is None else None, False)

    for label, ok, note in results:
        print("  [%s] %-48s -> %s" % ("ok" if ok else "FAIL", label, note))
    failed = sum(1 for _l, ok, _n in results if not ok)
    print("%d specimens, %d failed" % (len(results), failed))
    if failed:
        sys.exit(3)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    for name in ("plan", "tree"):
        p = sub.add_parser(name)
        p.add_argument("path")
    for name in ("extract", "verify"):
        p = sub.add_parser(name)
        p.add_argument("path")
        p.add_argument("--slice", required=True)
        if name == "extract":
            p.add_argument("--out", required=True)
            p.add_argument("--only")
        else:
            p.add_argument("--limit", type=int)
    sub.add_parser("selftest")
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        sys.exit(2)
    {"plan": cmd_plan, "tree": cmd_tree, "extract": cmd_extract,
     "verify": cmd_verify, "selftest": cmd_selftest}[args.cmd](args)


if __name__ == "__main__":
    main()
