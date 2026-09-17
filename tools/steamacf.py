#!/usr/bin/env python3
"""steamacf.py -- read a Steam application manifest and redact the one field
that identifies a person.

WHY THIS FILE EXISTS
--------------------
Four objects in a row this collection read a `goggame-galaxyFileList.ini`
sitting inside the game's own directory. Steam does not work that way: the
bookkeeping is an `.acf` one level above the game folder, in Valve's
**KeyValues** text format, which is public and is used here as such.

The manifest can be published in full but for one field. `"LastOwner"` is a
**SteamID64**: seventeen digits that identify one Steam account and, through
it, one person. `pc-motoracer-doc/docs/11` settled the rule as *redact what
identifies a machine or a person, publish what identifies a setting*, and a
SteamID64 is the first thing this collection has met that identifies a person
directly rather than by inference.

The redaction is done **by this program and never by hand**, exactly as
`goglog.py` redacts an installation path, so that no document in this
repository ever holds the original and the shape stays checkable: the output
says how many digits were removed and what the account universe and type
nibbles were, which are properties of the ID format and not of the person.

`"LauncherPath"` is a fixed system location -- the same string on every
Windows that installed Steam in the default place -- and by the same rule it
is published.

    python tools/steamacf.py --selftest
    python tools/steamacf.py --path "<library>/steamapps/appmanifest_317940.acf"
    python tools/steamacf.py --path ... --tree
"""
import argparse
import os
import re
import sys

REDACT = {"lastowner"}
TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|([{}])')


class NotKeyValues(Exception):
    pass


def parse(text):
    """Valve KeyValues: quoted strings, braces, nothing else that matters.

    Returns a list of (path, key, value) in file order, plus the tree.
    """
    toks = []
    for m in TOKEN.finditer(text):
        toks.append(m.group(1) if m.group(2) is None else m.group(2))
    i = 0
    n = len(toks)

    def block(depth):
        nonlocal i
        out = []
        while i < n:
            t = toks[i]
            if t == "}":
                if depth == 0:
                    raise NotKeyValues("a closing brace at the top level")
                i += 1
                return out
            if t == "{":
                raise NotKeyValues("a block opened where a key was expected")
            key = t
            i += 1
            if i >= n:
                raise NotKeyValues("key %r has no value" % key)
            if toks[i] == "{":
                i += 1
                if depth > 32:
                    raise NotKeyValues("nesting deeper than 32")
                out.append((key, block(depth + 1)))
            elif toks[i] == "}":
                raise NotKeyValues("key %r has no value" % key)
            else:
                out.append((key, toks[i]))
                i += 1
        if depth != 0:
            raise NotKeyValues("a block was never closed")
        return out

    if n == 0:
        raise NotKeyValues("no tokens at all")
    root = block(0)
    if i != n:
        raise NotKeyValues("%d tokens left over after the root block"
                           % (n - i))
    return root


def redact_steamid(value):
    """Replace a SteamID64 with a token, and say what was there in terms of
    the ID FORMAT rather than of the account."""
    if not value.isdigit() or len(value) != 17:
        return "<REDACTED>", "not a 17-digit decimal"
    v = int(value)
    universe = v >> 56
    account_type = (v >> 52) & 0xF
    instance = (v >> 32) & 0xFFFFF
    return ("<STEAMID64:%d digits redacted>" % len(value),
            "universe %d, account type %d, instance %d -- the individual "
            "account number is what was removed" % (universe, account_type,
                                                    instance))


def flat(node, prefix=""):
    for k, v in node:
        if isinstance(v, list):
            for x in flat(v, prefix + k + "/"):
                yield x
        else:
            yield prefix, k, v


def cmd_show(args):
    text = open(args.path, encoding="utf-8", errors="replace").read()
    size = os.path.getsize(args.path)
    root = parse(text)
    print("manifest      : %s" % os.path.basename(args.path))
    print("bytes         : %d" % size)
    print("top-level key : %s" % ", ".join(k for k, _v in root))
    print()
    note = None
    keys = 0
    redacted = 0
    for prefix, k, v in flat(root):
        keys += 1
        if k.lower() in REDACT:
            v, note = redact_steamid(v)
            redacted += 1
        print('   %-28s "%s"' % ('"%s%s"' % (prefix, k), v))
    print()
    print("keys printed  : %d" % keys)
    print("keys redacted : %d   (the rule: redact what identifies a person)"
          % redacted)
    if note:
        print("what the redacted value was, as a matter of ID format:")
        print("   %s" % note)
    return 0


def cmd_check(args):
    """The two closures the manifest offers, against a tree on disk."""
    text = open(args.path, encoding="utf-8", errors="replace").read()
    root = parse(text)
    kv = {k: v for _p, k, v in flat(root) if not isinstance(v, list)}
    depots = []
    for k, v in root[0][1] if root and isinstance(root[0][1], list) else []:
        pass
    # walk for InstalledDepots
    def find(node, want):
        for k, v in node:
            if k == want and isinstance(v, list):
                return v
            if isinstance(v, list):
                r = find(v, want)
                if r is not None:
                    return r
        return None
    idep = find(root, "InstalledDepots") or []
    for did, body in idep:
        d = dict((k, v) for k, v in body if not isinstance(v, list))
        depots.append((did, int(d.get("size", "0")), d.get("manifest", "")))
    size_on_disk = int(kv.get("SizeOnDisk", "0"))
    counted = 0
    files = 0
    for r, _dirs, fs in os.walk(args.root):
        for f in fs:
            counted += os.path.getsize(os.path.join(r, f))
            files += 1
    print("SizeOnDisk declared      : %d" % size_on_disk)
    print("the tree, counted        : %d over %d files" % (counted, files))
    print("residue                  : %d" % (size_on_disk - counted))
    print()
    print("installed depots:")
    for did, sz, man in depots:
        print("   %-10s %14d   manifest %s" % (did, sz, man))
    print("   sum      %14d" % sum(d[1] for d in depots))
    print("   residue against SizeOnDisk : %d"
          % (size_on_disk - sum(d[1] for d in depots)))
    print()
    # the soundtrack branch
    ost = os.path.join(args.root, "Original Soundtrack")
    if os.path.isdir(ost):
        b = 0
        n = 0
        for r, _d, fs in os.walk(ost):
            for f in fs:
                b += os.path.getsize(os.path.join(r, f))
                n += 1
        print("the 'Original Soundtrack' branch, counted : %d over %d files"
              % (b, n))
        for did, sz, _m in depots:
            if sz == b:
                print("   depot %s declares exactly that number" % did)
    print()
    print("WHAT THIS BUYS, AND IT IS LESS THAN IT LOOKS")
    print("A total that closes to the byte says the tree WEIGHS what Steam")
    print("thinks it weighs. It says nothing about any individual file: one")
    print("byte changed anywhere leaves SizeOnDisk untouched, and so does any")
    print("pair of edits that cancel. It is not a checksum and must not be")
    print("reported as one.")
    return 0


def selftest():
    cases = []
    good = '"AppState"\n{\n\t"appid"\t\t"317940"\n\t"InstalledDepots"\n\t{\n\t\t"317942"\n\t\t{\n\t\t\t"size"\t"10"\n\t\t}\n\t}\n}\n'
    try:
        r = parse(good)
        cases.append(("a two-level manifest",
                      r[0][0] == "AppState" and len(list(flat(r))) == 2))
    except NotKeyValues:
        cases.append(("a two-level manifest", False))

    for name, text in (("an unclosed block", '"A"\n{\n"k" "v"\n'),
                       ("a key with no value", '"A"\n{\n"k"\n}\n'),
                       ("a stray closing brace", '"A"\n{\n"k" "v"\n}\n}\n'),
                       ("nothing at all", "")):
        try:
            parse(text)
            cases.append((name, False))
        except NotKeyValues:
            cases.append((name, True))

    tok, note = redact_steamid("76561198000000000")
    cases.append(("a SteamID64 is replaced and its digits counted",
                  "76561198" not in tok and "17 digits" in tok
                  and "universe 1" in note))
    tok, _n = redact_steamid("12345")
    cases.append(("a short value is still redacted", tok == "<REDACTED>"))

    # a value that merely looks like an id must NOT leak through the printer
    text = '"AppState"\n{\n\t"LastOwner"\t"76561197960287930"\n}\n'
    r = parse(text)
    leaked = False
    for _p, k, v in flat(r):
        if k.lower() in REDACT:
            v, _ = redact_steamid(v)
        if "76561197960287930" in v:
            leaked = True
    cases.append(("the printer cannot emit the original", not leaked))

    ok = sum(1 for _n, v in cases if v)
    print("steamacf selftest: %d specimens built in memory" % len(cases))
    for n, v in cases:
        print("  %-52s %s" % (n, "PASS" if v else "FAIL"))
    print()
    print("%d of %d specimens behaved as required" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path")
    ap.add_argument("--root", default="karmaflow-steam")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.path:
        ap.print_help()
        return 0
    if a.check:
        return cmd_check(a)
    return cmd_show(a)


if __name__ == "__main__":
    sys.exit(main())
