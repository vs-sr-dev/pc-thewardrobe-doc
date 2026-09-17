#!/usr/bin/env python3
"""uuidscan.py -- find version-1 UUIDs in a tree, decode the clock they carry,
and redact the node field by program.

WHY A TOOL AND NOT A GREP
-------------------------
A version-1 UUID is two things at once and they have to be treated
differently:

  * **a clock.** Sixty bits of hundred-nanosecond ticks since 1582-10-15 UTC.
    That is an authoring date, in a file whose filesystem dates were destroyed
    by the delivery mechanism, and it is exactly the kind of artefact this
    collection exists to publish;
  * **a machine.** Forty-eight bits in the position RFC 4122 fills with the
    generating interface's MAC address. That is not a date and it is not
    credit. It identifies one device belonging to one person who did not
    choose to write it down.

`pc-rpgmaker2000-doc/docs/10` states the rule as *publish what claims credit
and redact what routes a message*, with the amendment that where it cannot be
established that an identifier has stopped identifying, it redacts. A MAC
address does not route a message and it is not credit either; it is a device
fingerprint a stranger can use to link one person's files across the internet.
**This tool therefore publishes the timestamp and the version, counts the
distinct nodes, and never prints a node.** The distinct-node count is the
finding -- "these seventeen identifiers were generated on two machines" is a
statement about the artefact; the twelve hex digits are not.

The redaction is by program, so a document that quotes this tool's output
cannot leak what the tool removed.

    python tools/uuidscan.py <root>
    python tools/uuidscan.py <root> --expect 17
    python tools/uuidscan.py --selftest
"""
import argparse
import datetime
import hashlib
import os
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

UUID = re.compile(rb"([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-"
                  rb"([0-9a-fA-F]{4})-([0-9a-fA-F]{12})")
GREGORIAN = datetime.datetime(1582, 10, 15, tzinfo=datetime.timezone.utc)
# A version-1 timestamp outside this window is not a date somebody made a file
# on, and reporting it as one would be the same mistake as reading 0x00200000
# as 1970.
EARLIEST = datetime.datetime(1990, 1, 1, tzinfo=datetime.timezone.utc)
LATEST = datetime.datetime(2100, 1, 1, tzinfo=datetime.timezone.utc)


def decode(lo, mid, hi_ver, seq, node):
    ver = (int(hi_ver, 16) >> 12) & 0xF
    ticks = (((int(hi_ver, 16) & 0x0FFF) << 48) | (int(mid, 16) << 32) |
             int(lo, 16))
    try:
        when = GREGORIAN + datetime.timedelta(microseconds=ticks / 10)
    except (OverflowError, ValueError):
        when = None
    plausible = bool(when and EARLIEST <= when <= LATEST)
    return {"version": ver, "ticks": ticks, "when": when,
            "plausible": plausible, "seq": seq.lower(),
            "node_id": hashlib.sha1(node.lower().encode()).hexdigest()[:8]}


def scan(root):
    rows = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            path = os.path.join(dp, f)
            try:
                blob = open(path, "rb").read()
            except OSError:
                continue
            for m in UUID.finditer(blob):
                parts = [g.decode("ascii") for g in m.groups()]
                d = decode(*parts)
                if d["version"] != 1:
                    continue
                d["path"] = os.path.relpath(path, root).replace(os.sep, "/")
                d["at"] = m.start()
                rows.append(d)
    return rows


def run(args):
    rows = scan(args.root)
    if not rows:
        print("version-1 UUIDs : 0")
        if args.expect:
            raise SystemExit("FATAL: --expect %d, got 0" % args.expect)
        return 0
    print("version-1 UUIDs : %d in %d file(s)"
          % (len(rows), len({r["path"] for r in rows})))
    print()
    print("  %-42s %8s  %-30s %s"
          % ("file", "at", "the clock it carries (UTC)", "machine"))
    for r in sorted(rows, key=lambda r: (r["path"], r["at"])):
        when = (r["when"].strftime("%Y-%m-%d %H:%M:%S.%f")
                if r["plausible"] else "(not a plausible date)")
        # Truncate the MIDDLE, never the front. A column that eats the first
        # characters of a path prints "mple/ArcheiaPictureTutorial/..." and
        # loses which directory the file is in; one that eats the last
        # characters loses which file it is. Both ends are load-bearing.
        p = r["path"]
        if len(p) > 42:
            p = p[:16] + "..." + p[-23:]
        print("  %-42s %8d  %-30s %s"
              % (p, r["at"], when, "M%s" % r["node_id"][:4]))
    print()
    nodes = {r["node_id"] for r in rows}
    plaus = [r for r in rows if r["plausible"]]
    print("  distinct node fields : %d" % len(nodes))
    print("  (the node field is the position RFC 4122 fills with the")
    print("   generating machine's MAC address. It is NOT printed. The")
    print("   label M#### above is a hash of it, so that two identifiers")
    print("   from one machine can be seen to be from one machine without")
    print("   the machine being named.)")
    print()
    print("  carrying a plausible date : %d of %d" % (len(plaus), len(rows)))
    if plaus:
        first = min(r["when"] for r in plaus)
        last = max(r["when"] for r in plaus)
        print("  earliest : %s UTC" % first.strftime("%Y-%m-%d %H:%M:%S.%f"))
        print("  latest   : %s UTC" % last.strftime("%Y-%m-%d %H:%M:%S.%f"))
    if args.expect is not None and len(rows) != args.expect:
        raise SystemExit("FATAL: --expect %d, got %d" % (args.expect,
                                                         len(rows)))
    return 0


def selftest():
    checks = []

    def check(name, got, want):
        checks.append((name, got == want, got, want))

    d = decode("e288fa52", "a3fc", "11e7", "880e", "9cd150758198")
    check("version 1 is read", d["version"], 1)
    check("the clock decodes",
          d["when"].strftime("%Y-%m-%d %H:%M:%S"), "2017-09-28 03:26:58")
    check("the date is plausible", d["plausible"], True)
    check("the node is not returned in the clear",
          "9cd150758198" in repr(d), False)
    check("the node label is stable",
          decode("e288fa52", "a3fc", "11e7", "880e",
                 "9CD150758198")["node_id"], d["node_id"])
    check("two nodes give two labels",
          decode("e288fa52", "a3fc", "11e7", "880e",
                 "e4bedc1a55ee")["node_id"] != d["node_id"], True)

    d4 = decode("00000000", "0000", "4000", "0000", "000000000000")
    check("a version-4 UUID is reported as version 4", d4["version"], 4)

    d0 = decode("00000000", "0000", "1000", "0000", "000000000000")
    check("a zero timestamp is not a plausible date", d0["plausible"], False)

    # the regular expression must not match a shorter or longer run
    check("a 12-digit node is required",
          UUID.search(b"e288fa52-a3fc-11e7-880e-9cd15075819") is None, True)
    check("a real UUID matches",
          UUID.search(b"e288fa52-a3fc-11e7-880e-9cd150758198") is not None,
          True)
    check("uppercase matches too",
          UUID.search(b"E288FA52-A3FC-11E7-880E-9CD150758198") is not None,
          True)

    import shutil
    import tempfile
    tmp = tempfile.mkdtemp(prefix="uuidscan-")
    try:
        open(os.path.join(tmp, "a.bin"), "wb").write(
            b"xx e288fa52-a3fc-11e7-880e-9cd150758198 yy")
        open(os.path.join(tmp, "b.bin"), "wb").write(
            b"a version 4: 12345678-1234-4234-8234-123456789abc")
        rows = scan(tmp)
        check("one version-1 UUID found in the tree", len(rows), 1)
        check("the version-4 one is skipped", rows[0]["path"], "a.bin")
        check("its offset is reported", rows[0]["at"], 3)
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
    ap.add_argument("root", nargs="?")
    ap.add_argument("--expect", type=int)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest or args.root == "selftest":
        return selftest()
    if not args.root:
        raise SystemExit("uuidscan: a root is required (or --selftest)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
