#!/usr/bin/env python3
"""aifcensus.py -- ARM Image Format, every executable on a 3DO disc.

The first disc of this collection derived the header from its bytes; this
tool applies it and re-checks every claim on a second disc rather than
inheriting any of them.

    0x00  BL decompress_code   or NOP (0xE1A00000)
    0x04  BL relocation_code   or NOP
    0x08  BL zero_init_code    or NOP
    0x0C  BL entry_point
    0x10  SWI &11              0xEF000011   <- the signature
    0x14  u32 read-only size
    0x18  u32 read-write size
    0x1C  u32 debug size
    0x20  u32 zero-init size
    0x24  u32 debug type
    0x28  u32 image base
    0x2C  u32 work space
    0x30  u32 address mode and flags
    0x34  u32 data base

Big-endian throughout. A `BL` is 0xEB followed by a 24-bit signed word
displacement; the target is `8 + 4 * disp` from the branch.

Two derived checks are printed per image and neither is assumed:

  * the entry point, decoded from the BL at 0x0C;
  * the relocation target, decoded from the BL at 0x04, against
    read-only + read-write + debug size.

CORRECTED ON THE THIRD DISC, TWICE.

**The relocation target is `ro + rw + debug`, not `ro + rw`.** The first two
discs shipped `debug size` 0 on 127 images of 127, so the two expressions were
the same number and the wrong one got written down. The third disc has two
images with debug areas and they land on `ro + rw + debug` to the byte, which
makes the identity 37 of 37 here and 164 of 164 across three discs.

**Compression is not decided by the size relation.** This tool used to call an
image compressed when offset 0 held a BL, and then print `(ro+rw)/size` as
the expansion ratio as if it were a confirmation. On the third disc that ratio
is BELOW 1 on eleven images of the twenty with a BL, which no decompressor can
do. The ratio is wrong, not the BL: `ro + rw + debug` is not the whole
decompressed image, because the relocation table is compressed with it and is
not counted in any header field.

So compression is decided by two structural tests that do not use sizes at all,
and both are printed:

  * **the appended routine.** A compressed image carries, past its relocation
    data, the decompressor the BL at offset 0 branches to. Its length is 392,
    456 or 464 bytes on the third disc, on 20 images of 20; images with a NOP
    at offset 0 have no such tail, 17 of 17.
  * **the body does not look like ARM code.** 32-bit ARM code is overwhelmingly
    unconditional, so the top nibble of the first byte of each word is 0xE far
    more often than chance. Over the body, uncompressed images run 0.53 to 0.77
    and compressed ones 0.08 to 0.18, with Shannon entropy 5.27..6.04 against
    6.80..7.20. Two statistics, two populations, no overlap, 37 of 37.

usage:
    aifcensus.py TREE            every AIF image under a tree
    aifcensus.py validate        negative controls; must fail
"""
import math
import os
import struct
import sys

NOP = 0xE1A00000


class Bad(Exception):
    pass


def bl_target(word, at):
    """Decode a BL at address `at`. Returns None if it is not a BL."""
    if (word >> 24) != 0xEB:
        return None
    disp = word & 0x00FFFFFF
    if disp & 0x800000:
        disp -= 0x1000000
    return at + 8 + 4 * disp


def entropy(b):
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = float(len(b))
    return -sum((c / n) * math.log(c / n, 2) for c in counts if c)


def always_share(b):
    """Share of 32-bit words whose top nibble is 0xE, the ARM 'always' condition.

    Compiled ARM code is mostly unconditional, so this runs high; compressed
    bytes have no reason to prefer any nibble and it falls towards 1/16.
    """
    n = len(b) // 4
    if n == 0:
        return 0.0
    return float(sum(1 for i in range(n) if (b[4 * i] >> 4) == 0xE)) / n


def parse(d):
    if len(d) < 0x38:
        raise Bad("%d bytes is too short for a 0x38-byte AIF header" % len(d))
    w = struct.unpack(">14I", d[0:56])
    if w[4] != 0xEF000011:
        raise Bad("word at 0x10 is %08x, not the SWI &11 signature" % w[4])
    ro, rw, dbg, zi, dbgtype, base, work, flags, database = w[5:14]
    return {
        "size": len(d),
        "decompress": w[0], "reloc": w[1], "zeroinit": w[2], "entry_bl": w[3],
        "ro": ro, "rw": rw, "debug": dbg, "zi": zi,
        "dbgtype": dbgtype, "base": base, "work": work,
        "flags": flags, "database": database,
        "entry": bl_target(w[3], 0x0C),
        "reloc_target": bl_target(w[1], 0x04),
        "stub_at": bl_target(w[0], 0x00),
        "stub_len": (len(d) - bl_target(w[0], 0x00)
                     if bl_target(w[0], 0x00) is not None
                     and 0 < bl_target(w[0], 0x00) <= len(d) else 0),
        "H": entropy(d[0x40:bl_target(w[0], 0x00)]
                     if bl_target(w[0], 0x00) is not None else d[0x40:]),
        "condE": always_share(d[0x40:bl_target(w[0], 0x00)]
                              if bl_target(w[0], 0x00) is not None else d[0x40:]),
        "compressed": (w[0] != NOP),
    }


def validate():
    ok = True
    cases = [
        ("2,048 zero bytes", b"\0" * 2048),
        ("the string iamaduck", b"iamaduck" * 256),
        ("a CCB cel file", b"CCB \x00\x00\x00\x50" + b"\0" * 200),
        ("an AIF header 40 bytes long", b"\xe1\xa0\x00\x00" * 10),
        ("an AIF with the wrong SWI",
         b"\xe1\xa0\x00\x00" * 4 + b"\xef\x00\x00\x12" + b"\0" * 64),
    ]
    for name, data in cases:
        try:
            parse(data)
            print("FAIL: %-38s was ACCEPTED as an AIF image" % name)
            ok = False
        except Bad as e:
            print("ok  : %-38s rejected -- %s" % (name, e))
    good = (struct.pack(">4I", NOP, NOP, NOP, 0xEB00003B)
            + struct.pack(">I", 0xEF000011) + struct.pack(">9I", 0x1000, 0x200,
                                                          0, 0, 0, 0, 0, 32, 0)
            + b"\0" * 8)
    try:
        a = parse(good)
        assert a["entry"] == 0x100, a["entry"]
        assert not a["compressed"]
        print("ok  : %-38s accepted, entry 0x%x" % ("positive control", a["entry"]))
    except (Bad, AssertionError) as e:
        print("FAIL: positive control rejected -- %s" % e)
        ok = False
    return 0 if ok else 1


def main():
    if len(sys.argv) != 2:
        sys.stderr.write(__doc__)
        raise SystemExit(2)
    if sys.argv[1] == "validate":
        raise SystemExit(validate())
    tree = sys.argv[1]

    rows = []
    for dp, dn, fn in os.walk(tree):
        for f in sorted(fn):
            p = os.path.join(dp, f)
            d = open(p, "rb").read()
            try:
                a = parse(d)
            except Bad:
                continue
            a["path"] = "/" + os.path.relpath(p, tree).replace(os.sep, "/")
            rows.append(a)
    rows.sort(key=lambda r: r["path"])

    print("%-40s %8s %8s %8s %6s %6s %5s %5s %6s %6s"
          % ("path", "size", "ro", "rw", "debug", "entry", "flags", "comp",
             "H", "cond=E"))
    for a in rows:
        print("%-40s %8d %8d %8d %6d  0x%03x %6d %5s %6.3f %6.3f"
              % (a["path"], a["size"], a["ro"], a["rw"], a["debug"],
                 a["entry"] or 0, a["flags"], "yes" if a["compressed"] else "",
                 a["H"], a["condE"]))

    n = len(rows)
    print()
    print("AIF images                          : %d" % n)
    print("SWI &11 at 0x10                     : %d of %d" % (n, n))
    print("entry point 0x100                   : %d of %d"
          % (sum(1 for a in rows if a["entry"] == 0x100), n))
    print("flags at 0x30 == 32                 : %d of %d"
          % (sum(1 for a in rows if a["flags"] == 32), n))
    print("image base == 0                     : %d of %d"
          % (sum(1 for a in rows if a["base"] == 0), n))
    print("debug size == 0                     : %d of %d"
          % (sum(1 for a in rows if a["debug"] == 0), n))
    eq = sum(1 for a in rows if a["reloc_target"] == a["ro"] + a["rw"])
    p4 = sum(1 for a in rows if a["reloc_target"] == a["ro"] + a["rw"] + 4)
    eqd = sum(1 for a in rows if a["reloc_target"]
              == a["ro"] + a["rw"] + a["debug"])
    print("reloc target == ro + rw             : %d of %d" % (eq, n))
    print("reloc target == ro + rw + 4         : %d of %d" % (p4, n))
    print("reloc target == ro + rw + debug     : %d of %d   <- the identity" % (eqd, n))
    print("neither of the three                : %d of %d"
          % (sum(1 for a in rows
                 if a["reloc_target"] not in (a["ro"] + a["rw"],
                                              a["ro"] + a["rw"] + 4,
                                              a["ro"] + a["rw"] + a["debug"])), n))
    comp = [a for a in rows if a["compressed"]]
    unc = [a for a in rows if not a["compressed"]]
    print()
    print("compressed images                   : %d of %d" % (len(comp), n))
    print("  decided by the appended routine and the body statistics, NOT by size")
    print("  %-34s %8s %6s %6s %6s %9s"
          % ("path", "stored", "stub", "H", "cond=E", "decl/size"))
    for a in comp:
        decl = a["ro"] + a["rw"] + a["debug"]
        print("  %-34s %8d %6d %6.3f %6.3f %9.4f%s"
              % (a["path"], a["size"], a["stub_len"], a["H"], a["condE"],
                 float(decl) / a["size"],
                 "  <- ratio below 1" if decl < a["size"] else ""))
    print()
    print("  stub lengths seen                 : %s"
          % ", ".join("%d (x%d)" % (L, sum(1 for a in comp if a["stub_len"] == L))
                      for L in sorted(set(a["stub_len"] for a in comp))))
    print("  images with a stub                : %d of %d compressed"
          % (sum(1 for a in comp if a["stub_len"]), len(comp)))
    print("  images with a stub, uncompressed  : %d of %d   (must be 0)"
          % (sum(1 for a in unc if a["stub_len"]), len(unc)))
    if comp and unc:
        print("  H         compressed %.4f..%.4f   uncompressed %.4f..%.4f"
              % (min(a["H"] for a in comp), max(a["H"] for a in comp),
                 min(a["H"] for a in unc), max(a["H"] for a in unc)))
        print("  cond=E    compressed %.4f..%.4f   uncompressed %.4f..%.4f"
              % (min(a["condE"] for a in comp), max(a["condE"] for a in comp),
                 min(a["condE"] for a in unc), max(a["condE"] for a in unc)))
        sep = (min(a["H"] for a in comp) > max(a["H"] for a in unc)
               and min(a["condE"] for a in unc) > max(a["condE"] for a in comp))
        print("  the two populations are disjoint on both statistics: %s" % sep)
        print("  the size relation agrees with them on %d of %d"
              % (sum(1 for a in comp
                     if a["ro"] + a["rw"] + a["debug"] > a["size"]), len(comp)))
    bysub = {}
    for a in rows:
        top = a["path"].split("/")[1] if a["path"].count("/") > 1 else "(root)"
        bysub[top] = bysub.get(top, 0) + 1
    print()
    print("by directory:")
    for k in sorted(bysub):
        print("  %-12s %3d" % (k, bysub[k]))
    # the system directory is spelled `System` on the first two discs and
    # `system` on the third, so this must fold case or it silently answers
    # "all of them".
    outside = sum(v for k, v in bysub.items() if k.lower() != "system")
    print("  outside the system directory: %d of %d" % (outside, n))
    comp_out = sum(1 for a in comp
                   if a["path"].split("/")[1].lower() != "system"
                   or a["path"].count("/") <= 1)
    print("  compressed outside it        : %d of %d" % (comp_out, len(comp)))


if __name__ == "__main__":
    main()
