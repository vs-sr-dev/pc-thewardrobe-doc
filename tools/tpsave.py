#!/usr/bin/env python3
"""tpsave.py -- read a Theme Park save: the `.GD`, the `.G0` and the `.GY`.

The program names its own save files, in the `LE` image of `GAME/MAIN.EXE`:

    %ssave/%s.gy     %ssave/%s.g%d     %ssave/%s.GD     %ssave/DEMO.GY

So there are three kinds and the middle one is a numbered slot -- the game's
own menu offers `GAME 00` .. `GAME 07`, and this object only ever used slot 0.

**`.GD`, 141 bytes, fully derived:**

    +0    char[32]  the player's name
    +32   char[32]  the save's name, which is also the file's name
    +64   char[32]  a third name, present on one save of five
    +96   u8 x 4    four small fields
    +100  36 zero bytes
    +136  u32       200000 -- and it is 200000 on 5 of 5 saves, so it is a
                    constant of the game and not a fact about the park

**`.G0` and `.GY`, both exactly 304,668 bytes**, 14 of 14. The first 40 bytes
carry five `u32` counters, and the file carries the game's whole ride
catalogue at a fixed offset:

    +6    u32   100000  -- the same on 13 of 13 saves
    +10   u32   varies, and varies between two saves seven seconds apart
    +14   u32   varies, zero on eight of thirteen
    +18   u32   zero on ten of thirteen, else a round 50,000 or 100,000
    +22   u32   varies -- and on a park that has just been created it is
                exactly 200000

    +293578  29 x 200 bytes, each beginning with a NUL-terminated ride name,
             in the ride-index order that `RIDEANI.NNN` uses

What is NOT derived: the 200-byte ride record past its name, the park map,
and the guest array. Those are named in [17](../docs/17-leftovers.md).

    python tools/tpsave.py census <root>
    python tools/tpsave.py gd     <file.GD>
    python tools/tpsave.py header <file.GY|.G0>
    python tools/tpsave.py rides  <file.GY|.G0>
    python tools/tpsave.py diff   <a> <b>
    python tools/tpsave.py selftest
"""
import os
import struct
import sys

SAVE_SIZE = 304668
GD_SIZE = 141
RIDE_BASE = 293578
RIDE_STRIDE = 200
RIDE_COUNT = 29


class Refused(Exception):
    pass


def read_gd(d):
    if len(d) != GD_SIZE:
        raise Refused("a .GD is %d bytes, this is %d" % (GD_SIZE, len(d)))
    def s(o):
        return d[o:o + 32].split(b"\0")[0].decode("latin-1")
    return {"player": s(0), "save": s(32), "third": s(64),
            "f96": list(d[96:100]),
            "zeros": d[100:136] == b"\0" * 36,
            "u136": struct.unpack_from("<I", d, 136)[0]}


def read_save(d):
    if len(d) != SAVE_SIZE:
        raise Refused("a .GY/.G0 is %d bytes, this is %d" % (SAVE_SIZE, len(d)))
    if struct.unpack_from("<I", d, 0)[0] != 1:
        raise Refused("the first u32 is %d, not 1"
                      % struct.unpack_from("<I", d, 0)[0])
    return {"u0": struct.unpack_from("<I", d, 0)[0],
            "u6": struct.unpack_from("<I", d, 6)[0],
            "u10": struct.unpack_from("<I", d, 10)[0],
            "u14": struct.unpack_from("<I", d, 14)[0],
            "u18": struct.unpack_from("<I", d, 18)[0],
            "u22": struct.unpack_from("<I", d, 22)[0],
            "nonzero": sum(1 for b in d if b)}


def rides(d):
    out = []
    for i in range(RIDE_COUNT):
        o = RIDE_BASE + RIDE_STRIDE * i
        name = d[o:o + 20].split(b"\0")[0].decode("latin-1").strip()
        out.append((i, o, name, d[o + 20:o + RIDE_STRIDE]))
    return out


def cmd_census(root):
    print("%-46s %8s %9s %9s %9s %9s %9s %8s"
          % ("file", "bytes", "u6", "u10", "u14", "u18", "u22", "non-zero"))
    n = ok = 0
    for base, _, names in os.walk(root):
        for f in sorted(names):
            if not f.upper().endswith((".GY", ".G0")):
                continue
            p = os.path.join(base, f)
            d = open(p, "rb").read()
            n += 1
            try:
                h = read_save(d)
            except Refused as e:
                print("%-46s REFUSED %s" % (f, e))
                continue
            ok += 1
            print("%-46s %8d %9d %9d %9d %9d %9d %7.4f%%"
                  % (os.path.relpath(p, root).replace(os.sep, "/"), len(d),
                     h["u6"], h["u10"], h["u14"], h["u18"], h["u22"],
                     100.0 * h["nonzero"] / len(d)))
    print()
    print("accepted %d of %d" % (ok, n))
    print()
    print("%-46s %-18s %-18s %-14s %10s"
          % ("file", "player", "save", "third", "u32@136"))
    for base, _, names in os.walk(root):
        for f in sorted(names):
            if not f.upper().endswith(".GD"):
                continue
            p = os.path.join(base, f)
            g = read_gd(open(p, "rb").read())
            print("%-46s %-18s %-18s %-14s %10d"
                  % (os.path.relpath(p, root).replace(os.sep, "/"),
                     g["player"], g["save"], g["third"] or "-", g["u136"]))
    return 0


def cmd_gd(path):
    g = read_gd(open(path, "rb").read())
    print("%s  141 bytes" % os.path.basename(path))
    for k in ("player", "save", "third"):
        print("  %-8s %r" % (k, g[k]))
    print("  +96      %s" % g["f96"])
    print("  +100     36 zero bytes: %s" % g["zeros"])
    print("  +136     u32 %d" % g["u136"])
    return 0


def cmd_header(path):
    d = open(path, "rb").read()
    h = read_save(d)
    print("%s  %d bytes, %.4f %% non-zero"
          % (os.path.basename(path), len(d), 100.0 * h["nonzero"] / len(d)))
    for k in ("u0", "u6", "u10", "u14", "u18", "u22"):
        print("  %-4s %10d" % (k, h[k]))
    return 0


def cmd_rides(path):
    d = open(path, "rb").read()
    read_save(d)
    for i, o, name, body in rides(d):
        print("%2d  %7d  %-22s %s"
              % (i, o, name, " ".join("%02x" % b for b in body[:12])))
    return 0


def cmd_diff(a, b):
    x = open(a, "rb").read()
    y = open(b, "rb").read()
    if len(x) != len(y):
        print("different lengths: %d and %d" % (len(x), len(y)))
        return 1
    d = [i for i in range(len(x)) if x[i] != y[i]]
    print("%s vs %s" % (os.path.basename(a), os.path.basename(b)))
    print("  %d bytes differ of %d  (%.4f %%)"
          % (len(d), len(x), 100.0 * len(d) / len(x)))
    if not d:
        return 0
    runs = []
    s = p = d[0]
    for i in d[1:]:
        if i > p + 16:
            runs.append((s, p))
            s = i
        p = i
    runs.append((s, p))
    print("  %d runs; the ten widest:" % len(runs))
    for s, e in sorted(runs, key=lambda r: r[1] - r[0], reverse=True)[:10]:
        where = ""
        if RIDE_BASE <= s < RIDE_BASE + RIDE_STRIDE * RIDE_COUNT:
            where = "  <- ride record %d" % ((s - RIDE_BASE) // RIDE_STRIDE)
        elif s < 64:
            where = "  <- the header"
        print("     %7d..%7d  (%d)%s" % (s, e, e - s + 1, where))
    return 0


def cmd_selftest():
    good = bytearray(SAVE_SIZE)
    struct.pack_into("<I", good, 0, 1)
    struct.pack_into("<I", good, 22, 200000)
    good[RIDE_BASE:RIDE_BASE + 11] = b"FLIGHT SIM\0"
    cases = [
        ("a 304,668-byte save whose first u32 is 1", bytes(good), True),
        ("a save one byte short", bytes(good)[:-1], False),
        ("a save whose first u32 is 0", bytes(SAVE_SIZE), False),
        ("empty", b"", False),
    ]
    fails = 0
    for name, data, ok in cases:
        try:
            read_save(data)
            got, why = True, ""
        except Refused as e:
            got, why = False, str(e)
        mark = "ok " if got == ok else "FAIL"
        if got != ok:
            fails += 1
        print("%s  %-46s expected %-7s got %-7s %s"
              % (mark, name, "accept" if ok else "refuse",
                 "accept" if got else "refuse", why))
    gdcases = [("a 141-byte .GD", bytes(GD_SIZE), True),
               ("a 140-byte .GD", bytes(GD_SIZE - 1), False)]
    for name, data, ok in gdcases:
        try:
            read_gd(data)
            got, why = True, ""
        except Refused as e:
            got, why = False, str(e)
        mark = "ok " if got == ok else "FAIL"
        if got != ok:
            fails += 1
        print("%s  %-46s expected %-7s got %-7s %s"
              % (mark, name, "accept" if ok else "refuse",
                 "accept" if got else "refuse", why))
    r = rides(bytes(good))
    hit = r[0][2] == "FLIGHT SIM" and r[0][1] == RIDE_BASE
    print("%s  %-46s %s"
          % ("ok " if hit else "FAIL",
             "the ride table is read at the derived offset",
             "record 0 at 293578 is FLIGHT SIM" if hit else repr(r[0])))
    if not hit:
        fails += 1
    print()
    print("%d specimens, %d must be accepted, %d failures"
          % (len(cases) + len(gdcases) + 1, 3, fails))
    return 1 if fails else 0


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    return {"census": lambda: cmd_census(rest[0]),
            "gd": lambda: cmd_gd(rest[0]),
            "header": lambda: cmd_header(rest[0]),
            "rides": lambda: cmd_rides(rest[0]),
            "diff": lambda: cmd_diff(rest[0], rest[1]),
            "selftest": cmd_selftest}.get(cmd, lambda: 2)()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
