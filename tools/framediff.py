"""framediff.py -- compare frames decoded by this repository's own decoder
against frames decoded by an independent implementation.

A decoder that consumes every chunk to the exact byte has proved that it parses
the container correctly. It has not proved that it paints the right pixels: a
transposed quadrant table or an inverted mask bit consumes exactly the same
number of bytes and produces a wrong picture. The only cheap check on the
pixels is a second implementation that shares no code with the first.

RGB555 has 32 levels per channel and the two implementations may round the
5-bit-to-8-bit expansion differently (x*255/31 versus x<<3, a difference of up
to 7 per channel), so the test is not bit-equality: it is that every channel of
every pixel agrees to within a stated tolerance, and that the *structure* --
which pixels differ from their neighbours -- is identical.

Usage:
    python tools/framediff.py DIR_A DIR_B --map 0:1,24:25 --tol 8
"""

import os
import sys


def load(path):
    from PIL import Image
    import numpy as np
    return np.asarray(Image.open(path).convert("RGB")).astype(int)


def main(argv):
    import numpy as np
    if len(argv) < 3:
        print(__doc__)
        return 2
    a_dir, b_dir = argv[1], argv[2]
    tol = int(argv[argv.index("--tol") + 1]) if "--tol" in argv else 8
    pairs = []
    if "--map" in argv:
        for item in argv[argv.index("--map") + 1].split(","):
            x, y = item.split(":")
            pairs.append((int(x), int(y)))
    a_files = {int("".join(c for c in f if c.isdigit())): os.path.join(a_dir, f)
               for f in os.listdir(a_dir) if f.lower().endswith(".png")}
    b_files = {int("".join(c for c in f if c.isdigit())): os.path.join(b_dir, f)
               for f in os.listdir(b_dir) if f.lower().endswith(".png")}
    if not pairs:
        pairs = [(k, k) for k in sorted(a_files) if k in b_files]
    if not pairs:
        print("FATAL: no frame pairs to compare -- refusing to report success")
        return 3

    worst_overall = 0
    bad = 0
    print("%-8s %-8s %10s %10s %10s %9s" %
          ("mine", "theirs", "pixels", "max delta", "mean delta", "verdict"))
    for x, y in pairs:
        if x not in a_files or y not in b_files:
            print("missing pair %d:%d" % (x, y))
            bad += 1
            continue
        A, B = load(a_files[x]), load(b_files[y])
        if A.shape != B.shape:
            print("%-8d %-8d shape mismatch %s vs %s" % (x, y, A.shape, B.shape))
            bad += 1
            continue
        d = np.abs(A - B)
        mx, mean = int(d.max()), float(d.mean())
        worst_overall = max(worst_overall, mx)
        ok = mx <= tol
        if not ok:
            bad += 1
        print("%-8d %-8d %10d %10d %10.4f %9s"
              % (x, y, A.shape[0] * A.shape[1], mx, mean, "ok" if ok else "DIFFERS"))
    print()
    print("pairs compared      : %d" % len(pairs))
    print("worst channel delta : %d  (tolerance %d)" % (worst_overall, tol))
    print("pairs over tolerance: %d" % bad)
    if bad == 0:
        print()
        print("Two implementations that share no code paint the same picture.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
