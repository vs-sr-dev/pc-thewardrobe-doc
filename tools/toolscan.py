"""toolscan.py -- every tool in tools/ must be text, and the test that says so
must be able to fail.

The rule: no byte below 9, and no byte in 14..31. That admits tab (9), line feed
(10), carriage return (13) and form feed (12), and rejects NUL, escape, and the
rest of the C0 controls -- which is what a Python source file corrupted by a
bad write or a truncated download looks like.

The positive control must be chosen INSIDE the interval the test covers. A
previous session picked 0x0b, which is between 9 and 14 and therefore passes,
and for a moment the test looked broken. This one uses 0x00 (below 9), 0x01
(below 9) and 0x1b (inside 14..31), and all three must be reported.

Usage:
    python tools/toolscan.py tools
"""

import os
import sys


def bad_bytes(data):
    return {b for b in data if b < 9 or 14 <= b <= 31}


def main(argv):
    root = argv[1] if len(argv) > 1 else "tools"
    # This session also writes .md and .txt, and the rule is about every file
    # the session writes, not only the tools. A second argument names the
    # extension; the FATAL on an empty match is kept for both.
    ext = argv[2] if len(argv) > 2 else ".py"
    files = sorted(f for f in os.listdir(root) if f.endswith(ext))
    if not files:
        print("FATAL: no %s files under %s -- a tool that finds nothing is not"
              " a tool that says zero" % (ext, root))
        return 3
    bad = 0
    for f in files:
        with open(os.path.join(root, f), "rb") as fh:
            data = fh.read()
        b = bad_bytes(data)
        if b:
            bad += 1
            print("  %-22s %d control byte(s): %s"
                  % (f, len(b), " ".join("0x%02X" % x for x in sorted(b))))
    print("files scanned                      : %d" % len(files))
    print("files with a forbidden control byte: %d" % bad)
    print()
    print("=== POSITIVE CONTROLS: each must be reported ===")
    ok = True
    for probe, why in ((0x00, "NUL, below 9"),
                       (0x01, "SOH, below 9"),
                       (0x1B, "ESC, inside 14..31")):
        found = bad_bytes(b"print('hi')" + bytes([probe]) + b"\n")
        hit = probe in found
        print("  0x%02X  %-20s -> %s" % (probe, why, "reported" if hit else "*** MISSED ***"))
        ok = ok and hit
    if not ok:
        print("POSITIVE CONTROL FAILED")
        return 4
    print("all three fired.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
