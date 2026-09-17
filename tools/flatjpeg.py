#!/usr/bin/env python3
"""flatjpeg.py -- the control-population method, moved from palettes to JPEG.

`flatness.py` was written last session for a 1992 Tandy VIS disc and its file
handling does not apply here. Its **method** does, and the method is the part
worth carrying: find a population on the object whose nature is already known,
measure the statistic on that, then score the unknown against the range the
control occupies. The statistic itself is imported from `flatness.py` so that
this is literally the same code and not a re-implementation that happens to
agree.

On this object the control is sitting in the open. The `Desktop Wallpapers`
directory holds seven images at up to six resolutions each: they are digital
artwork exported from a drawing program, they carry no scanner resolution, and
their JPEG marker sequence says Photoshop "Save for Web". The `Concept Art`
directory is the unknown, and its filenames make a claim -- "as scribbled on by
Steve Purcell", "with notes from the artist" -- that a filename is not entitled
to settle.

The statistic is the fraction of 2 x 2 pixel blocks whose four samples are
equal, measured on the luma channel. Paper grain, pencil tooth and scanner
noise destroy it; flat digital fills produce it.

TWO THINGS THAT WOULD MAKE THIS DISHONEST, AND WHAT IS DONE ABOUT THEM

  * **JPEG itself flattens.** A heavily compressed image scores higher than a
    lightly compressed one regardless of origin, so the tool prints bytes per
    pixel beside the statistic and the reader can see whether the two
    populations were compressed alike.
  * **Downscaling flattens too.** The wallpapers exist at six sizes and the
    small ones are resampled, so the control range is printed per resolution
    as well as pooled.

    python tools/flatjpeg.py --control DIR --unknown DIR [--max-side 1200]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flatness import flat  # noqa: E402  the statistic, not a copy of it

from PIL import Image  # noqa: E402


def score(path, max_side):
    im = Image.open(path).convert("L")
    w, h = im.size
    if max(w, h) > max_side:
        k = max_side / float(max(w, h))
        im = im.resize((max(1, int(w * k)), max(1, int(h * k))), Image.LANCZOS)
    w, h = im.size
    pix = list(im.getdata())
    uni, hflat, distinct = flat(pix, w, h)
    return uni, hflat, distinct, w, h, os.path.getsize(path)


def collect(d):
    out = []
    for root, _dirs, names in os.walk(d):
        for n in sorted(names):
            if n.lower().endswith((".jpg", ".jpeg")):
                out.append(os.path.join(root, n))
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--control", required=True)
    ap.add_argument("--unknown", required=True)
    ap.add_argument("--max-side", type=int, default=1200)
    ap.add_argument("--out")
    args = ap.parse_args()

    lines = []

    def say(s=""):
        lines.append(s)
        print(s)

    ctrl = collect(args.control)
    unk = collect(args.unknown)
    if not ctrl or not unk:
        say("control %d files, unknown %d files -- refusing to score"
            % (len(ctrl), len(unk)))
        return 1

    cs = []
    say("CONTROL: %s" % args.control)
    say("%-44s %8s %8s %9s %9s" % ("file", "2x2 uni", "h-flat", "px", "B/px"))
    for p in ctrl:
        u, hf, dist, w, h, sz = score(p, args.max_side)
        cs.append(u)
        say("%-44s %7.4f%% %7.4f%% %9d %9.4f"
            % (os.path.basename(p)[:44], u, hf, w * h,
               sz / float(w * h)))
    lo, hi = min(cs), max(cs)
    say("control range   %.4f%% .. %.4f%%   (n=%d)" % (lo, hi, len(cs)))
    say("control spread  a factor of %.2f between the extremes" % (hi / lo))

    say()
    say("UNKNOWN: %s" % args.unknown)
    say("%-46s %8s %8s %9s  verdict" % ("file", "2x2 uni", "h-flat", "B/px"))
    below = 0
    inside = 0
    above = 0
    for p in unk:
        u, hf, dist, w, h, sz = score(p, args.max_side)
        if u < lo:
            v = "BELOW control"
            below += 1
        elif u > hi:
            v = "above control"
            above += 1
        else:
            v = "inside control"
            inside += 1
        say("%-46s %7.4f%% %7.4f%% %9.4f  %s"
            % (os.path.basename(p)[:46], u, hf,
               sz / float(w * h), v))
    say()
    say("unknown files below the control range : %d of %d" % (below, len(unk)))
    if hi / lo > 3:
        say("WARNING: the control range spans a factor of %.2f. A control that"
            % (hi / lo))
        say("         wide cannot discriminate: it is not one population.")
    say("unknown files inside                  : %d of %d" % (inside, len(unk)))
    say("unknown files above                   : %d of %d" % (above, len(unk)))
    if args.out:
        open(args.out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
