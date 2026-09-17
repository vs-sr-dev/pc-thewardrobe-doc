"""contactsheet.py -- put every frame of a movie, or every image in a
directory, on one page so that a human being can look at all of them.

The branch's rule is that the last step of any claim about pictures is a person
looking at a picture. That rule does not scale to 147 frames one at a time, and
sampling eight of them is how a title card gets missed. A contact sheet is the
compromise that is still a reading: every frame is present, at a size where
lettering is visible, in decode order.

Usage:
    python tools/contactsheet.py IN_DIR OUT.png --cols 12 --width 200
    python tools/contactsheet.py IN_DIR OUT.png --cols 8 --width 260 --label
"""

import os
import sys


def natural_key(name):
    digits = "".join(c if c.isdigit() else " " for c in name).split()
    return ([int(d) for d in digits], name)


def main(argv):
    from PIL import Image, ImageDraw
    if len(argv) < 3:
        print(__doc__)
        return 2
    in_dir, out = argv[1], argv[2]
    cols = int(argv[argv.index("--cols") + 1]) if "--cols" in argv else 12
    cw = int(argv[argv.index("--width") + 1]) if "--width" in argv else 200
    label = "--label" in argv

    files = sorted((f for f in os.listdir(in_dir)
                    if f.lower().endswith((".png", ".bmp", ".jpg", ".jpeg"))),
                   key=natural_key)
    if not files:
        print("FATAL: no images in %s -- refusing to write an empty sheet" % in_dir)
        return 3

    if "--cell" in argv:
        # square cells, each image letterboxed inside one: use this when the
        # directory holds images of many different shapes and taking the
        # aspect ratio from the first one would squash all the others.
        cw = ch = int(argv[argv.index("--cell") + 1])
        square = True
    else:
        first = Image.open(os.path.join(in_dir, files[0]))
        ch = max(1, round(cw * first.height / first.width))
        square = False
    pad = 2
    lab = 12 if label else 0
    rows = (len(files) + cols - 1) // cols
    sheet = Image.new("RGB", (cols * (cw + pad) + pad,
                              rows * (ch + pad + lab) + pad), (24, 24, 24))
    draw = ImageDraw.Draw(sheet)
    for i, f in enumerate(files):
        im = Image.open(os.path.join(in_dir, f)).convert("RGB")
        x = pad + (i % cols) * (cw + pad)
        y = pad + (i // cols) * (ch + pad + lab)
        if square:
            s = min(cw / im.width, ch / im.height)
            im = im.resize((max(1, int(im.width * s)), max(1, int(im.height * s))))
            sheet.paste(im, (x + (cw - im.width) // 2, y + (ch - im.height) // 2))
        else:
            sheet.paste(im.resize((cw, ch)), (x, y))
        if label:
            draw.text((x + 2, y + ch + 1), f.rsplit(".", 1)[0][-8:], fill=(190, 190, 190))
    sheet.save(out)
    print("images  : %d" % len(files))
    print("grid    : %d cols x %d rows" % (cols, rows))
    print("cell    : %dx%d" % (cw, ch))
    print("wrote   : %s  (%dx%d)" % (out, sheet.width, sheet.height))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
