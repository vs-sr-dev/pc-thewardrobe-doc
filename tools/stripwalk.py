#!/usr/bin/env python3
"""stripwalk.py -- do the FRME payloads walk as Cinepak strips?

The `FHDR` sub-chunk of this disc's stream files declares its compression type
as the four characters `cvid`. That is a claim the file makes about itself and
it is not evidence. The evidence would be that the payload has the shape the
public Cinepak definition describes, and chains:

    strip:  u16 id, u16 size including this header,
            u16 y0, u16 x0, u16 y1, u16 x1

with the strips tiling the frame's height exactly and the last one ending at the
end of the payload. This walks them and refuses to report success unless both
hold.

usage: stripwalk.py FILE [--frames N] [--start OFFSET]
"""
import argparse
import collections
import struct


def chunks(data):
    off = 0
    out = []
    while off < len(data):
        tag = data[off:off + 4]
        size = struct.unpack(">I", data[off + 4:off + 8])[0]
        if size < 8 or off + size > len(data):
            raise SystemExit("bad chain at %d" % off)
        out.append((off, tag, size))
        off += size
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--frames", type=int, default=5)
    ap.add_argument("--payload", type=int, default=44,
                    help="offset of the codec payload inside a FILM chunk")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    data = open(a.file, "rb").read()
    cs = chunks(data)
    frames = [c for c in cs if c[1] == b"FILM"
              and data[c[0] + 16:c[0] + 20] == b"FRME"]
    print("%s: %d FRME chunks" % (a.file, len(frames)))

    good = 0
    ids = collections.Counter()
    heights = collections.Counter()
    shown = 0
    for off, t, size in frames:
        p = off + a.payload
        end = off + size
        strips = []
        ok = True
        while p + 12 <= end:
            sid, ssz = struct.unpack(">2H", data[p:p + 4])
            y0, x0, y1, x1 = struct.unpack(">4H", data[p + 4:p + 12])
            if ssz < 12 or p + ssz > end:
                ok = False
                break
            strips.append((p - off, sid, ssz, y0, x0, y1, x1))
            ids[sid] += 1
            p += ssz
            if end - p < 12:
                break
        # the strips must tile the height and finish the payload
        tiled = bool(strips) and strips[0][3] == 0
        for i in range(1, len(strips)):
            if strips[i][3] != strips[i - 1][5]:
                tiled = False
        slack = end - p
        if ok and tiled and slack < 12:
            good += 1
            if strips:
                heights[strips[-1][5]] += 1
        if shown < a.frames and not a.quiet:
            shown += 1
            print("  frame at %d, %d bytes: %d strip(s), tiled %s, %d bytes over"
                  % (off, size, len(strips), tiled, slack))
            for s in strips:
                print("      +%-6d id 0x%04x  size %6d  y %3d..%-3d  x %3d..%-3d"
                      % (s[0], s[1], s[2], s[3], s[5], s[4], s[6]))
    print()
    print("frames whose strips chain, tile the height and finish the payload: "
          "%d of %d" % (good, len(frames)))
    print("strip ids seen: %s"
          % ", ".join("0x%04x (x%d)" % (k, v) for k, v in ids.most_common()))
    print("frame heights implied by the last strip: %s"
          % ", ".join("%d (x%d)" % (k, v) for k, v in heights.most_common()))


if __name__ == "__main__":
    main()
