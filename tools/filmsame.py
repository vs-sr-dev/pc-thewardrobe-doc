"""filmsame.py -- are the twelve films twelve films?

Seven members of movie.vt7a are ~91 MB and all run 3:57.  Byte-identical they
are not: the archive has no duplicate sha1.  The question is whether the
PICTURE is the same and only the soundtrack differs, which is a different
number in the leftovers column.

The method: for each member, hash the payload of the Ogg pages belonging to the
video stream only, discarding every page header (which carries a serial number
and a sequence number and a checksum, all of which differ between two muxes of
the same video).  Two films whose video payload hashes agree are the same film.

    python tools/filmsame.py "<root>"

Nothing is extracted.
"""
import os
import sys
import struct
import hashlib
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vt7a import read_table, extent                 # noqa: E402
from oggtime import codec_info, bos_serials, last_granule, hms   # noqa: E402


def main():
    root = sys.argv[1]
    p = os.path.join(root, "movie.vt7a")
    n, ver, m2, count, recs = read_table(p)
    fh = open(p, "rb")
    rows = []
    for r in sorted(recs, key=lambda x: x[1]):
        fh.seek(r[1])
        blob = fh.read(extent(r))
        ser = bos_serials(blob[:8192])
        vh = hashlib.sha1()
        ah = hashlib.sha1()
        vbytes = abytes = 0
        vpages = apages = 0
        i = 0
        while i + 27 <= len(blob):
            if blob[i:i + 4] != b"OggS":
                i += 1
                continue
            s = struct.unpack_from("<I", blob, i + 14)[0]
            nseg = blob[i + 26]
            segs = blob[i + 27:i + 27 + nseg]
            body = blob[i + 27 + nseg:i + 27 + nseg + sum(segs)]
            if s == ser.get("theora"):
                vh.update(body)
                vbytes += len(body)
                vpages += 1
            elif s == ser.get("vorbis"):
                ah.update(body)
                abytes += len(body)
                apages += 1
            i += 27 + nseg + sum(segs)
        codec, rate, dim = codec_info(blob[:8192])
        g = last_granule(fh, r[1], extent(r), ser.get("theora"))
        kfs = ((blob[blob.find(b"\x80theora") + 40] & 0x03) << 3) \
            | (blob[blob.find(b"\x80theora") + 41] >> 5)
        frames = (g >> kfs) + (g & ((1 << kfs) - 1))
        secs = frames * rate[1] / float(rate[0])
        rows.append({"key": r[0], "extent": extent(r), "secs": secs,
                     "vhash": vh.hexdigest(), "ahash": ah.hexdigest(),
                     "vbytes": vbytes, "abytes": abytes,
                     "vpages": vpages, "apages": apages,
                     "audio": "vorbis" in ser})
    print("%-12s %11s %9s %12s %12s %-9s %-9s"
          % ("key", "bytes", "length", "video bytes", "audio bytes",
             "video sha1", "audio sha1"))
    print("-" * 84)
    for r in sorted(rows, key=lambda x: -x["extent"]):
        print("%-12d %11d %9s %12d %12d %-9s %-9s"
              % (r["key"], r["extent"], hms(r["secs"]), r["vbytes"],
                 r["abytes"], r["vhash"][:8],
                 r["ahash"][:8] if r["audio"] else "-none-"))
    print()
    vg = collections.Counter(r["vhash"] for r in rows)
    ag = collections.Counter(r["ahash"] for r in rows if r["audio"])
    print("members                       : %d" % len(rows))
    print("distinct video payload hashes : %d" % len(vg))
    print("distinct audio payload hashes : %d" % len(ag))
    print()
    for h, c in vg.most_common():
        if c > 1:
            same = [r for r in rows if r["vhash"] == h]
            waste = sum(r["extent"] for r in same) - max(r["extent"] for r in same)
            print("the SAME picture appears %d times: keys %s"
                  % (c, ", ".join(str(r["key"]) for r in same)))
            print("   %s each, %d bytes in total, of which %d are the extra copies"
                  % (hms(same[0]["secs"]), sum(r["extent"] for r in same), waste))
            print("   video payload %d bytes; audio payloads %s"
                  % (same[0]["vbytes"],
                     ", ".join(str(r["abytes"]) for r in same)))
    if len(vg) == len(rows):
        print("no two members share a video payload: twelve films, twelve pictures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
