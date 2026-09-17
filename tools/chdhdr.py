#!/usr/bin/env python3
"""Read a CHD v5 header and its metadata chain by hand.

No library, no chdman. Fifteen lines of structure and the track count
comes out with no intermediary. Refuses anything that is not
'MComprHD' version 5, loudly.

usage: chdhdr.py <file.chd>
"""
import struct
import sys


def die(msg):
    sys.stderr.write("chdhdr: " + msg + "\n")
    raise SystemExit(2)


def main():
    if len(sys.argv) != 2:
        die("usage: chdhdr.py <file.chd>")
    path = sys.argv[1]
    with open(path, "rb") as f:
        head = f.read(124)
        if len(head) < 124:
            die("short file: %d bytes, need 124 for a v5 header" % len(head))
        tag = head[0:8]
        if tag != b"MComprHD":
            die("not a CHD: magic is %r, expected b'MComprHD'" % tag)
        hlen, version = struct.unpack(">II", head[8:16])
        if version != 5:
            die("CHD version %d, this reader only knows 5" % version)
        if hlen != 124:
            die("v5 header claims %d bytes, expected 124" % hlen)

        comp = [head[16 + 4 * i:20 + 4 * i] for i in range(4)]
        logical, mapoff, metaoff = struct.unpack(">QQQ", head[32:56])
        hunkbytes, unitbytes = struct.unpack(">II", head[56:64])
        rawsha1 = head[64:84].hex()
        sha1 = head[84:104].hex()
        parentsha1 = head[104:124].hex()

        size = f.seek(0, 2)

        print("file                %s" % path)
        print("container size      %d bytes" % size)
        print("magic               %s" % tag.decode("ascii"))
        print("header length       %d" % hlen)
        print("version             %d" % version)
        print("compressors         %s" % " ".join(
            c.decode("ascii", "replace") if c != b"\0\0\0\0" else "-"
            for c in comp))
        print("logical bytes       %d" % logical)
        print("hunk bytes          %d" % hunkbytes)
        print("unit bytes          %d" % unitbytes)
        print("units per hunk      %d" % (hunkbytes // unitbytes))
        if logical % hunkbytes:
            print("hunks               %d  (+ %d bytes short tail)"
                  % (logical // hunkbytes, logical % hunkbytes))
        else:
            print("hunks               %d" % (logical // hunkbytes))
        print("total units         %d" % (logical // unitbytes))
        print("map offset          %d" % mapoff)
        print("metadata offset     %d" % metaoff)
        print("sha1 (whole)        %s" % sha1)
        print("sha1 (raw data)     %s" % rawsha1)
        print("parent sha1         %s" % parentsha1)
        print("compression ratio   %.4f %%" % (100.0 * size / logical))
        print()

        # the metadata chain: 16-byte entry, then the payload
        off = metaoff
        n = 0
        frames_total = 0
        while off:
            f.seek(off)
            ent = f.read(16)
            if len(ent) < 16:
                die("metadata entry at %d is short" % off)
            mtag = ent[0:4]
            flags_len = struct.unpack(">I", ent[4:8])[0]
            mlen = flags_len & 0x00FFFFFF
            nxt = struct.unpack(">Q", ent[8:16])[0]
            payload = f.read(mlen)
            text = payload.rstrip(b"\0").decode("ascii", "replace")
            print("metadata #%d  tag=%s  len=%d" % (n, mtag.decode("ascii", "replace"), mlen))
            print("    %s" % text)
            for part in text.split():
                if part.startswith("FRAMES:"):
                    frames_total += int(part.split(":", 1)[1])
            n += 1
            off = nxt
        print()
        print("metadata entries    %d" % n)
        print("frames declared     %d" % frames_total)
        units = logical // unitbytes
        if frames_total:
            if units == frames_total:
                print("units == frames     yes, no padding")
            else:
                print("units == frames     NO: %d units, %d frames, %d padding units"
                      % (units, frames_total, units - frames_total))


if __name__ == "__main__":
    main()
