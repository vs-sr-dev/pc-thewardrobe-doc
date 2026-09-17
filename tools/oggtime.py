"""oggtime.py -- how long the recordings are.

A byte count is not a duration.  Every Ogg member in this object carries its own
granule position on its last page, and the codec identification header carries
its sample rate, so the length of the recording can be read rather than guessed.

    vt7a <root>          the film, the music and the effects, from the VT7A side
    osa  <root>          the speech, from the AUFS side
    all  <root>          both, with the totals the thesis needs

Nothing is extracted.  Each member is touched twice: its first 4 KiB for the
codec header, and its last 64 KiB for the final page.

    python tools/oggtime.py all "<root>"
"""
import os
import sys
import struct
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vt7a import read_table as vt_table, extent, signature, VT7A   # noqa: E402
from aufs import read_table as aufs_table, OSA                     # noqa: E402


def codec_info(head):
    """Return (codec, rate, extra) from the first pages of an Ogg stream."""
    i = head.find(b"\x80theora")
    if i >= 0:
        fmbw, fmbh = struct.unpack_from(">HH", head, i + 10)
        num, den = struct.unpack_from(">II", head, i + 22)
        return "theora", (num, den), (fmbw * 16, fmbh * 16)
    i = head.find(b"OpusHead")
    if i >= 0:
        return "opus", 48000, head[i + 9]
    i = head.find(b"\x01vorbis")
    if i >= 0:
        rate = struct.unpack_from("<I", head, i + 12)[0]
        ch = head[i + 11]
        return "vorbis", rate, ch
    return None, None, None


def last_granule(fh, off, size, serial=None, back=1 << 16):
    """The granule position of the last page of the member -- of the stream
    with the given serial number, when one is asked for.

    A multiplexed Ogg stream (Skeleton + Theora + Vorbis, which is what the
    films in this object are) ends on a page belonging to whichever stream
    finished last.  Reading that page's granule as if it were the video's is
    how a two-hour film becomes a fourteen-hour one, so the serial is not
    optional here."""
    start = max(off, off + size - back)
    fh.seek(start)
    buf = fh.read(off + size - start)
    i = buf.rfind(b"OggS")
    while i >= 0:
        if serial is None or struct.unpack_from("<I", buf, i + 14)[0] == serial:
            return struct.unpack_from("<q", buf, i + 6)[0]
        i = buf.rfind(b"OggS", 0, i)
    if serial is not None and start > off:
        # the video stream's last page is further back than the window
        return last_granule(fh, off, size, serial, back * 8)
    return None


def bos_serials(head):
    """Map codec name -> serial number, from the beginning-of-stream pages."""
    out = {}
    pos = 0
    while pos + 27 <= len(head) and head[pos:pos + 4] == b"OggS":
        flags = head[pos + 5]
        serial = struct.unpack_from("<I", head, pos + 14)[0]
        nseg = head[pos + 26]
        segs = head[pos + 27:pos + 27 + nseg]
        body = head[pos + 27 + nseg:pos + 27 + nseg + sum(segs)]
        if flags & 0x02:
            if body[:7] == b"\x80theora":
                out["theora"] = serial
            elif body[:7] == b"\x01vorbis":
                out["vorbis"] = serial
            elif body[:8] == b"OpusHead":
                out["opus"] = serial
        pos += 27 + nseg + sum(segs)
    return out


def hms(sec):
    sec = int(round(sec))
    return "%d:%02d:%02d" % (sec // 3600, (sec % 3600) // 60, sec % 60)


def do_vt7a(root):
    rows = []
    print("%-22s %8s %14s %-14s %12s %10s"
          % ("archive", "members", "bytes", "codec", "seconds", "h:mm:ss"))
    print("-" * 86)
    grand_s = 0.0
    grand_b = 0
    for arch in VT7A:
        p = os.path.join(root, arch)
        n, ver, m2, count, recs = vt_table(p)
        per = collections.defaultdict(lambda: [0, 0, 0.0])
        with open(p, "rb") as fh:
            for r in sorted(recs, key=lambda x: x[1]):
                fh.seek(r[1])
                head = fh.read(4096)
                if head[:4] != b"OggS":
                    continue
                codec, rate, extra = codec_info(head)
                ser = bos_serials(head)
                g = last_granule(fh, r[1], extent(r), ser.get(codec))
                if codec == "theora":
                    num, den = rate
                    # theora granule: (keyframe << shift) | offset; the frame
                    # number is the sum of the two halves.  The shift lives in
                    # the identification header at +40, low 5 bits of a byte
                    i = head.find(b"\x80theora")
                    kfshift = ((head[i + 40] & 0x03) << 3) | (head[i + 41] >> 5)
                    frames = (g >> kfshift) + (g & ((1 << kfshift) - 1))
                    secs = frames * den / float(num)
                elif codec in ("vorbis", "opus"):
                    secs = g / float(rate)
                else:
                    secs = 0.0
                e = per[codec]
                e[0] += 1
                e[1] += extent(r)
                e[2] += secs
        for codec, (c, b, s) in sorted(per.items()):
            print("%-22s %8d %14d %-14s %12.2f %10s"
                  % (arch, c, b, codec, s, hms(s)))
            grand_s += s
            grand_b += b
            rows.append((arch, codec, c, b, s))
    print("-" * 86)
    print("%-22s %8s %14d %-14s %12.2f %10s"
          % ("TOTAL", "", grand_b, "", grand_s, hms(grand_s)))
    return rows


def do_osa(root):
    print("%-22s %8s %14s %12s %10s"
          % ("osa", "members", "bytes", "seconds", "h:mm:ss"))
    print("-" * 72)
    grand_s = 0.0
    grand_b = 0
    grand_n = 0
    rows = []
    for name in OSA:
        p = os.path.join(root, name)
        n, count, recs = aufs_table(p)
        secs = 0.0
        b = 0
        with open(p, "rb") as fh:
            for _id, off, size in recs:
                g = last_granule(fh, off, size)
                if g is not None and g > 0:
                    secs += g / 48000.0
                b += size
        print("%-22s %8d %14d %12.2f %10s" % (name, count, b, secs, hms(secs)))
        rows.append((name, count, b, secs))
        grand_s += secs
        grand_b += b
        grand_n += count
    print("-" * 72)
    print("%-22s %8d %14d %12.2f %10s"
          % ("TOTAL", grand_n, grand_b, grand_s, hms(grand_s)))
    print()
    firsts = [r for r in rows if "_part2" not in r[0]]
    print("one language, both parts, mean over the five: %s"
          % hms(grand_s / 5.0))
    return rows


def main():
    cmd, root = sys.argv[1], sys.argv[2]
    if cmd in ("vt7a", "all"):
        print("== the VT7A side: film, music and effects ==")
        print()
        do_vt7a(root)
        print()
    if cmd in ("osa", "all"):
        print("== the AUFS side: recorded speech, five languages ==")
        print()
        do_osa(root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
