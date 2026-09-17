"""strm.py -- the STRM members, which are 73.07 % of everything inside the
seven VT7A archives and therefore decide the thesis.

Nothing about STRM is published anywhere.  What is written here is derived from
the bytes of 3,991 members, and every claim is stated so that it can fail.

    head   <root> <archive> [--n N]   the first 64 bytes of N members, decoded
    scan   <root> <archive> [--n N]   what magics live INSIDE a member
    frames <root> <archive> [--n N]   derive the frame table and check it
    census <root>                     all STRM members, all archives

    python tools/strm.py scan "<root>" graphics_720.vt7a --n 6
"""
import os
import sys
import struct
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vt7a import read_table, extent, signature      # noqa: E402


def strm_members(root, arch):
    p = os.path.join(root, arch)
    n, ver, m2, count, recs = read_table(p)
    fh = open(p, "rb")
    for r in sorted(recs, key=lambda x: x[1]):
        fh.seek(r[1])
        if fh.read(4) != b"STRM":
            continue
        yield fh, r


def head(root, arch, n_show):
    print("STRM header, read as: char[4] 'STRM', u32 version, f32, u32, u32,")
    print("u16 width, u16 height, then fields whose meaning is derived below.")
    print()
    shown = 0
    vers = collections.Counter()
    floats = collections.Counter()
    for fh, r in strm_members(root, arch):
        fh.seek(r[1])
        b = fh.read(80)
        ver, f, w1, w2 = struct.unpack_from("<IfII", b, 4)
        w, h = struct.unpack_from("<HH", b, 20)
        vers[ver] += 1
        floats["%.4f" % f] += 1
        if shown < n_show:
            rest = struct.unpack_from("<10H", b, 24)
            print("key %-11d extent %-10d ver %d  f %.3f  %d %d   %dx%d"
                  % (r[0], extent(r), ver, f, w1, w2, w, h))
            print("     u16 from +24: %s" % (rest,))
            print("     u32 from +44: %s" % (struct.unpack_from("<5I", b, 44),))
            shown += 1
    print()
    print("versions seen : %s" % dict(vers))
    print("the float at +8: %s" % dict(floats))
    return 0


MAGICS = [(b"RIFF", "RIFF"), (b"WEBP", "WEBP"), (b"OggS", "OggS"),
          (b"\x89PNG", "PNG"), (bytes([0x78, 0x9c]), "zlib 789c"),
          (bytes([0x78, 0xda]), "zlib 78da"), (b"DDS ", "DDS"),
          (b"STRM", "STRM"), (b"sdw" + bytes([0]), "sdw")]


def scan(root, arch, n_show):
    print("What lives INSIDE a STRM member.  Each member is read in full and")
    print("searched for the magics this object is already known to use.")
    print()
    shown = 0
    grand = collections.Counter()
    total = 0
    for fh, r in strm_members(root, arch):
        fh.seek(r[1])
        blob = fh.read(extent(r))
        total += 1
        c = collections.Counter()
        for sig, name in MAGICS:
            k = blob.count(sig)
            if k:
                c[name] += k
                grand[name] += k
        if shown < n_show:
            w, h = struct.unpack_from("<HH", blob, 20)
            print("key %-11d %9d B  %4dx%-4d   %s"
                  % (r[0], extent(r), w, h,
                     ", ".join("%s %d" % kv for kv in c.most_common())))
            # where is the first RIFF?
            i = blob.find(b"RIFF")
            if i >= 0:
                print("     first RIFF at +%d; the 20 bytes before it: %s"
                      % (i, " ".join("%02x" % x for x in blob[max(0, i - 20):i])))
                sz = struct.unpack_from("<I", blob, i + 4)[0]
                print("     that RIFF declares %d bytes; next RIFF at +%d, gap %d"
                      % (sz, blob.find(b"RIFF", i + 4),
                         blob.find(b"RIFF", i + 4) - (i + 8 + sz)
                         if blob.find(b"RIFF", i + 4) > 0 else -1))
            shown += 1
        if shown >= n_show and total > 200:
            break
    print()
    print("magics found across %d STRM members of %s:" % (total, arch))
    for k, v in grand.most_common():
        print("   %-12s %8d" % (k, v))
    return 0


def frames(root, arch, n_show):
    print("The frame table.  A STRM member whose payload is a run of RIFF/WEBP")
    print("chunks is an animation: each chunk is one frame.  The claim to test")
    print("is that the chunks tile the member end to end with no gap.")
    print()
    print("%-12s %10s %8s %9s %8s %10s %9s"
          % ("key", "extent", "WxH", "frames", "1st at", "sum sizes", "residue"))
    shown = 0
    closes = 0
    tot = 0
    for fh, r in strm_members(root, arch):
        fh.seek(r[1])
        blob = fh.read(extent(r))
        w, h = struct.unpack_from("<HH", blob, 20)
        i = blob.find(b"RIFF")
        if i < 0:
            continue
        first = i
        n = 0
        pos = i
        while pos >= 0 and pos + 8 <= len(blob):
            if blob[pos:pos + 4] != b"RIFF":
                break
            sz = struct.unpack_from("<I", blob, pos + 4)[0]
            pos += 8 + sz + (sz & 1)
            n += 1
        tot += 1
        residue = len(blob) - pos
        if 0 <= residue <= 16:
            closes += 1
        if shown < n_show:
            print("%-12d %10d %8s %9d %8d %10d %9d"
                  % (r[0], extent(r), "%dx%d" % (w, h), n, first,
                     pos - first, residue))
            shown += 1
        if tot > 400:
            break
    print()
    print("members whose RIFF chain reaches the end of the member: %d of %d"
          % (closes, tot))
    return 0


def census(root):
    """Count what the STRM header actually declares.  The RIFF walk this
    function used to do found nothing, because a STRM member does not hold
    RIFF chunks -- so it is gone, and what is counted here is only what the
    header says: dimensions, and the two count fields at +26 and +78."""
    from vt7a import VT7A
    print("%-22s %8s %15s %10s %11s %12s %12s"
          % ("archive", "STRM", "bytes", "sum f@26", "sum f@78",
             "min WxH", "max WxH"))
    grand_n = grand_b = grand_f = 0
    for arch in VT7A:
        n = b = f26 = f78 = px = 0
        dims = []
        agree = 0
        for fh, r in strm_members(root, arch):
            fh.seek(r[1])
            head = fh.read(96)
            n += 1
            b += extent(r)
            w, h = struct.unpack_from("<HH", head, 20)
            a = struct.unpack_from("<H", head, 26)[0]
            c = struct.unpack_from("<H", head, 78)[0]
            f26 += a
            f78 += c
            agree += (a == c)
            px += w * h * a
            dims.append((w, h))
        if not n:
            continue
        grand_n += n
        grand_b += b
        grand_f += f26
        grand_px = globals().setdefault("_px", 0) + px
        globals()["_px"] = grand_px
        dims.sort(key=lambda d: d[0] * d[1])
        print("%-22s %8d %15d %10d %11d %12s %12s"
              % (arch, n, b, f26, f78, "%dx%d" % dims[0], "%dx%d" % dims[-1]))
        print("%-22s the two count fields agree on %d members of %d"
              % ("", agree, n))
        print("%-22s frames x pixels declared: %d" % ("", px))
    print("%-22s %8d %15d %10d" % ("TOTAL", grand_n, grand_b, grand_f))
    print()
    print("frames per member, mean : %.2f" % (grand_f / float(grand_n)))
    print("bytes per declared frame: %.2f" % (grand_b / float(grand_f)))
    print("declared frame-pixels   : %d" % globals().get("_px", 0))
    print("bytes per frame-pixel   : %.4f"
          % (grand_b / float(globals().get("_px", 1) or 1)))
    return 0


def main():
    cmd, root = sys.argv[1], sys.argv[2]
    n = 6
    if "--n" in sys.argv:
        n = int(sys.argv[sys.argv.index("--n") + 1])
    if cmd == "census":
        return census(root)
    arch = sys.argv[3]
    if cmd == "head":
        return head(root, arch, n)
    if cmd == "scan":
        return scan(root, arch, n)
    if cmd == "frames":
        return frames(root, arch, n)
    print(__doc__)


if __name__ == "__main__":
    main()
