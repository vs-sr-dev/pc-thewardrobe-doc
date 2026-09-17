#!/usr/bin/env python3
"""thesis3do.py -- how much of a 3DO pressing is recorded sound, with every
denominator named and every step of the arithmetic printed.

The fraction is meaningless without saying what it is a fraction OF. Four
candidates exist for a CHD-backed CD-ROM and this tool prints all four:

    logical bytes in the container   sectors * 2448   (CHD's unit size)
    bytes extracted                  sectors * 2352   (MODE1_RAW)
    user data in the track           sectors * 2048   <- the one used
    user data the volume declares    declared_blocks * 2048

The numerator has two candidates too, and they differ by the size of the
container headers: the sum of the FILE sizes, and the sum of the SSND
PAYLOADS. Both are printed and the document says which it publishes.

Then the Red Book question: what the same running time would occupy as
CD-DA tracks, at 2,352 bytes per sector and 75 sectors per second.

usage: thesis3do.py <tree> <sectors> <declared_blocks>
"""
import os
import struct
import sys


def read_comm(path):
    """Return (rate, channels, bits, frames, ssnd_bytes, codec) or None."""
    d = open(path, "rb").read()
    if len(d) < 12 or d[0:4] != b"FORM":
        return None
    if d[8:12] not in (b"AIFF", b"AIFC"):
        return None
    off = 12
    comm = ssnd = None
    while off + 8 <= len(d):
        cid = d[off:off + 4]
        clen = struct.unpack(">I", d[off + 4:off + 8])[0]
        if cid == b"COMM":
            comm = d[off + 8:off + 8 + clen]
        elif cid == b"SSND":
            # SSND payload is offset(4) + blocksize(4) + the samples
            ssnd = clen - 8
        off += 8 + clen + (clen & 1)
    if comm is None or ssnd is None:
        return None
    ch, frames, bits = struct.unpack(">HIH", comm[0:8])
    # 80-bit IEEE extended
    ext = comm[8:18]
    sign = ext[0] >> 7
    exp = ((ext[0] & 0x7F) << 8) | ext[1]
    mant = int.from_bytes(ext[2:10], "big")
    if exp == 0 and mant == 0:
        rate = 0.0
    else:
        rate = (-1.0) ** sign * mant * 2.0 ** (exp - 16383 - 63)
    codec = comm[18:22].decode("ascii", "replace") if len(comm) >= 22 else "NONE"
    return (rate, ch, bits, frames, ssnd, codec)


def hms(sec):
    m = int(sec // 60)
    return "%d:%05.2f" % (m, sec - 60 * m)


def main():
    if len(sys.argv) != 4:
        sys.stderr.write(__doc__)
        raise SystemExit(2)
    tree, sectors, declared = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

    files = []
    for dp, dn, fn in os.walk(tree):
        for f in fn:
            files.append(os.path.join(dp, f))
    files.sort()

    tree_bytes = sum(os.path.getsize(p) for p in files)

    rec = []
    for p in files:
        c = read_comm(p)
        if c:
            rec.append((p, os.path.getsize(p), c))

    if not rec:
        sys.stderr.write("thesis3do: no AIFF/AIFF-C containers found under %s\n" % tree)
        raise SystemExit(3)

    # denominators
    d_logical = sectors * 2448
    d_raw = sectors * 2352
    d_user = sectors * 2048
    d_declared = declared * 2048

    print("THE DENOMINATORS")
    print("  sectors in the track                    %12d" % sectors)
    print("  logical bytes in the container  x2448   %12d" % d_logical)
    print("  bytes extracted                 x2352   %12d" % d_raw)
    print("  user data in the track          x2048   %12d   <- published" % d_user)
    print("  user data the volume declares   x2048   %12d  (%d blocks)"
          % (d_declared, declared))
    print("  bytes in files (the tree)               %12d   = %.4f %% of user data"
          % (tree_bytes, 100.0 * tree_bytes / d_user))
    print()

    print("THE NUMERATORS")
    groups = {}
    for p, sz, c in rec:
        key = os.path.basename(os.path.dirname(p))
        groups.setdefault(key, []).append((p, sz, c))
    for k in sorted(groups):
        g = groups[k]
        fb = sum(x[1] for x in g)
        pb = sum(x[2][4] for x in g)
        secs = sum(x[2][3] / x[2][0] for x in g)
        print("  %-12s %3d files  file bytes %12d  SSND payload %12d  %s"
              % (k, len(g), fb, pb, hms(secs)))
    file_bytes = sum(x[1] for x in rec)
    ssnd_bytes = sum(x[2][4] for x in rec)
    total_secs = sum(x[2][3] / x[2][0] for x in rec)
    print("  %-12s %3d files  file bytes %12d  SSND payload %12d  %s"
          % ("TOTAL", len(rec), file_bytes, ssnd_bytes, hms(total_secs)))
    print("  container overhead                       %12d bytes = %.4f %% of the files"
          % (file_bytes - ssnd_bytes,
             100.0 * (file_bytes - ssnd_bytes) / file_bytes))
    print()

    print("THE THESIS, both numerators against all four denominators")
    print("  %-34s %10s %10s" % ("", "file bytes", "SSND"))
    for name, d in (("logical bytes x2448", d_logical),
                    ("bytes extracted x2352", d_raw),
                    ("user data in track x2048", d_user),
                    ("user data declared x2048", d_declared)):
        print("  %-34s %9.4f %% %8.4f %%"
              % (name, 100.0 * file_bytes / d, 100.0 * ssnd_bytes / d))
    print()

    print("THE RED BOOK QUESTION")
    print("  running time                            %s = %.2f s"
          % (hms(total_secs), total_secs))
    cdda_bytes = total_secs * 44100 * 2 * 2
    cdda_sectors = cdda_bytes / 2352.0
    print("  as CD-DA: 44,100 x 2 ch x 2 bytes       %12.0f bytes" % cdda_bytes)
    print("  at 2,352 bytes per sector               %12.0f sectors" % cdda_sectors)
    print("  75 sectors per second                   %12.2f s (identity check)"
          % (cdda_sectors / 75.0))
    print("  as a share of a 74-minute CD (333,000)  %12.4f %%"
          % (100.0 * cdda_sectors / 333000.0))
    print("  the whole pressing is                   %12d sectors" % sectors)
    print("  Red Book audio would need               %12.4f x this pressing"
          % (cdda_sectors / sectors))
    nonaudio = tree_bytes - file_bytes
    print()
    print("  everything on the disc that is NOT this audio %6d bytes = %d sectors"
          % (nonaudio, -(-nonaudio // 2048)))
    need = cdda_sectors + -(-nonaudio // 2048)
    print("  a hypothetical Red Book pressing         %12.0f sectors = %.4f %% of 333,000"
          % (need, 100.0 * need / 333000.0))
    print("  ... so it %s have fitted on a 74-minute CD."
          % ("WOULD" if need <= 333000 else "would NOT"))
    print("  compression achieved by SDX2             %12.4f : 1"
          % (cdda_bytes / ssnd_bytes))


if __name__ == "__main__":
    main()
