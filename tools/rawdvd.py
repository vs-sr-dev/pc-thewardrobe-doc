#!/usr/bin/env python3
"""rawdvd.py -- one sequential raw read of an optical volume, and nothing else.

A file-level copy of a disc preserves the files and throws away the volume:
the descriptors, the path tables, the directory extents, the gaps between
files and every sector the volume claims that no file claims. Those are the
part of this object that the leftovers chapter is about, so they have to come
off the medium as sectors.

This is a *second* pass over the drive and the session says so rather than
pretending the file copy was enough. It is cheap where the first pass was not:
the first pass was seek-bound at 6.6 MB/s across 103 files, this one is one
sequential run from LBA 0 to the end.

Two things it does that `dd` does not:

  * it reads in whole logical blocks and refuses a length that is not a
    multiple of the block size, because a short read at the end of an optical
    device is the normal failure mode and a truncated last sector is worse
    than a missing one;
  * it reports throughput and the exact sector count it got, so the image can
    be checked against the descriptor's own volume space size instead of
    being assumed complete.

    python tools/rawdvd.py \\\\.\\E: out.iso [--sectors N] [--block 2048]
    python tools/rawdvd.py \\\\.\\E: --probe          (read 4 sectors, print)
"""
import argparse
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("device")
    ap.add_argument("out", nargs="?")
    ap.add_argument("--block", type=int, default=2048)
    ap.add_argument("--sectors", type=int, default=0,
                    help="stop after N sectors; 0 means read to the end")
    ap.add_argument("--chunk", type=int, default=512,
                    help="sectors per read call")
    ap.add_argument("--probe", action="store_true",
                    help="read four sectors and print their first bytes")
    args = ap.parse_args()

    try:
        fh = open(args.device, "rb", buffering=0)
    except OSError as exc:
        print("cannot open %s: %s" % (args.device, exc))
        print("raw device access on Windows needs an elevated shell")
        return 2

    if args.probe:
        data = fh.read(args.block * 4)
        print("read %d bytes" % len(data))
        for i in range(0, len(data), args.block):
            sec = data[i:i + args.block]
            nz = sum(1 for b in sec if b)
            print("  LBA %d  nonzero %d/%d  first16 %s" %
                  (i // args.block, nz, len(sec), sec[:16].hex()))
        fh.close()
        return 0

    if not args.out:
        print("an output path is required unless --probe")
        return 2

    want = args.sectors * args.block if args.sectors else None
    got = 0
    t0 = time.time()
    with open(args.out, "wb") as out:
        while True:
            n = args.block * args.chunk
            if want is not None:
                n = min(n, want - got)
                if n <= 0:
                    break
            buf = fh.read(n)
            if not buf:
                break
            if len(buf) % args.block:
                print("SHORT READ: %d bytes is not a multiple of %d at offset %d"
                      % (len(buf), args.block, got))
                out.write(buf[:len(buf) - len(buf) % args.block])
                got += len(buf) - len(buf) % args.block
                break
            out.write(buf)
            got += len(buf)
    fh.close()
    dt = time.time() - t0
    print("device   %s" % args.device)
    print("bytes    %d" % got)
    print("sectors  %d of %d" % (got // args.block, args.block))
    print("seconds  %.1f" % dt)
    if dt > 0:
        print("rate     %.2f MB/s" % (got / dt / 1048576.0))
    print("residue  %d" % (got % args.block))
    return 0


if __name__ == "__main__":
    sys.exit(main())
