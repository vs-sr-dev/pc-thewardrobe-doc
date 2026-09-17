#!/usr/bin/env python3
"""psystem.py -- read a UCSD p-System volume directory out of a flat image.

    python tools/psystem.py IMAGE                 # header, entries, extent audit
    python tools/psystem.py IMAGE --extract N DIR # write entry N's present blocks
    python tools/psystem.py IMAGE --extract-all DIR
    python tools/psystem.py IMAGE --blocks        # per-block allocation map
    python tools/psystem.py --refuse FILE...      # assert none is a p-System volume

THE FORMAT IS PUBLIC AND THIS TOOL SAYS SO.
The 26-byte directory record and the packed date word are documented in the
UCSD p-System / Apple Pascal literature. What arrived free from that definition
is the field layout below; what did NOT arrive free, and is derived here from
the bytes of this image, is every figure the tool prints.

    volume header, 26 bytes at block 2 offset 0
      0..1   dfirstblk   first block of the directory region (0)
      2..3   dlastblk    first block after it (6: two boot blocks + four
                         directory blocks)
      4..5   dvid kind   0
      6      length of the volume name, 7 max
      7..13  volume name (SEVEN bytes -- not fifteen)
     14..15  deovblk     blocks on the volume, AS DECLARED
     16..17  dnumfiles   number of entries following
     18..19  dloadtime
     20..21  dlastboot   packed date
     22..25  four reserved bytes

    file record, 26 bytes, repeated dnumfiles times
      0..1   dfirstblk   first block of the file
      2..3   dlastblk    first block AFTER the file (so length = last - first)
      4..5   filekind
      6      length of the name, 15 max
      7..21  name (FIFTEEN bytes; the tail is NOT cleared between writes and
                   holds whatever the previous entry left there)
     22..23  dlastbyte   bytes used in the file's last block
     24..25  packed date: month in bits 0..3, day in bits 4..8, year in 9..15

    2 + 2 + 2 + 1 + 15 + 2 + 2 = 26, residue 0.

THE EXTENT AUDIT IS THE POINT OF THIS TOOL AND IT IS NOT PART OF THE FORMAT.
A directory is arithmetic about itself: every dlastblk equals the next entry's
dfirstblk, the chain closes on deovblk, and none of that involves the length of
the file it is stored in. So this tool checks every extent twice -- once against
the volume the header declares and once against the image actually handed to
it -- and prints both columns. An extent that passes the first and fails the
second is a file the directory promises and the medium does not have.

Refuse-first, as with every reader in this box: validate() raises on six
grounds and --refuse asserts that an input is NOT a volume, so the reader can
be shown failing before any figure it produces is quoted.
"""
import argparse
import os
import struct
import sys

BLOCK = 512
DIRBLOCK = 2
RECORD = 26

# UCSD filekind, from the published definition.
KIND = {
    0: "untypedfile",
    1: "xdskfile",
    2: "codefile",
    3: "textfile",
    4: "infofile",
    5: "datafile",
    6: "graffile",
    7: "fotofile",
    8: "securedir",
}


class NotAVolume(Exception):
    """Refusal, carrying the reason."""


def unpack_date(word):
    """month bits 0..3, day bits 4..8, year bits 9..15 -- the published packing.

    Returned raw. No repair, no windowing of the year, no clamping: a record
    that decodes to an impossible date is a finding about the record and
    silently fixing it would destroy the finding.
    """
    return word & 0xF, (word >> 4) & 0x1F, (word >> 9) & 0x7F


def validate(data, path):
    if len(data) < (DIRBLOCK + 1) * BLOCK:
        raise NotAVolume("%s: %d bytes, too short to hold block 2" % (path, len(data)))
    if len(data) % BLOCK:
        raise NotAVolume("%s: %d bytes is not a whole number of 512-byte blocks"
                         % (path, len(data)))
    off = DIRBLOCK * BLOCK
    first, last, kind = struct.unpack_from("<3H", data, off)
    vlen = data[off + 6]
    eov, nfiles = struct.unpack_from("<2H", data, off + 14)
    if first != 0:
        raise NotAVolume("%s: dfirstblk is %d, not 0" % (path, first))
    if not (2 <= last <= 32):
        raise NotAVolume("%s: dlastblk is %d, outside 2..32" % (path, last))
    if not (1 <= vlen <= 7):
        raise NotAVolume("%s: volume-name length byte is %d, outside 1..7"
                         % (path, vlen))
    name = data[off + 7:off + 7 + vlen]
    if not all(0x20 <= c < 0x7F for c in name):
        raise NotAVolume("%s: volume name %r is not printable" % (path, name))
    if not (1 <= eov <= 0xFFFF):
        raise NotAVolume("%s: deovblk is %d" % (path, eov))
    # 4 directory blocks of 512 hold 2048/26 = 78 records, one of which is the
    # header, so 77 files is the format's own ceiling.
    if nfiles > 77:
        raise NotAVolume("%s: dnumfiles is %d, above the 77 the four "
                         "directory blocks can hold" % (path, nfiles))
    return dict(dfirstblk=first, dlastblk=last, kind=kind,
                name=name.decode("ascii"), eovblk=eov, nfiles=nfiles,
                dloadtime=struct.unpack_from("<H", data, off + 18)[0],
                dlastboot=struct.unpack_from("<H", data, off + 20)[0],
                reserved=data[off + 22:off + 26])


def entries(data, vol):
    off = DIRBLOCK * BLOCK
    out = []
    for i in range(1, vol["nfiles"] + 1):
        b = off + i * RECORD
        first, last, kind = struct.unpack_from("<3H", data, b)
        nlen = data[b + 6]
        raw = data[b + 7:b + 22]
        lastbyte, date = struct.unpack_from("<2H", data, b + 22)
        out.append(dict(n=i, first=first, last=last, kind=kind,
                        namelen=nlen, name=raw[:nlen].decode("latin-1"),
                        tail=raw[nlen:], lastbyte=lastbyte, dateword=date,
                        blocks=last - first))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image", nargs="+")
    ap.add_argument("--refuse", action="store_true")
    ap.add_argument("--extract", type=int)
    ap.add_argument("--extract-all")
    ap.add_argument("--blocks", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    if args.refuse:
        accepted = []
        for path in args.image:
            data = open(path, "rb").read()
            try:
                validate(data, path)
                accepted.append(path)
                print("ACCEPTED (and --refuse said it would not be): %s" % path)
            except NotAVolume as why:
                print("REFUSED: %s" % why)
        if accepted:
            sys.exit("--refuse: %d of %d inputs were accepted"
                     % (len(accepted), len(args.image)))
        return 0

    if len(args.image) != 1:
        sys.exit("one image at a time unless --refuse")
    path = args.image[0]
    data = open(path, "rb").read()
    try:
        vol = validate(data, path)
    except NotAVolume as why:
        sys.exit("REFUSED: %s" % why)

    present = len(data) // BLOCK
    ents = entries(data, vol)

    print("image             : %s" % os.path.basename(path))
    print("bytes             : %d" % len(data))
    print("blocks PRESENT    : %d" % present)
    print("volume name       : %s   (%d characters)" % (vol["name"], len(vol["name"])))
    print("directory region  : blocks %d..%d  (%d blocks: 2 boot + %d directory)"
          % (vol["dfirstblk"], vol["dlastblk"] - 1, vol["dlastblk"],
             vol["dlastblk"] - 2))
    print("blocks DECLARED   : %d   = %d bytes" % (vol["eovblk"], vol["eovblk"] * BLOCK))
    print("files declared    : %d" % vol["nfiles"])
    m, d, y = unpack_date(vol["dlastboot"])
    print("dlastboot         : 0x%04X -> %02d/%02d/%02d" % (vol["dlastboot"], m, d, y))
    print("dloadtime         : 0x%04X" % vol["dloadtime"])
    print("reserved 22..25   : %s" % " ".join("%02x" % c for c in vol["reserved"]))
    print()
    print("THE TWO DENOMINATORS THIS HEADER CREATES")
    print("  declared        : %d blocks = %d bytes" % (vol["eovblk"], vol["eovblk"] * BLOCK))
    print("  present         : %d blocks = %d bytes" % (present, present * BLOCK))
    print("  absent          : %d blocks = %d bytes"
          % (vol["eovblk"] - present, (vol["eovblk"] - present) * BLOCK))
    print()

    hdr = ("  #  name             kind        first  next  blocks     bytes  "
           "lastb   date      chain  ON MEDIUM")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    expect = vol["dlastblk"]
    alloc = 0
    short = []
    for e in ents:
        m, d, y = unpack_date(e["dateword"])
        chain = "ok" if e["first"] == expect else "GAP %+d" % (e["first"] - expect)
        expect = e["last"]
        nbytes = (e["blocks"] - 1) * BLOCK + e["lastbyte"] if e["blocks"] else 0
        alloc += e["blocks"]
        if e["last"] <= present:
            med = "all %d" % e["blocks"]
        elif e["first"] >= present:
            med = "NONE of %d" % e["blocks"]
            short.append(e)
        else:
            med = "%d of %d  MISSING %d" % (present - e["first"], e["blocks"],
                                            e["last"] - present)
            short.append(e)
        print("  %2d  %-15s  %-11s %5d %5d  %6d %9d  %5d  %02d/%02d/%02d  %-6s %s"
              % (e["n"], e["name"], KIND.get(e["kind"], "kind %d" % e["kind"]),
                 e["first"], e["last"], e["blocks"], nbytes, e["lastbyte"],
                 m, d, y, chain, med))

    print()
    print("EXTENT AUDIT -- the directory's arithmetic against the medium's")
    print("  first free block after the last entry : %d" % expect)
    print("  volume header says the volume ends at : %d" % vol["eovblk"])
    print("  agreement                             : %s"
          % ("YES" % () if expect == vol["eovblk"] else "no"))
    print("  blocks allocated to files             : %d" % alloc)
    print("  + directory region                    : %d" % vol["dlastblk"])
    print("  = accounted for, of the DECLARED       %d of %d, residue %d"
          % (alloc + vol["dlastblk"], vol["eovblk"],
             vol["eovblk"] - alloc - vol["dlastblk"]))
    print("  entries that do NOT fit on this image : %d of %d"
          % (len(short), len(ents)))
    for e in short:
        print("      %-15s wants blocks %d..%d; the image ends at %d"
              % (e["name"], e["first"], e["last"] - 1, present - 1))
    if not short:
        print("      (none -- and if this line prints on an image whose header")
        print("       declares more blocks than the file holds, the audit is broken)")

    if args.blocks:
        print()
        owner = ["free"] * present
        for b in range(min(vol["dlastblk"], present)):
            owner[b] = "boot/dir"
        for e in ents:
            for b in range(e["first"], min(e["last"], present)):
                owner[b] = e["name"]
        run_start, run_name = 0, owner[0]
        print("BLOCK MAP over the %d present blocks" % present)
        for b in range(1, present + 1):
            cur = owner[b] if b < present else None
            if cur != run_name:
                print("  %4d..%-4d  %4d blocks  %s" % (run_start, b - 1,
                                                       b - run_start, run_name))
                run_start, run_name = b, cur
        free = owner.count("free")
        print("  free blocks on the image: %d = %d bytes" % (free, free * BLOCK))

    if args.extract is not None or args.extract_all:
        outdir = args.extract_all or args.out
        if not outdir:
            sys.exit("--extract needs --out DIR")
        os.makedirs(outdir, exist_ok=True)
        want = ents if args.extract_all else [e for e in ents if e["n"] == args.extract]
        if not want:
            sys.exit("no such entry")
        for e in want:
            lo = e["first"] * BLOCK
            hi = min(e["last"], present) * BLOCK
            if hi <= lo:
                print("  %-15s SKIPPED, none of it is on this image" % e["name"])
                continue
            blob = data[lo:hi]
            dest = os.path.join(outdir, e["name"])
            open(dest, "wb").write(blob)
            print("  %-15s %7d bytes -> %s%s"
                  % (e["name"], len(blob), dest,
                     "   TRUNCATED" if e["last"] > present else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
