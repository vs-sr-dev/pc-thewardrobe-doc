#!/usr/bin/env python3
"""discinfo.py -- what the drive says the disc physically IS.

The ISO 9660 descriptors describe the *image*, not the *medium*: a burned
copy of a pressed master carries identical descriptors, so nothing in the
file system can tell the two apart. Only the drive can, and it will answer
three different ways. This asks all three and prints them side by side,
because two commands agreeing is a measurement and one command is a claim.

  1. **MMC GET CONFIGURATION** through the CD-ROM class driver
     (`IOCTL_CDROM_GET_CONFIGURATION`) -- current profile: 0x10 is DVD-ROM
     and pressed, 0x11 is DVD-R, 0x1B is DVD+R, and so on.
  2. **The DVD physical format descriptor** (`IOCTL_DVD_READ_STRUCTURE`),
     whose layer-type field says `embossed` for moulded pits and
     `recordable` for dye.
  3. The same two MMC commands sent as **raw SCSI pass-through**
     (`IOCTL_SCSI_PASS_THROUGH_DIRECT`), which frequently works when the
     class-driver IOCTLs above return ERROR_NOT_SUPPORTED -- USB bridges and
     some virtual drives refuse the cooked calls and pass the raw ones.

ON ERROR 50. `ERROR_NOT_SUPPORTED` from these IOCTLs means one of two things
and the tool must not confuse them: **unelevated**, the call is refused
because pass-through requires administrator rights; **elevated**, the call is
refused because the *device* does not implement it. This tool checks whether
it is elevated and says which it is, because an earlier version printed
"needs elevation" unconditionally and was wrong the moment somebody ran it
as administrator.

    python tools/discinfo.py E:            (run it elevated)
"""

import ctypes
import ctypes.wintypes as w
import struct
import sys

PROFILES = {
    0x08: "CD-ROM              -- PRESSED",
    0x09: "CD-R                -- recordable",
    0x0A: "CD-RW               -- rewritable",
    0x10: "DVD-ROM             -- PRESSED",
    0x11: "DVD-R sequential    -- recordable",
    0x12: "DVD-RAM",
    0x13: "DVD-RW restricted overwrite",
    0x14: "DVD-RW sequential",
    0x15: "DVD-R DL sequential -- recordable",
    0x16: "DVD-R DL jump       -- recordable",
    0x17: "DVD-RW DL",
    0x1A: "DVD+RW",
    0x1B: "DVD+R               -- recordable",
    0x2A: "DVD+RW DL",
    0x2B: "DVD+R DL            -- recordable",
    0x40: "BD-ROM              -- PRESSED",
    0x41: "BD-R SRM",
    0x43: "BD-RE",
}

BOOKS = {0: "DVD-ROM -- PRESSED", 1: "DVD-RAM", 2: "DVD-R", 3: "DVD-RW",
         4: "HD DVD-ROM", 9: "DVD+RW", 10: "DVD+R", 13: "DVD+RW DL",
         14: "DVD+R DL"}

LAYER = {1: "embossed (moulded pits -- PRESSED)",
         2: "recordable (dye -- burned)",
         4: "rewritable"}


class SPTD(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ushort),
                ("ScsiStatus", ctypes.c_ubyte),
                ("PathId", ctypes.c_ubyte),
                ("TargetId", ctypes.c_ubyte),
                ("Lun", ctypes.c_ubyte),
                ("CdbLength", ctypes.c_ubyte),
                ("SenseInfoLength", ctypes.c_ubyte),
                ("DataIn", ctypes.c_ubyte),
                ("DataTransferLength", ctypes.c_ulong),
                ("TimeOutValue", ctypes.c_ulong),
                ("DataBuffer", ctypes.c_void_p),
                ("SenseInfoOffset", ctypes.c_ulong),
                ("Cdb", ctypes.c_ubyte * 16)]


class SPTDWB(ctypes.Structure):
    _fields_ = [("sptd", SPTD), ("filler", ctypes.c_ulong),
                ("sense", ctypes.c_ubyte * 32)]


def main():
    drive = (sys.argv[1] if len(sys.argv) > 1 else "E:").rstrip(":\\/")
    path = r"\\.\%s:" % drive
    k = ctypes.windll.kernel32
    INVALID = ctypes.c_void_p(-1).value
    elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
    # pass-through needs write access
    h = k.CreateFileW(path, 0xC0000000 if elevated else 0x80000000,
                      3, None, 3, 0, None)
    if h == INVALID:
        h = k.CreateFileW(path, 0x80000000, 3, None, 3, 0, None)
    if h == INVALID:
        sys.exit("cannot open %s: error %d" % (path, ctypes.GetLastError()))

    def ioctl(code, inbuf, outlen):
        out = ctypes.create_string_buffer(outlen)
        ret = w.DWORD()
        ok = k.DeviceIoControl(h, code, inbuf, len(inbuf) if inbuf else 0,
                               out, outlen, ctypes.byref(ret), None)
        return bool(ok), out.raw[:ret.value], ctypes.GetLastError()

    def why(err):
        if err != 50:
            return "error %d" % err
        return ("error 50 ERROR_NOT_SUPPORTED -- running elevated, so this is "
                "the DEVICE refusing, not a permission problem" if elevated
                else "error 50 ERROR_NOT_SUPPORTED -- not elevated; re-run as "
                     "administrator")

    print("drive            : %s" % path)
    print("running elevated : %s" % ("yes" if elevated else "NO"))
    print()

    got = []

    print("=== 1. MMC current profile, via the class driver ===")
    ok, d, err = ioctl(0x00024044, struct.pack("<II", 0, 1), 4096)
    if ok and len(d) >= 8:
        _len, _r, cur = struct.unpack_from(">IHH", d, 0)
        print("  profile 0x%02X : %s" % (cur, PROFILES.get(cur, "unknown")))
        got.append(("class-driver profile", PROFILES.get(cur, "unknown")))
    else:
        print("  FAILED, %s" % why(err))

    print()
    print("=== 2. DVD physical format descriptor, via the class driver ===")
    ok, d, err = ioctl(0x00560028, struct.pack("<qIBBH", 0, 0, 0, 0, 0), 2048)
    if ok and len(d) >= 8:
        b = d[4:]
        book = b[0] >> 4
        ltype = b[2] & 0x0F
        names = [v for kk, v in LAYER.items() if ltype & kk] or ["unknown"]
        print("  book type  : %d  %s" % (book, BOOKS.get(book, "unknown")))
        print("  layers     : %d" % (((b[2] >> 5) & 3) + 1))
        print("  layer type : 0x%X  %s" % (ltype, ", ".join(names)))
        got.append(("physical descriptor", BOOKS.get(book, "unknown")))
    else:
        print("  FAILED, %s" % why(err))

    print()
    print("=== 3. the same two, as raw SCSI pass-through ===")
    if not elevated:
        print("  skipped -- pass-through needs administrator rights")
    else:
        # GET CONFIGURATION (0x46), RT=1 (current), feature 0
        for cdb, name, parse in (
            (bytes([0x46, 0x01, 0, 0, 0, 0, 0, 0x00, 0x20, 0]),
             "GET CONFIGURATION", "profile"),
            (bytes([0xAD, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x14, 0]),
             "READ DVD STRUCTURE", "physical"),
        ):
            buf = ctypes.create_string_buffer(4096)
            p = SPTDWB()
            p.sptd.Length = ctypes.sizeof(SPTD)
            p.sptd.CdbLength = len(cdb)
            p.sptd.SenseInfoLength = 32
            p.sptd.DataIn = 1                      # SCSI_IOCTL_DATA_IN
            p.sptd.DataTransferLength = 4096
            p.sptd.TimeOutValue = 10
            p.sptd.DataBuffer = ctypes.cast(buf, ctypes.c_void_p)
            p.sptd.SenseInfoOffset = SPTDWB.sense.offset
            for i, c in enumerate(cdb):
                p.sptd.Cdb[i] = c
            ret = w.DWORD()
            ok = k.DeviceIoControl(h, 0x0004D014, ctypes.byref(p),
                                   ctypes.sizeof(p), ctypes.byref(p),
                                   ctypes.sizeof(p), ctypes.byref(ret), None)
            if not ok:
                print("  %-20s FAILED, %s" % (name, why(ctypes.GetLastError())))
                continue
            if p.sptd.ScsiStatus:
                print("  %-20s SCSI status %d, sense %s"
                      % (name, p.sptd.ScsiStatus,
                         bytes(p.sptd.sense[:14]).hex(" ")))
                continue
            raw = buf.raw
            if parse == "profile":
                cur = struct.unpack_from(">H", raw, 6)[0]
                print("  %-20s profile 0x%02X : %s"
                      % (name, cur, PROFILES.get(cur, "unknown")))
                got.append(("SPTI profile", PROFILES.get(cur, "unknown")))
            else:
                b = raw[4:]
                book = b[0] >> 4
                ltype = b[2] & 0x0F
                names = [v for kk, v in LAYER.items() if ltype & kk] or ["?"]
                print("  %-20s book type %d %s ; layer type 0x%X %s"
                      % (name, book, BOOKS.get(book, "?"), ltype,
                         ", ".join(names)))
                got.append(("SPTI physical", BOOKS.get(book, "unknown")))

    print()
    print("=== available on any drive, without any of the above ===")
    ok, d, err = ioctl(0x00024038, None, 1024)
    if ok and len(d) >= 4:
        print("  sessions      : first %d, last %d%s"
              % (d[2], d[3], "  (single session)" if d[2] == d[3] else ""))
    ok, d, err = ioctl(0x0007405C, None, 16)
    if ok and len(d) >= 8:
        n = struct.unpack_from("<q", d, 0)[0]
        print("  device length : %d bytes = %d sectors of 2048"
              % (n, n // 2048))

    print()
    if len(got) >= 2:
        # Compare on the medium each statement names, not on the label text.
        # The first version of this compared the formatted strings, whose
        # column padding differs between the two tables, and reported that
        # two identical answers disagreed. A comparison is only a measurement
        # if it compares the thing and not the presentation of the thing.
        def key(v):
            return " ".join(v.split()).split("--")[0].strip().upper()
        vals = {key(v) for _n, v in got}
        if len(vals) == 1:
            print("VERDICT: %d independent statements and they AGREE -- %s"
                  % (len(got), " ".join(got[0][1].split())))
        else:
            print("VERDICT: %d statements and they DISAGREE. Say so and stop."
                  % len(got))
            for n, v in got:
                print("   %-22s %s" % (n, " ".join(v.split())))
    elif len(got) == 1:
        print("VERDICT: only one statement (%s: %s). One command is a claim, "
              "not a measurement -- record it as unconfirmed."
              % got[0])
    else:
        print("VERDICT: the medium is NOT established. This drive answers "
              "none of the three. Record it as a stated gap; do not infer the "
              "medium from the file system, which cannot know.")
    k.CloseHandle(h)


if __name__ == "__main__":
    main()
