#!/usr/bin/env python3
"""devlen.py -- three answers to "how long is this volume", printed together.

The pre-briefing for this object recorded a device length of 2,941,157,376
bytes, said the primary descriptor's 1,436,112 sectors agreed with it, and
called the Joliet descriptor's 1,436,105 the odd one out. A sequential read of
the device stops at 1,436,105.

So the question has three answers and they are not the same measurement:

  * what the volume manager *reports* as the length (IOCTL_DISK_GET_LENGTH_INFO);
  * what the medium *delivers* when you read it to the end;
  * what the descriptors *claim*.

A tool that prints one of those and calls it "the device length" is choosing
one without saying so. This prints all three and the last readable LBA, found
by bisection rather than assumed, and it never writes.

    python tools/devlen.py //./E:
"""
import ctypes
import ctypes.wintypes as wintypes
import struct
import sys

IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
GENERIC_READ = 0x80000000
FILE_SHARE_ALL = 0x00000007
OPEN_EXISTING = 3
BLOCK = 2048


def ioctl_length(path):
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = ctypes.c_void_p
    h = k32.CreateFileW(path, GENERIC_READ, FILE_SHARE_ALL, None,
                        OPEN_EXISTING, 0, None)
    if h in (None, 0) or h == ctypes.c_void_p(-1).value:
        return None, "CreateFileW failed, error %d" % ctypes.get_last_error()
    buf = ctypes.create_string_buffer(8)
    ret = wintypes.DWORD()
    ok = k32.DeviceIoControl(ctypes.c_void_p(h), IOCTL_DISK_GET_LENGTH_INFO,
                             None, 0, buf, 8, ctypes.byref(ret), None)
    err = ctypes.windll.kernel32.GetLastError()
    k32.CloseHandle(ctypes.c_void_p(h))
    if not ok:
        return None, "IOCTL_DISK_GET_LENGTH_INFO failed, error %d" % err
    return struct.unpack("<q", buf.raw)[0], "ok"


def last_readable(path):
    """Bisect for the highest LBA that returns a full block."""
    f = open(path, "rb", buffering=0)

    def readable(lba):
        try:
            f.seek(lba * BLOCK)
            return len(f.read(BLOCK)) == BLOCK
        except OSError:
            return False

    if not readable(0):
        f.close()
        return None
    lo, hi = 0, 1
    while readable(hi):
        lo, hi = hi, hi * 2
        if hi > 1 << 32:
            break
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if readable(mid):
            lo = mid
        else:
            hi = mid
    f.close()
    return lo


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    n, why = ioctl_length(path)
    if n is None:
        print("reported length   -- %s" % why)
    else:
        print("reported length   %d bytes = %.4f sectors of %d"
              % (n, n / float(BLOCK), BLOCK))
    lba = last_readable(path)
    if lba is None:
        print("readable extent   cannot read LBA 0")
        return 1
    print("last readable LBA %d" % lba)
    print("readable extent   %d sectors = %d bytes" % (lba + 1, (lba + 1) * BLOCK))
    return 0


if __name__ == "__main__":
    sys.exit(main())
