#!/usr/bin/env python3
"""patch_assoc.py -- teach assoc.Img to read a 2352-byte-per-sector image.

M3. `iso9660.py` grew a `RawSectorImage` when this branch first met a CloneCD
set, but `assoc.py` -- which `slack.py`, and anything else that wants raw
directory records, is built on -- never did. Its `Img.sector(lba)` seeks to
`lba * 2048` unconditionally. Pointed at a MODE2/2352 BIN it lands 304 bytes
further into the wrong place with every sector, and the first thing it hits is
an IndexError in `walk()`, which is at least honest.

The fix is the same one `iso9660.py` already makes: look for the twelve-byte
sync pattern at offset 0, and if it is there, treat the file as physical sectors
and hand back the user data of each -- offset 16 for Mode 1, offset 24 for Mode
2, decided per sector from that sector's own mode byte rather than from one
global assumption.

    python tools/patch_assoc.py tools/assoc.py
"""

import sys

OLD = '''class Img:
    def __init__(self, path):
        self.f = open(path, "rb")

    def sector(self, lba):
        self.f.seek(lba * SECTOR)
        d = self.f.read(SECTOR)
        return d if len(d) == SECTOR else None

    def read(self, lba, n):
        self.f.seek(lba * SECTOR)
        return self.f.read(n * SECTOR)'''

NEW = '''RAW_SECTOR = 2352
SYNC = b"\\x00" + b"\\xff" * 10 + b"\\x00"


class Img:
    """A CD image, cooked (2,048 bytes per sector) or raw (2,352).

    Raw framing is detected from the sync pattern at offset 0, not assumed from
    the extension: a MODE1/2352 or MODE2/2352 BIN begins 00 FF*10 00. When the
    file is raw, every sector's user data is located from that sector's own
    mode byte -- offset 16 for Mode 1, offset 24 for Mode 2 -- so a mixed-mode
    image reads correctly rather than plausibly. See M3 in
    docs/19-corrections.md."""

    def __init__(self, path):
        self.f = open(path, "rb")
        head = self.f.read(12)
        self.raw = head == SYNC
        self.stride = RAW_SECTOR if self.raw else SECTOR

    def _user(self, phys):
        if len(phys) < RAW_SECTOR:
            return None
        mode = phys[15]
        off = 24 if mode == 2 else 16
        return phys[off:off + SECTOR]

    def sector(self, lba):
        self.f.seek(lba * self.stride)
        d = self.f.read(self.stride)
        if len(d) < self.stride:
            return None
        return self._user(d) if self.raw else d

    def read(self, lba, n):
        self.f.seek(lba * self.stride)
        d = self.f.read(n * self.stride)
        if not self.raw:
            return d
        out = bytearray()
        for i in range(len(d) // RAW_SECTOR):
            u = self._user(d[i * RAW_SECTOR:(i + 1) * RAW_SECTOR])
            if u is None:
                break
            out += u
        return bytes(out)'''


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "tools/assoc.py"
    src = open(path, encoding="utf-8").read()
    if "RAW_SECTOR" in src:
        raise SystemExit("%s already raw-aware; refusing to patch twice" % path)
    n = src.count(OLD)
    if n != 1:
        raise SystemExit("PATTERN NOT FOUND (%d occurrences) in %s" % (n, path))
    open(path, "w", encoding="utf-8").write(src.replace(OLD, NEW, 1))
    print("ok   patched Img in %s" % path)


if __name__ == "__main__":
    main()
