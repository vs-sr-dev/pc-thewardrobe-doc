#!/usr/bin/env python3
"""thumbsdb.py -- what was in the folder the last time somebody looked at it.

`Thumbs.db` is Windows Explorer's thumbnail cache: an OLE2 compound file that
Explorer writes into a folder the first time that folder is shown in Thumbnails
view, holding one small JPEG per image plus a `Catalog` stream that names them.
Nobody puts it there on purpose and nobody looks at it, which is why it is
worth reading: it is a **snapshot of the folder's contents at the moment
somebody browsed it**, and it survives the deletion of the files it describes.

This disc carries ten of them. This tool reads each one's catalogue and sets it
against the files actually present in that directory, so the two questions that
matter get numbers:

  * which catalogued images are **still there** -- the cache agrees with the disc;
  * which catalogued images are **gone** -- named by the cache, absent from the
    directory, and therefore evidence of something that was in the folder and
    did not ship.

The `Catalog` stream layout, as Windows XP writes it:

     0   4  header length (16)
     4   4  version
     8   4  entry count
    12   4  thumbnail width/height
   then, per entry:
     0   4  entry length
     4   4  index, matching the stream name
     8   8  FILETIME of the source file
    16   n  the file name, UTF-16LE, NUL-terminated

Thumbnails are JPEG behind a 12-byte header; `--extract` writes them out.

    python tools/thumbsdb.py TREE
    python tools/thumbsdb.py TREE --extract _work/thumbs
    python tools/thumbsdb.py FILE --one
"""

import argparse
import datetime
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ole2 import CFB  # noqa: E402

ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
IMAGE_EXT = (".jpg", ".jpeg", ".gif", ".png", ".bmp", ".tif", ".tiff",
             ".ico", ".pcx", ".tga", ".psd", ".psp")


def filetime(v):
    if not v:
        return ""
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).strftime(
                    "%Y-%m-%d %H:%M:%S")
    except Exception:
        return "?"


class Thumbs:
    def __init__(self, path):
        self.path = path
        self.c = CFB(path)
        self.fat = self.c.fat()
        self.ents = self.c.entries()
        self.root = [e for e in self.ents if e["type"] == "root"][0]
        self.mini = b"".join(self.c.sector(s)
                             for s in self.c.chain(self.root["start"], self.fat))
        mf = b"".join(self.c.sector(s)
                      for s in self.c.chain(self.c.minifat, self.fat))
        self.mf = [struct.unpack_from("<I", mf, i)[0]
                   for i in range(0, len(mf), 4)]

    def stream(self, e):
        if e["size"] >= self.c.cutoff:
            data = b"".join(self.c.sector(s)
                            for s in self.c.chain(e["start"], self.fat))
            return data[:e["size"]]
        out = b""
        s = e["start"]
        while s not in (ENDOFCHAIN, FREESECT) and len(out) < e["size"]:
            out += self.mini[s * self.c.mssz:(s + 1) * self.c.mssz]
            s = self.mf[s]
        return out[:e["size"]]

    def catalog(self):
        cat = [e for e in self.ents if e["name"] == "Catalog"]
        if not cat:
            return []
        d = self.stream(cat[0])
        out = []
        # the header length is a 16-bit field, not a 32-bit one: the first four
        # bytes of a real catalogue are 10 00 07 00, i.e. length 16, version 7.
        # Reading it as a dword gives 0x00070010 and silently finds no entries.
        off = struct.unpack_from("<H", d, 0)[0] if len(d) >= 2 else 16
        if off < 8 or off > len(d):
            off = 16
        while off + 16 <= len(d):
            ln = struct.unpack_from("<I", d, off)[0]
            if ln < 17 or off + ln > len(d):
                break
            idx = struct.unpack_from("<I", d, off + 4)[0]
            ft = struct.unpack_from("<Q", d, off + 8)[0]
            raw = d[off + 16:off + ln]
            name = raw.decode("utf-16-le", "replace").split("\x00")[0]
            out.append((idx, name, filetime(ft)))
            off += ln
        return out

    def thumbs(self):
        return {e["name"]: e for e in self.ents if e["type"] == "stream"
                and e["name"] != "Catalog"}


def report(path, tree=None, extract=None):
    t = Thumbs(path)
    cat = t.catalog()
    rel = os.path.relpath(path, tree).replace(os.sep, "/") if tree else path
    folder = os.path.dirname(path)
    real = os.listdir(folder) if os.path.isdir(folder) else []
    present = {f.lower() for f in real}
    still, gone = [], []
    for _i, name, _ft in cat:
        if name.startswith("{") and name.endswith("}"):
            continue                     # the folder's own custom picture
        (still if name.lower() in present else gone).append(name)
    imgs = sorted(f for f in real if f.lower().endswith(IMAGE_EXT))
    print("%-46s %7d bytes   last written %s"
          % (rel, os.path.getsize(path), t.root["modified"] or t.root["created"]))
    print("   catalogued %d   thumbnails %d   images in the directory now %d"
          % (len(cat), len(t.thumbs()), len(imgs)))
    if still:
        print("   still present (%d): %s" % (len(still), ", ".join(still)))
    if gone:
        print("   NAMED BUT ABSENT (%d):" % len(gone))
        for g in gone:
            when = [c[2] for c in cat if c[1] == g]
            print("       %-52s %s" % (g, when[0] if when else ""))
    catalogued = {n.lower() for _i, n, _ft in cat}
    extra = [f for f in imgs if f.lower() not in catalogued]
    if extra:
        print("   present but not catalogued (%d): %s"
              % (len(extra), ", ".join(extra[:8])))
    if extract:
        os.makedirs(extract, exist_ok=True)
        for idx, name, _ft in cat:
            e = t.thumbs().get(str(idx))
            if not e:
                continue
            d = t.stream(e)
            j = d.find(b"\xff\xd8\xff")
            if j < 0:
                continue
            base = (rel.replace("/", "_") + "." + str(idx) + "."
                    + os.path.basename(name) + ".jpg")
            open(os.path.join(extract, base), "wb").write(d[j:])
    print()
    return len(cat), len(still), len(gone)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--one", action="store_true")
    ap.add_argument("--extract")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    if a.one:
        report(a.path, None, a.extract)
        return

    n = tc = ts = tg = 0
    total = 0
    for dp, _dn, fn in os.walk(a.path):
        for f in sorted(fn):
            if f.lower() != "thumbs.db":
                continue
            p = os.path.join(dp, f)
            n += 1
            total += os.path.getsize(p)
            c, s, g = report(p, a.path, a.extract)
            tc += c
            ts += s
            tg += g
    print("=" * 72)
    print("caches %d   bytes %d   catalogued names %d   still present %d   absent %d"
          % (n, total, tc, ts, tg))


if __name__ == "__main__":
    main()
