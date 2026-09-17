#!/usr/bin/env python3
"""Census one installed game directory: path, size, mtime, SHA-1, extension.

The object of this document is a live Steam installation of 4,769 files and
17,519,466,565 bytes on a drive this repository does not own. Nothing here
writes to it: the tool opens files read-only and its only output is the text
file named on the command line.

Two things it does that a `find`+`sha1sum` pipeline does not:

* it records the extension **case-folded and as spelt**, because 1,150 of this
  object's XML files are `.XML` and 175 are `.xml`, and every count in this
  document that says "XML" has to say which of the two it means;
* it emits the running total so the census can be checked against the
  distributor's own `SizeOnDisk` field without a second pass.

Hashing is optional and off by default, because the video is 14.5 GB and a
full pass costs minutes: `--sha1` turns it on.

Output is TSV, one line per file, sorted by path:

    sha1 (or '-')  size  mtime_utc  ext_as_spelt  relative/path

Usage:  python tools/instcensus.py <install_dir> <out.txt> [--sha1]
"""
import datetime
import hashlib
import os
import sys


def sha1_of(path, buf=1 << 20):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        while True:
            b = f.read(buf)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def main(root, out, want_sha1=False):
    rows = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            try:
                st = os.stat(full)
            except OSError as e:
                sys.stderr.write("!! stat failed %s: %s\n" % (rel, e))
                continue
            ext = os.path.splitext(name)[1]
            digest = "-"
            if want_sha1:
                try:
                    digest = sha1_of(full)
                except OSError as e:
                    sys.stderr.write("!! read failed %s: %s\n" % (rel, e))
                    digest = "!"
            mtime = datetime.datetime.fromtimestamp(
                st.st_mtime, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            rows.append("%s\t%d\t%s\t%s\t%s" % (digest, st.st_size, mtime, ext, rel))
            total += st.st_size
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(rows) + "\n")
    sys.stderr.write("%d files, %d bytes -> %s\n" % (len(rows), total, out))
    print("%d files, %d bytes" % (len(rows), total))


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    main(args[0], args[1], "--sha1" in sys.argv)
