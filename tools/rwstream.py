#!/usr/bin/env python3
"""rwstream.py -- read the twelve-byte RenderWare chunk header, and one level in.

A RenderWare stream is a tree of chunks and every chunk begins with the same
twelve bytes:

    u32 type      the chunk identifier
    u32 size      the size of the chunk BODY, not counting these twelve bytes
    u32 version   a packed library ID

The header is public and so is the version packing.  For a library ID with any
of its top sixteen bits set, the unpacking is

    version = ((id >> 14) & 0x3FF00) + 0x30000 | ((id >> 16) & 0x3F)
    build   = id & 0xFFFF

and the four nibbles of `version` read out as the RenderWare release number.
Nothing here decodes a payload: the tool validates the header, walks one level
down, and reports what the children are.  It is validated on a file that MUST
fail before it is run on anything else -- pass --selftest.

    python tools/rwstream.py --validate <file>
    python tools/rwstream.py --census <dir> [--ext .rws]
    python tools/rwstream.py --selftest <a file that is not a RenderWare stream>

The named fields under --census are those of chunk type 0x0000080D as it
appears in this object, derived from the bytes of two files and then checked
against every file in the tree.  They are printed with their offsets so the
derivation can be argued with.
"""
import argparse
import collections
import os
import struct
import sys

MAGIC_SIZE = 12


def unpack_version(libid):
    """The published RenderWare library-ID unpacking. Returns (text, build)."""
    if libid & 0xFFFF0000:
        v = ((libid >> 14) & 0x3FF00) + 0x30000 | ((libid >> 16) & 0x3F)
        build = libid & 0xFFFF
        text = "%d.%d.%d.%d" % ((v >> 16) & 0xF, (v >> 12) & 0xF,
                                (v >> 8) & 0xF, v & 0xFF)
        return text, build, v
    # the pre-3.1 packing: the ID is the version shifted left by eight
    return "%d.%d" % ((libid >> 8) & 0xF, (libid >> 4) & 0xF), None, libid


def read_header(blob, off=0):
    if off + MAGIC_SIZE > len(blob):
        return None
    return struct.unpack_from("<III", blob, off)


def walk(blob, off, end, depth=0, out=None, maxdepth=2):
    """Return a list of (depth, offset, type, size, version) for the chunks
    that tile [off, end).  Stops and records a defect if they do not."""
    if out is None:
        out = []
    while off < end:
        h = read_header(blob, off)
        if h is None:
            out.append((depth, off, None, None, None))
            return out
        t, s, v = h
        out.append((depth, off, t, s, v))
        nxt = off + MAGIC_SIZE + s
        if nxt > end or s < 0:
            out.append((depth, off, "OVERRUN", nxt, end))
            return out
        if depth < maxdepth and s >= MAGIC_SIZE:
            walk(blob, off + MAGIC_SIZE, nxt, depth + 1, out, maxdepth)
        off = nxt
    return out


# Fields of the 0x0000080E struct, offsets from the START OF ITS BODY.
#
# The struct is a serialised C++ object graph -- it still contains the build
# machine's heap pointers -- and it is NOT laid out at constant offsets.  It
# carries three fixed-width name fields, and the width of a name field varies
# from file to file.  The first word of the struct is the size of the
# descriptor, so with three names of width w the width is recoverable:
#
#     w = 16 + (word0 - 264) / 3
#
# and every offset after the k-th name shifts by k * (w - 16).  That rule is
# not asserted here, it is CHECKED: the field called "data bytes" must equal
# the size of the 0x0000080F chunk read from its own header, on every file, or
# the file is reported as not obeying the layout.
BASE_NAME = 16          # the narrowest name field seen
BASE_WORD0 = 264        # word0 when the name field is BASE_NAME wide
NAMES_IN_STRUCT = 3

FIELDS = [
    ("+0    descriptor size", 0, 0),
    ("+16   count", 16, 0),
    ("+48   grain a", 48, 0),
    ("+52   span", 52, 0),
    ("+56   grain b", 56, 0),
    ("+120  data bytes", 120, 1),
    ("+128  length field", 128, 1),
    ("+176  flags", 176, 2),
    ("+180  span 2", 180, 2),
    ("+188  pair", 188, 2),
    ("+192  field192", 192, 2),
    ("+196  field196", 196, 2),
    ("+204  sample rate", 204, 2),
    ("+212  length field 2", 212, 2),
    ("+216  channels and unit", 216, 2),
]


def one(path):
    n = os.path.getsize(path)
    with open(path, "rb") as fh:
        blob = fh.read(4096)
    h = read_header(blob)
    if h is None:
        return None, "shorter than twelve bytes"
    t, s, v = h
    if t != 0x0000080D:
        return None, "outer chunk is 0x%08X, not 0x0000080D" % t
    if MAGIC_SIZE + s != n:
        return None, "12 + %d = %d, file is %d" % (s, 12 + s, n)
    kids = walk(blob, MAGIC_SIZE, min(n, len(blob)), maxdepth=0)
    kids = [k for k in kids if k[2] is not None and not isinstance(k[2], str)]
    rec = {"size": n, "type": t, "declared": s, "version": v,
           "children": [(k[2], k[3]) for k in kids]}
    # the struct child
    if kids and kids[0][2] == 0x0000080E:
        base = kids[0][1] + MAGIC_SIZE
        word0 = struct.unpack_from("<I", blob, base)[0]
        if (word0 - BASE_WORD0) % NAMES_IN_STRUCT:
            rec["name width"] = None
            return rec, None
        w = BASE_NAME + (word0 - BASE_WORD0) // NAMES_IN_STRUCT
        if w < BASE_NAME or w > 512:
            rec["name width"] = None
            return rec, None
        d = w - BASE_NAME
        rec["name width"] = w
        for label, off, k in FIELDS:
            o = base + off + k * d
            if o + 4 <= len(blob):
                rec[label] = struct.unpack_from("<I", blob, o)[0]
        nm = blob[base + 80:base + 80 + w]
        z = nm.find(b"\x00")
        rec["name"] = nm[:z if z >= 0 else w].decode("latin-1")
        rec["name tail"] = nm[z + 1:].decode("latin-1") if 0 <= z < w - 1 else ""
    return rec, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate")
    ap.add_argument("--selftest")
    ap.add_argument("--census")
    ap.add_argument("--ext", default=".rws")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--audio", help="read every payload and measure it")
    ap.add_argument("--bits", type=int, default=4,
                    help="bits per sample assumed when converting bytes to seconds")
    a = ap.parse_args()

    if a.selftest:
        rec, err = one(a.selftest)
        if rec is not None:
            sys.exit("SELFTEST FAILED: %s parsed as a RenderWare stream" % a.selftest)
        print("selftest OK: %s refused -- %s" % (os.path.basename(a.selftest), err))
        print()

    if a.validate:
        n = os.path.getsize(a.validate)
        with open(a.validate, "rb") as fh:
            blob = fh.read(min(n, 1 << 20))
        print("file        : %s  %d bytes" % (os.path.basename(a.validate), n))
        t, s, v = read_header(blob)
        text, build, unp = unpack_version(v)
        print("outer chunk : type 0x%08X  size %d  version 0x%08X" % (t, s, v))
        print("  closure   : 12 + %d = %d ; file is %d -> %s"
              % (s, 12 + s, n, "OK" if 12 + s == n else "MISMATCH"))
        print("  version   : 0x%08X -> unpacked 0x%05X -> RenderWare %s, build 0x%04X"
              % (v, unp, text, build))
        print("children (one level down):")
        for depth, off, ct, cs, cv in walk(blob, 12, min(n, len(blob)), maxdepth=0):
            if isinstance(ct, str):
                print("   DEFECT %s at +%d" % (ct, off))
                continue
            print("   +%-8d type 0x%08X  size %-10d  version 0x%08X  ends +%d"
                  % (off, ct, cs, cv, off + 12 + cs))
        rec, err = one(a.validate)
        if rec:
            print("named fields of the 0x0000080E struct:")
            print("   name field width  : %s" % rec.get("name width"))
            for label, _, _k in FIELDS:
                if label in rec:
                    print("   %-20s 0x%08X %12d" % (label, rec[label], rec[label]))
            print("   %-20s %r  (tail of the %s-byte field: %r)"
                  % ("+80   name", rec.get("name"), rec.get("name width"),
                     rec.get("name tail")))
        print()

    if a.census:
        files = []
        for dirpath, dirnames, filenames in os.walk(a.census):
            dirnames.sort()
            for fn in sorted(filenames):
                if fn.lower().endswith(a.ext):
                    files.append(os.path.join(dirpath, fn))
        ok = bad = 0
        types = collections.Counter()
        versions = collections.Counter()
        kids = collections.Counter()
        rates = collections.Counter()
        f176 = collections.Counter()
        f188 = collections.Counter()
        f216 = collections.Counter()
        databytes = 0
        structbytes = 0
        laidout = 0
        structsize = collections.Counter()
        counts = collections.Counter()
        offlayout = []
        widths = collections.Counter()
        totbytes = 0
        mod2048 = 0
        tails = collections.Counter()
        failures = []
        for f in files:
            rec, err = one(f)
            totbytes += os.path.getsize(f)
            if os.path.getsize(f) % 2048 == 0:
                mod2048 += 1
            if rec is None:
                bad += 1
                failures.append((f, err))
                continue
            ok += 1
            types[rec["type"]] += 1
            versions[rec["version"]] += 1
            kids[tuple(t for t, s in rec["children"])] += 1
            kid = dict(rec["children"])
            databytes += kid.get(0x0000080F, 0)
            structbytes += kid.get(0x0000080E, 0)
            structsize[kid.get(0x0000080E, 0)] += 1
            widths[rec.get("name width")] += 1
            if rec.get("+120  data bytes") == kid.get(0x0000080F):
                laidout += 1
                rates[rec["+204  sample rate"]] += 1
                f176[rec["+176  flags"]] += 1
                f188[rec["+188  pair"]] += 1
                f216[rec["+216  channels and unit"]] += 1
                counts[rec["+16   count"]] += 1
            else:
                offlayout.append((os.path.basename(f), rec.get("+120  data bytes"),
                                  kid.get(0x0000080F)))
            tails[bool(rec.get("name tail", "").strip("\x00"))] += 1
        print("census of %s over %d files matching %s" % (a.census, len(files), a.ext))
        print("   parsed            : %d   refused: %d" % (ok, bad))
        print("   bytes             : %d" % totbytes)
        print("   size mod 2048 == 0: %d of %d" % (mod2048, len(files)))
        for label, c in (("outer type", types), ("version word", versions)):
            print("   %-18s: %s" % (label,
                  ", ".join("0x%08X x%d" % (k, v) for k, v in c.most_common())))
        print("   child sequences   :")
        for k, v in kids.most_common():
            print("        %-40s x%d" % (" ".join("0x%08X" % t for t in k), v))
        print("   0x080E struct size: %s"
              % ", ".join("%d x%d" % (k, v) for k, v in structsize.most_common(6)))
        print("   files whose +120 equals the 0x080F size (named offsets hold): %d of %d"
              % (laidout, ok))
        print("   name field width  : %s"
              % ", ".join("%s x%d" % (k, v) for k, v in widths.most_common(8)))
        print("   +16  count        : %s"
              % ", ".join("%d x%d" % (k, v) for k, v in counts.most_common(8)))
        print("   +204 sample rate  : %s"
              % ", ".join("%d x%d" % (k, v) for k, v in rates.most_common()))
        print("   +176 flags        : %s"
              % ", ".join("0x%X x%d" % (k, v) for k, v in f176.most_common(8)))
        print("   +188 pair         : %s"
              % ", ".join("0x%08X x%d" % (k, v) for k, v in f188.most_common(8)))
        print("   +216 field216     : %s"
              % ", ".join("0x%X x%d" % (k, v) for k, v in f216.most_common(8)))
        print("   sum of 0x080F payload  : %d" % databytes)
        print("   sum of 0x080E struct   : %d" % structbytes)
        print("   chunk headers (3 x 12) : %d" % (36 * ok))
        print("   accounted              : %d of %d, residue %d"
              % (databytes + structbytes + 36 * ok, totbytes,
                 totbytes - databytes - structbytes - 36 * ok))
        print("   payload share of the .rws mass: %.4f %%"
              % (100.0 * databytes / totbytes))
        if offlayout:
            print("   files where the named offsets do NOT hold: %d, first 5:" % len(offlayout))
            for nm, a1, b1 in offlayout[:5]:
                print("        %-28s +120=%s  0x080F=%s" % (nm, a1, b1))
        print("   16-byte name field with rubbish after the NUL : %d of %d"
              % (tails[True], tails[True] + tails[False]))
        for f, err in failures[:20]:
            print("   REFUSED %s -- %s" % (f, err))

    if a.audio:
        files = []
        for dirpath, dirnames, filenames in os.walk(a.audio):
            dirnames.sort()
            for fn in sorted(filenames):
                if fn.lower().endswith(a.ext):
                    files.append(os.path.join(dirpath, fn))
        branches = collections.defaultdict(lambda: {
            "files": 0, "bytes": 0, "payload": 0, "voiced": 0,
            "rates": collections.Counter(), "chan": collections.Counter(),
            "nib": collections.Counter(), "lag": [0] * 9, "lagn": 0})
        for f in files:
            n = os.path.getsize(f)
            with open(f, "rb") as fh:
                blob = fh.read()
            off, pay = 12, b""
            while off < n:
                ct, cs, cv = struct.unpack_from("<III", blob, off)
                if ct == 0x0000080F:
                    pay = blob[off + 12:off + 12 + cs]
                    break
                off += 12 + cs
            rec, err = one(f)
            key = os.path.basename(os.path.dirname(f))
            if os.path.normpath(os.path.dirname(f)) == os.path.normpath(a.audio):
                key = "(top)"
            b = branches[key]
            b["files"] += 1
            b["bytes"] += n
            b["payload"] += len(pay)
            b["voiced"] += len(pay.rstrip(b"\x00"))
            ch = rec.get("+216  channels and unit")
            rt = rec.get("+204  sample rate")
            b["rates"][rt] += 1
            b["chan"][(ch >> 8) & 0xFF if ch is not None else None] += 1
            head = pay[:65536]
            for x in head:
                b["nib"][x & 0xF] += 1
                b["nib"][x >> 4] += 1
            if len(head) > 64:
                b["lagn"] += 1
                for lag in range(1, 9):
                    same = sum(1 for i in range(lag, len(head)) if head[i] == head[i - lag])
                    b["lag"][lag - 1] += same / float(len(head) - lag)
        print()
        print("audio census of %s, %d files, %d bits per sample assumed"
              % (a.audio, len(files), a.bits))
        gt = gs = 0.0
        for key in sorted(branches):
            b = branches[key]
            rate = b["rates"].most_common(1)[0][0]
            ch = b["chan"].most_common(1)[0][0]
            sps = float(rate * ch * a.bits) / 8.0 if rate and ch else 0.0
            secs = b["payload"] / sps if sps else 0.0
            vsecs = b["voiced"] / sps if sps else 0.0
            gt += secs
            gs += vsecs
            print("   %-10s %5d files  %12d bytes  payload %12d  non-padding %12d"
                  % (key, b["files"], b["bytes"], b["payload"], b["voiced"]))
            print("        rate %s   channels %s   bytes per second %.0f"
                  % (", ".join("%s x%d" % kv for kv in b["rates"].most_common(4)),
                     ", ".join("%s x%d" % kv for kv in b["chan"].most_common(4)), sps))
            print("        seconds: %.1f whole payload, %.1f without the trailing zeros"
                  % (secs, vsecs))
            tot = float(sum(b["nib"].values()))
            print("        nibble histogram %%: %s"
                  % " ".join("%X:%.1f" % (k, 100 * b["nib"][k] / tot) for k in range(16)))
            sym = sum(abs(b["nib"][k] - b["nib"][k + 8]) for k in range(8)) / tot
            print("        sign-magnitude symmetry |n| vs |n+8|: %.4f  (0 = perfect)" % sym)
            print("        mean byte-equality at lag 1..8: %s"
                  % " ".join("%.4f" % (v / b["lagn"]) for v in b["lag"]))
        print("   TOTAL seconds: %.1f whole payload, %.1f without the trailing zeros"
              % (gt, gs))
        print("   TOTAL h:m:s  : %d:%02d:%02d  and  %d:%02d:%02d"
              % (gt // 3600, (gt % 3600) // 60, gt % 60,
                 gs // 3600, (gs % 3600) // 60, gs % 60))


if __name__ == "__main__":
    main()
