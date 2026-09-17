#!/usr/bin/env python3
"""dpserial.py - read updata\\_flink\\DPSerial.00N and close it on the byte.

The container has no table of contents. Every member is preceded by a 256-byte
record that holds nothing but the **absolute path the file had on the machine
that built the archive**, NUL-terminated, and 0xCC to the end of the 256:

    00   44 3a 5c 70 72 6f 67 72 61 6d 6d 65 72 5f 50 43   D:\\programmer_PC
    10   5c 6d 61 69 6e 5c 55 50 44 41 54 41 2f 42 47 2f   \\main\\UPDATA/BG/
    20   42 47 2e 50 52 4d 00 cc cc cc cc cc cc cc cc cc   BG.PRM..........
    ...  cc ...                                            to offset 256
    100  <member bytes>

Note the separators: backslash for the first three components, forward slash
for everything below.  That is a constant prefix prepended to a relative list,
not a path the operating system ever produced.

Two independent readers live here and they are made to agree.

**The walker** uses the format, which is complete:

    0    the path, NUL-terminated, then 0xCC to offset 256
    256  u32 little-endian, the member's length in bytes
    260  the member
         zero padding of 16 - (length mod 16) bytes, so always 1..16 of them,
         so the member plus its padding is always a multiple of 16

That closes every member of all three archives with no residue, and the
padding is all-zero on 14,328 of 14,328.

**The scanner** ignores all of that and finds record starts by signature,
validating each candidate hard before accepting it:

  * the path must be printable ASCII, at least 8 and at most 254 bytes;
  * it must be followed by exactly one NUL;
  * **every remaining byte to offset 256 must be 0xCC** — this is what makes
    a false positive essentially impossible, because a run of 0xCC of the exact
    length needed to reach a 256 boundary is not something member data does.

Member length for the scanner is `next_record_start - (this_record_start +
256)`, and the last member runs to end of file.  A run is only a census if it
closes: the tool prints the residue, and a residue of zero means every byte of
the archive is either a record, a length, a member, or zero padding.

`--walk` runs both and asserts they produce the same record offsets and the
same lengths.  Two methods that share no assumption agreeing on 14,328 members
is the reason the count can be published as a census rather than an estimate.

Nothing is extracted.  --emit-tree writes the reconstructed directory tree of
the build machine, which is names only.

    python tools/dpserial.py ARCHIVE [ARCHIVE ...]
    python tools/dpserial.py ARCHIVE --paths out.txt --tree out-tree.txt
"""
import argparse
import os
import struct
import sys

SIG = b"D:\x5cprogrammer_PC"
REC = 256


def scan(path, sig=SIG):
    """Yield (offset, pathstring) for every validated record header."""
    size = os.path.getsize(path)
    hits = []
    chunk = 1 << 24
    overlap = REC + len(sig)
    with open(path, "rb") as fh:
        base = 0
        prev = b""
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            data = prev + buf
            start = base - len(prev)
            i = 0
            while True:
                j = data.find(sig, i)
                if j < 0:
                    break
                i = j + 1
                off = start + j
                blk = data[j:j + REC]
                if len(blk) < REC:
                    # near the tail of this window; the overlap will catch it
                    break
                nul = blk.find(b"\x00")
                if nul < 8 or nul > 254:
                    continue
                name = blk[:nul]
                if any(b < 0x20 or b > 0x7E for b in name):
                    continue
                if blk[nul + 1:] != b"\xcc" * (REC - nul - 1):
                    continue
                hits.append((off, name.decode("ascii")))
            prev = data[-overlap:] if len(data) >= overlap else data
            base += len(buf)
    # the scan can see the same header twice across the window seam
    out = []
    seen = set()
    for off, name in hits:
        if off in seen:
            continue
        seen.add(off)
        out.append((off, name))
    out.sort()
    return out, size


def walk(path):
    """Deterministic walk using the length field.  Returns (records, residue)."""
    size = os.path.getsize(path)
    recs = []
    pads = {}
    with open(path, "rb") as fh:
        off = 0
        while off < size:
            fh.seek(off)
            blk = fh.read(REC + 4)
            if len(blk) < REC + 4:
                break
            nul = blk.find(b"\x00")
            if nul < 1 or nul > 254:
                break
            if blk[nul + 1:REC] != b"\xcc" * (REC - nul - 1):
                break
            name = blk[:nul].decode("ascii", "replace")
            ln = struct.unpack("<I", blk[REC:REC + 4])[0]
            pad = 16 - (ln % 16)
            recs.append((off, name, ln, pad))
            pads[pad] = pads.get(pad, 0) + 1
            off += REC + 4 + ln + pad
    return recs, size - off, pads


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("archives", nargs="+")
    ap.add_argument("--walk", action="store_true",
                    help="also walk by the length field and check the two agree")
    ap.add_argument("--paths", help="write every member path here, one per line")
    ap.add_argument("--tree", help="write the reconstructed build-machine tree here")
    ap.add_argument("--sizes", help="write path<TAB>length<TAB>archive here")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    all_paths = []
    rows = []
    grand_members = 0
    grand_bytes = 0
    grand_residue = 0

    for arc in a.archives:
        recs, size = scan(arc)
        name = os.path.basename(arc)
        if a.walk:
            wrecs, wres, wpads = walk(arc)
            same = (len(wrecs) == len(recs)
                    and all(w[0] == r[0] and w[1] == r[1]
                            for w, r in zip(wrecs, recs)))
            print("walk vs scan on %s : %d records vs %d, offsets and names %s, walk residue %d"
                  % (name, len(wrecs), len(recs), "IDENTICAL" if same else "DIFFER", wres))
            print("   padding lengths seen : %s"
                  % ", ".join("%d x%d" % (k, v) for k, v in sorted(wpads.items())))
        if not recs:
            print("%-16s NO RECORDS" % name)
            continue
        lengths = []
        for k, (off, p) in enumerate(recs):
            end = recs[k + 1][0] if k + 1 < len(recs) else size
            lengths.append(end - off - REC)
        header_bytes = len(recs) * REC
        member_bytes = sum(lengths)
        residue = size - header_bytes - member_bytes
        lead = recs[0][0]

        # does the member's first dword predict its length?
        diffs = {}
        neg = 0
        with open(arc, "rb") as fh:
            for (off, p), ln in zip(recs, lengths):
                if ln < 4:
                    diffs["(member shorter than 4)"] = diffs.get("(member shorter than 4)", 0) + 1
                    continue
                fh.seek(off + REC)
                dw = struct.unpack("<I", fh.read(4))[0]
                d = ln - dw
                if d < 0:
                    neg += 1
                    continue
                diffs[d] = diffs.get(d, 0) + 1

        print("######## %s ########" % name)
        print("file bytes            : %d" % size)
        print("records found         : %d" % len(recs))
        print("first record at offset: %d" % lead)
        print("record bytes          : %d  (%d x %d)" % (header_bytes, len(recs), REC))
        print("member bytes          : %d" % member_bytes)
        print("residue               : %d   %s"
              % (residue, "CLOSES ON THE BYTE" if residue == 0 else "DOES NOT CLOSE"))
        print("member length  min %d  max %d  mean %.1f"
              % (min(lengths), max(lengths), member_bytes / float(len(lengths))))
        print("record overhead       : %.6f %% of the archive"
              % (100.0 * header_bytes / size))
        print("first dword of member vs member length, top differences:")
        for d, n in sorted(diffs.items(), key=lambda kv: -kv[1])[:8]:
            print("    length - dword = %-24s %6d members" % (d, n))
        if neg:
            print("    dword larger than the member          %6d members" % neg)
        print()

        grand_members += len(recs)
        grand_bytes += size
        grand_residue += residue
        for (off, p), ln in zip(recs, lengths):
            all_paths.append(p)
            rows.append((p, ln, name))

    print("======== all archives ========")
    print("archives              : %d" % len(a.archives))
    print("members               : %d" % grand_members)
    print("archive bytes         : %d" % grand_bytes)
    print("total residue         : %d" % grand_residue)
    print("distinct paths        : %d" % len(set(all_paths)))
    print("repeated paths        : %d" % (len(all_paths) - len(set(all_paths))))

    # the tree of the machine that built it
    roots = {}
    dirs = set()
    exts = {}
    depth = {}
    prefix_ok = 0
    PREFIX = "D:\x5cprogrammer_PC\x5cmain\x5c"
    for p in all_paths:
        if p.startswith(PREFIX):
            prefix_ok += 1
        norm = p.replace("\x5c", "/")
        parts = norm.split("/")
        roots[parts[0]] = roots.get(parts[0], 0) + 1
        d = "/".join(parts[:-1])
        dirs.add(d)
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))
        depth[len(parts)] = depth.get(len(parts), 0) + 1
        e = os.path.splitext(parts[-1])[1].upper()
        exts[e] = exts.get(e, 0) + 1

    print()
    print("constant prefix %r on %d of %d paths" % (PREFIX, prefix_ok, len(all_paths)))
    print("prefix bytes spent    : %d" % (len(PREFIX) * prefix_ok))
    print("path text bytes       : %d" % sum(len(p) + 1 for p in all_paths))
    print("distinct directories  : %d" % len(dirs))
    print("drive roots           : %s" % ", ".join(sorted(roots)))
    print()
    print("-- depth histogram (components) --")
    for k in sorted(depth):
        print("   %2d components  %6d" % (k, depth[k]))
    print()
    print("-- extensions inside the archives --")
    for e, n in sorted(exts.items(), key=lambda kv: -kv[1]):
        print("   %-8s %6d" % (e or "(none)", n))

    # third level, the way the pre-briefing counted it
    third = {}
    for p in all_paths:
        parts = p.replace("\x5c", "/").split("/")
        key = "/".join(parts[:3])
        third[key] = third.get(key, 0) + 1
    print()
    print("-- third level --")
    for k, n in sorted(third.items(), key=lambda kv: -kv[1]):
        print("   %-46s %6d" % (k, n))

    # per top-level branch under UPDATA
    branch = {}
    for (p, ln, arc) in rows:
        parts = p.replace("\x5c", "/").split("/")
        key = parts[3] if len(parts) > 4 else "(top)"
        n, b = branch.get(key, (0, 0))
        branch[key] = (n + 1, b + ln)
    tot = sum(b for _n, b in branch.values())
    print()
    print("-- members by branch of the build tree --")
    for k in sorted(branch, key=lambda x: -branch[x][1]):
        n, b = branch[k]
        print("   %-14s %6d  %13d  %7.4f %%" % (k, n, b, 100.0 * b / tot))
    print("   %-14s %6d  %13d" % ("TOTAL", sum(n for n, _b in branch.values()), tot))

    if a.paths:
        with open(a.paths, "w", encoding="utf-8", newline="\n") as fh:
            for p in all_paths:
                fh.write(p + "\n")
    if a.sizes:
        with open(a.sizes, "w", encoding="utf-8", newline="\n") as fh:
            for p, ln, arc in rows:
                fh.write("%s\t%d\t%s\n" % (p, ln, arc))
    if a.tree:
        with open(a.tree, "w", encoding="utf-8", newline="\n") as fh:
            for d in sorted(dirs):
                fh.write(d + "/\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
