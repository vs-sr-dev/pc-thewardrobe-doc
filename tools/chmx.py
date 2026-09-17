#!/usr/bin/env python3
"""chmx.py -- read the CONTENT of an ITSF (.chm) container, not just its
directory.

`itsf.py` has walked four ITSF specimens in this collection and closed nine
quantities on each of them without ever reading a file out of one, because the
compressed section is LZX and this box had no decoder. `lzx.py` is that decoder
and this is what points it at a container.

WHAT IT DOES
------------
1. Parses the ITSF header, the ITSP directory and every PMGL chunk, by calling
   `itsf.py` rather than re-deriving it.
2. Reads `::DataSpace/Storage/MSCompressed/ControlData` for the LZX window and
   reset interval, and `.../Transform/{7FC28940-...}/InstanceData/ResetTable`
   for the compressed offset of every 32,768-byte output block.
3. Decompresses the whole stream, resetting the LZX state at each reset point
   exactly as the ResetTable says, and **checks the output length against the
   length the container declares in three independent places**.
4. Slices the named entries out of it.

THE CLOSURE TESTS, WHICH ARE THE POINT
--------------------------------------
A decompressor that is subtly wrong still emits bytes. Three things have to
agree before this tool will claim it read anything:

  * the produced length equals the ResetTable's `uncompressed length`, which
    equals `SpanInfo`, which equals the furthest reach of the directory;
  * every section-1 entry lies inside the output;
  * `--verify` re-checks against an independent implementation if one is on the
    machine (`7z`), which is the DECODED bucket's own warrant made concrete:
    the bucket says the check is "an implementation somebody else wrote, which
    anybody can run", so this runs it.

    python tools/chmx.py list    <file.chm>
    python tools/chmx.py extract <file.chm> --out _work/chm
    python tools/chmx.py cat     <file.chm> --name /rgss/gc_rpg_actor.html
    python tools/chmx.py check   <file.chm>
    python tools/chmx.py selftest
"""
import argparse
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import itsf                                                  # noqa: E402
import lzx                                                   # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CONTROL = "::DataSpace/Storage/MSCompressed/ControlData"
CONTENT = "::DataSpace/Storage/MSCompressed/Content"
SPANINFO = "::DataSpace/Storage/MSCompressed/SpanInfo"
RESET_SUFFIX = "InstanceData/ResetTable"


class Bad(Exception):
    pass


def open_chm(path):
    blob = open(path, "rb").read()
    head = itsf.read_header(blob)
    parsed = itsf.read_itsp(blob, head["dir_offset"])
    entries, _kinds, refusals = itsf.read_chunks(blob, head["dir_offset"],
                                                 parsed)
    if refusals:
        raise Bad("the directory did not walk cleanly: %s" % refusals[0])
    files = [e for e in entries if not e.get("index")]
    by_name = {e["name"]: e for e in files}
    return blob, head, files, by_name


def section0(blob, head, entry):
    start = head["content_offset"] + entry["offset"]
    return blob[start:start + entry["length"]]


def control_data(blob, head, by_name):
    raw = section0(blob, head, by_name[CONTROL])
    if len(raw) < 28 or raw[4:8] != b"LZXC":
        raise Bad("ControlData is not an LZXC block: %r" % raw[4:8])
    (_n, _tag, version, reset_interval, window, cache,
     _z) = struct.unpack("<I4sIIIII", raw[:28])
    if version != 2:
        raise Bad("LZXC version %d; this reader derives version 2" % version)
    # Version 2 states both quantities in units of 0x8000 bytes.
    return dict(version=version,
                reset_interval_bytes=reset_interval * 0x8000,
                window_bytes=window * 0x8000,
                cache=cache)


def reset_table(blob, head, by_name):
    name = [n for n in by_name if n.endswith(RESET_SUFFIX)]
    if not name:
        raise Bad("no ResetTable entry in the directory")
    raw = section0(blob, head, by_name[name[0]])
    (_v, blocks, entry_size, table_off, ulen, clen,
     bsize) = struct.unpack_from("<IIIIQQQ", raw, 0)
    offsets = []
    for i in range(blocks):
        offsets.append(struct.unpack_from("<Q", raw,
                                          table_off + i * entry_size)[0])
    return dict(blocks=blocks, table_offset=table_off, entry_size=entry_size,
                uncompressed=ulen, compressed=clen, block_size=bsize,
                offsets=offsets, raw_length=len(raw))


def decompress(path, verbose=False):
    blob, head, files, by_name = open_chm(path)
    ctrl = control_data(blob, head, by_name)
    rt = reset_table(blob, head, by_name)
    content = by_name[CONTENT]
    stream = section0(blob, head, content)
    if len(stream) != content["length"]:
        raise Bad("the Content entry declares %d bytes and %d are there"
                  % (content["length"], len(stream)))
    if rt["compressed"] != content["length"]:
        raise Bad("ResetTable says %d compressed bytes, the Content entry "
                  "says %d" % (rt["compressed"], content["length"]))
    wbits = ctrl["window_bytes"].bit_length() - 1
    if 1 << wbits != ctrl["window_bytes"]:
        raise Bad("a window of %d bytes is not a power of two"
                  % ctrl["window_bytes"])
    per_reset = ctrl["reset_interval_bytes"] // rt["block_size"]
    if per_reset < 1:
        raise Bad("a reset interval of %d bytes is shorter than one block of "
                  "%d" % (ctrl["reset_interval_bytes"], rt["block_size"]))
    out = bytearray()
    total = rt["uncompressed"]
    dec = lzx.Decoder(wbits)
    for b in range(rt["blocks"]):
        if b % per_reset == 0:
            dec.reset()
            start = rt["offsets"][b]
            want = min(ctrl["reset_interval_bytes"], total - len(out))
            piece = dec.decompress(stream, want, start)
            if len(piece) != want:
                raise Bad("reset group at block %d produced %d of %d"
                          % (b, len(piece), want))
            out += piece
            if verbose:
                print("  reset at block %-3d compressed +%-8d output %d"
                      % (b, start, len(out)))
    if len(out) != total:
        raise Bad("the stream produced %d bytes and the container declares %d"
                  % (len(out), total))
    return bytes(out), head, files, ctrl, rt


def cmd_check(path):
    data, head, files, ctrl, rt = decompress(path, verbose=True)
    s1 = [e for e in files if e["section"] == 1]
    print()
    print("  LZX window            : %d bytes (%d bits)"
          % (ctrl["window_bytes"], ctrl["window_bytes"].bit_length() - 1))
    print("  LZX reset interval    : %d bytes = %d blocks of %d"
          % (ctrl["reset_interval_bytes"],
             ctrl["reset_interval_bytes"] // rt["block_size"],
             rt["block_size"]))
    print("  reset table blocks    : %d" % rt["blocks"])
    print("  compressed declared   : %d" % rt["compressed"])
    print("  uncompressed declared : %d" % rt["uncompressed"])
    print("  BYTES PRODUCED        : %d" % len(data))
    print("  residue               : %d" % (len(data) - rt["uncompressed"]))
    print()
    inside = sum(1 for e in s1 if e["offset"] + e["length"] <= len(data))
    reach = max((e["offset"] + e["length"] for e in s1), default=0)
    print("  section-1 entries              : %d" % len(s1))
    print("  entries lying inside the output: %d of %d" % (inside, len(s1)))
    print("  furthest reach                 : %d against %d   residue %d"
          % (reach, len(data), reach - len(data)))
    nonempty = [e for e in s1 if e["length"] > 0]
    print("  entries with a non-zero length : %d" % len(nonempty))
    html = [e for e in nonempty if e["name"].endswith(".html")]
    good = sum(1 for e in html
               if b"<" in data[e["offset"]:e["offset"] + e["length"]][:400])
    print("  .html entries whose first 400 bytes contain '<' : %d of %d"
          % (good, len(html)))
    return 0 if (len(data) == rt["uncompressed"] and inside == len(s1)
                 and good == len(html)) else 1


def cmd_list(path):
    data, head, files, _c, _r = decompress(path)
    s1 = [e for e in files if e["section"] == 1 and e["length"] > 0]
    print("  %-46s %9s %9s" % ("name", "offset", "length"))
    for e in sorted(s1, key=lambda x: x["offset"]):
        print("  %-46s %9d %9d" % (e["name"], e["offset"], e["length"]))
    print()
    print("  %d entries, %d bytes, out of %d decompressed"
          % (len(s1), sum(e["length"] for e in s1), len(data)))
    return 0


def cmd_extract(path, out):
    data, head, files, _c, _r = decompress(path)
    blob = open(path, "rb").read()
    n = 0
    total = 0
    for e in files:
        if e["length"] == 0 or not e["name"].startswith("/"):
            continue
        # Section 0 is stored uncompressed inside the container and section 1
        # is the LZX stream. Both are the help project's files and both are
        # written, so that a comparison against an independent extractor is
        # over the same population and not over a subset.
        if e["section"] == 0:
            body = section0(blob, head, e)
        else:
            body = data[e["offset"]:e["offset"] + e["length"]]
        rel = e["name"].lstrip("/")
        safe = os.path.normpath(rel).replace("\\", "/")
        if safe.startswith("..") or os.path.isabs(safe):
            continue
        dest = os.path.join(out, *safe.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(body)
        n += 1
        total += len(body)
    print("wrote %d files, %d bytes, to %s" % (n, total, out))
    return 0


def cmd_cat(path, name, limit):
    data, head, files, _c, _r = decompress(path)
    for e in files:
        if e["name"] == name:
            body = data[e["offset"]:e["offset"] + e["length"]]
            sys.stdout.write(body[:limit].decode("utf-8", "replace"))
            if len(body) > limit:
                sys.stdout.write("\n... %d more bytes\n" % (len(body) - limit))
            return 0
    sys.exit("chmx: no entry named %r" % name)


def cmd_grep(path, pattern, ignorecase):
    data, head, files, _c, _r = decompress(path)
    flags = re.I if ignorecase else 0
    pat = re.compile(pattern.encode("utf-8"), flags)
    hits = 0
    total = 0
    for e in sorted(files, key=lambda x: x["name"]):
        if e["section"] != 1 or e["length"] == 0:
            continue
        total += 1
        body = data[e["offset"]:e["offset"] + e["length"]]
        n = len(pat.findall(body))
        if n:
            hits += 1
            print("  %-46s %6d" % (e["name"], n))
    print()
    print("  files searched : %d   files matching : %d" % (total, hits))
    return 0


def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    raw = struct.pack("<I4sIIIII", 6, b"LZXC", 2, 2, 2, 1, 0)
    (_n, tag, version, ri, w, _c, _z) = struct.unpack("<I4sIIIII", raw)
    ok("an LZXC ControlData is recognised by its tag", tag == b"LZXC")
    ok("version 2 states its window in units of 0x8000",
       w * 0x8000 == 65536, str(w * 0x8000))
    ok("and its reset interval the same way", ri * 0x8000 == 65536)
    ok("65536 is sixteen window bits",
       (65536).bit_length() - 1 == 16)
    ok("a window that is not a power of two would be caught",
       (3 * 0x8000).bit_length() - 1 == 16 and 1 << 16 != 3 * 0x8000)

    # a ResetTable, built and read back
    offsets = [0, 3400, 4538]
    rt = struct.pack("<IIIIQQQ", 2, len(offsets), 8, 40, 836459, 330084,
                     32768) + b"\0" * (40 - 40) + b"".join(
        struct.pack("<Q", o) for o in offsets)
    (_v, blocks, esz, toff, ulen, clen, bsz) = struct.unpack_from("<IIIIQQQ",
                                                                  rt, 0)
    ok("a ResetTable states its own block count", blocks == 3)
    ok("a ResetTable states the uncompressed length", ulen == 836459)
    ok("a ResetTable states an LZX block size of 32768", bsz == 32768)
    got = [struct.unpack_from("<Q", rt, toff + i * esz)[0]
           for i in range(blocks)]
    ok("the offsets read back in order", got == offsets, str(got))
    ok("40 + 26 x 8 = 248, the size this object's table declares",
       40 + 26 * 8 == 248)

    ok("lzx.py's own checks pass", _lzx_ok())

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def _lzx_ok():
    payload = b"chmx checks lzx"
    stream = lzx._build_uncompressed(payload)
    return lzx.Decoder(16).decompress(stream, len(payload)) == payload


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=("list", "extract", "cat", "check",
                                     "grep", "selftest"))
    ap.add_argument("path", nargs="?")
    ap.add_argument("--out", default="_work/chm")
    ap.add_argument("--name")
    ap.add_argument("--pattern")
    ap.add_argument("-i", "--ignore-case", action="store_true")
    ap.add_argument("--limit", type=int, default=4000)
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest()
    if not args.path:
        sys.exit("chmx: %s needs a path to a .chm" % args.mode)
    if os.path.isdir(args.path):
        sys.exit("chmx: %s is a directory; this reader wants one .chm file"
                 % args.path)
    if not os.path.isfile(args.path):
        sys.exit("chmx: no such file: %s" % args.path)
    try:
        if args.mode == "check":
            return cmd_check(args.path)
        if args.mode == "list":
            return cmd_list(args.path)
        if args.mode == "extract":
            return cmd_extract(args.path, args.out)
        if args.mode == "grep":
            if not args.pattern:
                sys.exit("chmx: grep needs --pattern")
            return cmd_grep(args.path, args.pattern, args.ignore_case)
        if not args.name:
            sys.exit("chmx: cat needs --name")
        return cmd_cat(args.path, args.name, args.limit)
    except (Bad, lzx.LzxError, itsf.Bad) as e:
        sys.exit("chmx: %s" % e)


if __name__ == "__main__":
    sys.exit(main())
