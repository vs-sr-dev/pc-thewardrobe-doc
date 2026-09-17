#!/usr/bin/env python3
"""sfdmeta.py -- the Sofdec private stream 0xBF, and the audio nobody checked.

Two things the .SFD walker in this collection did not do.

ONE. Every .SFD on this disc carries exactly one packet with stream id 0xBF --
MPEG-1 private stream 2 -- of 2,030 payload bytes. Its printable runs were
read by the pre-briefing and nothing else was. This tool derives the field
layout from the bytes and prints the numbers between the strings.

TWO. The .SFD census in sfd.py labels stream id 0xC0 "MPEG audio". 0xC0 is
indeed the first MPEG *audio* stream id, but the id is a slot number, not a
codec. --audio extracts the 0xC0 payload and tests it against the ADX header
that adx.py already validates on this disc's 822 archive members. If the
payload is ADX then the label in sfd.py is wrong about the thing that matters.

    python tools/sfdmeta.py --selftest
    python tools/sfdmeta.py --bf _work/hd/DEMO.SFD
    python tools/sfdmeta.py --bf-compare _work/hd ../other/_work/hd
    python tools/sfdmeta.py --audio _work/hd/DEMO.SFD --out _work/a.adx
"""

import argparse
import os
import re
import struct
import sys

PACK = b"\x00\x00\x01\xba"
END = b"\x00\x00\x01\xb9"


def packets(data, want=None):
    """Yield (stream_id, payload_bytes) walking an MPEG-1 program stream.

    The MPEG-1 pack header is 12 bytes: four for the start code and eight for
    the SCR and mux rate. Using 14 -- the MPEG-2 length -- desynchronises the
    walk on the first pack and yields one enormous bogus packet, which is how
    this function was got wrong the first time.
    """
    n = len(data)
    if data[0:4] != PACK:
        raise ValueError("does not begin with a pack start code")
    i = 0
    while i + 4 <= n:
        if data[i:i + 3] != b"\x00\x00\x01":
            break
        sid = data[i + 3]
        if sid == 0xBA:
            i += 12
            continue
        if sid == 0xB9:
            break
        if i + 6 > n:
            break
        ln = struct.unpack_from(">H", data, i + 4)[0]
        body = data[i + 6:i + 6 + ln]
        if want is None or sid in want:
            yield sid, body
        i += 6 + ln


def strip_pes(body):
    """Remove the MPEG-1 PES header stuffing and timestamps."""
    p = 0
    while p < len(body) and body[p] == 0xFF:
        p += 1
    if p < len(body) and (body[p] & 0xC0) == 0x40:
        p += 2
    if p < len(body):
        f = body[p] & 0xF0
        if f == 0x20:
            p += 5
        elif f == 0x30:
            p += 10
        elif body[p] == 0x0F:
            p += 1
    return body[p:]


def bf_payload(path):
    d = open(path, "rb").read()
    got = [b for sid, b in packets(d, {0xBF})]
    if len(got) != 1:
        raise SystemExit("%s carries %d packets of stream 0xBF, expected 1"
                         % (os.path.basename(path), len(got)))
    return got[0]


STAMP = re.compile(rb"(19|20)\d{10}$")


def parse_bf(p):
    """Derive the record layout.

    What the bytes say, on this disc:

      +0   16   b'SofdecStream\\0\\0\\0\\0'   -- the format's own name
      +16  ...  a run of 32-bit fields
      then three 32-byte NAME SLOTS, each holding
             12 bytes  filename, space padded, with its extension
             12 bytes  a YYYYMMDDHHMM stamp as ASCII digits, then padding
      and between them, further 32-bit fields.

    Rather than assert offsets, this walks the payload for printable runs and
    reports every one with its offset, then prints every non-zero 32-bit word
    with its offset, so that a reader can check the claim against the dump.
    """
    out = {"len": len(p), "magic": bytes(p[:16])}
    runs = []
    for m in re.finditer(rb"[\x20-\x7e]{4,}", p):
        runs.append((m.start(), m.group().decode("ascii")))
    out["runs"] = runs
    words = []
    for o in range(0, len(p) - 3, 4):
        v = struct.unpack_from("<I", p, o)[0]
        if v:
            words.append((o, v))
    out["nonzero_le_words"] = words
    return out


def cmd_bf(paths):
    for path in paths:
        p = bf_payload(path)
        r = parse_bf(p)
        print("=== %s : stream 0xBF, %d bytes ==="
              % (os.path.basename(path), r["len"]))
        print("  first 16 bytes : %r" % r["magic"])
        print("  printable runs of 4+ : %d" % len(r["runs"]))
        for o, s in r["runs"]:
            print("    +0x%04X  %s" % (o, s))
        nz = r["nonzero_le_words"]
        print("  non-zero 32-bit little-endian words outside the strings : %d"
              % len(nz))
        span = [(o, s) for o, s in r["runs"]]

        def in_string(o):
            return any(so <= o < so + len(ss) for so, ss in span)
        shown = [(o, v) for o, v in nz if not in_string(o)]
        for o, v in shown[:40]:
            print("    +0x%04X  %10d  0x%08X" % (o, v, v))
        if len(shown) > 40:
            print("    ... %d more" % (len(shown) - 40))
        print("  trailing bytes from the last string to the end : %d"
              % (r["len"] - (span[-1][0] + len(span[-1][1])) if span else r["len"]))
        print()
    return 0


def cmd_bf_table(root):
    """One row per film: the six strings and their stamps, side by side."""
    files = sorted(f for f in os.listdir(root) if f.upper().endswith(".SFD"))
    print("=== the Sofdec authoring clock, %d films ===" % len(files))
    print("%-14s %-12s %-12s %-12s %-12s %-12s"
          % ("file", "sfd source", "sfd stamp", "m1v stamp", "sfa stamp", "muxer"))
    rows = []
    for f in files:
        p = bf_payload(os.path.join(root, f))
        runs = [s for _, s in parse_bf(p)["runs"]]
        names, stamps, mux = [], [], ""
        for s in runs:
            m = re.search(r"(\d{12})", s)
            if m and ("." in s):
                names.append(s[:m.start()].strip())
                stamps.append(m.group(1))
            elif "SFDMUX" in s or "DCMVCRE" in s:
                mux = (mux + " " + s.strip()).strip()
        while len(stamps) < 3:
            stamps.append("")
        print("%-14s %-12s %-12s %-12s %-12s %s"
              % (f, names[0] if names else "", stamps[0], stamps[1],
                 stamps[2], mux))
        rows.append((f, names, stamps, mux))
    allst = sorted(s for _, _, ss, _ in rows for s in ss if s)
    if allst:
        print()
        print("  earliest stamp : %s" % allst[0])
        print("  latest stamp   : %s" % allst[-1])
        print("  distinct       : %d over %d films" % (len(set(allst)), len(rows)))
    return 0


ADX_MAGIC = 0x8000


def cmd_audio(path, out):
    d = open(path, "rb").read()
    buf = bytearray()
    n = 0
    for sid, body in packets(d, set(range(0xC0, 0xE0))):
        buf += strip_pes(body)
        n += 1
    print("=== %s : stream 0xC0..0xDF ===" % os.path.basename(path))
    print("  packets                 : %d" % n)
    print("  payload bytes           : %s" % f"{len(buf):,}")
    head = bytes(buf[:32])
    print("  first 32 bytes          : %s" % head.hex(" "))
    magic = struct.unpack_from(">H", head, 0)[0] if len(head) >= 2 else 0
    co = struct.unpack_from(">H", head, 2)[0] if len(head) >= 4 else 0
    print("  16-bit big-endian magic : 0x%04X   %s"
          % (magic, "== ADX 0x8000" if magic == ADX_MAGIC else "NOT ADX"))
    if magic == ADX_MAGIC and co >= 6 and co + 2 <= len(buf):
        tag = bytes(buf[co - 2:co + 4])
        enc, blk, bits, ch = head[4], head[5], head[6], head[7]
        rate = struct.unpack_from(">I", head, 8)[0]
        samples = struct.unpack_from(">I", head, 12)[0]
        print("  copyright offset        : %d, bytes there %r" % (co, tag))
        print("  encoding %d block %d bits %d channels %d rate %d samples %d"
              % (enc, blk, bits, ch, rate, samples))
        if rate:
            print("  duration                : %.3f s" % (samples / rate))
        print()
        print("  THE PAYLOAD OF STREAM 0xC0 IS ADX, NOT MPEG AUDIO.")
    if out:
        open(out, "wb").write(bytes(buf))
        print("  written                 : %s" % out)
    return 0


def selftest():
    # Build a two-pack program stream by hand and walk it.
    def pes(sid, payload):
        return (b"\x00\x00\x01" + bytes([sid])
                + struct.pack(">H", len(payload)) + payload)
    pack = PACK + b"\x21\x00\x01\x00\x01\x80\x00\x01"   # 12 bytes total
    body = pack + pes(0xE0, b"\x0f" + b"VIDEO") + pes(0xBF, b"META!!") \
        + pack + pes(0xC0, b"\x0f" + b"\x80\x00AUDIO") + END
    got = list(packets(body))
    assert [s for s, _ in got] == [0xE0, 0xBF, 0xC0], \
        "stream ids wrong: %r" % [hex(s) for s, _ in got]
    assert strip_pes(got[0][1]) == b"VIDEO", "PES strip wrong: %r" % got[0][1]
    assert got[1][1] == b"META!!"
    # NEGATIVE CONTROL 1: a 14-byte pack skip -- the MPEG-2 length -- must NOT
    # produce this answer. If it did, the 12 would be unfalsifiable.
    n2 = 0
    i = 0
    try:
        while i + 4 <= len(body):
            if body[i:i + 3] != b"\x00\x00\x01":
                break
            sid = body[i + 3]
            if sid == 0xBA:
                i += 14
                continue
            if sid == 0xB9:
                break
            ln = struct.unpack_from(">H", body, i + 4)[0]
            n2 += 1
            i += 6 + ln
    except Exception:
        pass
    assert n2 != 3, "the 14-byte skip must not reproduce the 12-byte walk"
    # NEGATIVE CONTROL 2: input that is not a program stream must raise.
    try:
        list(packets(b"NOTAPROGRAMSTREAM"))
    except ValueError:
        pass
    else:
        raise AssertionError("a non-program-stream input did not raise")
    # NEGATIVE CONTROL 3: the ADX magic test must reject non-ADX.
    assert struct.unpack_from(">H", b"\x80\x00xx", 0)[0] == ADX_MAGIC
    assert struct.unpack_from(">H", b"\xff\xfbxx", 0)[0] != ADX_MAGIC, \
        "an MPEG audio sync word must not pass the ADX test"
    print("sfdmeta selftest: 4 assertions passed, 3 negative controls fired")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bf", nargs="+")
    ap.add_argument("--bf-table")
    ap.add_argument("--audio")
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.bf:
        return cmd_bf(a.bf)
    if a.bf_table:
        return cmd_bf_table(a.bf_table)
    if a.audio:
        return cmd_audio(a.audio, a.out)
    raise SystemExit("sfdmeta.py: pick --bf, --bf-table, --audio or --selftest")


if __name__ == "__main__":
    sys.exit(main())
