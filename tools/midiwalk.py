#!/usr/bin/env python3
"""midiwalk.py -- walk a Standard MIDI File (MMA RP-001, a public format)
chunk by chunk and event by event: tracks, their names, tempo, programs,
note counts. Written for BUMPY.MID of pc-bumpy-doc; `midread.py` in this
box is Sam & Max's .MDI walker and asserts on a plain .MID, so it is left
alone (dirguard's survey counts it among the 'raised').

    python tools/midiwalk.py census FILE...
    python tools/midiwalk.py selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard   # noqa: E402
import nameguard  # noqa: E402


class Refused(Exception):
    pass


def _varlen(b, i):
    v = 0
    while True:
        if i >= len(b):
            raise Refused("variable-length number runs off the track")
        c = b[i]
        i += 1
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            return v, i


def track(b):
    """One MTrk body -> dict of counts. Running status honoured."""
    i = 0
    status = None
    t = dict(events=0, notes=0, programs=set(), channels=set(), name=None,
             tempo=[], meta=0, sysex=0, ticks=0, end=False)
    while i < len(b):
        delta, i = _varlen(b, i)
        t["ticks"] += delta
        if i >= len(b):
            raise Refused("delta time with no event")
        c = b[i]
        if c == 0xFF:
            typ = b[i + 1]
            ln, j = _varlen(b, i + 2)
            data = b[j:j + ln]
            i = j + ln
            t["meta"] += 1
            if typ == 0x03 or (typ == 0x01 and t["name"] is None):
                # BUMPY.MID names its tracks with a TEXT event (01h),
                # eight characters padded with spaces, not with 03h
                t["name"] = data.decode("latin-1").strip()
            elif typ == 0x20 and ln == 1:
                t["prefix"] = data[0]
            elif typ == 0x51 and ln == 3:
                t["tempo"].append(struct.unpack(">I", b"\0" + data)[0])
            elif typ == 0x2F:
                t["end"] = True
        elif c in (0xF0, 0xF7):
            ln, j = _varlen(b, i + 1)
            i = j + ln
            t["sysex"] += 1
        else:
            if c & 0x80:
                status = c
                i += 1
            elif status is None:
                raise Refused("data byte %02X with no running status at %d" % (c, i))
            kind = status & 0xF0
            t["channels"].add(status & 0x0F)
            n = 1 if kind in (0xC0, 0xD0) else 2
            args = b[i:i + n]
            i += n
            if kind == 0x90 and len(args) == 2 and args[1]:
                t["notes"] += 1
            if kind == 0xC0 and args:
                t["programs"].add(args[0])
        t["events"] += 1
    if not t["end"]:
        raise Refused("track has no end-of-track meta event")
    return t


def walk(d):
    if d[:4] != b"MThd":
        raise Refused("no MThd")
    hl, fmt, ntrk, div = struct.unpack_from(">IHHH", d, 4)
    if hl != 6:
        raise Refused("MThd length %d, not 6" % hl)
    p = 8 + hl
    tracks = []
    while p + 8 <= len(d):
        tag, ln = d[p:p + 4], struct.unpack_from(">I", d, p + 4)[0]
        if p + 8 + ln > len(d):
            raise Refused("chunk %r at %d runs past the end" % (tag, p))
        if tag == b"MTrk":
            tracks.append(track(d[p + 8:p + 8 + ln]))
        p += 8 + ln
    if p != len(d):
        raise Refused("chunk walk ends at %d, file is %d" % (p, len(d)))
    if len(tracks) != ntrk:
        raise Refused("MThd says %d tracks, %d MTrk found" % (ntrk, len(tracks)))
    return dict(format=fmt, tracks=tracks, division=div)


def cmd_census(paths):
    nameguard.guard()
    rc = 0
    for path in paths:
        d = open(path, "rb").read()
        try:
            m = walk(d)
        except Refused as e:
            print("REFUSED  %s: %s" % (os.path.basename(path), e))
            rc = 1
            continue
        print("%s  %d bytes  format %d  %d tracks  %d ticks/quarter; the chunk walk closes on the file" % (
            os.path.basename(path), len(d), m["format"], len(m["tracks"]), m["division"]))
        for k, t in enumerate(m["tracks"]):
            tempo = ", ".join("%d us/quarter = %.1f bpm" % (x, 60e6 / x) for x in t["tempo"]) or "-"
            print("  track %d  %-10s events %5d  notes %5d  prefix %-2s status-ch %-8s prog %-14s length %6d ticks  tempo %s" % (
                k, repr(t["name"]) if t["name"] else "-", t["events"], t["notes"],
                t.get("prefix", "-"), ",".join(str(c) for c in sorted(t["channels"])) or "-",
                ",".join(str(c) for c in sorted(t["programs"])) or "-", t["ticks"], tempo))
        print("  notes in all tracks: %d" % sum(t["notes"] for t in m["tracks"]))
    return rc


def _smf(tracks, fmt=1, div=192):
    out = b"MThd" + struct.pack(">IHHH", 6, fmt, len(tracks), div)
    for body in tracks:
        out += b"MTrk" + struct.pack(">I", len(body)) + body
    return out


def selftest():
    nameguard.guard()
    fails = 0

    def check(label, cond, note=""):
        nonlocal fails
        print("%s  %-60s %s" % ("ok " if cond else "FAIL", label, note))
        if not cond:
            fails += 1

    name = b"\x00\xFF\x03\x04xylo"
    tempo = b"\x00\xFF\x51\x03\x07\xA1\x20"
    notes = b"\x00\x90\x3C\x40" + b"\x81\x00\x3C\x00" + b"\x00\x3E\x40" + b"\x60\x3E\x00"  # running status
    prog = b"\x00\xC1\x05"
    end = b"\x00\xFF\x2F\x00"
    m = walk(_smf([name + tempo + end, notes + prog + end]))
    check("two tracks, format 1, 192 ppqn", m["format"] == 1 and len(m["tracks"]) == 2 and m["division"] == 192)
    check("track name and tempo read (500,000 us = 120 bpm)",
          m["tracks"][0]["name"] == "xylo" and m["tracks"][0]["tempo"] == [500000])
    t = m["tracks"][1]
    check("running status: 2 notes on, 1 program (5) on channel 1, 224 ticks",
          t["notes"] == 2 and t["programs"] == {5} and t["channels"] == {0, 1} and t["ticks"] == 128 + 96)
    for label, blob, needle in (
            ("a file without MThd", b"MTrk" + bytes(10), "no MThd"),
            ("a chunk running past the end", _smf([end])[:-2], "runs past"),
            ("a track without end-of-track", _smf([name]), "no end"),
            ("a track count that does not match", _smf([end], fmt=0)[:10] + b"\x00\x02" + _smf([end])[12:], "says 2")):
        try:
            walk(blob)
            check("refuses " + label, False, "accepted")
        except Refused as e:
            check("refuses " + label, needle in str(e), str(e))
    print("\nmidiwalk.py selftest: %d failures, 0 skipped (specimens are built)" % fails)
    return 1 if fails else 0


def main(argv=None):
    nameguard.guard()
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("census", "selftest"))
    ap.add_argument("args", nargs="*")
    a = ap.parse_args(argv)
    if a.cmd == "selftest":
        return selftest()
    if not a.args:
        ap.error("no input")
    for p in a.args:
        dirguard.want_file(p, "midiwalk.py")
    return cmd_census(a.args)


if __name__ == "__main__":
    sys.exit(main())
