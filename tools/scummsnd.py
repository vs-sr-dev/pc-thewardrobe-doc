#!/usr/bin/env python3
"""Read the music of a SCUMM container, and of the loose reference file.

What the bytes say, derived here:

* Every `SOUN` chunk in the container is either a `MIDI` chunk or a `SOU `
  chunk holding one or more format wrappers (`ROL ` for Roland). Both use the
  same `[tag][big-endian length]` convention as the container itself, and the
  `MIDI` wrapper's declared length is checked against its chunk: **that is an
  eleventh answer to this collection's oldest question, inside the same
  object as the tenth.**
* Inside the wrapper comes an `MDpg` chunk -- a small LucasArts header whose
  payload is a few bytes per MIDI part -- and then a **Standard MIDI File**:
  `MThd`, big-endian length 6, format, track count, division; then `MTrk`
  chunks.
* `SAMNMAX/TESTMIDI`, 354 bytes, is the same structure outside any container,
  and is used as the control: the reader is run on it first, and it must
  consume all 354 bytes.

Duration is reported in ticks and, where a `set tempo` meta event is present,
in seconds. These files are **format 2** -- independent patterns, not one
simultaneous song -- so a single "length" is not well defined; the tool prints
the longest track and the sum, and says which is which rather than picking.

Usage:
  python tools/scummsnd.py file  <TESTMIDI>
  python tools/scummsnd.py souns <SAMNMAX.001> [--key 0x69] [--csv F]
"""
import collections
import sys


def load(path, key=0):
    d = open(path, "rb").read()
    return bytes(b ^ key for b in d) if key else d


def be(b, o, n=4):
    return int.from_bytes(b[o:o + n], "big")


def varlen(b, i):
    v = 0
    while True:
        x = b[i]
        i += 1
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            return v, i


def read_smf(b, base):
    """Parse a Standard MIDI File at b[base]. Returns dict or None."""
    if b[base:base + 4] != b"MThd":
        return None
    ln = be(b, base + 4)
    fmt = be(b, base + 8, 2)
    ntrk = be(b, base + 10, 2)
    div = be(b, base + 12, 2)
    p = base + 8 + ln
    tracks = []
    tempos = []
    events = 0
    for _ in range(ntrk):
        if b[p:p + 4] != b"MTrk":
            break
        tl = be(b, p + 4)
        q = p + 8
        end = q + tl
        ticks = 0
        while q < end:
            dt, q = varlen(b, q)
            ticks += dt
            st = b[q]
            if st == 0xFF:
                meta = b[q + 1]
                n, q = varlen(b, q + 2)
                if meta == 0x51 and n == 3:
                    tempos.append(be(b, q, 3))
                q += n
            elif st in (0xF0, 0xF7):
                n, q = varlen(b, q + 1)
                q += n
            else:
                if st & 0x80:
                    q += 1
                    kind = st & 0xF0
                else:
                    kind = last & 0xF0
                last = st if st & 0x80 else last
                q += 1 if kind in (0xC0, 0xD0) else 2
            events += 1
        tracks.append(ticks)
        p = end
    return dict(fmt=fmt, ntrk=ntrk, div=div, tracks=tracks, tempos=tempos,
                end=p, events=events)


def secs(info):
    if not info or not info["div"] or not info["tracks"]:
        return 0.0
    us = info["tempos"][0] if info["tempos"] else 500000
    return max(info["tracks"]) * us / 1e6 / info["div"]


def cmd_file(path):
    b = load(path)
    print("file size      %d" % len(b))
    tag = b[:4]
    ln = be(b, 4)
    print("outer tag      %r declared %d, chunk would be %d, file %d -> %s"
          % (tag, ln, ln + 8, len(b),
             "DECLARES ITS OWN LENGTH CORRECTLY" if ln + 8 == len(b)
             else "MISMATCH"))
    p = 8
    while p < len(b):
        t = b[p:p + 4]
        if t == b"MThd":
            break
        l = be(b, p + 4)
        print("  inner chunk  %r %d bytes payload" % (t, l))
        p += 8 + l
    info = read_smf(b, p)
    if not info:
        print("no MThd found")
        return
    print("SMF at         %d" % p)
    print("  format %d, %d tracks, %d ticks per quarter note"
          % (info["fmt"], info["ntrk"], info["div"]))
    print("  track lengths in ticks: %s" % info["tracks"])
    print("  tempo events: %s" % info["tempos"])
    print("  events: %d" % info["events"])
    print("  longest track: %.3f s" % secs(info))
    print("parser stopped %d of %d -> %s"
          % (info["end"], len(b),
             "CONSUMES THE FILE EXACTLY" if info["end"] == len(b)
             else "LEFTOVER %d" % (len(b) - info["end"])))


def cmd_souns(path, key, csv):
    c = load(path, key)
    souns = []

    def walk(lo, hi):
        p = lo
        while p < hi:
            t = c[p:p + 4]
            l = int.from_bytes(c[p + 4:p + 8], "big")
            if t == b"SOUN":
                souns.append((p, l))
            elif t in (b"LECF", b"LFLF", b"ROOM"):
                walk(p + 8, p + l)
            p += l
    walk(0, len(c))
    kinds = collections.Counter()
    fmts = collections.Counter()
    tot_ticks = 0
    tot_secs = 0.0
    tot_events = 0
    declared_ok = 0
    declared_n = 0
    rows = []
    for p, l in souns:
        b = c[p + 8:p + l]
        kinds[b[:4].decode("latin-1")] += 1
        # the wrapper declares its own length
        wl = be(b, 4)
        declared_n += 1
        if wl + 8 == len(b):
            declared_ok += 1
        q = 8
        while q < len(b) and b[q:q + 4] != b"MThd":
            if b[q:q + 4] in (b"ROL ", b"GMD ", b"ADL ", b"SPK ", b"MIDI",
                              b"SBL ", b"MAC "):
                fmts[b[q:q + 4].decode("latin-1")] += 1
                q += 8
                continue
            ll = be(b, q + 4)
            if ll <= 0 or q + 8 + ll > len(b):
                break
            q += 8 + ll
        info = read_smf(b, q)
        if info:
            tot_ticks += max(info["tracks"]) if info["tracks"] else 0
            tot_secs += secs(info)
            tot_events += info["events"]
            rows.append((p, l, info["fmt"], info["ntrk"],
                         max(info["tracks"]) if info["tracks"] else 0,
                         secs(info)))
    print("SOUN chunks        %d, %d bytes" % (len(souns), sum(l for _, l in souns)))
    print("first inner tag    %s" % dict(kinds))
    print("format wrappers    %s" % dict(fmts))
    print("wrappers whose declared length matches: %d of %d"
          % (declared_ok, declared_n))
    print("SMFs parsed        %d" % len(rows))
    print("MIDI events        %d" % tot_events)
    print("summed longest-track duration %.1f s = %.2f min"
          % (tot_secs, tot_secs / 60))
    if rows:
        print("longest single cue %.1f s" % max(r[5] for r in rows))
        print("track counts       %s"
              % dict(collections.Counter(r[3] for r in rows).most_common()))
    if csv:
        with open(csv, "w") as f:
            f.write("offset,chunkbytes,format,tracks,ticks,seconds\n")
            for r in rows:
                f.write("%d,%d,%d,%d,%d,%.3f\n" % r)
        print("wrote %s" % csv)


def main(argv):
    key = 0
    csv = None
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--key":
            key = int(argv[i + 1], 0); i += 2
        elif argv[i] == "--csv":
            csv = argv[i + 1]; i += 2
        else:
            rest.append(argv[i]); i += 1
    if rest[0] == "file":
        cmd_file(rest[1])
    elif rest[0] == "souns":
        cmd_souns(rest[1], key or 0x69, csv)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
