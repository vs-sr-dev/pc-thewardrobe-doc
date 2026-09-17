#!/usr/bin/env python3
"""smfcensus.py -- census a tree of Standard MIDI Files against the published
format, close each one on its own declared chunk lengths, and read out every
text-bearing meta event.

Standard MIDI File is specified: MMA/AMEI RP-001, the 1988 specification the
MIDI Manufacturers Association published and still sells. This tool uses that
specification and says so. Three things it measures that a player does not
report:

  * **closure.** 14 bytes of MThd plus, for each of the `ntrks` tracks, 8 bytes
    of MTrk header and the declared data length, must equal the file's byte
    count. Residue is printed per file and in total, and a file with bytes after
    its last track is a different object from one without;
  * **the track count against the header.** `MThd` declares how many tracks
    there are before any of them is read. A file where the walk finds a
    different number is reporting on itself incorrectly, and that is worth
    knowing on a stock library;
  * **the text.** Meta events 0x01 text, 0x02 copyright, 0x03 sequence/track
    name, 0x04 instrument, 0x05 lyric, 0x06 marker and 0x08 program name carry
    whatever the authoring tool or the composer put there. On a resource library
    shipped by a publisher, that is the only place a human name can survive.

The playing time is computed from the tempo map -- every 0x51 set-tempo event
in track order -- and not from a single tempo assumed at the start, because a
file that changes tempo would otherwise be misreported.

    python tools/smfcensus.py <root>
    python tools/smfcensus.py <root> --text
    python tools/smfcensus.py <root> --tsv notes/smfcensus.tsv
    python tools/smfcensus.py selftest
"""
import argparse
import collections
import os
import struct
import sys

TEXT_META = {0x01: "text", 0x02: "copyright", 0x03: "name",
             0x04: "instrument", 0x05: "lyric", 0x06: "marker",
             0x07: "cue", 0x08: "program", 0x09: "device"}


class Bad(Exception):
    pass


def varlen(buf, i):
    """A MIDI variable-length quantity: seven bits per byte, high bit continues."""
    v = 0
    n = 0
    while True:
        if i + n >= len(buf):
            raise Bad("a variable-length quantity runs off the end at %d" % i)
        b = buf[i + n]
        v = (v << 7) | (b & 0x7F)
        n += 1
        if not b & 0x80:
            return v, n
        if n > 4:
            raise Bad("a variable-length quantity longer than four bytes at %d"
                      % i)


def walk_track(data):
    """Return (events, ticks, tempos, texts) for one MTrk body.

    Running status is honoured, because a file that uses it is not malformed and
    a reader that does not is simply wrong.
    """
    i = 0
    ticks = 0
    running = None
    events = 0
    tempos = []
    texts = []
    while i < len(data):
        delta, n = varlen(data, i)
        i += n
        ticks += delta
        if i >= len(data):
            raise Bad("a delta time at the end of the track with no event")
        b = data[i]
        if b == 0xFF:
            i += 1
            if i >= len(data):
                raise Bad("a meta event with no type byte")
            mtype = data[i]
            i += 1
            ln, n = varlen(data, i)
            i += n
            if i + ln > len(data):
                raise Bad("meta event 0x%02X declares %d bytes and the track "
                          "ends at %d" % (mtype, ln, len(data)))
            payload = data[i:i + ln]
            i += ln
            if mtype == 0x51 and ln == 3:
                tempos.append((ticks, (payload[0] << 16) | (payload[1] << 8)
                               | payload[2]))
            if mtype in TEXT_META:
                texts.append((TEXT_META[mtype], payload))
            events += 1
            if mtype == 0x2F:
                if i != len(data):
                    raise Bad("end-of-track at %d but the track is %d bytes"
                              % (i, len(data)))
                return events, ticks, tempos, texts
            continue
        if b in (0xF0, 0xF7):
            i += 1
            ln, n = varlen(data, i)
            i += n
            if i + ln > len(data):
                raise Bad("a system-exclusive event overruns the track")
            i += ln
            events += 1
            continue
        if b & 0x80:
            running = b
            i += 1
        elif running is None:
            raise Bad("a data byte 0x%02X at %d with no running status" % (b, i))
        need = 1 if (running & 0xF0) in (0xC0, 0xD0) else 2
        if i + need > len(data):
            raise Bad("a channel event at %d needs %d data bytes and the track "
                      "ends at %d" % (i, need, len(data)))
        i += need
        events += 1
    raise Bad("the track ended without an end-of-track meta event")


def walk_smf(blob):
    """Return a dict of everything the file declares about itself, or raise."""
    if len(blob) < 14:
        raise Bad("shorter than a 14-byte MThd: %d bytes" % len(blob))
    if blob[:4] != b"MThd":
        raise Bad("no MThd at 0: %r" % blob[:4])
    (hlen,) = struct.unpack_from(">I", blob, 4)
    if hlen != 6:
        raise Bad("MThd declares a header length of %d, not 6" % hlen)
    fmt, ntrks, division = struct.unpack_from(">HHH", blob, 8)
    if fmt not in (0, 1, 2):
        raise Bad("MThd declares format %d, which is not 0, 1 or 2" % fmt)
    off = 8 + hlen
    tracks = []
    while off + 8 <= len(blob):
        tag = blob[off:off + 4]
        (tlen,) = struct.unpack_from(">I", blob, off + 4)
        if off + 8 + tlen > len(blob):
            raise Bad("track %d at %d declares %d bytes and the file ends at %d"
                      % (len(tracks), off, tlen, len(blob)))
        if tag != b"MTrk":
            raise Bad("expected MTrk at %d, found %r" % (off, tag))
        body = blob[off + 8:off + 8 + tlen]
        tracks.append((off, tlen, walk_track(body)))
        off += 8 + tlen
    return dict(format=fmt, ntrks_declared=ntrks, ntrks_walked=len(tracks),
                division=division, tracks=tracks, residue=len(blob) - off)


def seconds(info):
    """Playing time from the tempo map, in seconds, or None for SMPTE division."""
    div = info["division"]
    if div & 0x8000:
        return None
    if div == 0:
        return None
    # Merge every track's tempo events onto one timeline; format 1 puts them in
    # track 0 by convention but nothing enforces it.
    tempos = sorted(t for tr in info["tracks"] for t in tr[2][2])
    end = max((tr[2][1] for tr in info["tracks"]), default=0)
    if not tempos or tempos[0][0] > 0:
        tempos = [(0, 500000)] + tempos
    total = 0.0
    for k, (tick, usq) in enumerate(tempos):
        nxt = tempos[k + 1][0] if k + 1 < len(tempos) else end
        if nxt > tick:
            total += (nxt - tick) * (usq / 1e6) / div
    return total


def census(root, show_text, tsv):
    rows = []
    refused = []
    for dp, dn, fn in os.walk(root):
        for f in sorted(fn):
            if not f.lower().endswith((".mid", ".midi")):
                continue
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            blob = open(p, "rb").read()
            try:
                info = walk_smf(blob)
            except Bad as e:
                refused.append((rel, str(e)))
                continue
            info["path"] = rel
            info["dirname"] = os.path.dirname(rel) or "."
            info["bytes"] = len(blob)
            info["seconds"] = seconds(info)
            rows.append(info)
    if not rows and not refused:
        sys.exit("smfcensus: no .mid under %r -- refusing to report a clean "
                 "census over an empty population" % root)

    print("root                      : %s" % root)
    print("files matching .mid/.midi : %d" % (len(rows) + len(refused)))
    print("parsed as Standard MIDI   : %d" % len(rows))
    print("refused                   : %d" % len(refused))
    for rel, why in refused:
        print("   %-46s %s" % (rel, why))
    print("bytes in parsed files     : %d" % sum(r["bytes"] for r in rows))
    print()
    print("-- closure: 14 + every declared MTrk length --------------------")
    print("   files closing at residue 0            : %d of %d"
          % (sum(1 for r in rows if r["residue"] == 0), len(rows)))
    for r in [x for x in rows if x["residue"] != 0][:10]:
        print("   %-42s residue %d" % (r["path"], r["residue"]))
    print("   files whose walked track count equals")
    print("   the count MThd declares               : %d of %d"
          % (sum(1 for r in rows
                 if r["ntrks_declared"] == r["ntrks_walked"]), len(rows)))
    print("   tracks walked                         : %d"
          % sum(r["ntrks_walked"] for r in rows))
    print("   events walked                         : %d"
          % sum(t[2][0] for r in rows for t in r["tracks"]))
    print()
    print("-- what MThd declares -----------------------------------------")
    print("   format  tracks  division  files")
    shape = collections.Counter((r["format"], r["ntrks_declared"],
                                 r["division"]) for r in rows)
    for (f, n, d), c in sorted(shape.items()):
        print("   %6d  %6d  %8d  %5d" % (f, n, d, c))
    print("   distinct formats   : %s"
          % dict(collections.Counter(r["format"] for r in rows)))
    print("   distinct divisions : %s"
          % dict(collections.Counter(r["division"] for r in rows)))
    print()
    print("-- the tempo map and the playing time -------------------------")
    timed = [r for r in rows if r["seconds"] is not None]
    print("   files with a usable division          : %d of %d"
          % (len(timed), len(rows)))
    print("   total playing time                    : %.3f s (%.2f min)"
          % (sum(r["seconds"] for r in timed),
             sum(r["seconds"] for r in timed) / 60.0))
    ntemp = collections.Counter(
        sum(len(t[2][2]) for t in r["tracks"]) for r in rows)
    print("   set-tempo events per file             : %s" % dict(sorted(ntemp.items())))
    longest = max(timed, key=lambda r: r["seconds"])
    shortest = min(timed, key=lambda r: r["seconds"])
    print("   longest  : %-30s %.3f s" % (longest["path"], longest["seconds"]))
    print("   shortest : %-30s %.3f s" % (shortest["path"], shortest["seconds"]))
    print()
    print("-- text-bearing meta events -----------------------------------")
    kinds = collections.Counter()
    strings = collections.Counter()
    for r in rows:
        for t in r["tracks"]:
            for kind, payload in t[2][3]:
                kinds[kind] += 1
                strings[(kind, payload)] += 1
    print("   files carrying at least one           : %d of %d"
          % (sum(1 for r in rows
                 if any(t[2][3] for t in r["tracks"])), len(rows)))
    print("   by meta type : %s" % (dict(kinds) or "{}"))
    print("   distinct strings                      : %d" % len(strings))
    if show_text:
        for (kind, payload), n in strings.most_common():
            try:
                s = payload.decode("ascii")
            except UnicodeDecodeError:
                s = repr(payload)
            print("      %-10s x%-4d %s" % (kind, n, s))

    print()
    print("-- by directory -----------------------------------------------")
    agg = collections.defaultdict(lambda: [0, 0, 0.0])
    for r in rows:
        a = agg[r["dirname"]]
        a[0] += 1
        a[1] += r["bytes"]
        a[2] += r["seconds"] or 0.0
    print("   %-16s %5s %12s %12s" % ("dir", "files", "bytes", "seconds"))
    for k in sorted(agg):
        a = agg[k]
        print("   %-16s %5d %12d %12.3f" % (k, a[0], a[1], a[2]))

    if tsv:
        with open(tsv, "w", encoding="utf-8") as fh:
            fh.write("path\tbytes\tformat\tntrks\tdivision\tresidue\t"
                     "events\tticks\tseconds\ttempos\n")
            for r in sorted(rows, key=lambda x: x["path"]):
                fh.write("%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%d\n"
                         % (r["path"], r["bytes"], r["format"],
                            r["ntrks_declared"], r["division"], r["residue"],
                            sum(t[2][0] for t in r["tracks"]),
                            max((t[2][1] for t in r["tracks"]), default=0),
                            "%.3f" % r["seconds"] if r["seconds"] is not None
                            else "-",
                            sum(len(t[2][2]) for t in r["tracks"])))
        print()
        print("full table : %s (%d rows)" % (tsv, len(rows)))
    ok = not refused and all(r["residue"] == 0 for r in rows)
    return 0 if ok else 1


def mtrk(body):
    return b"MTrk" + struct.pack(">I", len(body)) + body


def make_smf(fmt=1, ntrks=None, division=96, tracks=None, trailer=b"",
             hlen=6):
    if tracks is None:
        tracks = [b"\x00\xFF\x2F\x00"]
    n = ntrks if ntrks is not None else len(tracks)
    out = b"MThd" + struct.pack(">I", hlen) + struct.pack(">HHH", fmt, n,
                                                          division)
    for t in tracks:
        out += mtrk(t)
    return out + trailer


def selftest():
    checks = []

    def ok(name, cond):
        checks.append((name, bool(cond)))

    def refuses(name, blob, fragment):
        try:
            walk_smf(blob)
        except Bad as e:
            ok(name + " (" + fragment + ")", fragment in str(e))
        else:
            ok(name + " (" + fragment + ")", False)

    good = make_smf()
    info = walk_smf(good)
    ok("a constructed one-track SMF parses", info["ntrks_walked"] == 1)
    ok("it closes at residue 0", info["residue"] == 0)
    ok("MThd's declared count equals the walked count",
       info["ntrks_declared"] == info["ntrks_walked"])

    refuses("empty input", b"", "shorter than")
    refuses("a PNG", b"\x89PNG\r\n\x1a\n" + bytes(40), "no MThd")
    refuses("a RIFF WAVE", b"RIFF" + bytes(4) + b"WAVE" + bytes(20), "no MThd")
    refuses("an MThd declaring a 10-byte header", make_smf(hlen=10), "not 6")
    refuses("format 3", make_smf(fmt=3), "not 0, 1 or 2")
    refuses("a track whose length overruns the file",
            b"MThd" + struct.pack(">I", 6) + struct.pack(">HHH", 0, 1, 96)
            + b"MTrk" + struct.pack(">I", 1 << 20) + b"\x00",
            "ends at")
    refuses("a second chunk that is not MTrk",
            make_smf(tracks=[b"\x00\xFF\x2F\x00"])
            + b"JUNK" + struct.pack(">I", 0),
            "found b'JUNK'")
    refuses("a track with no end-of-track",
            make_smf(tracks=[b"\x00\x90\x40\x40"]), "without an end-of-track")
    refuses("end-of-track before the last byte",
            make_smf(tracks=[b"\x00\xFF\x2F\x00\x00"]),
            "end-of-track at")
    refuses("a data byte with no running status",
            make_smf(tracks=[b"\x00\x40\x40\x00\xFF\x2F\x00"]),
            "no running status")
    refuses("a variable-length quantity of five bytes",
            make_smf(tracks=[b"\xFF\xFF\xFF\xFF\xFF\x00"]),
            "longer than four bytes")

    info = walk_smf(make_smf(trailer=b"tail"))
    ok("four appended bytes are residue 4, not swallowed",
       info["residue"] == 4)

    info = walk_smf(make_smf(ntrks=7))
    ok("a header that lies about its track count is reported, not fixed",
       info["ntrks_declared"] == 7 and info["ntrks_walked"] == 1)

    # Running status: one 0x90 followed by two note pairs with no status byte.
    info = walk_smf(make_smf(
        tracks=[b"\x00\x90\x40\x40" b"\x00\x41\x40" b"\x00\xFF\x2F\x00"]))
    ok("running status is honoured and gives 3 events",
       info["tracks"][0][2][0] == 3)

    # One quarter note at 96 ticks per quarter and 500,000 us per quarter is
    # half a second.
    info = walk_smf(make_smf(
        tracks=[b"\x00\xFF\x51\x03\x07\xA1\x20" b"\x60\xFF\x2F\x00"]))
    ok("96 ticks at 500000 us/quarter is 0.5 s",
       abs(seconds(info) - 0.5) < 1e-9)
    info = walk_smf(make_smf(
        tracks=[b"\x00\xFF\x51\x03\x03\xD0\x90" b"\x60\xFF\x2F\x00"]))
    ok("the same 96 ticks at 250000 us/quarter is 0.25 s",
       abs(seconds(info) - 0.25) < 1e-9)
    info = walk_smf(make_smf(division=0x8000 | 0xE8,
                             tracks=[b"\x60\xFF\x2F\x00"]))
    ok("an SMPTE division yields no seconds rather than a wrong number",
       seconds(info) is None)

    info = walk_smf(make_smf(
        tracks=[b"\x00\xFF\x03\x04Trck" b"\x00\xFF\x02\x03(c)"
                b"\x00\xFF\x2F\x00"]))
    got = dict(info["tracks"][0][2][3])
    ok("a track name meta event is read out", got.get("name") == b"Trck")
    ok("a copyright meta event is read out", got.get("copyright") == b"(c)")

    info = walk_smf(make_smf(
        tracks=[b"\x00\xF0\x02\x7E\xF7" b"\x00\xFF\x2F\x00"]))
    ok("a system-exclusive event is skipped by its declared length",
       info["residue"] == 0)

    width = max(len(n) for n, _ in checks)
    for n, g in checks:
        print("  %-*s %s" % (width, n, "ok" if g else "FAIL"))
    bad = [n for n, g in checks if not g]
    print("%d checks, %d failures" % (len(checks), len(bad)))
    return 1 if bad else 0



def utf8_stdout():
    """Print recovered text without dying on a default Windows console.

    This tool prints strings it recovered from an object, and those strings can
    hold any byte. On a default Windows console `sys.stdout` is cp1252 and a
    single Japanese character kills the process half-way through a table. The
    previous session shipped a tool that only worked when `PYTHONIOENCODING`
    happened to be set, and that is the defect this function exists to not
    repeat: the encoding is made explicit here rather than inherited.
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--text", action="store_true")
    ap.add_argument("--tsv")
    args = ap.parse_args()
    utf8_stdout()
    if args.root == "selftest":
        return selftest()
    return census(args.root, args.text, args.tsv)


if __name__ == "__main__":
    sys.exit(main())
