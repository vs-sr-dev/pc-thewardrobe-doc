#!/usr/bin/env python3
"""asf.py - read Windows Media (.wmv) headers without decoding a frame.

ASF is a public container: a tree of GUID-tagged objects, each carrying its own
64-bit length, defined in Microsoft's Advanced Systems Format specification.
Everything this tool prints comes from that definition, and nothing below the
Header Object is touched — the Data Object, which is where the pictures and the
sound actually are, is skipped by its declared length and never read.

The objects read here:

  Header Object          75B22630-668E-11CF-A6D9-00AA0062CE6C
  File Properties        8CABDCA1-A947-11CF-8EE4-00C00C205365
      file id, file size, **creation date as a 64-bit FILETIME**,
      data packet count, play duration and send duration in 100 ns units,
      preroll, min/max packet size, maximum bitrate
  Stream Properties      B7DC0791-A9B7-11CF-8EE6-00C00C205365
      audio streams carry a WAVEFORMATEX: tag, channels, sample rate,
      average bytes per second, bits per sample
      video streams carry width, height and a BITMAPINFOHEADER with a
      four-character codec code
  Content Description    75B22633-668E-11CF-A6D9-00AA0062CE6C
  Extended Content Desc. D2D0A440-E307-11D2-97F0-00A0C95EA850
      where `WMFSDKVersion` and friends live

The creation date matters more than anything else here: the filesystem this
object lives on dates 937 of its 958 files to the four minutes of the
installation, so an internal clock is the only clock there is.

    python tools/asf.py DIR
    python tools/asf.py FILE --full
"""
import argparse
import datetime
import glob
import os
import struct
import sys

HEADER = bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c")
FILEPROPS = bytes.fromhex("a1dcab8c47a9cf118ee400c00c205365")
STREAMPROPS = bytes.fromhex("9107dcb7b7a9cf118ee600c00c205365")
CONTENTDESC = bytes.fromhex("3326b2758e66cf11a6d900aa0062ce6c")
EXTCONTENT = bytes.fromhex("40a4d0d207e3d21197f000a0c95ea850")
HEADEREXT = bytes.fromhex("b503bf5f2ea9cf118ee300c00c205365")
CODECLIST = bytes.fromhex("4052d1861d31d011a3a400a0c90348f6")
AUDIOMEDIA = bytes.fromhex("409e69f84d5bcf11a8fd00805f5c442b")
VIDEOMEDIA = bytes.fromhex("c0ef19bc4d5bcf11a8fd00805f5c442b")

WAVETAG = {
    0x0001: "PCM", 0x0002: "MS ADPCM", 0x0011: "IMA ADPCM",
    0x0055: "MP3", 0x0160: "WMA v1", 0x0161: "WMA v2",
    0x0162: "WMA 9 Professional", 0x0163: "WMA 9 Lossless",
    0x0164: "WMA Pro over S/PDIF",
}


def ft(v):
    if not v:
        return "(zero)"
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=v // 10)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "(out of range)"


def objects(buf, off, end):
    while off + 24 <= end:
        guid = buf[off:off + 16]
        size = struct.unpack_from("<Q", buf, off + 16)[0]
        if size < 24 or off + size > end:
            return
        yield guid, off, size
        off += size


def read(path):
    with open(path, "rb") as fh:
        head = fh.read(32)
        if head[:16] != HEADER:
            raise ValueError("not ASF")
        hsize = struct.unpack_from("<Q", head, 16)[0]
        nobj = struct.unpack_from("<I", head, 24)[0]
        fh.seek(0)
        buf = fh.read(min(hsize, 4 << 20))
    info = {"path": path, "size": os.path.getsize(path),
            "headersize": hsize, "objects": nobj,
            "streams": [], "ext": {}, "desc": {}, "codecs": []}
    for guid, off, size in objects(buf, 30, min(len(buf), hsize)):
        if guid == FILEPROPS:
            (fsize, created, packets, playdur, senddur, preroll,
             flags, minpk, maxpk, maxbr) = struct.unpack_from("<QQQQQQIIII", buf, off + 40)
            info.update(filesize=fsize, created=created, packets=packets,
                        playdur=playdur, senddur=senddur, preroll=preroll,
                        flags=flags, minpk=minpk, maxpk=maxpk, maxbitrate=maxbr)
        elif guid == STREAMPROPS:
            st = buf[off + 24:off + 40]
            tslen, eclen = struct.unpack_from("<II", buf, off + 64)
            sflags = struct.unpack_from("<H", buf, off + 72)[0]
            ts = buf[off + 78:off + 78 + tslen]
            if st == AUDIOMEDIA and tslen >= 16:
                tag, ch, rate, bps, align, bits = struct.unpack_from("<HHIIHH", ts, 0)
                info["streams"].append(
                    {"kind": "audio", "num": sflags & 0x7F, "tag": tag,
                     "codec": WAVETAG.get(tag, "0x%04X" % tag), "channels": ch,
                     "rate": rate, "bytespersec": bps, "bits": bits})
            elif st == VIDEOMEDIA and tslen >= 11 + 40:
                w, h = struct.unpack_from("<II", ts, 0)
                bih = ts[11:]
                cc = bih[16:20].decode("latin-1", "replace")
                bitcount = struct.unpack_from("<H", bih, 14)[0]
                info["streams"].append(
                    {"kind": "video", "num": sflags & 0x7F, "width": w,
                     "height": h, "fourcc": cc, "bits": bitcount})
            else:
                info["streams"].append({"kind": "other", "num": sflags & 0x7F})
        elif guid == CONTENTDESC:
            lens = struct.unpack_from("<HHHHH", buf, off + 24)
            p = off + 34
            for name, n in zip(("title", "author", "copyright", "description",
                                "rating"), lens):
                info["desc"][name] = buf[p:p + n].decode("utf-16-le", "replace").rstrip("\x00")
                p += n
        elif guid == EXTCONTENT:
            n = struct.unpack_from("<H", buf, off + 24)[0]
            p = off + 26
            for _i in range(n):
                nl = struct.unpack_from("<H", buf, p)[0]
                nm = buf[p + 2:p + 2 + nl].decode("utf-16-le", "replace").rstrip("\x00")
                p += 2 + nl
                vt, vl = struct.unpack_from("<HH", buf, p)
                v = buf[p + 4:p + 4 + vl]
                p += 4 + vl
                if vt == 0:
                    v = v.decode("utf-16-le", "replace").rstrip("\x00")
                elif vt == 3 and vl == 4:
                    v = struct.unpack("<I", v)[0]
                elif vt == 4 and vl == 8:
                    v = struct.unpack("<Q", v)[0]
                else:
                    v = v.hex()
                info["ext"][nm] = v
        elif guid == CODECLIST:
            cnt = struct.unpack_from("<I", buf, off + 40)[0]
            p = off + 44
            for _i in range(cnt):
                typ = struct.unpack_from("<H", buf, p)[0]
                nl = struct.unpack_from("<H", buf, p + 2)[0]
                nm = buf[p + 4:p + 4 + nl * 2].decode("utf-16-le", "replace").rstrip("\x00")
                p += 4 + nl * 2
                dl = struct.unpack_from("<H", buf, p)[0]
                ds = buf[p + 2:p + 2 + dl * 2].decode("utf-16-le", "replace").rstrip("\x00")
                p += 2 + dl * 2
                il = struct.unpack_from("<H", buf, p)[0]
                p += 2 + il
                info["codecs"].append((typ, nm, ds))
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    files = []
    for t in a.targets:
        if os.path.isdir(t):
            # walk, do not glob one level: the object this tool was pointed at
            # keeps every .wmv in a subdirectory, and a one-level glob printed
            # an empty table with no error, which is the failure mode this
            # branch has a rule about.
            found = []
            for root, _dirs, names in os.walk(t):
                for n in names:
                    if n.lower().endswith(".wmv"):
                        found.append(os.path.join(root, n))
            if not found:
                print("no .wmv under %s" % t)
            files.extend(sorted(found))
        else:
            files.append(t)

    rows = []
    print("%-18s %11s %10s %9s %7s  %-22s %-24s %s"
          % ("file", "bytes", "seconds", "packets", "kbit/s", "video", "audio", "created (UTC)"))
    print("-" * 138)
    for p in files:
        try:
            i = read(p)
        except Exception as exc:
            print("%-18s  NOT ASF: %s" % (os.path.basename(p), exc))
            continue
        sec = i["playdur"] / 1e7 - i["preroll"] / 1e3
        v = [s for s in i["streams"] if s["kind"] == "video"]
        au = [s for s in i["streams"] if s["kind"] == "audio"]
        vd = ("%s %dx%d" % (v[0]["fourcc"], v[0]["width"], v[0]["height"])) if v else "-"
        ad = ("%s %dch %dHz %db" % (au[0]["codec"], au[0]["channels"],
                                    au[0]["rate"], au[0]["bits"])) if au else "-"
        kbps = i["size"] * 8.0 / sec / 1000 if sec > 0 else 0
        print("%-18s %11d %10.3f %9d %7.1f  %-22s %-24s %s"
              % (os.path.basename(p), i["size"], sec, i["packets"], kbps,
                 vd, ad, ft(i["created"])))
        rows.append((p, i, sec))
        if a.full:
            for k in sorted(i["ext"]):
                print("        ext  %-28s %s" % (k, i["ext"][k]))
            for k in sorted(i["desc"]):
                if i["desc"][k]:
                    print("        desc %-28s %s" % (k, i["desc"][k]))
            for t, n, d in i["codecs"]:
                print("        codec type %d  %-28s %s" % (t, n, d))
            print("        packet size %d..%d  max bitrate %d  streams %d"
                  % (i["minpk"], i["maxpk"], i["maxbitrate"], len(i["streams"])))

    if not rows:
        return 0
    print("-" * 138)
    tb = sum(i["size"] for _p, i, _s in rows)
    ts = sum(s for _p, _i, s in rows)
    tp = sum(i["packets"] for _p, i, _s in rows)
    print("files                 : %d" % len(rows))
    print("bytes                 : %d" % tb)
    print("packets               : %d" % tp)
    print("play duration         : %.3f s = %.2f min = %.4f h" % (ts, ts / 60, ts / 3600))
    print("mean bitrate over all : %.1f kbit/s" % (tb * 8.0 / ts / 1000))
    print("declared max bitrate  : min %d  max %d"
          % (min(i["maxbitrate"] for _p, i, _s in rows),
             max(i["maxbitrate"] for _p, i, _s in rows)))

    def hist(fn, label):
        c = {}
        for _p, i, _s in rows:
            c[fn(i)] = c.get(fn(i), 0) + 1
        print("%-22s: %s" % (label, ", ".join("%s x%d" % (k, v)
                                              for k, v in sorted(c.items(), key=lambda kv: -kv[1]))))

    hist(lambda i: len(i["streams"]), "streams per file")
    hist(lambda i: next((("%s %dx%d" % (s["fourcc"], s["width"], s["height"]))
                         for s in i["streams"] if s["kind"] == "video"), "-"), "video")
    hist(lambda i: next((("%s %dch %dHz" % (s["codec"], s["channels"], s["rate"]))
                         for s in i["streams"] if s["kind"] == "audio"), "-"), "audio")
    hist(lambda i: i["ext"].get("WMFSDKVersion", "-"), "WMFSDKVersion")
    hist(lambda i: i["ext"].get("WMFSDKNeeded", "-"), "WMFSDKNeeded")
    hist(lambda i: i["ext"].get("IsVBR", "-"), "IsVBR")
    hist(lambda i: ft(i["created"])[:7], "creation month")
    audiobytes = 0
    for _p, i, s in rows:
        for st in i["streams"]:
            if st["kind"] == "audio":
                audiobytes += st["bytespersec"] * s
    print("audio bytes, from the declared byte rate x duration : %d = %.4f %% of the container"
          % (audiobytes, 100.0 * audiobytes / tb))
    print("distinct creation dates : %d"
          % len(set(i["created"] for _p, i, _s in rows)))
    print("creation date range     : %s .. %s"
          % (ft(min(i["created"] for _p, i, _s in rows)),
             ft(max(i["created"] for _p, i, _s in rows))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
