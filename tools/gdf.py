#!/usr/bin/env python3
"""gdf.py -- read a Windows Game Definition File out of a PE's resources.

A GDF is Microsoft's Games Explorer card (Windows Vista/7, `gameux.dll`): an
XML document in the resource type `DATA`, name `__GDF_XML`, one per language,
and a picture in `__GDF_THUMBNAIL`. The schema is Microsoft's and public
(GDF schema v1/v2: `<GameDefinitionFile>`, `<GameDefinition>`, `<Name>`,
`<ReleaseDate>`, `<Genres>`, `<Developer>`, `<Publisher>`, `<Description>`,
`<Ratings>`, `<SavedGames>`, `<ExtendedProperties>`, `<GameTasks>`); the PE
resource tree is Microsoft's PE/COFF; nothing here is guessed. `pe.py` lists
the entries; this tool reads what is in them.

Written on pc-losthorizon-doc, whose `LostHorizonGDF.dll` carries six XML
blocks (languages 1024, 1031, 1033, 1036, 1040, 3082) and six thumbnails of
182,801 bytes: the object's own card -- title, date, developer, publisher --
before a single archive is opened.

The selection is by RESOURCE NAME (`__GDF_XML`, `__GDF_THUMBNAIL`), which is
the GDF specification's own signature; a PE with neither is refused. The
thumbnail's format is read from its own head (PNG / JPEG / BMP) and not from
the schema, which does not fix it.

    python tools/gdf.py FILE                  the card, one block per language
    python tools/gdf.py FILE --list           the resource entries
    python tools/gdf.py FILE --extract DIR    write every block and thumbnail
    python tools/gdf.py FILE --raw LANG       print one XML block whole
    python tools/gdf.py --selftest
"""
import argparse
import hashlib
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                  # noqa: E402
import nameguard                                 # noqa: E402
import pe                                        # noqa: E402

nameguard.guard()

LANGS = {1024: "neutral (0x400)", 1031: "German", 1033: "English (US)",
         1036: "French", 1040: "Italian", 3082: "Spanish (modern)",
         2057: "English (UK)", 1043: "Dutch", 1045: "Polish", 1049: "Russian",
         1046: "Portuguese (BR)", 1041: "Japanese", 2052: "Chinese (PRC)"}

FIELDS = ("Name", "ReleaseDate", "Genre", "Developer", "Publisher",
          "Description", "Version", "GameID")


def picture_kind(b):
    """What the thumbnail is, from its own head."""
    if b.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(b) >= 24:
            w, h = struct.unpack_from(">II", b, 16)
            return "PNG %d x %d" % (w, h)
        return "PNG"
    if b.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if b.startswith(b"BM"):
        return "BMP"
    if b.startswith(b"GIF8"):
        return "GIF"
    return "unknown (%s)" % b[:4].hex()


def resources(p):
    """(name, lang, offset, size) for every DATA resource named __GDF_*."""
    rva, _size = p.dirs[2] if len(p.dirs) > 2 else (0, 0)
    if not rva:
        return []
    base = p.rva_to_off(rva)
    if base is None:
        return []
    out = []
    pe.walk_res(p, base, base, 0, [], out)
    rows = []
    for path, drva, dsize in out:
        if len(path) < 3 or not isinstance(path[1], str):
            continue
        if not path[1].startswith("__GDF_"):
            continue
        off = p.rva_to_off(drva)
        if off is None:
            continue
        rows.append((path[1], path[2], off, dsize))
    rows.sort(key=lambda r: (r[0], r[1]))
    return rows


def decode_xml(blob):
    """The GDF XML is UTF-16 (a BOM in every block seen) or UTF-8."""
    if blob[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return blob.decode("utf-16")
    if blob[:3] == b"\xef\xbb\xbf":
        return blob[3:].decode("utf-8")
    return blob.decode("utf-8", "replace")


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def card(text):
    """The fields of one GDF block, by local tag name, namespace ignored."""
    root = ET.fromstring(text.lstrip("﻿"))
    out = {}
    for el in root.iter():
        t = _local(el.tag)
        if t == "GameDefinition":
            out["GameID"] = el.get("gameID", "")
        elif t == "Genre":
            out.setdefault("Genre", [])
            out["Genre"].append((el.text or "").strip())
        elif t in ("Developer", "Publisher"):
            out[t] = ((el.text or "").strip(), el.get("URI", ""))
        elif t == "Version":
            out["Version"] = (el.text or "").strip()
        elif t in ("Name", "ReleaseDate", "Description"):
            out[t] = re.sub(r"\s+", " ", (el.text or "")).strip()
        elif t == "SavedGames":
            out["SavedGames"] = (el.get("baseKnownFolderID", ""),
                                 el.get("path", ""))
        elif t == "Rating":
            out.setdefault("Ratings", [])
            out["Ratings"].append((el.get("ratingSystemID", ""),
                                   el.get("ratingID", "")))
        elif t == "GameTask" or t == "Task":
            out.setdefault("Tasks", [])
            out["Tasks"].append((el.get("name", ""),
                                 " ".join("%s=%s" % (_local(c.tag),
                                                     c.get("path", c.text or ""))
                                          for c in el)))
    return out


def load(path):
    dirguard.want_file(path, "gdf")
    try:
        p = pe.PE(path)
    except (ValueError, struct.error) as e:
        sys.exit("gdf: %s" % e)
    rows = resources(p)
    if not any(r[0] == "__GDF_XML" for r in rows):
        sys.exit("gdf: %s carries no __GDF_XML resource: not a Game "
                 "Definition File" % nameguard.safe(path))
    return p, rows


def show(p, rows):
    print("%s: %d GDF resources" % (nameguard.safe(os.path.basename(
        p.path)), len(rows)))
    xml_rows = [r for r in rows if r[0] == "__GDF_XML"]
    thumbs = [r for r in rows if r[0] == "__GDF_THUMBNAIL"]
    for name, lang, off, size in xml_rows:
        text = decode_xml(p.data[off:off + size])
        c = card(text)
        print()
        print("  __GDF_XML lang %d (%s)  %d bytes  sha1 %s"
              % (lang, LANGS.get(lang, "?"), size,
                 hashlib.sha1(p.data[off:off + size]).hexdigest()[:12]))
        for k in FIELDS:
            if k not in c:
                continue
            v = c[k]
            if isinstance(v, tuple):
                v = "%s   URI=%s" % v
            elif isinstance(v, list):
                v = ", ".join(v)
            print("    %-12s %s" % (k, v))
        for k in ("SavedGames", "Ratings", "Tasks"):
            if k in c:
                print("    %-12s %s" % (k, c[k]))
    if thumbs:
        print()
        sha = {}
        for name, lang, off, size in thumbs:
            b = p.data[off:off + size]
            h = hashlib.sha1(b).hexdigest()
            sha.setdefault(h, []).append(lang)
            print("  __GDF_THUMBNAIL lang %d  %d bytes  %s  sha1 %s"
                  % (lang, size, picture_kind(b), h[:12]))
        print("  thumbnails: %d, distinct by sha1: %d" % (len(thumbs), len(sha)))


def extract(p, rows, outdir):
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for name, lang, off, size in rows:
        b = p.data[off:off + size]
        if name == "__GDF_XML":
            fn = "gdf-%d.xml" % lang
        else:
            kind = picture_kind(b).split()[0].lower()
            ext = {"png": "png", "jpeg": "jpg", "bmp": "bmp"}.get(kind, "bin")
            fn = "thumb-%d.%s" % (lang, ext)
        with open(os.path.join(outdir, fn), "wb") as fh:
            fh.write(b)
        n += 1
    print("wrote %d files to %s" % (n, nameguard.safe(outdir)))


SAMPLE = """<?xml version="1.0" encoding="utf-16"?>
<GameDefinitionFile xmlns:baseTypes="urn:schemas-microsoft-com:GamesExplorerBaseTypes.v1" xmlns="urn:schemas-microsoft-com:GameDescription.v1">
  <GameDefinition gameID="{3DD51863-BA4A-4396-85D6-C44121C0AD46}">
    <Name>Sample Title</Name>
    <Description>A
       description   on two lines</Description>
    <ReleaseDate>2010-08-27</ReleaseDate>
    <Genres><Genre>Action/Adventure</Genre></Genres>
    <Ratings><Rating ratingSystemID="{0}" ratingID="{1}"/></Ratings>
    <Version><VersionNumber>1.0.0.0</VersionNumber></Version>
    <SavedGames baseKnownFolderID="{FDD39AD0-238F-46AF-ADB4-6C85480369C7}" path="Sample"/>
    <Developer URI="http://www.example.de/">Example Studio</Developer>
    <Publisher URI="http://www.example.com">Example Publisher</Publisher>
    <ExtendedProperties><GameTasks><Play><Primary><FileTask path="game.exe"/></Primary></Play></GameTasks></ExtendedProperties>
  </GameDefinition>
</GameDefinitionFile>"""


def selftest():
    checks = []
    c = card(SAMPLE)
    checks.append(("Name is read", c.get("Name") == "Sample Title", c.get("Name")))
    checks.append(("ReleaseDate is read", c.get("ReleaseDate") == "2010-08-27", ""))
    checks.append(("Developer is (text, URI)",
                   c.get("Developer") == ("Example Studio", "http://www.example.de/"),
                   str(c.get("Developer"))))
    checks.append(("Publisher is (text, URI)",
                   c.get("Publisher") == ("Example Publisher", "http://www.example.com"), ""))
    checks.append(("the description's whitespace is folded",
                   c.get("Description") == "A description on two lines",
                   repr(c.get("Description"))))
    checks.append(("the gameID is read off the attribute",
                   c.get("GameID") == "{3DD51863-BA4A-4396-85D6-C44121C0AD46}", ""))
    checks.append(("Genre is a list", c.get("Genre") == ["Action/Adventure"], ""))
    checks.append(("SavedGames carries the folder GUID and path",
                   c.get("SavedGames") == ("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", "Sample"), ""))
    utf16 = b"\xff\xfe" + SAMPLE.encode("utf-16-le")
    checks.append(("a UTF-16 block with a BOM decodes",
                   card(decode_xml(utf16)).get("Name") == "Sample Title", ""))
    checks.append(("a UTF-8 block with a BOM decodes",
                   card(decode_xml(b"\xef\xbb\xbf" + SAMPLE.encode("utf-8"))).get("Name")
                   == "Sample Title", ""))
    checks.append(("a PNG head is named PNG with its size",
                   picture_kind(b"\x89PNG\r\n\x1a\n" + bytes(8)
                                + struct.pack(">II", 256, 256)) == "PNG 256 x 256", ""))
    checks.append(("a JPEG head is named JPEG",
                   picture_kind(b"\xff\xd8\xff\xe0") == "JPEG", ""))
    checks.append(("four random bytes are unknown",
                   picture_kind(b"\x01\x02\x03\x04").startswith("unknown"), ""))
    checks.append(("a block that is not XML raises, and is not silently a card",
                   _raises(lambda: card("not xml at all")), ""))
    width = max(len(x[0]) for x in checks)
    failed = 0
    for label, ok, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if ok else "FAIL", note))
        failed += 0 if ok else 1
    print()
    print("%d checks, %d failures (0 skipped: the selftest needs no object)"
          % (len(checks), failed))
    return 1 if failed else 0


def _raises(fn):
    try:
        fn()
    except ET.ParseError:
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file", nargs="?")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--extract", metavar="DIR")
    ap.add_argument("--raw", type=int, metavar="LANG")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.file:
        ap.error("give a PE file or --selftest")
    p, rows = load(a.file)
    p.path = a.file
    if a.list:
        for name, lang, off, size in rows:
            print("  %-16s lang %-5d file 0x%08X  %d bytes" % (name, lang, off, size))
        return 0
    if a.raw is not None:
        for name, lang, off, size in rows:
            if name == "__GDF_XML" and lang == a.raw:
                sys.stdout.write(decode_xml(p.data[off:off + size]))
                return 0
        sys.exit("gdf: no __GDF_XML for language %d" % a.raw)
    if a.extract:
        extract(p, rows, a.extract)
        return 0
    show(p, rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
