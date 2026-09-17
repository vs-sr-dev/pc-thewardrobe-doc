#!/usr/bin/env python3
"""xmp.py -- pull the Adobe XMP packet out of a file and read it as a clock.

XMP is a public specification (ISO 16684-1). Adobe applications embed one when
they export, and it carries three things this collection cares about and which
nothing else in a video container does: **the tool that made the file**, **dated
history entries with their UTC offset**, and, for After Effects, **the absolute
path of the project file on the machine that rendered it**.

The tool does not decode a single frame. It scans the first and last few
megabytes for the packet delimiters and parses the XML between them.

    python tools/xmp.py "<root>/ed6_op.avi"
    python tools/xmp.py "<root>" --walk --ext .avi .dat
"""
import argparse
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

OPEN = b"<x:xmpmeta"
CLOSE = b"</x:xmpmeta>"
WINDOW = 8 << 20

FIELDS = [
    ("xmp:CreatorTool", "creator tool"),
    ("xmp:CreateDate", "create date"),
    ("xmp:ModifyDate", "modify date"),
    ("xmp:MetadataDate", "metadata date"),
    ("xmpDM:videoFrameSize/stDim:w", "width"),
    ("xmpDM:videoFrameSize/stDim:h", "height"),
    ("xmpDM:videoFrameRate", "frame rate"),
    ("xmpDM:videoPixelAspectRatio", "pixel aspect"),
    ("xmpDM:videoFieldOrder", "field order"),
    ("xmpDM:audioSampleRate", "audio rate"),
    ("xmpDM:audioSampleType", "audio sample"),
    ("xmpDM:audioChannelType", "audio channels"),
    ("xmpDM:duration/xmpDM:value", "duration value"),
    ("xmpDM:duration/xmpDM:scale", "duration scale"),
    ("xmpDM:startTimecode/xmpDM:timeValue", "start timecode"),
    ("xmpDM:altTimecode/xmpDM:timeValue", "alt timecode"),
    ("creatorAtom:aeProjectLink/creatorAtom:fullPath", "After Effects project"),
    ("creatorAtom:aeProjectLink/creatorAtom:compositionID", "composition id"),
    ("creatorAtom:aeProjectLink/creatorAtom:renderQueueItemID", "render queue item"),
    ("xmpMM:DocumentID", "document id"),
    ("xmpMM:OriginalDocumentID", "original document id"),
    ("xmpMM:InstanceID", "instance id"),
]

NS = {
    "x": "adobe:ns:meta/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "xmp": "http://ns.adobe.com/xap/1.0/",
    "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
    "stEvt": "http://ns.adobe.com/xap/1.0/sType/ResourceEvent#",
    "creatorAtom": "http://ns.adobe.com/creatorAtom/1.0/",
    "xmpDM": "http://ns.adobe.com/xmp/1.0/DynamicMedia/",
    "stDim": "http://ns.adobe.com/xap/1.0/sType/Dimensions#",
    "dc": "http://purl.org/dc/elements/1.1/",
}


def extract(path):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(min(size, WINDOW))
        if size > WINDOW:
            fh.seek(max(0, size - WINDOW))
            tail = fh.read()
        else:
            tail = b""
    for where, blob, base in (("head", head, 0), ("tail", tail, max(0, size - WINDOW))):
        i = blob.find(OPEN)
        if i < 0:
            continue
        j = blob.find(CLOSE, i)
        if j < 0:
            continue
        return where, base + i, blob[i:j + len(CLOSE)]
    return None, None, None


def qname(path):
    out = []
    for part in path.split("/"):
        pre, local = part.split(":")
        out.append("{%s}%s" % (NS[pre], local))
    return out


def report(path):
    where, off, blob = extract(path)
    print("== %s ==" % os.path.basename(path))
    if blob is None:
        print("   no XMP packet found in the first or last %d bytes" % WINDOW)
        return False
    print("   packet at offset %d (%s of the file), %d bytes" % (off, where, len(blob)))
    root = ET.fromstring(blob.decode("utf-8", "replace"))
    m = re.search(r'x:xmptk="([^"]+)"', blob.decode("utf-8", "replace"))
    if m:
        print("   %-24s: %s" % ("xmp toolkit", m.group(1).strip()))
    desc = root.find(".//{%s}Description" % NS["rdf"])
    for spec, label in FIELDS:
        parts = qname(spec)
        node = desc
        for q in parts:
            if node is None:
                break
            nxt = node.find(q)
            if nxt is None:
                nxt = node.get(q)
                if nxt is not None:
                    node = nxt
                    break
                node = None
            else:
                node = nxt
        if node is None:
            continue
        val = node if isinstance(node, str) else (node.text or "")
        val = val.strip()
        if val:
            print("   %-24s: %s" % (label, val))
    # history is the part that carries a time zone
    hist = desc.findall(".//{%s}li" % NS["rdf"])
    rows = []
    for li in hist:
        act = li.find("{%s}action" % NS["stEvt"])
        wh = li.find("{%s}when" % NS["stEvt"])
        ag = li.find("{%s}softwareAgent" % NS["stEvt"])
        if act is not None or wh is not None:
            rows.append(((act.text if act is not None else ""),
                         (wh.text if wh is not None else ""),
                         (ag.text if ag is not None else "")))
    if rows:
        print("   history:")
        for act, wh, ag in rows:
            print("      %-8s %-30s %s" % (act, wh, ag))
    zones = set(re.findall(r"[+-]\d\d:\d\d", blob.decode("utf-8", "replace")))
    print("   UTC offsets present in the packet : %s" % (", ".join(sorted(zones)) or "none"))
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--walk", action="store_true")
    ap.add_argument("--ext", nargs="*", default=[".avi"])
    a = ap.parse_args()
    if not a.walk:
        ok = report(a.path)
        sys.exit(0 if ok else 1)
    found = 0
    seen = 0
    for dirpath, dirnames, filenames in os.walk(a.path):
        dirnames.sort()
        for fn in sorted(filenames):
            if os.path.splitext(fn)[1].lower() in [e.lower() for e in a.ext]:
                seen += 1
                if report(os.path.join(dirpath, fn)):
                    found += 1
                print()
    print("files examined : %d   files carrying an XMP packet : %d" % (seen, found))


if __name__ == "__main__":
    main()
