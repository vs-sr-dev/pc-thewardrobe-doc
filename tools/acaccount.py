#!/usr/bin/env python3
"""acaccount.py -- the accounting of this object, to residue zero, with a
column no object in this collection has needed before: redundancy.

Every file is assigned by the FIRST rule it matches. The rules are about what
the file IS, and on this object the extension is not even evidence: 1,559 of
the 1,598 files have no extension at all and their names are a bare GUID. So
the rules are magic and position, never suffix, except for the four files whose
suffix is the only thing anybody has -- and those four are read anyway.

The two resource rules are the interesting ones. A file in
`OfficialContent\\Resources\\` is not classified by guessing: `header.bin`
holds 112 GUID lists, one per `ContentModel` type, and the type names are in
`Storage.dll`'s user-string heap in the same alphabetical order. Slot 109 is
`Visualization` and holds 1,547 of the GUIDs; slot 64 is `Music` and holds 12.
So the twelve files that have no magic are named by the object's own index and
not by their size.

The redundancy column is separate from the bucket. A file is REDUNDANT if some
other file in the tree has the same sha1 and sorts before it; the bytes are
still counted in its bucket, and the redundancy total is reported beside the
buckets rather than subtracted from them, because both numbers are true and
subtracting one from the other is what produces a wrong total.

    python tools/acaccount.py academagia-steam
    python tools/acaccount.py academagia-steam --split
    python tools/acaccount.py --selftest
"""
import argparse
import collections
import hashlib
import os
import struct
import sys
import uuid

PNG = b"\x89PNG\r\n\x1a\n"
JPEG = b"\xff\xd8\xff"
OGG = b"OggS"
PDF = b"%PDF"
ICO = b"\x00\x00\x01\x00"
MZ = b"MZ"
ZIP = b"PK\x03\x04"

# The nine assemblies that are not the studio's, by file name. Used only for
# the four-way split, never for the bucket table.
THIRD_PARTY = {
    "Castle.DynamicProxy.dll", "FirebirdSql.Data.FirebirdClient.dll",
    "Iesi.Collections.dll", "NHibernate.dll", "OpenTK.dll",
    "System.Linq.Dynamic.dll", "log4net.dll", "NVorbis.dll",
    "NVorbis.OpenTKSupport.dll", "CSteamworks.dll", "steam_api64.dll",
    "steam_api.dll", "openal32.dll",
}
STUDIO_PE = {
    "Academagia.exe", "Academagia.UI.dll", "Academagia.Core.dll",
    "Common.dll", "ContentModel.dll", "GameLogic.dll", "Storage.dll",
    "FontLibrary.dll",
}


def head(path, n=16):
    with open(path, "rb") as f:
        return f.read(n)


def classify(rel, path, size, music, visual):
    """Return (bucket, status). First rule wins; the order is the rule."""
    parts = rel.replace("\\", "/").split("/")
    name = parts[-1]
    h = head(path)
    if parts[:2] == ["OfficialContent", "Resources"]:
        try:
            g = uuid.UUID(name).bytes_le
        except ValueError:
            return "a resource whose name is not a GUID", "not derived"
        if g in music:
            return "Music resource (named by the index)", "named"
        if g in visual:
            if h.startswith(PNG):
                return "Visualization resource, PNG (published)", "read"
            if h.startswith(JPEG):
                return "Visualization resource, JPEG (published)", "read"
            return "Visualization resource, no magic", "not derived"
        return "a resource the index does not list", "not derived"
    if rel.replace("\\", "/") == "OfficialContent/info.bin":
        return "content manifest, MS-NRBF (published)", "read"
    if rel.replace("\\", "/") == "OfficialContent/header.bin":
        return "content index, Storage (derived)", "read"
    if rel.replace("\\", "/") == "OfficialContent/data.bin":
        return "content dump, Storage (derived, in part)", "part"
    if parts[:2] == ["OfficialContent", "Media"] and h.startswith(OGG):
        return "Ogg Vorbis (published)", "read"
    if name.lower().endswith(".mdm") and h.startswith(ZIP):
        return "mod package, OPC/ZIP (published)", "read"
    if h.startswith(MZ):
        return "PE/COFF (published)", "read"
    if h.startswith(PDF):
        return "PDF (published)", "read"
    if h.startswith(ICO):
        return "ICO (published)", "read"
    if name.lower().endswith((".xml", ".config", ".txt")):
        return "text and configuration", "read"
    return "FORMAT NOT DERIVED", "not derived"


def index_sets(root):
    """The Music and Visualization GUID sets, taken from header.bin itself."""
    hp = os.path.join(root, "OfficialContent", "header.bin")
    with open(hp, "rb") as f:
        h = f.read()
    slots = []
    p = 0
    while p < len(h):
        if h[p] == 0:
            slots.append(None)
            p += 1
            continue
        if h[p] != 0xFF:
            raise SystemExit("acaccount: header.bin byte %#04x at %d is "
                             "neither a null slot nor a list" % (h[p], p))
        c = struct.unpack_from("<I", h, p + 1)[0]
        slots.append((p + 5, c))
        p += 5 + 16 * c
    if len(slots) != 112:
        raise SystemExit("acaccount: header.bin has %d slots, not 112 -- the "
                         "type table no longer lines up" % len(slots))
    out = []
    for i in (64, 109):                      # Music, Visualization
        off, c = slots[i]
        out.append({bytes(h[off + 16 * k:off + 16 * k + 16])
                    for k in range(c)})
    return out


def run(root, split=False):
    music, visual = index_sets(root)
    rows = []
    for dirpath, _, files in os.walk(root):
        for f in sorted(files):
            p = os.path.join(dirpath, f)
            rel = os.path.relpath(p, root)
            size = os.path.getsize(p)
            with open(p, "rb") as fh:
                sha = hashlib.sha1(fh.read()).hexdigest()
            rows.append((rel, p, size, sha))
    rows.sort()
    seen = {}
    redundant = 0
    redundant_bytes = 0
    buckets = collections.OrderedDict()
    status_of = {}
    for rel, p, size, sha in rows:
        if sha in seen:
            redundant += 1
            redundant_bytes += size
        else:
            seen[sha] = rel
        b, st = classify(rel, p, size, music, visual)
        e = buckets.setdefault(b, [0, 0, 0, 0])
        e[0] += 1
        e[1] += size
        if sha in seen and seen[sha] != rel:
            e[2] += 1
            e[3] += size
        status_of[b] = st
    total_f = sum(e[0] for e in buckets.values())
    total_b = sum(e[1] for e in buckets.values())
    print("root  : %s" % root)
    print()
    print("%-44s %6s %13s %10s %8s %12s  %s"
          % ("bucket", "files", "bytes", "share", "dupes", "dupe bytes",
             "status"))
    for b, e in sorted(buckets.items(), key=lambda kv: -kv[1][1]):
        print("%-44s %6d %13d %9.4f %% %8d %12d  %s"
              % (b, e[0], e[1], 100.0 * e[1] / total_b, e[2], e[3],
                 status_of[b]))
    print()
    print("sum   : %d files, %d bytes" % (total_f, total_b))
    on_disk_f = len(rows)
    on_disk_b = sum(r[2] for r in rows)
    print("tree  : %d files, %d bytes" % (on_disk_f, on_disk_b))
    print("residue against the tree : %d files, %d bytes"
          % (on_disk_f - total_f, on_disk_b - total_b))
    print()
    by_status = collections.Counter()
    bytes_status = collections.Counter()
    for b, e in buckets.items():
        by_status[status_of[b]] += e[0]
        bytes_status[status_of[b]] += e[1]
    for st in ("read", "part", "named", "not derived"):
        if by_status[st] or bytes_status[st]:
            print("%-12s : %6d files  %13d bytes  %8.4f %%"
                  % (st, by_status[st], bytes_status[st],
                     100.0 * bytes_status[st] / total_b))
    print()
    print("REDUNDANCY, reported beside the buckets and never subtracted:")
    print("  distinct sha1        : %d of %d files" % (len(seen), on_disk_f))
    print("  second-and-later copies : %d files  %d bytes  %.4f %%"
          % (redundant, redundant_bytes, 100.0 * redundant_bytes / total_b))
    if split:
        print()
        four = collections.Counter()
        fourf = collections.Counter()
        for rel, p, size, sha in rows:
            name = os.path.basename(rel)
            parts = rel.replace("\\", "/").split("/")
            if name in THIRD_PARTY:
                k = "third-party code"
            elif name in STUDIO_PE:
                k = "the studio's own code"
            elif parts[:2] == ["OfficialContent", "Resources"] or \
                    parts[:2] == ["OfficialContent", "Media"] or \
                    name.lower() in ("academagia.ico",):
                k = "art and audio"
            elif parts[0] in ("OfficialContent", "Mods"):
                k = "the studio's own content"
            else:
                k = "everything else"
            four[k] += size
            fourf[k] += 1
        print("THE FOUR-WAY SPLIT")
        for k, v in sorted(four.items(), key=lambda kv: -kv[1]):
            print("  %-26s %6d files %13d bytes %8.4f %%"
                  % (k, fourf[k], v, 100.0 * v / total_b))
        print("  sum %d against %d" % (sum(four.values()), total_b))
        code = four["third-party code"] + four["the studio's own code"]
        data = total_b - code
        print("  data : code = %.2f : 1" % (data / code))
    return 0


def selftest():
    """Specimens that must be classified, and specimens that must not."""
    import tempfile
    ok = 0
    fail = []
    music = {uuid.UUID(int=1).bytes_le}
    visual = {uuid.UUID(int=2).bytes_le}
    with tempfile.TemporaryDirectory() as td:
        cases = [
            ("OfficialContent/Resources/" + str(uuid.UUID(int=2)),
             PNG + b"\0" * 8, "Visualization resource, PNG (published)"),
            ("OfficialContent/Resources/" + str(uuid.UUID(int=1)),
             b"\x0e" * 16, "Music resource (named by the index)"),
            ("OfficialContent/Resources/" + str(uuid.UUID(int=3)),
             PNG + b"\0" * 8, "a resource the index does not list"),
            ("OfficialContent/Resources/not-a-guid", b"\0" * 16,
             "a resource whose name is not a GUID"),
            ("Mods/x.mdm", ZIP + b"\0" * 12, "mod package, OPC/ZIP (published)"),
            ("x.dll", MZ + b"\0" * 14, "PE/COFF (published)"),
            ("m.pdf", PDF + b"\0" * 12, "PDF (published)"),
            ("q.dat", b"\x01\x02\x03\x04" + b"\0" * 12, "FORMAT NOT DERIVED"),
            # A PNG that is NOT under Resources must not become a resource.
            ("loose.png", PNG + b"\0" * 8, "FORMAT NOT DERIVED"),
        ]
        for rel, blob, want in cases:
            p = os.path.join(td, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(blob)
            got, _ = classify(rel, p, len(blob), music, visual)
            if got == want:
                ok += 1
            else:
                fail.append("%s -> %r, wanted %r" % (rel, got, want))
    print("selftest: %d of %d specimens classified as required "
          "(4 of the 9 must land in a bucket that means 'not read')"
          % (ok, 9))
    for f in fail:
        print("  FAILED: %s" % f)
    return 0 if not fail else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?")
    ap.add_argument("--split", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.root:
        ap.error("give a root or --selftest")
    return run(a.root, a.split)


if __name__ == "__main__":
    sys.exit(main())
