#!/usr/bin/env python3
"""nrbf.py -- read a .NET BinaryFormatter stream (MS-NRBF) to residue zero.

MS-NRBF is *[MS-NRBF]: .NET Remoting: Binary Format Data Structure*, a
published Microsoft specification. This reader implements the subset that
`OfficialContent\\info.bin` and the `info.bin` inside every `.mdm` actually
use -- the class, library, string, primitive and reference records -- and it
REFUSES anything else rather than skipping it, because a serialisation reader
that skips is a reader that lies about its residue.

The point of the tool on this object is two integers:

    Storage.Publish.PublishInfo._objectsCount
    Storage.Publish.PublishInfo._resourceCount

which are the only two denominators in the object that were written by the
program that built it.

Every run reports the residue: bytes consumed against bytes in the file. A
stream that does not end on a MessageEnd record at exactly the last byte is a
failure and is reported as one.

    python tools/nrbf.py academagia-steam/OfficialContent/info.bin
    python tools/nrbf.py --zip academagia-steam/Mods/Content.mdm --member info.bin
    python tools/nrbf.py --selftest
"""
import argparse
import datetime
import io
import os
import struct
import sys
import uuid
import zipfile

# MS-NRBF section 2.1.2.1, RecordTypeEnumeration.
SERIALIZED_STREAM_HEADER = 0
CLASS_WITH_ID = 1
SYSTEM_CLASS_WITH_MEMBERS = 2
CLASS_WITH_MEMBERS = 3
SYSTEM_CLASS_WITH_MEMBERS_AND_TYPES = 4
CLASS_WITH_MEMBERS_AND_TYPES = 5
BINARY_OBJECT_STRING = 6
BINARY_ARRAY = 7
MEMBER_PRIMITIVE_TYPED = 8
MEMBER_REFERENCE = 9
OBJECT_NULL = 10
MESSAGE_END = 11
BINARY_LIBRARY = 12
OBJECT_NULL_MULTIPLE_256 = 13
OBJECT_NULL_MULTIPLE = 14
ARRAY_SINGLE_PRIMITIVE = 15
ARRAY_SINGLE_OBJECT = 16
ARRAY_SINGLE_STRING = 17

# MS-NRBF section 2.1.2.3, PrimitiveTypeEnumeration. Note that there is no
# value 4: the enumeration runs Boolean=1, Byte=2, Char=3, (gap), Decimal=5,
# Double=6, Int16=7, Int32=8, Int64=9. Getting this table one place out is
# exactly the failure this reader was written to avoid, because a wrong width
# desynchronises the stream and the next record type byte is then garbage --
# which is what a first run of this tool produced, loudly.
PRIMITIVES = {
    1: ("Boolean", 1), 2: ("Byte", 1), 3: ("Char", None),
    5: ("Decimal", None), 6: ("Double", 8), 7: ("Int16", 2),
    8: ("Int32", 4), 9: ("Int64", 8), 10: ("SByte", 1), 11: ("Single", 4),
    12: ("TimeSpan", 8), 13: ("DateTime", 8), 14: ("UInt16", 2),
    15: ("UInt32", 4), 16: ("UInt64", 8), 17: ("Null", 0),
    18: ("String", None),
}
MEMBER_PRIMITIVES = PRIMITIVES


class NrbfError(Exception):
    pass


class Reader(object):
    def __init__(self, data):
        self.d = data
        self.p = 0

    def u8(self):
        if self.p + 1 > len(self.d):
            raise NrbfError("u8 past end at %d" % self.p)
        v = self.d[self.p]
        self.p += 1
        return v

    def i32(self):
        if self.p + 4 > len(self.d):
            raise NrbfError("i32 past end at %d" % self.p)
        v = struct.unpack_from("<i", self.d, self.p)[0]
        self.p += 4
        return v

    def raw(self, n):
        if self.p + n > len(self.d):
            raise NrbfError("read of %d past end at %d" % (n, self.p))
        v = self.d[self.p:self.p + n]
        self.p += n
        return v

    def string(self):
        """LengthPrefixedString: 7-bit encoded length, then UTF-8 bytes."""
        n = 0
        shift = 0
        while True:
            b = self.u8()
            n |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
            if shift > 35:
                raise NrbfError("string length prefix too long at %d" % self.p)
        return self.raw(n).decode("utf-8")


def _dt(ticks_word):
    """A .NET DateTime as MS-NRBF writes it: 62 bits of ticks, 2 of Kind."""
    kind = (ticks_word >> 62) & 3
    ticks = ticks_word & ((1 << 62) - 1)
    base = datetime.datetime(1, 1, 1)
    return base + datetime.timedelta(microseconds=ticks // 10), kind


def _guid_from_members(vals):
    """System.Guid serialises as _a.._k: int32, int16, int16, then 8 bytes."""
    a, b, c = vals[0], vals[1], vals[2]
    rest = bytes((v & 0xFF) for v in vals[3:11])
    return uuid.UUID(bytes=struct.pack(">IHH", a & 0xFFFFFFFF, b & 0xFFFF,
                                       c & 0xFFFF) + rest)


class Stream(object):
    """A parsed MS-NRBF stream. Objects are kept by id; classes by id."""

    def __init__(self, data):
        self.r = Reader(data)
        self.layouts = {}      # objectId -> (name, [memberName], [(kind, extra)])
        self.classes = {}      # objectId -> class name
        self.objects = {}      # objectId -> dict or value
        self.libraries = {}
        self.records = 0
        self.ended = False
        self._parse()

    # -- record dispatch ---------------------------------------------------
    def _parse(self):
        r = self.r
        t = r.u8()
        if t != SERIALIZED_STREAM_HEADER:
            raise NrbfError("first record is %d, not a stream header" % t)
        root, header, major, minor = r.i32(), r.i32(), r.i32(), r.i32()
        self.root, self.major, self.minor = root, major, minor
        self.records = 1
        if major != 1:
            raise NrbfError("major version %d is not 1" % major)
        while not self.ended:
            t = r.u8()
            self.records += 1
            self._record(t)

    def _record(self, t):
        r = self.r
        if t == BINARY_LIBRARY:
            lid = r.i32()
            self.libraries[lid] = r.string()
        elif t == MESSAGE_END:
            self.ended = True
        elif t == CLASS_WITH_MEMBERS_AND_TYPES:
            self._class(r, system=False)
        elif t == SYSTEM_CLASS_WITH_MEMBERS_AND_TYPES:
            self._class(r, system=True)
        elif t == CLASS_WITH_ID:
            self._class_with_id(r)
        elif t == BINARY_ARRAY:
            self._binary_array(r)
        elif t == BINARY_OBJECT_STRING:
            oid = r.i32()
            self.objects[oid] = r.string()
        elif t == OBJECT_NULL:
            pass
        else:
            raise NrbfError("record type %d at offset %d is not implemented; "
                            "this reader refuses rather than skips"
                            % (t, r.p - 1))

    def _class(self, r, system):
        oid = r.i32()
        name = r.string()
        count = r.i32()
        if count < 0 or count > 4096:
            raise NrbfError("member count %d for %s is not credible"
                            % (count, name))
        members = [r.string() for _ in range(count)]
        kinds = [r.u8() for _ in range(count)]
        info = []
        for k in kinds:
            if k == 0:                      # Primitive
                info.append(("prim", r.u8()))
            elif k == 1:                    # String
                info.append(("str", None))
            elif k == 3:                    # SystemClass
                info.append(("sysclass", r.string()))
            elif k == 4:                    # Class
                info.append(("class", (r.string(), r.i32())))
            elif k == 2:                    # Object
                info.append(("object", None))
            else:
                raise NrbfError("BinaryTypeEnum %d is not implemented" % k)
        if not system:
            r.i32()                         # LibraryId
        self.layouts[oid] = (name, members, info)
        vals = []
        for kind, extra in info:
            vals.append(self._value(kind, extra))
        self.classes[oid] = name
        self.objects[oid] = dict(zip(members, vals))
        self.objects[oid]["__class__"] = name
        return oid

    def _binary_array(self, r):
        """BinaryArray, MS-NRBF 2.4.3.1. `deleted.bin` inside a .mdm is a
        serialised List<Guid>, so the array of System.Guid has to be walked
        element by element -- including the ObjectNullMultiple runs that fill
        a List's spare capacity, which are the reason a List of 2,423 items
        occupies an array of 4,096."""
        oid = r.i32()
        atype = r.u8()
        rank = r.i32()
        if rank != 1 or atype not in (0, 1, 2):
            raise NrbfError("array type %d rank %d is not implemented"
                            % (atype, rank))
        lengths = [r.i32() for _ in range(rank)]
        if atype in (3, 4, 5):
            [r.i32() for _ in range(rank)]
        kind = r.u8()
        if kind == 0:
            extra = ("prim", r.u8())
        elif kind == 1:
            extra = ("str", None)
        elif kind == 3:
            extra = ("sysclass", r.string())
        elif kind == 4:
            extra = ("class", (r.string(), r.i32()))
        elif kind == 2:
            extra = ("object", None)
        else:
            raise NrbfError("array BinaryTypeEnum %d is not implemented" % kind)
        total = lengths[0]
        items = []
        while len(items) < total:
            if extra[0] == "prim":
                items.append(self._value("prim", extra[1]))
                continue
            t = self.r.u8()
            self.records += 1
            if t == OBJECT_NULL:
                items.append(None)
            elif t == OBJECT_NULL_MULTIPLE_256:
                items.extend([None] * self.r.u8())
            elif t == OBJECT_NULL_MULTIPLE:
                items.extend([None] * self.r.i32())
            elif t == MEMBER_REFERENCE:
                items.append(("ref", self.r.i32()))
            elif t == BINARY_OBJECT_STRING:
                o2 = self.r.i32()
                self.objects[o2] = self.r.string()
                items.append(self.objects[o2])
            elif t in (CLASS_WITH_MEMBERS_AND_TYPES,
                       SYSTEM_CLASS_WITH_MEMBERS_AND_TYPES):
                items.append(("obj", self._class(
                    self.r,
                    system=(t == SYSTEM_CLASS_WITH_MEMBERS_AND_TYPES))))
            elif t == CLASS_WITH_ID:
                items.append(("obj", self._class_with_id(self.r)))
            else:
                raise NrbfError("array element record %d is not implemented"
                                % t)
        if len(items) != total:
            raise NrbfError("array declared %d elements and %d were read"
                            % (total, len(items)))
        self.objects[oid] = items
        self.arrays = getattr(self, "arrays", [])
        self.arrays.append((oid, total, items))
        return oid

    def _class_with_id(self, r):
        """ClassWithId: a second instance of a class whose layout was already
        written. MS-NRBF 2.3.2.5. Without this a stream holding two objects of
        the same class cannot be read, which is exactly what a mod's info.bin
        does and the base game's does not."""
        oid = r.i32()
        mid = r.i32()
        if mid not in self.layouts:
            raise NrbfError("ClassWithId %d refers to unknown metadata id %d"
                            % (oid, mid))
        name, members, info = self.layouts[mid]
        vals = [self._value(kind, extra) for kind, extra in info]
        self.classes[oid] = name
        self.objects[oid] = dict(zip(members, vals))
        self.objects[oid]["__class__"] = name
        return oid

    def _value(self, kind, extra):
        r = self.r
        if kind == "prim":
            pname, size = MEMBER_PRIMITIVES[extra]
            if size is None:
                raise NrbfError("inline primitive %s is not implemented"
                                % pname)
            b = r.raw(size)
            if pname == "Int32":
                return struct.unpack("<i", b)[0]
            if pname == "Int64":
                return struct.unpack("<q", b)[0]
            if pname == "Int16":
                return struct.unpack("<h", b)[0]
            if pname == "Double":
                return struct.unpack("<d", b)[0]
            if pname in ("Byte", "SByte", "Boolean"):
                return b[0]
            if pname == "DateTime":
                return _dt(struct.unpack("<Q", b)[0])
            return b
        # Everything else is a nested record: read it and return a marker.
        t = r.u8()
        self.records += 1
        if t == MEMBER_REFERENCE:
            return ("ref", r.i32())
        if t == OBJECT_NULL:
            return None
        if t == BINARY_OBJECT_STRING:
            oid = r.i32()
            s = r.string()
            self.objects[oid] = s
            return s
        if t in (CLASS_WITH_MEMBERS_AND_TYPES,
                 SYSTEM_CLASS_WITH_MEMBERS_AND_TYPES):
            return ("obj", self._class(
                r, system=(t == SYSTEM_CLASS_WITH_MEMBERS_AND_TYPES)))
        if t == CLASS_WITH_ID:
            return ("obj", self._class_with_id(r))
        if t == BINARY_ARRAY:
            return ("arr", self._binary_array(r))
        if t == OBJECT_NULL_MULTIPLE_256:
            return ("nulls", r.u8())
        if t == OBJECT_NULL_MULTIPLE:
            return ("nulls", r.i32())
        raise NrbfError("nested record type %d is not implemented" % t)

    # -- the two integers --------------------------------------------------
    def publish_info(self):
        for oid, o in self.objects.items():
            if isinstance(o, dict) and o.get("__class__", "").endswith(
                    "PublishInfo"):
                return o
        raise NrbfError("no PublishInfo object in this stream")

    def db_info(self):
        for oid, o in self.objects.items():
            if isinstance(o, dict) and o.get("__class__", "") == "Storage.DBInfo":
                return o
        return None

    def guid(self):
        for oid, o in self.objects.items():
            if isinstance(o, dict) and o.get("__class__") == "System.Guid":
                vals = [o["_a"], o["_b"], o["_c"]] + [o["_" + c] for c in
                                                      "defghijk"]
                return _guid_from_members(vals)
        return None


def report(data, label):
    s = Stream(data)
    used = s.r.p
    print("stream        : %s" % label)
    print("bytes         : %d read of %d   residue %d"
          % (used, len(data), len(data) - used))
    print("records       : %d   ends on MessageEnd : %s"
          % (s.records, s.ended))
    for lid, lname in sorted(s.libraries.items()):
        print("library %-5d : %s" % (lid, lname))
    lists = [o for o in s.objects.values()
             if isinstance(o, dict) and o.get("__class__", "").startswith(
                 "System.Collections.Generic.List")]
    if lists:
        lo = lists[0]
        print("class          : %s" % lo["__class__"].split("[[")[0])
        print("  _size          : %d" % lo["_size"])
        arr = s.objects.get(lo["_items"][1]) if isinstance(
            lo["_items"], tuple) else None
        if arr is not None:
            live = [x for x in arr if x is not None]
            print("  array capacity : %d   non-null elements : %d"
                  % (len(arr), len(live)))
            gs = []
            for x in live:
                if isinstance(x, tuple) and x[0] == "obj":
                    o = s.objects.get(x[1], {})
                    if o.get("__class__") == "System.Guid":
                        gs.append(_guid_from_members(
                            [o["_a"], o["_b"], o["_c"]] +
                            [o["_" + c] for c in "defghijk"]))
            print("  System.Guid    : %d   distinct : %d"
                  % (len(gs), len(set(gs))))
            if gs:
                print("  first          : %s" % gs[0])
        if len(data) - used:
            print("FAILURE: residue is not zero")
            return 1
        return 0
    pi = s.publish_info()
    print("PublishInfo")
    print("  _objectsCount  : %d" % pi["_objectsCount"])
    print("  _resourceCount : %d" % pi["_resourceCount"])
    db = s.db_info()
    if db:
        print("DBInfo")
        print("  _name          : %r" % db["_name"])
        print("  _author        : %r" % db["_author"])
        print("  _maxId         : %d" % db["_maxId"])
        for f in ("_creationDate", "_modificationDate"):
            v = db[f]
            if isinstance(v, tuple):
                print("  %-14s : %s  (DateTimeKind %d)"
                      % (f, v[0].isoformat(sep=" "), v[1]))
        g = s.guid()
        if g:
            print("  _guid          : %s" % g)
        mi = db["_modInfo"]
        if isinstance(mi, tuple) and mi and mi[0] in ("obj", "ref"):
            mo = s.objects.get(mi[1], {})
            print("  _modInfo       : %s" % mo.get("__class__"))
            for k in sorted(mo):
                if k == "__class__":
                    continue
                v = mo[k]
                if isinstance(v, tuple) and len(v) == 2 and hasattr(
                        v[0], "isoformat"):
                    v = "%s (Kind %d)" % (v[0].isoformat(sep=" "), v[1])
                print("      %-16s : %s" % (k, v))
        else:
            print("  _modInfo       : %s" % (mi,))
    ver = [o for o in s.objects.values()
           if isinstance(o, dict) and o.get("__class__") == "System.Version"]
    if ver:
        v = ver[0]
        print("version        : %d.%d.%d.%d"
              % (v["_Major"], v["_Minor"], v["_Build"], v["_Revision"]))
    if len(data) - used:
        print("FAILURE: residue is not zero")
        return 1
    return 0


def selftest():
    """Specimens built in memory. Most of them must be refused."""
    ok = 0
    fail = []

    def must_fail(name, blob):
        try:
            Stream(blob)
        except NrbfError:
            return True
        fail.append(name)
        return False

    # 1..6: things that are not this format, or are truncated, or lie.
    cases = [
        ("empty", b""),
        ("wrong first record", b"\x0c" + b"\x00" * 32),
        ("truncated header", b"\x00\x01\x00\x00\x00"),
        ("major version 2", b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"
                            b"\x02\x00\x00\x00\x00\x00\x00\x00"),
        ("unimplemented record", b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"
                                 b"\x01\x00\x00\x00\x00\x00\x00\x00\x07"),
        ("absurd member count", b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"
                                b"\x01\x00\x00\x00\x00\x00\x00\x00"
                                b"\x05\x01\x00\x00\x00\x01A"
                                b"\xff\xff\x00\x00"),
    ]
    for name, blob in cases:
        if must_fail(name, blob):
            ok += 1

    # 7: one specimen that MUST parse -- a header, a string, a message end.
    good = (b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x06\x01\x00\x00\x00\x03" + b"1.0" + b"\x0b")
    try:
        s = Stream(good)
        assert s.ended and s.r.p == len(good), "residue on the good specimen"
        assert s.objects[1] == "1.0"
        ok += 1
    except Exception as e:                                    # noqa: BLE001
        fail.append("good specimen: %s" % e)

    # 8: a 7-bit length prefix over 127 bytes, which the naive reader gets
    #    wrong and which this object's own streams do not exercise.
    long_s = "x" * 300
    blob = (b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
            b"\x06\x01\x00\x00\x00\xac\x02" + long_s.encode() + b"\x0b")
    try:
        s = Stream(blob)
        assert s.objects[1] == long_s and s.r.p == len(blob)
        ok += 1
    except Exception as e:                                    # noqa: BLE001
        fail.append("300-byte string: %s" % e)

    print("selftest: %d of 8 specimens behaved as required "
          "(6 of the 8 must be refused)" % ok)
    for f in fail:
        print("  FAILED: %s" % f)
    return 0 if not fail else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--zip", dest="zippath")
    ap.add_argument("--member", default="info.bin")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.zippath:
        with zipfile.ZipFile(a.zippath) as z:
            data = z.read(a.member)
        return report(data, "%s :: %s" % (os.path.basename(a.zippath),
                                          a.member))
    if not a.path:
        ap.error("give a path, or --zip, or --selftest")
    with open(a.path, "rb") as f:
        data = f.read()
    return report(data, a.path)


if __name__ == "__main__":
    sys.exit(main())
