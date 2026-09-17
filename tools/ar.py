#!/usr/bin/env python3
"""ar.py -- a reader for the ARSENAL container pair, `<name>.mtc` + `<name>.mdf`.

Derived on `pc-streetsofkamurocho-doc` from one specimen: `AR_win32.mtc`,
4,096 bytes, and `AR_win32.mdf`, 29,700,096 bytes, from *Streets of Kamurocho*
(SEGA, 2020; engine by Empty Clip Studios, whose credits name the technology
`ARSENAL` -- which is where `AR` comes from). There is no published layout for
this format and there was no prior art in 461 tools or 124 repositories.

    THERE IS NO MAGIC NUMBER, SO `validate` REFUSES ON ARITHMETIC.

That is the interesting constraint and it is stated here rather than buried.
The first four bytes of the `.mdf` are `34 15 8c 65`, which are the first four
bytes of member 0's ciphertext and not a signature; the `.mtc` opens with the
integer 16 and not with a word. So a reader that refuses on a magic number
cannot exist for this format, and this one refuses on nine arithmetic facts,
every one of which a random 4,096-byte file fails:

    1. head[0] is the header size and must be 16; head[2] is the count and
       must be non-zero and must fit the file;
    2. the `count` pointers after the header must step by exactly 16;
    3. the first pointer must equal 16 + 4*count -- the record array begins
       exactly where the pointer array ends;
    4. the records' first field must step by exactly 32, and the first of them
       must equal 16 + 4*count + 16*count -- the block array begins exactly
       where the record array ends;
    5. the records' third field must be strictly ascending as SIGNED int32,
       which is what makes the table searchable and is not a property random
       data has;
    6. the extents must start at 0 and be contiguous with no gap and no
       overlap;
    7. the extents must sum to exactly the size of the `.mdf` -- residue 0,
       not "close";
    8. every member's stored length must equal its plaintext size rounded up
       to a multiple of 16, and must not exceed its extent;
    9. everything after the block array must be zero.

Any one of those failing is a refusal with the failing quantity printed.

MEMBER PAYLOADS ARE ENCRYPTED. Every member is AES-128-CBC with a sixteen-byte
zero initialisation vector and one key shared by the whole archive. The key is
an ASCII string of at most fifteen characters, zero-padded to sixteen -- the
game copies it with `strncpy` into a zeroed buffer -- and it is a per-title
literal, so this reader does NOT carry one. Pass it with `--key`. Without a
key, `census` still works: the directory is in the clear.

    python tools/ar.py validate  path/to/NAME.mtc
    python tools/ar.py census    path/to/NAME.mtc
    python tools/ar.py extract   path/to/NAME.mtc OUTDIR --key STRING
    python tools/ar.py selftest
"""
import argparse
import io
import os
import struct
import sys

HEAD = 16
REC = 16
BLK = 32


class ArError(Exception):
    pass


def align16(n):
    return (n + 15) // 16 * 16


class Ar(object):
    """The .mtc directory. Nothing here reads the .mdf except `extents`."""

    def __init__(self, idx, payload_size):
        self.idx = idx
        self.payload_size = payload_size
        self.count = 0
        self.records = []
        self.blocks = []

    # -- the refusals -------------------------------------------------
    def validate(self, verbose=True):
        idx = self.idx
        say = (lambda s: sys.stdout.write(s + "\n")) if verbose else (lambda s: None)

        if len(idx) < HEAD:
            raise ArError("index is %d bytes, shorter than the %d-byte header"
                          % (len(idx), HEAD))
        h0, h1, count, h3 = struct.unpack_from("<4I", idx, 0)
        if h0 != HEAD:
            raise ArError("REFUSED: header field 0 is %d, not the header size %d"
                          % (h0, HEAD))
        if count == 0:
            raise ArError("REFUSED: the count is 0; an archive of nothing is "
                          "not an archive")
        need = HEAD + 4 * count + REC * count + BLK * count
        if need > len(idx):
            raise ArError("REFUSED: a count of %d needs %d bytes of index and "
                          "the file is %d" % (count, need, len(idx)))
        say("head            : %r, count %d" % ((h0, h1, count, h3), count))
        self.count = count

        ptr = list(struct.unpack_from("<%dI" % count, idx, HEAD))
        steps = {b - a for a, b in zip(ptr, ptr[1:])} if count > 1 else {REC}
        if steps != {REC}:
            raise ArError("REFUSED: the pointer array steps by %s, not by %d"
                          % (sorted(steps), REC))
        want = HEAD + 4 * count
        if ptr[0] != want:
            raise ArError("REFUSED: first pointer is %d, and the pointer array "
                          "ends at %d" % (ptr[0], want))
        say("pointers        : %d, %d..%d, step %d" % (count, ptr[0], ptr[-1], REC))

        rec = [struct.unpack_from("<4I", idx, p) for p in ptr]
        boff = [r[0] for r in rec]
        bsteps = {b - a for a, b in zip(boff, boff[1:])} if count > 1 else {BLK}
        if bsteps != {BLK}:
            raise ArError("REFUSED: the record array's block pointers step by "
                          "%s, not by %d" % (sorted(bsteps), BLK))
        want = HEAD + 4 * count + REC * count
        if boff[0] != want:
            raise ArError("REFUSED: first block pointer is %d, and the record "
                          "array ends at %d" % (boff[0], want))
        say("records         : %d, blocks at %d..%d, step %d"
            % (count, boff[0], boff[-1], BLK))

        keys = [r[2] - 2 ** 32 if r[2] >= 2 ** 31 else r[2] for r in rec]
        bad = [i for i in range(count - 1) if not keys[i] < keys[i + 1]]
        if bad:
            raise ArError("REFUSED: the key column is not strictly ascending as "
                          "signed int32; it falls at row %d" % bad[0])
        say("keys            : %d, strictly ascending as int32" % count)

        blk = [struct.unpack_from("<8I", idx, o) for o in boff]
        self.records, self.blocks = rec, blk

        pos = 0
        total = 0
        for i, b in enumerate(blk):
            off, alloc, size, stored = b[2], b[3], b[4], b[6]
            if off != pos:
                raise ArError("REFUSED: member %d starts at %d and the previous "
                              "one ends at %d" % (i, off, pos))
            if stored != align16(size):
                raise ArError("REFUSED: member %d stores %d bytes for a size of "
                              "%d; align16 of that is %d"
                              % (i, stored, size, align16(size)))
            if stored > alloc:
                raise ArError("REFUSED: member %d stores %d bytes in an extent "
                              "of %d" % (i, stored, alloc))
            pos += alloc
            total += alloc
        if self.payload_size is not None and total != self.payload_size:
            raise ArError("REFUSED: the %d extents sum to %d and the payload is "
                          "%d; the residue is %d"
                          % (count, total, self.payload_size,
                             self.payload_size - total))
        say("extents         : %d, contiguous from 0, sum %d" % (count, total))

        end = HEAD + 4 * count + REC * count + BLK * count
        tail = idx[end:]
        if set(tail) - {0}:
            raise ArError("REFUSED: %d bytes after the block array at %d are not "
                          "all zero" % (len(tail), end))
        say("tail            : %d bytes from %d, all zero" % (len(tail), end))
        say("VALID")
        return True

    def census(self):
        rows = []
        for i, b in enumerate(self.blocks):
            rows.append((i, b[2], b[3], b[4], b[6], self.records[i][2]))
        return rows


def open_pair(mtc, need_payload=True):
    """Open the index, and the payload beside it when there is one.

    REPAIRED on pc-themurderofsonicthehedgehog-doc, and the defect was mine.

    This function used to raise `no payload beside the index` before reading a
    single byte of the file it had been handed. Given a UnityFS asset bundle it
    exited 3 with a message about a `.mdf` that was never going to exist --
    which is a refusal on a FILE NAME, in a reader whose entire argument is
    that it refuses on ARITHMETIC because the format has no magic number.

    `inno56.py` searches all 653,824 bytes and reports that its identifier is
    not there. `drpk.py` refuses on magic and prints the four bytes it found.
    Both say something about the bytes. This said something about the
    directory listing.

    Eight of the nine checks in `validate` need only the index, and the class
    has always handled `payload_size = None` for the ninth. So the payload is
    now OPTIONAL for `validate` and required for `census` and `extract`, which
    genuinely cannot run without it. Handed a bundle, `validate` now says:

        REFUSED: header field 0 is 1416785493, not the header size 16

    which is a statement about the first four bytes of the thing it was given.
    """
    mdf = os.path.splitext(mtc)[0] + ".mdf"
    if not os.path.exists(mdf):
        if need_payload:
            raise ArError("no payload beside the index: expected %s" % mdf)
        return Ar(open(mtc, "rb").read(), None), None
    return Ar(open(mtc, "rb").read(), os.path.getsize(mdf)), mdf


def cmd_validate(a):
    ar, mdf = open_pair(a.mtc, need_payload=False)
    if mdf is None:
        sys.stdout.write(
            "no .mdf beside this index, so check 7 (the extents sum to the\n"
            "payload size) cannot run. The other eight run on the index alone\n"
            "and they run now.\n")
    ar.validate()
    if mdf is None:
        sys.stdout.write("\nEIGHT of nine checks passed on the index alone; "
                         "check 7 was not run.\n")
    return 0


def cmd_census(a):
    ar, mdf = open_pair(a.mtc)
    ar.validate(verbose=False)
    print("index   : %s, %d bytes" % (a.mtc, len(ar.idx)))
    print("payload : %s, %d bytes" % (mdf, ar.payload_size))
    print("members : %d" % ar.count)
    print()
    print("%4s %11s %11s %11s %11s %11s  %s"
          % ("#", "offset", "extent", "size", "stored", "slack", "key"))
    tslack = 0
    tsize = 0
    for i, off, alloc, size, stored, key in ar.census():
        tslack += alloc - stored
        tsize += size
        print("%4d %11d %11d %11d %11d %11d  0x%08X"
              % (i, off, alloc, size, stored, alloc - stored, key))
    print()
    print("plaintext bytes : %d" % tsize)
    print("extent bytes    : %d" % ar.payload_size)
    print("slack           : %d = %.4f %% of the payload"
          % (tslack, 100.0 * tslack / ar.payload_size))
    return 0


def cmd_extract(a):
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise ArError("extract needs pycryptodome; census and validate do not")
    if not a.key:
        raise ArError("extract needs --key: the key is per-title and this "
                      "reader deliberately carries none")
    key = a.key.encode("ascii")[:15].ljust(16, b"\0")
    ar, mdf = open_pair(a.mtc)
    ar.validate(verbose=False)
    os.makedirs(a.outdir, exist_ok=True)
    payload = open(mdf, "rb").read()
    n = 0
    for i, off, alloc, size, stored, key32 in ar.census():
        ct = payload[off:off + stored]
        pt = AES.new(key, AES.MODE_CBC, b"\0" * 16).decrypt(ct)[:size]
        open(os.path.join(a.outdir, "m%02d.bin" % i), "wb").write(pt)
        n += len(pt)
    print("%d members, %d plaintext bytes written to %s" % (ar.count, n, a.outdir))
    return 0


# ---------------------------------------------------------------- selftest
def build(count=3, sizes=None, break_=None):
    """Build an index in memory. `break_` names the thing to spoil."""
    sizes = sizes or [24, 4096, 100]
    count = len(sizes)
    ptr_at = HEAD
    rec_at = HEAD + 4 * count
    blk_at = rec_at + REC * count
    end = blk_at + BLK * count
    page = max(4096, (end + 4095) // 4096 * 4096)
    buf = bytearray(page)

    head_size = HEAD if break_ != "head" else 24
    struct.pack_into("<4I", buf, 0, head_size,
                     0, 0 if break_ == "zero-count" else count, 0)

    step = REC if break_ != "ptr-step" else 20
    for i in range(count):
        struct.pack_into("<I", buf, ptr_at + 4 * i, rec_at + i * step)
    if break_ == "ptr-base":
        struct.pack_into("<I", buf, ptr_at, rec_at + 8)

    keys = [0x80000000 + i * 0x01000000 for i in range(count)]
    if break_ == "key-order" and count > 1:
        keys[0], keys[1] = keys[1], keys[0]
    for i in range(count):
        struct.pack_into("<4I", buf, rec_at + i * REC,
                         blk_at + i * BLK, 0, keys[i] & 0xFFFFFFFF, 0)

    off = 0
    total = 0
    for i, s in enumerate(sizes):
        stored = align16(s)
        alloc = (stored + 4095) // 4096 * 4096
        o = off if break_ != "gap" or i == 0 else off + 4096
        st = stored if break_ != "stored" else stored + 1
        struct.pack_into("<8I", buf, blk_at + i * BLK,
                         0, 1, o, alloc, s, 0, st, 0)
        off = o + alloc
        total = off
    if break_ == "tail":
        buf[end] = 1
    if break_ == "residue":
        total += 4096
    return bytes(buf), total


def cmd_selftest(a):
    cases = [
        (None, True, "a well-formed three-member index"),
        ("head", False, "header field 0 is 24 instead of 16"),
        ("zero-count", False, "a count of zero"),
        ("ptr-step", False, "the pointer array steps by 20"),
        ("ptr-base", False, "the record array does not start where the "
                            "pointers end"),
        ("key-order", False, "the key column is not ascending"),
        ("gap", False, "a 4,096-byte gap between two members"),
        ("stored", False, "a stored length that is not align16 of the size"),
        ("tail", False, "one non-zero byte after the block array"),
        ("residue", False, "the extents do not sum to the payload size"),
        ("random", False, "4,096 random-looking bytes with no structure"),
    ]
    ok = 0
    print("specimens are built in memory; %d of %d must be REJECTED"
          % (sum(1 for _, e, _ in cases if not e), len(cases)))
    print()
    for name, expect_ok, what in cases:
        if name == "random":
            idx = bytes((i * 37 + 11) & 0xFF for i in range(4096))
            total = 4096
        else:
            idx, total = build(break_=name)
        ar = Ar(idx, total)
        try:
            ar.validate(verbose=False)
            got = True
            why = ""
        except ArError as e:
            got = False
            why = str(e).split(";")[0]
        mark = "ok  " if got == expect_ok else "FAIL"
        if got == expect_ok:
            ok += 1
        print("  %s  %-9s %-56s %s"
              % (mark, "accept" if expect_ok else "reject", what, why[:70]))
    print()
    print("%d of %d cases behaved as required" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("validate")
    p.add_argument("mtc")
    p.set_defaults(fn=cmd_validate)
    p = sub.add_parser("census")
    p.add_argument("mtc")
    p.set_defaults(fn=cmd_census)
    p = sub.add_parser("extract")
    p.add_argument("mtc")
    p.add_argument("outdir")
    p.add_argument("--key", default=None,
                   help="the archive key, an ASCII string of at most 15 "
                        "characters; per-title, so there is no default")
    p.set_defaults(fn=cmd_extract)
    p = sub.add_parser("selftest")
    p.set_defaults(fn=cmd_selftest)
    a = ap.parse_args()
    if not getattr(a, "fn", None):
        ap.print_help()
        return 2
    try:
        return a.fn(a)
    except ArError as e:
        sys.stderr.write("%s\n" % e)
        return 3


if __name__ == "__main__":
    sys.exit(main())
