#!/usr/bin/env python3
"""mode1.py -- a full census of every physical sector of a Mode 1 2352-byte image.

`rawcensus.py` in this toolbox censuses raw images and its arithmetic is right,
but it was written for a Mode 2 Form 1 disc and it cannot read this one. The
difference is not cosmetic and it is worth stating exactly, because the two
layouts spend the same 304 bytes on different things:

    Mode 2 Form 1            Mode 1
    ----------------------   ----------------------
     0..11   sync             0..11   sync
    12..14   header MSF      12..14   header MSF
       15    mode = 2           15    mode = 1
    16..23   subheader       16..2063 user data (2048)
    24..2071 user data       2064..2067 EDC
    2072..75 EDC             2068..2075 reserved, eight bytes
    2076..2351 ECC           2076..2351 ECC

  * the EDC of Mode 2 Form 1 covers bytes 16..2071 -- subheader and payload,
    2,056 bytes, and *not* the sync or the header;
  * the EDC of Mode 1 covers bytes 0..2063 -- sync, header and payload,
    **2,064 bytes**, starting at zero.

The two parity codes are not parallel and this is easy to get wrong: P is
computed over the 2,064 bytes at 12..2075, and Q is computed over the 2,236
bytes at 12..2247, i.e. over the same data *plus the P parity*. Q protects P.

Same generator polynomial in both: the reflected CRC-32 with generator
(x^16+x^15+x^2+1)(x^16+x^2+x+1), reflected constant 0xD8018001, init 0, no
final xor. A verifier written for one mode reports zero verifications on the
other, which is what `rawcensus.py` does here. That is the whole adaptation.

The ECC is the same in both modes and this tool checks it rather than counting
it. ECMA-130 defines two interleaved Reed-Solomon (26,24) and (45,43) codes
over GF(2^8) with the primitive polynomial x^8+x^4+x^3+x^2+1 (0x11D), computed
over the 2,064 bytes at offsets 12..2075 -- header, payload, EDC and the eight
reserved bytes. P parity is 172 bytes at 2076..2247, Q parity is 104 bytes at
2248..2351. In Mode 2 Form 1 the header is zeroed for the computation; in
Mode 1 it is not, and this tool does the Mode 1 thing.

Everything is vectorised across sectors with numpy -- byte position k is walked
across a block of sectors at once instead of walking a sector across its bytes.
The answer is bit-identical to the scalar reference, which is what --validate
proves before any census is trusted.

    python tools/mode1.py IMG --validate            # scalar vs vector, both codes
    python tools/mode1.py IMG --census
    python tools/mode1.py IMG --census --json OUT.json
    python tools/mode1.py IMG --census --no-ecc     # EDC only, faster
    python tools/mode1.py IMG --cook OUT.iso        # write the 2048-byte payloads
    python tools/mode1.py IMG --range A B           # dump one sector's fields

No constant in this file belongs to any particular disc.
"""

import argparse
import json
import os
import sys

import numpy as np

SECTOR = 2352
SYNC = b"\x00" + b"\xff" * 10 + b"\x00"
EDC_POLY = 0xD8018001

# Mode 1 field boundaries.
USER_OFF = 16
USER_END = 2064           # 2048 bytes of payload
EDC_OFF = 2064
EDC_END = 2068
RESERVED_OFF = 2068
RESERVED_END = 2076       # eight bytes that must be zero
ECC_OFF = 2076
ECC_P_OFF = 2076
ECC_P_LEN = 172
ECC_Q_OFF = 2248
ECC_Q_LEN = 104
ECC_SRC_OFF = 12
# P parity is computed over 86 x 24 = 2,064 bytes: offsets 12..2075, i.e.
# header, payload, EDC and the eight reserved bytes.
ECC_SRC_P_LEN = 2064
# Q parity is computed over 52 x 43 = 2,236 bytes: offsets 12..2247, i.e. the
# same 2,064 bytes *plus the 172 bytes of P parity that were just computed*.
# The two codes are not parallel; Q protects P. Getting this wrong reads off
# the end of the P source, which is how it was caught.
ECC_SRC_Q_LEN = 2236
ECC_SRC_LEN = ECC_SRC_P_LEN


def edc_table():
    tbl = np.zeros(256, dtype=np.uint32)
    for i in range(256):
        v = i
        for _ in range(8):
            v = (v >> 1) ^ (EDC_POLY if v & 1 else 0)
        tbl[i] = v
    return tbl


TBL = edc_table()


def gf_tables():
    """GF(2^8) with primitive polynomial 0x11D, as ECMA-130 Annex A defines it."""
    f = np.zeros(256, dtype=np.uint8)
    b = np.zeros(256, dtype=np.uint8)
    for i in range(256):
        j = ((i << 1) ^ (0x11D if (i & 0x80) else 0)) & 0xFF
        f[i] = j
        b[i ^ j] = i
    return f, b


F_LUT, B_LUT = gf_tables()


def ecc_indices(major_count, minor_count, major_mult, minor_inc):
    """The gather pattern of one ECMA-130 parity block, precomputed once.

    Returns (major_count, minor_count) int32 of offsets into the 2,064-byte
    ECC source.  This is the index arithmetic of the reference implementation
    hoisted out of the inner loop; nothing about it is disc-specific.
    """
    size = major_count * minor_count
    out = np.zeros((major_count, minor_count), dtype=np.int32)
    for major in range(major_count):
        index = (major >> 1) * major_mult + (major & 1)
        for minor in range(minor_count):
            out[major, minor] = index
            index += minor_inc
            if index >= size:
                index -= size
    return out


IDX_P = ecc_indices(86, 24, 2, 86)
IDX_Q = ecc_indices(52, 43, 86, 88)
assert IDX_P.max() < ECC_SRC_P_LEN, "P gather runs off its 2064-byte source"
assert IDX_Q.max() < ECC_SRC_Q_LEN, "Q gather runs off its 2236-byte source"
assert IDX_Q.max() >= ECC_SRC_P_LEN, "Q must reach into the P parity bytes"


def edc_block(arr):
    """arr: (n, k) uint8. Returns (n,) uint32 of the CD EDC over each row."""
    n, k = arr.shape
    crc = np.zeros(n, dtype=np.uint32)
    for col in range(k):
        idx = (crc & 0xFF).astype(np.uint8) ^ arr[:, col]
        crc = TBL[idx] ^ (crc >> np.uint32(8))
    return crc


def edc_scalar(data):
    """Reference implementation, one sector, per byte. Used only to validate."""
    crc = 0
    for b in data:
        crc = int(TBL[(crc ^ b) & 0xFF]) ^ (crc >> 8)
    return crc


def ecc_block(src, idx):
    """src: (n, 2064) uint8. idx: (major, minor) int32. Returns (n, 2*major)."""
    n = src.shape[0]
    major_count, minor_count = idx.shape
    out = np.zeros((n, 2 * major_count), dtype=np.uint8)
    for major in range(major_count):
        ecc_a = np.zeros(n, dtype=np.uint8)
        ecc_b = np.zeros(n, dtype=np.uint8)
        row = idx[major]
        for minor in range(minor_count):
            temp = src[:, row[minor]]
            ecc_a ^= temp
            ecc_b ^= temp
            ecc_a = F_LUT[ecc_a]
        ecc_a = B_LUT[F_LUT[ecc_a] ^ ecc_b]
        out[:, major] = ecc_a
        out[:, major + major_count] = ecc_a ^ ecc_b
    return out


def ecc_scalar(src, idx):
    """One sector, plain Python. The reference --validate checks the vector against."""
    major_count, minor_count = idx.shape
    out = bytearray(2 * major_count)
    for major in range(major_count):
        ecc_a = 0
        ecc_b = 0
        for minor in range(minor_count):
            temp = src[int(idx[major, minor])]
            ecc_a ^= temp
            ecc_b ^= temp
            ecc_a = int(F_LUT[ecc_a])
        ecc_a = int(B_LUT[int(F_LUT[ecc_a]) ^ ecc_b])
        out[major] = ecc_a
        out[major + major_count] = ecc_a ^ ecc_b
    return bytes(out)


def bcd_decode(a):
    hi = a >> 4
    lo = a & 0x0F
    return hi * 10 + lo, (hi < 10) & (lo < 10)


def sector_count(path):
    size = os.path.getsize(path)
    n, rem = divmod(size, SECTOR)
    if rem:
        raise SystemExit("%s is not a whole number of %d-byte sectors "
                         "(remainder %d)" % (path, SECTOR, rem))
    return size, n


def blocks(path, total, block=4096):
    with open(path, "rb") as fh:
        lba = 0
        while lba < total:
            k = min(block, total - lba)
            buf = fh.read(k * SECTOR)
            if len(buf) != k * SECTOR:
                raise SystemExit("short read at LBA %d" % lba)
            yield lba, np.frombuffer(buf, dtype=np.uint8).reshape(k, SECTOR)
            lba += k


def cmd_validate(path, n=32, start=16):
    """Prove the vector code equals the scalar reference on real sectors, and
    that the scalar reference agrees with what the disc already stores."""
    size, total = sector_count(path)
    if start + n > total:
        start = 0
    with open(path, "rb") as fh:
        fh.seek(start * SECTOR)
        buf = fh.read(n * SECTOR)
    arr = np.frombuffer(buf, dtype=np.uint8).reshape(-1, SECTOR)

    vec = edc_block(arr[:, 0:EDC_END - 4])
    psrc = np.ascontiguousarray(arr[:, ECC_SRC_OFF:ECC_SRC_OFF + ECC_SRC_P_LEN])
    qsrc = np.ascontiguousarray(arr[:, ECC_SRC_OFF:ECC_SRC_OFF + ECC_SRC_Q_LEN])
    pvec = ecc_block(psrc, IDX_P)
    qvec = ecc_block(qsrc, IDX_Q)

    edc_same = edc_store = p_store = q_store = 0
    for i in range(arr.shape[0]):
        ref = edc_scalar(bytes(arr[i, 0:EDC_END - 4]))
        if ref != int(vec[i]):
            raise SystemExit("EDC MISMATCH vector vs scalar at LBA %d: "
                             "%08X vs %08X" % (start + i, int(vec[i]), ref))
        edc_same += 1
        stored = int.from_bytes(bytes(arr[i, EDC_OFF:EDC_END]), "little")
        if stored == ref:
            edc_store += 1

        prow = ecc_scalar(bytes(psrc[i]), IDX_P)
        qrow = ecc_scalar(bytes(qsrc[i]), IDX_Q)
        if prow != bytes(pvec[i]) or qrow != bytes(qvec[i]):
            raise SystemExit("ECC MISMATCH vector vs scalar at LBA %d"
                             % (start + i))
        if prow == bytes(arr[i, ECC_P_OFF:ECC_P_OFF + ECC_P_LEN]):
            p_store += 1
        if qrow == bytes(arr[i, ECC_Q_OFF:ECC_Q_OFF + ECC_Q_LEN]):
            q_store += 1

    print("validate: %d Mode 1 sectors from LBA %d" % (arr.shape[0], start))
    print("  EDC   vectorised == scalar reference   %d/%d" % (edc_same, arr.shape[0]))
    print("  EDC   computed   == stored             %d/%d" % (edc_store, arr.shape[0]))
    print("  ECC P vectorised == scalar reference   %d/%d" % (arr.shape[0], arr.shape[0]))
    print("  ECC P computed   == stored             %d/%d" % (p_store, arr.shape[0]))
    print("  ECC Q computed   == stored             %d/%d" % (q_store, arr.shape[0]))
    if edc_store != arr.shape[0] or p_store != arr.shape[0] or q_store != arr.shape[0]:
        raise SystemExit("the stored codes do not match on a known-good run; "
                         "the polynomial, the byte range or the mode is wrong")
    print("  -> byte range 0..%d for EDC and %d..%d for ECC confirmed on this image"
          % (EDC_END - 5, ECC_SRC_OFF, ECC_SRC_OFF + ECC_SRC_LEN - 1))


def cmd_census(path, jsonout=None, block=4096, do_ecc=True, progress=False):
    size, total = sector_count(path)
    sync_np = np.frombuffer(SYNC, dtype=np.uint8)

    # BUG FIX, dc-dinocrisis-doc: the example lists below are capped at 4,000
    # entries, and the previous version printed len(list) as the count. On a
    # 504,150-sector track that turned every phenomenon larger than 4,000 into
    # a phenomenon of exactly 4,000, silently. The lists stay capped -- they
    # are examples -- and `n_` holds the true total.
    n = {"sync": 0, "bcd": 0, "hdr": 0, "edc": 0,
         "eccp": 0, "eccq": 0, "reserved": 0}
    bad_sync = []
    modes = {}
    hdr_bad_bcd = []
    hdr_wrong = []
    edc_bad = []
    edc_checked = 0
    ecc_checked = 0
    ecc_p_bad = []
    ecc_q_bad = []
    reserved_nonzero = []
    user_zero = 0
    zero_runs = []

    for lba, arr in blocks(path, total, block):
        k = arr.shape[0]
        idx = np.arange(lba, lba + k, dtype=np.int64)

        good = np.all(arr[:, 0:12] == sync_np, axis=1)
        for j in np.nonzero(~good)[0]:
            n["sync"] += 1
            if len(bad_sync) < 4000:
                bad_sync.append(int(lba + j))

        mm, mmok = bcd_decode(arr[:, 12])
        ss, ssok = bcd_decode(arr[:, 13])
        ff, ffok = bcd_decode(arr[:, 14])
        okbcd = mmok & ssok & ffok
        for j in np.nonzero(~okbcd)[0]:
            n["bcd"] += 1
            if len(hdr_bad_bcd) < 4000:
                hdr_bad_bcd.append(int(lba + j))
        v = idx + 150
        want = np.stack([v // 4500, (v // 75) % 60, v % 75], axis=1)
        got = np.stack([mm, ss, ff], axis=1).astype(np.int64)
        wrong = okbcd & np.any(got != want, axis=1)
        for j in np.nonzero(wrong)[0]:
            n["hdr"] += 1
            if len(hdr_wrong) < 4000:
                hdr_wrong.append((int(lba + j),
                                  tuple(int(x) for x in got[j]),
                                  tuple(int(x) for x in want[j])))

        for m, c in zip(*np.unique(arr[:, 15], return_counts=True)):
            modes[int(m)] = modes.get(int(m), 0) + int(c)

        crc = edc_block(arr[:, 0:EDC_END - 4])
        stored = (arr[:, EDC_OFF].astype(np.uint32)
                  | (arr[:, EDC_OFF + 1].astype(np.uint32) << np.uint32(8))
                  | (arr[:, EDC_OFF + 2].astype(np.uint32) << np.uint32(16))
                  | (arr[:, EDC_OFF + 3].astype(np.uint32) << np.uint32(24)))
        bad = crc != stored
        for j in np.nonzero(bad)[0]:
            n["edc"] += 1
            if len(edc_bad) < 4000:
                edc_bad.append(int(lba + j))
        edc_checked += k

        nz = np.any(arr[:, RESERVED_OFF:RESERVED_END] != 0, axis=1)
        for j in np.nonzero(nz)[0]:
            n["reserved"] += 1
            if len(reserved_nonzero) < 4000:
                reserved_nonzero.append(int(lba + j))

        if do_ecc:
            psrc = np.ascontiguousarray(
                arr[:, ECC_SRC_OFF:ECC_SRC_OFF + ECC_SRC_P_LEN])
            qsrc = np.ascontiguousarray(
                arr[:, ECC_SRC_OFF:ECC_SRC_OFF + ECC_SRC_Q_LEN])
            pv = ecc_block(psrc, IDX_P)
            qv = ecc_block(qsrc, IDX_Q)
            pb = np.any(pv != arr[:, ECC_P_OFF:ECC_P_OFF + ECC_P_LEN], axis=1)
            qb = np.any(qv != arr[:, ECC_Q_OFF:ECC_Q_OFF + ECC_Q_LEN], axis=1)
            for j in np.nonzero(pb)[0]:
                n["eccp"] += 1
                if len(ecc_p_bad) < 4000:
                    ecc_p_bad.append(int(lba + j))
            for j in np.nonzero(qb)[0]:
                n["eccq"] += 1
                if len(ecc_q_bad) < 4000:
                    ecc_q_bad.append(int(lba + j))
            ecc_checked += k

        zuser = np.all(arr[:, USER_OFF:USER_END] == 0, axis=1)
        user_zero += int(zuser.sum())
        for j in np.nonzero(zuser)[0]:
            a = int(lba + j)
            if zero_runs and zero_runs[-1][1] == a - 1:
                zero_runs[-1][1] = a
            else:
                zero_runs.append([a, a])

        if progress:
            sys.stderr.write("\r  %d / %d" % (lba + k, total))
            sys.stderr.flush()
    if progress:
        sys.stderr.write("\n")

    out = {
        "image": os.path.basename(path),
        "bytes": size,
        "sectors": total,
        "frame_bytes": total * 304,
        "frame_pct": 100.0 * total * 304 / size,
        "ecc_bytes": total * 276,
        "bad_sync": len(bad_sync),
        "modes": {str(m): c for m, c in sorted(modes.items())},
        "header_bad_bcd": len(hdr_bad_bcd),
        "header_not_lba_plus_150": len(hdr_wrong),
        "edc_checked": edc_checked,
        "edc_mismatches": len(edc_bad),
        "ecc_checked": ecc_checked,
        "ecc_p_mismatches": len(ecc_p_bad),
        "ecc_q_mismatches": len(ecc_q_bad),
        "reserved_nonzero": len(reserved_nonzero),
        "user_area_all_zero": user_zero,
        "zero_run_count": len(zero_runs),
        "zero_runs": [[a, b, b - a + 1] for a, b in zero_runs],
    }

    print("=" * 72)
    print("MODE 1 RAW SECTOR CENSUS  %s" % os.path.basename(path))
    print("=" * 72)
    print("sectors                              %d" % total)
    print("bytes                                %d" % size)
    print("frame overhead 304 x sectors         %d  (%.4f %%)"
          % (total * 304, 100.0 * total * 304 / size))
    print("  of which ECC 276 x sectors         %d  (%.4f %%)"
          % (total * 276, 100.0 * total * 276 / size))
    print()
    print("-- sync ------------------------------------------------------------")
    print("  correct 00 FF*10 00                %d / %d" % (total - n["sync"], total))
    print()
    print("-- mode byte -------------------------------------------------------")
    for m in sorted(modes):
        print("  mode %-3d                           %10d  (%.4f %%)"
              % (m, modes[m], 100.0 * modes[m] / total))
    print()
    print("-- header MSF ------------------------------------------------------")
    print("  non-BCD                            %d" % n["bcd"])
    print("  header != LBA+150                  %d" % n["hdr"])
    for row in hdr_wrong[:8]:
        print("    LBA %d: %02d:%02d:%02d, expected %02d:%02d:%02d"
              % (row[0], row[1][0], row[1][1], row[1][2],
                 row[2][0], row[2][1], row[2][2]))
    print()
    print("-- EDC (over bytes 0..2063) ----------------------------------------")
    print("  sectors checked                    %d / %d" % (edc_checked, total))
    print("  mismatches                         %d" % n["edc"])
    if edc_bad:
        print("    first %s" % edc_bad[:8])
    print()
    print("-- ECC (ECMA-130 P and Q over 12..2075) ----------------------------")
    if do_ecc:
        print("  sectors checked                    %d / %d" % (ecc_checked, total))
        print("  P parity mismatches                %d" % n["eccp"])
        print("  Q parity mismatches                %d" % n["eccq"])
    else:
        print("  skipped (--no-ecc)")
    print()
    print("-- reserved field 2068..2075 ---------------------------------------")
    print("  non-zero                           %d / %d" % (n["reserved"], total))
    print()
    print("-- user area -------------------------------------------------------")
    print("  sectors with 2048 zero bytes       %d  (%.4f %%)"
          % (user_zero, 100.0 * user_zero / total))
    print("  runs of consecutive zero-user sectors  %d" % len(zero_runs))
    for a, b in zero_runs[:10]:
        print("    LBA %d .. %d   (%d sectors)" % (a, b, b - a + 1))
    if len(zero_runs) > 20:
        print("    ...")
    for a, b in zero_runs[-10:]:
        print("    LBA %d .. %d   (%d sectors)" % (a, b, b - a + 1))
    print()

    if jsonout:
        with open(jsonout, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1)
        print("wrote %s" % jsonout)
    return out


def cmd_cook(path, dest, block=4096):
    size, total = sector_count(path)
    written = 0
    with open(dest, "wb") as out:
        for lba, arr in blocks(path, total, block):
            out.write(np.ascontiguousarray(arr[:, USER_OFF:USER_END]).tobytes())
            written += arr.shape[0]
    print("cooked %d sectors -> %s  (%d bytes)"
          % (written, dest, written * 2048))
    assert written == total, "cooked %d of %d sectors" % (written, total)


def cmd_range(path, a, b):
    size, total = sector_count(path)
    with open(path, "rb") as fh:
        for lba in range(a, min(b + 1, total)):
            fh.seek(lba * SECTOR)
            s = fh.read(SECTOR)
            crc = edc_scalar(s[0:EDC_END - 4])
            stored = int.from_bytes(s[EDC_OFF:EDC_END], "little")
            print("LBA %-8d  MSF %02X:%02X:%02X  mode %d  EDC %08X %s  "
                  "reserved %s  user[0:16] %s"
                  % (lba, s[12], s[13], s[14], s[15], stored,
                     "ok" if crc == stored else "BAD %08X" % crc,
                     "zero" if s[RESERVED_OFF:RESERVED_END] == b"\0" * 8 else "NONZERO",
                     s[16:32].hex()))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("image")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--no-ecc", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--cook", metavar="OUT")
    ap.add_argument("--range", nargs=2, type=int, metavar=("A", "B"))
    ap.add_argument("--start", type=int, default=16)
    ap.add_argument("--n", type=int, default=32)
    ap.add_argument("--progress", action="store_true")
    args = ap.parse_args()

    did = False
    if args.validate:
        cmd_validate(args.image, n=args.n, start=args.start)
        did = True
    if args.census:
        cmd_census(args.image, jsonout=args.json, do_ecc=not args.no_ecc,
                   progress=args.progress)
        did = True
    if args.cook:
        cmd_cook(args.image, args.cook)
        did = True
    if args.range:
        cmd_range(args.image, args.range[0], args.range[1])
        did = True
    if not did:
        ap.error("nothing to do: pass --validate, --census, --cook or --range")


if __name__ == "__main__":
    main()
