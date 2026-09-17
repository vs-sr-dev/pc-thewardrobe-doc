#!/usr/bin/env python3
"""rawcensus.py -- a full census of every physical sector of a 2352-byte image.

`rawsect.py` already audits raw sectors and its arithmetic is correct; what it
cannot do is finish. Its EDC check is a per-byte Python loop over 2,056 bytes of
every sector, and on 349,462 sectors that is 718 million iterations of
interpreted code. On this object the difference between "sampled 4,017 sectors"
and "censused 349,462" is the whole point of having a raw image at all, so the
census has to be affordable.

This tool computes the same CD EDC -- reflected CRC-32 with the generator
(x^16+x^15+x^2+1)(x^16+x^2+x+1), reflected constant 0xD8018001, init 0, no final
xor -- column-wise with numpy: instead of walking 2,056 bytes of one sector, it
walks byte position k across a whole block of sectors at once, 2,056 times. The
answer is bit-identical; only the loop order changes.

Everything else it reports is a straight count over the same pass:

  sync          bytes 0..11 == 00 FF*10 00
  header MSF    bytes 12..14, BCD, must equal LBA + 150
  mode          byte 15
  subheader     bytes 16..23, two 4-byte copies that must agree
  form          bit 0x20 of the submode byte
  user area     Mode 2 Form 1: bytes 24..2071
  EDC           Mode 2 Form 1: bytes 2072..2075, over bytes 16..2071
  ECC           bytes 2076..2351

Validate before census, always:

    python tools/rawcensus.py IMG --validate            # against rawsect.py
    python tools/rawcensus.py IMG --census
    python tools/rawcensus.py IMG --census --json OUT.json
    python tools/rawcensus.py IMG --submode 0x00        # list LBAs by submode

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


def edc_table():
    tbl = np.zeros(256, dtype=np.uint32)
    for i in range(256):
        v = i
        for _ in range(8):
            v = (v >> 1) ^ (EDC_POLY if v & 1 else 0)
        tbl[i] = v
    return tbl


TBL = edc_table()


def edc_scalar(data):
    """Reference implementation, one sector, per byte. Used only to validate."""
    crc = 0
    for b in data:
        crc = int(TBL[(crc ^ b) & 0xFF]) ^ (crc >> 8)
    return crc


def edc_block(arr):
    """arr: (n, k) uint8. Returns (n,) uint32 of the CD EDC over each row."""
    n, k = arr.shape
    crc = np.zeros(n, dtype=np.uint32)
    for col in range(k):
        idx = (crc & 0xFF).astype(np.uint8) ^ arr[:, col]
        crc = TBL[idx] ^ (crc >> np.uint32(8))
    return crc


def bcd_decode(a):
    """a: uint8 array. Returns (value, valid) with value = tens*10 + units."""
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


def blocks(path, total, block=8192):
    with open(path, "rb") as fh:
        lba = 0
        while lba < total:
            k = min(block, total - lba)
            buf = fh.read(k * SECTOR)
            if len(buf) != k * SECTOR:
                raise SystemExit("short read at LBA %d" % lba)
            yield lba, np.frombuffer(buf, dtype=np.uint8).reshape(k, SECTOR)
            lba += k


def cmd_validate(path, n=64, start=0):
    """Prove edc_block == edc_scalar on real sectors before trusting the census."""
    size, total = sector_count(path)
    with open(path, "rb") as fh:
        fh.seek(start * SECTOR)
        buf = fh.read(n * SECTOR)
    arr = np.frombuffer(buf, dtype=np.uint8).reshape(-1, SECTOR)
    vec = edc_block(arr[:, 16:2072])
    ok = 0
    stored_ok = 0
    for i in range(arr.shape[0]):
        ref = edc_scalar(bytes(arr[i, 16:2072]))
        if ref != int(vec[i]):
            raise SystemExit("MISMATCH at LBA %d: vector %08X scalar %08X"
                             % (start + i, int(vec[i]), ref))
        ok += 1
        stored = int.from_bytes(bytes(arr[i, 2072:2076]), "little")
        if stored == ref:
            stored_ok += 1
    print("validate: %d sectors from LBA %d" % (ok, start))
    print("  vectorised EDC == scalar reference   %d/%d" % (ok, ok))
    print("  computed EDC == stored EDC           %d/%d" % (stored_ok, ok))
    if stored_ok != ok:
        raise SystemExit("stored EDC does not match on a known-good run; "
                         "the polynomial or the byte range is wrong")


def cmd_census(path, jsonout=None, block=8192):
    size, total = sector_count(path)
    sync_np = np.frombuffer(SYNC, dtype=np.uint8)

    bad_sync = []
    modes = {}
    forms = {}
    subheaders = {}
    subhdr_mismatch = []
    hdr_bad_bcd = []
    hdr_wrong = []
    edc_bad = []
    edc_checked = 0
    ecc_zero = []
    user_zero = 0
    user_zero_runs = []
    submode_lba = {}

    for lba, arr in blocks(path, total, block):
        k = arr.shape[0]
        idx = np.arange(lba, lba + k, dtype=np.int64)

        good = np.all(arr[:, 0:12] == sync_np, axis=1)
        for j in np.nonzero(~good)[0]:
            if len(bad_sync) < 2000:
                bad_sync.append(int(lba + j))

        mm, mmok = bcd_decode(arr[:, 12])
        ss, ssok = bcd_decode(arr[:, 13])
        ff, ffok = bcd_decode(arr[:, 14])
        okbcd = mmok & ssok & ffok
        for j in np.nonzero(~okbcd)[0]:
            if len(hdr_bad_bcd) < 2000:
                hdr_bad_bcd.append(int(lba + j))
        v = idx + 150
        want = np.stack([v // 4500, (v // 75) % 60, v % 75], axis=1)
        got = np.stack([mm, ss, ff], axis=1).astype(np.int64)
        wrong = okbcd & np.any(got != want, axis=1)
        for j in np.nonzero(wrong)[0]:
            if len(hdr_wrong) < 2000:
                hdr_wrong.append((int(lba + j),
                                  tuple(int(x) for x in got[j]),
                                  tuple(int(x) for x in want[j])))

        for m, c in zip(*np.unique(arr[:, 15], return_counts=True)):
            modes[int(m)] = modes.get(int(m), 0) + int(c)

        m2 = arr[:, 15] == 2
        if m2.any():
            sh = arr[m2, 16:20]
            sh2 = arr[m2, 20:24]
            mism = np.any(sh != sh2, axis=1)
            m2idx = idx[m2]
            for j in np.nonzero(mism)[0]:
                if len(subhdr_mismatch) < 2000:
                    subhdr_mismatch.append(int(m2idx[j]))
            keys, inv, counts = np.unique(sh, axis=0, return_inverse=True,
                                          return_counts=True)
            for r, c in zip(keys, counts):
                key = tuple(int(x) for x in r)
                subheaders[key] = subheaders.get(key, 0) + int(c)
            for ki, r in enumerate(keys):
                sm = int(r[2])
                lst = submode_lba.setdefault(sm, [])
                if len(lst) < 4000:
                    lst.extend(int(x) for x in m2idx[inv == ki][:4000 - len(lst)])

            form2 = (sh[:, 2] & 0x20) != 0
            forms[1] = forms.get(1, 0) + int((~form2).sum())
            forms[2] = forms.get(2, 0) + int(form2.sum())

            f1 = np.zeros(k, dtype=bool)
            f1[np.nonzero(m2)[0][~form2]] = True
            if f1.any():
                sub = arr[f1]
                subidx = idx[f1]
                crc = edc_block(sub[:, 16:2072])
                stored = (sub[:, 2072].astype(np.uint32)
                          | (sub[:, 2073].astype(np.uint32) << np.uint32(8))
                          | (sub[:, 2074].astype(np.uint32) << np.uint32(16))
                          | (sub[:, 2075].astype(np.uint32) << np.uint32(24)))
                bad = crc != stored
                for j in np.nonzero(bad)[0]:
                    if len(edc_bad) < 2000:
                        edc_bad.append(int(subidx[j]))
                edc_checked += int(f1.sum())

                zecc = np.all(sub[:, 2076:2352] == 0, axis=1)
                for j in np.nonzero(zecc)[0]:
                    if len(ecc_zero) < 2000:
                        ecc_zero.append(int(subidx[j]))

                zuser = np.all(sub[:, 24:2072] == 0, axis=1)
                user_zero += int(zuser.sum())
                for j in np.nonzero(zuser)[0]:
                    a = int(subidx[j])
                    if user_zero_runs and user_zero_runs[-1][1] == a - 1:
                        user_zero_runs[-1][1] = a
                    else:
                        user_zero_runs.append([a, a])

    out = {
        "image": os.path.basename(path),
        "bytes": size,
        "sectors": total,
        "bad_sync": len(bad_sync),
        "modes": {str(m): c for m, c in sorted(modes.items())},
        "forms": {str(f): c for f, c in sorted(forms.items())},
        "subheaders": {"%02X %02X %02X %02X" % k_: v
                       for k_, v in sorted(subheaders.items(),
                                           key=lambda kv: -kv[1])},
        "subheader_copies_disagree": len(subhdr_mismatch),
        "header_bad_bcd": len(hdr_bad_bcd),
        "header_not_lba_plus_150": len(hdr_wrong),
        "edc_checked": edc_checked,
        "edc_mismatches": len(edc_bad),
        "ecc_all_zero": len(ecc_zero),
        "user_area_all_zero": user_zero,
        "user_zero_runs": [[a, b, b - a + 1] for a, b in user_zero_runs
                           if b - a + 1 >= 1][-40:],
        "submode_lbas_sample": {("0x%02X" % sm): v[:8]
                                for sm, v in sorted(submode_lba.items())},
    }

    print("=" * 72)
    print("RAW SECTOR CENSUS  %s" % os.path.basename(path))
    print("=" * 72)
    print("sectors                              %d" % total)
    print("bytes                                %d" % size)
    print("frame overhead (2352-2048) x sectors %d  (%.4f %%)"
          % (total * 304, 100.0 * total * 304 / size))
    print()
    print("-- sync ------------------------------------------------------------")
    print("  correct 00 FF*10 00                %d / %d" % (total - len(bad_sync), total))
    if bad_sync:
        print("  bad                                %d  first %s"
              % (len(bad_sync), bad_sync[:8]))
    print()
    print("-- mode byte -------------------------------------------------------")
    for m in sorted(modes):
        print("  mode %-2d                            %10d  (%.4f %%)"
              % (m, modes[m], 100.0 * modes[m] / total))
    print()
    print("-- form ------------------------------------------------------------")
    for f in sorted(forms):
        print("  Mode 2 Form %d                      %10d  (%.4f %%)"
              % (f, forms[f], 100.0 * forms[f] / total))
    print()
    print("-- subheader (file, channel, submode, coding) ----------------------")
    for key, n in sorted(subheaders.items(), key=lambda kv: -kv[1]):
        sm = key[2]
        bits = []
        for bit, name in ((0x80, "EOF"), (0x40, "RT"), (0x20, "form2"),
                          (0x10, "trigger"), (0x08, "data"), (0x04, "audio"),
                          (0x02, "video"), (0x01, "EOR")):
            if sm & bit:
                bits.append(name)
        print("  %02X %02X %02X %02X  %10d  (%.4f %%)  %s"
              % (key[0], key[1], key[2], key[3], n, 100.0 * n / total,
                 "|".join(bits) if bits else "-"))
    print("  copies disagree                    %d" % len(subhdr_mismatch))
    print()
    print("-- header MSF ------------------------------------------------------")
    print("  non-BCD                            %d" % len(hdr_bad_bcd))
    print("  header != LBA+150                  %d" % len(hdr_wrong))
    for row in hdr_wrong[:8]:
        print("    LBA %d: %02d:%02d:%02d, expected %02d:%02d:%02d"
              % (row[0], row[1][0], row[1][1], row[1][2],
                 row[2][0], row[2][1], row[2][2]))
    print()
    print("-- EDC / ECC -------------------------------------------------------")
    print("  Form 1 sectors EDC-checked         %d" % edc_checked)
    print("  EDC mismatches                     %d" % len(edc_bad))
    if edc_bad:
        print("    first %s" % edc_bad[:8])
    print("  all-zero ECC field                 %d" % len(ecc_zero))
    print()
    print("-- user area -------------------------------------------------------")
    print("  Form 1 sectors with 2048 zero bytes %d  (%.4f %%)"
          % (user_zero, 100.0 * user_zero / total))
    print("  last runs of consecutive zero-user sectors:")
    for a, b in user_zero_runs[-12:]:
        print("    LBA %d .. %d   (%d sectors)" % (a, b, b - a + 1))
    print()

    if jsonout:
        with open(jsonout, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1)
        print("wrote %s" % jsonout)
    return out


def cmd_submode(path, target, block=8192):
    size, total = sector_count(path)
    hits = []
    for lba, arr in blocks(path, total, block):
        m2 = arr[:, 15] == 2
        if not m2.any():
            continue
        sm = arr[m2, 18]
        idx = np.arange(lba, lba + arr.shape[0])[m2]
        for j in np.nonzero(sm == target)[0]:
            hits.append(int(idx[j]))
    print("submode 0x%02X: %d sectors" % (target, len(hits)))
    if not hits:
        return
    runs = []
    for a in hits:
        if runs and runs[-1][1] == a - 1:
            runs[-1][1] = a
        else:
            runs.append([a, a])
    print("  %d runs" % len(runs))
    for a, b in runs[:60]:
        print("    LBA %d .. %d   (%d)" % (a, b, b - a + 1))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--validate-start", type=int, default=0)
    ap.add_argument("--validate-n", type=int, default=64)
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--submode")
    ap.add_argument("--block", type=int, default=8192)
    a = ap.parse_args()

    if a.validate:
        cmd_validate(a.image, a.validate_n, a.validate_start)
    if a.census:
        cmd_census(a.image, a.json, a.block)
    if a.submode is not None:
        cmd_submode(a.image, int(a.submode, 0), a.block)
    if not (a.validate or a.census or a.submode is not None):
        ap.print_help()


if __name__ == "__main__":
    main()
