"""twoclocks.py -- is a PE link timestamp the same instant as an ISO 9660
directory record's recording date?

The claim under test is a coincidence, and a coincidence is only evidence if the
two sides are independent. A PE COFF timestamp is a 32-bit count of seconds
since 1970-01-01 00:00:00 UTC, written by the linker. An ISO 9660 directory
record date (ECMA-119 9.1.5) is seven bytes -- years since 1900, month, day,
hour, minute, second, and an offset from GMT in 15-minute intervals as a signed
byte -- written by the mastering software from the file's local mtime. Different
epochs, different widths, different producers, two years apart in the toolchain.

This tool converts both to a single UTC instant and prints the difference in
seconds. It does the arithmetic itself rather than calling a timezone library,
so that the 15-minute-interval field is visible in the output.

Usage:
    python tools/twoclocks.py --coff 942492842 --iso 63 0B 0D 0C 22 02 04
    python tools/twoclocks.py --selftest
"""

import calendar
import sys


def coff_to_utc(ts):
    return calendar.timegm(__import__("time").gmtime(ts)), ts


def iso_record_date(raw):
    if len(raw) != 7:
        raise ValueError("an ISO 9660 recording date is exactly 7 bytes, got %d" % len(raw))
    year = 1900 + raw[0]
    month, day, hour, minute, second = raw[1], raw[2], raw[3], raw[4], raw[5]
    tz = raw[6]
    if tz > 127:
        tz -= 256
    offset_minutes = tz * 15
    local = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    utc = local - offset_minutes * 60
    return {
        "year": year, "month": month, "day": day,
        "hour": hour, "minute": minute, "second": second,
        "tz_raw": raw[6], "tz_quarters": tz, "offset_minutes": offset_minutes,
        "local_epoch_as_if_utc": local, "utc": utc,
    }


def fmt(epoch):
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(epoch))


def compare(coff, raw):
    d = iso_record_date(raw)
    print("ISO 9660 directory record date")
    print("  raw bytes            : %s" % " ".join("%02X" % b for b in raw))
    print("  decoded local        : %04d-%02d-%02d %02d:%02d:%02d"
          % (d["year"], d["month"], d["day"], d["hour"], d["minute"], d["second"]))
    print("  tz byte              : 0x%02X = %d quarter-hours = %+d minutes"
          % (d["tz_raw"], d["tz_quarters"], d["offset_minutes"]))
    print("  as UTC               : %s  (epoch %d)" % (fmt(d["utc"]), d["utc"]))
    print()
    print("PE COFF file header timestamp")
    print("  raw value            : %d" % coff)
    print("  as UTC               : %s  (epoch %d)" % (fmt(coff), coff))
    print()
    delta = d["utc"] - coff
    print("difference           : %d seconds" % delta)
    print("same instant         : %s" % (delta == 0))
    return delta


def selftest():
    print("=== POSITIVE CONTROL: a date that must NOT match ===")
    # 1999-11-13 12:34:02 at GMT+01:00, but with the timezone byte set to 0 (UTC).
    raw = bytes([99, 11, 13, 12, 34, 2, 0])
    delta = compare(942492842, raw)
    if delta == 0:
        print("POSITIVE CONTROL FAILED: a GMT+00:00 record must be one hour off")
        return 1
    if delta != 3600:
        print("POSITIVE CONTROL ODD: expected +3600, got %d" % delta)
        return 1
    print("positive control fired: %+d seconds, as it must" % delta)
    print()
    print("=== NEGATIVE CONTROL: a malformed record must raise ===")
    try:
        iso_record_date(b"\x00" * 6)
    except ValueError as exc:
        print("raised as expected: %s" % exc)
        return 0
    print("POSITIVE CONTROL FAILED: a 6-byte date was accepted")
    return 1


def main(argv):
    if "--selftest" in argv:
        return selftest()
    if "--coff" not in argv or "--iso" not in argv:
        print(__doc__)
        return 2
    coff = int(argv[argv.index("--coff") + 1], 0)
    raw = bytes(int(x, 16) for x in argv[argv.index("--iso") + 1:][:7])
    return 0 if compare(coff, raw) == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
