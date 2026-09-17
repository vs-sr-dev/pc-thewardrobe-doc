#!/usr/bin/env python3
"""pif.py -- a reader for the Windows 3.x Program Information File.

WHERE THIS CAME FROM, AND WHY ONLY HALF OF IT CAME
--------------------------------------------------
The PIF parser below is **`pc-baronbaldric-doc/tools/pifico.py`**, written on
that object for `BALDRIC.PIF`, and it is here because
`pc-hexxagon-doc`'s pre-briefing found it in the collection and not in this
box. A tool that already exists next door and did not travel is a finding
about the box, and the repair is to carry it -- not to re-derive it. The
arithmetic of a stock 545-byte 3.x PIF is `pc-baronbaldric-doc/docs/04`'s and
is cited there rather than redone here.

**Its other half did not come, and that is a decision.** `pifico.py` parses a
`.PIF` and a `.ICO`; this box already has `ico.py`, which reads `HEXX.ICO` at
residue 0 on the first run. Importing a second icon reader to get a PIF reader
would put two tools on one format for no gain, so the ICO half stayed where it
was.

WHAT CHANGED ON THE WAY IN
--------------------------
`pifico.py` predates the box's standing rules and keeps none of them: no
`dirguard.want_file`, no `nameguard.guard()`, no `--selftest`, and selection
by whatever path it is handed. Copying it unchanged would have imported a tool
that four of the box's five rules say is not finished. So the parsing is that
tool's, field for field, and the front door is this box's:

  * `dirguard.want_file`, so a directory is refused and not a traceback;
  * `nameguard.guard()`, because it prints a file name;
  * selection by GRAMMAR -- the 22-byte `MICROSOFT PIFEX` section header at
    offset 0x171, and a section chain that accounts for every byte -- and
    never by the `.PIF` extension;
  * a `--selftest` built from a PIF constructed in this file, so it passes in
    a repository that holds no PIF at all, and which says how many checks it
    skipped when the object is not beside it.

THE LAYOUT, WHICH IS PUBLISHED
------------------------------
369 bytes of standard section, then a chain of 22-byte section headers:

    +0   char[16]  name, space padded
    +16  u16       offset of the next header, 0xFFFF to end
    +18  u16       offset of this section's data
    +20  u16       length of that data

`MICROSOFT PIFEX`'s data IS the 369-byte standard section, so its length must
not be counted twice. A stock Windows 3.x PIF Editor writes exactly three
sections and 369 + 22 + 22 + 104 + 22 + 6 = **545**.

`HEXXAGON`'s shipped `HEXX.PIF` is 545 bytes -- the CRC-32 in `HEXX01.EXE`
says so. The one on disk is 995, and `--validate` says where the other 450
went.

    python tools/pif.py Hexxagon/HEXX.PIF
    python tools/pif.py Hexxagon/HEXX.PIF --validate
    python tools/pif.py --selftest
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

STANDARD = 0x171          # 369, the standard section
SECTION_HEADER = 22
PIFEX = 'MICROSOFT PIFEX'
END = 0xFFFF


class PifError(Exception):
    """A file this reader will not pretend to understand."""


def _s(b):
    return b.split(b'\x00')[0].decode('latin-1').rstrip()


def sections(blob):
    """The section chain, or a refusal. Never trusts a name or an extension."""
    if len(blob) < STANDARD + SECTION_HEADER:
        raise PifError('shorter than a standard section and one header')
    out = []
    p = STANDARD
    seen = set()
    while True:
        if p in seen:
            raise PifError('the section chain loops at 0x%03X' % p)
        seen.add(p)
        if p + SECTION_HEADER > len(blob):
            raise PifError('a section header at 0x%03X runs past the end' % p)
        name = _s(blob[p:p + 16])
        nxt, doff, dlen = struct.unpack_from('<HHH', blob, p + 16)
        if dlen and doff + dlen > len(blob):
            raise PifError('section %r claims %d bytes at 0x%04X and the file '
                           'is %d' % (name, dlen, doff, len(blob)))
        out.append(dict(at=p, name=name, next=nxt, data_at=doff, length=dlen))
        if nxt == END:
            break
        p = nxt
    if not out or out[0]['name'] != PIFEX:
        raise PifError('the first section at 0x%03X is %r and not %r'
                       % (STANDARD, out[0]['name'] if out else None, PIFEX))
    return out


def accounted(blob, chain):
    """369 + every header + every section's data, PIFEX's data excepted."""
    total = STANDARD
    for sec in chain:
        total += SECTION_HEADER
        if not sec['name'].startswith('MICROSOFT'):
            total += sec['length']
    return total


def is_pif(blob):
    """Selection by grammar: the chain parses and accounts for every byte."""
    try:
        chain = sections(blob)
    except PifError:
        return False
    return accounted(blob, chain) == len(blob)


def standard(blob):
    """The published fields of the 369-byte standard section."""
    mx, mn = struct.unpack_from('<HH', blob, 0x20)
    return dict(reserved=blob[0], checksum=blob[1],
                title=_s(blob[2:32]), max_memory=mx, min_memory=mn,
                program=_s(blob[0x24:0x63]), dos_flags=blob[0x63],
                directory=_s(blob[0x64:0x84]),
                parameters=_s(blob[0x84:0xA5]))


# ---------------------------------------------------------------- selftest --

OBJECT_REL = 'Hexxagon/HEXX.PIF'
OBJECT_CHECKS = 9


def _build(extra=None):
    """A PIF built here, so the grammar block runs in any repository."""
    body = bytearray(b'\x20' * STANDARD)
    body[0] = 0
    body[1] = 0x52
    body[2:2 + 30] = b'Test'.ljust(30, b'\x00')
    struct.pack_into('<HH', body, 0x20, 128, 64)
    body[0x24:0x24 + 0x3F] = b'TEST.EXE'.ljust(0x3F, b'\x00')
    body[0x64:0x64 + 0x20] = b'\x00' * 0x20
    body[0x84:0x84 + 0x21] = b'\x00' * 0x21

    named = [(PIFEX, b''), ('WINDOWS 386 3.0', bytes(104)),
             ('WINDOWS 286 3.0', bytes(6))]
    if extra:
        named.append(extra)
    headers = bytearray()
    payload = bytearray()
    base = STANDARD
    head_bytes = SECTION_HEADER * len(named)
    data_at = base + head_bytes
    for i, (name, data) in enumerate(named):
        at = base + i * SECTION_HEADER
        nxt = END if i == len(named) - 1 else at + SECTION_HEADER
        if name == PIFEX:
            doff, dlen = 0x0000, STANDARD
        else:
            doff, dlen = data_at + len(payload), len(data)
            payload += data
        headers += name.ljust(16).encode('latin-1') \
            + struct.pack('<HHH', nxt, doff, dlen)
    return bytes(body + headers + payload)


def selftest(object_path=None):
    checks = []
    skipped = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    blob = _build()
    want('a stock three-section PIF built here is 545 bytes', len(blob), 545)
    want('369 + 22 + 22 + 104 + 22 + 6', 369 + 22 + 22 + 104 + 22 + 6, 545)
    want('and it is recognised as a PIF', is_pif(blob), True)
    chain = sections(blob)
    want('three sections', [s['name'] for s in chain],
         [PIFEX, 'WINDOWS 386 3.0', 'WINDOWS 286 3.0'])
    want('PIFEX\'s data is the standard section and is not counted twice',
         accounted(blob, chain), len(blob))
    fields = standard(blob)
    want('the standard fields read back',
         [fields['title'], fields['program'], fields['max_memory']],
         ['Test', 'TEST.EXE', 128])

    # a fourth section, which is what Windows 95 adds and what this object has
    blob4 = _build(('WINDOWS VMM 4.0', bytes(428)))
    want('a fourth section of 428 bytes makes it 995',
         len(blob4), 545 + SECTION_HEADER + 428)
    want('995 - 545', 995 - 545, SECTION_HEADER + 428)
    want('and it still accounts for every byte', is_pif(blob4), True)

    # -- the refusals -------------------------------------------------------
    for label, data in (
            ('a file too short for a header is refused', b'\x00' * 100),
            ('a chain whose first section is not PIFEX is refused',
             bytes(STANDARD) + b'NOT PIFEX'.ljust(16)
             + struct.pack('<HHH', END, 0, 0)),
    ):
        try:
            sections(data)
            checks.append((label, False, 'it parsed'))
        except PifError:
            checks.append((label, True, ''))
    # THE POSITIVE CONTROL THAT MUST FIRE: one byte more and it must refuse.
    want('a PIF with one byte appended no longer accounts for every byte',
         is_pif(blob + b'\x00'), False)
    want('and a truncated one does not either', is_pif(blob[:-1]), False)

    here = os.path.dirname(os.path.abspath(__file__))
    obj = object_path or os.path.join(here, '..', *OBJECT_REL.split('/'))
    if os.path.isfile(obj):
        before = len(checks)
        with open(obj, 'rb') as handle:
            blob = handle.read()
        want('the object is a PIF', is_pif(blob), True)
        want('and it is 995 bytes, not the 545 that shipped', len(blob), 995)
        chain = sections(blob)
        want('it carries four sections', len(chain), 4)
        want('and the fourth is WINDOWS VMM 4.0', chain[3]['name'],
             'WINDOWS VMM 4.0')
        # THE CONFIRMATION: the added section begins where the shipped file
        # ended. That number is in HEXX01.EXE's central directory and not here.
        want('whose header begins at 545, the size of the shipped file',
             chain[3]['at'], 545)
        want('and whose data is 428 bytes, so 22 + 428 = 450',
             [chain[3]['length'], SECTION_HEADER + chain[3]['length']],
             [428, 450])
        want('545 + 450', 545 + 450, len(blob))
        fields = standard(blob)
        want('the window title is Hexxagon', fields['title'], 'Hexxagon')
        want('and the program it points at is HEXX.EXE', fields['program'],
             'HEXX.EXE')
        grew = len(checks) - before
        checks.append(('the object block contributes the %d checks the skip '
                       'figure promises' % OBJECT_CHECKS,
                       grew == OBJECT_CHECKS, 'it contributed %d' % grew))
    else:
        skipped.append((OBJECT_CHECKS,
                        '%s not beside the box; pass --object PATH to run '
                        'them' % OBJECT_REL))

    checks.append(('dirguard.want_file is imported',
                   hasattr(dirguard, 'want_file'), ''))
    checks.append(('nameguard.guard is imported',
                   hasattr(nameguard, 'guard'), ''))

    width = max(len(c[0]) for c in checks)
    for label, ok, detail in checks:
        print('  %-*s  %s%s' % (width, label, 'ok' if ok else 'FAIL',
                                '' if ok else '   ' + detail))
    for count, why in skipped:
        print('  %-*s  SKIP   %d checks: %s' % (width, '(object block)',
                                                count, why))
    bad = sum(1 for _l, ok, _d in checks if not ok)
    lost = sum(count for count, _why in skipped)
    print('%d checks, %d failures, %d skipped' % (len(checks), bad, lost))
    return 1 if bad else 0


# -------------------------------------------------------------------- main --

def report(name, blob, deep):
    chain = sections(blob)
    fields = standard(blob)
    print('%s' % name)
    print('  file size                 : %d' % len(blob))
    print()
    print('  -- standard section, %d bytes --' % STANDARD)
    print('  0x002 window title        : %r' % fields['title'])
    print('  0x020 max memory          : %d KB' % fields['max_memory'])
    print('  0x022 min memory          : %d KB' % fields['min_memory'])
    print('  0x024 program path        : %r' % fields['program'])
    print('  0x063 ms-dos flags        : 0x%02X' % fields['dos_flags'])
    print('  0x064 default directory   : %r' % fields['directory'])
    print('  0x084 program parameters  : %r' % fields['parameters'])
    print()
    print('  -- section chain --')
    for sec in chain:
        print('  0x%03X %-17s next=0x%04X data=0x%04X len=%d'
              % (sec['at'], repr(sec['name']), sec['next'], sec['data_at'],
                 sec['length']))
        if deep and sec['length'] and sec['name'].startswith('WINDOWS 386'):
            w = struct.unpack_from('<12H', blob, sec['data_at'])
            print('        386: maxmem=%d reqmem=%d fgprio=%d bgprio=%d '
                  'emsmax=%d emsmin=%d xmsmax=%d xmsmin=%d'
                  % w[:8])
        if deep and sec['length'] and sec['name'].startswith('WINDOWS 286'):
            w = struct.unpack_from('<3H', blob, sec['data_at'])
            print('        286: xmsmin=%d xmsmax=%d flags=0x%04X' % w)
    total = accounted(blob, chain)
    print()
    print('  %d + section headers + section data : %d of %d   %s'
          % (STANDARD, total, len(blob),
             'EXACT' if total == len(blob) else 'MISMATCH'))


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--validate', action='store_true',
                    help='also decode the 386 and 286 section bodies')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--object', default=None,
                    help='where %s is, for --selftest, when the box has '
                         'travelled away from it' % OBJECT_REL)
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest(args.object))
    if not args.file:
        ap.error('give a Windows 3.x PIF')
    path = dirguard.want_file(args.file, 'pif')
    with open(path, 'rb') as handle:
        blob = handle.read()
    if not is_pif(blob):
        try:
            chain = sections(blob)
        except PifError as exc:
            print('REFUSE  %s: %s' % (os.path.basename(path), exc))
            return 1
        print('REFUSE  %s: the section chain accounts for %d bytes and the '
              'file is %d' % (os.path.basename(path),
                              accounted(blob, chain), len(blob)))
        return 1
    report(os.path.basename(path), blob, args.validate)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
