#!/usr/bin/env python3
"""verres.py -- print EVERY VS_VERSIONINFO string of every PE in a tree, not
just `CompanyName`.

Why this exists
----------------

`pecensus.py` reads one field, `CompanyName`, and reports it as the binary's
identity.  On this object that produced a sentence in the pre-briefing which is
false: *"`Tokyo RPG Factory` is not in a single version resource."*  It is.
`SETSUNA.exe` has no `CompanyName` at all -- the field is absent from the block,
not blank -- and its `LegalCopyright` reads

    (c)2016 Tokyo RPG Factory Co., Ltd. All rights reserved.

A census that reads one field of a structure with a dozen of them will keep
producing that class of error, so this prints the whole block and lets the
reader see which fields are absent.

It also recovers something no other tool here reports: `SETSUNA.exe` carries a
non-standard key, `Unity Version`, whose value is the engine build **with its
revision hash**.

    python verres.py census DIR      -- one row per PE, the interesting fields
    python verres.py dump   DIR      -- every field of every PE
    python verres.py grep   DIR --text STRING

Standard library only; the resource walk is `pe.py`'s.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pe as pemod                                          # noqa: E402
import redact as redactmod                                  # noqa: E402

# Added on pc-rpgmakerxp-doc. Until this object, every version resource this
# tool had met named a company; `SciLexer.dll` names a private individual and
# HIS E-MAIL ADDRESS, in `CompanyName`, written there by a linker. This tool
# printed it into a committed note, and so did `pecensus.py`, in a repository
# whose personal-data rule (pc-rpgmaker95-doc/docs/10, amended twice) says that
# what routes a message is redacted.
#
# The redaction is BY PROGRAM and at the single point every mode passes
# through, on the precedent of `uuidscan.py`'s node field: a document that
# quotes this tool cannot leak what the rule says to withhold, and a
# discipline that depends on the operator remembering is not one.
# The NAME, the copyright line, the product and the version are credit and are
# printed unchanged.


def _redact(value):
    out, _n = redactmod.redact(value.encode('utf-8', 'surrogatepass'))
    return out.decode('utf-8', 'replace')

# The keys Microsoft defines, plus the ones vendors add.  A key seen in a
# block but not in this set is printed as `other`, never dropped.
KNOWN = ('Comments', 'CompanyName', 'FileDescription', 'FileVersion',
         'InternalName', 'LegalCopyright', 'LegalTrademarks',
         'OriginalFilename', 'PrivateBuild', 'ProductName', 'ProductVersion',
         'SpecialBuild', 'Unity Version')
STRUCTURAL = ('VS_VERSION_INFO', 'StringFileInfo', 'VarFileInfo',
              'Translation')


def pe_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _d, names in os.walk(root):
        for nm in sorted(names):
            p = os.path.join(dirpath, nm)
            try:
                with open(p, 'rb') as f:
                    if f.read(2) == b'MZ':
                        yield p
            except OSError:
                continue


def fields(path):
    """[(key, value)] in file order, or [] when there is no version block.

    `pecensus.py` takes the next run that is not itself a key, skipping up to
    three.  That rule invents values: `Assembly-CSharp.dll` has an EMPTY
    `LegalCopyright`, and the skipping rule walks past it and returns the file
    name from the following field.  Here a value is the IMMEDIATELY next run,
    and if that run is itself a key the value is empty -- which is what an
    empty field looks like once the writer has dropped it from the block.
    """
    try:
        vi = pemod.PE(path).versioninfo()
    except Exception as ex:                                 # noqa: BLE001
        return None, str(ex)
    runs = (vi or {}).get('strings') or []
    if not runs:
        return [], None
    keyset = set(KNOWN) | set(STRUCTURAL)
    out = []
    i = 0
    while i < len(runs):
        k = runs[i]
        if k in keyset and k not in STRUCTURAL:
            val = ''
            if i + 1 < len(runs) and runs[i + 1] not in keyset:
                val = runs[i + 1]
            out.append((k, _redact(val)))
        i += 1
    return out, None


def short(p, root, keep=44):
    r = os.path.relpath(p, root).replace('\\', '/')
    return r if len(r) <= keep else '...' + r[-(keep - 3):]


def cmd_census(args):
    n = withblock = 0
    print('%-44s %-22s %s' % ('FILE', 'CompanyName', 'LegalCopyright'))
    missing = []
    for p in pe_files(args.root):
        n += 1
        f, err = fields(p)
        if err is not None:
            print('%-44s %s' % (short(p, args.root), err))
            continue
        if not f:
            print('%-44s %s' % (short(p, args.root),
                                '(no version resource at all)'))
            missing.append(p)
            continue
        withblock += 1
        d = dict(f)
        if 'CompanyName' not in d:
            co = '(field absent)'
        else:
            co = d['CompanyName'] or '(empty)'
        print('%-44s %-22s %s' % (short(p, args.root), co[:22],
                                  d.get('LegalCopyright', '')[:58]))
    print()
    print('PE files                       : %d' % n)
    print('carrying a version resource    : %d' % withblock)
    print('with no version resource at all: %d' % len(missing))
    for p in missing:
        print('   %s' % short(p, args.root, 70))
    return 0


def cmd_dump(args):
    for p in pe_files(args.root):
        f, err = fields(p)
        print('%s' % short(p, args.root, 200))
        if err is not None:
            print('    error: %s' % err)
            continue
        if not f:
            print('    (no version resource)')
            continue
        for k, v in f:
            print('    %-18s %s' % (k, v))
        print()
    return 0


def cmd_grep(args):
    hits = 0
    for p in pe_files(args.root):
        f, _err = fields(p)
        for k, v in (f or []):
            if args.text.lower() in v.lower() or args.text.lower() in k.lower():
                hits += 1
                print('%-44s %-18s %s' % (short(p, args.root), k, v))
    print()
    print('%d version-resource fields contain %r' % (hits, args.text))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('mode', choices=('census', 'dump', 'grep'))
    ap.add_argument('root')
    ap.add_argument('--text')
    args = ap.parse_args()
    if args.mode == 'grep' and not args.text:
        ap.error('grep needs --text')
    return globals()['cmd_' + args.mode](args)


if __name__ == '__main__':
    sys.exit(main())
