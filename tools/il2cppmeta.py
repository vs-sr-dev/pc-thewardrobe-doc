#!/usr/bin/env python3
"""Read the string tables out of an il2cpp `global-metadata.dat`.

This file is the only English on DISSIDIA's data directory outside fifty-six
table names: 25,070,416 bytes holding every C# class, method, field and
namespace name in the managed code, and every string literal the code contains.
It holds no code -- that is in `libil2cpp.so`, which this pipeline does not
disassemble -- so what comes out is an index, not a program.

THE HEADER IS NOT THE PUBLISHED ONE, AND THE FILE SAYS SO ITSELF.

Every public description of this format calls the header an array of
`(offset, size)` **pairs**.  Read that way, DISSIDIA's file gives a third
section starting at 31,022 when the second ends at 124,468, which is not a
layout, it is noise.  Read as **triples** -- offset, size, and a third field --
the sections chain end to end:

    section 0   offset        380  size    124,088   third  31,022
    section 1   offset    124,468  size  1,070,745   third  31,021
    section 2   offset  1,195,216  size  3,262,785   third 176,874
    ...
    section 30                                    ends at 25,070,416

**and 25,070,416 is the length of the file, residue 0** -- 31 sections, each
starting where the last ended give or take at most four bytes of alignment.
That is the check this reader is built on: it is a quantity the file states
twice, it fires on the whole header rather than on a sample, and no wrong
layout satisfies it.  Version 39 accompanies Unity 6000.3.10f1 here; whether it
is a stock Unity layout or a fork is not settled by this tool, and the tool does
not claim it.

The two sections that matter are found by content, not by position: the
identifier table is the largest NUL-terminated ASCII run, and the literal data
is the other one.  `strings` prints them; `grep` searches them; `census` counts.

    python il2cppmeta.py header FILE
    python il2cppmeta.py strings FILE [--section N] [--out F] [--min 3]
    python il2cppmeta.py grep FILE PATTERN [--limit N]
    python il2cppmeta.py urls FILE            -- every http(s):// found, PRINTED
                                                 AND NOT RESOLVED

Refuses anything whose magic is not 0xFAB11BAF, loudly, with a non-zero exit.
Standard library only.
"""

import os
import re
import struct
import sys

MAGIC = 0xFAB11BAF


class MetaError(Exception):
    pass


def load(path):
    d = open(path, 'rb').read()
    if len(d) < 8:
        raise MetaError('%s: %d bytes, too short for a header' % (path, len(d)))
    magic, ver = struct.unpack_from('<II', d, 0)
    if magic != MAGIC:
        raise MetaError('%s: magic is 0x%08X, not 0x%08X -- this is not an '
                        'il2cpp global-metadata' % (path, magic, MAGIC))
    return d, ver


def sections(d):
    """The header as (offset, size, third) triples, stopping when the chain
    stops chaining.  Returns the list and the byte the last one ends on."""
    out = []
    prev = None
    k = 0
    while 8 + (3 * k + 3) * 4 <= len(d):
        off, size, third = struct.unpack_from('<III', d, 8 + 3 * k * 4)
        if off == 0 or size > len(d) or off + size > len(d):
            break
        if prev is not None and not (0 <= off - prev <= 8):
            break
        out.append((off, size, third))
        prev = off + size
        k += 1
    return out, (prev or 0)


def is_text_run(d, off, size, sample=4096):
    """How much of a section reads as printable ASCII with NUL separators."""
    n = min(size, sample)
    good = sum(1 for c in d[off:off + n] if 32 <= c < 127 or c == 0)
    return good / n if n else 0.0


def text_sections(d, secs):
    out = []
    for i, (off, size, third) in enumerate(secs):
        if size < 4096:
            continue
        r = is_text_run(d, off, size)
        if r > 0.98:
            out.append((i, off, size, third, r))
    return out


def cut(d, off, size, minlen=4):
    """NUL-terminated runs that are actually text.

    The string blobs are interleaved with tables that are not text, and a naive
    cut on NUL yields thousands of two-byte fragments of integer arrays.  A run
    is kept only if every byte is printable ASCII or a byte a UTF-8 sequence
    can start -- so Japanese survives and a little-endian int does not.  The
    filter is stated rather than tuned: `strings --min N` moves it.
    """
    out = []
    p = off
    end = off + size
    while p < end:
        q = d.find(b'\0', p, end)
        if q < 0:
            q = end
        if q - p >= minlen:
            run = d[p:q]
            printable = sum(1 for c in run if 32 <= c < 127)
            if printable == len(run) or (printable >= 0.5 * len(run) and
                                         _utf8_ok(run)):
                out.append(run.decode('utf-8', 'replace'))
        p = q + 1
    return out


def _utf8_ok(run):
    try:
        run.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def cmd_header(argv):
    d, ver = load(argv[2])
    secs, end = sections(d)
    print('%s' % argv[2])
    print('  magic 0x%08X   version %d   %d bytes' % (MAGIC, ver, len(d)))
    print('  %d sections chain; last ends at %d' % (len(secs), end))
    print('  file length %d -> %s' % (len(d),
                                      'AGREES, residue 0' if end == len(d)
                                      else 'MISMATCH, residue %d'
                                           % (len(d) - end)))
    ts = text_sections(d, secs)
    print()
    print('%3s %11s %11s %11s %6s %8s' % ('k', 'offset', 'size', 'third',
                                          'pad', 'ascii'))
    prev = None
    for i, (off, size, third) in enumerate(secs):
        pad = '' if prev is None else str(off - prev)
        prev = off + size
        r = is_text_run(d, off, size)
        print('%3d %11d %11d %11d %6s %7.1f%%%s'
              % (i, off, size, third, pad, 100 * r,
                 '  <- text' if r > 0.98 and size >= 4096 else ''))
    print()
    for i, off, size, third, r in ts:
        n = len(cut(d, off, size))
        print('  section %d is text: %d bytes, %d NUL-terminated strings, '
              'third field %d' % (i, size, n, third))
    return 0 if end == len(d) else 1


def _pick(d, secs, which):
    if which is not None:
        off, size, _ = secs[which]
        return [(which, off, size)]
    # Every section, not just the ones that look like text at a glance.  The
    # strings on this file are spread across several sections and a reader that
    # picks only the obvious ones does not report zero, it reports a smaller
    # number that looks like an answer.  `cut` filters the noise out.
    return [(i, off, size) for i, (off, size, _t) in enumerate(secs)]


def cmd_strings(argv):
    d, ver = load(argv[2])
    secs, _ = sections(d)
    which = int(argv[argv.index('--section') + 1]) \
        if '--section' in argv else None
    minlen = int(argv[argv.index('--min') + 1]) if '--min' in argv else 3
    out = None
    if '--out' in argv:
        out = open(argv[argv.index('--out') + 1], 'w', encoding='utf-8')
    total = 0
    for i, off, size in _pick(d, secs, which):
        ss = cut(d, off, size, minlen)
        total += len(ss)
        print('section %d: %d bytes, %d strings' % (i, size, len(ss)))
        if out:
            for s in ss:
                out.write(s + '\n')
    if out:
        out.close()
    print('%d strings in total' % total)
    return 0


def cmd_grep(argv):
    d, ver = load(argv[2])
    secs, _ = sections(d)
    pat = re.compile(argv[3], re.I)
    limit = int(argv[argv.index('--limit') + 1]) if '--limit' in argv else 40
    n = 0
    for i, off, size in _pick(d, secs, None):
        for s in cut(d, off, size):
            if pat.search(s):
                n += 1
                if n <= limit:
                    print('  [%d] %s' % (i, s))
    print('%d match(es)' % n)
    return 0


def cmd_urls(argv):
    d, ver = load(argv[2])
    secs, _ = sections(d)
    pat = re.compile(r'https?://[^\s"\'<>]{4,}')
    hosts = {}
    seen = []
    for i, off, size in _pick(d, secs, None):
        for s in cut(d, off, size):
            for m in pat.findall(s):
                seen.append(m)
                h = m.split('/')[2] if '/' in m[8:] else m
                hosts[h] = hosts.get(h, 0) + 1
    print('%d URL occurrences, %d distinct hosts' % (len(seen), len(hosts)))
    print('THESE ARE PRINTED AND NOT RESOLVED. The service is live.')
    for h in sorted(hosts, key=lambda x: -hosts[x]):
        print('  %-58s %d' % (h, hosts[h]))
    return 0


CMDS = dict(header=cmd_header, strings=cmd_strings, grep=cmd_grep,
            urls=cmd_urls)


def main(argv):
    if len(argv) < 3 or argv[1] not in CMDS:
        print(__doc__)
        return 2
    try:
        return CMDS[argv[1]](argv)
    except MetaError as e:
        print('REFUSED  %s' % e)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
