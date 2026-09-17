#!/usr/bin/env python3
"""symtab.py -- the C symbol names a linker left past the end of an MZ image.

WHAT THIS IS FOR
----------------
An MZ header states how long the program image is, in `e_cp` pages and
`e_cblp` bytes-in-the-last-page. Anything in the file past that point is
**slack**: the loader will never read it, and whatever is there was put there
by something other than the program. On `ROVESCIN.EXE` the slack is 14,910
bytes -- 43.9732 % of the file -- and it is a table of NUL-terminated C symbol
names in the author's own Italian.

That table is the best documentation this object has, and it is documentation
its author never wrote and never meant anybody to read. Nobody dresses up for
the linker.

HOW A SYMBOL IS COUNTED, AND WHY THE RULE IS WRITTEN DOWN
----------------------------------------------------------
A symbol is a **NUL-terminated** run of letters, `0-9` and `_` that begins
with `_` **at the start of an identifier** -- the byte before the underscore
is not a letter, a digit or an underscore. Not "a run of printable bytes that
looks like one": the terminator is part of the evidence, and requiring it is
what separates a symbol from four capitals that happen to follow an
underscore inside compressed data.

(The rule read "capitals" and had no left boundary until `pc-bianconatale-doc`;
see the comment on `SYMBOL` below for both defects, and for why the 244 this
docstring quotes for ROVESCIN.EXE is now **239**.)

**And there is no minimum length.** The probe that first counted this table
looked for runs of four or more printable characters and reported 241 names.
This rule reported **244**, and the two disagree in two ways worth naming:

  * the run rule reported `_AHINCR` where the file holds `__AHINCR` -- Borland
    prefixes a C name with `_`, so a C name that already begins with `_`
    arrives with two. **Eighty** names differ by that one character alone,
    and they are the same symbols under two spellings, not different symbols;
  * the run rule's four-character floor **dropped `_RE`**, which sits between
    `_FONT` and `__ATEXITTBL`, NUL-terminated on both sides. *Re*, the king,
    the third-highest card in the deck this program deals. **A length filter
    nobody argued for removed the shortest symbol in the table, and it
    happened to be a playing card.**

`--selftest` requires a two-character symbol to be counted, and requires the
count over the whole 14,910 bytes to be 239 symbols and 239 *distinct* names
-- a linker's table repeats nothing, and a reading that produced duplicates
would be a reading that had found substrings. (It did: the 244 held five
substrings of Borland helper labels, and the sentence above was true of the
count and false of the reading, which is why a distinct-count check alone was
not enough.)

WHAT IT DOES NOT KNOW
---------------------
It does not know what produced the table -- a linker's map, a debugger's
symbols, an object-file fragment the linker appended. The shape says C and the
producer does not name itself. It does not know which names are the author's
and which are his C library's; `--split` guesses at that with a list of known
Borland runtime names and **reports the guess as a guess**.

    python tools/symtab.py rovescino/ROVESCIN.EXE
    python tools/symtab.py rovescino/ROVESCIN.EXE --list
    python tools/symtab.py rovescino/ROVESCIN.EXE --grep DICE
    python tools/symtab.py rovescino/ROVESCIN.EXE --split
    python tools/symtab.py --selftest
"""
import argparse
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard
import nameguard

# One or more leading underscores -- Borland's startup uses two -- then at
# least one LETTER, then letters, digits and underscores, then the NUL. The
# leading letter is what stops a bare `_\0` in the middle of a data area from
# being counted as a symbol with an empty name, which the first draft did
# three times.
#
# THE LETTER WAS A CAPITAL, AND THAT WAS A DEFECT. This pattern was written on
# `ROVESCIN.EXE`, whose author wrote every symbol in Italian capitals --
# `_DICE_CRAXI`, `_ORDINA_CARTE` -- and the pattern closed the form it was
# shown. On `BN.EXE` (BIANCO NATALE, Tecnoart, 1994) the author wrote
# `_BMBimage_in`, `_DB_bob_display`, `_mouse`, `_enemy_for_stage`, and the
# capitals-only pattern reported **20 symbols of 381** -- 5.2477 % -- while
# printing `0 failures`. `pc-hexxagon-doc/docs/10` had named the class one
# session earlier, on `sift.py`'s street-address pattern: *a repair that
# closed the form it was shown and did not ask what the other forms were*,
# and predicted that the next object it met might be a person's. It was.
# C symbols are case-sensitive and a C programmer may use either case; the
# rule is now the language's and not one author's.
#
# AND THE SECOND DEFECT, WHICH THE FIRST REPAIR UNCOVERED. Admitting lower
# case took BN.EXE from 20 to 401 found -- and 381 distinct, so twenty
# repeats, in a table this docstring says repeats nothing. Every repeat was a
# TAIL of a name that does not begin with an underscore: `_x` out of `max_x`,
# `_ax` out of `r_ax`, `_t` out of `size_t`, `_TOS` out of `emws_TOS`. The
# pattern had no left boundary, and under capitals only that showed on five
# names of ROVESCIN.EXE's 244 -- `_LDIV`, `_LLSH`, `_PADD` out of `H_LDIV`,
# `H_LLSH`, `H_PADD`, and `_LXMUL`, `_PCMP` out of `N_LXMUL`, `N_PCMP`,
# Borland's own helper labels -- which nobody noticed because five fragments
# of five different labels do not repeat. The lookbehind requires the
# underscore to BEGIN an identifier. With it, BN.EXE reports 334 found and
# 334 distinct and ROVESCIN.EXE 239 and 239: a linker's table repeats
# nothing, on both, for the first time. **The published 244 was 239 symbols
# and five fragments**, and `--selftest` now asserts 239 and names the five.
SYMBOL = re.compile(rb'(?<![A-Za-z0-9_])_+[A-Za-z][A-Za-z0-9_]*\x00')

# Borland's C0.ASM startup and its runtime, by name. This list exists to make
# a GUESS reportable, not to make it true: a name in it is *probably* the C
# library's and a name outside it is *probably* the author's, and both halves
# are printed with that word attached.
RUNTIME_MARKS = (
    'C0', 'CRTINIT', 'ATEXIT', 'STK', 'HEAP', 'BRK', 'SBRK', 'MALLOC',
    'FREE', 'REALLOC', 'FARMALLOC', 'FARFREE', 'FARHEAP', 'EXIT', 'ABORT',
    'ERRNO', 'DOSERR', 'STREAMS', 'FMODE', 'OPENFD', 'TMPNAM', 'TMPNUM',
    'ENVIRON', 'ENVLNG', 'ENVSEG', 'ENVSIZE', 'SETENVP', 'PSP', 'OSMAJOR',
    'OSMINOR', 'VERSION', 'TURBOCRT', 'AHSHIFT', 'AHINCR', 'CTYPE',
    'TZ', 'TIMEZONE', 'DAYLIGHT', 'MONTHDAY', 'ISDST', 'STARTTIME',
    'REALCVT', 'LDIV', 'LUDIV', 'LMOD', 'LUMOD', 'LXLSH', 'LXMUL', 'LLSH',
    'PADD', 'PSUB', 'PCMP', 'MMODEL', 'ROVER', 'FIRST', 'LAST',
    'SAVEAREA', 'INT0VECTOR', 'INT4VECTOR', 'INT5VECTOR', 'INT6VECTOR',
    'SCANTODVECTOR', 'REALCVTVECTOR', 'VIDEO', 'RESTOREZERO',
    'EXITCLEAN', 'EXITBUF', 'EXITFOPEN', 'EXITOPEN', 'NOTUMASK', 'WSCROLL',
    'DIRECTVIDEO', 'HARDBUF', 'SETUPIO', 'SCREENIO', 'VALIDATEXY',
)

# Standard C library entry points, which are somebody else's names in any
# language. Anything left after these and RUNTIME_MARKS is the author's.
LIBC = set("""
ACCESS ATEXIT ATOI ATOL BRK CHMOD CLOSE CPRINTF CPUTN DELAY DOSTOUNIX EOF
FCLOSE FDOPEN FFLUSH FGETC FGETCHAR FLUSHALL FOPEN FPUTC FPUTCHAR FPUTN
FREAD FREOPEN FSEEK FTELL GETCH GETCHE GETDATE GETENV GETTEXT GETTIME
HIGHVIDEO INT86 INT86X IOCTL IOERROR ISATTY ITOA LONGTOA LOWVIDEO LSEEK
LTOA MEMCPY MEMSET MKNAME MOVETEXT NFGETC NGETCHE NORMVIDEO NUNGETCH OPEN
OUTPORT OUTPORTB PRINTF PUTCH PUTTEXT RAND READ SCROLL SEGREAD SETBLOCK
SETDATE SETMEM SETTIME SETVBUF SRAND STIME STRCAT STRCPY STRLEN STRNCPY
TELL TEXTATTR TEXTBACKGROUND TEXTCOLOR TIME TMPNAM TZSET ULTOA UNGETCH
UNLINK UNIXTODOS VPRINTER VPTR VRAM WHEREX WHEREXY WHEREY WRITE XFCLOSE
XFFLUSH MAIN
""".split())


class SymtabError(Exception):
    """A file this reader will not pretend to understand."""


def image_length(blob):
    """Where the loader stops reading, from the MZ header's own arithmetic."""
    if blob[:2] not in (b'MZ', b'ZM'):
        raise SymtabError('not an MZ executable')
    cblp, cp = struct.unpack('<HH', blob[2:6])
    return (cp - 1) * 512 + cblp if cblp else cp * 512


def slack(blob):
    """(offset, bytes) of everything past the declared image."""
    at = image_length(blob)
    if at > len(blob):
        raise SymtabError('the header declares %d bytes and the file has %d'
                          % (at, len(blob)))
    return at, blob[at:]


def symbols(blob):
    """Every NUL-terminated `_`-symbol, in the order the file carries it.

    No minimum length. See the docstring: the four-character floor that this
    table was first counted under dropped `_RE`.
    """
    out = []
    for match in SYMBOL.finditer(blob):
        name = match.group()[:-1].decode('ascii')
        out.append((match.start(), name))
    return out


def split(names):
    """(author's, runtime's, and it is a GUESS) -- the word is in the return."""
    mine, theirs = [], []
    for name in names:
        # Compared in capitals, because the marks are written in capitals
        # and the names, since the repair above, may not be.
        stem = name.lstrip('_').upper()
        if stem in LIBC or any(mark in stem for mark in RUNTIME_MARKS):
            theirs.append(name)
        else:
            mine.append(name)
    return mine, theirs


# Where the object-dependent block of `--selftest` lives, and how many checks
# it contributes. Copied by `pc-hexxagon-doc` into a repository that does not
# hold `ROVESCIN.EXE`, this tool printed `13 checks, 0 failures` where it had
# printed 21: eight assertions gone, and the summary line silent about it.
# The count below is DECLARED here and VERIFIED wherever the object is
# reachable, so the skip figure cannot drift.
OBJECT_REL = 'rovescino/ROVESCIN.EXE'
OBJECT_CHECKS = 9

# A second declared block, for the object the repair was made on. The first
# block is the regression -- every one of the 239 real names must stay -- and
# this one is the positive control: 334 where the old pattern saw 20. Both
# are counted, skippable and re-pointable, on the same terms.
HOME_REL = 'Bianco-Natale/BN.EXE'
HOME_CHECKS = 7


def selftest(object_path=None, home_path=None):
    checks = []
    skipped = []

    def want(label, got, expected):
        checks.append((label, got == expected,
                       '' if got == expected else 'got %r wanted %r'
                       % (got, expected)))

    # -- the header arithmetic ----------------------------------------------
    head = b'MZ' + struct.pack('<HH', 53, 38) + bytes(56)
    want('e_cblp 53 and e_cp 38 give an image of 18997',
         image_length(head), 18997)
    want('e_cblp 0 means the last page is full',
         image_length(b'MZ' + struct.pack('<HH', 0, 2) + bytes(56)), 1024)
    try:
        image_length(b'XX' + bytes(60))
        checks.append(('a file that is not MZ is refused', False, 'it parsed'))
    except SymtabError:
        checks.append(('a file that is not MZ is refused', True, ''))

    # -- the symbol rule ----------------------------------------------------
    want('a NUL-terminated symbol is found',
         [n for _o, n in symbols(b'\x00_MAIN\x00')], ['_MAIN'])
    want('TWO-CHARACTER SYMBOLS COUNT -- there is no minimum length',
         [n for _o, n in symbols(b'_FONT\x00_RE\x00_X\x00')],
         ['_FONT', '_RE', '_X'])
    want('a symbol with no terminator is NOT counted',
         [n for _o, n in symbols(b'_NOTERMINATED')], [])
    # This check used to read `lower case is not a symbol` and expect [].
    # That was the defect, asserted. C is case-sensitive both ways.
    want('LOWER CASE IS A SYMBOL -- the pattern is C\'s and not one '
         'author\'s', [n for _o, n in symbols(b'_lower\x00')], ['_lower'])
    want('mixed case is a symbol',
         [n for _o, n in symbols(b'_BMBimage_in\x00_DB_bob_display\x00')],
         ['_BMBimage_in', '_DB_bob_display'])
    want('a bare underscore before a digit is still not a symbol',
         [n for _o, n in symbols(b'_1\x00')], [])
    want('the split compares in capitals, so a lower-case malloc is the '
         'runtime\'s', split(['_malloc', '_mouse'])[1], ['_malloc'])
    want('a leading double underscore is kept',
         [n for _o, n in symbols(b'__TURBOCRT\x00')], ['__TURBOCRT'])
    want('digits are allowed inside', [n for _o, n in symbols(b'_C0ARGC\x00')],
         ['_C0ARGC'])
    # This check used to run on b'xxx_RE\x00' and pass, which is the second
    # defect asserted: a tail of `xxx_RE` is not a symbol beginning with `_`.
    want('the offset is where the underscore is',
         symbols(b'\x00\x00\x00_RE\x00')[0][0], 3)
    want('A TAIL OF A LONGER NAME IS NOT A SYMBOL: xxx_RE yields nothing',
         [n for _o, n in symbols(b'xxx_RE\x00')], [])
    want('nor is the tail of a name with digits before the underscore',
         [n for _o, n in symbols(b'e086_Entry\x00')], [])
    want('but a name that begins with the underscore after a NUL is',
         [n for _o, n in symbols(b'r_ax\x00_mouse\x00')], ['_mouse'])

    # -- the split is a guess and behaves like one --------------------------
    mine, theirs = split(['_ORDINA_CARTE', '_MALLOC', '_DICE_CRAXI',
                          '__TURBOCRT', '_TOPO'])
    want('the author\'s names land on the author\'s side',
         sorted(mine), ['_DICE_CRAXI', '_ORDINA_CARTE', '_TOPO'])
    want('the runtime\'s names land on the runtime\'s side',
         sorted(theirs), ['_MALLOC', '__TURBOCRT'])

    # -- and against the object, if it is beside the box --------------------
    here = os.path.dirname(os.path.abspath(__file__))
    obj = object_path or os.path.join(here, '..', *OBJECT_REL.split('/'))
    if os.path.isfile(obj):
        before = len(checks)
        with open(obj, 'rb') as handle:
            blob = handle.read()
        at, tail = slack(blob)
        want('the declared image ends at 18997', at, 18997)
        want('the slack is 14910 bytes', len(tail), 14910)
        found = symbols(tail)
        names = [n for _o, n in found]
        # 239, not the 244 pc-rovescino-doc published: five of those were
        # tails of Borland helper labels, and the SYMBOL comment names them.
        want('the slack holds 239 symbols', len(found), 239)
        want('and a linker\'s table repeats none of them: 239 distinct',
             len(set(names)), 239)
        want('the five fragments of the old 244 are gone, and their labels '
             'do not begin with an underscore',
             [n for n in ('_LDIV', '_LLSH', '_PADD', '_LXMUL', '_PCMP')
              if n in set(names)], [])
        want('_RE is one of them, and it is the shortest',
             min(names, key=len), '_RE')
        want('the four suits are all there',
             sorted(n for n in set(names)
                    if n in ('_ORO', '_COPPE', '_MAZZE', '_SPADE')),
             ['_COPPE', '_MAZZE', '_ORO', '_SPADE'])
        want('there are exactly four _DICE_ functions',
             sorted(n for n in set(names) if n.startswith('_DICE_')),
             ['_DICE_COSSIGA', '_DICE_CRAXI', '_DICE_IL_GOBBO',
              '_DICE_OCCHETTO'])
        want('THE DECLARED IMAGE HOLDS NONE OF THEM: the table is entirely '
             'in the slack', len(symbols(blob[:at])), 0)
        grew = len(checks) - before
        checks.append(('the object block contributes the %d checks the skip '
                       'figure promises' % OBJECT_CHECKS,
                       grew == OBJECT_CHECKS, 'it contributed %d' % grew))
    else:
        skipped.append((OBJECT_CHECKS,
                        '%s not beside the box; pass --object PATH to run '
                        'them' % OBJECT_REL))

    # -- and against the object the repair was made on --------------------
    home = home_path or os.path.join(here, '..', *HOME_REL.split('/'))
    if os.path.isfile(home):
        before = len(checks)
        with open(home, 'rb') as handle:
            blob = handle.read()
        at, tail = slack(blob)
        want('BN.EXE: the declared image ends at 48438', at, 48438)
        want('the slack is 21719 bytes', len(tail), 21719)
        found = symbols(tail)
        names = [n for _o, n in found]
        want('the slack holds 334 symbols and 334 distinct, where the '
             'capitals-only pattern saw 20', [len(found), len(set(names))],
             [334, 334])
        # 17 and not 20: `_ST`, `_ND` and `_TOS` were tails of
        # `_bn_fire_anim_ST`, `_bn_fire_anim_ND` and `emws_TOS`, which the
        # old pattern could not see whole. Three of its twenty were fragments.
        want('17 of the old 20 are whole names; _ST, _ND and _TOS were tails '
             'of _bn_fire_anim_ST, _bn_fire_anim_ND and emws_TOS',
             [len([n for n in set(names)
                   if re.fullmatch(r'_+[A-Z][A-Z0-9_]*', n)]),
              sorted(n for n in set(names) if n.startswith('_bn_fire_anim')),
              [n for n in ('_ST', '_ND', '_TOS') if n in set(names)]],
             [17, ['_bn_fire_anim_ND', '_bn_fire_anim_ST'], []])
        want('the .BMB loader and the double-buffered blit are named',
             sorted(n for n in set(names)
                    if n in ('_BMBimage_in', '_DB_bob_display')),
             ['_BMBimage_in', '_DB_bob_display'])
        want('four enemy frame sequences, one per level',
             sorted(n for n in set(names)
                    if re.fullmatch(r'_enemy[1-4]_fr_seq', n)),
             ['_enemy1_fr_seq', '_enemy2_fr_seq', '_enemy3_fr_seq',
              '_enemy4_fr_seq'])
        want('the declared image holds none of them', len(symbols(blob[:at])),
             0)
        grew = len(checks) - before
        checks.append(('the home block contributes the %d checks the skip '
                       'figure promises' % HOME_CHECKS,
                       grew == HOME_CHECKS, 'it contributed %d' % grew))
    else:
        skipped.append((HOME_CHECKS,
                        '%s not beside the box; pass --home PATH to run '
                        'them' % HOME_REL))

    checks.append(('dirguard.want_file is imported',
                   hasattr(dirguard, 'want_file'), ''))

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


def main():
    nameguard.guard()
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('file', nargs='?')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--grep', default=None,
                    help='print only symbols containing this substring')
    ap.add_argument('--split', action='store_true',
                    help='guess at author versus C runtime, and say so')
    ap.add_argument('--whole-file', action='store_true',
                    help='scan the whole file, not only the slack')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--object', default=None,
                    help='where %s is, for --selftest, when the box has '
                         'travelled away from it' % OBJECT_REL)
    ap.add_argument('--home', default=None,
                    help='where %s is, for --selftest, likewise' % HOME_REL)
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest(args.object, args.home))
    if not args.file:
        ap.error('give an MZ executable')
    path = dirguard.want_file(args.file, 'symtab')
    with open(path, 'rb') as handle:
        blob = handle.read()

    at, tail = slack(blob)
    region = blob if args.whole_file else tail
    base = 0 if args.whole_file else at
    found = symbols(region)
    names = [n for _o, n in found]
    distinct = sorted(set(names))

    print('%s' % os.path.basename(path))
    print('  file                 : %d bytes' % len(blob))
    print('  declared image       : %d' % at)
    print('  SLACK past the image : %d = %.4f %% of the file'
          % (len(tail), 100.0 * len(tail) / len(blob)))
    print('  scanned              : %s'
          % ('the whole file' if args.whole_file else 'the slack only'))
    print('  symbols              : %d   distinct : %d'
          % (len(found), len(distinct)))
    if not args.whole_file:
        print('  symbols in the image : %d   (the loader reads these; it does '
              'not read the slack)' % len(symbols(blob[:at])))
    print('  shortest             : %s'
          % (min(distinct, key=len) if distinct else '(none)'))
    print('  longest              : %s'
          % (max(distinct, key=len) if distinct else '(none)'))

    if args.split:
        mine, theirs = split(distinct)
        print('')
        print('  A GUESS, and it is labelled one: a name is filed as the C')
        print('  runtime\'s if it is a known Borland or libc entry point, and')
        print('  as the author\'s otherwise. Neither list is authoritative.')
        print('  probably the C runtime\'s : %d' % len(theirs))
        print('  probably the author\'s    : %d' % len(mine))
        print('')
        for name in sorted(mine):
            print('    %s' % name)
        return 0

    if args.grep:
        print('')
        for offset, name in found:
            if args.grep in name:
                print('  %7d  %s' % (base + offset, name))
        return 0

    if args.list:
        print('')
        line = []
        for name in distinct:
            line.append(name)
            if len(line) == 4:
                print('  ' + ''.join('%-22s' % n for n in line).rstrip())
                line = []
        if line:
            print('  ' + ''.join('%-22s' % n for n in line).rstrip())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
