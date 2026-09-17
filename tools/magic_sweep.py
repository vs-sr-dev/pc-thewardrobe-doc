#!/usr/bin/env python3
"""Sweep the whole partition for every container tag the corpus knows.

Three families of needle:

  * **the corpus's own** -- the envelopes and project tags of the twelve
    *Tales* builds documented so far, plus the middleware stamps that turned up
    beside them, plus the two names -- `stan` and `dimlos` -- that *Tales of
    the Tempest* raised and *Tales of Innocence* did not settle;
  * **the direct prequel's** -- what the 2003 GameCube release of this game
    carries, read out of that repository rather than invented: `MSCF`, `top2`,
    `Top2Btl`, `_custom`, `rutee`, `tod2_cut`, `h4m`, `HVQM4`;
  * **the middleware** anyone might have bought instead.

**Read the chance rate before reading any count.**  A four-byte needle turns
up by chance about once per 4 GB of uniform data.  The reading of a count
therefore changes with the size of the medium and the count alone does not say
so:

    Tales of Innocence, 128 MB cartridge      0.031 expected hits
    Tales of Hearts, 256 MiB cartridge        0.063 expected hits
    Ratatosk no Kishi, 4.29 GB Wii partition  1.00  expected hits
    Tales of Vesperia, 7.84 GB XGD2 image     1.82  expected hits

On the two discs a single hit means nothing and a zero is weak.  On a
cartridge the rate is small enough that **a single hit is worth locating and a
zero is strong** -- the denominator points the ordinary way round, which after
two disc-sized targets is worth saying out loud.  The table prints the
expected rate beside every needle so the two kinds are never mixed.

Longer needles are worth much more here, and the table prints the expected
rate for each so the two kinds are never mixed.

    python magic_sweep.py PARTITION.bin
    python magic_sweep.py PARTITION.bin --context

Standard library only.
"""

import os
import sys

CORPUS = [
    (b'CPS ', 'Legendia 2005, the sixteen-byte envelope'),
    (b'CPS\x00', 'Legendia 2005, other spelling'),
    (b'TLPS', 'Tales container tag'),
    (b'TLPK', 'Tales container tag'),
    (b'AFS\x00', 'CRI AFS archive'),
    (b'SCPK', 'Destiny 2 2002 bundle'),
    (b'THEIRSCE', 'Tales script container'),
    (b'FILE.FPB', 'Destiny 2 2002 archive name'),
    (b'FPS2', 'Rebirth / Abyss archive'),
    (b'FPS3', 'Rebirth / Abyss archive'),
    (b'FPS4', 'Tales archive, later builds'),
    (b'MSCF', "the studio's own envelope, 2003 and here"),
    (b'CVMH', 'CRI CVM volume header'),
    (b'ROFSBLD', 'CRI ROFS builder stamp'),
    (b'SAMPLE_GAME_TITLE', 'CRI builder default title'),
    (b'TO7', 'Abyss project tag'),
    (b'TO8', 'project tag, next in the series'),
    (b'ToR', 'Rebirth project tag'),
    (b'ToL', 'Legendia project tag'),
    (b'tox', 'Legendia project directory'),
    (b'tor_', 'Rebirth effect prefix, found on the Abyss disc'),
    (b'no_se_', 'Rebirth sound-effect prefix'),
    (b'stan', 'Tempest 2006 name, raised and unresolved'),
    (b'dimlos', 'Tempest 2006 name, raised and unresolved'),
    (b'EZBIND', 'Innocence 2007 archive'),
    (b'NT_DS1', 'Tempest 2006 project tag'),
    (b'To9', 'the next project number after Vesperia'),
    (b'TO9', 'the same, upper case'),
    (b'TODS', 'the DS project tag on the 2008 cartridges'),
    (b'TODS3', 'the same, with its number'),
    (b'CTODS3', 'the same, item-table spelling'),
    (b'V154', 'the second container on the 2008 cartridges'),
    (b'MODS', 'Actimagine Mobiclip video'),
    (b'VXDS', 'Actimagine VX video, the 2006 cartridge'),
    (b'MOC5', 'Actimagine Mobiclip, other spelling'),
    (b'SDAT', 'the NitroSDK sound archive'),
    (b'BLZ\x00', 'the Nintendo linker backwards LZ, as a string'),
    (b'(c)CRI', 'CRI copyright, stamped in ADX and AHX headers'),
    (b'CRI ', 'CRI middleware'),
    (b'shing', 'Hearts 2008, the male lead'),
    (b'kohaku', 'Hearts 2008, the female lead'),
    (b'beryl', 'Hearts 2008, party'),
    (b'hisui', 'Hearts 2008, party'),
    (b'innes', 'Hearts 2008, party'),
    (b'kunzite', 'Hearts 2008, party'),
    (b'yuri', 'Vesperia 2008, the male lead'),
    (b'estelle', 'Vesperia 2008'),
    (b'karol', 'Vesperia 2008'),
    (b'rita', 'Vesperia 2008'),
    (b'raven', 'Vesperia 2008'),
    (b'judith', 'Vesperia 2008'),
    (b'flynn', 'Vesperia 2008'),
    (b'repede', 'Vesperia 2008'),
    (b'YUR', 'Vesperia 2008, the three-letter form its assets use'),
    (b'EST', 'Vesperia 2008, three-letter form'),
    (b'KAR', 'Vesperia 2008, three-letter form'),
    (b'luke', 'Abyss 2005'),
    (b'emil', 'Ratatosk 2008'),
    (b'marta', 'Ratatosk 2008'),
    (b'lloyd', 'Symphonia 2003'),
    (b'veigue', 'Rebirth 2004'),
    (b'senel', 'Legendia 2005'),
    (b'reid', 'Eternia 2000'),
    (b'cress', 'Phantasia 1995'),
]

PREQUEL = [
    (b'top2', 'the 2003 project name, from `top2.c`'),
    (b'Top2', 'the 2003 relocatable modules'),
    (b'_custom', 'the one team-named map that shipped in 2003'),
    (b'rutee', 'the 2003 disc, a character from Tales of Destiny'),
    (b'tod2_cut', 'the 2003 movie table, named after Destiny 2'),
    (b'HVQM4', "Hudson's video codec, the 2003 disc's"),
    (b'.h4m', 'the 2003 movie extension'),
    (b'testfield', 'the 2003 test maps'),
    (b'BTLenemy', 'the 2003 file that held 251 codec blocks'),
    (b'ToSM', "this build's own sound-archive tag"),
    (b'TOSM', "this build's own sound-archive tag, upper case"),
    (b'RT4J', 'this game id'),
]


THISBUILD = [
    (b'TO11', "this build's project tag, predicted before the image was opened"),
    (b'To11', 'the same, mixed case, the spelling Hearts also used'),
    (b'to11', 'the same, lower case'),
    (b'TOS11', 'the same, with the series prefix Symphonia used'),
    (b'TOX11', "the same, with this disc's volume id in front"),
    (b'TOP311', 'the same, with the machine in the middle'),
    (b'TOPS311', 'the same, machine spelled out'),
    (b'TOPS3_11', 'the same, with a separator'),
    (b'TOPS3', "a first-on-this-machine count, the analogue of Hearts' TODS3"),
    (b'TO11RAW', 'the project tag as a file extension, as Hearts used .to9moh'),
    (bytes((0x5b, 0x80, 0x80, 0x8d)),
     'the packer signature at +8 of every 2003 and 2008 MSCF payload'),
    (b'TOX', "the volume id, which is the label and not necessarily the tag"),
    (b'TLZC', "this build's member compressor envelope"),
    (b'TLDAT', 'the container'),
    (b'TOFHDB', 'its index'),
    (b'TLFILE', 'the container, by name'),
    (b'BLJS-10120', 'this product code'),
    (b'NPWR01769', 'this trophy set'),
    (b'TL::', 'the engine namespace, demangled'),
    (b'N2TL', 'the engine namespace, as Itanium mangling writes it'),
    (b'tlVec', "the 2009 build's vector type"),
    (b'tlMtx', "the 2009 build's matrix type"),
    (b'Flagment', "the 2009 build's misspelling of Fragment"),
    (b'jude', 'this game, the male lead'),
    (b'milla', 'this game, the female lead'),
    (b'alvin', 'this game, party'),
    (b'elize', 'this game, party'),
    (b'leia', 'this game, party'),
    (b'rowen', 'this game, party'),
    (b'gaius', 'this game'),
    (b'muzet', 'this game'),
    (b'teepo', 'this game'),
]

PREQUEL = [
    (b'TO10', 'the 2009 Wii build, the previous number in the sequence'),
    (b'To10', 'the same, mixed case'),
    (b'TO10DS', 'the DS ROM the 2009 disc shipped'),
    (b'STGJAF', 'the 2009 game id'),
    (b'CRILAYLA', 'the CPK member compressor the 2009 disc used'),
    (b'CPK ', 'the CRI container the 2009 disc kept its bulk in'),
    (b'@UTF', 'CRI table format'),
    (b'asbel', '2009, the male lead'),
    (b'sophie', '2009, the female lead'),
    (b'hubert', '2009, party'),
    (b'cheria', '2009, party'),
    (b'malik', '2009, party'),
    (b'pascal', '2009, party'),
    (b'richard', '2009, party'),
    (b'namco-talesstudio', 'the studio domain, on the 2009 disc'),
    (b'cyclamen', 'the studio intranet board, on the 2009 disc'),
    (b'intra/', 'the studio intranet, on the 2009 disc'),
    (b'Siren14', 'the audio middleware banner, on the 2009 disc'),
    (b'Nu-Sound', 'the audio middleware banner, on the 2009 disc'),
    (b'chr_edit', 'the in-house editor the 2009 disc shipped'),
    (b'take_njd', 'the mailbox the 2009 disc shipped'),
    (b'sim:', 'the devkit path prefix the 2009 disc used'),
]

MIDDLEWARE = [
    (b'CRID', 'CRI Sofdec 2'),
    (b'@UTF', 'CRI table format'),
    (b'ADXF', 'CRI ADX'),
    (b'AHXF', 'CRI AHX'),
    (b'Sofdec', 'CRI video'),
    (b'CRI ', 'CRI Middleware'),
    (b'criware', 'CRI Middleware'),
    (b'VXDS', 'Actimagine VX'),
    (b'MODS', 'Actimagine Mobiclip'),
    (b'Bink', 'RAD Game Tools Bink'),
    (b'Miles', 'RAD Game Tools Miles'),
    (b'Havok', 'Havok physics'),
    (b'Granny', 'RAD Granny'),
    (b'FMOD', 'Firelight FMOD'),
    (b'zlib', 'zlib'),
    (b'inflate', 'zlib'),
    (b'PK\x03\x04', 'zip local header'),
    (b'\x1f\x8b\x08', 'gzip'),
]

# Added for the fourteenth build.  Everything the *platform* supplies, so that
# "what does it use instead" is asked with the same instrument as "does it use
# the format" -- and the cast of every title in the corpus, so the cross-title
# question is asked in both directions at once.
PS3 = [
    (b'SCE\x00', 'an SCE container -- a SELF, a PRX or a PUP'),
    (b'\x7fELF', 'an ELF, PPU or SPU'),
    (b'PSARC', "Sony's archive format"),
    (b'.sprx', 'a PS3 relocatable module'),
    (b'.prx', 'a PS3 relocatable module, short form'),
    (b'cellSpurs', 'the SPU task runtime'),
    (b'cellFs', 'the file system library'),
    (b'sceNp', 'the network platform library'),
    (b'edge', "Sony's EDGE SPU library, which carries a zlib of its own"),
    (b'EDGE', 'the same, upper case'),
    (b'PAMF', "Sony's multiplexed media container"),
    (b'MSF\x00', "Sony's audio stream"),
    (b'RIFF', 'a RIFF container -- AT3 lives in one'),
    (b'WAVEfmt', 'a RIFF WAVE'),
    (b'p360001', 'the SDK stamp this executable carries'),
    (b'SNC', "Sony's own C++ compiler"),
    (b'GCC:', 'the GNU compiler stamp'),
    (b'BIKi', 'RAD Game Tools Bink, revision i'),
    (b'BIKb', 'RAD Game Tools Bink, revision b'),
    (b'KB2', 'RAD Game Tools Bink 2'),
    (b'\x5d\x00\x00\x01\x00', 'an LZMA properties byte and a 64 KiB dictionary'),
]

CAST = [
    (b'rutee', 'Destiny 1997 / Symphonia 2003'),
    (b'stahn', 'Destiny 1997'),
    (b'dimlos', 'Destiny 1997'),
    (b'cress', 'Phantasia 1995'),
    (b'reid', 'Eternia 2000'),
    (b'veigue', 'Rebirth 2004'),
    (b'senel', 'Legendia 2005'),
    (b'luke', 'Abyss 2005'),
    (b'emil', 'Ratatosk 2008, six weeks earlier'),
    (b'marta', 'Ratatosk 2008, six weeks earlier'),
    (b'richter', 'Ratatosk 2008, six weeks earlier'),
    (b'lloyd', 'Symphonia 2003 and Ratatosk 2008'),
    (b'yuri', 'this game'),
    (b'estelle', 'this game'),
    (b'karol', 'this game'),
    (b'repede', 'this game'),
    (b'judith', 'this game'),
    (b'flynn', 'this game'),
]


def iter_files(path):
    """Every file under `path`, or `path` itself if it is a file.

    The disc-level sweep on this platform is **blind to the executable**,
    because `EBOOT.BIN` is a signed SELF whose segments are encrypted: every
    string in the game's own code returns zero on the raw image and the zero
    means nothing.  So the sweep is run twice -- once over the image, once
    over the decrypted corpus -- and both are published, because neither is
    the whole medium."""
    if os.path.isfile(path):
        yield path
        return
    for dp, dn, fn in os.walk(path):
        dn.sort()
        for f in sorted(fn):
            yield os.path.join(dp, f)


def sweep_tree(paths, needles):
    counts = dict((n, 0) for n, _ in needles)
    first = dict((n, []) for n, _ in needles)
    uniq = list(dict.fromkeys(n for n, _ in needles).keys())
    total = 0
    for root in paths:
        for p in iter_files(root):
            with open(p, 'rb') as f:
                buf = f.read()
            total += len(buf)
            for n in uniq:
                i = buf.find(n)
                while i >= 0:
                    counts[n] += 1
                    if len(first[n]) < 6:
                        first[n].append('%s@%d' % (p, i))
                    i = buf.find(n, i + 1)
    return counts, first, total


def sweep(path, needles, chunk=1 << 24):
    counts = dict((n, 0) for n, _ in needles)
    first = dict((n, []) for n, _ in needles)
    maxn = max(len(n) for n, _ in needles)
    # The tables overlap on purpose -- `rutee` and `dimlos` are each named in
    # two of them, because each table is meant to be readable on its own.  The
    # *scan* must still see every needle once: searching the same bytes twice
    # counts every hit twice and turns one chance survivor into two, which is
    # exactly the kind of number this tool exists to keep honest.
    needles = list(dict.fromkeys(n for n, _ in needles).keys())
    needles = [(n, "") for n in needles]
    f = open(path, 'rb')
    pos = 0
    prev = b''
    while True:
        buf = f.read(chunk)
        if not buf:
            break
        blob = prev + buf
        base = pos - len(prev)
        for n, _why in needles:
            i = 0
            while True:
                i = blob.find(n, i)
                if i < 0:
                    break
                # The carried-over tail exists so a needle can straddle the
                # seam.  A match that lies *entirely* inside it was already
                # found and counted in the previous chunk, so counting it again
                # inflates every short needle by however many seams it happens
                # to sit near -- which is how `rutee` came back as two hits at
                # one offset.  Require the match to reach into the new data.
                if i + len(n) <= len(prev):
                    i += 1
                    continue
                counts[n] += 1
                if len(first[n]) < 6:
                    first[n].append(base + i)
                i += 1
        prev = blob[-(maxn - 1):] if maxn > 1 else b''
        pos += len(buf)
    return counts, first, pos



# This build's own needles.  The tables above are inherited: CORPUS is the
# corpus-wide set and THISBUILD/PREQUEL were written for Tales of Xillia and
# Tales of Graces.  They are kept and run because on this package every one of
# them is a **negative control** -- a needle chosen for another build, over a
# medium where a four-byte needle is expected 0.07 times, is exactly the shape
# of evidence that says the sweep is not simply matching everything.  What
# follows is the set chosen for this build.
LUMINARIA = [
    (b'com.bandainamcoent.toluminaria_en', "this build's package name"),
    (b'jp.colopl', "the developer's Java package"),
    (b'Colopl', 'the developer, as a C# namespace'),
    (b'Prizm', "the developer's realtime networking framework"),
    (b'AppGuard', 'the protector named in the manifest'),
    (b'com.inca.security', 'the protector, by package'),
    (b'libil2cpp', 'the IL2CPP scripting backend'),
    (b'UnityPlayer', 'the engine'),
    (b'2019.4.16f1', 'the engine version the serialized files declare'),
    (b'global-metadata', 'the IL2CPP metadata, by name'),
    (b'FSB5', 'the FMOD sound bank the audio arrives in'),
    (b'commitHash', 'the build stamp shipped as a TextAsset'),
    (b'345d15660355fd91c6229d2badeabc225f14263c', 'the commit it names'),
    (b'aska0000', 'Crestoria 2020: the ASKA disc image'),
    (b'libEpic', "Crestoria 2020: the project's native library"),
    (b'jb.Aska', 'Crestoria 2020: the ASKA activity package'),
    (b'SLZ', 'Crestoria 2020: the compressed-resource wrapper'),
    (b'ISF', 'Crestoria 2020: the package format'),
    (b'AHA3', 'Crestoria 2020: the compiled shader cache'),
    (b'MRON', 'Crestoria 2020: the object notation'),
    (b'tales-of-epic', "Crestoria 2020: the project's Firebase name"),
    (b'TO12', 'the project tag, if the numbering continued past TO11'),
    (b'TO14', 'the project tag, if it skipped'),
    (b'Luminaria', 'the title, in any string at all'),
]


def table(title, needles, counts, first, size, context, path):
    print()
    print('=== %s' % title)
    print('%-20s %8s %10s  %s'
          % ('NEEDLE', 'HITS', 'EXPECTED', 'WHAT IT WOULD MEAN'))
    for n, why in needles:
        exp = size / float(256 ** min(len(n), 8))
        print('%-20s %8s %10s  %s'
              % (repr(n)[1:][:20], '{:,}'.format(counts[n]),
                 ('%.3g' % exp) if exp >= 0.001 else '<0.001', why))
        if context and counts[n] and first[n]:
            f = open(path, 'rb')
            for o in first[n]:
                f.seek(max(0, o - 16))
                b = f.read(48)
                print('        0x%010X  %s' % (o, b.hex()))


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    path = argv[1]
    context = '--context' in argv
    all_needles = (LUMINARIA + CORPUS + THISBUILD + PREQUEL + MIDDLEWARE
                   + PS3 + CAST)
    if '--tree' in argv:
        roots = argv[argv.index('--tree') + 1].split(',')
        counts, first, size = sweep_tree(roots, all_needles)
        context = False
    else:
        counts, first, size = sweep(path, all_needles)
    print('image %s, %s bytes' % (os.path.basename(path), '{:,}'.format(size)))
    rate = size / 4294967296.0
    print('a four-byte needle has a chance rate of %.4f on this medium.' % rate)
    if rate >= 1.0:
        print('A single hit is therefore not evidence and a zero is weak: the')
        print('denominators are inverted, in the direction section 7 describes')
        print('for a multi-gigabyte medium.')
    else:
        print('A single hit is therefore worth something and a zero is strong:')
        print('this medium is %.0f times smaller than the point where a'
              % (1.0 / rate if rate else 0))
        print('four-byte needle is expected once, so the inversion section 7')
        print('describes runs the *other* way here.  For scale: the Wii')
        print('partition of Tales of Graces is 4.29 GB and the PlayStation 3')
        print('disc of Tales of Xillia is 6.95 GB, where the same needle is')
        print('expected once or twice by chance alone.')
    print()
    print('One caveat the chance figure does not carry: it assumes uniform')
    print('random bytes.  Much of this medium is English-ish text -- symbol')
    print('tables, class names, shader source -- where short alphabetic')
    print('needles occur far above the uniform rate for reasons that have')
    print('nothing to do with what they were chosen to find.  Read any hit on')
    print('a lower-case four-letter needle as a substring until it is shown to')
    print('be a token.')
    table('the corpus', CORPUS, counts, first, size, context, path)
    table('this build: the needles chosen for it',
          LUMINARIA, counts, first, size, context, path)
    table('Tales of Xillia 2011, inherited -- here a set of negative controls',
          THISBUILD, counts, first, size, context, path)
    table('Tales of Graces 2009, inherited -- likewise',
          PREQUEL, counts, first, size, context, path)
    table('middleware', MIDDLEWARE, counts, first, size, context, path)
    table('what this platform supplies', PS3, counts, first, size,
          context, path)
    table('the cast of every title in the corpus', CAST, counts, first, size,
          context, path)


if __name__ == '__main__':
    main(sys.argv)
