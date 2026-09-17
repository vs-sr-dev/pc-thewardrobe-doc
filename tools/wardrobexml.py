#!/usr/bin/env python3
"""wardrobexml.py -- the XML script of THE WARDROBE (CINIC Games, Unity 6),
read as data: six language trees, a `default\\` tree of new-game state, an
`areas\\` tree of walk polygons, and inside them a command language of the
studio's own, one `<command>` per line, in the clear.

WHAT THE FILES ARE (StreamingAssets\\XML\\, 1,208 files on the object)
--------------------------------------------------------------------
    areas\\NAME.xml            <area bitmask X Y b-scale f-scale> + <angle x y>: the
                              walkable polygon of a room, and its foot scale
    default\\skinny.xml        the new game: <skinny location X Y pose ...> and
                              seven <location name open> map entries
    default\\inventory.xml     <inventory gs="False"/>: empty
    default\\settings.xml      <setting>: language, text visibility, OST/SFX/VO
    default\\locations\\*.xml  the initial state of every room (47)
    default\\dialogs\\*.xml    the initial state of every dialogue (33)
    LANG\\default.xml          <default>: the stock refusals (`pick-n`, `pick-e`, ...)
    LANG\\objects\\*.xml       <object name>: description, inventory combinations,
                              per-location <hotspot ID> scripts
    LANG\\locations\\*.xml     <location>: <script> by room status, <indipendent>
                              loops, <entry>, <scene bitmap ...>, <hotspots>,
                              <character>, ...
    LANG\\dialogs\\*.xml       <dialog internal>: <voice ID=ITALIAN name=TRANSLATION>
                              + <script>: the dialogue options
    LANG\\scripts\\cutscenes   <script> / <intro>: subtitles over a movie, timed
    LANG\\scripts\\buffers     <buffer>: the telephone (<script name="666">) and
                              the time machine (`load "viaggio_tempo_1863"`)
    LANG\\scripts\\documents   <document>: a letter, twice
    LANG\\scripts\\transfers   <script>: two room transitions

THE COMMAND LANGUAGE, as read from the bytes
--------------------------------------------
    <command>[GUARD] VERB [TARGET] [FLAGS...] [ARGS...] [N] [$K]</command>

    GUARD   a room status the line runs under: `0`, `1`, `2`, a set `0-1-2`
            -- inside <location><script>/<indipendent> and the hotspots of
            a room. (`default` is NOT a guard: it is the verb that speaks a
            stock refusal from LANG\\default.xml -- `default -talk`,
            `default e -pick` for a sarcastic one, `default n -pick` for a
            neutral one.)
    VERB    `text`, `wait`, `expression`, `pose`, `sound`, `hide`, `internal`,
            `animation`, `show`, `bitmap`, `if`/`fie`/`fi`, `throw`, `pick`,
            `goto`, `status`, `pause`, `resume`, `screen`, `stop`, `lookat`,
            `dialog`, `achievement`, `load`, `nolook`, `cutscene`, `move`,
            `area`, `ost`, `buffer`, `inventory`, `blackscreen`, ... (the
            `grammar` mode counts them all)
    TARGET  `-"name"`, `+"name"`, `>"name"` or bare `-skinny`, `-ost`: who or
            what the verb acts on. For `text`: the SPEAKER. A `text` with no
            speaker is SKINNY, the player; `-"me"` is the character the file
            belongs to (the object's owner, the dialogue's partner); any other
            name is that character.
    FLAGS   `-c=colour`, `-w=width`, `-o=x,y`, `-f=...`, `-s=speed`, `-l`,
            `-a`, `-x`, `-g`, `-i`, `-fo=ms`, `-=a=anchor`
    ARGS    "quoted strings", (x,y) points, numbers with a decimal COMMA (`0,5`)
    N       a trailing integer on `text`: the line's number inside its hotspot,
            which the voice banks index (fevbank.py joins them)
    $K      a trailing `$64`-style tag: counted, not interpreted

The Italian line is the KEY: every language's <voice ID="..."> carries the
Italian text and name="..." the translation, so a six-language diff is a
count per file (`diff`). Verb counts differ between `ita` and the other
five (10,636 vs 10,674 commands): `diff` says in which files and which verbs.

Nothing is executed. The interpreter of these verbs is in
`Assembly-CSharp.dll` and `cilmeta.py owners --grep` finds it by name.

    python tools/wardrobexml.py census   XMLROOT           -- every tree: files, roots, tags, commands, misspelt tags
    python tools/wardrobexml.py grammar  XMLROOT/LANG      -- verbs, guards, flags, speakers, with counts
    python tools/wardrobexml.py diff     XMLROOT           -- the six trees against ita, file by file
    python tools/wardrobexml.py lines    XMLROOT/LANG      -- every text line: file, container, speaker, N, text (TSV)
    python tools/wardrobexml.py voices   XMLROOT           -- the <voice ID> keys across the six trees
    python tools/wardrobexml.py selftest

Standard library only.
"""

import argparse
import collections
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                            # noqa: E402
import nameguard                                           # noqa: E402

LANGS = ('deu', 'eng', 'fra', 'ita', 'rus', 'spa')
TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|\([^)]*\)|\S+')
GUARD = re.compile(r'^\d+(-\d+)*$')
FLAG = re.compile(r'^-(=?[a-zA-Z]+)(=.*)?$')
TARGET = re.compile(r'^([-+>#])"([^"]*)"$')
# a bare word after `-` is a flag (`-talk`, `-pick`, `-l`, `-nc`) unless it
# names one of the two things the script addresses without quotes:
BARE_TARGETS = ('skinny', 'ost')
TAG = re.compile(r'<([A-Za-z][A-Za-z0-9_-]*)')


class Command(object):
    """One <command> line, tokenised."""

    def __init__(self, text):
        self.raw = text
        toks = TOKEN.findall(text.strip())
        self.guard = None
        if len(toks) > 1 and GUARD.match(toks[0]):
            self.guard = toks.pop(0)
        self.verb = toks[0] if toks else ''
        self.target = None
        self.flags = []
        self.args = []
        self.number = None
        self.dollar = None
        last = len(toks) - 1
        for i, t in enumerate(toks[1:], 1):
            m = TARGET.match(t)
            if m and self.target is None:
                self.target = (m.group(1), m.group(2))
                continue
            if t[:1] == '-' and t[1:] in BARE_TARGETS and self.target is None:
                self.target = ('-', t[1:])
                continue
            if FLAG.match(t):
                self.flags.append(FLAG.match(t).group(1))
                continue
            if re.match(r'^\$\d+$', t):
                self.dollar = t
                continue
            if i == last and re.match(r'^\d+$', t):
                self.number = int(t)      # only a TRAILING integer is the number
                continue
            self.args.append(t)

    @property
    def speaker(self):
        """For `text`: who speaks. None = Skinny (unlabelled)."""
        if self.target and self.target[0] == '-':
            return self.target[1]
        return None

    @property
    def quoted(self):
        return [a[1:-1] for a in self.args if a.startswith('"') and a.endswith('"')]


def read_xml(path):
    """(ElementTree root or None, text, misspelt/odd tags). The text is
    decoded as UTF-8 with replacement so a count never dies on a byte."""
    raw = open(path, 'rb').read()
    text = raw.decode('utf-8', 'replace')
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        root = None
    return root, text


def files_under(root):
    out = []
    for dp, _dn, fn in os.walk(root):
        for f in sorted(fn):
            if f.lower().endswith('.xml'):
                out.append(os.path.join(dp, f))
    return sorted(out)


def commands_in(text):
    """Every <command>...</command> body, in file order, by regex -- so a
    misspelt tag is NOT a command, exactly as an XML parser would not find
    it; `census` counts the misspelt ones separately."""
    return [Command(_unescape(c)) for c in re.findall(r'<command>(.*?)</command>', text, re.S)]


def _unescape(s):
    return (s.replace('&gt;', '>').replace('&lt;', '<').replace('&quot;', '"')
            .replace('&apos;', "'").replace('&amp;', '&'))


def tree_of(xmlroot):
    """The subtrees: areas, default, and the six languages, each a list of
    files."""
    trees = collections.OrderedDict()
    for nm in sorted(os.listdir(xmlroot)):
        p = os.path.join(xmlroot, nm)
        if os.path.isdir(p):
            trees[nm] = files_under(p)
    return trees


# ------------------------------------------------------------------ census

KNOWN_TAGS = None


def cmd_census(args):
    dirguard.want_tree(args.path, 'wardrobexml')
    trees = tree_of(args.path)
    if not trees:
        sys.exit('wardrobexml: no subdirectory under %s' % args.path)
    all_tags = collections.Counter()
    per_tree = {}
    for tname, files in trees.items():
        roots = collections.Counter()
        tags = collections.Counter()
        ncmd = ntext = nbytes = 0
        bad = []
        guards = 0
        for f in files:
            root, text = read_xml(f)
            nbytes += os.path.getsize(f)
            if root is None:
                bad.append(f)
                m = re.match(r'\s*(?:<\?xml[^>]*>\s*)?<([A-Za-z_-]+)', text)
                roots[m.group(1) if m else '?'] += 1
            else:
                roots[root.tag] += 1
            for t in TAG.findall(text):
                tags[t] += 1
                all_tags[t] += 1
            cs = commands_in(text)
            ncmd += len(cs)
            ntext += sum(1 for c in cs if c.verb == 'text')
            guards += sum(1 for c in cs if c.guard is not None)
        per_tree[tname] = (files, roots, tags, ncmd, ntext, nbytes, bad, guards)
    print('%-8s %5s %9s %-46s %8s %6s %6s %s' % ('TREE', 'FILES', 'BYTES', 'ROOTS', 'COMMANDS', 'TEXT', 'GUARD', 'NOT WELL-FORMED'))
    for tname, (files, roots, tags, ncmd, ntext, nbytes, bad, guards) in per_tree.items():
        print('%-8s %5d %9d %-46s %8d %6d %6d %d' % (tname, len(files), nbytes,
              ' '.join('%s %d' % kv for kv in roots.most_common(6))[:46], ncmd, ntext, guards, len(bad)))
    print()
    # tags that occur in one tree only, or fewer than 4 times anywhere: the misspellings
    print('tags seen %d distinct; the rare ones (<= 12 occurrences over every tree: twice per '
          'language) with their files -- the misspellings live here:' % len(all_tags))
    for t, c in sorted(all_tags.items(), key=lambda kv: (kv[1], kv[0])):
        if c > 12:
            continue
        where = []
        for tname, (files, *_r) in per_tree.items():
            for f in files:
                if '<%s' % t in open(f, 'rb').read().decode('utf-8', 'replace'):
                    where.append(os.path.relpath(f, args.path).replace(os.sep, '/'))
        print('  <%s> x%d  %s' % (t, c, ', '.join(where[:6])))
    print()
    print('tags, all trees:')
    for t, c in all_tags.most_common():
        print('  %-14s %6d' % (t, c))
    tot_files = sum(len(v[0]) for v in per_tree.values())
    tot_bytes = sum(v[5] for v in per_tree.values())
    print()
    print('%d files, %d bytes, in %d trees' % (tot_files, tot_bytes, len(per_tree)))
    return 0


# ------------------------------------------------------------------ grammar

def cmd_grammar(args):
    dirguard.want_tree(args.path, 'wardrobexml')
    files = files_under(args.path)
    if not files:
        sys.exit('wardrobexml: no .xml under %s' % args.path)
    verbs = collections.Counter()
    guards = collections.Counter()
    flags = collections.defaultdict(collections.Counter)
    targets = collections.defaultdict(collections.Counter)
    speakers = collections.Counter()
    numbered = dollars = 0
    n = 0
    examples = {}
    for f in files:
        _root, text = read_xml(f)
        for c in commands_in(text):
            n += 1
            verbs[c.verb] += 1
            if c.guard is not None:
                guards[c.guard] += 1
            for fl in c.flags:
                flags[c.verb][fl] += 1
            if c.target:
                targets[c.verb][c.target[0]] += 1
            if c.verb == 'text':
                speakers[c.speaker or '(unlabelled = Skinny)'] += 1
                numbered += c.number is not None
                dollars += c.dollar is not None
            if c.verb not in examples:
                examples[c.verb] = c.raw.strip()[:70]
    print('%d commands in %d files under %s' % (n, len(files), os.path.basename(args.path)))
    print()
    print('%-14s %6s  %-24s %-12s  %s' % ('VERB', 'COUNT', 'FLAGS', 'TARGET SIGN', 'EXAMPLE'))
    for v, c in verbs.most_common():
        fl = ' '.join('%s:%d' % kv for kv in flags[v].most_common(4))
        tg = ' '.join('%s:%d' % kv for kv in targets[v].most_common(3))
        print('%-14s %6d  %-24s %-12s  %s' % (v[:14], c, fl[:24], tg[:12], examples[v]))
    print()
    print('%d distinct verbs' % len(verbs))
    print()
    print('%-14s %6s' % ('GUARD', 'COUNT'))
    for g, c in guards.most_common():
        print('%-14s %6d' % (g, c))
    print('%d guarded commands' % sum(guards.values()))
    print()
    print('%-34s %6s   (text lines by speaker)' % ('SPEAKER', 'LINES'))
    for s, c in speakers.most_common():
        print('%-34s %6d' % (s[:34], c))
    print('%d distinct speakers; %d text lines carry a trailing number, %d a $-tag'
          % (len(speakers), numbered, dollars))
    return 0


# ------------------------------------------------------------------ diff

def skeleton(text):
    """The command sequence with the language taken out: guard, verb,
    target sign, flags, number -- not the quoted strings."""
    out = []
    for c in commands_in(text):
        out.append((c.guard, c.verb, c.target[0] if c.target else None,
                    tuple(c.flags), c.number))
    return out


def cmd_diff(args):
    dirguard.want_tree(args.path, 'wardrobexml')
    trees = tree_of(args.path)
    langs = [l for l in LANGS if l in trees]
    if 'ita' not in langs or len(langs) < 2:
        sys.exit('wardrobexml: diff wants ita and at least one other language tree under %s' % args.path)
    base = {os.path.relpath(f, os.path.join(args.path, 'ita')).replace(os.sep, '/'): f
            for f in trees['ita']}
    print('the key tree is ita (%d files); every other tree against it, file by file' % len(base))
    print()
    print('%-5s %5s %8s %8s %8s %-40s' % ('LANG', 'FILES', 'SAME', 'DIFFER', 'MISSING', 'VERB DELTA vs ita (lang - ita)'))
    detail = []
    for lang in langs:
        if lang == 'ita':
            continue
        mine = {os.path.relpath(f, os.path.join(args.path, lang)).replace(os.sep, '/'): f
                for f in trees[lang]}
        same = differ = 0
        missing = [k for k in base if k not in mine] + [k for k in mine if k not in base]
        delta = collections.Counter()
        for rel, fi in base.items():
            if rel not in mine:
                continue
            si = skeleton(read_xml(fi)[1])
            so = skeleton(read_xml(mine[rel])[1])
            if si == so:
                same += 1
                continue
            differ += 1
            vi = collections.Counter(x[1] for x in si)
            vo = collections.Counter(x[1] for x in so)
            d = collections.Counter()
            for v in set(vi) | set(vo):
                if vo[v] != vi[v]:
                    d[v] = vo[v] - vi[v]
            delta.update(d)
            detail.append((lang, rel, len(si), len(so), dict(d)))
        ds = ' '.join('%s%+d' % kv for kv in sorted(delta.items()))
        print('%-5s %5d %8d %8d %8d %-40s' % (lang, len(mine), same, differ, len(missing), ds))
    print()
    print('the files that differ (command count ita -> lang, verb delta):')
    for lang, rel, ni, no, d in detail:
        print('  %-4s %-44s %5d -> %5d  %s' % (lang, rel[:44], ni, no,
              ' '.join('%s%+d' % kv for kv in sorted(d.items()))))
    # the <voice ID> keys: are they the same set in every tree?
    print()
    ids = {}
    for lang in langs:
        s = collections.Counter()
        for f in trees[lang]:
            for m in re.findall(r'<voice ID="([^"]*)"', read_xml(f)[1]):
                s[m] += 1
        ids[lang] = s
    ref = ids['ita']
    for lang in langs:
        print('  %s: %d <voice ID> (%d distinct); %d not in ita\'s set, %d of ita\'s missing'
              % (lang, sum(ids[lang].values()), len(ids[lang]),
                 len(set(ids[lang]) - set(ref)), len(set(ref) - set(ids[lang]))))
    return 0


# ------------------------------------------------------------------ lines

def container_of(text):
    """For every <command> position in `text`, the nearest enclosing
    container attribute: hotspot ID, voice ID, script name, or the tag."""
    marks = []
    for m in re.finditer(r'<(hotspot|voice|script|description|default|indipendent|intro|document|object|item|use|pick|look|talk|act|action|go|goto)\b([^>]*)>', text):
        attrs = dict(re.findall(r'([A-Za-z_-]+)="([^"]*)"', m.group(2)))
        label = attrs.get('ID') or attrs.get('name') or ''
        marks.append((m.start(), m.group(1), label))
    return marks


def cmd_lines(args):
    dirguard.want_tree(args.path, 'wardrobexml')
    files = files_under(args.path)
    if not files:
        sys.exit('wardrobexml: no .xml under %s' % args.path)
    print('\t'.join(('file', 'container', 'label', 'speaker', 'n', 'text')))
    n = 0
    for f in files:
        rel = os.path.relpath(f, args.path).replace(os.sep, '/')
        _root, text = read_xml(f)
        marks = container_of(text)
        for m in re.finditer(r'<command>(.*?)</command>', text, re.S):
            c = Command(_unescape(m.group(1)))
            if c.verb != 'text':
                continue
            cont = ('', '')
            for pos, tag, label in marks:
                if pos < m.start():
                    cont = (tag, label)
            q = c.quoted
            n += 1
            print('\t'.join((rel, cont[0], cont[1], c.speaker or '',
                             '' if c.number is None else str(c.number),
                             (q[-1] if q else '').replace('\t', ' '))))
    print('# %d text lines' % n, file=sys.stderr)
    return 0


def cmd_voices(args):
    dirguard.want_tree(args.path, 'wardrobexml')
    trees = tree_of(args.path)
    langs = [l for l in LANGS if l in trees]
    if not langs:
        sys.exit('wardrobexml: no language tree under %s' % args.path)
    table = collections.defaultdict(dict)
    for lang in langs:
        for f in trees[lang]:
            rel = os.path.relpath(f, os.path.join(args.path, lang)).replace(os.sep, '/')
            for k, nm in re.findall(r'<voice ID="([^"]*)"[^>]*name="([^"]*)"', read_xml(f)[1]):
                table[(rel, k)][lang] = _unescape(nm)
    print('\t'.join(['file', 'ID (the Italian key)'] + langs))
    for (rel, k), d in sorted(table.items()):
        print('\t'.join([rel, _unescape(k)] + [d.get(l, '') for l in langs]))
    print('# %d (file, ID) pairs over %d trees' % (len(table), len(langs)), file=sys.stderr)
    return 0


# ------------------------------------------------------------------ selftest

SAMPLE = '''<object name="birra">
  <description>
    <command>text "BirraH!"</command>
    <comomand>wait 0,5</comomand>
  </description>
  <location name="baracca">
    <hotspot ID="cocktail">
      <command>if not internal -"cocktail" 0</command>
      <command>text "Nope." 1</command>
      <command>fie</command>
      <command>animation -skinny 00 -o=-12,56 -f=7,2,14 -s=90 "skinny_versa_birra1"</command>
      <command>text -"custode" -c=lblue "Una bevuta non si rifiuta mai!" 3</command>
      <command>text "Peggio che mischiare birra e coca." $64</command>
      <command>1 status &gt;"spiaggia" 3</command>
      <command>0-1-2 wait 0,5</command>
      <command>fi</command>
    </hotspot>
  </location>
</object>
'''


def cmd_selftest(_args):
    checks = []
    cs = commands_in(SAMPLE)
    checks.append(('a misspelt <comomand> is not a command: 10 of 11 lines count',
                   len(cs) == 10, str(len(cs))))
    c = Command('text -"custode" -c=lblue "Una bevuta non si rifiuta mai!" 3')
    checks.append(('speaker, colour flag, quoted text and trailing number are read',
                   c.verb == 'text' and c.speaker == 'custode' and c.flags == ['c']
                   and c.quoted == ['Una bevuta non si rifiuta mai!'] and c.number == 3,
                   '%r %r %r %r' % (c.speaker, c.flags, c.quoted, c.number)))
    c = Command('text "Nope." 1')
    checks.append(('an unlabelled text has no speaker (Skinny) and number 1',
                   c.speaker is None and c.number == 1, ''))
    c = Command('animation -skinny 00 -o=-12,56 -f=7,2,14 -s=90 "skinny_versa_birra1"')
    checks.append(('a bare -skinny is a target, -o= -f= -s= are flags, 00 is an argument',
                   c.target == ('-', 'skinny') and c.flags == ['o', 'f', 's']
                   and c.args[0] == '00' and c.quoted == ['skinny_versa_birra1'],
                   '%r %r %r' % (c.target, c.flags, c.args)))
    c = Command('1 status >"spiaggia" 3')
    checks.append(('a leading digit is a guard, >"x" a target with sign >',
                   c.guard == '1' and c.verb == 'status' and c.target == ('>', 'spiaggia')
                   and c.number == 3, '%r %r %r' % (c.guard, c.verb, c.target)))
    c = Command('0-1-2 wait 0,5')
    checks.append(('a guard set 0-1-2 is a guard; 0,5 (decimal comma) is an argument',
                   c.guard == '0-1-2' and c.verb == 'wait' and c.args == ['0,5'], ''))
    c = Command('text "Peggio che mischiare birra e coca." $64')
    checks.append(('a trailing $64 is the dollar tag, not a number',
                   c.dollar == '$64' and c.number is None, ''))
    c = Command('fie')
    checks.append(('a bare verb has no guard: `fie` is not a guard', c.guard is None and c.verb == 'fie', ''))
    c = Command('default e -pick')
    checks.append(('`default` is a verb, not a guard: `default e -pick`',
                   c.guard is None and c.verb == 'default' and c.args == ['e']
                   and c.flags == ['pick'], '%r %r %r' % (c.guard, c.verb, c.flags)))
    c = Command('internal #"diavoletto" 1')
    checks.append(('#"x" is a target with sign #', c.target == ('#', 'diavoletto') and c.number == 1, ''))
    c = Command('if not internal -"cocktail" 0')
    checks.append(('`0` at the END is a number, not a guard', c.guard is None and c.number == 0, ''))
    c = Command('sound -l "loop_perdita"')
    checks.append(('-l is a flag, not a target', c.flags == ['l'] and c.target is None, ''))
    sk = skeleton(SAMPLE)
    sk2 = skeleton(SAMPLE.replace('Nope.', 'Non.').replace('Una bevuta', 'A drink'))
    checks.append(('the skeleton ignores the quoted strings, so a translation has the same one',
                   sk == sk2 and len(sk) == 10, str(len(sk))))
    sk3 = skeleton(SAMPLE.replace('<command>fie</command>\n', ''))
    checks.append(('a dropped command changes the skeleton', sk3 != sk and len(sk3) == 9, ''))
    ok_tags = TAG.findall(SAMPLE)
    checks.append(('the misspelt tag is found by the tag scan', 'comomand' in ok_tags, ''))
    marks = container_of(SAMPLE)
    checks.append(('containers are found with their labels',
                   ('hotspot', 'cocktail') in [(t, l) for _p, t, l in marks], str(marks)))
    width = max(len(c[0]) for c in checks)
    bad = 0
    for label, ok, note in checks:
        print('  %-*s  %s  %s' % (width, label, 'ok  ' if ok else 'FAIL', note))
        bad += not ok
    print()
    print('%d checks, %d failures' % (len(checks), bad))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    for nm in ('census', 'grammar', 'diff', 'lines', 'voices'):
        sub.add_parser(nm).add_argument('path')
    sub.add_parser('selftest')
    args = ap.parse_args()
    nameguard.guard()
    return {'census': cmd_census, 'grammar': cmd_grammar, 'diff': cmd_diff,
            'lines': cmd_lines, 'voices': cmd_voices,
            'selftest': cmd_selftest}[args.cmd](args)


if __name__ == '__main__':
    sys.exit(main())
