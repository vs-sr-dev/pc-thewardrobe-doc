#!/usr/bin/env python3
"""unitylog.py -- walk a Unity player's `output_log.txt` and, for MONSTRUM,
the game's own lines in it: one run per `Test Seed`, the monster and the deck
chosen, the three counters, the achievements saved.

A Unity 5 player writes `output_log.txt` beside its data: the engine banner
(`Initialize engine version:`), the graphics device, the assemblies loaded,
and then every `Debug.Log` the game makes, each followed by a stack trace
in parentheses.  Nothing about the file is specified, but it is plain text
and its shape is stable across the two copies this object carries (one of
2026-01-31 in `Monstrum_Data\\`, one of 2018-12-15 in the crash folder).

What MONSTRUM prints, in the order it prints it -- read off both logs, not
assumed:

    Test Seed: <n>            the level seed, once per run
    Level Test: <n>           the same number again
    Count data:               then three lines `Brute k`, `Hunter k`,
                              `Fiend k`, then `Inc: <one of them>` -- the
                              counter of the monster named in `Inc:` is one
                              higher on the next run's `Count data:`
    Achievements setup / Loading Achievements from <Local|Steam>
    Saved: KEY:True|False     sixteen keys, the first on the `Saved:` line
    <date> <time> AM|PM-----  a wall-clock stamp
    Count data: / LowerDeck k / UpperDeck k / Inc: <deck>   the start deck
    Crash!!!                  (the 2018 log only)

`runs` prints one row per `Test Seed`: seed, the counters before it, the
monster, the deck, how many achievement keys were saved True, the clock
stamps inside the run.  `summary` counts everything once.  Nothing here is a
regular expression over "any text": every field is a line prefix, and a line
that matches none is counted in `other` so that a format drift is a number.

PATHS.  The log names the install directory in every assembly line and the
crash folder's `error.log` names the account that ran the game.  `paths`
counts the distinct directories and prints them MASKED (`<dir>\\name`);
nothing here prints a directory whole.  Rule 6 of the collection, applied to
the object's bytes.

    python tools/unitylog.py summary FILE
    python tools/unitylog.py runs    FILE
    python tools/unitylog.py paths   FILE
    python tools/unitylog.py selftest

Standard library only.
"""

import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dirguard                                            # noqa: E402
import nameguard                                           # noqa: E402

nameguard.guard()

STAMP = re.compile(r'^(\d{1,2}/\d{1,2}/\d{4}) (\d{1,2}:\d{2}:\d{2} [AP]M)-+$')
COUNT = re.compile(r'^(Brute|Hunter|Fiend|LowerDeck|UpperDeck) (\d+)$')
# a drive-letter path up to a file extension the log prints (the install
# directory on this object has a space in its name, so `\S+` would cut it)
PATH = re.compile(r'[A-Za-z]:\\.*?\.(?:dll|exe|txt|ini|log|mdb)\b')


def mask(path):
    p = path.replace('/', '\\')
    return '<dir>\\' + p.rsplit('\\', 1)[1] if '\\' in p else p


class Log(object):
    def __init__(self, text):
        self.lines = text.splitlines()
        self.engine = None
        self.renderer = None
        self.runs = []
        self.other = 0
        self.stamps = []
        self.crash = 0
        self.exceptions = 0
        self.assemblies = 0
        self.saved_lines = 0
        run = None
        pending = {}
        for ln in self.lines:
            s = ln.rstrip('\r')
            if s.startswith('Initialize engine version: '):
                self.engine = s[len('Initialize engine version: '):]
            elif s.startswith('    Renderer: '):
                self.renderer = s[len('    Renderer: '):]
            elif s.startswith('Test Seed: '):
                run = dict(seed=int(s[11:]), counters={}, monster=None,
                           decks={}, deck=None, saved={}, stamps=[],
                           achievements_from=None)
                self.runs.append(run)
                pending = {}
            elif s.startswith('Level Test: '):
                pass
            elif s == 'Count data:':
                pending = {}
            elif COUNT.match(s):
                k, v = COUNT.match(s).groups()
                pending[k] = int(v)
                if run is not None:
                    (run['decks'] if k.endswith('Deck')
                     else run['counters'])[k] = int(v)
            elif s.startswith('Inc: '):
                what = s[5:]
                if run is not None:
                    if what.endswith('Deck'):
                        run['deck'] = what
                    else:
                        run['monster'] = what
            elif s.startswith('Loading Achievements from '):
                if run is not None:
                    run['achievements_from'] = s[len('Loading Achievements from '):]
            elif s.startswith('Saved: '):
                self.saved_lines += 1
                k, _, v = s[7:].partition(':')
                if run is not None:
                    run['saved'][k] = v
            elif re.match(r'^[A-Z_0-9]+:(True|False)$', s):
                k, _, v = s.partition(':')
                if run is not None and run['saved']:
                    run['saved'][k] = v
            elif STAMP.match(s):
                d, t = STAMP.match(s).groups()
                self.stamps.append((d, t))
                if run is not None:
                    run['stamps'].append((d, t))
            elif s.startswith('Platform assembly: ') or s.startswith('Loading '):
                self.assemblies += 1
            elif s.startswith('Crash!!!') or s.startswith('**** Crash!'):
                self.crash += 1
            elif 'Exception' in s and not s.startswith(' '):
                self.exceptions += 1
            else:
                self.other += 1

    def paths(self):
        c = collections.Counter()
        for ln in self.lines:
            for m in PATH.finditer(ln):
                d = m.group(0).replace('/', '\\').rsplit('\\', 1)[0]
                c[d] += 1
        return c


def load(path):
    dirguard.want_file(path, 'unitylog')
    with open(path, 'rb') as f:
        return Log(f.read().decode('utf-8', 'replace'))


def cmd_summary(args):
    lg = load(args.path)
    print('%s   %d lines' % (os.path.basename(args.path), len(lg.lines)))
    print('  engine             %s' % lg.engine)
    print('  renderer           %s' % lg.renderer)
    print('  assembly lines     %d' % lg.assemblies)
    print('  runs (Test Seed)   %d' % len(lg.runs))
    print('  clock stamps       %d   first %s   last %s'
          % (len(lg.stamps), ' '.join(lg.stamps[0]) if lg.stamps else '-',
             ' '.join(lg.stamps[-1]) if lg.stamps else '-'))
    print('  Saved: lines       %d' % lg.saved_lines)
    print('  crash markers      %d' % lg.crash)
    print('  exception lines    %d' % lg.exceptions)
    print('  other lines        %d' % lg.other)
    mons = collections.Counter(r['monster'] for r in lg.runs)
    decks = collections.Counter(r['deck'] for r in lg.runs)
    print('  monsters chosen    %s' % dict(mons))
    print('  decks chosen       %s' % dict(decks))
    esc = sum(1 for r in lg.runs
              for k, v in r['saved'].items() if k.startswith('ESCAPE_')
              and v == 'True')
    print('  ESCAPE_* saved True   %d' % esc)
    return 0


def cmd_runs(args):
    lg = load(args.path)
    print('%-3s %-11s %-14s %-8s %-10s %-6s %-6s %s'
          % ('#', 'SEED', 'BRUTE/HUNT/FI', 'MONSTER', 'DECK', 'SAVED',
             'TRUE', 'STAMPS'))
    for i, r in enumerate(lg.runs, 1):
        c = r['counters']
        print('%-3d %-11d %-14s %-8s %-10s %-6d %-6d %s'
              % (i, r['seed'],
                 '%s/%s/%s' % (c.get('Brute', '-'), c.get('Hunter', '-'),
                               c.get('Fiend', '-')),
                 r['monster'] or '-', r['deck'] or '-', len(r['saved']),
                 sum(1 for v in r['saved'].values() if v == 'True'),
                 ', '.join(t for _d, t in r['stamps'])))
    print()
    print('%d runs' % len(lg.runs))
    # the tally check: the counter of the chosen monster is one higher next run
    ok = bad = 0
    for a, b in zip(lg.runs, lg.runs[1:]):
        if not a['monster'] or not a['counters'] or not b['counters']:
            continue
        for k in ('Brute', 'Hunter', 'Fiend'):
            want = a['counters'].get(k, 0) + (1 if k == a['monster'] else 0)
            if b['counters'].get(k) == want:
                ok += 1
            else:
                bad += 1
    print('counter steps between consecutive runs: %d as the tally rule '
          'predicts, %d not' % (ok, bad))
    if lg.runs and lg.runs[0]['achievements_from']:
        print('achievements loaded from: %s'
              % ', '.join(sorted(set(r['achievements_from'] or '-'
                                     for r in lg.runs))))
    return 0


def cmd_paths(args):
    lg = load(args.path)
    c = lg.paths()
    print('%d path occurrences in %d distinct directories (masked):'
          % (sum(c.values()), len(c)))
    for d, n in c.most_common():
        print('  %5d  %s' % (n, mask(d + '\\x')[:-2]))
    return 0


SPECIMEN = '''Initialize engine version: 5.5.0f3 (38b4efef76f0)
GfxDevice: creating device client; threaded=1
Direct3D:
    Version:  Direct3D 11.0 [level 11.0]
    Renderer: Test GPU (ID=0x1)
Platform assembly: X:\\Some Dir\\Game_Data\\Managed\\UnityEngine.dll (this message is harmless)
Test Seed: 111
Level Test: 111
Count data:
Brute 2
Hunter 2
Fiend 2
Inc: Fiend
Achievements setup
Loading Achievements from Local
Saved: ESCAPE_HELICOPTER:False
ESCAPE_LIFERAFT:True
1/31/2026 5:39:24 PM--------------------------------------
Count data:
LowerDeck 3
UpperDeck 3
Inc: UpperDeck
Test Seed: 222
Count data:
Brute 2
Hunter 2
Fiend 3
Inc: Hunter
Saved: ESCAPE_HELICOPTER:False
Count data:
LowerDeck 3
UpperDeck 4
Inc: LowerDeck
NullReferenceException: Object reference not set
Crash!!!
'''


def cmd_selftest(_args):
    lg = Log(SPECIMEN)
    checks = [
        ('engine and renderer read', lg.engine == '5.5.0f3 (38b4efef76f0)'
         and lg.renderer == 'Test GPU (ID=0x1)', ''),
        ('two runs by Test Seed', len(lg.runs) == 2
         and [r['seed'] for r in lg.runs] == [111, 222], ''),
        ('run 1: counters 2/2/2, Fiend, UpperDeck',
         lg.runs[0]['counters'] == {'Brute': 2, 'Hunter': 2, 'Fiend': 2}
         and lg.runs[0]['monster'] == 'Fiend'
         and lg.runs[0]['deck'] == 'UpperDeck', str(lg.runs[0])),
        ('run 2: Fiend counter is one higher, Hunter, LowerDeck',
         lg.runs[1]['counters']['Fiend'] == 3
         and lg.runs[1]['monster'] == 'Hunter'
         and lg.runs[1]['deck'] == 'LowerDeck', ''),
        ('run 1 saved two keys, one True',
         lg.runs[0]['saved'] == {'ESCAPE_HELICOPTER': 'False',
                                 'ESCAPE_LIFERAFT': 'True'}, ''),
        ('the clock stamp is attached to run 1',
         lg.runs[0]['stamps'] == [('1/31/2026', '5:39:24 PM')]
         and lg.runs[1]['stamps'] == [], ''),
        ('achievements source is Local', lg.runs[0]['achievements_from']
         == 'Local', ''),
        ('one crash marker, one exception line, one assembly line',
         lg.crash == 1 and lg.exceptions == 1 and lg.assemblies == 1, ''),
        ('the path is counted and masked', lg.paths()
         == {'X:\\Some Dir\\Game_Data\\Managed': 1}
         and mask('X:\\Some Dir\\Game_Data\\Managed\\UnityEngine.dll')
         == '<dir>\\UnityEngine.dll', str(lg.paths())),
        ('an empty log has no runs and does not crash',
         Log('').runs == [] and Log('').engine is None, ''),
    ]
    w = max(len(c[0]) for c in checks)
    bad = 0
    for label, ok, note in checks:
        print('  %-*s  %s  %s' % (w, label, 'ok  ' if ok else 'FAIL', note[:60]))
        bad += not ok
    print()
    print('%d checks, %d failures' % (len(checks), bad))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd')
    for n in ('summary', 'runs', 'paths'):
        sub.add_parser(n).add_argument('path')
    sub.add_parser('selftest')
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 2
    return {'summary': cmd_summary, 'runs': cmd_runs, 'paths': cmd_paths,
            'selftest': cmd_selftest}[args.cmd](args)


if __name__ == '__main__':
    sys.exit(main())
