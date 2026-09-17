# 08 — Tools, predictions and calibration: a coverage repair in one probe and one Unicode category, two readers taught to refuse, three readers written and two mended, rule 0 refusing twice, nine corrections to the pre-briefing, five hunches scored, and the term +6.50

*Measure: `python tools/toolsdiff.py ../pc-losthorizon-doc/tools --expect-differing 0` (notes/toolsdiff-before.txt on arrival, notes/toolsdiff.txt at the end), `python tools/coverage.py selftest` and the other thirteen selftests with `PYTHONIOENCODING` unset (notes/selftests.txt), `python tools/coverage.py tree --root TheWardrobe` before and after (notes/coverage-before.txt, notes/coverage.txt), `python tools/dirguard.py --survey --tools tools` (notes/dirguard-survey.txt), `python tools/rule0hook.py --report` (notes/rule0-report.txt), `python _work/calib3.py` (notes/calib3.txt).*

## The box, on arrival and at the end

614 Python files, `pc-losthorizon-doc/tools/` copied whole, 0 differing on
arrival. At the end 617: three written, five mended, 463 selftest checks
over 14 selftests with 0 failures and `PYTHONIOENCODING` unset; the
`dirguard` survey reads raised 214, refused 325, exit 0 77 (Lost Horizon:
214 / 322 / 77 — the three new readers refuse a directory or a file that is
not theirs).

## The repair, first: a coverage table wrong in two ways

`coverage.py tree` filed 484 files, 13.0941 % of the object, as opaque, and
three UTF-8 XML files as "plain text, cp437 with box-drawing art"
(notes/coverage-before.txt). Two defects:

1. **A format with no probe.** The RIFF probe asked for form `WAVE`; the 482
   FMOD Studio banks are RIFF form `FEV `, and fell through. The repair is
   `_fev_bank`: `RIFF`, form `FEV `, the RIFF length equal to the file's
   minus eight (a closure on the file, which is why the probe asks for the
   length — the twentieth that does), a walk over the top-level chunks the
   4,096-byte head reaches with every id printable and no chunk running past
   the RIFF length, and `FMT ` first. DECODED, because third-party readers of
   the container exist and `fevbank.py` reads it here; a RIFF `WAVE` still
   files as a WAVE. Seven checks: a hand-built 494-byte shell is decoded and
   named; the same with its length off by one, with a chunk past the end, or
   with `XMT ` first is opaque.
2. **A text probe that could not notice a space.** Five UTF-8 XML files
   carry U+00A0 NO-BREAK SPACE (French typography before `?` and `:`), and
   `'\xa0'.isprintable()` is False. `_codec_text` demanded every character
   printable or one of tab, CR, LF and U+3000, so the five failed UTF-8; two
   went opaque, three fell to `_cp437_art`, where `C2 A0` is a box-drawing
   byte and a letter. The byte-order-mark repair of pc-rpgmakermv-doc had
   been the same defect one code point over, fixed for that code point
   alone. The repair admits Unicode category **Zs** — the seventeen space
   separators — through one `_text_ok()` shared by the three text probes
   (`_codec_text`, `_cp932_text`, the UTF-16 probe), and eight checks assert
   both the cause (`'\xa0'.isprintable() is False`) and the repair (UTF-8
   with a no-break space is UTF-8, cp437 art still refuses it, U+FEFF
   mid-file and U+200B still refuse, U+3000 still admits, cp932 still
   closes).

After: opaque 0 files, 0 bytes; UTF-8 598 → 603; 482 banks decoded;
residue 0 (notes/coverage.txt). The sixth appearance of the class "a codec
probe that cannot fail", one object after the fifth.

## Two readers that died on a PNG, and one that would have lied

`unitytex17.py census` and `unitymovie.py census` both died with a
`struct.error` traceback from `unityfs.load` on `StreamingAssets\SaveIcon.png`.
Cause: `unityfs.is_serialized()` checked the version word at +8 and the
endianness byte at +16 — and a PNG's IHDR chunk length (`00 00 00 0D`) is
"version 13" with a zero high byte of the width at +16. `coverage.py`'s own
probe had always also required `fileSize == the file`; `is_serialized()` now
does the same (i64 at +24 from format 22), `load()` raises `NotSerialized`
— a `ValueError` naming the path and the reason — instead of letting
`struct` speak, and the two censuses catch it and count the file as
refused. Then `unitytex17.py` **refuses format 22 by name**, because a
version-17 layout applied to a version-22 body renders a plausible, wrong
picture; its census on this object now prints 105 refusals that point at
`unitytex22.py` and returns 1 (notes/unitytex17-refuses-22.txt). A
`selftest` was added to `unityfs.py` (14 checks: hand-built headers at 17
and 22, the PNG refused on disk and in memory, the metadata closure) and
four checks each to the two censuses.

While there, `unityfs.py info`'s `metadata size 1292 (parsed to 1340)` was
made to say what it means — `1292, after a 48-byte header = 1340; parsed to
1340 agrees` — and `verify` counts that closure on every file, 105 of 105
([03](03-the-serialized-files-and-the-sprites.md)).

## Three readers written

* **`unitytex22.py`** — `Texture2D` and `Sprite` at format 22, read from a
  hex dump of two textures and one sprite, closed twice on 1,161 of 1,161
  and once on 17,368 of 17,368; `census`, `list`, `sidecars`, `sprites`,
  `extract`, `render` (a sprite by name or path id, cut from its texture by
  `m_TextureRect`, decoded by `unitytex.py`'s DXT/RGBA decoders); selects
  by the SerializedFile's header, refuses format 17 and a PNG by name; 17
  checks, the last five on a hand-built format-22 file with one texture
  and one sprite rendered to a 2 × 2 PNG.
* **`wardrobexml.py`** — the studio's command language: `census` (trees,
  roots, tags, misspellings), `grammar` (verbs, guards, flags, speakers),
  `diff` (six trees against `ita` by skeleton), `lines`, `voices`; 16
  checks on a hand-built object file with a misspelt tag, a guard, a
  decimal comma, a `$`-tag and a bare `-skinny`. Its docstring writes the
  grammar down.
* **`fevbank.py`** — the FMOD Studio bank: the chunk tree to residue 0,
  the `SND ` chunk's FSB5 found and handed to `fsb5.Fsb5` as a slice, the
  padding closure and the `SNDH` closure; `tree`, `census`, `samples`;
  selects by `RIFF` + `FEV ` + length; 9 checks on a hand-built bank with
  two named samples, a shell, and two corruptions refused.

And **`pecensus.py`** mended: a managed PE whose timestamp has bit 31 set,
or lies after its own mtime, is a deterministic build hash and is counted
apart (`stamp_kind()`, `--selftest` with controls both ways); `impossible
mtimes : 136 of 161` became `0 of 25 datable` and `136 of 143 managed are
hashes` ([07](07-steam-the-two-generations-and-the-clocks.md)).

All three new readers take `dirguard.want_file` / `want_tree`, call
`nameguard.guard()` (the object's names have spaces), select by magic and
not by extension, and pass their selftests in a repository that does not
contain the object.

## Rule 0

`tools/rule0hook.py` was registered before the first command and proved
with a deliberate `python -c` (refused). Over the session:
**184 shell calls seen up to the commit, 182 allowed, 2 refused** — the deliberate inline
program, and one here-string (`<<< ""`) typed by reflex into a command
that did not need it. 0 reached the shell (notes/rule0-report.txt, the
paths masked by the hook itself). Every patch to an existing tool was
written as a JSON spec of exact `old`/`new` strings and applied by a
scratch `_work/applypatch.py` that writes a temp file and `os.replace()`s
it, refusing when a string is not found exactly once — which caught
`unityfs.py` being CRLF on the first try. **And the habit the prompt
named, named again:** `python -` with nothing on stdin was typed three
times, hung the shell three times, and was killed three times; it is not
a rule-0 violation (nothing goes through the shell) and the hook rightly
lets it pass, and it cost three minutes.

## Nine corrections to the pre-briefing

Every figure in `_pre/` was re-derived; these are the ones that changed.

1. **1,208 XML files** → **1,207** of the script; the 1,208th `.xml` is
   Mono's `etc\mono\mconfig\config.xml`. The pre-briefing's own sum,
   6 × 179 + 83 + 50, was 1,207 all along.
2. **"48 bytes of metadata the reader walks past the declared size — a
   version-22 field it does not know"** → the 48-byte header of format 22,
   counted once by the file and once by the reader, as the 20-byte header
   was on Monstrum. No field is unread; 105 of 105 close.
3. **"ONE FSB5 at +0 of the `SND ` chunk"** → at +0 on 4 of 420 and at even
   offsets up to +30 on the rest, 32-byte alignment; and the bank writes the
   offset down in `SNDH`, which the walker now checks.
4. **"60 banks with no sound"** → 62 with no `SND `: the 60 shells of 494
   bytes plus `master_bank.bank` and `master_bank.strings.bank`.
5. **"2,651 `text` commands per language"** → 3,185: the 2,651 are the
   unguarded ones, and 534 more sit behind a room-status guard (`1 text
   …`), which the first scan counted as verbs `0`, `1`, `2`.
6. **"a skeleton named `skinny` who is `me`"** → `-"me"` is the character
   the file belongs to (494 lines); Skinny is the line with no speaker
   (2,267).
7. **"33 repeats: Rewired in x86_64 and ARM64, the six-language copies of
   short XML scripts"** → 28 XML repeats and 5 of Mono's; the ARM64 DLLs
   hash differently from their x64 twins (machine 0xAA64).
8. **"the Steam update wrote every big file in two minutes"** → in 65
   seconds (17:02:28 … 17:03:34); the two minutes are the XML's 2024
   window.
9. **Hunch (b)'s "the 29 empty banks are cutscenes and those cutscenes are
   the MP4s"** → 24 of the 29 are cutscenes, and the films carry no audio
   track on 31 of 33: the voice was never in the MP4.

And the pre-briefing's list of verbs (fifteen) stood for 52; its
`achievement` ×18 is the default tree's count (47 in `ita`); its "two
Unity readers die on a PNG" was exactly right, as was "`cilmeta` rc 2 is
usage, not refusal".

## The five hunches, scored

**a.** *The 48 bytes are a new field per external or a trailing block;
once placed, the Texture2D at 22 is 17's layout plus a few fields, closed
twice on 1,161 of 1,161; the five `.resS` tile to the last byte; the first
sprite the owner sees is the skeleton.* — The 48 bytes: **wrong** (the
header). The layout, closed twice on 1,161: **right**. The sidecars to the
last byte: **right to within 229 bytes** of alignment slack, three of five
exactly. The first sprite: **right**, `skinny_attende`. Three of four.

**b.** *Every one of the 420 `SND ` chunks holds one FSB5 that closes, all
Vorbis at 44.1 or 48 kHz, one sample per voice line; English and Italian
minutes differ by under 10 %; the 29 empty banks are the same 29 in both
languages, and those cutscenes are the MP4s.* — 420 closing, Vorbis, 48
kHz: **right**. One sample per line: **right on 144 of 175 banks**.
Under 10 %: **wrong by 0.2 points** (10.2 %). The same 29: **right**;
cutscenes: 24 of 29; "are the MP4s": **wrong** — the films are silent.
About half.

**c.** *About twenty verbs with `-"speaker"` arguments; the six trees
identical except `ita`'s 38 fewer, which are `text` lines merged or split;
the interpreter one class with a method per verb.* — Twenty: **wrong**
(52). Identical but for the 38: **right** — the five translations are
identical line for line. The 38 as text: **wrong** (`wait` +19,
`expression` +15, `animation` +4 …; `text` 0). One class: **right**
(`Script`); a method per verb: **wrong** (one `Execute`, 52 literals). One
and a half of four.

**d.** *The update rewrote the binaries, the serialized files and the
banks and left the XML alone but for a handful; the beta-built file is a
small `sharedassets` nobody touched; the console stubs are the PS4/Xbox
port's, shipped because the project was one.* — The handful: **right**,
36 of 1,207. The beta file: **wrong** — Unity's own `unity default
resources`, not the studio's. The stubs: **right**, and the enum
`Platform { PS4, XboxOne, Switch, Steam, DrmFree }` and eighteen
controller screens say so from the code and the pictures. Two of three.

**e.** *The year is not in the bytes as a date; the cell says 2024 (XML) /
2026 (build) with both witnesses; the studio cell says CINIC Games and
nothing more.* — **Right**, with one witness the hunch did not name: the
studio's own build clock, `lib_burst_generated.dll` 2026-05-06, and a
version string `2.4.7`.

Two right, one three-quarters, one half, one one-and-a-half of four — and
the one the pictures hung on, **a**, was wrong about the bytes and right
about the picture.

## The renders, and what the owner said

Five renders were sent as they were made — the skeleton, the menu wall,
the PS4 control screen, the bedroom, the icon — with a question each
time. What came back is recorded here as it came: *no reply had arrived
by the time these documents were written*; the layout stands on its two
closures, and the owner's word, when it comes, is the third.

## P20, P21 and P22

Remain in declared pause, as on the last eleven objects: no family
prediction, no ancestor, no priced clause.

## The term

Expected, from the brief: a coverage repair, a layout read from a hex dump
with a first sprite sent, a grammar and a six-language diff, a bank walker
closing 420 FSB5, films by boxes, deterministic stamps said right. Found:
all of it, and four of the brief's framings overturned by the bytes (the
48 bytes, `me`, the 38, the silent films), a second closure on the banks
the brief did not know of (`SNDH`), the interpreter with 52 literals for
52 verbs, the studio's build clock in a native DLL, five platforms in an
enum. Nothing was locked and nothing had to be priced; the brief was right
about nearly everything it named. **+6.50**, the tenth positive term in a
row: real surplus, smaller than Lost Horizon's, where a lock had to be
walked around.

Appended by hand to `_work/calib3.py`, whose `--append` only prints, with
its comment line, for whoever comes next. The series now has **49 terms,
sum 31.07, mean 0.6341, 27 negative, 21 positive, 1 zero, last ten 76.50
for a mean of 7.6500, tail run 0**; the term ranks 17th of 49 by absolute
value. `calib3.py`'s eight claims were updated to these figures and print
`claims wrong : 0 of 8` (notes/calib3.txt); on arrival the 48-term file
printed the same.
