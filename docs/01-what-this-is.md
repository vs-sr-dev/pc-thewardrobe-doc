# 01 — What this is: a 3.5 GB Steam install of a Unity 6 point-and-click by an Italian studio, whose script sits in 1,207 XML files in six languages with the Italian line as the key, whose pictures are 17,368 sprites at a format version this box had never read, and whose voices are 400 FMOD Studio banks in two languages

*Measure: `python tools/treecensus.py TheWardrobe` (notes/treecensus.txt), `python tools/hashall.py TheWardrobe` (notes/hash-repeats.txt for the tail), `python tools/coverage.py tree --root TheWardrobe` (notes/coverage.txt; notes/coverage-before.txt is the same command before the repair in [08](08-tools-predictions-and-calibration.md)), `python tools/unityfs.py census "TheWardrobe/The Wardrobe_Data"` (notes/unityfs-census.txt), `python tools/wardrobexml.py census …/XML` (notes/xml-census.txt), `python tools/fevbank.py census …/StreamingAssets` (notes/fevbank-census.txt).*

## The object

One directory, `TheWardrobe\`, copied whole from the owner's Steam library with
its modification times kept (`robocopy /E /COPY:DAT /DCOPY:T`). Where it sat on
the drive it came from is not written here.

    TheWardrobe\    2,020 files    83 directories    3,494,280,269 bytes    1,987 distinct SHA-1

Thirty-three files repeat another's bytes: 28 are XML files identical across
languages (three files the same in all six trees, seven dialogues identical
between `default\` and `eng\`, and `lettera` = `lettera_struccata` six times),
5 are Mono's own configuration files repeated per profile. The two ARM64
Rewired plugins do **not** repeat their x86_64 twins — different machine
word, different bytes (notes/hash-repeats.txt). Nothing was run, installed or
emulated; every figure here was read out of bytes as data, with a public
format where one exists and a closure where none does.

The owner's framing was: *The Wardrobe*, "a point-and-click, the work of an
Italian studio", from Steam — and nothing else. The object says the rest
itself, in two lines of Unity's `app.info` and again in `PlayerSettings`:

    CINIC Games
    The Wardrobe

and in 1,207 XML files under `StreamingAssets\XML\` where every dialogue
option of every language carries the Italian line as its key:

    <voice ID="Piante, semi, bacche e fiori." name="Plants, seeds, berries and flowers.">
      <script>
        <command>text -"me" "Though the plant kingdom can seem harmless, ..."</command>

Studio, title, master language: three bytes of the object. The engine is
Unity `6000.3.6f1` (104 of 105 serialized files; one, Unity's own
`Resources/unity default resources`, was built by the beta `6000.3.0b4`),
serialization format 22, x64, Mono. The year is discussed in
[07](07-steam-the-two-generations-and-the-clocks.md): the object carries no
release date, only clocks.

## The split, by magic

`coverage.py` classifies every file by its first 4,096 bytes and its length,
never by its name. Before this session's repair it filed 484 files, 13.09 %
of the bytes, as opaque; after it, none ([08](08-tools-predictions-and-calibration.md)):

| bucket | files | bytes | share | what |
|---|---:|---:|---:|---|
| derived | 5 | 2,466,018,272 | 70.5730 % | five `.resS` streamed sidecars, named by the `m_StreamData` records of their sibling serialized files — 960 records reach 2,466,018,043 of those bytes; the 229 not reached are alignment slack in 27 places, none longer than 13 bytes ([03](03-the-serialized-files-and-the-sprites.md)) |
| decoded | 482 | 457,534,468 | 13.0938 % | FMOD Studio banks, `RIFF` form `FEV `, walked to residue 0 on 482 of 482; 420 hold an FSB5 that closes twice ([05](05-the-sound.md)) |
| decoded | 105 | 243,781,032 | 6.9766 % | Unity SerializedFiles at format 22, 28,593 objects, 105 of 105 closing on their own length and on their metadata ([03](03-the-serialized-files-and-the-sprites.md)) |
| specified | 33 | 222,398,304 | 6.3646 % | MPEG-4, box trees closing at residue 0 on 33 of 33 ([06](06-the-films-and-the-programs.md)) |
| specified | 161 | 98,067,688 | 2.8065 % | PE: 143 managed, 18 native ([06](06-the-films-and-the-programs.md)) |
| specified | 1,234 | 6,480,505 | 0.1855 % | plain text: 628 ASCII, 603 UTF-8 (the 1,207 XML files of the script among them), 3 PNG |
| opaque | 0 | 0 | 0 % | |
| **sum** | **2,020** | **3,494,280,269** | **100.0000 %** | residue 0 |

The three "plain text" rows are added by hand from notes/coverage.txt:
628 + 603 + 3 = 1,234 files, 3,990,357 + 2,313,410 + 176,738 = 6,480,505 bytes.

Read as a game rather than as buckets: **70.57 % is pixels** (the sidecars
the sprites slice), **13.09 % is sound** (482 banks), **6.98 % is the
serialized object graph** (sprites, textures, scripts), **6.36 % is 33
films**, **2.81 % is programs**, and **0.16 % — 5,421,040 bytes in 1,207 XML
files — is the game in writing**, which is the part that reads.

## What it says about itself, in the clear

* **The script.** `StreamingAssets\XML\`: `areas\` 50 walk polygons,
  `default\` 83 files of new-game state, and six language trees `deu eng fra
  ita rus spa` of 179 files each — 85 objects, 47 rooms, 33 dialogues, 6
  scripts, 3 intros, 2 buffers. Inside: a command language of the studio's
  own, `<command>[status] verb [-"target"] [flags] "text" [n]</command>`,
  **52 verbs**, 10,636 commands in Italian and 10,674 in each other
  language, **3,185 `text` lines per language**, 35 speakers, with the
  Italian line as the key of every dialogue option in every language
  ([04](04-the-text-of-the-game.md)). The room files are named in Italian,
  with spaces (`bicchiere di birra.xml`, `bambola voodoo funzionante.xml`).
* **The pictures.** 17,368 `Sprite` objects over 1,161 `Texture2D` in 6 of
  the 105 serialized files, all at format 22, read from a hex dump and closed
  on 1,161 of 1,161 textures (twice) and 17,368 of 17,368 sprites; **99
  sprites are 1,920 × 1,080 backgrounds**, 2,066 are frames of the skeleton
  `skinny_*`; the first sprite rendered was the skeleton, it went to the
  owner at once, and the owner confirmed it and four more at sight
  ([03](03-the-serialized-files-and-the-sprites.md)).
* **The voices.** 482 FMOD Studio banks: 200 `_vo_ita`, 200 `_vo_eng`, 79
  `_sfx`, `ost`, `master_bank`, `master_bank.strings`. Two spoken languages
  against six written. 6,385 Vorbis samples at 48 kHz: **Italian 2,991
  samples, 148.3 minutes; English 2,974, 134.6 minutes**; 62 banks carry no
  sound, the same 29 per voice language ([05](05-the-sound.md)).
* **The films.** 33 MP4 (H.264 High 4.1, 1,920 × 1,080, 60 fps), 444.6 s in
  all — and **31 of the 33 have no audio track**: the cutscene's soundtrack
  is one sample in its `_sfx` bank and its lines are in its `_vo_` bank
  ([06](06-the-films-and-the-programs.md)).
* **The programs.** Unity's player (`The Wardrobe.exe`, 667,648 bytes,
  importing one function from `UnityPlayer.dll` 6000.3.6.45072), a Mono
  runtime, 143 managed assemblies of which two are the studio's
  (`Assembly-CSharp.dll`: 379 types, 3,136 methods, the interpreter of the
  52 verbs by name; `Assembly-CSharp-firstpass.dll`: Steamworks.NET), FMOD,
  Rewired, Resonance, Steamworks, Burst — and five console wrappers
  (`SonyNP`, `SonyPS4CommonDialog`, `SonyPS4SaveData`, `XboxOneCommonImport`,
  `UsersImport`), two ARM64 plugins, and a `_DoNotShip` folder, shipped
  ([06](06-the-films-and-the-programs.md)).
* **The clocks.** Two generations in one folder: 1,178 files keep
  2024-09-28 (1,171 XML of the script, 4 plugin DLLs, 3 Mono files) and 842
  were written 2026-06-05 17:02:28 … 17:03:34 — 65 seconds — by the Steam
  update; 36 XML files (six per language) are among the 842. The datable
  link stamps run 2016-03-03 … 2026-05-06, the last being the studio's own
  Burst-compiled code; 136 of 143 managed assemblies carry a build hash in
  the timestamp field, not a date ([07](07-steam-the-two-generations-and-the-clocks.md)).

## The four denominators

Every percentage in these documents names one of these:

| denominator | value | used for |
|---|---:|---|
| files, bytes of the install | 2,020, 3,494,280,269 | coverage, the split, the generations |
| serialized files, objects | 105, 28,593 | textures 1,161, sprites 17,368, the census |
| banks, banks with sound, samples | 482, 420, 6,385 | the voices, the seconds per language |
| XML files, `text` lines per language | 1,207 (6 × 179 + 83 + 50), 3,185 | the grammar, the diff, the join |

## What was read, and how far

The texture layout at 22 to a render (some sprites, not 17,368: a census and
five renders, sent to the owner and confirmed); the XML to a grammar and a
six-language diff (not an execution); the banks to their chunk tree and the
sample headers (no audio decoded); the films to their boxes (no frame
decoded); the assemblies to their members (no IL). Unity's SerializedFile,
FMOD's FSB5 and `FEV ` are their makers' unpublished formats and sit in the
DECODED bucket because public third-party readers exist for them; the chunk
names and field names in these documents are this session's reading of the
bytes, not their makers' documentation. The rest — the `.strings` bank's
packed name table, the sprites' meshes, the shaders, the 1,542
MonoBehaviours' fields — was counted and is not claimed.
