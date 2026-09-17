# pc-thewardrobe-doc

A measured description of one directory: 2,020 files, 83 subdirectories,
3,494,280,269 bytes, 1,987 distinct hashes, copied from the owner's Steam
library — **THE WARDROBE**, a 2D point-and-click by **CINIC Games** (the
studio's name in Unity's `app.info` and `PlayerSettings`; the owner said
"an Italian studio" and the bytes say the master language is Italian) on
Unity 6000.3.6f1, serialization format 22, in which 70.57 % of the bytes are
five streamed sidecars the sprites slice, 13.09 % are 482 FMOD Studio banks,
6.36 % are 33 films, and 0.16 % — 1,207 XML files in six languages with the
Italian line as the key — is the whole game in writing, in the clear. The
work was to repair a coverage table that called the banks opaque and three
UTF-8 files art, to teach two readers to refuse a PNG instead of dying on
it, to read the Texture2D and Sprite layouts of a format version nobody
here had read from a hex dump and close them on every object, to write the
grammar of the studio's command language and diff it across six languages,
to walk the banks to their sample headers and join them to the script, and
to say which of the folder's two generations of files the 2026 update
touched. The object is not published. What is published is what could be
counted, closed on, decoded and rendered — all of it from the object's own
bytes, none of it from outside.

## The short card

| | |
| --- | --- |
| **what it is** | a point-and-click played by `Skinny`, a skeleton in a green hoodie (2,267 unlabelled lines of 3,185, 2,066 sprites), through 47 rooms from a boy's bedroom to a museum, a graveyard, a beach in 1861 and 1981 and a meteorite, with 85 inventory objects, 33 dialogue partners, 115 named characters, 27 achievements, 31 cutscenes and a wedding; the premise is in `intro.xml`: two boys, a picnic, a plum, a skeleton shut in his friend's wardrobe |
| **title** | THE WARDROBE — `app.info` line 2, `PlayerSettings.productName`, the sprite `logo_the_wardrobe`, the achievement `wardrobe` |
| **studio** | **CINIC Games** — `app.info` line 1, `PlayerSettings.companyName`, 51 types in the namespace `CINIC.*`; nothing else names a studio, and no certificate is theirs (Unity 86, Microsoft 3, Valve 1) |
| **year** | **no release date in the bytes**; the index's cell says **2024**, the oldest day the game's own content carries (1,171 XML files saved 2024-09-28) — not a release year: the engine is 2026's (player linked 2026-01-27), the studio's Burst DLL was linked 2026-05-06, Steam deposited the copy 2026-06-05, and a version string `2.4.7` sits in `PlayerSettings`; what year the game first shipped, this copy does not say |
| **engine** | Unity 6000.3.6f1 (104 of 105 serialized files; Unity's own `unity default resources` from beta `6000.3.0b4`), x64, Mono; FMOD Studio for sound, Rewired for input, Resonance for spatial audio, Burst, Steamworks.NET; and a script interpreter of the studio's own, class `Script`, whose 52 verbs are literals in `Assembly-CSharp.dll` and whose error messages are in Italian |
| **files** | 2,020: 1,208 `.xml` (1,207 of the script + Mono's), 482 `.bank`, 159 `.dll` + 2 `.exe`, 54 without extension (`level0`…`49`, `globalgamemanagers` …), 52 `.assets`, 33 `.mp4`, 5 `.resS`, 3 `.png`, 22 of Mono's and Unity's small files (`.config` 7, `.browser` 3, `.aspx` 3, `.map` 3, `.txt` 2, `.json` 2, `.ini`, `.info`) |
| **bytes** | 3,494,280,269 — sidecars 2,466,018,272 (70.57 %), banks 457,534,468 (13.09 %), serialized files 243,781,032 (6.98 %), films 222,398,304 (6.36 %), PE 98,067,688 (2.81 %), XML 5,421,040 (0.16 %) |
| **the serialized files** | 105 at format 22, 28,593 objects, 105 of 105 closing on their length **and** on `header + metadataSize` — the "48 unexplained bytes" of the pre-briefing were the 48-byte header; Sprite 17,368, Texture2D 1,161, MonoBehaviour 1,542, SpriteRenderer 1,177 |
| **the pictures** | `Texture2D` at 22 read from a hex dump and closed twice on 1,161 of 1,161 (DXT5 735, RGBA32 236, DXT1 91, Alpha8 49, ARGB4444 32, RGB24 18; 99 at 1,920 × 1,080); `Sprite` closed on 17,368 of 17,368, every one naming a texture in its own file; the five sidecars tiled by 960 records to 2,466,018,043 of 2,466,018,272 bytes (229 bytes of alignment slack); **six renders made and five sent — the skeleton first**, the menu, a PS4 control screen in Italian, the bedroom (and its walk mask by accident), the player's icon; eighteen controller screens for PS4, Xbox One and Switch in six languages among the sprites |
| **the text** | 1,207 XML: 6 trees × 179 (85 objects, 47 rooms, 33 dialogues, 6 scripts, 3 intros, 2 buffers) + 83 default + 50 walk polygons; a command language `[status] verb [-"target"] [flags] "text" [n]` of **52 verbs**, 10,636 commands in `ita`, 10,674 in each other tree, 3,185 `text` lines per language, 35 speakers (`me` is the file's own character, not Skinny), 178 dialogue keys the same in all six; **the five translations are identical to each other** and differ from Italian in 81 files by 38 commands of timing (`wait` +19, `expression` +15 …) and 0 of text; three misspelt tags in six copies |
| **the sound** | 482 FMOD Studio banks (`RIFF` form `FEV `) walked to residue 0; 420 FSB5 inside `SND ` chunks closing on the chunk **and** on the bank's own `SNDH` record, 420 of 420; 6,385 Vorbis samples at 48 kHz: **Italian 2,991 samples / 148.3 min, English 2,974 / 134.6 min** (+10.2 %), effects 389 / 39.4 min, soundtrack 31 / 63.0 min; 62 banks with no sound, the same 29 per voice language; samples named by the line numbers of the script, 175 of 200 banks named for an XML file, 144 exact |
| **the films** | 33 MP4, H.264 High 4.1, 1,920 × 1,080, 60 fps, 444.6 s, box trees closed 33 of 33 — **31 of them silent**: each cutscene's soundtrack is one sample in its `_sfx` bank and its lines are in its `_vo_` bank |
| **the programs** | Unity's player importing one function (`UnityMain2`), 143 managed assemblies (136 with a build hash where a date would be), `Assembly-CSharp.dll` 379 types / 3,136 methods, `-firstpass` = Steamworks.NET; an enum `Platform { PS4, XboxOne, Switch, Steam, DrmFree }`; five console wrappers, two ARM64 plugins and a `_DoNotShip` folder shipped; 0 protection markers; 90 signatures |
| **Steam** | `steam_api64.dll` signed Valve, `CSteamworks.dll`, `SteamManager`, `'steamdeck'`; no `steam_appid.txt`, no `.vdf`, no appid literal; no save, no log, no crash: **no diary** |
| **the clocks** | 1,178 files at 2024-09-28 (1,171 XML + 4 DLL + 3 Mono), 842 at 2026-06-05 written in 65 s; the update touched 36 XML (6 × 6 languages); datable link stamps 2016-03-03 … 2026-05-06 |
| **crossings** | 19 of 1,987 over 119 repositories, all engine furniture (13 Mono, 3 managed, 3 plugins); not a byte of the game |
| **coverage** | specified 9.3566 %, decoded 20.0704 %, derived 70.5730 %, **opaque 0 files, 0 bytes**, residue 0 — from 13.0941 % opaque before the repair |
| **tools** | 617 Python files: 614 inherited from pc-losthorizon-doc (0 differing on arrival), 5 mended (`coverage.py`, `unityfs.py`, `unitytex17.py`, `unitymovie.py`, `pecensus.py`), 3 written (`unitytex22.py`, `wardrobexml.py`, `fevbank.py`); 463 selftest checks, 0 failures |

**The work this time was a repair, a layout, a grammar, a walker and a
diff — on an object behind nothing at all.** The last object kept its
file names behind a lock nobody opened; this one keeps its whole script in
UTF-8 with the original line as the key of every translation, and what
changed is where the difficulty went: not into a lock but into a format
version the box had never met and a table that called a seventh of the
object unreadable. The table was wrong twice, in a probe that did not exist
and a probe that could not see a space; the 48 bytes that looked like a new
field were the header; the Texture2D at 22 was 17's plus nine fields and
three wrap modes, and closed on all 1,161; the sprites are the pictures and
closed on all 17,368; the first one out was the skeleton. The script gave
its grammar in an afternoon — fifty-two verbs, a status guard, a decimal
comma, `me` who is never Skinny — and its diff said the translators were
handed one master and the Italian kept moving. The banks closed twice,
once on the chunk and once on a record that wrote the answer down for them,
and their sample names turned out to be the script's line numbers. The
films are silent, which the pre-briefing did not expect and the banks
explain. And the clocks: a 2024 script under a 2026 engine, a build hash
where 136 dates should be, and one native DLL that kept the studio's own
day.

**The pre-briefing's figures were corrected nine times**; its five hunches
score two right, one three-quarters, one half, one one-and-a-half of four,
and the one the pictures hung on was wrong about the bytes and right about
the picture.

## The chapters

Eight, and the count is the content's: the serialized files and the
sprites had to be one because the format is new to the box and the pictures
are the object's 77 %; the text one because the XML is the game in writing
and the interpreter reads it by name; the sound one because 482 banks are a
container of their own with a join to the text; the films and the programs
one because 33 silent films and 161 binaries share the question of what
this build is and where else it went; Steam, the two generations and the
clocks one because they are what the shop and the calendar left on the
object and where the card's two hard cells are decided; and the tools one
because a repair came before the first reader and a term has to be
written.

| chapter | what it says |
|---|---|
| [01 — What this is](docs/01-what-this-is.md) | the install, the split by magic, what it says in the clear, the four denominators, how far each thing was read |
| [02 — The technical sheet](docs/02-the-technical-sheet.md) | every figure with its command |
| [03 — The serialized files and the sprites](docs/03-the-serialized-files-and-the-sprites.md) | the 48 bytes, the Texture2D and Sprite layouts at format 22, two closures on 1,161 and one on 17,368, the sidecars to 229 bytes, the backgrounds, the console screens, six renders |
| [04 — The text of the game](docs/04-the-text-of-the-game.md) | the tree, the command language of 52 verbs, who speaks, the story as the intro writes it, the six-language diff, the interpreter by name |
| [05 — The sound](docs/05-the-sound.md) | the `FEV ` container, two closures on 420 banks, the census by language, 62 shells, the join by line number, the soundtrack |
| [06 — The films and the programs](docs/06-the-films-and-the-programs.md) | 33 films of which 31 silent, the player, the studio's code and its platform enum, the plugins and the console wrappers, three signers |
| [07 — Steam, the two generations and the clocks](docs/07-steam-the-two-generations-and-the-clocks.md) | what Steam left, 1,178 under 842, 36 XML the update touched, hashes that are not dates and the one that is, the beta, Studio and Year from the bytes, crossings, personal data counted |
| [08 — Tools, predictions and calibration](docs/08-tools-predictions-and-calibration.md) | the coverage repair, the refusals, three readers written and five mended, rule 0, nine corrections, five hunches scored, the term +6.50 |

`notes/` holds the raw output of every command cited; `tools/` the box.
The object, the renders, the pre-briefing and the working directory are not
published; the notes were checked for this machine's paths and for personal
identifiers before commit.
