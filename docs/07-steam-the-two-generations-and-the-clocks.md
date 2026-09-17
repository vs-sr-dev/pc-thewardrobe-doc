# 07 — Steam, the two generations and the clocks: a folder Steam left nothing in but the game, 1,178 files of September 2024 under 842 of June 2026 written in 65 seconds, 136 timestamps that are hashes, one that is the studio's, a beta among the releases, and a Studio cell full and a Year cell that says what the bytes say

*Measure: `python _work/generations.py TheWardrobe` (notes/mtimes.txt), `python tools/pecensus.py TheWardrobe` (notes/pecensus.txt, and notes/pecensus-before.txt for the 136 "impossible" ones), `python tools/unityfs.py info "…/Resources/unity default resources"` (notes/unityfs-defaultresources.txt), `python tools/crossall.py _work/sha1-all.txt --collection .. --skip pc-thewardrobe-doc` (notes/crossall.txt), `python tools/sift.py TheWardrobe --group personal` and `--group buildpath` (notes/sift-personal.txt, notes/sift-buildpath.txt — counts only; `--show` was run in `_work/` and is not published), the hex dump of `PlayerSettings` in `globalgamemanagers` (`_work/hexobj.py`).*

## What Steam left in the folder

The game, and nothing of its own. There is no `steam_appid.txt`, no
`installscript.vdf`, no `.vdf` of any kind, no Steam manifest; the
application id is not a string in any assembly (the only `AppId` is the
Steamworks.NET type `AppId_t`), and if it is an integer constant in IL it
was not read. Steam's presence is in the game's own bytes:
`Plugins\x86_64\steam_api64.dll` signed by Valve, `CSteamworks.dll`,
`Assembly-CSharp-firstpass.dll` = Steamworks.NET, a `SteamManager` class,
the literals `'steamdeck'` and `'SteamDeck'`, `CINIC.Utility.SteamPageButton`,
and the enum `CINIC.Utility.Platform { PS4, XboxOne, Switch, Steam, DrmFree }`
— which names the shop this copy came from as one of five targets, and a
`DrmFree` one beside it. The install's own clock, 2026-06-05, is Steam's
writing; the folder carries no receipt for it.

No save, no log, no crash dump: Unity writes those under the user's profile
and this copy is the Steam folder alone. **No diary.** The save's shape is
in the assembly (`CINIC.Save.SaveManager`, `Slot`, `'/data/skinny.xml'`,
`'/data/inventory.xml'`, `SaveIcon.png` beside the films): the default
tree of [04](04-the-text-of-the-game.md) copied per slot, with a
screenshot. That is a reading of names.

## Two generations, file by file

Every file's modification time is one of two days (notes/mtimes.txt):

| generation | files | bytes | window | what |
|---|---:|---:|---|---|
| **2024-09-28** | 1,178 | 9,813,528 | 12:05:30 … 12:07:52 local, 2 min 22 s | 1,172 `.xml` (1,171 of the script + Mono's `config.xml`), 4 `.dll` (`CSteamworks`, `fmod`, `fmodl`, `gvraudio`), `browscap.ini`, one `.browser` |
| **2026-06-05** | 842 | 3,484,466,741 | 17:02:28 … 17:03:34 local, **65 s** | 482 `.bank`, 155 `.dll`, 52 `.assets`, 33 `.mp4`, 5 `.resS`, 54 without extension (`level0`…`49`, `globalgamemanagers`, `unity default resources` …), 36 `.xml`, 3 `.png`, 2 `.exe`, 2 `.json`, `app.info`, `boot.config`, Mono's other 17 |

The 2024 clock is the older Steam deposit that the June 2026 update did
not overwrite: **1,171 of the 1,207 script files, four plugins whose
bytes the update did not change**. The 2026 clock is everything the update
rewrote, in 65 seconds, whatever its bytes — the pre-briefing's "two
minutes" was the XML's window, not the update's. Which of the 842 changed
content between the two deposits is not knowable from one copy; which
**XML** files the update touched is: **36 — six files in each of six
languages**: `dialogs\tutorial.xml`, `locations\bagno.xml`, `bagno1.xml`,
`discarica.xml`, `interno_gru.xml`, `objects\magnete.xml`. Five of the six
are among the 81 files where the Italian tree differs from the other five
([04](04-the-text-of-the-game.md)): the update edited the tutorial, two
bathrooms, the dump, a crane's cab and a magnet, and left the other 1,171
files at their 2024 bytes. Hunch (d) of the pre-briefing — "left the XML
alone but for a handful" — is right, and the handful is 36.

## The clocks that are not clocks, and the ones that are

`pecensus.py` reported `impossible mtimes : 136 of 161` and a COFF range
reaching 2104-12-01. Its arithmetic was right and its label wrong: a
managed assembly built deterministically carries, in the PE timestamp
field, a hash of the build with bit 31 set — a value past 2038-01-19 that
is not a date. The tool now says so (`deterministic (hash) stamps, not
dates, counted apart : 136 of 143 managed`), prints them as `hash
0x…`, and reports `impossible mtimes : 0 of 25 datable binaries`
([08](08-tools-predictions-and-calibration.md); notes/pecensus.txt against
notes/pecensus-before.txt). The 25 datable stamps, over 16 distinct days:

| linked (UTC) | file | whose |
|---|---|---|
| 2016-03-03 | `fmod.dll`, `fmodl.dll` | Firelight (FMOD) |
| 2017-01-08 | `CSteamworks.dll` | Steamworks.NET's native shim |
| 2017-05-12 | `gvraudio.dll` | Google VR audio |
| 2019-06-19 … 2021-10-22 | `Unity.Burst.Unsafe.dll`, `System.Runtime.CompilerServices.Unsafe.dll`, `steam_api64.dll` (2020-02-21), `XboxOneCommonImport.dll` (2020-04-20), `resonanceaudio.dll` (2021-03-22), `SonyNP.dll` ×3 (2021-07-27) | package vendors; the console wrappers |
| 2022-12-01 | `fmodstudio.dll` | Firelight |
| 2023-10-30, 2024-02-13 | four `Rewired_*` plugins (x64 and ARM64) | Guavaman |
| 2025-09-23, 2025-10-14 | `D3D12Core.dll`; Mono's two runtime DLLs | Microsoft; Unity's Mono |
| **2026-01-27** | `The Wardrobe.exe` 10:58, `UnityCrashHandler64.exe` 10:56, `UnityPlayer.dll` 11:13 | Unity 6000.3.6f1's player build |
| **2026-05-06 12:29:54** | `lib_burst_generated.dll` | **the studio's own build**: Burst compiles the project's jobs to native code at build time, and native code gets a date |

The studio's managed code (`Assembly-CSharp.dll`, hash 0x93265E19)
carries no date; its native twin does. So the build Steam deployed on
2026-06-05 was made on 2026-05-06, on an engine Unity built on 2026-01-27,
from XML files last saved 2024-09-28 but for six.

**The beta.** 104 of 105 serialized files say `6000.3.6f1`; one says
`6000.3.0b4`: `Resources\unity default resources` (37 textures, Unity's
built-in shaders and materials). It is Unity's file, shipped as-is from
the editor's own resources and not rebuilt with the project; hunch (d)
had it as "a small `sharedassets` nobody touched", and it is smaller than
that — not the studio's at all.

## The card: Studio and Year, from the bytes

**Studio: CINIC Games.** Witnesses: `app.info` line 1 (`CINIC Games`, 11
bytes, followed by `The Wardrobe`); `PlayerSettings` in
`globalgamemanagers` (`companyName` = `CINIC Games`, `productName` = `The
Wardrobe`); the namespace `CINIC.*` on 51 of the assembly's 379 types
(`CINIC.TheWardrobe`, `CINIC.Utility.CinicManager`); no other studio name
in 1,207 XML files, 6,146 literals or 90 certificates (Unity, Microsoft,
Valve sign; the studio signs nothing). Who CINIC Games is beyond the name
is not in the bytes: the `sviluppatori` dialogue has three characters
named Francesco, Stefano and Marco who claim to have made the hero, and a
`credits` verb runs once; nothing else names a person, and the personal
identifiers the bytes do carry are counted below and not quoted.

**Year: the bytes carry no release date.** What they carry:

| clock | value | witness |
|---|---|---|
| the script's last save | 2024-09-28 | 1,171 XML mtimes, 2 min 22 s |
| the engine | Unity 6000.3.6f1, player linked 2026-01-27 | `globalgamemanagers`, `UnityPlayer.dll` |
| the studio's build | 2026-05-06 | `lib_burst_generated.dll` COFF |
| the deposit on this disk | 2026-06-05 17:02–17:03 | 842 mtimes |
| a version | `2.4.7` (and `1.0`, `1.0`) | three version-shaped strings in `PlayerSettings`; which is `bundleVersion` is not derived without a type tree; `CINIC.Utility.GameVersion.gameVersionLabel` displays one |

A game whose script was saved in 2024 and whose engine is 2026's, at
version 2.4.7, is a game some way into its life on this copy's evidence;
what year it first shipped is the sort of thing this object does not state.
The index's Year cell takes four digits and nothing else, so it carries
**2024** — the oldest day the game's own content carries, the script's
clock — and this paragraph is the argument that it is a clock and not a
release date; a year from memory would have fitted the cell just as well
and proved nothing.

## Against the collection

`crossall.py` over 119 repositories: **19 of 1,987 distinct hashes cross**,
and all nineteen are engine furniture — 13 files of `MonoBleedingEdge\etc\`
(`machine.config`, `web.config`, `settings.map`, `browscap.ini`,
`DefaultWsdlHelpGenerator.aspx`, `Compat.browser`, `config`,
`mconfig\config.xml`), 3 managed (`System.Runtime.dll`, `netstandard.dll`,
`Unity.Burst.Unsafe.dll`) and 3 plugins (`CSteamworks.dll`,
`Rewired_WindowsGamingInput.dll`, `resonanceaudio.dll`) — across
pc-twinsensquest-doc, pc-themurderofsonicthehedgehog-doc,
pc-iamsetsuna-doc, pc-monstrum-doc, pc-teslaeffect-doc and
pc-academagia-doc. Not a byte of the game crosses. By a grep of the
collection's READMEs, this is the first FMOD Studio bank (`FEV `) and the
first script written in XML here, and the first Unity 6 **on PC** — not
the first Unity 6: android-dissidiaduellum-doc is Unity 6000.3.10f1 at
format 22, and it is where `unityfs.py` learned the 48-byte header that
[03](03-the-serialized-files-and-the-sprites.md) leans on. Firsts by the
sweep and the grep, not as facts of the world.

## The personal data, counted and not quoted

`sift.py --group personal` over 2,020 blobs: e-mail shapes 82 in 8 blobs,
home-directory paths 19 in 7, a telephone shape 2 in 1, a street-address
shape 1 in 1, postal-code-and-town shapes 24 in 16 (positive control 161
hits, negative control quiet). `--group buildpath`: drive-letter paths
1,045 in 29 blobs, Unix build paths 4 in 4. The home directories are
developers' machines — in the Burst symbol file the `_DoNotShip` folder
shipped, in five managed DLLs (the studio's two, FMOD's two, one of
Rewired's) and in `CSteamworks.dll` — and one 11-character lowercase
handle sits at the end of `PlayerSettings`; the e-mail shapes are 35 in
Mono's `browscap.ini` and help generators, 2 in `UnityPlayer.dll`, and the
rest in three of the game's own blobs (a sidecar, a serialized file, one
voice bank — shapes in pixels and Vorbis, most likely, and not checked).
All of them
are bytes of other people's machines: counted here, masked in `notes/`,
and not written.
