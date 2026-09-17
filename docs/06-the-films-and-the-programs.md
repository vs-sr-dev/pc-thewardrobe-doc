# 06 — The films and the programs: 33 MP4 closing at residue 0 of which 31 are silent, Unity's player importing one function, 143 managed assemblies of which two are the studio's, an enum that names five platforms, five console wrappers and a `_DoNotShip` folder in a Windows build, and 90 signatures from three signers

*Measure: `python tools/mp4box.py census …/StreamingAssets/Movies` (notes/mp4box-census.txt), `python tools/mp4probe.py …/Movies/*.mp4` (notes/mp4probe.txt), `python tools/pecensus.py TheWardrobe` (notes/pecensus.txt; the same before the repair, notes/pecensus-before.txt), `python tools/pe.py "TheWardrobe/The Wardrobe.exe" --sections --imports --version --resources` (notes/pe-exe.txt), `pe.py … UnityPlayer.dll` (notes/pe-unityplayer.txt), `python tools/clrmeta.py TheWardrobe --census` (notes/clrmeta-census.txt), `python tools/cilmeta.py members … Assembly-CSharp.dll` and `… -firstpass.dll` (notes/cilmeta-*-members.txt), `python tools/authenticode.py …` over the 90 signed files (notes/signers.txt, notes/authenticode-*.txt), `python tools/protscan.py TheWardrobe` (notes/protscan.txt).*

## The films

`StreamingAssets\Movies\` holds 33 MP4, 222,398,304 bytes, 6.36 % of the
install. `mp4box.py census`: 33 of 33 begin with `ftyp` (major brand
`isom`, compatible `isom iso2 avc1 mp41`), **33 of 33 box trees close at
residue 0**, four top-level boxes each (`ftyp free mdat moov`), an edit
list in every one, 26,331 access units, `mvhd` 444.639 s against `stts`
444.622 s (agreeing to the millisecond on 17 of 33: the container's claim
and the sample table's sum are printed apart, as that tool insists). The
sample bytes are 222,045,582 of 222,398,304 — 99.84 % of the files are
payload. `mp4probe.py` names the tracks:

| films | video | audio |
|---|---|---|
| 31 | one `avc1` track, AVC High profile level 4.1, 1,920 × 1,080 on 28 of them (`estrazione_ingranaggi` 1,916 × 1,080, `johnny` 1,892 × 1,080, `outro1` 1,194 × 796), **60 frames per second** (`accensione_catacomba`: 840 samples in 14.000 s; `intro`: 3,928 in 65.467 s), 3.4–7.0 Mbit/s | **none** |
| `CG_horizontal.mp4` | 1,920 × 1,080, AVC Main 4.1, 25 fps, 5.6 s | `mp4a` AAC LC, 48 kHz stereo |
| `TW_gamera_logo.mp4` | 1,920 × 1,080, AVC High 4.2, 30 fps, 5.0 s | `mp4a` AAC LC, 48 kHz stereo |

**Thirty-one of the thirty-three have no audio track.** The two that do
are the two logos. The pre-briefing supposed the cutscenes' voices travelled
in the MP4 and that is why 29 voice banks were empty; the bytes say the
films are silent and the sound is FMOD's: each cutscene has a `cut_NAME_sfx`
bank holding one Vorbis stream as long as the film, and a `cut_NAME_vo_ita`
/ `_vo_eng` bank holding its lines — seven of them with lines, twenty-four
without, and `scripts\cutscenes\` subtitles for the seven
([04](04-the-text-of-the-game.md), [05](05-the-sound.md)). The 31 film
names are the 31 `cut_` banks' names: `intro`, `outro1` … `outro4`,
`viaggio_tempo_1863`, `viaggio_tempo_1981`, `viaggio_tempo_back`,
`skinny_matrix`, `matrimonio`, `boogeyman`, `casa_a_fuoco`,
`nonnina_spaventa_ragazzini`, `pomello_excalibur`,
`pomello_fiamma_ossidrica`, `sveglia_barbone`, `pittore_dipinge` … The
longest are `intro` (65.5 s, 33.2 MB), `outro2` (60.2 s), `outro3` (31.2
s), `matrimonio` (20.7 s); all 33 together are 7.41 minutes. No frame was
decoded; the boxes were walked and the tables read.

Beside them, three PNG (`SaveIcon.png` 80,430 bytes, `SaveIconEmpty.png`,
`ScreenShotOverlay.png`; 176,738 bytes, 3 of 3 closing — notes/pngcensus.txt)
that the assembly's `CINIC.Save.SaveManager` and its `Slot` presumably
draw around a screenshot; that is a reading of names, not of code.

## The player

`The Wardrobe.exe` is Unity's stub: PE32+ x64, 667,648 bytes, six sections,
linked 2026-01-27 10:58:40 UTC (COFF 0x69789A60, a date and not a hash:
[07](07-steam-the-two-generations-and-the-clocks.md)), importing **one
name from `UnityPlayer.dll` — `UnityMain2` — and 71 from KERNEL32**, and
nothing else. Its `.rsrc` (565,272 bytes, 85 % of the file) is nine icons
of 16 to 256 pixels (32-bpp DIBs, 1,128 to 270,376 bytes), a `GROUP_ICON`,
a `VERSION` (FileVersion 6000.3.6.45072 — the engine's, not the game's) and
a manifest. The 256 × 256 icon was pulled out and converted
([03](03-the-serialized-files-and-the-sprites.md)): the skeleton's face.
`UnityPlayer.dll` is 35,780,016 bytes, FileVersion 6000.3.6.45072,
linked 2026-01-27 11:13:20; `UnityCrashHandler64.exe` 1,609,136 bytes,
the same morning; `D3D12\D3D12Core.dll` 4,725,304 bytes, Microsoft's,
2025-09-23; `MonoBleedingEdge\EmbedRuntime\mono-2.0-bdwgc.dll` 7,828,912
bytes and `MonoPosixHelper.dll`, 2025-10-14, plus Mono's `etc\` — the 20
files of `MonoBleedingEdge\` are the runtime and its configuration, 13 of
which cross the collection byte for byte
([07](07-steam-the-two-generations-and-the-clocks.md)). The game is not in
the player; the player is 0.02 % of the install.

## The studio's code

161 PE files, 98,067,688 bytes: 143 managed (all CLI v4.0.30319, PE32) and
18 native (PE32+: 16 x64, 2 ARM64). `protscan.py` finds none of eleven
copy-protection markers in any of them (positive control: 161 hits on
the DOS stub).

**`Assembly-CSharp.dll`**, 819,712 bytes: 379 types, 2,196 fields, 3,136
methods (`cilmeta.py members`, ECMA-335 tables, no IL). 164 types sit in
no namespace — `Script`, `Hotspot`, `Location`, `Voice`, `ObjectI`,
`Entry`, `ScreenC`, `Global`, `CutsceneScript`, `Icon`, `Map`,
`DocumentViewer`, `LogoScreen`, `SteamManager` — the interpreter of
[04](04-the-text-of-the-game.md) and the rooms; 51 under `CINIC.*`:
`CINIC.TheWardrobe` (29: `PlatformManager`, `IPlatformManager`,
`PlatformStatus`, `XboxManager`, `XboxLiveNotSyncException`,
`PlatformDependentUI`, `LocalizedText`, `LocalizedImage`, `MainMenuUI`,
`InventoryMenuUI`, `SlotButton` …), `CINIC.Utility` (10: `GameVersion`
with one field `gameVersionLabel`, `Platform`, `PlatformActivator`,
`CinicManager`, `SteamPageButton`, `Mailchimp`), `CINIC.Online` (8:
`Trophy`, `TrophyContainer`, `TrophyManager`, `UserManager`,
`EngagementScreen`, `SpeedRun`, `Sword`), `CINIC.Save` (4: `SaveData`,
`SaveManager`, `Slot`, `SaveDataResult`), `CINIC.Video.VideoPlayer`,
`CINIC.Text.TextManager`, `CINIC.CameraScaler`; and 55 under `Rewired.*`
(the input package's demo scripts, compiled in). **`CINIC.Utility.Platform`
is an enum of five: `PS4`, `XboxOne`, `Switch`, `Steam`, `DrmFree`.**

Its `#US` heap, 240,624 bytes in 6,146 literals (`clrmeta.py
--userstrings`): the 52 verbs, the flags, the poses, the expressions, the
XML paths (`'/XML/'`, `'/XML/default/skinny.xml'`, `'/XML/areas/'`,
`'/data/skinny.xml'` for the save), XPath fragments
(`"/skinny/location[@name='"`, `"/inventory/object[@ID='"`,
`"/location/sound[@name='"`), `'SteamManager'`, `'steamdeck'`,
`'SteamDeck'`, `'LoadBanks'`, `'ACHIEVEMENT_'`, `'Achievement not found: '`,
seven localised words for ACHIEVEMENTS (`OBIETTIVI`, `ERFOLGE`, `SUCCÈS`,
`LOGROS`, `ДОСТИЖЕ́НИЯ`), Steamworks.NET's diagnostics, and the eighteen
Italian error messages. No Steam application id: the only `AppId` is the
type `AppId_t` in the `#Strings` heap.

**`Assembly-CSharp-firstpass.dll`**, 401,408 bytes: 494 types, 2,966
fields, 2,975 methods — 395 of the first 400 types under `Steamworks.`
(the Steamworks.NET wrapper, compiled as a first-pass assembly) plus
`TMPro.Examples`. The bigger `#Strings` heap the pre-briefing wondered at
is Steamworks' method table.

The rest of `Managed\` (131 files) is Unity's (`UnityEngine.*Module.dll`
×~70, `Unity.*`), Mono's (`System.*`, `mscorlib`, `netstandard`), and the
packages': `FMODUnity`, `FMODUnityResonance`, `Rewired_Core`,
`Rewired_Windows`, `Rewired_Windows_Functions`.

## The plugins, and where else this build went

`Plugins\x86_64`: `fmod.dll`, `fmodl.dll` (2016-03-03, Firelight
Technologies), `fmodstudio.dll` (2022-12-01) — the runtime of the 482 banks;
`resonanceaudio.dll` (2021-03-22) and `gvraudio.dll` (2017-05-12) — spatial
audio in a 2D game; `Rewired_DirectInput.dll`, `Rewired_WindowsGamingInput.dll`
(2023–2024); `CSteamworks.dll` (2017-01-08, unsigned, its `CompanyName` a person's
name — counted, not quoted) and `steam_api64.dll` (2020-02-21, signed
**Valve**, Bellevue WA); `lib_burst_generated.dll` (443,392 bytes, **2026-05-06 12:29:54** —
the studio's Burst-compiled jobs, and the only datable stamp of the
studio's own build). `Plugins\ARM64`: the two Rewired DLLs again, machine
0xAA64, linked 2024-02-13 — an ARM Windows nobody here runs.

**Console wrappers in a Windows build:** `Managed\SonyNP.dll` (242,176
bytes, FileVersion 6.500.7878.26511), `SonyPS4CommonDialog.dll`
(1.0.7878.26512), `SonyPS4SaveData.dll` (0.1.7878.26512) — three managed
PS4 assemblies compiled by csc 11.00 on 2021-07-27 (their version's
build number 7878 is that date's day count from 2000-01-01, so the stamp
and the version agree); `XboxOneCommonImport.dll` (2020-04-20) and
`UsersImport.dll`. `CINIC.TheWardrobe.XboxManager`, `CINIC.Online.Trophy`
and `TrophyManager`, the `Platform` enum's `PS4 XboxOne Switch`, and the
eighteen `PS4_* XONE_* SWITCH_*` controller screens among the sprites
([03](03-the-serialized-files-and-the-sprites.md)) are the same fact from
four directions: the Unity project this Steam build came out of also
targets three consoles, and the Windows build carried the managed stubs
along. Whether those builds exist is not in these bytes.

**`The Wardrobe_BurstDebugInformation_DoNotShip\Data\Plugins\x86_64\lib_burst_generated.txt`**,
193,524 bytes: the debug symbol text Burst writes beside its DLL, in a
folder Unity names `DoNotShip`, shipped. It carries developer machine
paths, counted and not quoted
([07](07-steam-the-two-generations-and-the-clocks.md)).

## The signatures

90 of 161 PE files carry an Authenticode certificate table
(notes/pecensus.txt); `authenticode.py` reads the signer's subject from
each (notes/signers.txt):

| signer | files |
|---|---:|
| Unity Technologies SF (DigiCert G4 code signing, 2021–2036) | 86 — the player, the crash handler, `UnityPlayer.dll`, every `UnityEngine.*Module.dll`, Mono's two runtime DLLs |
| Microsoft Corporation | 3 — `D3D12Core.dll`, `System.IO.Hashing.dll`, `System.Runtime.CompilerServices.Unsafe.dll` |
| Valve (Bellevue, WA; DigiCert SHA2 code signing) | 1 — `steam_api64.dll` |

The studio's two assemblies, FMOD's, Rewired's, Resonance's, the console
wrappers and `CSteamworks.dll` are unsigned (71 files). No certificate
names CINIC Games.

## What is not read

No frame of any film, no instruction of any assembly, no export of the
native plugins beyond their headers; the `.rsrc` of `UnityPlayer.dll`;
the Burst symbol file beyond its personal-path count.
