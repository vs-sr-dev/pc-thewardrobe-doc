# 02 — The technical sheet: every figure with the command that made it

*Measure: every row names its command; the raw output is in `notes/`. Sums marked "by hand" were added from the rows above them and checked against a second row. Paths are relative to the repository root; `D` is `TheWardrobe/The Wardrobe_Data`, `SA` is `D/StreamingAssets`.*

## The install

| figure | value | command |
|---|---|---|
| files, directories, bytes | 2,020, 83, 3,494,280,269 | `treecensus.py TheWardrobe` (notes/treecensus.txt) |
| distinct SHA-1 | 1,987 of 2,020; 19 hashes shared by 33 extra files: 28 XML (3 files × 6 languages, 7 dialogues `default` = `eng`, `lettera` = `lettera_struccata` × 6), 5 Mono `etc` files | `hashall.py TheWardrobe`; `_work/repeats.py` (notes/hash-repeats.txt) |
| by extension | `.xml` 1,208 / 5,446,857; `.bank` 482 / 457,534,468; `.dll` 159 / 95,790,904; no extension 54 / 9,179,747; `.assets` 52 / 234,605,100; `.mp4` 33 / 222,398,304; `.config` 7 / 146,119; `.resS` 5 / 2,466,018,272; `.browser` 3 / 4,815; `.aspx` 3 / 181,725; `.map` 3 / 7,866; `.png` 3 / 176,738; `.exe` 2 / 2,276,784; `.txt` 2 / 193,763; `.json` 2 / 6,799; `.ini` 1 / 311,984; `.info` 1 / 24 | `treecensus.py` |
| top-level | `The Wardrobe_Data` 1,995 files 98.51 %; root 3 files (`The Wardrobe.exe`, `UnityPlayer.dll`, `UnityCrashHandler64.exe`) 1.09 %; `MonoBleedingEdge` 20 files 0.26 %; `D3D12` 1; `The Wardrobe_BurstDebugInformation_DoNotShip` 1 | `treecensus.py` |
| mtime generations | 2024-09-28 ×1,178 (9,813,528 B, 12:05:30–12:07:52); 2026-06-05 ×842 (3,484,466,741 B, 17:02:28–17:03:34 = 65 s) | `_work/generations.py TheWardrobe` (notes/mtimes.txt) |
| XML files the update rewrote | 36 = 6 files × 6 languages | same |
| coverage, before the repair | opaque 484 files 13.0941 % (482 `.bank` + 2 XML); 3 XML as "cp437 with box-drawing art" | `coverage.py tree --root TheWardrobe` (notes/coverage-before.txt) |
| coverage, after | specified 1,428 / 9.3566 %; decoded 587 / 20.0704 %; derived 5 / 70.5730 %; **opaque 0**; residue 0 | same (notes/coverage.txt) |
| crossings with the collection | 19 of 1,987 over 119 repositories, all engine furniture (13 Mono `etc`, 3 managed, 3 plugins) | `crossall.py _work/sha1-all.txt --collection .. --skip pc-thewardrobe-doc` (notes/crossall.txt) |
| copy-protection markers over 161 PE | 0 (positive control 161) | `protscan.py TheWardrobe` (notes/protscan.txt) |
| personal identifiers | e-mail shapes 82 in 8 blobs; home dirs 19 in 7; telephone 2 in 1; drive-letter paths 1,045 in 29 | `sift.py TheWardrobe --group personal`, `--group buildpath` (notes/sift-*.txt) |

## The serialized files (Unity, format 22)

| figure | value | command |
|---|---|---|
| files, objects | 105, 28,593; format 22 ×105; Unity `6000.3.6f1` ×104, `6000.3.0b4` ×1 (`Resources/unity default resources`) | `unityfs.py census D` (notes/unityfs-census.txt) |
| closures | fileSize == file 105 of 105; header + metadataSize == parse end 105 of 105; objects inside their file 28,593 of 28,593 | `unityfs.py verify D` (notes/unityfs-verify.txt) |
| the "48 bytes" | the 48-byte header of format 22 (20 at 17), counted once by the file and once by the reader | `unityfs.py info D/globalgamemanagers` (notes/unityfs-ggm.txt) |
| classes | Sprite 17,368; GameObject 2,452; Transform 1,692; MonoBehaviour 1,542; MonoScript 1,435; SpriteRenderer 1,177; Texture2D 1,161 (79.84 % of in-file bytes); Shader 111; ComputeShader 11; Font 8; Mesh 13; TextAsset 4 | `unityfs.py census D` |
| Texture2D at 22 | 1,161 in 6 files; body closure 1,161 of 1,161; arithmetic closure 1,161 of 1,161; streamed 960, inline 195, none 6; 2,659,751,664 bytes of pixels | `unitytex22.py census D` (notes/unitytex22-census.txt) |
| formats | DXT5 735; RGBA32 236; DXT1 91; Alpha8 49; ARGB4444 32; RGB24 18 — all six decodable | same |
| sizes | 1,920 × 1,080 ×99; 512 × 288 ×44; 16 × 16 ×32; 512 × 512 ×13; `sheet*` ×125 | same; `unitytex22.py list D/resources.assets` |
| the i32 after `m_Name` | 1 on the 109 alpha-less textures (RGB24 18 + DXT1 91), 0 on 1,052 | `_work/texfields.py D` (notes/unitytex22-fields-and-gaps.txt) |
| sidecars | 5 files, 2,466,018,272 B; 960 records reach 2,466,018,043; 229 bytes of slack in 27 places (≤ 13 B each); 3 of 5 to the exact last byte, 0 overlaps | `unitytex22.py sidecars D` (notes/unitytex22-sidecars.txt); `_work/texfields.py` |
| Sprite at 22 | 17,368; body closure 17,368 of 17,368; texture PPtr in own file 17,368, external 0, null 0; 1,064 distinct textures named; tight mesh 16,735; packed 0; rotated 0; PPU 1 ×17,287; 341,300 vertices, 894,291 indices | `unitytex22.py sprites D` (notes/unitytex22-sprites.txt) |
| sprites by file | `resources.assets` 17,350; `sharedassets2` 12; `sharedassets1` 4; `sharedassets0` 1; `globalgamemanagers.assets` 1 | same |
| rectangles | 587 × 181 ×206; 48 × 58 ×144; 145 × 145 ×144; 221 × 504 ×140; 579 × 432 ×119; 1,920 × 1,080 ×99 | same |
| most-sliced textures | `ingranaggio` 250; `pianta_carnivora` 207; `pale_mulino_notte` 193; `pale_mulino` 193; `ruota_panoramica` 180; `objects` 171; `timer_bomba` 144; `orologio_pizza` 144; `flowey_glitch` 138; `piccioni` 108 | same, joined to `unityfs.py objects D/resources.assets --class 28` |
| the skeleton | 2,066 sprites `skinny_*`; `skinny_arpione` 144 frames | `unitytex22.py sprites D --list` (run locally) |
| console screens | `PS4_* XONE_* SWITCH_*` × `ITA ENG FRA DEU SPA RUS` = 18 sprites at 1,920 × 1,080 | same |
| renders | 6 made (`skinny_attende`, `menu_ronald`, `PS4_ITA`, `cameretta` ×2, the exe icon), 5 sent, kept in `_work/` | `unitytex22.py render D --sprite NAME --out FILE`; `_work/exeicon.py`, `_work/dib2png.py` |

## The text (XML)

| figure | value | command |
|---|---|---|
| files, bytes, trees | 1,207, 5,421,040; `areas` 50, `default` 83, six languages × 179 (the 1,208th `.xml` is Mono's) | `wardrobexml.py census SA/XML` (notes/xml-census.txt) |
| roots per language | `object` 85, `location` 47, `dialog` 33, `script` 6, `intro` 3, `buffer` 2 | same |
| well-formed | 1,207 of 1,207; 47 tags; 3 misspelt tags (`comomand`, `comand`, `hotstpot`) ×6 languages | same |
| commands | ita 10,636; each other language 10,674; default 1,926 | same |
| `text` lines | 3,185 per language (2,651 unguarded + 534 guarded); default 821 | same; `wardrobexml.py grammar` |
| verbs | 52 (ita and eng alike); top: `text` 3,185, `wait` 1,541, `expression` 804, `pose` 509, `sound` 493, `animation` 485, `internal` 484, `hide` 482, `show` 427, `bitmap` 424, `if` 234 | `wardrobexml.py grammar SA/XML/ita` (notes/xml-grammar-ita.txt), `…/eng` (notes/xml-grammar-eng.txt) |
| guards | 2,742 guarded commands (ita); statuses 0 ×1,432, 1 ×591, 2 ×244, 3 ×138, sets `0-1` ×84 … `1-2-3-4-5` ×1 | same |
| speakers | 35; unlabelled (Skinny) 2,267; `me` 494; `altoparlante` 68; `tutorial` 60; `guardia` 57; `skinny_mic` 41; `custode` 29 | same |
| numbered / `$`-tagged lines | 147 / 473 (ita) | same |
| achievements | 27 distinct names in 47 `achievement` commands (ita) | `grep` over `SA/XML/ita` |
| dialogue keys | 178 `<voice ID>` per tree, 171 distinct, the same set in all six | `wardrobexml.py diff SA/XML` (notes/xml-diff.txt) |
| the diff | five translations identical to each other; vs ita 98 files same, 81 differ; delta `wait` +19, `expression` +15, `animation` +4, `lookat` +1, `sound` +1, `internal` −1, `pose` −1, `text` 0 = +38 | same |
| areas | 50 polygons, 429 vertices | `grep -c "<angle"` |
| rooms' cast | 115 distinct `<character ID>`, 152 distinct `<item ID>`, 372 `<scene>` (ita) | `grep` |
| the interpreter | class `Script` (28 fields, 20 methods: `Execute`, `Update`, `Listing`, `SkipText`, `Abort`…); 52 of 52 verbs as `#US` literals; 18 Italian error messages | `cilmeta.py members … --type Script` (notes/cilmeta-csharp-script.txt); `clrmeta.py … --userstrings` |

## The sound (FMOD Studio)

| figure | value | command |
|---|---|---|
| banks by magic (RIFF + `FEV ` + length == file) | 482; walked to residue 0: 482 of 482 | `fevbank.py census SA` (notes/fevbank-census.txt); `riffwalk.py SA` (notes/riffwalk.txt) |
| shells (no `SND `) | 62: 60 of 494 bytes (29 `_vo_ita`, 29 `_vo_eng`, 2 `_sfx`) + `master_bank` + `master_bank.strings` | same |
| FSB5 closures | pad + declared == `SND ` chunk: 420 of 420; `SNDH` offset and length agree: 420 of 420; fsb5.py's own closure: 420 of 420 | same |
| FSB5 padding in `SND ` | +0 ×4 … +26 ×122, +30 ×66: 32-byte alignment | same |
| samples | 6,385; FSB5 v1; Vorbis ×420 banks; 48,000 Hz ×6,385; mono 5,003, stereo 1,382; names on 420 of 420 | same; `fevbank.py samples SA` (notes/fevbank-samples.tsv) |
| by kind | `vo_ita` 200 banks / 2,991 samples / 8,895.1 s; `vo_eng` 200 / 2,974 / 8,073.1 s; `sfx` 79 / 389 / 2,364.2 s; `ost` 1 / 31 / 3,780.4 s; total 23,112.8 s = 385.2 min; 450,182,496 sample bytes | same |
| Italian vs English voice | +10.2 % (8,895.1 / 8,073.1) | by hand |
| the same 29 shells | 24 `cut_*` + `inv_gomma_solidificata`, `inv_lettera`, `inv_polvere_sparo`, `loc_presa_armadio`, `loc_tv`, in both languages | `ls -la SA \| awk '$5==494'`, `diff` |
| the join | 175 of 200 banks name an XML file (2 buf, 7 cut, default, 33 dia, 85 inv, 47 loc); 144 exact (eng 148); `default_vo` 67 samples = 67 `<phrase>`; `matrix_vo` 277/278 samples, no file | `_work/voicejoin.py ita`, `eng` (notes/voice-join.txt) |
| chunk ids | 42 distinct; `LIST` 92,017; `BUS ` 18,746; `WAV ` 6,385; `EVTB` 6,242 | `fevbank.py census` |
| `cut_*_sfx` | 31, one sample each on 29, two on 2, as long as the film | `fevbank-samples.tsv` |

## The films

| figure | value | command |
|---|---|---|
| MP4 | 33, 222,398,304 B; `ftyp isom`; box trees closed 33 of 33; sample bytes 222,045,582 (99.84 %) | `mp4box.py census SA/Movies` (notes/mp4box-census.txt); `mp4probe.py` (notes/mp4probe.txt) |
| duration | mvhd 444.639 s, stts 444.622 s; 26,331 access units | same |
| tracks | 31 video-only (AVC High 4.1; 1,920 × 1,080 ×28; 60 fps); 2 with AAC LC 48 kHz stereo (`CG_horizontal`, `TW_gamera_logo`) | `mp4probe.py` |
| films ↔ banks | 31 `cut_*` banks per language for 31 films by name | `ls` |

## The programs

| figure | value | command |
|---|---|---|
| PE files | 161: managed 143 (PE32), native 18 (PE32+: 16 x64, 2 ARM64) | `pecensus.py`, `clrmeta.py --census` (notes/pecensus.txt, notes/clrmeta-census.txt) |
| the player | `The Wardrobe.exe` 667,648 B, 6 sections, COFF 2026-01-27 10:58:40, imports `UnityMain2` + 71 KERNEL32 names; `.rsrc` 565,272 B = 9 icons + version + manifest | `pe.py … --sections --imports --version --resources` (notes/pe-exe.txt) |
| `UnityPlayer.dll` | 35,780,016 B, FileVersion 6000.3.6.45072, 2026-01-27 11:13:20 | `pe.py` (notes/pe-unityplayer.txt) |
| `Assembly-CSharp.dll` | 819,712 B; 379 types, 2,196 fields, 3,136 methods; 164 types in no namespace, 51 `CINIC.*`, 55 `Rewired.*`; `#US` 240,624 B / 6,146 literals | `cilmeta.py members` (notes/cilmeta-csharp-members.txt); `clrmeta.py` (notes/clrmeta-csharp.txt) |
| `Assembly-CSharp-firstpass.dll` | 401,408 B; 494 types, 2,966 fields, 2,975 methods; 395 of the first 400 types `Steamworks.*` | `cilmeta.py members … --limit 400` (notes/cilmeta-firstpass-members.txt) |
| `CINIC.Utility.Platform` | enum `PS4 XboxOne Switch Steam DrmFree` | `cilmeta.py members … --type CINIC.Utility.Platform` |
| console wrappers | `SonyNP.dll` 6.500.7878.26511, `SonyPS4CommonDialog.dll`, `SonyPS4SaveData.dll` (csc 11, 2021-07-27); `XboxOneCommonImport.dll` (2020-04-20); `UsersImport.dll` | `pecensus.py`; `pe.py … --version` (notes/pe-sonynp.txt) |
| deterministic stamps | 136 of 143 managed are hashes (bit 31 set); impossible mtimes 0 of 25 datable; COFF range 2016-03-03 … 2026-05-06 over 16 days | `pecensus.py` (notes/pecensus.txt vs notes/pecensus-before.txt) |
| the studio's build clock | `lib_burst_generated.dll` 2026-05-06 12:29:54 | same |
| signatures | 90 of 161: Unity Technologies SF 86, Microsoft 3, Valve 1 | `authenticode.py` ×90 via `_work/signers.py` (notes/signers.txt) |
| `_DoNotShip` | 1 file, `lib_burst_generated.txt`, 193,524 B | `treecensus.py` |
| Steam furniture | no `steam_appid.txt`, no `.vdf`, no appid literal; `steam_api64.dll` (Valve), `CSteamworks.dll`, Steamworks.NET, `SteamManager`, `'steamdeck'` | `find`, `grep` over the `#US` dump |
| `PlayerSettings` | `CINIC Games` / `The Wardrobe`; versions `1.0`, `1.0`, `2.4.7`; `public.app-category.games`; quality names `Fastest`…`Fantastic` | `_work/hexobj.py D/globalgamemanagers --class 129` |

## The tools

| figure | value | command |
|---|---|---|
| on arrival | 614 `.py`, 0 differing from pc-losthorizon-doc | `toolsdiff.py ../pc-losthorizon-doc/tools --expect-differing 0` (notes/toolsdiff-before.txt) |
| at the end | 617: 3 written (`unitytex22.py`, `wardrobexml.py`, `fevbank.py`), 5 mended (`coverage.py`, `unityfs.py`, `unitytex17.py`, `unitymovie.py`, `pecensus.py`) | same (notes/toolsdiff.txt) |
| selftests | 463 checks, 0 failures over 14 selftests, `PYTHONIOENCODING` unset | `_work/mknotes.py selftests.txt` (notes/selftests.txt) |
| dirguard survey | raised 214, refused 325, exit 0 77 | `dirguard.py --survey --tools tools` (notes/dirguard-survey.txt) |
| rule 0 | see [08](08-tools-predictions-and-calibration.md) | `rule0hook.py --report` (notes/rule0-report.txt) |
