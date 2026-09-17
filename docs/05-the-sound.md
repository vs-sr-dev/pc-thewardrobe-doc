# 05 — The sound: 482 FMOD Studio banks walked to residue 0, 420 FSB5 closed twice, 6,385 Vorbis samples at 48 kHz, 148 minutes of Italian voice against 135 of English, 62 banks with no sound, and a join in which the samples are named by the line numbers of the script

*Measure: `python tools/riffwalk.py "TheWardrobe/The Wardrobe_Data/StreamingAssets"` (notes/riffwalk.txt), `python tools/fevbank.py census …/StreamingAssets` (notes/fevbank-census.txt), `fevbank.py samples` (notes/fevbank-samples.tsv), `fevbank.py tree …/ost.bank | …/loc_bagno_vo_ita.bank | …/master_bank.strings.bank | …/cut_outro1_vo_ita.bank` (notes/fevbank-tree-*.txt), `python tools/fsb5.py walk …/ost.bank` (notes/fsb5-refuses-bank.txt), `python _work/voicejoin.py ita|eng` (notes/voice-join.txt).*

## The container, and where the box stopped

`StreamingAssets\` holds 482 `.bank` files, 457,534,468 bytes, 13.09 % of
the install. `riffwalk.py` closes every one as a RIFF with form `FEV ` at
residue 0 and stops there: it knows RIFF and not FMOD Studio. `fsb5.py`
knows the sample bank FMOD Studio puts inside and refuses the file ("does
not begin with FSB5"): right, and useless, since the FSB5 is not at byte 0.
`coverage.py` had no probe between the two and filed all 482 as opaque
([08](08-tools-predictions-and-calibration.md)). `fevbank.py` is the walker
in between, and this is the container as its bytes read:

    RIFF <length> "FEV "                length + 8 == the file, 482 of 482
      FMT  8
      LIST PROJ                         the project: BNKI (a GUID and a count),
                                        LIST IBSS / GBSS / MBSS (buses: 18,746 BUS
                                        chunks over the object), LIST EVTS (6,242
                                        EVTB events), LIST TLNS (timelines), LIST
                                        WAIS (6,516 wave instances), LIST WAVS
                                        (6,385 WAV records of 30 bytes — one per
                                        sample), SNDH, STDT, STBL, HASH, DEL, MUTE,
                                        REFI, PLAT ...
      SND  <length>                     ONE FSB5, after 0..30 bytes of padding
                                        that aligns it to 32

Every chunk lies inside its parent and the walk ends on the last byte on
482 of 482; 92,017 `LIST` chunks and 42 distinct chunk ids over the object
(notes/fevbank-census.txt). The pre-briefing had the FSB5 "at +0 of the
chunk": measured, it sits at +0 on 4 banks, +26 on 122, +30 on 66, +14 on
40 — sixteen even offsets, whatever 32-byte alignment demands.

**Two closures on every sample bank.** The FSB5's own header declares its
three block sizes, and `60 + headers + names + data` must equal what the
`SND ` chunk holds after the padding: **420 of 420**. And `SNDH`, twelve
bytes inside `LIST PROJ` — `u16 u16` (3, 8 everywhere), `u32` absolute
offset of the FSB5, `u32` its length — agrees with the walk's own offset
and the FSB5's own length on **420 of 420**: FMOD wrote the answer down
twice and the reader found both.

## The census

| kind (by file name) | banks | shells | samples | seconds | file bytes | sample bytes |
|---|---:|---:|---:|---:|---:|---:|
| `_vo_ita` | 200 | 29 | 2,991 | 8,895.1 = **148.3 min** | 169,611,414 | 166,342,720 |
| `_vo_eng` | 200 | 29 | 2,974 | 8,073.1 = **134.6 min** | 157,054,902 | 153,826,176 |
| `_sfx` | 79 | 2 | 389 | 2,364.2 = 39.4 min | 44,070,844 | 43,592,128 |
| `ost` | 1 | 0 | 31 | 3,780.4 = 63.0 min | 86,498,816 | 86,421,472 |
| `master_bank` | 1 | 1 | 0 | | 5,684 | |
| `master_bank.strings` | 1 | 1 | 0 | | 292,808 | |
| **all** | **482** | **62** | **6,385** | **23,112.8 = 385.2 min** | **457,534,468** | **450,182,496** |

All 420 sample banks are FSB5 version 1, codec 15 (Vorbis), 48,000 Hz on
6,385 of 6,385 samples, mono on 5,003 and stereo on 1,382, with a name
table on 420 of 420. The seconds are `samples ÷ rate` from the sample
headers; no audio was decoded. **Two spoken languages against six written:
Italian voice is 10.2 % longer than English** (8,895 s against 8,073 s) —
over the pre-briefing's "under 10 %", by a hair.

**Sixty-two banks carry no `SND `.** Sixty are 494-byte shells — `FMT `,
a `LIST PROJ` of nothing and no sound — and two are `master_bank.bank`
(5,684 bytes: the project's own buses, effects and snapshots — 11 `BUS `, 5
`EVTB`, 5 `SNAB` — and no sound) and
`master_bank.strings.bank` (292,808 bytes, a `STDT` chunk of 292,313 that is
the event-name table in a packed, trie-like form — single characters with
24-bit links — counted and not decoded). The sixty are **the same 29 names
in both voice languages** plus two effect banks, `loc_marciapiede_sfx` and
`loc_toppa_bagno_sfx`: 24 cutscenes (`cut_armadio_discarica`, `cut_arrivo_pacco`,
`cut_casa_a_fuoco`, `cut_ciccione_fuga`, `cut_estrazione_ingranaggi`,
`cut_evoluzione_mostro`, `cut_foto_telecamera`, `cut_fuga_ladro`,
`cut_furgone`, `cut_ingresso_catacomba`, `cut_johnny`,
`cut_nonnina_spaventa_ragazzini`, `cut_outro1`, `cut_outro2`,
`cut_pala_custode`, `cut_pittore_dipinge`, `cut_pomello_excalibur`,
`cut_pomello_fiamma_ossidrica`, `cut_ripresa_trasloco`, `cut_skinny_matrix`,
`cut_sveglia_barbone`, `cut_viaggio_tempo_1863`, `_1981`, `_back`) and five
that are not: `inv_gomma_solidificata`, `inv_lettera`, `inv_polvere_sparo`,
`loc_presa_armadio`, `loc_tv` — the two rooms and the three objects whose
XML has no spoken line (`presa_armadio.xml` and `tv.xml` are byte-identical
in all six languages: nothing in them to translate). The pre-briefing's
"the same 29 cutscenes" is right on the 29 and wrong on the cutscenes: 24
of 29.

## The join: banks named for files, samples named for lines

The 200 voice banks per language are the XML tree of
[04](04-the-text-of-the-game.md) by name: 85 `inv_OBJECT` for the 85
objects (spaces and all: `inv_bambola voodoo funzionante_vo_ita.bank`), 47
`loc_ROOM` for the 47 rooms, 33 `dia_PARTNER` for the 33 dialogues, 2
`buf_` for the two buffers, 31 `cut_` for 31 of the 33 films, `default`
for `default.xml`, and one `matrix` that names no file — 2 + 31 + 1 + 33 +
85 + 47 + 1 = 200.

Inside a bank the samples are named with **numbers**: `loc_bagno_vo_ita`
holds 45 samples named `6 1 1 8 7 1 12 1 1 1 1 1 3 5 1 1 4 2 …`, and
`bagno.xml` holds 45 `text` lines; a sample's name is the line's position
inside its block (most blocks have one line, hence the ones), and the
explicit trailing `N` on 147 Italian lines (`text "Questa potrebbe
aiutare?" 2`) is the same number written out where a hotspot has several.
The `$K` tags (473 lines) point at a line kept elsewhere and have no sample
of their own. The join over 200 banks (notes/voice-join.txt):

| kind | banks | XML file found | samples = text lines − `$` | samples | lines − `$` |
|---|---:|---:|---:|---:|---:|
| `loc` | 47 | 47 | 33 | 1,452 | 1,467 |
| `dia` | 33 | 33 | 27 | 797 | 824 |
| `inv` | 85 | 85 | 76 | 268 | 292 |
| `buf` | 2 | 2 | 2 | 111 | 111 |
| `cut` | 31 | 7 | 6 | 19 | 18 |
| `default` | 1 | 1 | — | 67 | 67 `<phrase>` |
| `matrix` | 1 | 0 | — | 277 | — |
| **all** | **200** | **175** | **144** | **2,991** | |

**175 of 200 banks name an XML file; on 144 of them the sample count is
exactly the file's spoken lines; `default_vo_ita`'s 67 samples are
`default.xml`'s 67 stock refusals, voiced.** The English join is the same
shape (148 exact of 175). The 25 without a file are the 24 cutscene shells
(no lines, nothing to name) and `matrix_vo_*`, 277 Italian and 278 English
samples numbered 1 … 277 and 12.4 minutes of voice for a scene no XML
file carries by that name (the assembly has `'/matrix/'` as a literal and
`skinny_matrix` is a film). Of the 31 not exact, the differences are small
(`dia_barista` 13 samples for 18 lines: the mute barman's `"..."` lines have
no voice) except `dia_sfida guardia` (39 for 57) and `matrix`.

## The music and the effects

`ost.bank` is 31 stereo samples, 63.0 minutes, 86,421,472 bytes of Vorbis
— the soundtrack, named by its samples (notes/fevbank-tree-ost.txt). The 79
`_sfx` banks are 47 `loc_ROOM_sfx`, 31 `cut_FILM_sfx` and one
`default_sfx`: 389 samples, 39.4 minutes; the 31 `cut_*_sfx` are special — **29 hold one sample as long as
their film, two hold two** (`cut_casa_a_fuoco`, `cut_ciccione_fuga`) —
`cut_intro_sfx` 66.0 s against `intro.mp4`'s 65.5 s,
`cut_outro2_sfx` 60.3 against 60.2, `cut_armadio_discarica_sfx` 8.0 against
7.4): the cutscene's whole soundtrack in one Vorbis stream, because 31 of
the 33 films have no audio track of their own
([06](06-the-films-and-the-programs.md)).

## The bucket, and what is not read

`FEV ` and FSB5 are FMOD's, unpublished. Public third-party readers exist
for both (vgmstream reads the `SND ` chunk of exactly this container; the
FSB5 sample header has been read by python-fsb5 and vgmstream for years),
so `coverage.py` files them as DECODED; the chunk names above are what the
four-letter ids say and what the counts make of them, and FMOD's own names
for the fields are not derived. Not read: the Vorbis inside (no sample
decoded, no minute listened to), the event and bus records beyond their
counts, the `.strings` table, and which line `$56` is.
