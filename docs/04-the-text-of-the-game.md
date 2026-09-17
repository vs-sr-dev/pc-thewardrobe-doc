# 04 — The text of the game: 1,207 XML files in the clear, a command language of 52 verbs keyed by room status, 3,185 lines per language in six languages with the Italian line as the key, 35 speakers, a six-language diff that is 38 tweaks of timing and not of text, and the interpreter found by name in the assembly

*Measure: `python tools/wardrobexml.py census "TheWardrobe/The Wardrobe_Data/StreamingAssets/XML"` (notes/xml-census.txt), `wardrobexml.py grammar …/XML/ita` and `…/XML/eng` (notes/xml-grammar-ita.txt, -eng.txt), `wardrobexml.py diff …/XML` (notes/xml-diff.txt), `wardrobexml.py lines …/XML/ita` and `voices …/XML` (run locally: the whole script is the game's text and is not published), `python tools/cilmeta.py members … --type Script` and `owners --grep` (notes/cilmeta-csharp-script.txt, -owners.txt), `python tools/clrmeta.py … --userstrings` (run locally).*

## The tree

`StreamingAssets\XML\` holds 1,207 files and 5,421,040 bytes in eight
subtrees (notes/xml-census.txt). The pre-briefing counted 1,208: the
1,208th `.xml` of the install is Mono's `etc\mono\mconfig\config.xml`, and
6 × 179 + 83 + 50 was always 1,207.

| tree | files | bytes | roots | commands | `text` | guarded |
|---|---:|---:|---|---:|---:|---:|
| `areas\` | 50 | 19,068 | `area` 50 | 0 | 0 | 0 |
| `default\` | 83 | 282,813 | `location` 47, `dialog` 33, `inventory`, `setting`, `skinny` | 1,926 | 821 | 0 |
| `deu\` `eng\` `fra\` `rus\` `spa\` | 179 each | 824,548 … 929,882 | `object` 85, `location` 47, `dialog` 33, `script` 6, `intro` 3, `buffer` 2 | 10,674 each | 3,185 each | 2,752 each |
| `ita\` | 179 | 831,536 | the same six | **10,636** | 3,185 | 2,742 |

Every file is well-formed XML (0 of 1,207 fail `xml.etree`), and 47
distinct tags occur. Three of them are misspellings that the parser reads as
unknown elements and the interpreter therefore skips: `<comomand>` in
`objects\bicchiere di birra.xml`, `<comand>` in `locations\cucina1.xml`,
`<hotstpot>` in `objects\peperoncino.xml` — each in all six languages,
because the six trees were copied from one master with the typos in it.

What the trees are:

* **`areas\`** — one `<area bitmask="ROOM" X Y b-scale f-scale>` per room
  with `<angle x y>` vertices: 429 vertices over 50 polygons, the floor the
  hero may walk on, and the scale of his feet at the back and the front of
  it. The `bitmask` is a sprite: [03](03-the-serialized-files-and-the-sprites.md)
  rendered `cameretta`'s by accident and got a black polygon.
* **`default\`** — the new game. `skinny.xml` is one element:
  `<skinny location="cameretta" X="900" Y="-750" pose="dl" map="False"
  transfer="" n_sk="True" n_sf="True" t="0">` with seven `<location name
  open>` map entries (`dump` open, `party museum campsite graveyard beach
  meteorite` closed); `inventory.xml` is `<inventory gs="False"/>`;
  `settings.xml` starts the game in `eng` with text visible and OST, SFX
  and VO at 1.0; `locations\` and `dialogs\` are the initial state of every
  room and dialogue. Seven of the 33 default dialogues are byte-identical to
  their `eng\` copies (notes/hash-repeats.txt): the default tree is the
  English tree with the state attributes reset.
* **`LANG\objects\`** — 85 inventory objects, `<object name>` with a
  `<description>`, an `<inventory>` of combinations with other objects, and
  per-room `<hotspot ID>` scripts: 420 hotspots in Italian. Named in Italian
  with spaces: `bambola voodoo`, `bambola voodoo incompleta`, `bambola voodoo
  funzionante`, `bicchiere di birra`, `bicchiere vuoto`, and `viagra`,
  `plutonio`, `residui_plutonio`, `disco_alieno`, `starter_kit_metallaro`,
  `registrazione_polizia`, `capsaicina`, `jalapeno`, `peperoncino`.
* **`LANG\locations\`** — 47 rooms: `cameretta`, `salotto`, `cucina`,
  `bagno`, `studio`, `scantinato`, `giardino`, `marciapiede`, `vicolo`,
  `discarica`, `cantiere`, `interno_gru`, `museo`, `sala_vikingi_egizi`,
  `sala_botanica_IIWW`, `sala_telecamere`, `accampamento`, `cimitero`,
  `catacomba`, `cripta`, `grotta`, `spiaggia`, `meteorite`, `macchina_tempo`,
  `casa_albero`, `baracca`, `fogna`, `retro_furgone`, `elenco_telefonico`,
  `frigorifero`, `pensile`, `tv`, `bonus`, `intro` … each with a `<script>`
  by room status, an `<indipendent>` loop, `<entry>` points, `<scene bitmap
  X Y position animated>` layers (372 in Italian), `<character ID>` (115
  distinct across the rooms) and `<item ID>` (152 distinct) hotspots with
  `<look>`, `<talk>`, `<use>`, `<pick>`, `<act>`, `<go>` scripts.
* **`LANG\dialogs\`** — 33 dialogue partners: `barista`, `cieco`, `custode`,
  `guardia`, `sfida guardia`, `nonnina`, `ronald`, `robot`, `Z8`, `mummia`,
  `zombie`, `orso`, `coccodrillo`, `dragone`, `eremita`, `frank`,
  `pinhead`, `morpheus`, `quarterback`, `scienziato`, `noce`,
  `diavoletto`, `libro_magia_nera`, `mostro_polvere`, two `audioguida`,
  `tutorial`, `scelta_pezzo`, `scelta_premio`, `non_sapevo_come_chiamarlo`,
  and `sviluppatori` — "developers", in which three characters named
  Francesco, Stefano and Marco answer "Come sarebbe a dire che mi hai creato
  tu?" in the `bonus` room.
* **`LANG\scripts\`** — `cutscenes\` (7 files: timed subtitles over a film,
  `<command>wait 1,5</command>` then `text (2640,150) -c=rrred -w=900 "…"`),
  `buffers\call.xml` (the telephone: a `<script name="666">` per number)
  and `buffers\data_viaggio.xml` (the time machine: `load
  "viaggio_tempo_1863"`, which is a film's name), `documents\` (a letter,
  twice), `transfers\` (two room transitions).
* **`LANG\default.xml`** — 67 `<phrase front sarcastic>` stock refusals in
  `<pick-n>` (7 neutral: "Non mi serve.", "Sta bene lì dov'è."), `<pick-e>`
  (sarcastic: "Mi prendi in giro?"), `<talk>`, `<use>`.

## The command language

Every script is `<command>` lines. Read from 64,000 of them (10,636 in
Italian, 10,674 × 5 in the others, 1,926 in `default\`), the shape is:

    <command>[GUARD] VERB [TARGET] [FLAGS...] [ARGS...] [N] [$K]</command>

    GUARD    a room status the line runs under: 0, 1, 2 … 7, or a set 0-1-2 (2,742
             guarded commands in Italian; 0 ×1,432, 1 ×591, 2 ×244, 3 ×138, 0-1 ×84, 4 ×81 …)
    VERB     one of 52 (table below)
    TARGET   -"name", +"name", >"name", #"name", or bare -skinny / -ost: what the verb acts on
    FLAGS    -c=colour  -w=width  -o=x,y  -f=frames  -s=speed  -l  -a  -x  -g  -i  -nc  -fo=ms  -=a=anchor
    ARGS     "quoted strings", (x,y) points, numbers with a DECIMAL COMMA: wait 0,5
    N        a trailing integer on text: the line's number inside its block — the voice banks' sample name
    $K       a trailing $64-style tag on 473 Italian text lines: a reference to a shared line

The 52 verbs of the Italian tree, with counts (notes/xml-grammar-ita.txt;
the English tree has the same 52):

| verb | count | verb | count | verb | count | verb | count |
|---|---:|---|---:|---|---:|---|---:|
| `text` | 3,185 | `throw` | 122 | `stop` | 58 | `map` | 13 |
| `wait` | 1,541 | `goto` | 110 | `achievement` | 47 | `destination` | 13 |
| `expression` | 804 | `pick` | 110 | `load` | 38 | `bitmask` | 11 |
| `pose` | 509 | `status` | 108 | `nolook` | 33 | `background` | 10 |
| `sound` | 493 | `pause` | 86 | `cutscene` | 33 | `position` | 9 |
| `animation` | 485 | `resume` | 85 | `area` | 29 | `label` | 7 |
| `internal` | 484 | `fie` | 85 | `move` | 28 | `viewer` | 4 |
| `hide` | 482 | `default` | 84 | `buffer` | 25 | `document` | 3 |
| `show` | 427 | `screen` | 71 | `ost` | 24 | `name`, `transfer`, `tutorial`, `check`, `quake`, `block`, `scroll`, `camera` | 2 each |
| `bitmap` | 424 | `dialog` | 64 | `inventory` | 20 | `credits`, `end` | 1 each |
| `if` | 234 | `lookat` | 60 | `blackscreen` | 14 | | |
| `fi` | 146 | | | | | | |

`if … fie … fi` is if-else-endif (`if not internal -"cocktail" 0` … `fie`
… `fi`); `internal -"x" -g 1` sets a hotspot's internal state and `if
internal` reads it; `status >"cameretta" 3` sets a room's status and the
GUARD reads it; `expression "sarcastic"` and `pose d` are the hero's face
and facing (the assembly's literals list `normal happy sad angry suffering
terrified sarcastic perplexed scared` and `u ur r dr dl l ul`);
`animation -skinny 00 -o=-12,56 -f=7,2,14 -s=90 "skinny_versa_birra1"`
plays a sprite sheet of [03](03-the-serialized-files-and-the-sprites.md)
with an offset, a frame list and a speed; `bitmap -"custode" "custode_l"`
swaps a character's sprite; `cutscene -s "outro3"` plays a film of
[06](06-the-films-and-the-programs.md); `achievement "maestro_spada"`
names one of 27 achievements (`maestro_spada` ×15, `pixel_hunting` ×4,
`tentato_omicidio` ×3, and one each of `666`, `bianconiglio`,
`undertale_spoiler`, `tu_quoque_prunus`, `peggior_videogioco`,
`viaggiatore_del_tempo`, `speedrun`, `esorcista`, `contatto_alieno` …);
`default e -pick` speaks a sarcastic stock refusal from `default.xml` and
`default n -pick` a neutral one. `pick n "premio"`, `throw "buono"`,
`inventory`, `map "meteorite"`, `document "locandina"`, `credits`, `end`.

The `0`, `1`, `2` the first scan counted as verbs (1,443 + 589 + 244) are
guards: `<command>1 text -"ciccione" "Posalo pure sulla pensilina della
vasca."</command>` runs when the bathroom is in status 1. That is also why
the pre-briefing's "2,651 `text` commands" is short: 2,651 are the
unguarded ones; with the 534 under a guard, **every language has 3,185**.

## Who speaks

A `text` line names its speaker as a target or not at all. Counting the
Italian tree's 3,185 (the English tree gives the same table):

| speaker | lines | who |
|---|---:|---|
| (no target) | 2,267 | **Skinny**, the player's skeleton |
| `-"me"` | 494 | **the character the file belongs to** — the object's owner, the dialogue's partner: in `anelli.xml` a pharaoh's daughter, in `bibbia.xml` a drunk "gesoo", in `dentiera.xml` an old woman, in `Z8.xml` a robot in yellow |
| `altoparlante` | 68 | a loudspeaker |
| `tutorial` | 60 | the tutorial voice |
| `guardia` | 57 | a night guard who hates Halloween |
| `skinny_mic` | 41 | Skinny into a telephone |
| `custode` | 29 | a caretaker |
| `Francesco`, `Frank`, `Orso`, `Noce`, `inventory`, `eremita`, `Boogeyman`, `teppistello1`, `inserviente_left`, `Due`, `giostraio`, `Uno`, `Tre`, `inserviente_up`, `Stefano`, `Marco`, `Egon`, `teppistello2`, `nonnina`, `toro_skinny`, `giocatore_basso`, `ciccione`, `diavoletto`, `barman`, `zombie`, `ronald`, `zingara`, `telecamera2` | 19 … 1 | 28 more |

35 speakers. The pre-briefing had "a skeleton named skinny who is `me`":
the bytes say the opposite — `me` is whoever the file is about, and Skinny
is the line with no name on it. `-c=lblue`, `-c=yellow`, `-c=rrred`,
`-c=white` colour a speaker's lines; `-"me" -c=lblue "..."` in `barista.xml`
is a barman who never says a word.

The 115 `<character ID>` of the rooms are the cast Skinny meets, and the
names are the joke: `Aku Aku`, `Angry Bird`, `Flowey`, `Sigmund Freud`,
`Sir Daniel Fortesque`, `Pinhead addormentato`, `Morpheus`, `Illuminati`,
`Manet`, `king kong`, `t-rex`, `moai`, `Olandese Volante`, `diario di Tom
Riddle`, `moglie di Frankenstein`, `crash test dummy`, `maggiore T.J.
Kong`, `Giuda`, `cactus ballerini`, `teste in salamoia`, `I tre fratelli
Orco`, `Johnny Express`, `Winston`, `Wally`, `Z8`, `ronald`, `scheletro`.

## The story, as the intro writes it

`scripts\cutscenes\intro.xml` (root `<intro>`, 8 `text` lines at
(960,1050) in white over the film `intro.mp4`, 65.5 s) is the premise in
the studio's own words, Italian tree:

> Ronald e Skinny, come accadeva spesso, erano usciti per fare un picnic e
> trascorrere la giornata nelle campagne vicine. … Ad un tratto Ronald tirò
> fuori dal suo cestino un paio di piccole prugne e ne porse una all'amico.
> … Mmm… deliziosa. … Deliziosamente… MORTALE! … Una nuova fiammella di vita
> venne instillata nel corpo di Skinny, ormai ridotto in scheletro… e
> SBATTUTO all'interno dell'armadio di Ronald, perchè vegliasse su di lui per
> il resto dei suoi giorni.

Two boys, a picnic, a plum (`tu_quoque_prunus` is an achievement), a
skeleton in a wardrobe: the title. The rooms then run from `cameretta` to
`cimitero`, `museo`, `spiaggia-1861`, `spiaggia-1981` (the time machine's
`viaggio_tempo_1863` and `_1981` films), `meteorite` and `matrimonio`
(a wedding film, 20.7 s, and the `anelli` object). Nothing beyond this is
derived: no plot summary is written that the bytes do not spell.

## The six languages, and the diff

The key is Italian. Every `<voice ID="…" name="…">` in every tree carries
the Italian option text as `ID` and the language's own as `name` — 178
`<voice>` per tree, 171 distinct IDs, **the same 178 in all six**
(notes/xml-diff.txt's last block). `wardrobexml.py voices` lays them side
by side, 178 rows by six columns; one row, from `dialogs\Z8.xml`:

| ID (ita) | deu | eng | fra | rus | spa |
|---|---|---|---|---|---|
| Computer, riposo. | Computer, deaktivieren! | Computer, deactivate! | Ordinateur, désactivation ! | Компьютер, отключись! | Computadora, cierra sesión. |

The command lines are compared as **skeletons** — guard, verb, target
sign, flags, trailing number, and not the quoted string — so a translation
of a file has the same skeleton as its original and a dropped or added
command does not. Against `ita`:

| tree | files | same skeleton | differ | verb delta, tree − ita |
|---|---:|---:|---:|---|
| `deu` `eng` `fra` `rus` `spa` | 179 | 98 | 81 | `wait` +19, `expression` +15, `animation` +4, `lookat` +1, `sound` +1, `internal` −1, `pose` −1, **`text` 0** |

**The five translations are identical to each other line for line** (their
81 differing files and their deltas coincide), and the 38 commands they have
over the Italian are not dialogue: nineteen `wait`s, fifteen `expression`s,
four `animation`s. The Italian tree is the master that kept being edited
after the translations were cut from it — timings and faces trimmed, in 81
files (32 rooms, 23 dialogues, 23 objects, 3 scripts), 21 of them with the
same command count and a different order. The pre-briefing's hunch that
the 38 were "text lines merged or split in translation" is wrong on the
verb: `text` is 3,185 in all six.

Where the update touched the text: 36 of the 1,207 files carry the 2026
clock — `dialogs\tutorial.xml`, `locations\bagno.xml`, `bagno1.xml`,
`discarica.xml`, `interno_gru.xml`, `objects\magnete.xml`, six languages
each ([07](07-steam-the-two-generations-and-the-clocks.md)); five of the
six are also among the 81 the Italian tree differs on.

## The interpreter, by name

`Assembly-CSharp.dll` (379 types, 2,196 fields, 3,136 methods; 164 types
in no namespace, 51 under `CINIC.*`) has a class **`Script`** with 28
fields and 20 methods: `List`, `Index`, `VoiceOver`,
`VoiceOverParameterName`, `InIf`, `IfGuard`, `IfInternal`, `Talkie`,
`WaitTimer`, `QuakeTimer`, `PixelToQuake`, `ScrollingTimer`,
`CameraDestination`, `Text`; `Execute`, `Update`, `Listing`, `SkipText`,
`StopTalkie`, `Abort` (notes/cilmeta-csharp-script.txt). `Hotspot` has a
`NoLook` field, `Location` a `Status`, `Voice` a `text` and a `Status`,
`CutsceneScript` a `blackscreen`, `Global` a `BlackScreen` and a `Cutscene`.
And **all 52 verbs are literals in the assembly's `#US` heap** — `'fie'
'wait' 'lookat' 'expression' 'animation' 'quake' 'nolook' 'blackscreen'
'achievement'` in one run — with the flags (`'-c=' '-w=' '-pick' '-use'
'-talk'`), the target signs (`'-"' '#"' '>"' '@"'`), the poses, the
expressions, `'/XML/default/skinny.xml'`, an XPath
`"/skinny/location[@name='"`, and eighteen error messages in Italian:
`COMANDO ERRATO`, `HOTSPOT NON TROVATO`, `SECONDO HOTSPOT NON TROVATO`,
`FILE NON TROVATO`, `BUFFER NON INIZIALIZZATO`, `SKINNY TALKIE NON
TROVATA`. One interpreter, one `Execute`, a string per verb: the
pre-briefing's "a method per verb" is half right (one class) and half not.
Whether `Execute` switches on those strings is IL, which was not read.

## What is not read

The script was not executed and no room was walked; the `$K` references
were counted (473) and not resolved; the `<scene>` layers and `<entry>`
points were counted and not laid out; the 1,542 MonoBehaviours that hold
the rooms' runtime state were not opened. The whole script text is in
`notes/`'s reach with one command and is not published here.
