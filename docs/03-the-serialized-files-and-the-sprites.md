# 03 — The serialized files and the sprites: format 22 read from a hex dump, 1,161 textures closed twice, 17,368 sprites closed once, five sidecars tiled to within 229 bytes, and the first picture the box ever rendered from Unity 6 was the skeleton

*Measure: `python tools/unityfs.py info "TheWardrobe/The Wardrobe_Data/globalgamemanagers"` (notes/unityfs-ggm.txt), `unityfs.py census` and `verify` (notes/unityfs-census.txt, notes/unityfs-verify.txt), `python tools/unitytex22.py census|sidecars|sprites "TheWardrobe/The Wardrobe_Data"` (notes/unitytex22-census.txt, -sidecars.txt, -sprites.txt), `python _work/texfields.py` (notes/unitytex22-fields-and-gaps.txt), `python tools/unitytex22.py render … --sprite NAME --out FILE` (the renders stay in `_work/`).*

## The container: 105 files, and 48 bytes that were not a new field

`unityfs.py` (written at format 21 on an Android object, extended to 22 on
DISSIDIA) reads all 105 serialized files of `The Wardrobe_Data\`: 28,593
objects, every file declaring its own length correctly, every object inside
its file. The population is a 2D game's:

| class | objects | in-file bytes | share |
|---|---:|---:|---:|
| Sprite (213) | 17,368 | 34,745,284 | 14.31 % |
| GameObject (1) | 2,452 | 132,128 | 0.05 % |
| Transform (4) | 1,692 | 134,700 | 0.06 % |
| MonoBehaviour (114) | 1,542 | 3,541,652 | 1.46 % |
| MonoScript (115) | 1,435 | 169,872 | 0.07 % |
| SpriteRenderer (212) | 1,177 | 244,816 | 0.10 % |
| Texture2D (28) | 1,161 | 193,903,136 | 79.84 % |
| Shader (48) | 111 | 1,623,760 | 0.67 % |
| ComputeShader (72) | 11 | 5,429,376 | 2.24 % |
| Font (128) | 8 | 624,264 | 0.26 % |
| Mesh (43) | 13 | 153,776 | 0.06 % |
| 50 × `level` files | RenderSettings, LightmapSettings, NavMeshSettings, LightingSettings, one PreloadData each | | |

Rows from notes/unityfs-census.txt; the share is of in-file bytes, and the
1,161 textures own 79.84 % of them before the sidecars are counted.

`info` printed `metadata size 1292 (parsed to 1340)` on `globalgamemanagers`
and `498527 (parsed to 498575)` on `resources.assets`: 48 bytes over, both
times. The pre-briefing read that as a version-22 field the reader walked
past without knowing. It is not. On pc-monstrum-doc, at format 17, the same
line read `1292 (parsed to 1312)`: **20 bytes**, the size of the old header,
counted once by the file (`metadataSize` starts after it) and once by the
reader (the parse position starts at byte 0). Format 22 moved the length
fields to 64-bit words and the header grew from 20 bytes to 48. The 48 are
the header. `unityfs.py info` now prints `metadata size 1292, after a
48-byte header = 1340; parsed to 1340   agrees`, and `verify` counts the
closure on every file: **105 of 105 parse their metadata to exactly header +
metadataSize** (notes/unityfs-verify.txt). The object table was never
misplaced — `dataOffset` is 1,344, the parse end rounded up to 16.

## The Texture2D at format 22, read from two bodies

`unitytex17.py` reads the version-17 layout and refuses this object by name
([08](08-tools-predictions-and-calibration.md)). The layout at 22 was read
from the hex dump of two bodies in `sharedassets0.assets` — `Background`
(32 × 32 RGBA32, 6 mips, streamed, 152 bytes) and `BradyBunchUltimate SDF
Atlas` (1,024 × 1,024 Alpha8, inline, 1,048,716 bytes) — and is what
`unitytex22.py` parses:

    aligned string  m_Name
    4 bytes         new since 17: byte 0 is 1 on exactly the 109 textures whose format has
                    no alpha channel (RGB24 ×18, DXT1 ×91) and 0 on the 1,052 that have one
    i32 i32 i32     m_Width, m_Height, m_CompleteImageSize
    i32             m_MipsStripped              new
    i32 i32         m_TextureFormat, m_MipCount
    u8 u8 u8        m_IsReadable, m_IsPreProcessed, m_IgnoreMipmapLimit (new); align 4
    aligned string  m_MipmapLimitGroupName      new
    u8              m_StreamingMipmaps (new); align 4
    i32             m_StreamingMipmapsPriority  new
    i32 i32         m_ImageCount, m_TextureDimension
    i32 i32 f32     filter, aniso, mip bias
    i32 i32 i32     wrap U, V, W                three wrap modes; 17 had one
    i32             m_LightmapFormat
    i32             m_ColorSpace                new
    i32 + bytes     m_PlatformBlob, align       new; 0 bytes on every texture here
    i32 + bytes     image data, align           0 when streamed
    u64 u32 string  m_StreamData: offset (u64; 17 had u32), size, path

Unity's names for the four bytes after the name are not derived; what the
bytes say is that byte 0 behaves as "the alpha channel is optional" and the
other three are 0 on 1,161 of 1,161.

**Two closures on every texture**, as on 17: the body ends exactly where the
last field ends (padding 0), and `m_CompleteImageSize` equals the sum of the
mip levels by the format's bits per pixel, with the stream record (or the
inline block) the same size. **1,161 of 1,161 close both ways.** The formats:

| format | count | bytes | decoded here |
|---|---:|---:|---|
| DXT5 (12) | 735 | 1,965,279,808 | yes |
| RGBA32 (4) | 236 | 549,197,496 | yes |
| DXT1 (10) | 91 | 58,669,856 | yes |
| Alpha8 (1) | 49 | 4,753,765 | yes |
| ARGB4444 (2) | 32 | 137,408 | yes |
| RGB24 (3) | 18 | 81,713,331 | yes |

2,659,751,664 bytes of pixels in all: 960 textures streamed into the five
sidecars, 195 inline (158 of them in `resources.assets`, 36 in Unity's own
`unity default resources`, one SDF font atlas in `sharedassets0.assets`),
6 with no pixels (0 × 0 dynamic font atlases). By size: **99 textures are
1,920 × 1,080** and 44 are 512 × 288 (their quarter-scale twins); 125 are
named `sheet0`…`sheetN` — DXT5 animation sheets up to 4,092 × 2,740 — and
561 of the 1,053 textures in `resources.assets` are at least 1,000 pixels
wide. Six of the 105 files hold textures at all: `resources.assets` 1,053,
`globalgamemanagers.assets` 48, `unity default resources` 37,
`sharedassets2.assets` 16, `sharedassets1.assets` 5, `sharedassets0.assets` 2.

## The five sidecars, tiled by their siblings' records

The coverage table files the five `.resS` as DERIVED because every stream
record of a sibling file lies inside them; `unitytex22.py sidecars` says how
much of each the records reach:

| sidecar | bytes | records | reached | gaps | ends at |
|---|---:|---:|---:|---|---|
| `resources.assets.resS` | 2,432,582,144 | 892 | 2,432,582,144 | 24 gaps, 201 bytes (4, 8, 12 and once 13 bytes) | the last byte |
| `globalgamemanagers.assets.resS` | 5,716,192 | 48 | 5,716,192 | none | the last byte |
| `sharedassets1.assets.resS` | 2,397,456 | 4 | 2,397,456 | 1 gap, 8 bytes | the last byte |
| `sharedassets2.assets.resS` | 25,317,008 | 15 | 25,317,000 | none | 8 bytes short |
| `sharedassets0.assets.resS` | 5,472 | 1 | 5,460 | none | 12 bytes short |

960 records, no overlap, **2,466,018,043 of 2,466,018,272 bytes reached:
229 bytes in 27 places are the slack between records aligned to 4, 8 or 16,
and the two short tails are the same slack at the end of a file.** Three of
five tile to the exact last byte; the pre-briefing's "to the last byte" is
right to within 0.00001 % and wrong by 229 bytes, and the number is written
instead of the adjective.

## The Sprite at format 22, and why the pictures are the sprites

A texture here is a sheet; the picture the game draws is a `Sprite`, which
names a texture and a rectangle in it. Read from the 576-byte body of
`Background` in `sharedassets0.assets` and closed on every sprite of the
census:

    aligned string  m_Name
    f32 ×4          m_Rect                      x, y, w, h in texture pixels
    f32 ×2, ×4      m_Offset, m_Border
    f32             m_PixelsToUnits
    f32 ×2          m_Pivot
    u32, u8+align   m_Extrude, m_IsPolygon
    16 bytes + i64  m_RenderDataKey
    vector<string>  m_AtlasTags
    PPtr            m_SpriteAtlas               (0, 0) on every sprite here
    PPtr            m_RD.texture                fileID, pathID: THE PICTURE
    PPtr            alphaTexture; vector secondaryTextures
    vector<48 B>    m_SubMeshes; bytes m_IndexBuffer; u32 vertexCount;
                    vector<4 B> channels; bytes vertex data; vector<64 B> m_Bindpose
    f32 ×4          m_TextureRect               the rectangle IN the texture
    f32 ×2, ×2      m_TextureRectOffset, m_AtlasRectOffset
    u32             m_SettingsRaw               bit 0 packed, bits 2–5 rotation, bit 6 tight mesh
    f32 ×4, f32     m_UVTransform, m_DownscaleMultiplier
    vector<vector<Vector2>>  m_PhysicsShape
    vector          m_Bones (0 everywhere); aligned string m_SpriteID

**17,368 of 17,368 sprites close** on their body end. Every one names a
texture in its own file (fileID 0; no external, no null); together they name
1,064 of the 1,161 textures — the 97 unnamed being the font atlases,
Unity's default resources and the UI's own. 16,735 have a tight mesh, 0 are
packed, 0 rotated, 0 polygon; 17,287 are at 1 pixel per unit (a pixel-exact
2D game), 44 at 26.67, 27 at 100. 341,300 vertices and 894,291 indices in
all — the tight meshes are the sprites' outlines, and a render ignores them
and cuts the rectangle.

The sprites live where the textures do: `resources.assets` 17,350,
`sharedassets2.assets` 12, `sharedassets1.assets` 4, and one each in
`sharedassets0.assets` and `globalgamemanagers.assets`. The commonest
rectangles: 587 × 181 ×206, 48 × 58 ×144, 145 × 145 ×144, 221 × 504 ×140,
579 × 432 ×119, **1,920 × 1,080 ×99**. The textures with the most sprites
on them, by name: `ingranaggio` 250, `pianta_carnivora` 207, `pale_mulino`
and `pale_mulino_notte` 193 each, `ruota_panoramica` 180, `objects` 171,
`timer_bomba` 144, `orologio_pizza` 144, `flowey_glitch` 138, `piccioni`
108 — a gear, a carnivorous plant, windmill blades by day and by night, a
ferris wheel, the inventory sheet, a bomb timer, a pizza clock, a glitching
flower, pigeons: animation frames of the world, not of the hero. The
skeleton is 2,066 sprites named `skinny_*`: `skinny_arpione` 144 frames,
`skinny_accoltella_bambola_voodoo` 61, `skinny_massaggia_testa` 56,
`skinny_versa_birra_urinatoio` 49, `skinny_urna` 49 … and single poses
`skinny_attende`, `skinny_dorme`, `skinny_acqua`.

## The 99 backgrounds, and eighteen screens for consoles

The 99 sprites at 1,920 × 1,080 are named for the rooms of
[04](04-the-text-of-the-game.md) — `cameretta`, `salotto`, `cucina`,
`bagno`, `studio`, `scantinato`, `cripta`, `grotta`, `museo`, `spiaggia`,
`spiaggia-1861`, `spiaggia-1981`, `macchina_tempo`, `casa_albero`,
`baracca_giorno`, `baracca_notte`, `interno_gru`, `retro_furgone` … many
twice (a day and a night, a before and an after: `cameretta_ronald`,
`cameretta_traslocata`, `salotto_traslocato`, `studio_esploso`) — plus
`menu_ronald`, `menu_noronald`, `logo`, `logo_the_wardrobe`, `map`,
`error_message`, `blackscreen`, and **eighteen named `PS4_ITA`, `PS4_ENG`,
`PS4_FRA`, `PS4_DEU`, `PS4_SPA`, `PS4_RUS`, `XONE_*` ×6 and `SWITCH_*`
×6**: a controller-layout screen per platform per language, in a Windows
build. The programs carry PS4 and Xbox One wrappers
([06](06-the-films-and-the-programs.md)); the sprites add a Switch nobody's
DLL names.

## The renders, and what the owner said

`unitytex22.py render` finds a sprite by name, loads the texture its PPtr
names, decodes it with `unitytex.py`'s DXT1/DXT5/RGBA decoders, and cuts
`m_TextureRect` out of the top-down rows. Six were rendered and five sent;
the renders stay in `_work/` and are not published.

| sprite | texture | what it showed |
|---|---|---|
| `skinny_attende` (path 12419) | `sheet0`, 3,792 × 2,100 DXT5, rect 3394,942 167 × 510 | **the first picture: a skeleton in a green hoodie with red lettering on the chest, arms folded** — sent within a minute of the layout closing |
| `menu_ronald` (path 2023) | its own 1,920 × 1,080 DXT1 | a wall of pinned photographs of two boys, one blond in a yellow T-shirt, one dark-haired in the green hoodie: the menu |
| `PS4_ITA` (path 1131) | its own 1,920 × 1,080 DXT1 | a DualShock with Italian labels: ACCELERA CURSORE, MOSTRA HOTSPOT, MAPPA, INVENTARIO, AZIONE |
| `cameretta` (path 1268) | `cameretta`, 2,020 × 383 RGBA32 | **a black shape on transparency — not the room but its walk mask.** `areas\cameretta.xml` is `<area bitmask="cameretta" X="0" Y="697">` with `<segment color="black" footstep="footstep"/>`: the sprite the area names, placed at y = 697 in a 1,080-high room and 383 rows tall — 697 + 383 = 1,080, the floor strip exactly; black is the walkable floor that sounds of footsteps, 78.8 % of the 1,978 × 383 rectangle (x 44 … 2,019 in room coordinates: the room scrolls, its textures are 2,020 wide); the nine `<angle>` vertices (x 134 … 1,914) lie inside it and carry `b-scale` 0.47 / `f-scale` 0.7, the hero's size at the back and the front. Three sprites carry the name `cameretta` (2,020 × 383, 512 × 288, 1,920 × 1,080) and `render --sprite` took the first (`_work/maskbbox.py`) |
| `cameretta` (path 1683) | its own 1,920 × 1,080 DXT1 | the bedroom the game starts in (`default\skinny.xml`: `location="cameretta"`): a bed, a Union Jack rug, an arcade cabinet, two guitars, shelves, a poster, "the cake is a lie" written on the wall |
| the player's icon | `The Wardrobe.exe` resource ICON 9, 256 × 256 32-bpp DIB | the skeleton's face over the green hoodie |

**The owner confirmed all five sent renders at sight** — the skeleton,
the menu wall, the PS4 screen, the bedroom, the icon — and, shown the
black shape, said it "seems a walkable map of the bedroom" without being
sure; the bytes above make it sure. The layout is closed by the bytes
either way, and a picture that looks like the game the owner played is
the control the bytes cannot give ([08](08-tools-predictions-and-calibration.md)).

## What is not read

Unity 6's other forty classes; the sprites' tight meshes and physics shapes
beyond their counts; the 1,542 MonoBehaviours' fields; the 111 shaders; a
`Sprite` whose `m_SettingsRaw` says rotated (there are none here, and the
tool refuses one by name); the BC7 and ASTC formats (named, sized, not
decoded — there are none here either). `unitytex22.py` reads classes 28 and
213 at format 22 and nothing else, and says so.
