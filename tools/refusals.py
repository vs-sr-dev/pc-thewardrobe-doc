#!/usr/bin/env python3
"""refusals.py -- point every reader written for the last three objects at
this one and record what it says.

A tool that refuses is not a tool that failed. The rule this pipeline has run
on for several sessions is that a reader written for another object must be
aimed at the new one and its refusal written down, because the two failure
modes that matter are not the same:

  * a **clean refusal** -- the tool says the magic is wrong, or the arithmetic
    does not divide, and stops. That is the tool working;
  * a **plausible wrong answer** -- the tool finds a shape that looks like the
    one it was written for, prints a table, and exits 0. That is the dangerous
    one, and this object has two candidates for it that the pre-briefing named
    in advance: `bkf.py`, which reads a `u32` count followed by fixed-width
    records, and `mraccount.py`, whose bucket list is hard-coded for the
    previous object's extensions.

The twenty-two readers are the eleven written on `pc-heretickingdoms-doc`, the
six written on `pc-motoracer-doc` -- both sets derived here by differencing
the tool boxes of consecutive repositories, not by memory -- and five named in
`pc-themepark-doc/docs/15`.

    python tools/refusals.py
"""
import os
import subprocess
import sys

ROOT = "rpgmakerxp-steam"
TOOLS = os.path.dirname(os.path.abspath(__file__))

# %CHM% and %LDB% are resolved against the tree being pointed at, rather than
# being the previous object's file names. That defect was measured on
# pc-rpgmaker2003-doc: the table said `%ROOT%/rpg2000.chm` and `itsf.py` and
# `runexpect.py` therefore refused with FileNotFoundError on an object that
# ships a perfectly good .chm. Two of the nine "OS error" refusals were the
# harness naming the wrong file, which is a refusal about the harness and not
# about the object.
GLOBS = {"%CHM%": (".chm",), "%LDB%": (".ldb", ".ldb.dat"),
         "%LMT%": (".lmt",), "%LMU%": (".lmu",), "%PSD%": (".psd",),
         # Added on pc-rpgmakerxp-doc. Twelve of the sixteen `oserror`
         # refusals on this object were the harness pointing a reader at a
         # placeholder this tree has no file for -- which is the designed
         # behaviour and not a defect -- but the tree does have .rxdata, .ogg
         # and .jpg, and the readers written here need to be aimed at them.
         "%RXDATA%": (".rxdata",), "%OGG%": (".ogg",), "%JPG%": (".jpg",),
         "%SCRIPTS%": ("scripts.rxdata",),
         # Added on pc-rpgmakervxace-doc. `.mp3` is new to this pipeline.
         "%MP3%": (".mp3",)}

# Added on pc-rpgmakervxace-doc, and it is the point of the whole session.
#
# `%RXDATA%` resolves BY EXTENSION, and this object's Ruby Marshal documents
# are called `.rvdata2`. So the harness pointed `marshal48.py` and `rgssdb.py`
# at a path that does not exist, they refused correctly, and
# `refusalclass.py` filed the refusal under `format` -- reporting as a
# statement about the object what was a statement about a file name.
#
# The readers were repaired to select by MAGIC. A harness that still selects
# by extension would keep reporting them as refusing, so these two placeholders
# select by magic too, and the resolver below dispatches on which kind a token
# is. A harness has to obey the rule it is testing.
MAGICS = {
    # token: (a predicate on the first bytes, whether to return the DIRECTORY)
    "%MARSHAL%": (lambda b: len(b) >= 3 and b[0] == 0x04 and b[1] == 0x08
                  and b[2:3] in MARSHAL_TYPE_BYTES, False),
    "%MARSHALDIR%": (lambda b: len(b) >= 3 and b[0] == 0x04 and b[1] == 0x08
                     and b[2:3] in MARSHAL_TYPE_BYTES, True),
    # Added on pc-rpgmakermv-doc, to replace a hard-coded sentence in the
    # zaccount.py row claiming the object had no ZIP. PKWARE APPNOTE: a local
    # file header, or an empty archive's end-of-central-directory record.
    "%ZIP%": (lambda b: b[:4] in (b"PK\x03\x04", b"PK\x05\x06"), False),
    # And the two formats this object is full of and no previous one had.
    "%MP4%": (lambda b: len(b) >= 12 and b[4:8] == b"ftyp", False),
    "%PAK%": (lambda b: len(b) >= 20
              and int.from_bytes(b[:4], "little") in (4, 5)
              and (b[4] == 1 if int.from_bytes(b[:4], "little") == 5
                   else b[8] == 1), False),
}
MARSHAL_TYPE_BYTES = {bytes([c]) for c in b"0TFilfu:;\"I[{}oUCSc/me@dM'"}


def resolve_globs(root, arg):
    for token, (probe, want_dir) in MAGICS.items():
        if token not in arg:
            continue
        found = None
        for dp, _dn, fn in os.walk(root):
            for f in sorted(fn):
                p = os.path.join(dp, f)
                try:
                    with open(p, "rb") as fh:
                        # 8 bytes was enough for the two Marshal placeholders
                        # and is not enough for a File Type Box or a .pak
                        # header, both of which were added on
                        # pc-rpgmakermv-doc and both of which resolved to
                        # "no file of that magic in this tree" over trees full
                        # of them. Raised to 32 with the two new probes.
                        head = fh.read(32)
                except OSError:
                    continue
                if probe(head):
                    found = (dp if want_dir else p).replace(os.sep, "/")
                    break
            if found:
                break
        arg = arg.replace(token, found or "%s/(no file of that magic in this "
                                          "tree)" % root)
    for token, exts in GLOBS.items():
        if token not in arg:
            continue
        found = None
        for dp, _dn, fn in os.walk(root):
            for f in sorted(fn):
                if f.lower().endswith(exts):
                    found = os.path.join(dp, f).replace(os.sep, "/")
                    break
            if found:
                break
        # No file of that kind is a legitimate answer: the placeholder becomes
        # a path that does not exist, the reader refuses, and the report says
        # so. Silently dropping the entry would hide a reader that was never
        # pointed anywhere.
        arg = arg.replace(token, found or "%s/(no %s in this tree)"
                          % (root, exts[0]))
    return arg

# (tool, args, what it was written for)
READERS = [
    # pc-heretickingdoms-doc -- Hexen II / Heretic Kingdoms, eleven
    ("agp.py", ["%ROOT%"], "the .agp archive of Heretic Kingdoms"),
    ("kultaccount.py", ["%ROOT%"], "the accounting of Kult"),
    ("kultdat.py", ["%ROOT%"], "Kult's .dat"),
    ("kultdia.py", ["%ROOT%"], "Kult's dialogue"),
    ("kultexe.py", ["%ROOT%"], "Kult's executable"),
    ("kultidx.py", ["%ROOT%"], "Kult's .idx"),
    ("kultlang.py", ["%ROOT%"], "Kult's language tables"),
    ("kultnames.py", ["%ROOT%"], "Kult's internal names"),
    ("maska.py", ["%ROOT%"], "Kult's mask grids"),
    ("oggmeta.py", ["%ROOT%"], "Ogg Vorbis session metadata"),
    ("sdb.py", ["%ROOT%"], "Kult's .sdb"),
    # pc-motoracer-doc -- six
    ("bkf.py", ["%ROOT%"], "Delphine's .BKF archive -- DANGEROUS: a u32 "
                           "count then fixed-width records"),
    ("lez.py", ["%ROOT%"], "Delphine's LEZ1 compression"),
    ("buildorder.py", ["%ROOT%"], "the build order of Moto Racer's binaries"),
    ("mraccount.py", ["%ROOT%"], "Moto Racer's accounting -- DANGEROUS: a "
                                 "hard-coded bucket list"),
    ("peimpexp.py", ["%ROOT%/Binaries/Win64/KFGame.exe", "--imports"],
     "PE import and export directories (taught PE32+ this session)"),
    ("utf16sift.py", ["%ROOT%", "--group", "personal"],
     "UTF-16LE personal-data patterns"),
    # pc-themepark-doc -- five
    ("tpsave.py", ["%ROOT%"], "Theme Park's save files"),
    ("tptab.py", ["%ROOT%"], "Theme Park's tables"),
    ("gogmanifest.py", ["--root", "%ROOT%"], "GOG's galaxy file list"),
    ("hashdb.py", ["%ROOT%"], "GOG's .hashdb checksum table"),
    ("authenticode.py", ["%ROOT%/Binaries/Win64/KFGame.exe"],
     "the PKCS#7 blob of a signed PE"),
    # pc-karmaflow-doc -- thirteen, added on pc-academagia-doc. Two of them
    # are dangerous rather than merely inapplicable and are marked so.
    ("lzo1x.py", ["%ROOT%"], "LZO1X decompression for UE3 packages"),
    ("kfpkg.py", ["%ROOT%"], "the Unreal package of Karmaflow -- DANGEROUS: "
                             "it also looks for a length-prefixed table"),
    ("tfc.py", ["%ROOT%"], "a UE3 texture file cache"),
    ("tfcref.py", ["%ROOT%"], "the mip offsets that reference a .tfc"),
    ("wwise.py", ["%ROOT%"], "Wwise .bnk soundbanks"),
    ("steamacf.py", ["--root", "%ROOT%"], "a Steam appmanifest .acf"),
    ("kfaudio.py", ["%ROOT%"], "Karmaflow's .wem and .wav"),
    ("kftext.py", ["%ROOT%"], "Karmaflow's localisation tables"),
    ("kfopera.py", ["%ROOT%"], "Karmaflow's map names against a tracklist"),
    ("kfaccount.py", ["--root", "%ROOT%"], "Karmaflow's accounting -- "
                                           "DANGEROUS: a bucket list that "
                                           "assumes extensions"),
    ("pdbpaths.py", ["--root", "%ROOT%"], "CodeView RSDS build paths"),
    ("buildroot.py", ["--root", "%ROOT%"], "the studio build root of a "
                                           "native binary"),
    # pc-academagia-doc -- five, added on pc-iamsetsuna-doc.  Two of the five
    # are not refusals at all and were flagged as such before being run:
    # `clrmeta.py` reads this object's ten managed assemblies unchanged, and
    # `jstore.py` is the dangerous one, because an `@UTF` table and an `AFS2`
    # bank are both a marker followed by counts.
    ("nrbf.py", ["%ROOT%"], "an MS-NRBF .NET remoting stream"),
    ("jstore.py", ["%ROOT%"], "Academagia's Storage index -- DANGEROUS: it "
                              "looks for a marker, a u32 count and "
                              "fixed-width records, which is the shape of "
                              "@UTF and of AFS2"),
    ("clrmeta.py", ["%ROOT%", "--census"], "CLR metadata heaps -- expected "
                                           "NOT to refuse"),
    ("jsdata.py", ["%ROOT%"], "Academagia's data.bin record stream"),
    ("acaccount.py", ["%ROOT%"], "Academagia's accounting -- DANGEROUS: its "
                                 "bucket rules name that object's "
                                 "directories"),
    # the four Unity readers of pc-themurderofsonicthehedgehog-doc, which are
    # the reason this repository exists: they are the right family and the
    # wrong generation.
    ("unityfs.py", ["census", "%ROOT%"], "Unity SerializedFile v21 -- "
                                         "DANGEROUS: it runs on v15 and "
                                         "reports nineteen terabytes"),
    ("unityarc.py", ["validate", "%ROOT%"], "UnityFS archives; this object "
                                            "has UnityWeb"),
    ("unityasset.py", ["textures", "%ROOT%"], "type-tree deserialisation of "
                                              "UnityFS nodes"),
    ("bundlebudget.py", ["sample", "%ROOT%", "--n", "4"],
     "UnityFS block compression flags"),
    # pc-iamsetsuna-doc -- the ten written there, added on pc-rpgmaker95-doc.
    # Two of the ten are general tools and are expected NOT to refuse:
    # `sigcount.py` takes a signature on the command line, and `verres.py`
    # walks any directory looking for PE version resources.
    ("sfv15.py", ["census", "%ROOT%"], "Unity SerializedFile v15"),
    ("unityweb.py", ["census", "%ROOT%"], "UnityWeb LZMA bundles"),
    ("criutf.py", ["census", "%ROOT%"], "CRIWARE @UTF tables"),
    ("crihca.py", ["census", "%ROOT%"], "CRI HCA audio frames"),
    ("luac52.py", ["census", "%ROOT%"], "compiled Lua 5.2"),
    ("placement.py", ["%ROOT%"], "Unity scene placement records"),
    ("unitytex.py", ["census", "%ROOT%"], "Unity Texture2D decoding"),
    ("isaccount.py", ["check", "%ROOT%"], "I am Setsuna's accounting -- "
                                          "DANGEROUS: its bucket rules name "
                                          "that object's directories"),
    ("verres.py", ["census", "%ROOT%"], "PE version resources -- expected "
                                        "NOT to refuse, and it does not, but "
                                        "it counts NE files as PE"),
    ("sigcount.py", ["%ROOT%", "--hex", "135d658c"], "a byte signature given "
                                                     "on the command line -- "
                                                     "expected NOT to refuse"),
    # pc-rpgmaker95-doc -- the eight written there, added on
    # pc-rpgmaker2000-doc. The three InstallShield readers are the interesting
    # ones: this object contains no InstallShield at all, so they must refuse,
    # and `isz.py` must refuse on magic inside its first four bytes. If any of
    # them prints a table, that is the finding and not the refusal.
    ("isz.py", ["list", "%ROOT%/setup.exe.dat"],
     "an InstallShield 3 Z archive -- must refuse on magic in 4 bytes"),
    ("ispkg.py", ["%ROOT%/setup.exe.dat"], "an InstallShield .PKG manifest"),
    ("is32.py", ["list", "%ROOT%/setup.exe.dat"],
     "an InstallShield _INST32I container"),
    ("cptext.py", ["census", "%ROOT%/unlha32.txt"],
     "a codepage census of a text file -- expected NOT to refuse"),
    ("runexpect.py", ["%CHM%"],
     "printable runs against chance -- expected NOT to refuse"),
    ("redact.py", ["selftest"],
     "address redaction -- expected NOT to refuse"),
    # Repaired on pc-rpgmakermv-doc. This row carried the sentence "there is
    # no ZIP in this object" -- a claim about pc-rpgmaker2000-doc's tree,
    # frozen into a harness that is pointed at a different object every
    # session. pc-rpgmakermv-doc ships a 205,182,933-byte ZIP, and the harness
    # was still declaring there was none. It is the `%RXDATA%` defect of
    # pc-rpgmakervxace-doc in a different row of the same table: a description
    # is not a placeholder, and a harness may not carry an assertion about a
    # tree it is no longer looking at.
    #
    # The token is now `%ZIP%`, resolved BY MAGIC against whatever tree the
    # harness is aimed at, and the description says what the tool is for and
    # nothing about what the object contains.
    # `zaccount.py` is a four-layer accounting bound to one object's
    # InstallShield structure and needs a directory of extracted members, so
    # the harness can only point it at its own selftest. The tool that DOES
    # walk an arbitrary ZIP structurally is `zipdir.py`, and it is added here
    # -- it is one of the tools P22 says nobody had aimed.
    ("zaccount.py", ["selftest"],
     "a four-layer accounting; needs an extracted member directory, so its "
     "selftest is what the harness can point at"),
    ("zipdir.py", ["%ZIP%"], "a ZIP central directory, read without "
                             "extracting"),
    ("coverage.py", ["tree", "--root", "%ROOT%"],
     "the four-bucket coverage table -- written here, must NOT refuse"),
    # pc-rpgmaker2000-doc -- the five written here. They are pointed at the
    # object they were written for, so they are expected NOT to refuse; the
    # entry exists so that a later session pointing them somewhere else has
    # a baseline that says what "working" looked like.
    ("itsf.py", ["list", "%CHM%"],
     "a Microsoft ITSF container -- written here, must NOT refuse"),
    ("lcf.py", ["walk", "%LDB%"],
     "an LCF database -- written here, must NOT refuse"),
    ("pngcensus.py", ["%ROOT%"],
     "a PNG census -- written here, must NOT refuse"),
    ("smfcensus.py", ["%ROOT%"],
     "a Standard MIDI census -- written here, must NOT refuse"),
    ("peembed.py", ["%ROOT%/setup.exe.dat"],
     "a PE closed on its own sections -- written here, must NOT refuse"),
    # pc-rpgmaker2003-doc -- the readers written here. Same rule as above:
    # they are pointed at what they were written for, so a refusal from one of
    # them is a defect and not a measurement, and the entry exists so that a
    # later session pointing them at a different object has a baseline.
    ("lcfmap.py", ["walk", "%LMU%"],
     "an LCF map unit -- written here, must NOT refuse"),
    ("lcfdiff.py", ["%LDB%", "%LDB%"],
     "two LCF databases compared -- written here, must NOT refuse"),
    ("psd.py", ["%PSD%"],
     "an Adobe Photoshop file -- written here, must NOT refuse"),
    ("pngchunk.py", ["%ROOT%", "--type", "tIME"],
     "a named PNG chunk -- written here, must NOT refuse"),
    ("stampcheck.py", ["%ROOT%"],
     "three tests on a COFF timestamp -- written here, must NOT refuse"),
    ("uuidscan.py", ["%ROOT%"],
     "version-1 UUIDs -- written here, must NOT refuse"),
    ("vendorhash.py", ["%ROOT%"],
     "third-party components -- written here, must NOT refuse"),
    ("projdiff.py", ["%ROOT%", "--against", "%ROOT%"],
     "a project against a resource library -- written here"),
    ("toolsdiff.py", ["%ROOT%"],
     "two tool boxes compared; a tree of data is not one, so it must "
     "refuse ON READING and not on its command line"),
    # Itself, to prove the harness runs. The child is given --harness-check,
    # which makes it print one line and stop. WITHOUT that guard this entry
    # recursed forever and every invocation blocked for its full 900-second
    # timeout; the defect was recorded on the last two objects and is fixed
    # here.
    # pc-rpgmakerxp-doc -- the readers written here. Same rule as the two
    # blocks above: they are pointed at what they were written for, so a
    # refusal from one of them is a defect and not a measurement, and the
    # entry exists so that a later session pointing them at a different object
    # has a baseline that says what "working" looked like.
    # Repointed on pc-rpgmakervxace-doc from `%RXDATA%` (an extension the
    # previous object used) to `%MARSHAL%` (the signature both objects share).
    ("marshal48.py", ["walk", "%MARSHAL%"],
     "a Ruby Marshal 4.8 document -- written here, must NOT refuse"),
    ("rxscripts.py", ["list", "%SCRIPTS%"],
     "RPG Maker XP's Scripts.rxdata -- written here; this object ships NO "
     "scripts file of any name, so its refusal is the harness working"),
    ("rgssdb.py", ["tables", "%MARSHALDIR%"],
     "the Table and Color payloads Marshal cannot see -- written here"),
    ("chmx.py", ["check", "%CHM%"],
     "an ITSF container's LZX content -- written here, must NOT refuse"),
    ("lzx.py", ["selftest"],
     "Microsoft LZX -- a library; its selftest must NOT refuse"),
    ("depotsplit.py", ["--root", "%ROOT%", "--group", "all=.,rtp,System,"
                       "Bonus"],
     "a shop's depot boundary against a directory boundary -- written here"),
    ("namescan.py", ["%ROOT%", "--name", "Enterbrain"],
     "a literal name in both encodings -- written here, must NOT refuse"),
    ("rgssjoin.py", ["selftest"],
     "the data-against-help join -- needs two roots, so its selftest is what "
     "the harness can point at"),
    ("rule0hook.py", ["--check", "python tools/x.py"],
     "rule 0 as a program -- an ALLOWED command must exit 0"),
    ("refusals.py", ["--harness-check"],
     "itself; pointed here to prove the harness runs"),
    # pc-rpgmakermv-doc -- the six written here. Same rule as the rows above:
    # a reader written for THIS object is expected NOT to refuse, and the two
    # that need a second document or a document this session writes are
    # pointed at their own selftest instead of at a path that does not exist.
    ("mp4box.py", ["validate", "%MP4%"],
     "an ISO base media box tree -- written here, must NOT refuse"),
    ("chpak.py", ["validate", "%PAK%"],
     "a Chromium .pak index -- written here, must NOT refuse"),
    ("audiopair.py", ["%ROOT%"],
     "the same recording in two containers -- written here, must NOT refuse"),
    ("jsondiff.py", ["--selftest"],
     "two directories of JSON joined by key -- needs two roots, so its "
     "selftest is what the harness can point at"),
    ("regcheck.py", ["--selftest"],
     "P20's register-membership test -- it reads a document this session "
     "writes, so its selftest is what the harness can point at"),
    ("predmeasure.py", ["--selftest"],
     "P21's measurement count -- the same"),
]


def main():
    if "--harness-check" in sys.argv[1:]:
        print("refusals.py: harness check, and this child does not recurse")
        return 0
    root = sys.argv[1] if len(sys.argv) > 1 else ROOT
    clean = 0
    answered = 0
    missing = 0
    print("%d readers, pointed at an object none of them was written" % len(READERS))
    print("for. The column that matters is the last one.")
    print()
    for name, args, why in READERS:
        path = os.path.join(TOOLS, name)
        if not os.path.exists(path):
            print("%-16s MISSING FROM THE BOX" % name)
            missing += 1
            continue
        argv = [sys.executable, path] + [
            resolve_globs(root, a.replace("%ROOT%", root)) for a in args]
        try:
            p = subprocess.run(argv, capture_output=True, timeout=900)
            out = (p.stdout + p.stderr).decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            out = "(timed out)"
            p = None
        rc = p.returncode if p else -1
        last = [ln for ln in out.splitlines() if ln.strip()]
        tail = last[-1][:88] if last else "(no output)"
        verdict = "REFUSED" if rc != 0 else "exit 0"
        if rc != 0:
            clean += 1
        else:
            answered += 1
        print("%-16s %-8s %s" % (name, verdict, tail))
        print("%-16s          for: %s" % ("", why))
    print()
    print("readers pointed        : %d" % len(READERS))
    print("refused with a non-zero exit : %d" % clean)
    print("exited 0 anyway              : %d" % answered)
    print("absent from the box          : %d" % missing)
    print()
    print("An `exit 0` here is not a success. It means the tool found")
    print("something it was willing to print a table about, and each one has")
    print("to be looked at by hand -- which is what docs/13 does.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
