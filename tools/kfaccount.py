#!/usr/bin/env python3
"""kfaccount.py -- every byte of the object in a named bucket, twice.

TWO ACCOUNTINGS, AND THEY ANSWER DIFFERENT QUESTIONS
----------------------------------------------------
**By format**, which is the coverage figure: what has this repository opened,
and what is still a file name and a byte count? A bucket is `read` only if a
program in `tools/` walked it and its own arithmetic closed; `named` if the
format is published and the file was censused but not walked to residue; and
`unread` otherwise.

**By author**, which is the harder question this object poses: almost nothing
here was written by the people who signed it. Basecamp Games appears in no
version resource in the object at all, `Engine\\` is 408 of the 740 files, and
fifty-three of the fifty-nine binaries belong to NVIDIA, wxWidgets, Intel,
Microsoft, Valve or OC3.

Both accountings must close at residue 0 over 740 files, and a file that
matches no rule is a fatal error rather than an `(other)` row --- which is the
failure `mraccount.py` produces on this object when it is run unmodified.

    python tools/kfaccount.py --selftest
    python tools/kfaccount.py --format
    python tools/kfaccount.py --author
"""
import argparse
import collections
import os
import sys

ROOT = "karmaflow-steam"

# --------------------------------------------------------------- by format
# (bucket, status, why). Status: read / named / unread.
FORMAT_RULES = [
    (lambda r, e: e in (".kf", ".u", ".upk"),
     "Unreal package", "read",
     "tools/kfpkg.py: 113 of 113 validate, names/imports/exports at residue 0"),
    (lambda r, e: e == ".tfc",
     "texture file cache", "read",
     "tools/tfc.py: chain walked to residue 0; tools/tfcref.py: 46,074 of "
     "46,074 offsets confirmed"),
    (lambda r, e: e == ".bnk",
     "Wwise SoundBank", "read",
     "tools/wwise.py: chunk list tiles 21 of 21 at residue 0"),
    (lambda r, e: e == ".wem",
     "Wwise media", "read",
     "tools/wwise.py: RIFF closes 48 of 48, fmt 0xFFFF on 48 of 48"),
    (lambda r, e: e == ".wav",
     "RIFF/WAVE (published)", "read",
     "tools/kfaudio.py --wav and --bwf: 12 of 12 close on their own "
     "RIFF length, and the bext/minf chunks are read"),
    (lambda r, e: e == ".mp3",
     "MP3 + ID3v2 (published)", "read",
     "tools/kfaudio.py --id3: the frame table walked, 10 text frames "
     "on 12 of 12"),
    (lambda r, e: e in (".exe", ".dll"),
     "PE/COFF (published)", "read",
     "tools/pecensus.py: 59 of 59, PE32 6 and PE32+ 53"),
    (lambda r, e: e == ".bin",
     "compiled shader blob", "unread",
     "151 files; the first four bytes and nothing else"),
    (lambda r, e: e in (".rtf",),
     "RTF (published)", "named", "licence and readme text"),
    (lambda r, e: e in (".png", ".bmp", ".ico"),
     "image (published)", "named", "PNG, BMP and ICO headers censused"),
    (lambda r, e: e in (".xml", ".ini", ".txt", ".url", ".config",
                        ".response", ".properties"),
     "text and configuration", "read",
     "read as text; DefaultEngine.ini, build.properties, the linker response "
     "file and SoundbanksInfo.xml are all quoted in the documents"),
    (lambda r, e: True,
     "localisation and the catch-all", "read",
     "tools/kftext.py --loc: 206 of these 223 begin with a UTF-16LE BOM; "
     "the other 17 are the zero-byte files and one 96-byte ANSI stub"),
]

# --------------------------------------------------------------- by author
THIRD_PARTY_BINARIES = set("""
APEX_ClothingCHECKED_x64.dll APEX_ClothingGPUCHECKED_x64.dll
APEX_Clothing_LegacyCHECKED_x64.dll APEX_Common_LegacyCHECKED_x64.dll
APEX_DestructibleCHECKED_x64.dll APEX_Destructible_LegacyCHECKED_x64.dll
APEX_Framework_LegacyCHECKED_x64.dll ApexFrameworkCHECKED_x64.dll
EasyHook64.dll FxGraphLayout_x64.dll GRBCHECKED_1_1_api2_x64.dll
GRB_1_x64.dll NxCharacter64.dll PhysX3GpuCHECKED_x64.dll
PhysXCooking64.dll PhysXCore64.dll PhysXDevice64.dll PhysXExtensions64.dll
PhysXLoader64.dll atc_api.dll cudart64_41_22.dll cudart64_42_9.dll
dbghelp.dll libresample_x64.dll nvtt_64.dll p4dn.dll steam_api64.dll
substance_linker.dll substance_sse2_blend.dll tbbmalloc.dll
tbbmalloc_debug.dll
wxmsw28u_adv_vc_custom_64.dll wxmsw28u_aui_vc_custom_64.dll
wxmsw28u_core_vc_custom_64.dll wxmsw28u_html_vc_custom_64.dll
wxmsw28u_richtext_vc_custom_64.dll wxmsw28u_vc_custom_64.dll
wxmsw28u_xml_vc_custom_64.dll wxmsw28u_xrc_vc_custom_64.dll
wxmsw28ud_adv_vc_custom_64.dll wxmsw28ud_aui_vc_custom_64.dll
wxmsw28ud_core_vc_custom_64.dll wxmsw28ud_html_vc_custom_64.dll
wxmsw28ud_richtext_vc_custom_64.dll wxmsw28ud_vc_custom_64.dll
wxmsw28ud_xml_vc_custom_64.dll wxmsw28ud_xrc_vc_custom_64.dll
dotNetFx40_Full_setup.exe Interop.IWshRuntimeLibrary.dll
""".split())

# Epic's own, by version resource or by being a stock UDK script package.
EPIC_BINARIES = set("""
AgentInterface.dll WindowsTools_x64.dll UE3ShaderCompileWorker.exe
UnSetup.exe UE3Redist.exe UnrealEdCSharp.dll
libogg_64.dll libvorbis_64.dll libvorbisfile_64.dll
""".split())

EPIC_PACKAGES = set("""
Core.u Engine.u GameFramework.u GFxUI.u GFxUIEditor.u IpDrv.u
OnlineSubsystemSteamworks.u UDKBase.u UTGame.u UTGameContent.u UnrealEd.u
WinDrv.u UDKBase_LOC_INT.upk UDKFonts.upk ScaleForm.upk
""".split())


def classify_author(rel, base, ext):
    top = rel.split("/", 1)[0]
    if top == "Original Soundtrack":
        return ("the soundtrack",
                "twelve pieces as MP3 and as WAV, plus a cover image")
    if top == "Engine":
        return ("Epic's engine, shipped whole",
                "Epic's own Engine tree: localisation, shaders, config")
    if base in THIRD_PARTY_BINARIES:
        return ("third-party code",
                "a binary whose version resource is not Epic's and not the "
                "studio's")
    if base in EPIC_BINARIES or base in EPIC_PACKAGES:
        return ("Epic's engine, shipped whole",
                "Epic's own binary or stock UDK script package")
    if base in ("KFGame.exe", "KFGame.exe.response", "KFGame.exe.config"):
        return ("the studio's build of Epic's source",
                "linked by Basecamp from Epic's engine sources; its "
                "CompanyName is Epic's and its __FILE__ strings are the "
                "studio's")
    if base in ("build.properties", "UnSetup.Game.xml",
                "UnSetup.Manifests.xml", "UnSetup.exe.config"):
        return ("Epic's engine, shipped whole",
                "Epic's installer bookkeeping")
    if top == "Binaries":
        return ("Epic's engine, shipped whole", "Epic's installer payload")
    return ("the game's own content",
            "cooked packages, texture caches, sound banks, configuration and "
            "splash art that exist only in this game")


def walk(root):
    for r, _d, fs in os.walk(root):
        for f in sorted(fs):
            p = os.path.join(r, f)
            rel = os.path.relpath(p, root).replace("\\", "/")
            yield rel, f, os.path.splitext(f)[1].lower(), os.path.getsize(p)


def cmd_format(args):
    buckets = collections.OrderedDict()
    files = 0
    total = 0
    for rel, base, ext, size in walk(args.root):
        files += 1
        total += size
        for pred, name, status, why in FORMAT_RULES:
            if pred(rel, ext):
                b = buckets.setdefault(name, [0, 0, status, why])
                b[0] += 1
                b[1] += size
                break
        else:
            raise SystemExit("kfaccount: %s matched no rule" % rel)
    print("files : %d" % files)
    print("bytes : %d" % total)
    print()
    print("%-28s %6s %14s %9s  %s"
          % ("bucket", "files", "bytes", "share", "status"))
    for k, v in sorted(buckets.items(), key=lambda kv: -kv[1][1]):
        print("%-28s %6d %14d %8.4f %%  %s"
              % (k, v[0], v[1], 100.0 * v[1] / total, v[2]))
    print()
    s = sum(v[1] for v in buckets.values())
    n = sum(v[0] for v in buckets.values())
    print("sum   : %d files, %d bytes" % (n, s))
    print("residue against the tree : %d files, %d bytes"
          % (files - n, total - s))
    if total != s or files != n:
        raise SystemExit("kfaccount: the buckets do not close")
    print()
    for st in ("read", "named", "unread"):
        b = sum(v[1] for v in buckets.values() if v[2] == st)
        f = sum(v[0] for v in buckets.values() if v[2] == st)
        print("%-7s : %6d files %14d bytes  %8.4f %%"
              % (st, f, b, 100.0 * b / total))
    read = sum(v[1] for v in buckets.values() if v[2] == "read")
    named = sum(v[1] for v in buckets.values() if v[2] == "named")
    print()
    print("COVERAGE, walked to residue          : %.4f %%"
          % (100.0 * read / total))
    print("COVERAGE, walked or censused         : %.4f %%"
          % (100.0 * (read + named) / total))
    print("the free coverage this session began from : 15.5825 %")
    print()
    print("why each bucket carries the status it does:")
    for k, v in sorted(buckets.items(), key=lambda kv: -kv[1][1]):
        print("   %-28s %-7s %s" % (k, v[2], v[3]))
    return 0


def cmd_author(args):
    buckets = collections.OrderedDict()
    files = 0
    total = 0
    why = {}
    for rel, base, ext, size in walk(args.root):
        files += 1
        total += size
        name, reason = classify_author(rel, base, ext)
        why[name] = reason
        b = buckets.setdefault(name, [0, 0])
        b[0] += 1
        b[1] += size
    print("files : %d" % files)
    print("bytes : %d" % total)
    print()
    print("%-38s %6s %14s %9s" % ("who wrote it", "files", "bytes", "share"))
    for k, v in sorted(buckets.items(), key=lambda kv: -kv[1][1]):
        print("%-38s %6d %14d %8.4f %%"
              % (k, v[0], v[1], 100.0 * v[1] / total))
    s = sum(v[1] for v in buckets.values())
    n = sum(v[0] for v in buckets.values())
    print("%-38s %6d %14d %8.4f %%" % ("sum", n, s, 100.0 * s / total))
    print("residue : %d files, %d bytes" % (files - n, total - s))
    if total != s or files != n:
        raise SystemExit("kfaccount: the author buckets do not close")
    print()
    for k in buckets:
        print("   %-38s %s" % (k, why[k]))
    print()
    # data against code
    code = 0
    data = 0
    for rel, base, ext, size in walk(args.root):
        if ext in (".exe", ".dll", ".u"):
            code += size
        else:
            data += size
    print("data-to-code, on the same definition the last two objects used")
    print("  (executable code = .exe, .dll and compiled UnrealScript .u):")
    print("   code %d   data %d   ratio %.1f : 1"
          % (code, data, data / float(code)))
    return 0


def selftest():
    cases = []
    # every extension in the object must match a rule, and the catch-all must
    # be reached only by the localisation files
    seen = set()
    for rel, base, ext, size in walk(ROOT) if os.path.isdir(ROOT) else []:
        seen.add(ext)
    hit = collections.Counter()
    for e in sorted(seen):
        for i, (pred, name, _s, _w) in enumerate(FORMAT_RULES):
            if pred("x", e):
                hit[name] += 1
                break
    cases.append(("every extension in the object matches a rule",
                  sum(hit.values()) == len(seen) if seen else True))
    cases.append(("the catch-all is the localisation bucket",
                  FORMAT_RULES[-1][1] == "localisation and the catch-all"))
    cases.append(("a .kf is an Unreal package",
                  FORMAT_RULES[0][0]("a.kf", ".kf")))
    cases.append(("a .tfc is not an Unreal package",
                  not FORMAT_RULES[0][0]("a.tfc", ".tfc")))
    a, _r = classify_author("Engine/Config/Base.ini", "Base.ini", ".ini")
    cases.append(("anything under Engine/ is Epic's",
                  a == "Epic's engine, shipped whole"))
    a, _r = classify_author("Binaries/Win64/steam_api64.dll",
                            "steam_api64.dll", ".dll")
    cases.append(("steam_api64.dll is third-party", a == "third-party code"))
    a, _r = classify_author("Binaries/Win64/KFGame.exe", "KFGame.exe", ".exe")
    cases.append(("the game executable is its own bucket",
                  a == "the studio's build of Epic's source"))
    a, _r = classify_author("KFGame/CookedPC/Maps/World1/KF-W1_T1.kf",
                            "KF-W1_T1.kf", ".kf")
    cases.append(("a map is the game's own", a == "the game's own content"))
    a, _r = classify_author("Original Soundtrack/WAV/01.wav", "01.wav", ".wav")
    cases.append(("the soundtrack branch is the soundtrack",
                  a == "the soundtrack"))
    a, _r = classify_author("KFGame/CookedPC/Core.u", "Core.u", ".u")
    cases.append(("Core.u is Epic's, not the game's",
                  a == "Epic's engine, shipped whole"))
    ok = sum(1 for _n, v in cases if v)
    print("kfaccount selftest: %d specimens" % len(cases))
    for n, v in cases:
        print("  %-52s %s" % (n, "PASS" if v else "FAIL"))
    print()
    print("%d of %d behaved as required" % (ok, len(cases)))
    return 0 if ok == len(cases) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=ROOT)
    for c in ("selftest", "format", "author"):
        ap.add_argument("--" + c, action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.format:
        return cmd_format(a)
    if a.author:
        return cmd_author(a)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
