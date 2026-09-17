#!/usr/bin/env python3
"""toolclass.py -- every tool in tools/, classified, or nothing prints.

The rule this enforces: a repository that ships 278 tools and uses
nineteen of them owes the reader an account of the other 259. Every
file in tools/ appears in exactly one class below. If a tool is added
and not classified, or classified twice, this refuses to print the
table and says which one.
"""
import argparse
import os
import sys
from collections import Counter

CLASSES = [

('written for this object',
 'Ten, and every one exists because this object is a platform nothing in the tree had read. `opera.py` is the file system -- label, block header, directory entry, copy list -- and it refuses to census anything until its negative control has failed on two blocks that are not directories; that control is why the `next_block` bug cost this session ninety seconds and cost the pre-briefing 125 files. `sectormap3do.py` gives every one of the 307,446 sectors exactly one owner and will not print a total that is not 307,446. `opercopies.py` compares the copies the directory entry declares and found two groups that disagree. `bigfile.py` reads the movie archive and decodes its video members far enough to draw a frame, and raises `NotVideo` by name on the 53 members it cannot read rather than producing a plausible wrong answer. `discstr.py` and `disccontacts.py` exist because on a disc the right denominator is the pressing and not the file tree, and the second of them found five telephone-shaped strings that the file-tree scan did not. `markers.py` prints the chance expectation beside every count, because on 629 megabytes a three-byte string is expected 37.53 times. `aiffread.py` decodes the 80-bit extended sample rate; `modread.py` splits a module into score and sample and redacts contact data at the point of output; `aifstr.py` resolves paths against the listing exactly and case-folded, which on this disc is the difference between 84 hits and 107.',
 ['aiffread.py', 'aifstr.py', 'bigfile.py', 'disccontacts.py', 'discstr.py', 'markers.py', 'modread.py', 'opera.py', 'opercopies.py', 'sectormap3do.py']),

('inherited and used unmodified',
 'Six. `crossall.py` sweeps 67 repositories and returns zero, and the zero is reported as *zero against 67, of which zero are 3DO* rather than as a result. `contacts.py` returns zero over the file tree and that is the answer its pattern gives on those bytes -- the disc-wide scan returned five. `buildpaths.py` finds 114 Macintosh-shaped paths and every one is a false positive, 20 of them C error macros with colons in them and the rest three-character coincidences inside 319 megabytes of dense track data. `protscan.py` prints `files searched : 0` and then eleven zeros, which is the tool saying it did not run: this object has no `.exe` and no `.dll`, and its eleven PC schemes postdate the disc by two to ten years. `redactnotes.py` and `toolclass.py` are the housekeeping.',
 ['buildpaths.py', 'contacts.py', 'crossall.py', 'protscan.py', 'redactnotes.py', 'toolclass.py']),

('read as designs, and rewritten rather than reused',
 'Eight, and this is the first session in seven where the disc family came off the shelf at all. `sectormap.py`, `slack.py`, `rawsect.py`, `gapscan.py`, `gapmap.py` and `gapstruct.py` are the tools of the measurement this session turned on, and not one of them could run: every one of them knows what a sector is and none of them knows what a file is on this disc. They were read, and `sectormap3do.py` is what they became. `mode1.py` and `toc.py` were the closest to applying -- the track is `MODE1_RAW` and there is a table of contents in the CHD metadata -- and both stop at the point where they expect ISO 9660.',
 ['gapmap.py', 'gapscan.py', 'gapstruct.py', 'mode1.py', 'rawsect.py', 'sectormap.py', 'slack.py', 'toc.py']),

('does not apply: there is a disc and it is not that disc',
 'Sixty. `iso9660.py` is the one worth naming: it does not apply, and for a new reason. There *is* a file system here and it is not ISO 9660, so a tool that looks for a Primary Volume Descriptor at sector 16 does not find a broken one -- it finds a convincing nothing, which is worse. `xa.py`, `cdxa.py` and `subch.py` want Mode 2 Form 2, an XA subheader and a subchannel, and this pressing is `MODE1_RAW` with `SUBTYPE:NONE`. The rest of the class is the CD-i and Amiga CD apparatus: multi-disc comparison, lead-out, interleave, timestamps in directory records. This format has no timestamps at all.',
 ['abslack.py', 'cdxa.py', 'clocks.py', 'clocks4.py', 'clockwork.py', 'crossdisc.py', 'dates.py', 'dirclock.py', 'discdiff.py', 'discpass.py', 'fivelists.py', 'fourdisc.py', 'gap20.py', 'gapdump.py', 'gapname.py', 'gearcount.py', 'holepat.py', 'hunt.py', 'hunt2.py', 'imagecensus.py', 'interleave.py', 'iso9660.py', 'isodev.py', 'layers.py', 'leadout.py', 'mirror.py', 'msf.py', 'namespaces.py', 'padecho.py', 'padform.py', 'patch_iso9660.py', 'rawcensus.py', 'rawimage.py', 'recdates.py', 'sameplace.py', 'sdalign.py', 'secmap.py', 'slackorigin.py', 'spti.py', 'subch.py', 'sweep.py', 'threeclocks.py', 'threedisc.py', 'timeline.py', 'twocat.py', 'twoclocks.py', 'twodiscs.py', 'twofs.py', 'tzsplit.py', 'udf.py', 'vdall.py', 'vdfields.py', 'vdmatch.py', 'vdmatch3.py', 'vdpayload.py', 'vds.py', 'window.py', 'window2.py', 'xa.py', 'xfermax.py']),

('does not apply: the executables are ARM Image Format',
 "Seven. `mzcensus.py`, `pecensus.py`, `pe.py`, `ne.py`, `rsrc.py`, `deps.py` and `authenticode.py` all want a DOS or Windows executable. The 34 binaries here are AIF -- `SWI &11` at offset 0x10, entry at 0x100, image base 0 -- which is the ARM toolchain's own format and predates every one of those. Nothing was adapted; the header was derived and read directly.",
 ['authenticode.py', 'deps.py', 'mzcensus.py', 'ne.py', 'pe.py', 'pecensus.py', 'rsrc.py']),

('written for the previous object, and inapplicable here',
 "Six, one session old. `aniread.py`, `eleread.py`, `keyread.py`, `midread.py`, `plaread.py` and `twosimul.py` were written for an MS-DOS folder and none of them applies. Two lent a shape and no code: `aniread.py` closes a container on three identities before looking at a pixel, which is what `bigfile.py` does to the movie archive; and `keyread.py`'s negative control -- one that must fail using the same measurement that found the answer -- is what `opera.py`'s `--selftest` is.",
 ['aniread.py', 'eleread.py', 'keyread.py', 'midread.py', 'plaread.py', 'twosimul.py']),

('does not apply: the object contains no such structure',
 'The largest class, and it did not shrink. This disc shares no format with anything measured before it. Nothing is PE, nothing is a Windows resource, nothing is Bink or Smacker or Director or SCUMM, there is no PCM outside seventeen AIFF containers, no ZIP, no CAB, no MSI, no OLE2, no HFS. The nine tools written two sessions ago for a different container do not apply and were not adapted.',
 ['account.py', 'ambk.py', 'anm.py', 'asf.py', 'aufs.py', 'avi.py', 'avicheck.py', 'big.py', 'bigheads.py', 'biglang.py', 'bigpad.py', 'binindex.py', 'bink.py', 'bmp.py', 'bog.py', 'cab.py', 'cabdates.py', 'cabsig.py', 'cast.py', 'cmapcensus.py', 'crossmembers.py', 'datchain.py', 'datmembers.py', 'dattex.py', 'director.py', 'dobby.py', 'dpserial.py', 'edgemode.py', 'edgerun.py', 'edges.py', 'emdf.py', 'emdhead.py', 'empack.py', 'encodinghunt.py', 'encodings.py', 'filemaker.py', 'filmsame.py', 'fourmanifests.py', 'gogmanifest.py', 'hashdb.py', 'hfs.py', 'hfsx.py', 'hmc.py', 'inflate.py', 'inno.py', 'jbf.py', 'jpeg.py', 'keyhash.py', 'lang.py', 'langaxes.py', 'langtable.py', 'lbarc.py', 'lbdates.py', 'lbwhere.py', 'leakhere.py', 'machpaths.py', 'machpaths2.py', 'macrsrc.py', 'mapchain.py', 'mapgraph.py', 'members.py', 'micocat.py', 'micodb.py', 'mld.py', 'mov.py', 'mpegaudio.py', 'mpegps.py', 'msi.py', 'noisemap.py', 'noisestr.py', 'oggtime.py', 'ole2.py', 'pak.py', 'pakdec.py', 'pakraster.py', 'pcinvisible.py', 'pdfmeta.py', 'pixels.py', 'pkgdiff2.py', 'pkgsame.py', 'pmus.py', 'polhash.py', 'psblocks.py', 'qbank.py', 'qinv.py', 'qmus.py', 'qpic.py', 'qres.py', 'qsb.py', 'qshell.py', 'qtbl.py', 'qtext.py', 'renderers.py', 'romtables.py', 'rsc.py', 'rwstream.py', 'safedisc.py', 'sapread.py', 'scummcont.py', 'scummfont.py', 'scummidx.py', 'scummimg.py', 'scummsnd.py', 'scummtext.py', 'sdnumbers.py', 'sdtmp.py', 'securom.py', 'setuplist.py', 'sewave.py', 'spwdecode.py', 'stock.py', 'strm.py', 'swa.py', 'szdd.py', 'textdb.py', 'tga.py', 'threesets.py', 'threewalks.py', 'tilehunt.py', 'tim2png.py', 'timtmd.py', 'tmp2.py', 'tworez.py', 'umx.py', 'upkg.py', 'vise.py', 'vocx.py', 'vt7a.py', 'whose.py', 'whose4.py', 'whose5.py', 'xact.py', 'xmp.py', 'xsb2.py', 'zipdir.py', 'zob.py']),

('inherited, applicable here, not needed',
 "Every one would run and produce a number, and the numbers would not say anything the ten readers written for this disc's own formats have not said better. `hashall.py`, `entropy.py` and `treecensus.py` are the near misses: all three apply the moment a file exists, and on this object a file did not exist until `opera.py` did, so their work was done inside the extraction pass instead. Their output is in `notes/sha1-all.txt`, `notes/entropy.txt` and `notes/listing.txt` all the same.",
 ['accounting.py', 'assoc.py', 'audio.py', 'census.py', 'checklinks.py', 'checkscore.py', 'collectrefs.py', 'compare.py', 'crossbin.py', 'dircensus.py', 'discpair.py', 'entropy.py', 'envblock.py', 'filelist.py', 'filelist2.py', 'gamestats.py', 'hashall.py', 'headers.py', 'instcensus.py', 'leakcheck.py', 'leakthis.py', 'leftovers.py', 'listdiff.py', 'manifest.py', 'media.py', 'mkpattern.py', 'mtimes.py', 'namecensus.py', 'orphans.py', 'patch_assoc.py', 'pathdiff.py', 'paths.py', 'pathvendors.py', 'pcmtest.py', 'producers.py', 'refcheck.py', 'refs.py', 'requires.py', 'resolve.py', 'samebytes.py', 'signcount.py', 'smallfiles.py', 'strata.py', 'strcount.py', 'strdump.py', 'strs.py', 'thesis.py', 'thirdparty.py', 'thumbsdb.py', 'toolcheck.py', 'treecensus.py', 'treediff.py', 'verify.py', 'wavcheck.py', 'whichmember.py']),
]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="tools")
    ap.add_argument("--markdown", action="store_true")
    a = ap.parse_args()

    on_disk = sorted(f for f in os.listdir(a.dir) if f.endswith(".py"))
    named = []
    for _, _, files in CLASSES:
        named.extend(files)

    print("tools/*.py on disk        : %d" % len(on_disk))
    print("tools named in a class    : %d" % len(named))
    print("distinct tools classified : %d" % len(set(named)))
    print()
    for title, _, files in CLASSES:
        print("%-56s %5d" % (title, len(files)))
    print("%-56s %5d" % ("total", len(named)))
    print()

    ok = True
    dupes = sorted(f for f in set(named) if named.count(f) > 1)
    if dupes:
        ok = False
        print("!! classified more than once (%d): %s" % (len(dupes), ", ".join(dupes)))
    missing = sorted(set(on_disk) - set(named))
    if missing:
        ok = False
        print("!! on disk but in no class (%d): %s"
              % (len(missing), ", ".join(missing)))
    ghosts = sorted(set(named) - set(on_disk))
    if ghosts:
        ok = False
        print("!! named in a class but not on disk (%d): %s"
              % (len(ghosts), ", ".join(ghosts)))
    if len(named) != len(on_disk):
        ok = False
        print("!! totals disagree: %d classified, %d on disk"
              % (len(named), len(on_disk)))

    if not ok:
        print()
        print("refusing to print the table until every tool is classified "
              "exactly once.")
        return 1

    inapplicable = sum(len(f) for t, _, f in CLASSES if t.startswith("does not apply"))
    print("does not apply, both classes together : %d of %d = %.1f %%"
          % (inapplicable, len(on_disk), 100.0 * inapplicable / len(on_disk)))
    print()

    if a.markdown:
        for title, blurb, files in CLASSES:
            print("### %s — %d" % (title, len(files)))
            print()
            print(blurb)
            print()
            print("    " + "\n    ".join(
                " ".join(sorted(files)[i:i + 6]) for i in range(0, len(files), 6)))
            print()
    else:
        for title, _blurb, files in CLASSES:
            print("-- %s (%d)" % (title, len(files)))
            for f in sorted(files):
                print("     %s" % f)
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
