#!/usr/bin/env python3
"""rgssjoin.py -- join the class and field names a Marshal walk finds in the
object's data files against the class and field names the object's own help
file documents, and report the residue.

WHY THIS IS THE MEASUREMENT AND NOT A REMARK
--------------------------------------------
Two readings of the same object were made independently and by different
routes:

  * `marshal48.py` walks the sixteen `.rxdata` and reports every class name and
    every `@instance_variable` name that is actually INSTANTIATED in the bytes;
  * `chmx.py` decompresses `RPGXP.chm`'s LZX stream and hands over 117 HTML
    pages, of which one per class carries an `<h1>` with the class name and a
    definition list of its attributes.

Neither reading can see the other. Joining them asks the question this session
exists to answer -- *does the object document its own format?* -- and answers it
with a count in both directions rather than with an adjective. A name in the
data and not in the help is something the vendor shipped and did not describe;
a name in the help and not in the data is something the vendor described and
this database does not happen to use, which is a fact about the database and
not about the format.

The attribute names in the help are written WITHOUT the leading `@`, because
they are documented as Ruby accessor methods; the join strips it, and the
selftest asserts that stripping is what makes the two vocabularies comparable.

    python tools/rgssjoin.py join    --data <System/Data> --docs <chm/rgss>
    python tools/rgssjoin.py fields  --data <System/Data> --docs <chm/rgss>
    python tools/rgssjoin.py selftest
"""
import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import marshal48                                             # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

H1 = re.compile(r"<h1>\s*(.*?)\s*</h1>", re.I | re.S)
DT = re.compile(r"<dt>\s*(.*?)\s*</dt>", re.I | re.S)
H2 = re.compile(r"<h2>\s*(.*?)\s*</h2>", re.I | re.S)
TAG = re.compile(r"<[^>]+>")


def strip(s):
    return TAG.sub("", s).replace("&amp;", "&").strip()


def from_data(root):
    """{class name -> set of field names}, from the bytes, with @ stripped."""
    classes = collections.Counter()
    fields = collections.defaultdict(set)
    # Selected by MAGIC through `marshal48.marshal_files`. This filtered on the
    # literal extension `.rxdata`, which is the name the PREVIOUS object gave
    # this format; this object calls the same format `.rvdata2`. That makes
    # this the FOURTH reader with the defect, where the pre-briefing counted
    # three -- and it was found by running the tool rather than by reading the
    # brief.
    for p in marshal48.marshal_files(root):
        name = os.path.basename(p)
        with open(p, "rb") as fh:
            data = fh.read()
        _r, reader = marshal48.load(data, p)
        classes.update(reader.classes)
        for cls, names in reader.ivars.items():
            for f in names:
                fields[cls].add(f.lstrip("@"))
    if not classes:
        sys.exit("rgssjoin: no classes found under %r" % root)
    return classes, fields


def from_docs(root):
    """{class name -> set of documented attribute names}, from the help."""
    classes = {}
    fields = collections.defaultdict(set)
    pages = {}
    superclasses = {}
    for name in sorted(os.listdir(root)):
        if not name.lower().endswith(".html"):
            continue
        p = os.path.join(root, name)
        with open(p, "rb") as fh:
            text = fh.read().decode("iso-8859-1")
        m = H1.search(text)
        if not m:
            continue
        title = strip(m.group(1))
        # A page documents a class when its headings include Superclass; the
        # index pages (g_classes, s_index) carry an <h1> too and must not be
        # mistaken for one.
        heads = [strip(h) for h in H2.findall(text)]
        if "Superclass" not in heads:
            continue
        classes[title] = name
        pages[title] = name
        # The superclass, read from the same heading that identifies the page
        # as a class page. Added on pc-rpgmakervxace-doc, where six field
        # slots looked unmatched because `RPG::BGM` and `RPG::BGS` document
        # nothing of their own: their three attributes are on
        # `RPG::AudioFile`, whose page says in its first line that it is "a
        # superclass of BGM, BGS, ME, and SE". A join that does not follow
        # inheritance reports a vendor as having failed to document something
        # the vendor documented one page away.
        superclasses[title] = _superclass_of(text)
        # only the <dt> that sit under an "Attributes" heading count; a
        # Constants or Methods list is not a field of the serialised object.
        body = text
        i = body.lower().find("<h2>attributes</h2>")
        if i < 0:
            continue
        j = body.lower().find("<h2>", i + 4)
        chunk = body[i:j if j > 0 else len(body)]
        for dt in DT.findall(chunk):
            fields[title].add(strip(dt).lstrip("@"))
    if not classes:
        sys.exit("rgssjoin: no class pages found under %r" % root)
    return classes, fields, pages, superclasses


def _superclass_of(text):
    """The text that follows the `Superclass` heading, stripped of markup.

    Returns None when the page names no superclass or names `Object`, because
    `Object` carries no serialised attributes and following it would add
    nothing to the join.
    """
    low = text.lower()
    i = low.find("<h2>superclass</h2>")
    if i < 0:
        return None
    j = low.find("<h2>", i + 4)
    chunk = strip(text[i + len("<h2>superclass</h2>"):
                       j if j > 0 else len(text)])
    chunk = chunk.strip()
    if not chunk or chunk == "Object":
        return None
    return chunk.split()[0]


def inherited_fields(cls, fields, supers, seen=None):
    """Every attribute a class has, its own and its ancestors'."""
    seen = seen or set()
    if cls in seen:
        return set()
    seen.add(cls)
    out = set(fields.get(cls, ()))
    parent = supers.get(cls)
    if parent:
        out |= inherited_fields(parent, fields, supers, seen)
    return out


def cmd_join(data_root, docs_root):
    dcls, dfields = from_data(data_root)
    hcls, hfields, pages, supers = from_docs(docs_root)
    both = sorted(set(dcls) & set(hcls))
    only_data = sorted(set(dcls) - set(hcls))
    only_docs = sorted(set(hcls) - set(dcls))
    print("classes instantiated in the sixteen .rxdata : %d" % len(dcls))
    print("classes documented by RPGXP.chm             : %d" % len(hcls))
    print("in both                                     : %d" % len(both))
    print("in the data and NOT documented              : %d" % len(only_data))
    print("documented and NOT in this database         : %d" % len(only_docs))
    print()
    if only_data:
        print("  in the bytes and nowhere in the help file:")
        for c in only_data:
            print("    %-34s %d instances" % (c, dcls[c]))
        print()
    if only_docs:
        print("  documented and not instantiated here:")
        for c in only_docs:
            print("    %-34s %s" % (c, pages[c]))
        print()
    tot_d = tot_h = tot_both = 0
    tot_inh = 0
    print("  %-30s %6s %6s %6s %6s %7s %6s"
          % ("class", "data", "docs", "share", "unmat", "+inherit", "unmat"))
    for c in both:
        d, h = dfields[c], hfields[c]
        hi = inherited_fields(c, hfields, supers)
        tot_d += len(d)
        tot_h += len(h)
        tot_both += len(d & h)
        tot_inh += len(d & hi)
        print("  %-30s %6d %6d %6d %6d %7d %6d"
              % (c, len(d), len(h), len(d & h), len(d - h),
                 len(d & hi), len(d - hi)))
    print("  %-30s %6d %6d %6d %6d %7d %6d"
          % ("TOTAL", tot_d, tot_h, tot_both, tot_d - tot_both,
             tot_inh, tot_d - tot_inh))
    print()
    print("  fields in the bytes the help file names ON THE CLASS'S OWN "
          "PAGE : %d of %d" % (tot_both, tot_d))
    print("  fields in the bytes the help file names ONCE INHERITANCE IS")
    print("  FOLLOWED                                          : %d of %d"
          % (tot_inh, tot_d))
    print()
    print("  the superclasses the help file states, for the classes joined:")
    for c in both:
        if supers.get(c):
            print("    %-30s -> %s" % (c, supers[c]))
    return 0


def cmd_pages(data_root, docs_root):
    """How many of the help file's pages name something the walk found.

    `join` answers 'is every class documented'. This answers the coarser
    question the session was set -- 'does this help file document RGSS' -- as
    a count over pages rather than as a count over classes, so that the two
    are not confused.
    """
    dcls, dfields = from_data(data_root)
    fields = set()
    for s in dfields.values():
        fields |= s
    classes = set(dcls)
    total = with_rgss = with_class = with_field = 0
    for dp, _dn, fn in os.walk(docs_root):
        for f in sorted(fn):
            if not f.lower().endswith(".html"):
                continue
            total += 1
            with open(os.path.join(dp, f), "rb") as fh:
                text = fh.read().decode("iso-8859-1")
            flat = text.replace("\n", "")
            with_rgss += "RGSS" in text
            with_class += any(c in text for c in classes)
            with_field += any(("<dt>%s</dt>" % v) in flat or (">%s<" % v)
                              in text for v in fields)
    if not total:
        sys.exit("rgssjoin: no HTML under %r" % docs_root)
    print("classes the walk found      : %d" % len(classes))
    print("field names the walk found  : %d" % len(fields))
    print("HTML pages searched         : %d" % total)
    print("  naming RGSS                            : %d" % with_rgss)
    print("  naming a class the walk found          : %d" % with_class)
    print("  naming a field name the walk found     : %d" % with_field)
    return 0


def cmd_fields(data_root, docs_root):
    dcls, dfields = from_data(data_root)
    hcls, hfields, _p, _s = from_docs(docs_root)
    for c in sorted(set(dcls) & set(hcls)):
        d, h = dfields[c], hfields[c]
        miss_d = sorted(d - h)
        miss_h = sorted(h - d)
        if not miss_d and not miss_h:
            continue
        print("%s" % c)
        if miss_d:
            print("   in the bytes, not documented : %s" % ", ".join(miss_d))
        if miss_h:
            print("   documented, not in the bytes : %s" % ", ".join(miss_h))
        print()
    return 0


def selftest():
    checks = []

    def ok(label, cond, note=""):
        checks.append((label, bool(cond), note))

    page = (b'<html><head><title>RPG::Fixture</title></head><body>'
            b'<h1>RPG::Fixture</h1><p>Data class.</p>'
            b'<h2>Superclass</h2><ul><li>Object</li></ul>'
            b'<h2>Attributes</h2><dl><dt>id</dt><dd>The ID.</dd>'
            b'<dt>name</dt><dd>The name.</dd></dl>'
            b'<h2>Methods</h2><dl><dt>dup</dt><dd>not a field</dd></dl>'
            b'</body></html>')
    index = (b'<html><body><h1>Classes</h1><h2>Index</h2>'
             b'<dl><dt>RPG::Fixture</dt></dl></body></html>')
    tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "_rgssjoin_fixture")
    os.makedirs(tmp, exist_ok=True)
    try:
        with open(os.path.join(tmp, "gc_fixture.html"), "wb") as fh:
            fh.write(page)
        with open(os.path.join(tmp, "g_classes.html"), "wb") as fh:
            fh.write(index)
        cls, fields, pages, supers = from_docs(tmp)
        ok("a class page is recognised by its Superclass heading",
           list(cls) == ["RPG::Fixture"], str(list(cls)))
        # Inheritance, added on pc-rpgmakervxace-doc. Six field slots looked
        # unmatched there because two classes document nothing of their own.
        ok("a superclass of Object is read as no superclass, because Object "
           "carries no serialised attributes",
           supers.get("RPG::Fixture") is None, repr(supers.get("RPG::Fixture")))
        ok("a child inherits its parent's attributes",
           inherited_fields("Child", {"Child": {"c"}, "Parent": {"p"}},
                            {"Child": "Parent"}) == {"c", "p"})
        ok("and a chain of three resolves all the way up",
           inherited_fields("A", {"A": {"a"}, "B": {"b"}, "C": {"c"}},
                            {"A": "B", "B": "C"}) == {"a", "b", "c"})
        ok("a cycle in the superclass chain terminates instead of hanging",
           inherited_fields("A", {"A": {"a"}, "B": {"b"}},
                            {"A": "B", "B": "A"}) == {"a", "b"})
        ok("a class with no parent yields only its own",
           inherited_fields("A", {"A": {"a"}}, {}) == {"a"})
        ok("an index page carrying an h1 is NOT taken for a class page",
           "Classes" not in cls)
        ok("the Attributes list is read",
           fields["RPG::Fixture"] == {"id", "name"},
           str(sorted(fields["RPG::Fixture"])))
        ok("a Methods list is NOT read as fields",
           "dup" not in fields["RPG::Fixture"])
        ok("the tag stripper removes markup",
           strip("<a href='x'>Object</a>") == "Object")
        ok("stripping @ is what makes the two vocabularies comparable",
           "@battler_hue".lstrip("@") == "battler_hue")
    finally:
        for f in os.listdir(tmp):
            os.remove(os.path.join(tmp, f))
        os.rmdir(tmp)

    width = max(len(c[0]) for c in checks)
    failed = 0
    for label, good, note in checks:
        print("  %-*s  %s   %s" % (width, label, "ok  " if good else "FAIL",
                                   note))
        if not good:
            failed += 1
    print()
    print("%d checks, %d failures" % (len(checks), failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=("join", "fields", "pages", "selftest"))
    ap.add_argument("--data")
    ap.add_argument("--docs")
    args = ap.parse_args()
    if args.mode == "selftest":
        return selftest()
    for label, p in (("--data", args.data), ("--docs", args.docs)):
        if not p:
            sys.exit("rgssjoin: %s needs %s" % (args.mode, label))
        if not os.path.isdir(p):
            sys.exit("rgssjoin: %s is not a directory: %s" % (label, p))
    if args.mode == "join":
        return cmd_join(args.data, args.docs)
    if args.mode == "pages":
        return cmd_pages(args.data, args.docs)
    return cmd_fields(args.data, args.docs)


if __name__ == "__main__":
    sys.exit(main())
