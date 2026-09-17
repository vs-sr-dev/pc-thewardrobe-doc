"""Emit the redaction regex for this installation, derived from queen.ini.

The pattern itself is printed because redactnotes.py needs it on a command
line; it is never written into a document or a note.
"""
import re
import sys

SEP = chr(92)
src = sys.argv[1] if len(sys.argv) > 1 else "_game/queen.ini"
for line in open(src, encoding="latin1"):
    m = re.search(r"(?i)^path\s*=\s*(.+)$", line.strip())
    if m:
        p = m.group(1).strip()
        parts = [x for x in re.split("[" + SEP + SEP + "/]", p) if x]
        assert len(parts) >= 2, "install path has fewer than two components"
        pat = ("(?i)" + re.escape(parts[0]) + "[" + SEP + SEP + "/]"
               + re.escape(parts[1]))
        print(pat)
        break
else:
    raise SystemExit("no path= line in " + src)
