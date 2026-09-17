BS = chr(92)
NUL = chr(0)
# the program list at 0x1A3, as each disc's own documentation prints it,
# with one NUL terminator per entry
lists = {
    "Atlas":          (["minwin A:" + BS], 474),
    "Bible":          (["minwin A:"],      473),
    "Fitness":        (["minwin a:" + BS], 474),
    "Sherlock":       (["A:MOUSE.COM", "SHI.EXE"], 483),
    "Race the Clock": (["minwin A:"],      473),
}
BASE = 463
print("%-15s %-26s %4s %5s %6s %s" % ("disc", "program list at 0x1A3",
                                      "len", "base", "pred", "actual"))
ok = 0
for k, (entries, actual) in lists.items():
    L = sum(len(e) + 1 for e in entries)
    pred = BASE + L
    good = pred == actual
    ok += good
    print("%-15s %-26s %4d %5d %6d %6d  %s"
          % (k, NUL.join(entries).replace(NUL, "|"), L, BASE, pred, actual,
             "MATCH" if good else "NO"))
print()
print("%d of %d" % (ok, len(lists)))
