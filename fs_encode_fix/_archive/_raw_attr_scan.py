"""Scan directory attributes under a path on the raw FAT32 volume.

Usage: python _raw_attr_scan.py /Roms [max_levels]
Prints, per level, how many DIR entries have attr 0x10 (plain) vs 0x30 (DIR|ARCHIVE).
"""
import sys
import os
import importlib.util

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("rl", os.path.join(here, "_raw_ls.py"))
rl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rl)


def resolve(fs, clus, name):
    rec = rl.find_subdir(fs, clus, name)
    if not rec:
        return None
    return (rec[6] << 16) | rec[7]


def main():
    path = sys.argv[1]
    levels = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    f = rl.open_vol()
    fs = rl.Fat32(f)
    clus = fs.root_clus
    for p in [x for x in path.split("/") if x]:
        c = resolve(fs, clus, p)
        if c is None:
            print("NOT FOUND", p)
            return
        clus = c

    total10 = total30 = other = 0
    frontier = [(path, clus, 0)]
    while frontier:
        cur_path, cur_clus, depth = frontier.pop(0)
        if depth >= levels:
            continue
        plain, arch, oth, subdirs = [], [], [], []
        for rec in rl.parse_dir(fs, cur_clus):
            slot, off, raw, name83, lfn, attr, hi, lo, size = rec
            if not (attr & 0x10):
                continue
            disp = lfn or name83
            if disp in (".", "..") or name83 in ("", "."):
                continue
            if attr == 0x10:
                plain.append(disp)
            elif attr == 0x30:
                arch.append(disp)
            else:
                oth.append("%s(0x%02x)" % (disp, attr))
            if depth + 1 < levels:
                subdirs.append((disp, (hi << 16) | lo))
        total10 += len(plain)
        total30 += len(arch)
        other += len(oth)
        print("[%d] %-24s 0x10=%d 0x30=%d other=%d" % (depth, cur_path, len(plain), len(arch), len(oth)))
        if arch:
            print("      0x30: %s" % ", ".join(arch[:12]))
        if oth:
            print("      other: %s" % ", ".join(oth[:8]))
        if level_ok(depth):
            for name, c in subdirs:
                frontier.append((cur_path + "/" + name, c, depth + 1))
    print("TOTAL: 0x10 dirs=%d  0x30 dirs=%d  other=%d" % (total10, total30, other))
    f.close()


def level_ok(depth):
    return True


if __name__ == "__main__":
    main()
