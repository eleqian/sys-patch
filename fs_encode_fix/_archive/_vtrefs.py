#!/usr/bin/env python3
"""
For each detected vtable, find who references its base address (the constructor
`*obj = &VTABLE`) by scanning the .text for an ADRP+ADD pair that yields the VA.
Then report the referencing function name from the function map.
"""
import struct, json, sys

IMGBASE = 0x7100000000
BIN = r"D:/Design/NS/ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1"
D = open(BIN, "rb").read()
FMAP = {int(k) + (IMGBASE if int(k) < 0x1000000 else 0): v
        for k, v in json.load(open("_fmap.json")).items()}
VTS = json.load(open("_vtables.json"))

TEXT_FILE_BASE = 0x100          # file offset of VA 0x7100000000
TEXT_END_FILE = 0x100 + 0x1cb0e4

# build a sorted list of (va, name) function starts for "which function contains X"
fstarts = sorted(FMAP.items())

import bisect
fkeys = [a for a, _ in fstarts]
fvals = [n for _, n in fstarts]


def func_containing(va):
    i = bisect.bisect_right(fkeys, va) - 1
    if i < 0:
        return None
    return fstarts[i][1], fstarts[i][0]


def find_adrp_add_refs(target_va, limit=6):
    """Scan .text for `adrp xN, page(target); add xN, xN, #off(target)` or
       `adrp xN,page; ldr/str` patterns by decoding ADRP + ADD imm.
       We look for the 21-bit ADRP literal plus the ADD imm12 == target&0xfff.
       Return list of (insn_va, reg)."""
    hits = []
    page = target_va & ~0xfff
    off = target_va & 0xfff
    for fo in range(TEXT_FILE_BASE, TEXT_END_FILE, 4):
        va = fo - TEXT_FILE_BASE + IMGBASE
        w = struct.unpack_from("<I", D, fo)[0]
        if (w & 0x9F000000) != 0x90000000:      # ADRP
            continue
        immhi = (w >> 5) & 0x7FFFF
        immlo = (w >> 29) & 3
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        pc = va & ~0xfff
        val = (pc + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
        if val != page:
            continue
        rd = w & 0x1F
        # next insn: ADD Xd, Xn, #imm12  (0x91000000 mask)
        w2 = struct.unpack_from("<I", D, fo + 4)[0]
        if (w2 & 0xFF800000) == 0x91000000:
            imm12 = (w2 >> 10) & 0xFFF
            rn = (w2 >> 5) & 0x1F
            if rn == rd and imm12 == off:
                hits.append((va, rd))
                if len(hits) >= limit:
                    break
    return hits


def main():
    refs = {}
    for r in VTS:
        b = int(r["base"], 16)
        hits = find_adrp_add_refs(b)
        callers = []
        for va, rd in hits:
            fn, fstart = func_containing(va)
            if fn and (not callers or callers[-1][1] != fn):
                callers.append((hex(va), fn))
        refs[r["base"]] = callers
    json.dump(refs, open("_vtable_refs.json", "w"), indent=1)
    for r in VTS:
        c = refs[r["base"]]
        print(f"{r['base']} n={r['n']:3d} <- " + ", ".join(n for _, n in c[:3]))


if __name__ == "__main__":
    main()
