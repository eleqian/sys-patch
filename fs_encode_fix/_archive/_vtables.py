#!/usr/bin/env python3
"""
Model the RW region as C++ vtables / dispatch tables.

Observed structure of a vtable in this binary:
    [d0]              -> (often 0x71000xxxxx real dtor, or a +8 biasing entry)
    [d1]              -> real destructor
    [0]               -> 0  (offset-to-top)
    [typeinfo]        -> ptr into .data (typeinfo)   <-- not always a code ptr
    [2]&[3]           -> stub pair: 0x7100026574 (ret), 0x710002657c (mov x0,xzr;ret)
    [4..]             -> real virtual methods

We detect vtables by the presence of the stub pair at index 2/3, then extend the
run forward while slots are code pointers.
"""
import struct, json, sys

IMGBASE = 0x7100000000
BIN = r"D:/Design/NS/ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1"
D = open(BIN, "rb").read()
FMAP = {int(k) + (IMGBASE if int(k) < 0x1000000 else 0): v
        for k, v in json.load(open("_fmap.json")).items()}

SEC = [
    (0x00000000, 0x001cb0e4, +0x100, ".text"),
    (0x001cc000, 0x0023f000, +0x100, ".rod"),
    (0x0023f110, 0x0024dd00, -0xe1c, ".data"),
    (0x0024de40, 0x0024fb30, -0xe1c, ".got"),
    (0x0024fb30, 0x0025f548, -0xe1c, ".data1"),
]
DATA_LO, DATA_HI = IMGBASE + 0x0023f110, IMGBASE + 0x0025f548
TEXT_LO, TEXT_HI = IMGBASE, IMGBASE + 0x001cb0e4

def dlt(va):
    off = va - IMGBASE
    for lo, hi, dl, n in SEC:
        if lo <= off < hi:
            return dl
    return None

def rd(va):
    dl = dlt(va)
    if dl is None:
        return None
    o = va - IMGBASE + dl
    if o < 0 or o + 8 > len(D):
        return None
    lo, hi = struct.unpack_from("<II", D, o)
    if hi:
        return None
    return lo + IMGBASE if lo else 0

def num(t):
    return t is not None and TEXT_LO <= t < TEXT_HI

def nm(t):
    if not t:
        return "(zero)"
    return FMAP.get(t, "")

V = {
    "stub_ret": 0x7100026574,
    "stub_0":   0x710002657c,
    "pure":     0x71001c90e0,
    "stubret":  0x71001c8fc0,
}

def find_vtables():
    out = []
    va = DATA_LO
    while va + 8 <= DATA_HI:
        s2, s3 = rd(va), rd(va + 8)
        if s2 in V.values() and s3 in V.values() and va % 16 == 0:
            # walk back up to 2 slots for the destructor pair
            base = va
            b1, b0 = rd(va - 8), rd(va - 16)
            if num(b1) and num(b0):
                base = va - 16
            elif num(b1):
                base = va - 8
            # walk forward
            slots = []
            cur = base
            while cur + 8 <= DATA_HI:
                t = rd(cur)
                if num(t) or t == 0 and False:
                    slots.append((cur, t))
                    cur += 8
                else:
                    break
            out.append((base, slots))
            va = cur
        else:
            va += 8
    return out

def main():
    tabs = find_vtables()
    print(f"# {len(tabs)} C++ vtables detected (stub pair at slot 2/3)\n")
    rows = []
    for base, slots in tabs:
        rows.append({
            "base": hex(base), "n": len(slots),
            "slots": [[hex(a), hex(t) if t else "0", nm(t)] for a, t in slots],
        })
    json.dump(rows, open("_vtables.json", "w"), indent=1)
    for r in rows:
        print(f"{r['base']}  n={r['n']:3d}")
    print("\n--- detail (first 20) ---")
    for r in rows[:20]:
        print(r["base"], "n=", r["n"])
        for a, t, n in r["slots"]:
            print("   ", a, "->", t, n)
        print()

if __name__ == "__main__":
    main()
