#!/usr/bin/env python3
"""
FS callback/vtable inventory -- definitive pass.

Model (verified):
  * Objects store vptr = &(vtable[-2]) i.e. offset_to_top,typeinfo precede slot0.
    In practice vptr points 0x10 before the first method slot.
  * The vptr values live in the .got table (0x710024de40..0x710024fb30) as
    24-bit reloc-form pointers into .data.
  * A vtable run = consecutive 8-byte slots in .data that are zero or code
    pointers, starting at vptr+0x10.

This script enumerates every .got entry that points into .data, then dumps the
vtable slots with resolved names.
"""
import struct, json

IMGBASE = 0x7100000000
BIN = r"D:/Design/NS/ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1"
D = open(BIN, "rb").read()
FMAP = {int(k) + (IMGBASE if int(k) < 0x1000000 else 0): v
        for k, v in json.load(open("_fmap.json")).items()}

# section deltas
SEC = [
    (0x00000000, 0x001cb0e4, +0x100),
    (0x001cc000, 0x0023f000, +0x100),
    (0x0023f110, 0x0024dd00, -0xe1c),
    (0x0024de40, 0x0024fb30, -0xe1c),
    (0x0024fb30, 0x0025f548, -0xe1c),
]
TEXT_LO, TEXT_HI = IMGBASE, IMGBASE + 0x001cb0e4
DATA_LO, DATA_HI = IMGBASE + 0x0023f110, IMGBASE + 0x0025f548
GOT_LO, GOT_HI = 0x0024de40, 0x0024fb30

def dlt(va):
    off = va - IMGBASE
    for lo, hi, dl in SEC:
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

def in_data(t):
    return t is not None and DATA_LO <= t < DATA_HI

# ---- collect vptrs from .got ------------------------------------------
vptrs = []
for off in range(GOT_LO, GOT_HI, 8):
    va = IMGBASE + off
    v = rd(va)
    if in_data(v):
        vptrs.append((va, v))

print(f"# {len(vptrs)} GOT entries point into .data\n")

def dump_vtable(vptr, maxslots=200):
    """vtable slots start at vptr+0x10."""
    base = vptr + 0x10
    slots = []
    cur = base
    while cur + 8 <= DATA_HI and len(slots) < maxslots:
        t = rd(cur)
        if num(t):
            slots.append((cur, t))
            cur += 8
        elif t == 0:
            # zero slot allowed only as padding at end-of-run lookahead
            nxt = rd(cur + 8)
            if num(nxt):
                slots.append((cur, 0))
                cur += 8
            else:
                break
        else:
            break
    return slots

rows = []
for got_va, vptr in vptrs:
    sl = dump_vtable(vptr)
    rows.append({
        "got": hex(got_va),
        "vptr": hex(vptr),
        "slot0": hex(vptr + 0x10),
        "n": len(sl),
        "slots": [[hex(a), hex(t) if t else "0", nm(t)] for a, t in sl],
    })

json.dump(rows, open("_inventory.json", "w"), indent=1)
print("wrote _inventory.json")

# summary
big = sorted(rows, key=lambda r: -r["n"])
for r in big[:30]:
    print(f"vptr={r['vptr']} slot0={r['slot0']} n={r['n']:3d}  "
          f"first={r['slots'][0][2] or r['slots'][0][1]}")
