#!/usr/bin/env python3
"""
Group pointer-runs into TABLES and resolve every slot name.
A table = maximal span where every 8-byte slot is either a code pointer or a
zero-pad slot, and the span is separated from the next table by >=16 zero bytes
(two zero slots) -- matching the observed .data layout.
"""
import struct, json

BIN   = r"D:/Design/NS/ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1"
IMGBASE = 0x7100000000
FMAP = {int(k) + (IMGBASE if int(k) < 0x1000000 else 0): v
        for k, v in json.load(open("_fmap.json")).items()}

SEC = {
    ".text":   (0x00000000, 0x001cb0e4, +0x100),
    ".rodata": (0x001cc000, 0x0023f000, +0x100),
    ".data":   (0x0023f110, 0x0024dd00, -0xe1c),
    ".got":    (0x0024de40, 0x0024fb30, -0xe1c),
    ".data.1": (0x0024fb30, 0x0025f548, -0xe1c),
}
TEXT_LO, TEXT_HI = IMGBASE, IMGBASE + 0x001cb0e4
DATA_LO, DATA_HI = IMGBASE + 0x0023f110, IMGBASE + 0x0025f548

D = open(BIN, "rb").read()

def dlt(va):
    off = va - IMGBASE
    for _n, (lo, hi, dl) in SEC.items():
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

def isnum(t):
    return t is not None and (TEXT_LO <= t < TEXT_HI)

def nm(va):
    if va is None or va == 0:
        return "(zero)"
    return FMAP.get(va, "")

# ---- enumerate tables over the RW region -------------------------------
result = []
va = DATA_LO
while va + 8 <= DATA_HI:
    t = rd(va)
    if isnum(t):
        start = va
        slots = []
        lastptr = va
        cur = va
        while cur + 8 <= DATA_HI:
            tt = rd(cur)
            if isnum(tt):
                slots.append((cur, tt))
                lastptr = cur
                cur += 8
                continue
            # allow up to 2 zero slots of padding if a pointer follows
            if tt == 0:
                # peek ahead
                nxt = rd(cur + 8)
                nxt2 = rd(cur + 16)
                if isnum(nxt):
                    slots.append((cur, 0))
                    cur += 8
                    continue
                if nxt == 0 and isnum(nxt2):
                    break  # 2+ zeros => table end
                break
            break
        end = lastptr
        result.append((start, end, slots))
        va = cur
    else:
        va += 8

# merge tables separated by exactly <=8 bytes gap (i.e. one zero slot)
merged = []
for tb in result:
    if merged and tb[0] - merged[-1][1] <= 16:
        s, e, sl = merged[-1]
        merged[-1] = (s, tb[1], sl + tb[2])
    else:
        merged.append(list(tb) if isinstance(tb, tuple) else tb)
merged = [tuple(x) for x in merged]
result = merged

print(f"# {len(result)} tables in RW region\n")
rows = []
for start, end, slots in result:
    rows.append(
        {
            "base": hex(start),
            "end": hex(end),
            "n": len(slots),
            "slots": [[hex(a), hex(t) if t else "0", nm(t)] for a, t in slots],
        }
    )
json.dump(rows, open("_tables.json", "w"), indent=1)
for r in rows[:60]:
    print(f"{r['base']} .. {r['end']}  n={r['n']:3d}")
