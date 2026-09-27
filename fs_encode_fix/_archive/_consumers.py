#!/usr/bin/env python3
"""
Find, for each vptr (GOT entry value pointing into .data), the functions that
load that GOT slot via `adrp xN,page ; ldr xM,[xN,#imm]`.

Once we know a function loads a given vptr, that function is (usually) the
constructor or a factory for the class whose vtable is `vptr+0x10`.
"""
import struct, json, bisect

IMGBASE = 0x7100000000
BIN = r"D:/Design/NS/ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1"
D = open(BIN, "rb").read()
FMAP = {int(k) + (IMGBASE if int(k) < 0x1000000 else 0): v
        for k, v in json.load(open("_fmap.json")).items()}
INV = json.load(open("_inventory.json"))

TEXT_F = 0x100
TEXT_END = 0x100 + 0x1cb0e4
GOT_LO, GOT_HI = 0x0024de40, 0x0024fb30

fstarts_sorted = sorted(FMAP.items())
fkeys = [a for a, _ in fstarts_sorted]

def func_of(va):
    i = bisect.bisect_right(fkeys, va) - 1
    if i < 0:
        return None, None
    return fstarts_sorted[i][1], fstarts_sorted[i][0]

def adrp_target(va, w):
    if (w & 0x9F000000) != 0x90000000:
        return None
    imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return ((va & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF

def ldr_off(w):
    """unsigned-offset load (64-bit): 1111 1001 01 imm12 Rn Rt  -> opc=01"""
    if (w & 0xFFC00000) != 0xF9400000:
        return None
    imm12 = (w >> 10) & 0xFFF
    return imm12 * 8, (w >> 5) & 0x1F, w & 0x1F   # byte offset, Rn, Rt

def main():
    # map got_va -> vptr for quick lookup
    got2vp = {int(r["got"], 16): int(r["vptr"], 16) for r in INV}
    got_pages = {}
    for g in got2vp:
        got_pages.setdefault(g & ~0xFFF, []).append(g)

    consumers = {}   # vptr -> list of (insn_va, func_name)
    n = (TEXT_END - TEXT_F) // 4
    for i in range(n):
        fo = TEXT_F + i * 4
        va = fo - TEXT_F + IMGBASE
        w = struct.unpack_from("<I", D, fo)[0]
        page = adrp_target(va, w)
        if page is None or page not in got_pages:
            continue
        rd = w & 0x1F
        w2 = struct.unpack_from("<I", D, fo + 4)[0]
        # form A: ldr xM,[xN,#off]  (load the GOT slot value)
        lo = ldr_off(w2)
        if lo is not None:
            off, rn, rt = lo
            if rn == rd:
                lit = page + off
                if lit in got2vp:
                    vp = got2vp[lit]
                    fn, _ = func_of(va)
                    consumers.setdefault(vp, []).append((hex(va), fn))
        # form B: add xM,xN,#imm12  (address-of the GOT slot)
        if (w2 & 0xFF800000) == 0x91000000:
            if ((w2 >> 5) & 0x1F) == rd:
                lit = page + ((w2 >> 10) & 0xFFF)
                if lit in got2vp:
                    vp = got2vp[lit]
                    fn, _ = func_of(va)
                    consumers.setdefault(vp, []).append((hex(va), fn))

    json.dump({hex(k): v for k, v in consumers.items()},
              open("_vptr_consumers.json", "w"), indent=1)
    print(f"# {len(consumers)} vptrs have identified loaders\n")
    for r in INV:
        vp = int(r["vptr"], 16)
        c = consumers.get(vp, [])
        if r["slots"]:
            first = r["slots"][0][2] or r["slots"][0][1]
        else:
            first = "(empty)"
        print(f"{r['vptr']} n={r['n']:3d} first={first:40s} <- "
              + ", ".join(f for _, f in c[:3]))

if __name__ == "__main__":
    main()
