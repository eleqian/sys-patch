#!/usr/bin/env python3
"""
Enumerate function-pointer dispatch/vtable tables in the Switch FS KIP1 (19.exfat.FS.kip1).

CALIBRATED FILE<->VA MAPPING (verified against Ghidra memory reads):
  file_offset = (VA - 0x7100000000) + delta(section)
  delta:
     .text / .rodata / .rodata.1  : +0x100
     .data / .dynamic / .got / .data.1 : -0xe1c
  Pointer slots inside .data/.data.1 are stored in RELOCATED-pre form as a
  24-bit little-endian value equal to (target - 0x7100000000); the upper 4 bytes
  of the 8-byte slot are zero. (KIP1 is relocated at load time.)
"""
import struct, json, sys, re

BIN   = r"D:/Design/NS/ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1"
MAPF  = "_fmap.json"
IMGBASE = 0x7100000000

# section -> (va_lo_off, va_hi_off, file_delta)
SEC = {
    ".text":      (0x00000000, 0x001cb0e4, +0x100),
    ".rodata":    (0x001cc000, 0x001cc050, +0x100),
    ".rodata.1":  (0x001cc50e, 0x0023f000, +0x100),
    ".data":      (0x0023f110, 0x0024dd00, -0xe1c),
    ".got":       (0x0024de40, 0x0024fb30, -0xe1c),
    ".data.1":    (0x0024fb30, 0x0025f548, -0xe1c),
}
TEXT_LO, TEXT_HI = 0x00000000, 0x001cb0e4
DATA_LO, DATA_HI = 0x0023f110, 0x0025f548

D = open(BIN, "rb").read()
FMAP = {}
for line in open(MAPF):
    pass
FMAP = {int(k): v for k, v in json.load(open(MAPF)).items()}
# normalize: fmap keys are VAs already (full 0x71...)? check
_k = next(iter(FMAP))
if _k < 0x1000000:
    FMAP = {k + IMGBASE: v for k, v in FMAP.items()}


def delta_for_va(va):
    off = va - IMGBASE
    for _n, (lo, hi, dl) in SEC.items():
        if lo <= off < hi:
            return dl
    return None


def read_ptr(va):
    """Return target VA if the 8-byte slot at `va` holds a reloc-form code/data ptr."""
    dl = delta_for_va(va)
    if dl is None:
        return None
    o = va - IMGBASE + dl
    if o < 0 or o + 8 > len(D):
        return None
    lo = struct.unpack_from("<I", D, o)[0]
    hi = struct.unpack_from("<I", D, o + 4)[0]
    if hi != 0:
        return None
    if lo == 0:
        return 0
    return lo + IMGBASE


def is_code(va):
    return va is not None and TEXT_LO + IMGBASE <= va < TEXT_HI + IMGBASE


def is_data_ptr(va):
    return va is not None and (DATA_LO + IMGBASE) <= va < (DATA_HI + IMGBASE)


def name_of(va):
    if va is None:
        return None
    f = FMAP.get(va)
    if f:
        return f
    # table label?
    return None


def scan(lo_va, hi_va, min_run=3):
    """Yield (start_va, slots) runs of >=min_run consecutive code pointers."""
    va = lo_va
    res = []
    while va + 8 <= hi_va:
        t = read_ptr(va)
        if is_code(t):
            run = []
            cur = va
            while cur + 8 <= hi_va:
                tt = read_ptr(cur)
                if not is_code(tt):
                    break
                run.append((cur, tt))
                cur += 8
            if len(run) >= min_run:
                res.append((va, run))
            va = cur
        else:
            va += 8
    return res


def main():
    allt = []
    for sec, (lo, hi, dl) in SEC.items():
        if sec not in (".data", ".data.1", ".got"):
            continue
        runs = scan(IMGBASE + lo, IMGBASE + hi, min_run=3)
        for start, slots in runs:
            allt.append((sec, start, slots))
    allt.sort(key=lambda x: x[1])
    print(f"# {len(allt)} candidate pointer-runs (>=3 slots) in .data/.got/.data.1\n")
    for sec, start, slots in allt:
        named = sum(1 for _, t in slots if FMAP.get(t))
        print(f"[{sec}] 0x{start:012x}  slots={len(slots):2d}  named={named}")
    json.dump(
        [
            {"section": s, "va": hex(st), "slots": [[hex(a), hex(t), FMAP.get(t)] for a, t in sl]}
            for s, st, sl in allt
        ],
        open("_runs.json", "w"),
        indent=1,
    )


if __name__ == "__main__":
    print("fmap sample:", list(FMAP.items())[:2])
    main()
