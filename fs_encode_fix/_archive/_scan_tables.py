#!/usr/bin/env python3
"""Scan .text for aarch64 functions that load a function-pointer table base
via ADRP/ADD and then BR/indirect-call — then report the table address.

Heuristic: find ADRP+ADD (or ADRP+LDR) pairs whose computed address lands in
.data (0x710023f110-0x710024dcff) or .rodata.1, i.e. the base of a dispatch
table. We only report addresses that are 8-aligned and inside .data first.
"""
import struct, sys

BIN = r"D:/Design/NS/ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1"
# segment map (from Ghidra list_segments)
SEGS = [
    (0x7100000000, 0x71001cb0e4, ".text"),
    (0x71001cc000, 0x71001cc04f, ".rodata"),
    (0x71001cc050, 0x71001cc4b7, ".relr.dyn"),
    (0x71001cc500, 0x71001cc50d, ".dynstr"),
    (0x71001cc50e, 0x710023efff, ".rodata.1"),
    (0x710023f000, 0x710023f10f, ".init_array"),
    (0x710023f110, 0x710024dcff, ".data"),
    (0x710024dd00, 0x710024de3f, ".dynamic"),
    (0x710024de40, 0x710024fb2f, ".got"),
    (0x710024fb30, 0x710025f547, ".data.1"),
    (0x7100260000, 0x7100ffd20f, ".bss"),
]
BASE = 0x7100000000
IMAGE_OFF = 0x100  # NS KIP1: elf header at 0x100? verify by magic

with open(BIN, "rb") as f:
    raw = f.read()

# find ELF magic
idx = raw.find(b"\x7fELF")
print(f"ELF magic at file offset {hex(idx)}", file=sys.stderr)
assert idx >= 0

def v2o(va):
    return idx + (va - BASE)

def o2v(off):
    return BASE + (off - idx)

# Load .data
d_start, d_end = 0x710023f110, 0x710024dcff
d_off = v2o(d_start)
d_len = d_end - d_start
data = raw[d_off:d_off+d_len]

def in_text(v):
    return 0x7100000000 <= v < 0x71001cb0e4

def in_rodata1(v):
    return 0x71001cc50e <= v <= 0x710023efff

def in_data(v):
    return d_start <= v <= d_end

# walk .data as 8-byte words, find maximal runs of text pointers
runs = []
cur = None
for i in range(0, len(data) - 7, 8):
    v = struct.unpack_from("<Q", data, i)[0]
    isptr = in_text(v)
    if isptr:
        if cur is None:
            cur = [i, i+8]
        else:
            cur[1] = i+8
    else:
        if cur is not None:
            runs.append(tuple(cur))
            cur = None
if cur:
    runs.append(tuple(cur))

print(f"# total runs of text-pointers in .data: {len(runs)}")
print(f"{'table_va':>14} {'count':>5} {'first_fn':>14} {'last_fn':>14}")
for s, e in runs:
    n = (e - s)//8
    if n < 2:
        continue
    va = d_start + s
    vals = struct.unpack_from("<%dQ" % n, data, s)
    print(f"0x{va:012x} {n:5d} 0x{vals[0]:012x} 0x{vals[-1]:012x}")
