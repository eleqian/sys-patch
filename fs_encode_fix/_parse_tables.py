#!/usr/bin/env python3
"""Parse .data/.data.1 dumps (assembled from Ghidra read_memory JSON) into
function-pointer runs, and emit a table inventory."""
import json, struct, re, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))

def load(name):
    with open(os.path.join(HERE, name), "r") as f:
        return json.load(f)

chunks = []
for n in sorted(os.listdir(HERE)):
    m = re.match(r"^_d(\d+)\.json$", n)
    if m:
        chunks.append((int(m.group(1)), load(n)))
chunks.sort()
print(f"# loaded {len(chunks)} chunks", file=sys.stderr)

# concatenate: each chunk = {address, length, hex}
blob = bytearray()
base = None
for _, c in chunks:
    addr = int(c["address"], 16)
    if base is None:
        base = addr
    blob += bytes.fromhex(c["hex"])

TEXT_LO, TEXT_HI = 0x7100000000, 0x71001cb0e4

def is_text(v):
    return TEXT_LO <= v < TEXT_HI

n = len(blob)//8
vals = struct.unpack_from("<%dQ" % n, blob, 0)

runs = []
cur = None
for i, v in enumerate(vals):
    if is_text(v):
        if cur is None:
            cur = [i, i]
        else:
            # allow the run to continue
            pass
        cur[1] = i
    else:
        if cur is not None:
            runs.append(tuple(cur))
            cur = None
if cur:
    runs.append(tuple(cur))

print(f"# base=0x{base:012x} words={n} runs={len(runs)}")
print(f"{'#':>4} {'table_va':>14} {'n':>4}   entries")
for k, (s, e) in enumerate(runs):
    cnt = e - s + 1
    va = base + s*8
    print(f"{k:4d} 0x{va:012x} {cnt:4d}  " + " ".join("0x%x" % vals[j] for j in range(s, e+1)))
