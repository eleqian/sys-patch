import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

BIN = r"D:/Design/NS/ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1"
BASE = 0x7100000000
raw = open(BIN, "rb").read()

def v2o(va):
    return 0x100 + (va - BASE)

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def dis(va, length, label):
    print(f"\n==== {label} @ {va:#x} ====")
    o = v2o(va)
    for ins in md.disasm(raw[o:o + length], va):
        ann = ""
        if ins.mnemonic in ("adrp", "adr", "b", "bl", "cbz", "cbnz", "tbz", "tbnz"):
            try:
                ann = f"   ; -> {ins.operands[-1].imm & 0xffffffffffff:#x}"
            except Exception:
                pass
        print(f"{ins.address:#x}  {ins.mnemonic:8s} {ins.op_str}{ann}")

# rest of OEM2Unicode (after patched region start 0x98) and rest of Unicode2OEM
dis(0x71000feb54, 0xDC, "OEM2Unicode tail (orig)")
dis(0x71000feca0, 0xF0, "Unicode2OEM tail (orig, dead code after patch)")

# dump the linear-scan table at 0x71001db814
off = v2o(0x71001db814)
print("\n==== table @ 0x71001db814 ====")
vals = struct.unpack_from("<64H", raw, off)
print([hex(v) for v in vals[:32]])
# check sortedness / find terminator: scan until 0 or descending run
prev = -1
end = None
for i in range(0, 0x8000, 2):
    v = struct.unpack_from("<H", raw, off + i)[0]
    if v < prev:
        end = off + i
        print(f"first descent at table+{i:#x} (VA {0x71001db814+i:#x}): prev={prev:#x} v={v:#x}")
        break
    prev = v
else:
    print("no descent within 0x8000")
