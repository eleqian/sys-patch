# -*- coding: utf-8 -*-
"""解码 main.cpp 中全部 (cmp -> patch) 指令变换。"""
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

CASES = [
    (0xd4af4, "IDirectory_Read NOP", "e3fcff54", "1f2003d5"),
    (0xf45d8, "FAT_GetNextChar(3rd insn)", "09050091", "0900008b"),
    (0xf4d8c, "FAT_GetNextPathComponent", "09050091", "0901008b"),
    (0xf77e8, "AddLeft", "c806961a", "c802000b"),
    (0xf7984, "GetCharCount", "7306939a", "7302008b"),
    (0xf7a80, "CompareUnicode", "6802969a", "6802008b"),
    (0xf7bd0, "CompareOem", "9402979a", "9402008b"),
    (0xf4888, "R1 site1", "2a050011", "4a05000b"),
    (0xf49c4, "R1 site2", "280b0011", "280b000b"),
    (0xf4a90, "R1 site3", "2a050011", "4a05000b"),
    (0xf5dcc, "R2 MakeShortName", "f703002a", "57008052"),
]

def dec(hx, addr):
    out = []
    for i in md.disasm(bytes.fromhex(hx), addr):
        out.append("%s %s" % (i.mnemonic, i.op_str))
    return " | ".join(out) if out else "<INVALID>"

for site, name, cmp_hx, pat_hx in CASES:
    print("@0x%-7x %-26s" % (site, name))
    print("     cmp   %-18s -> %s" % (cmp_hx, dec(cmp_hx, site)))
    print("     patch %-18s -> %s" % (pat_hx, dec(pat_hx, site)))
