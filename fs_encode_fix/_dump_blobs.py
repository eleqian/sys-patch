"""临时工具：反汇编 sysmod ELF 里的 fs 替换体，核对指令构成与空洞余量。

用法：python _dump_blobs.py [符号名 ...]（缺省列全部 FUNCTIONS）
"""
import importlib.util
import sys

TOOLS = r"D:/Design/NS/sys-patch/sysmod/tools/check_patch_sizes.py"
ELF = r"D:/Design/NS/sys-patch/sysmod/sys-patch.elf"

spec = importlib.util.spec_from_file_location("guard", TOOLS)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

symbols, segments = guard.elf_symbols(ELF)
want = sys.argv[1:] or [e["symbol"] for e in guard.FUNCTIONS]
holes = {e["symbol"]: e["hole"] for e in guard.FUNCTIONS}

import capstone  # noqa: E402

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

for name in want:
    if name not in symbols:
        print("!! %s not found" % name)
        continue
    va, size = symbols[name]
    blob = guard.read_by_addr(segments, va, size)
    hole = holes.get(name, 0)
    print("=== %s  size=0x%X  hole=0x%X  slack=0x%X" % (name, size, hole, hole - size))
    for ins in md.disasm(blob, va):
        print("  +0x%03X  %-10s %s" % (ins.address - va, ins.mnemonic, ins.op_str))
