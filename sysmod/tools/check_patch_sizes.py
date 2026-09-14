#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_patch_sizes.py -- fs_codepage_patch() 构建期守卫。

每个补丁函数在源码中放入独立 .text.<函数名> section，函数体后有
<函数名>_end 汇编标签，运行时尺寸 = 标签地址 − 函数地址（无手工宏）。
本脚本校验两件事，任一失败即退出码 1（接入 make 后会让构建失败）：
  1. 标签正确性：(_end 符号地址 − 函数符号地址) 必须 == 函数符号的
     st_size。不等 = 标签被放错位置（如函数被延迟发射到标签之后、
     section 属性与标签指向的 section 不一致）→ 运行时算出的尺寸是
     垃圾值，绝不能写入 fs。
  2. 补丁空间：尺寸不得超过补丁位在 fs 二进制中的"空洞"
     （补丁位到下一个存活函数的距离，来自 Ghidra 函数边界，见 FUNCTIONS）。

用法：check_patch_sizes.py <elf>
纯标准库实现（直接解析 ELF64 符号表），不依赖 binutils/python 包。
"""

import argparse
import struct
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# fs .text 段镜像基址（19.exfat.FS.kip1）
IMAGE_BASE = 0x7100000000

# 每个被写入 fs 的替换函数：
#   symbol     -- 补丁函数（ELF 符号名，st_value/st_size）
#   end_symbol -- 函数体结束标签（紧随函数体，同 section）
#   site       -- fs 补丁位偏移（相对 0x7100000000）
#   hole       -- 该补丁位可用空间上限（字节）
#   hole_src   -- 空洞依据（Ghidra 函数边界，改 fs 目标固件版本时必须重推）
FUNCTIONS = [
    dict(symbol="patch_utf8_to_utf16", end_symbol="patch_utf8_to_utf16_end",
         site=0xFEAC0, hole=0x170,
         site_name="PFCODE_CP932_OEM2Unicode",
         hole_src="next function 0x71000fec30 (PFCODE_CP932_Unicode2OEM)"),
    dict(symbol="patch_utf16_to_utf8", end_symbol="patch_utf16_to_utf8_end",
         site=0xFEC30, hole=0x1D0,
         site_name="PFCODE_CP932_Unicode2OEM",
         hole_src="next function 0x71000fee00 (OEMCharWidth)"),
    dict(symbol="patch_is_oem_mb_char", end_symbol="patch_is_oem_mb_char_end",
         site=0xFEE40, hole=0x4C,
         site_name="PFCODE_CP932_isOEMMBchar",
         hole_src="original function extent 0x71000fee40..0x71000fee8c"),
    dict(symbol="patch_str_unicode2oem", end_symbol="patch_str_unicode2oem_end",
         site=0xF5840, hole=0x120,
         site_name="PFCODE_Str_Unicode2OEM",
         hole_src="next function 0x71000f5960 (Str_OEM2Unicode)"),
    dict(symbol="patch_stringdesc_toupper", end_symbol="patch_stringdesc_toupper_end",
         site=0xF7C10, hole=0xD0,
         site_name="StringDesc_ToUpper",
         hole_src="next function 0x71000f7ce0 (PFCODE_CP932_ConvertWidth)"),
]


def elf_symbols(path):
    """解析 ELF64 符号表，返回 {符号名: (st_value, st_size)}。"""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        sys.exit("error: %s is not an ELF file" % path)
    if data[4] != 2:
        sys.exit("error: %s is not a 64-bit ELF" % path)
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    sections = []
    for i in range(e_shnum):
        (sh_name, sh_type, _flags, _addr, sh_offset,
         sh_size, sh_link, _info, _align, sh_entsize) = struct.unpack_from(
            "<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
        sections.append(dict(name=sh_name, type=sh_type, offset=sh_offset,
                             size=sh_size, link=sh_link, entsize=sh_entsize))

    def cstr(blob, off):
        end = blob.index(b"\x00", off)
        return blob[off:end].decode("utf-8", "replace")

    symbols = {}
    for sec in sections:
        if sec["type"] != 2:  # SHT_SYMTAB
            continue
        strsec = sections[sec["link"]]
        strtab = data[strsec["offset"]:strsec["offset"] + strsec["size"]]
        entsize = sec["entsize"] or 24
        for off in range(sec["offset"], sec["offset"] + sec["size"], entsize):
            st_name, _info, _other, _shndx, st_value, st_size = struct.unpack_from(
                "<IBBHQQ", data, off)
            if st_name == 0:
                continue
            symbols[cstr(strtab, st_name)] = (st_value, st_size)
    return symbols


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    args = ap.parse_args()

    try:
        symbols = elf_symbols(args.elf)
    except OSError as e:
        sys.exit("error: cannot read ELF: %s" % e)

    errors = []
    rows = []
    for entry in FUNCTIONS:
        sym, end_sym = entry["symbol"], entry["end_symbol"]
        hole = entry["hole"]

        fn = symbols.get(sym)
        en = symbols.get(end_sym)
        if fn is None:
            errors.append("%s: symbol not found in ELF (renamed? inlined? removed?)" % sym)
            rows.append((sym, "-", "-", hole, "SYMBOL NOT FOUND"))
            continue
        if en is None:
            errors.append("%s: end label '%s' not found in ELF "
                          "(missing __asm__ end label / wrong section name?)" % (sym, end_sym))
            rows.append((sym, "0x%X" % fn[1], "-", hole, "END LABEL NOT FOUND"))
            continue

        fval, fsize = fn
        delta = en[0] - fval
        status = []
        if delta != fsize:
            errors.append("%s: end-label delta 0x%X != st_size 0x%X -- runtime size is wrong, "
                          "do NOT deploy (label misplaced or function deferred past it)"
                          % (sym, delta, fsize))
            status.append("LABEL MISMATCH")
        if delta > hole:
            errors.append("%s: size 0x%X exceeds hole 0x%X at site 0x%X (%s) -- would overwrite %s"
                          % (sym, delta, hole, entry["site"], entry["site_name"], entry["hole_src"]))
            status.append("HOLE OVERFLOW")
        rows.append((sym, "0x%X" % fsize, "0x%X" % delta, hole,
                     "OK" if not status else " / ".join(status)))

    print("patch size check (%s):" % args.elf)
    header = "  %-26s %-8s %-8s %-6s %s"
    print(header % ("SYMBOL", "ST_SIZE", "LABEL-D", "HOLE", "STATUS"))
    for sym, fsize, delta, hole, status in rows:
        print(header % (sym, fsize, delta, "0x%X" % hole, status))

    if errors:
        print()
        for e in errors:
            print("ERROR: %s" % e)
        sys.exit(1)
    print("all %d patch function sizes verified" % len(FUNCTIONS))


if __name__ == "__main__":
    main()
