#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_patch_sizes.py -- fs_codepage_patch() 构建期守卫。

校验两件事，任一失败即退出码 1（接入 make 后会让构建失败）：
  1. 补丁指令尺寸：sysmod/src/main.cpp 里的 PATCH_SZ_* #define 必须
     与链接产物 ELF 符号表中对应 patch_* 函数的实际尺寸（st_size）精确一致。
     尺寸不符 = 写入 fs 的函数被截断或污染相邻函数 → fs 崩溃/补丁失效。
  2. 补丁空间：每个函数的尺寸不得超过其补丁位在 fs 二进制中的"空洞"
     （补丁位到下一个存活函数的距离，来自 Ghidra 函数边界，见 HOLES 注释）。

用法：
  check_patch_sizes.py <elf> <main.cpp>            # 校验（make 钩子调用）
  check_patch_sizes.py <elf> <main.cpp> --update   # 用 ELF 实测尺寸回写 #define

纯标准库实现（直接解析 ELF64 符号表），不依赖 binutils/python 包。
"""

import argparse
import re
import struct
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# fs .text 段镜像基址（19.exfat.FS.kip1）
IMAGE_BASE = 0x7100000000

# 每个被写入 fs 的替换函数：
#   define  -- main.cpp 中的尺寸常量名
#   symbol  -- ELF 中（extern "C"）函数符号名
#   site    -- fs 补丁位偏移（相对 0x7100000000）
#   hole    -- 该补丁位可用空间上限（字节）
#   hole_src -- 空洞依据（Ghidra 函数边界，改 fs 目标固件版本时必须重推）
FUNCTIONS = [
    dict(define="PATCH_SZ_UTF8_TO_UTF16", symbol="patch_utf8_to_utf16",
         site=0xFEAC0, hole=0x170,
         site_name="PFCODE_CP932_OEM2Unicode",
         hole_src="next function 0x71000fec30 (PFCODE_CP932_Unicode2OEM)"),
    dict(define="PATCH_SZ_UTF16_TO_UTF8", symbol="patch_utf16_to_utf8",
         site=0xFEC30, hole=0x1D0,
         site_name="PFCODE_CP932_Unicode2OEM",
         hole_src="next function 0x71000fee00 (OEMCharWidth)"),
    dict(define="PATCH_SZ_IS_OEM_MB_CHAR", symbol="patch_is_oem_mb_char",
         site=0xFEE40, hole=0x4C,
         site_name="PFCODE_CP932_isOEMMBchar",
         hole_src="original function extent 0x71000fee40..0x71000fee8c"),
    dict(define="PATCH_SZ_STR_UNICODE2OEM", symbol="patch_str_unicode2oem",
         site=0xF5840, hole=0x120,
         site_name="PFCODE_Str_Unicode2OEM",
         hole_src="next function 0x71000f5960 (Str_OEM2Unicode)"),
    dict(define="PATCH_SZ_TOUPPER", symbol="patch_stringdesc_toupper",
         site=0xF7C10, hole=0xD0,
         site_name="StringDesc_ToUpper",
         hole_src="next function 0x71000f7ce0 (PFCODE_CP932_ConvertWidth)"),
]

DEFINE_RE = re.compile(r"(?m)^(#define\s+)(PATCH_SZ_[A-Z0-9_]+)(\s+)(0[xX][0-9a-fA-F]+|\d+)(\s*)$")


def elf_symbol_sizes(path):
    """解析 ELF64 符号表，返回 {符号名: st_size}。"""
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
            st_name, _info, _other, _shndx, _value, st_size = struct.unpack_from(
                "<IBBHQQ", data, off)
            if st_name == 0 or st_size == 0:
                continue
            symbols[cstr(strtab, st_name)] = st_size
    return symbols


def lookup_symbol(symbols, name):
    """精确匹配；找不到时容忍编译器改名（取以该名结尾且非零尺寸的唯一符号）。"""
    if name in symbols:
        return symbols[name]
    hits = [v for k, v in symbols.items() if k.endswith(name)]
    if len(hits) == 1:
        return hits[0]
    return None


def parse_defines(text):
    return {m.group(2): m for m in DEFINE_RE.finditer(text)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("main_cpp")
    ap.add_argument("--update", action="store_true",
                    help="rewrite PATCH_SZ_* defines from measured ELF sizes")
    args = ap.parse_args()

    try:
        symbols = elf_symbol_sizes(args.elf)
    except OSError as e:
        sys.exit("error: cannot read ELF: %s" % e)
    try:
        with open(args.main_cpp, "r", encoding="utf-8") as f:
            src = f.read()
    except OSError as e:
        sys.exit("error: cannot read source: %s" % e)

    defines = parse_defines(src)
    errors = []
    updates = []

    # 定义了但不在校验表里的 PATCH_SZ_* → 提醒同步本表
    known = {e["define"] for e in FUNCTIONS}

    rows = []
    for entry in FUNCTIONS:
        define_name, sym = entry["define"], entry["symbol"]
        actual = lookup_symbol(symbols, sym)
        site_va = IMAGE_BASE + entry["site"]
        hole = entry["hole"]

        if define_name not in defines:
            errors.append("%s: #define missing in %s" % (define_name, args.main_cpp))
            rows.append((define_name, sym, actual, None, hole, "DEFINE MISSING"))
            continue
        declared = int(defines[define_name].group(4), 0)

        if actual is None:
            errors.append("%s: symbol '%s' not found in ELF (renamed? inlined? removed?)"
                          % (define_name, sym))
            rows.append((define_name, sym, None, declared, hole, "SYMBOL NOT FOUND"))
            continue

        status = []
        # 运行时写入 fs 的拷贝长度是 #define 的值，实际尺寸与声明值任一
        # 超过空洞都算溢出（声明值过大时即使函数本身更小也会覆盖下一函数）。
        if declared > hole:
            errors.append("HOLEOVERFLOW %s: declared copy size 0x%X exceeds hole 0x%X at site 0x%X (%s) -- would overwrite %s"
                          % (define_name, declared, hole, entry["site"], entry["site_name"],
                             entry["hole_src"]))
            status.append("HOLE OVERFLOW")
        if actual != declared:
            errors.append("%s %s: #define 0x%X != actual size 0x%X in ELF%s"
                          % ("SIZEERR" if not args.update else "SIZEFIXED", define_name,
                             declared, actual, "" if not args.update else " (updated)"))
            updates.append((defines[define_name], actual))
            status.append("SIZE MISMATCH")
        if actual > hole:
            errors.append("%s: size 0x%X exceeds hole 0x%X at site 0x%X (%s) -- would overwrite %s"
                          % (define_name, actual, hole, entry["site"], entry["site_name"],
                             entry["hole_src"]))
            status.append("HOLE OVERFLOW")
        rows.append((define_name, sym, actual, declared, hole,
                     "OK" if not status else " / ".join(status)))

    # 定义了但不在校验表里的 PATCH_SZ_* → 提醒同步本表
    for name in defines:
        if name not in known:
            print("WARNING: %s defined in source but missing from check table "
                  "(add an entry with symbol/site/hole)" % name)

    print("patch size check (%s):" % args.elf)
    header = "  %-26s %-24s %-8s %-8s %-6s %s"
    print(header % ("DEFINE", "SYMBOL", "ACTUAL", "DECLARED", "HOLE", "STATUS"))
    for define_name, sym, actual, declared, hole, status in rows:
        print(header % (define_name, sym,
                        "0x%X" % actual if actual is not None else "-",
                        "0x%X" % declared if declared is not None else "-",
                        "0x%X" % hole, status))

    if updates:
        if not args.update:
            print("\nrun 'make update-patch-sizes' to rewrite the defines automatically")
        else:
            for match, actual in updates:
                src = src[:match.start()] + match.group(1) + match.group(2) + \
                      match.group(3) + "0x%02X" % actual + match.group(5) + src[match.end():]
            with open(args.main_cpp, "w", encoding="utf-8", newline="") as f:
                f.write(src)
            print("updated %d define(s) in %s" % (len(updates), args.main_cpp))

    if errors:
        # --update 模式下，已被回写修复的 size mismatch（SIZEFIXED）不再致命
        fatal = [e for e in errors if not e.startswith("SIZEFIXED ")]
        print()
        for e in errors:
            if e.startswith("SIZEFIXED "):
                print("fixed: " + e[len("SIZEFIXED "):])
            elif e.startswith("SIZEERR "):
                print("ERROR: " + e[len("SIZEERR "):])
            elif e.startswith("HOLEOVERFLOW "):
                print("ERROR: " + e[len("HOLEOVERFLOW "):])
            else:
                print("ERROR: " + e)
        if fatal:
            sys.exit(1)
        print("all size mismatches fixed; re-run the build to recompile")
        return
    print("all %d patch function sizes verified" % len(FUNCTIONS))


if __name__ == "__main__":
    main()
