#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_patch_sizes.py -- fs_codepage_patch() 构建期守卫（尺寸 + 空间 + 机器码）。

校验三件事，任一失败即退出码 1（接入 make 后会让构建失败）：

  1. 替换函数尺寸标签：(_end 地址 − 函数地址) 必须 == ELF 符号 st_size。
     不等 = 标签错位（如函数被延迟发射到标签之后）→ 运行时尺寸是垃圾值。
  2. 补丁空间：函数尺寸 ≤ 补丁位"空洞"（到下一个存活函数的距离，Ghidra 边界）。
  3. 手工字节补丁的机器码合法性（本脚本解析 src/main.cpp 得到实际字节）：
     每个改动过的 32 位指令必须是 nop / movz（Rd 不变）/ add 移位寄存器形式且
     **imm6=0、shift=0、Rm=w0|x0、Rd/Rn 与原指令一致**。
     —— 曾两次踩坑：R1 写成 `add w10,w10,w0,lsl #1`（Rn 丢失 + 带位移）、
        FAT_GetNextChar 写成 `add x9,x0,x0`（Rn 丢失），都会算出垃圾地址/索引，
        让 fs 崩溃或挂死（表现为开机卡 logo、log.ini 为空）。该规则可全自动拦截。

可选：若找得到 fs 目标二进制（$FS_KIP1 或内置默认路径），还会逐点比对 cmp 字节，
防止补丁位偏移写错 / 目标固件不匹配。

用法：check_patch_sizes.py <elf> [--main <main.cpp>] [--fs <fs.kip1>]
纯标准库实现（自己解析 ELF64 符号表 + 最小 AArch64 解码），不依赖 binutils/capstone。
"""

import argparse
import os
import re
import struct
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# fs .text 段镜像基址（19.exfat.FS.kip1）
IMAGE_BASE = 0x7100000000

# 替换函数（会被整函数写入 fs，其 cmp 字节只是版本指纹，不做指令级校验）
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

# 默认 fs 目标二进制（本机 RE 副本）；不存在则跳过 cmp 比对
DEFAULT_FS = "D:/Design/NS/ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1"


# ---------------------------------------------------------------- ELF 符号表

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


# ------------------------------------------------- 最小 AArch64 解码（够用即可）

def dec_add_imm(w):
    """ADD/SUB (immediate)。返回 None 或 dict(sf, rd, rn, imm, is_sub)。"""
    if ((w >> 23) & 0x3F) != 0b100010:
        return None
    if (w >> 22) & 1:                      # sh(bit22)=1 = 左移 12 的立即数，本补丁不用
        return None
    return dict(sf=(w >> 31) & 1, rd=w & 0x1F, rn=(w >> 5) & 0x1F,
                imm=(w >> 10) & 0xFFF, is_sub=(w >> 30) & 1)


def dec_add_reg(w):
    """ADD (shifted register)。返回 None 或 dict(sf, rd, rn, rm, shift, imm6)。"""
    if ((w >> 24) & 0x1F) != 0b01011:
        return None
    if (w >> 21) & 1:                      # bit21=1 = SUB
        return None
    return dict(sf=(w >> 31) & 1, rd=w & 0x1F, rn=(w >> 5) & 0x1F,
                rm=(w >> 16) & 0x1F, shift=(w >> 22) & 3, imm6=(w >> 10) & 0x3F)


def dec_csel_csinc(w):
    """CSEL / CSINC。返回 None 或 dict(sf, rd, rn, op2)。"""
    if ((w >> 21) & 0xFF) != 0b11010100:
        return None
    if (w >> 30) & 1:                      # op=1 = CSINV/CSNEG
        return None
    return dict(sf=(w >> 31) & 1, rd=w & 0x1F, rn=(w >> 5) & 0x1F, op2=(w >> 10) & 3)


def dec_movz(w):
    """MOVZ（mov Wd, #imm 的一种形式）。返回 None 或 dict(sf, rd, imm)。"""
    if ((w >> 23) & 0xFF) != 0b10100101:
        return None
    if ((w >> 21) & 3) != 0:               # hw=0
        return None
    return dict(sf=(w >> 31) & 1, rd=w & 0x1F, imm=(w >> 5) & 0xFFFF)


NOP = 0xD503201F


def dec_mem(w):
    """整数 load/store（unsigned-offset imm12 / unscaled imm9）。返回 None 或
    dict(load, size, rt, rn, off)。用于识别"只把访问宽度由 b 改 h"的合法改写。"""
    if ((w >> 27) & 0x7) != 0b111:
        return None
    opc = (w >> 22) & 3
    idx = (w >> 24) & 3          # 01 = unsigned offset, 00 = unscaled
    if idx == 0b01:
        off = (w >> 10) & 0xFFF
    elif idx == 0b00:
        off = (w >> 12) & 0x1FF
        if off & 0x100:
            off -= 0x200
    else:
        return None
    return dict(load=(opc & 1) == 1, size=(w >> 30) & 3, rt=w & 0x1F,
                rn=(w >> 5) & 0x1F, off=off)


def check_word_pair(cmp_w, pat_w):
    """校验一处被改写的 32 位指令，返回错误字符串或 None。"""
    if pat_w == NOP:
        return None                                   # -> nop 永远合法
    if pat_w == cmp_w:
        return "patch equals original (no-op patch?)"

    a = dec_add_reg(pat_w)
    if a is not None:
        # 允许的等价改写：add <Rd>, <Rn>, x0/w0（无移位）
        if a["rm"] != 0:
            return ("add has Rm=w%d, expected w0 (0x%08X)" % (a["rm"], pat_w))
        if a["imm6"] != 0 or a["shift"] != 0:
            return ("add carries shift/imm6=%d/shift=%d, expected none (0x%08X)"
                    % (a["imm6"], a["shift"], pat_w))
        if a["rd"] != (cmp_w & 0x1F):
            return ("add Rd=w%d != original Rd=w%d (0x%08X)"
                    % (a["rd"], cmp_w & 0x1F, pat_w))
        if a["rn"] != ((cmp_w >> 5) & 0x1F):
            return ("add Rn=w%d != original Rn=w%d (0x%08X)"
                    % (a["rn"], (cmp_w >> 5) & 0x1F, pat_w))
        # 原指令应确实是 ADD/CSEL/CSINC 之一，否则改写的语义无法确认
        if dec_add_imm(cmp_w) is None and dec_csel_csinc(cmp_w) is None:
            return ("original 0x%08X is not ADD-imm/CSEL/CSINC; refusing to guess"
                    % cmp_w)
        return None

    m = dec_movz(pat_w)
    if m is not None:
        if m["rd"] != (cmp_w & 0x1F):
            return ("movz Rd=w%d != original Rd=w%d (0x%08X)"
                    % (m["rd"], cmp_w & 0x1F, pat_w))
        return None

    # 允许"同一地址、同一寄存器的访问宽度改写"（ldrb->ldrh / strb->sturh）
    cm = dec_mem(cmp_w)
    pm = dec_mem(pat_w)
    if cm and pm:
        if (cm["rn"], cm["off"], cm["rt"], cm["load"]) != \
           (pm["rn"], pm["off"], pm["rt"], pm["load"]):
            return ("memory access changed operands (cmp rn=%d off=%d rt=%d load=%d / "
                    "patch rn=%d off=%d rt=%d load=%d)"
                    % (cm["rn"], cm["off"], cm["rt"], cm["load"],
                       pm["rn"], pm["off"], pm["rt"], pm["load"]))
        return None

    return "unsupported patch encoding 0x%08X (only nop / add Rd,Rn,w0 / movz / same-addr width change)" % pat_w


# --------------------------------------------------- main.cpp 提取补丁对

ARRAY_RE = re.compile(
    r"const\s+u8\s+(\w+)\s*\[\s*\d*\s*\]\s*=\s*\{(.*?)\}\s*;", re.S)
CALL_RE = re.compile(
    r"fs_patch_function\(\s*handle\s*,\s*mem_info\.addr\s*\+\s*(0x[0-9a-fA-F]+)\s*,"
    r"\s*(\w+)\s*,\s*sizeof\s*\(\s*\2\s*\)\s*,\s*([^,]+?)\s*,", re.S)


def strip_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return src


def parse_bytes(blob):
    out = []
    for tok in blob.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if not re.fullmatch(r"0[xX][0-9a-fA-F]+", tok):
            return None
        out.append(int(tok, 16) & 0xFF)
    return out


def extract_sites(main_cpp):
    with open(main_cpp, "r", encoding="utf-8") as f:
        src = strip_comments(f.read())

    arrays = {}
    for m in ARRAY_RE.finditer(src):
        data = parse_bytes(m.group(2))
        if data is not None:
            arrays[m.group(1)] = bytes(data)

    sites = []
    for m in CALL_RE.finditer(src):
        site = int(m.group(1), 16)
        cmp_name = m.group(2)
        patch_expr = m.group(3)
        pm = re.search(r"(\w+)\s*$", patch_expr)
        patch_name = pm.group(1) if pm else ""
        sites.append(dict(site=site, cmp_name=cmp_name, patch_name=patch_name,
                          cmp=arrays.get(cmp_name), patch=arrays.get(patch_name)))
    return sites


# -------------------------------------------------------------------- 主流程

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--main", default="src/main.cpp",
                    help="main.cpp 路径（默认相对 sysmod 目录）")
    ap.add_argument("--fs", default=os.environ.get("FS_KIP1", DEFAULT_FS),
                    help="fs 目标二进制（用于 cmp 字节比对；缺失则跳过）")
    args = ap.parse_args()

    try:
        symbols = elf_symbols(args.elf)
    except OSError as e:
        sys.exit("error: cannot read ELF: %s" % e)

    errors = []

    # ---- 1/2. 替换函数：结束标签 + 空洞
    print("patch size check (%s):" % args.elf)
    header = "  %-26s %-8s %-8s %-6s %s"
    print(header % ("SYMBOL", "ST_SIZE", "LABEL-D", "HOLE", "STATUS"))
    rows = []
    for entry in FUNCTIONS:
        sym, end_sym = entry["symbol"], entry["end_symbol"]
        hole = entry["hole"]
        fn, en = symbols.get(sym), symbols.get(end_sym)
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
    for sym, fsize, delta, hole, status in rows:
        print(header % (sym, fsize, delta, "0x%X" % hole, status))

    # ---- 3. 指令级补丁校验
    fs_offsets = {e["site"] for e in FUNCTIONS}
    try:
        sites = extract_sites(args.main)
    except OSError as e:
        sys.exit("error: cannot read main source: %s" % e)

    print()
    print("instruction patch check (%s):" % args.main)
    print(header % ("SITE", "KIND", "WORDS", "", "STATUS"))
    fs_data = None
    if args.fs and os.path.exists(args.fs):
        with open(args.fs, "rb") as f:
            fs_data = f.read()
        fs_note = "cmp vs %s" % os.path.basename(args.fs)
    else:
        fs_note = "cmp skipped (fs binary not found)"

    checked = 0
    for s in sites:
        site = s["site"]
        name = s["patch_name"] or s["cmp_name"]
        if site in fs_offsets:
            print(header % ("0x%X" % site, "replace-func", "-", "", "OK (size-checked)"))
            continue
        if s["cmp"] is None or s["patch"] is None:
            errors.append("0x%X (%s): byte array not found/parseable (%s / %s)"
                          % (site, name, s["cmp_name"], s["patch_name"]))
            print(header % ("0x%X" % site, "?", "-", "", "ARRAY NOT FOUND"))
            continue

        cmp_b, pat_b = s["cmp"], s["patch"]
        status = []
        if len(cmp_b) != len(pat_b):
            status.append("LENGTH MISMATCH")
            errors.append("0x%X (%s): cmp %d bytes != patch %d bytes"
                          % (site, name, len(cmp_b), len(pat_b)))
        else:
            changed = 0
            for i in range(0, len(cmp_b) - 3, 4):
                cw = struct.unpack_from("<I", cmp_b, i)[0]
                pw = struct.unpack_from("<I", pat_b, i)[0]
                if cw == pw:
                    continue
                changed += 1
                err = check_word_pair(cw, pw)
                if err:
                    status.append("BAD INSN@+%d" % i)
                    errors.append("0x%X (%s) +0x%X: 0x%08X -> 0x%08X: %s"
                                  % (site, name, i, cw, pw, err))
                else:
                    status.append("ok@+%d" % i)
            if changed == 0:
                status.append("NO CHANGE")
                errors.append("0x%X (%s): patch bytes identical to cmp bytes" % (site, name))

        # cmp 与 fs 二进制比对（校验偏移/固件版本）
        if fs_data is not None:
            foff = 0x100 + site
            got = fs_data[foff:foff + len(cmp_b)]
            if got != cmp_b:
                status.append("FS CMP MISMATCH")
                errors.append("0x%X (%s): fs binary cmp mismatch (want %s got %s) -- "
                              "wrong offset or wrong firmware"
                              % (site, name, cmp_b.hex(), got.hex()))
        print(header % ("0x%X" % site, "byte-patch", "%d" % (len(cmp_b) // 4),
                        ("%s" % ("; ".join(status) if status else "OK")), ""))
        checked += 1

    print("  (%s; %d instruction patch sites checked)" % (fs_note, checked))

    if errors:
        print()
        for e in errors:
            print("ERROR: %s" % e)
        sys.exit(1)
    print("all %d replacement functions and %d instruction patches verified"
          % (len(FUNCTIONS), checked))


if __name__ == "__main__":
    main()
