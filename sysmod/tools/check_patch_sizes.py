#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_patch_sizes.py -- fs_codepage_patch() 构建期守卫（尺寸 + 空间 + pattern 表）。

校验四件事，任一失败即退出码 1（接入 make 后会让构建失败）：

  1. 替换函数尺寸标签：(_end 地址 − 函数地址) 必须 == ELF 符号 st_size。
     不等 = 标签错位（如函数被延迟发射到标签之后）→ 运行时尺寸是垃圾值。
  2. 补丁空间：函数尺寸 ≤ 补丁位"空洞"（到下一个存活函数的距离，Ghidra 边界）。
  3. fs 补丁表（src/fs_codepage.cpp 的 fs_inst_patches[] / fs_blob_patches[]）
     结构合法：pattern 语法与长度上限、inst_offset 落在 pattern 内、cond ∈ 谓词清单、
     cond 与 patch 配套、分组区间连续覆盖两条表。
     —— 谓词清单是 X 宏 FS_PRED_LIST 的唯一定义处，条目表没有 pred_idx 列，因此
        「位号与 cond 脱节」在结构上不可能发生；守卫只核对 cond 在白名单里。
  4. pattern 命中（需要 fs 二进制）：每条 pattern 在 fs 的 .text 里**恰好命中 1 次**，
     且命中处 inst_offset 上的指令满足它标注的规则的 cond（函数体替换点则检查
     落点像不像函数入口）。
     —— pattern 驱动定位的安全性完全建立在这两点上：命中 0 次只是不写（安全失败），
        命中 ≥2 次就可能写到别的函数里去。
  5. 现场收割：`patch_str_unicode2oem` / `patch_widechar_compare` 需要 fs 的代码页上下文
     指针（首个还要的 callee 地址），而这些**逐版本变化**（26 个 fs 变体实测 ctx 槽有
     18 个不同地址、callee 有 3 种形状），所以不能写死：补丁器在覆写前从原函数体里收割
     原版自己的 `adrp+ldr`（→ 槽）与「跳出函数体的 bl」（→ callee），重编码后填进替换体
     最前的哨兵位。这里查两件事：① 替换体最前必须是固定顺序的占位哨兵（否则运行期判
     FAILED_HARVEST 不写）；② 参考固件上原函数能收割出唯一槽 / 唯一去重 callee（否则同上）。

说明：命令式的补丁字节不再是"手写常量"，而是由 fs_codepage.cpp 里 rules_*(inst) 从
命中到的真实指令现场算出（寄存器/地址/宽度全继承），因此没有"校验手写机器码"一项。

用法：check_patch_sizes.py <elf> [--main <fs_codepage.cpp>] [--fs <fs.kip1>]
纯标准库实现（自己解析 ELF64 符号表 + 最小 AArch64 判定），不依赖 binutils/capstone。
"""

import argparse
import collections
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
         site=0xFEE40, hole=0x50,
         site_name="PFCODE_CP932_isOEMMBchar",
         hole_src="original extent 0xfee40..0xfee8c + the udf padding word at 0xfee8c; "
                  "0xfee90 (mov w0,#2; ret) is a callback-table stub and must be preserved"),
    dict(symbol="patch_str_unicode2oem", end_symbol="patch_str_unicode2oem_end",
         site=0xF5840, hole=0x120,
         site_name="PFCODE_Str_Unicode2OEM",
         hole_src="next function 0x71000f5960 (Str_OEM2Unicode)"),
    dict(symbol="patch_stringdesc_toupper", end_symbol="patch_stringdesc_toupper_end",
         site=0xF7C10, hole=0xB0,
         site_name="StringDesc_ToUpper",
         hole_src="next function 0x71000f7ce0 (PFCODE_CP932_ConvertWidth)；"
                  "14.x/15.x 实测最小洞 0xB0（0819/081b 的 15.0.1 上为 0xd0），取全局最小 0xB0"),
    dict(symbol="patch_widechar_compare", end_symbol="patch_widechar_compare_end",
         site=0xF4770, hole=0x360,
         site_name="WideChar_Compare",
         hole_src="三种形状的洞 = 0x360(17-20.x) / 0x370(21-22.x) / 0x380(16.1.0)"
                  "（原件函数体实测 0x35c / 0x36c / 0x37c），取最小者 0x360"),
    dict(symbol="patch_fat_getnextchar", end_symbol="patch_fat_getnextchar_end",
         site=0xF44E0, hole=0x240,
         site_name="FAT_GetNextChar",
         hole_src="入口 = 19.exfat 实测 0xF44E0（守卫/审计脚本按模板命中点核对；"
                  "0xF44E0 + 0x290 正好是下一个函数 WideChar_Compare 的入口 0xF4770）。"
                  "48 个固件变体实测（真入口由 bl 目标确定）：洞 0x250(592 B, 22.x) / "
                  "0x260(608 B, 17.x·21.x) / 0x270(624 B) / 0x280(640 B) / 0x290(656 B)，"
                  "取最小者 0x250；14.x/15.x 后来实测更小 → 全局最小 0x240(576 B)。"
                  "⚠️ 启发式函数边界会把入口判后 ~0xbc，进而把洞低估到 "
                  "0x1a4 —— 必须按 bl 目标确定入口"),
]

# 默认 fs 目标二进制（本机 RE 副本）；不存在则跳过 cmp 比对
DEFAULT_FS = "D:/Design/NS/ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1"


# ---------------------------------------------------------------- ELF 符号表

def elf_symbols(path):
    """返回 (符号表 {名: (st_value, st_size)}, 可寻址段 [(addr, size, bytes)])。"""
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
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
         sh_size, sh_link, _info, _align, sh_entsize) = struct.unpack_from(
            "<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
        sections.append(dict(name=sh_name, type=sh_type, flags=sh_flags,
                             addr=sh_addr, offset=sh_offset, size=sh_size,
                             link=sh_link, entsize=sh_entsize))

    shstr = sections[e_shstrndx]

    def cstr(blob, off):
        end = blob.index(b"\x00", off)
        return blob[off:end].decode("utf-8", "replace")

    shstrtab = data[shstr["offset"]:shstr["offset"] + shstr["size"]]
    for s in sections:
        s["sname"] = cstr(shstrtab, s["name"]) if s["name"] else ""

    symbols = {}
    segments = []
    for sec in sections:
        if sec["type"] == 1 and (sec["flags"] & 0x2) and sec["size"]:   # PROGBITS+ALLOC
            segments.append((sec["addr"], sec["size"],
                             data[sec["offset"]:sec["offset"] + sec["size"]]))
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
    return symbols, segments


def read_by_addr(segments, addr, size):
    """按链接期虚拟地址从可寻址段里取字节。"""
    for saddr, ssize, blob in segments:
        if saddr <= addr and addr + size <= saddr + ssize:
            off = addr - saddr
            return blob[off:off + size]
    return None


# --------------------------------------------- 拷贝进 fs 的函数：位置无关性检查
#
# 这些函数会被原样拷到 fs 进程里执行，而 Switch 模块有加载地址随机化（ASLR）：
# Ghidra/ELF 里的绝对地址在运行时没有意义（内存里是"链接基址 + 随机偏移"）。
# 因此函数体内 **不得出现任何绝对地址物化**，也不得调用外部函数/引用外部数据，
# 所有引用必须是相对自身 PC 的（adrp/adr + add）。
# 允许的 PC 相对"本函数地址"物化：adrp xN, page + add xN, xN, #lo12 —— 因为被
# 拷到 fs 后它算出的正是该函数在 fs 中的运行时地址（编译期常量差不变）。

def scan_absolutes(code):
    """扫描函数体，返回可疑的绝对/外部引用列表 [(偏移, 说明)]。

    只关心"像地址的宽常量"：由 MOVZ/MOVK 拼出且最终值 ≥ 0x1000000（16 MiB）。
    小的合成常量（如返回值 0x00010002、掩码 0xfffffffd 走 MOVN）不误报。

    ★ P1 之后**唯一**合法的 adrp 用法是「adrp + add 同寄存器」（模块内 PC 相对，
    拷贝后自洽）。旧版还允许「adrp +0x159000 页增量 + ldr [x,#0xb50]」直接读
    fs 上下文槽 —— 那条路已被**现场收割**（哨兵占位）取代：槽地址在 26 份变体里
    有 18 个取值，写死就只能在恰好一份固件上工作。所以现在出现这种编码就是 bug，
    不再放行（原文的"槽在 0xf5000 页"断言一并删除——它本来就是死代码）。"""
    hits = []
    reg_val = {}                     # 寄存器 -> 由 MOVZ/MOVK 拼出的当前值
    adrp_regs = {}                   # adrp 目标寄存器 -> 偏移（等它后面的指令）
    for off in range(0, len(code) - 3, 4):
        w = struct.unpack_from("<I", code, off)[0]
        rd = w & 0x1F
        # LDR (literal) —— 字面量池在拷贝后指向 sysmod 的数据，必然错
        if (w & 0x3B000000) == 0x18000000:
            hits.append((off, "LDR-literal (literal pool / external data)"))
            continue
        # BL —— 只允许跳到函数体内（= 自递归）。bl 的立即数是相对自身 PC 的，
        # 整段原样拷进 fs 后偏移恒等 ⇒ 自递归是安全的、自包含的。
        # 跳到函数体外的 bl 仍然禁止（外部调用必须改写为经收割地址的 blr）。
        if (w & 0xFC000000) == 0x94000000:
            imm26 = w & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= 1 << 26
            tgt = off + (imm26 << 2)
            if not (0 <= tgt < len(code)):
                hits.append((off, "BL branches outside the function (external call) -- "
                                  "use blr with a harvested address instead"))
            continue
        # B（无条件跳转）—— 只允许跳到函数体内（表跳转/尾调用都会跳出去）
        if (w & 0xFC000000) == 0x14000000:
            imm26 = w & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= 1 << 26
            tgt = off + (imm26 << 2)
            if not (0 <= tgt < len(code)):
                hits.append((off, "B branches outside the function (tail call?)"))
            continue
        # adrp：只允许「adrp + add 同寄存器」这一种 PC 相对用法
        if (w & 0x9F000000) == 0x90000000:
            adrp_regs[rd] = (off, w)
            continue
        if (w & 0x1F800000) == 0x12800000:      # MOVN/MOVZ/MOVK
            opc = (w >> 29) & 3                 # 0=MOVN 2=MOVZ 3=MOVK
            hw = (w >> 21) & 3
            imm = (w >> 5) & 0xFFFF
            if opc == 2:
                reg_val[rd] = imm << (16 * hw)
            elif opc == 3:
                mask = 0xFFFF << (16 * hw)
                reg_val[rd] = (reg_val.get(rd, 0) & ~mask) | (imm << (16 * hw))
            else:
                reg_val.pop(rd, None)           # MOVN 是掩码常量，不参与地址合成
                continue
            if reg_val[rd] >= 0x1000000:
                hits.append((off, "MOVZ/MOVK builds wide constant 0x%X (address-like)"
                             % reg_val[rd]))
            continue
        if rd in adrp_regs:
            base_off, _adrp_w = adrp_regs.pop(rd)
            # 唯一允许：adrp + add 同寄存器 —— 模块内 PC 相对访问，拷贝后仍自洽
            if ((w >> 24) & 0x1F) == 0b01011 and ((w >> 5) & 0x1F) == rd:
                continue
            hits.append((base_off, "ADRP use not allowed (only ADRP+ADD self-relative; the "
                                   "fs context slot must go through the sentinel harvest, "
                                   "never a hardcoded page/offset): next insn 0x%08X" % w))
    for base_off, _w in adrp_regs.values():
        hits.append((base_off, "unused ADRP"))
    return hits



# ------------------------------------------------- fs 补丁表：解析 + 校验
#
# src/fs_codepage.cpp 里的 fs_inst_patches[] / fs_blob_patches[] 是**手维护的**
# 权威表（旧的 PATTERNS.json 生成链已不在仓库）。这里做的是"改完之后仍然自洽"
# 的构建期检查，纯标准库、不依赖 capstone。
#
# fs 补丁的安全性完全建立在「每条 pattern 在目标 .text 里恰好唯一命中一次」上：
# 命中 0 次只是不写（安全失败），命中 ≥2 次就可能写到别的函数里去。

PATTERN_MAX = 60          # PatternData::data[60]（单点写法下 槽数 == 模板字节数）

# --- 现场收割（哨兵占位对）：与 fs_codepage.cpp 的 FS_*_SENTINEL_* 常量一致 -------------
# 有些替换体不能写死「全局槽地址」或「被调用函数的地址」——它们逐版本变化（26 份 fs
# 变体实测槽地址有 18 个取值、callee 有 3 种形状）。补丁器在覆写前从**原函数体**里收割：
#   · ctx 槽  ← 原件里唯一的 `adrp + ldr` 对（Rd=Rn=Rt）
#   · callee  ← 原件里目标跳出函数体的 bl 的**去重目标**
# 再按占位指令自身的真实地址重编码成 `adrp+add` 覆写函数体**最前面**的哨兵。
# 因此哨兵必须在最前面且顺序固定 —— 位置漂了，pc 假设就不成立（下面会查）。
FS_CTX_SENTINELS = (0xDEAD0001, 0xDEAD0002)
FS_CALL_SENTINELS = (0xDEAD0003, 0xDEAD0004)
FS_CTX_SCAN = 0x120            # 原件 ctx 扫描窗口（= 最小洞 0x120）
FS_CALL_SCAN = 0x300           # 原件 callee 扫描窗口（≥ 最后一条外跳 bl 的偏移、
                               #  < 最小函数体 0x35c；与 fs_codepage.cpp 的 FS_CALL_SCAN 一致）
FS_CTX_MAX_DELTA = 0x400000    # 槽与代码的合理最大距离（26 份实测 1.3~1.7 MB）

# 需要现场收割的替换体（ELF 符号名）-> 期望的函数体最前哨兵字序列
HARVEST_BLOBS = {
    "patch_str_unicode2oem":  FS_CTX_SENTINELS,                        # 只 ctx 对
    "patch_widechar_compare": FS_CTX_SENTINELS + FS_CALL_SENTINELS,    # ctx 对 + callee 对
    "patch_fat_getnextchar":  FS_CTX_SENTINELS,                        # 只 ctx 对
}
# 需要查收割可行性的 blob 实现名（对应 fs_blob_patches[] 的 FsBlobImpl）
HARVEST_IMPLS = {"StrUnicode2Oem", "WideCharCompare", "FatGetNextChar"}

# 条目表（手维护，改格式时这里必须同步：解析不出来 = 静默跳过 = 不校验）
# 条目名 = `<功能名>_<版本范围>`（如 fs_cp_makeshortname_15.0.1-20.5.0），故名字字符集
# 必须允许 `. + - ,`——不然整表 0 命中、守卫"通过"却什么都没查（踩过）。
#   fs_inst_patches[]: { "name", "0x…pattern", inst_offset, cond, patch }
#   fs_blob_patches[]: { "name", "0x…pattern", entry_offset, FsBlobImpl::Impl }
PAT_RE = re.compile(
    r'\{\s*"([A-Za-z0-9_.,+-]+)",\s*"(0x[0-9A-Fa-f.]+)",\s*(-?\d+),\s*'
    r'(\w+),\s*(\w+)\s*\}')
BLOB_RE = re.compile(
    r'\{\s*"([A-Za-z0-9_.,+-]+)",\s*"(0x[0-9A-Fa-f.]+)",\s*(-?\d+),\s*FsBlobImpl::(\w+)\s*\}')
# FsFnGroup: label, pat_begin, pat_end, blob_begin, blob_end
GROUP_RE = re.compile(r'\{\s*"(\w+)\s*",\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\s*\}')
# 谓词清单的唯一来源：X 宏 FS_PRED_LIST(X) 里 `X(名字)` 的出现次序 = 位号。
# fs_preds[] 与 fs_pred_mask() 都由这个宏展开 ⇒ 「位号 ↔ 名字」不可能脱节，
# 守卫只需取出名字当白名单，核对每个条目的 cond 在其中。
PRED_LIST_RE = re.compile(r'X\(\s*(rules_is_\w+)\s*\)')

BLOB_IMPLS = {"Utf16ToUtf8", "Utf8ToUtf16", "IsOemMbChar", "StrUnicode2Oem",
              "StrDescToUpper", "WideCharCompare", "FatGetNextChar"}


def array_body(src, decl):
    """`decl` 之后第一个 '{' 到配对 '}' 之间的正文。

    必须按声明名取表体：非 fs 的 Patterns 表与 fs 表形状相近，全局 finditer 会串表。"""
    i = src.index("{", src.index(decl))
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i + 1:j]
    raise ValueError("unbalanced braces after %s" % decl)


def _bits(w, hi, lo):
    return (w >> lo) & ((1 << (hi - lo + 1)) - 1)


# patch 函数名 -> (必须配套的 cond 名, cond 的位域判定)。
# 与 src/fs_codepage.cpp 的 rules_is_* / rules_* 一一对应，改规则时必须同步改这里。
RULE_PATCHES = {
    "rules_nop": ("rules_is_bcond",
                  lambda w: (w & 0xFF000010) == 0x54000000),
    "rules_add_imm_to_add0": ("rules_is_add_imm",
                              lambda w: (w & 0x7F000000) == 0x11000000),
    "rules_add_w25_2_to_add_w27": ("rules_is_add_w25_2",
                                   lambda w: (w & 0x7F000000) == 0x11000000
                                   and _bits(w, 9, 5) == 25 and _bits(w, 21, 10) == 2),
    "rules_ldrb_imm_to_ldrh": ("rules_is_ldrb_imm",
                               lambda w: (w & 0xFFC00000) == 0x39400000),
    "rules_ldrb_imm_to_ldurh": ("rules_is_ldrb_imm",
                                lambda w: (w & 0xFFC00000) == 0x39400000),
    "rules_ldrb_reg_to_ldrh": ("rules_is_ldrb_reg",
                               lambda w: (w & 0xFFE00C00) == 0x38600800),
    "rules_strb_sp_to_sturh": ("rules_is_strb_imm_sp",
                               lambda w: (w & 0xFFC00000) == 0x39000000 and _bits(w, 9, 5) == 31),
    "rules_orr_lsl8_to_16": ("rules_is_orr_lsl8",
                             lambda w: _bits(w, 31, 31) == 0 and _bits(w, 30, 29) == 0b01
                             and _bits(w, 28, 24) == 0b01010 and _bits(w, 23, 22) == 0
                             and _bits(w, 21, 21) == 0 and _bits(w, 15, 10) == 8),
    "rules_bfi_8_8_to_16_8": ("rules_is_bfi_8_8",
                              lambda w: _bits(w, 31, 31) == 0 and _bits(w, 30, 29) == 0b01
                              and _bits(w, 28, 23) == 0b100110
                              and _bits(w, 21, 16) == 24 and _bits(w, 15, 10) == 7),
    "rules_csel_cinc_to_add": ("rules_is_csel_cinc",
                               lambda w: (w & 0x7FE00000) == 0x1A800000
                               and _bits(w, 11, 10) in (0b00, 0b01)),
    "rules_and_ffff_to_mov": ("rules_is_and_ffff",
                              lambda w: _bits(w, 31, 31) == 0 and _bits(w, 30, 29) == 0b00
                              and _bits(w, 28, 23) == 0b100100 and _bits(w, 22, 22) == 0
                              and _bits(w, 21, 16) == 0 and _bits(w, 15, 10) == 15),
    "rules_cmp_uxth_to_cmp": ("rules_is_cmp_uxth",
                              lambda w: (w & 0xFF20001F) == 0x6B20001F and _bits(w, 15, 13) == 0b001),
    "rules_mov_reg_to_movz2": ("rules_is_mov_w0",
                               lambda w: (w & 0xFFFFFFE0) == 0x2A0003E0),
    "rules_movz_2e_to_movz2": ("rules_is_movz_2e",
                               lambda w: (w & 0xFF800000) == 0x52800000 and _bits(w, 20, 5) == 0x2E),
}


def strip_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return src


def parse_fs_tables(fs_cpp):
    """从 fs 补丁源码抽出四张表：谓词表、函数组表、指令改写表、整函数体替换表。

    返回 (preds, pats, blobs, groups)。preds 是 dict：n = 谓词个数 = 表中
    cond 的合法取值集合（名字清单）。"""
    with open(fs_cpp, "r", encoding="utf-8") as f:
        src = strip_comments(f.read())

    # 谓词清单：X 宏体里 X(名字) 的出现次序即位号。
    pred_names = [m.group(1) for m in PRED_LIST_RE.finditer(src)]
    preds = dict(n=len(pred_names), names=pred_names)

    groups = [dict(label=m.group(1), pb=int(m.group(2)), pe=int(m.group(3)),
                   bb=int(m.group(4)), be=int(m.group(5)))
              for m in GROUP_RE.finditer(array_body(src, "fs_fn_groups"))]
    pats = [dict(name=m.group(1), pattern=m.group(2), inst_offset=int(m.group(3)),
                 cond=m.group(4), patch=m.group(5))
            for m in PAT_RE.finditer(array_body(src, "fs_inst_patches"))]
    blobs = [dict(name=m.group(1), pattern=m.group(2), inst_offset=int(m.group(3)),
                  impl=m.group(4))
             for m in BLOB_RE.finditer(array_body(src, "fs_blob_patches"))]
    return preds, pats, blobs, groups


def parse_pattern(s):
    """'0xAB.CD' -> [0xAB, None, 0xCD]；非法返回 None。

    逐字符解析，与 patch_types.h 的 `str2hex` 完全同构：**一个 `.` = 一个通配槽**。
    相邻两个 '.' 就是两个独立的通配字节（本身完全合法）。槽与固件字节错位时
    模板永远匹配不上 —— 下面的「唯一命中」检查是最终兜底。"""
    body = s[2:]
    out = []
    i = 0
    while i < len(body):
        if body[i] == ".":
            out.append(None)
            i += 1
        else:
            pair = body[i:i + 2]
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", pair):
                return None
            out.append(int(pair, 16))
            i += 2
    return out


def find_all(pat, hay):
    """pattern（None = REGEX_SKIP 通配）在 hay 里的全部命中下标。
    用最长连续实字节串做锚，避免纯 Python 逐字节扫描。"""
    n = len(pat)
    bs, bl, start = -1, 0, None
    for k in range(n + 1):
        if k < n and pat[k] is not None:
            if start is None:
                start = k
        elif start is not None:
            if k - start > bl:
                bl, bs = k - start, start
            start = None
    hits = []
    if bl == 0:
        return hits
    anchor = bytes(pat[bs:bs + bl])
    i = hay.find(anchor)
    while i != -1:
        st = i - bs
        if st >= 0 and st + n <= len(hay) and \
           all(pat[k] is None or hay[st + k] == pat[k] for k in range(n)):
            hits.append(st)
        i = hay.find(anchor, i + 1)
    return hits


PAD_WORDS = {0x00000000, 0xD65F03C0}          # udf #0 / ret


def entry_ok(text, p):
    """函数体替换点的入口合理性：目标不是填充字，且前方 4/8 字节是函数收尾
    （udf #0 / ret / 无条件 b）—— 写偏一个函数会把整段替换代码插错地方。"""
    if p < 0 or p + 4 > len(text):
        return False
    if struct.unpack_from("<I", text, p)[0] in PAD_WORDS:
        return False
    for back in (4, 8):
        q = p - back
        if q < 0:
            continue
        pw = struct.unpack_from("<I", text, q)[0]
        if pw in PAD_WORDS or (pw >> 26) == 0b000101:
            return True
    return False


def kip1_text(data):
    """KIP1 的 .text 字节（头部 0x20/0x24 给出相对 body 的偏移与大小）。"""
    off, size = struct.unpack_from("<II", data, 0x20)
    return data[0x100 + off:0x100 + off + size]


# 条目名规则：`<功能名>_<版本范围>`（范围沿用原 sys-patch 约定：`a.b.c-d.e.f` 闭区间 /
# `a.b.c+` 开区间；非连续覆盖用 `,` 分段）。功能前缀 = 族（补丁点）标识，
# 与 fs_codepage.cpp 的 fs_family_of() 同口径。
_VER_ITEM = r"\d+\.\d+\.\d+(?:-\d+\.\d+\.\d+)?\+?"
NAME_RE = re.compile(r"^(?P<point>fs_cp_[a-z0-9_]+?)_(?P<ver>" + _VER_ITEM +
                     r"(?:," + _VER_ITEM + r")*)$")


def point_of(name):
    """'fs_cp_makeshortname_14.1.2,21.0.0+' -> 'fs_cp_makeshortname'；不合规返回 None。

    族 = 名字里版本范围之前的功能前缀（与 fs_family_of 同口径）。名字不合规会让该条目
    退化成「不参与兄弟退役」（只是变慢，仍正确），所以要报错而不是静默。"""
    m = NAME_RE.match(name)
    return m.group("point") if m else None


def _adrp_page(w, pc):
    """复刻 fs_codepage.cpp fs_adrp_page：由 adrp 指令字 + 指令地址解出目标页。"""
    imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def ctx_harvest_problem(text, site):
    """复刻 fs_codepage.cpp fs_harvest_ctx_pair 的判据，看参考固件上能不能收割到 ctx 取指对。

    返回 None = 能收割；否则返回失败原因。这条检查很关键：收割不到时补丁器会**整点
    跳过不写**（安全失败），但那意味着该固件上 H1 溢出修复失效 —— 换参考固件后必须
    在这里看到通过，而不是等上机才发现。"""
    def rd32(o):
        return struct.unpack_from("<I", text, o)[0]

    adrps = [(k, rd32(site + k)) for k in range(0, FS_CTX_SCAN, 4)
             if (rd32(site + k) & 0x9F000000) == 0x90000000]
    if len(adrps) != 1:
        return "扫描窗内 adrp 数 = %d（需恰好 1 条）" % len(adrps)
    k, a = adrps[0]
    rd = a & 0x1F
    page = _adrp_page(a, IMAGE_BASE + site + k)
    lds = [(j, rd32(site + j)) for j in range(k + 4, FS_CTX_SCAN, 4)
           if (rd32(site + j) & 0xFFC00000) == 0xF9400000
           and (rd32(site + j) & 0x1F) == rd and ((rd32(site + j) >> 5) & 0x1F) == rd]
    if len(lds) != 1:
        return "配对 ldr 数 = %d（需恰好 1 条，且 Rn = Rt = adrp 的 Rd = x%d）" % (len(lds), rd)
    slot = page + ((lds[0][1] >> 10) & 0xFFF) * 8
    # 注意口径：入参 site 是「相对 IMAGE_BASE 的偏移」，而 page/slot 是**绝对 VA**
    fn_va = IMAGE_BASE + site
    if slot <= fn_va or slot - fn_va > FS_CTX_MAX_DELTA:
        return ("解析出的槽 0x%X 不合理（应落在函数体之后、且距代码 ≤0x%X）"
                % (slot, FS_CTX_MAX_DELTA))
    return None


def sentinel_problem(blob, sent):
    """哨兵占位必须**各自恰好出现 1 次**，且成对相邻、按声明顺序排列。

    不要求出现在函数体开头：编译器会把栈帧前导（stp/mov x29,sp…）排在 inline asm
    前面 —— 实测 patch_widechar_compare 的 ctx 对在 +0x24 一带。收割器是按**内容**
    在整段函数体里找配对（fs_fill_addr_pair 线性搜索），所以位置无关；但重复或错序
    会让它覆写到错的地方，必须拦。

    返回 None = 合格；否则返回原因。"""
    n = len(blob) // 4
    if n < len(sent):
        return "函数体太短（%d 字节）" % len(blob)
    words = struct.unpack_from("<%dI" % n, blob, 0)
    pos = []
    for w in sent:
        idx = [i for i in range(n) if words[i] == w]
        if len(idx) != 1:
            return "哨兵 0x%08X 出现 %d 次（需恰好 1 次）" % (w, len(idx))
        pos.append(idx[0])
    if pos[1] != pos[0] + 1:
        return "ctx 哨兵对不相邻（@+0x%X / @+0x%X）" % (pos[0] * 4, pos[1] * 4)
    if len(sent) == 4:
        if pos[3] != pos[2] + 1:
            return "callee 哨兵对不相邻（@+0x%X / @+0x%X）" % (pos[2] * 4, pos[3] * 4)
        if pos[2] <= pos[1]:
            return "callee 哨兵对必须排在 ctx 哨兵对之后（@+0x%X <= @+0x%X）" % (pos[2] * 4, pos[1] * 4)
    return None


def callee_harvest_problem(text, site, span=FS_CALL_SCAN):
    """复刻 fs_codepage.cpp fs_harvest_callee 的判据：原件前 span 字节里「目标跳出函数体」的 bl
    的**去重目标**必须恰好 1 个（M6 实测有 3 条 bl 指向同一个 callee）。

    返回 None = 能收割；否则返回失败原因。收不到 ⇒ 该点整点不写（安全失败），
    但那意味着该固件上 M6 的整函数替换失效 —— 换参考固件后必须在这里看到通过。"""
    def rd32(o):
        return struct.unpack_from("<I", text, o)[0]

    end = min(len(text), site + span)
    tgt = None
    cnt = 0
    for o in range(site, end, 4):
        w = rd32(o)
        if (w & 0xFC000000) != 0x94000000:
            continue
        imm = w & 0x3FFFFFF
        if imm & (1 << 25):
            imm -= 1 << 26
        t = o + (imm << 2)
        if site <= t < end:                 # 跳回函数体内 = 自递归，不算外部调用
            continue
        cnt += 1
        if tgt is None:
            tgt = t
        elif t != tgt:
            return "跳出函数体的 bl 有 %d 个**不同**目标（需恰好 1 个，且可分多次调用）" % 2
    if tgt is None:
        return "扫描窗 0x%X 内没有「跳出函数体」的 bl（无从收割 callee）" % span
    return None


def check_fs_tables(fs_cpp, fs_data, errors, warnings, partial_ok):
    """谓词表 + 函数组两级表 + 唯一命中 + 落点指令。返回 (打印行, pattern 数, blob 数)。

    检查项（任一失败都可能让补丁写错地方）：
      1. 谓词清单：FS_PRED_LIST 里 X(名字) 的次序即位号，名字不重复、个数 ≤ 32。
         （fs_preds[] / fs_pred_mask() 都由同一宏展开，位号与名字不可能脱节。）
      2. 条目结构：pattern 语法/长度、inst_offset 越界、inst_offset % 4（M3 按字索引）、
         cond 在白名单里、cond 与 patch 配套。
         （条目**没有** stage 分级：补丁要么整份生效，要么 [options] fs_codepage=0 整份跳过。）
      3. 函数组区间连续覆盖两条表，且组不空。
      4. 每条 pattern 在 fs .text 恰好命中 1 次、命中位置字对齐、落点指令满足 cond。
    """
    try:
        preds, pats, blobs, groups = parse_fs_tables(fs_cpp)
    except OSError as e:
        sys.exit("error: cannot read fs patch source: %s" % e)

    row = "  %-30s %-8s %-10s %-5s %s"
    lines = [row % ("NAME", "KIND", "SITE", "HITS", "STATUS")]

    if not pats or not blobs or not groups:
        errors.append("fs 补丁表没解析出来（pats=%d blobs=%d groups=%d）—— "
                      "表被删了/格式被改了？" % (len(pats), len(blobs), len(groups)))
        return lines, len(pats), len(blobs)

    # ---- 1. 谓词清单（X 宏 FS_PRED_LIST 是唯一定义处，名字出现次序 = 位号）
    if not preds["names"]:
        errors.append("谓词清单为空 —— FS_PRED_LIST 没解析出来（宏被改名/删了？）")
    if preds["n"] > 32:
        errors.append("谓词数 %d > 32 —— 位图塞不进一个 u32" % preds["n"])
    if len(set(preds["names"])) != preds["n"]:
        errors.append("谓词清单有重名：%s" % " ".join(preds["names"]))

    # ---- 2. 条目结构
    seen = set()
    for e in pats + blobs:
        if e["name"] in seen:
            errors.append("fs 补丁表里有重复的 patch_name: %s" % e["name"])
        seen.add(e["name"])
        p = parse_pattern(e["pattern"])
        if p is None:
            errors.append("%s: pattern 语法非法 (%s) —— 一个十六进制字符对 = 一个字节，"
                          "一个 `.` = 一个通配槽" % (e["name"], e["pattern"]))
            continue
        if len(p) > PATTERN_MAX:
            errors.append("%s: pattern %d 字节 > PatternData 容量 %d"
                          % (e["name"], len(p), PATTERN_MAX))
        if e["inst_offset"] < 0 or e["inst_offset"] + 4 > len(p):
            errors.append("%s: inst_offset %d 越界（pattern %d 字节）"
                          % (e["name"], e["inst_offset"], len(p)))
        if e["inst_offset"] % 4 != 0:
            errors.append("%s: inst_offset %d 不是 4 的倍数 —— M3 的谓词位图按 4 字节字"
                          "索引，下标会算错" % (e["name"], e["inst_offset"]))

    for e in pats:
        if e["patch"] not in RULE_PATCHES:
            errors.append("%s: 未知的 patch 函数 %s" % (e["name"], e["patch"]))
        else:
            want_cond = RULE_PATCHES[e["patch"]][0]
            if e["cond"] != want_cond:
                errors.append("%s: cond %s 与 patch %s 不配套（应为 %s）"
                              % (e["name"], e["cond"], e["patch"], want_cond))
        # cond 必须在谓词清单里：不在 ⇒ 位图永不置位 ⇒ 该条目运行期永远命中不了
        if e["cond"] not in preds["names"]:
            errors.append("%s: cond %s 不在谓词清单 FS_PRED_LIST 里 —— "
                          "fs_pred_index 会返回越界值，该条目永远命中不了"
                          % (e["name"], e["cond"]))
    for e in blobs:
        if e["impl"] not in BLOB_IMPLS:
            errors.append("%s: 未知的替换实现 FsBlobImpl::%s" % (e["name"], e["impl"]))

    # ---- 2b. 族（补丁点）与 blob 车道筛子 ------------------------------------
    # fs_codepage.cpp 有两处**从数据推导出来的结构**，错了不会编译失败、只会静默失效，
    # 所以必须在这里钉住：
    #   · 族号 = 名字里**版本范围之前的功能前缀**（fs_family_of）。同族是跨版本互斥变体，
    #     任一成员定位成功即让同族其余成员提前退役 ⇒ 名字不合规会退化成"不跳兄弟"
    #     （只是变慢，仍正确），但意味着优化失效，要报出来。
    #   · blob 车道筛子：模板偏移 0（否则偏移 4）必须有一个**确定字节**当筛子。若两处
    #     都是通配槽，该条目退化成"每个位置都试"（仍正确，只是慢）。
    for e in pats + blobs:
        if point_of(e["name"]) is None:
            errors.append("%s: 名字不是 `<功能名>_<版本范围>` 形式（如 "
                          "fs_cp_makeshortname_15.0.1-20.5.0）—— fs_family_of() 取不到族前缀，"
                          "该条目不参与兄弟退役（优化静默失效）" % e["name"])
    for e in blobs:
        p = parse_pattern(e["pattern"])
        if p is None:
            continue
        if len(p) < 5 or (p[0] is None and p[4] is None):
            errors.append("%s: 模板偏移 0 与 4 都是通配槽 —— blob 车道快筛对它无效"
                          "（退化成逐位置全试）" % e["name"])

    # ---- 3. 函数组区间：连续覆盖两条表，组不能空
    pi = bi = 0
    for g in groups:
        if g["pb"] != pi or g["pe"] < g["pb"]:
            errors.append("函数组 %s: pattern 区间 [%d,%d) 不连续（应始于 %d）"
                          % (g["label"], g["pb"], g["pe"], pi))
        if g["bb"] != bi or g["be"] < g["bb"]:
            errors.append("函数组 %s: blob 区间 [%d,%d) 不连续（应始于 %d）"
                          % (g["label"], g["bb"], g["be"], bi))
        if g["pe"] == g["pb"] and g["be"] == g["bb"]:
            errors.append("函数组 %s 是空的（既无 pattern 也无 blob）" % g["label"])
        pi, bi = g["pe"], g["be"]
    if pi != len(pats):
        errors.append("fs_fn_groups 的 pattern 区间只覆盖到 %d，表里有 %d 条"
                      % (pi, len(pats)))
    if bi != len(blobs):
        errors.append("fs_fn_groups 的 blob 区间只覆盖到 %d，表里有 %d 条"
                      % (bi, len(blobs)))

    # ---- 唯一命中 + 落点指令判定（需要 fs 二进制）
    if fs_data is None:
        lines.append("  (fs 二进制不可用：跳过 pattern 唯一性与落点检查)")
        return lines, len(pats), len(blobs)

    text = kip1_text(fs_data)
    hits_by = []
    for e in pats + blobs:
        kind = "pattern" if "patch" in e else "blob"
        p = parse_pattern(e["pattern"])
        hits_by.append((e, kind, None if p is None else find_all(p, text)))

    # 一个补丁点可能有多条"变体族"pattern（例：#17 的 bfi 形式只存在于 16.1.0，
    # orr lsl#8 形式只存在于 20.x+；#10 的 8 组/14 组两族）。任何一份固件只会命中
    # 其中一族，因此"命中 0 次"是否算错误，要按整个补丁点（名字里的功能前缀）汇总判断：
    #   点内 ≥1 族命中 -> 该点已覆盖，未命中的族只是"不适用于本固件"（warning）
    #   点内 0 族命中   -> 这个点在目标固件上根本没定位到（error）
    point_hits = collections.defaultdict(int)
    for e, _kind, hits in hits_by:
        if hits:
            point_hits[point_of(e["name"])] += len(hits)

    # 族互斥 =「兄弟提前退役」的安全前提：同族条目在**同一份固件**上至多 1 条命中。
    # 若这条不成立，退役会把本该应用的补丁跳掉 ⇒ 必须在参考固件上逐族验一遍。
    fam_hits = collections.defaultdict(list)
    for e, _kind, hits in hits_by:
        if hits:
            fam_hits[point_of(e["name"])].append(e["name"])
    for pt, names in sorted(fam_hits.items(), key=lambda kv: kv[0] or ""):
        if len(names) > 1:
            errors.append("补丁点 %s 在参考固件上同时命中 %d 条（%s）—— 族内互斥不成立，"
                          "「兄弟提前退役」会漏掉本该应用的补丁；该点的变体族必须互斥"
                          % (pt, len(names), ", ".join(names)))

    for e, kind, hits in hits_by:
        if hits is None:
            lines.append(row % (e["name"], kind, "-", "-", "BAD PATTERN"))
            continue
        if len(hits) == 1:
            site = hits[0] + e["inst_offset"]
            status = "OK"
            if kind == "blob":
                if not entry_ok(text, site):
                    status = "ENTRY SUSPECT"
                    errors.append("%s: 入口 0x%X 不像函数入口（填充字 / 前方无收尾）"
                                  % (e["name"], site))
                if e.get("impl") in HARVEST_IMPLS:
                    why = ctx_harvest_problem(text, site)
                    if not why and e.get("impl") == "WideCharCompare":
                        why = callee_harvest_problem(text, site)
                    if why:
                        status = "HARVEST FAIL"
                        errors.append("%s: 参考固件上%s —— 运行期会整点跳过不写"
                                      "（该点补丁失效）；换参考固件后必须重新确认"
                                      % (e["name"], why))
            else:
                # M3：位图按 4 字节字索引，(命中位置 i + inst_offset) 必须落在字边界上，
                # 否则扫描下标会算错、整条 pattern 静默失效。
                if site % 4 != 0:
                    status = "NOT WORD-ALIGNED"
                    errors.append("%s: 唯一命中位置 %d 使指令落在 0x%X（非字对齐）—— "
                                  "M3 谓词位图按字索引会漏掉该站点，先调 inst_offset"
                                  % (e["name"], hits[0], site))
                w = struct.unpack_from("<I", text, site)[0]
                cond_name, cond = RULE_PATCHES.get(e["patch"], (None, None))
                if cond is None:
                    status = "UNKNOWN RULE"
                elif not cond(w):
                    status = "COND FAIL"
                    errors.append("%s: 落点 0x%X 的指令 0x%08X 不满足 %s "
                                  "（pattern 与 inst_offset 不匹配？）"
                                  % (e["name"], site, w, cond_name))
            lines.append(row % (e["name"], kind, "0x%X" % site, "1", status))
            continue

        pt = point_of(e["name"])
        if len(hits) == 0 and partial_ok and point_hits[pt] > 0:
            warnings.append("%s: 本固件 0 命中，但补丁点 %s 已由其它变体族命中 "
                            "-> 版本族差异，跳过（非错误）" % (e["name"], pt))
            lines.append(row % (e["name"], kind, "-", "0", "skipped (other family)"))
        else:
            errors.append("%s: pattern 在 fs .text 里命中 %d 次，必须恰好 1 次 "
                          "（命中 0 = 该补丁点在目标固件上未定位到；>=2 = 可能写错地方）"
                          % (e["name"], len(hits)))
            lines.append(row % (e["name"], kind, "-", "%d" % len(hits),
                                "HIT COUNT != 1"))

    return lines, len(pats), len(blobs)


# -------------------------------------------------------------------- 主流程

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument("--main", default="src/fs_codepage.cpp",
                    help="fs 补丁源码路径（默认相对 sysmod 目录）")
    ap.add_argument("--fs", default=os.environ.get("FS_KIP1", DEFAULT_FS),
                    help="fs 目标二进制（用于 cmp 字节比对；缺失则跳过）")
    args = ap.parse_args()

    try:
        symbols, segments = elf_symbols(args.elf)
    except OSError as e:
        sys.exit("error: cannot read ELF: %s" % e)

    errors = []
    warnings = []

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
        elif delta == hole:
            # 零余量：现在过得了，但任何一次无害的源码调整（多一条 nop、寄存器分配变了、
            # 编译器换了版本）都会立刻变成 HOLE OVERFLOW。洞是 fs 函数边界定的、不可挪，
            # 所以唯一的出路是把这个替换体写小一点 —— 别等它某天突然构建失败。
            warnings.append("%s: ZERO SLACK -- size 0x%X == hole 0x%X at site 0x%X (%s); "
                            "any codegen growth breaks the build, shrink the replacement"
                            % (sym, delta, hole, entry["site"], entry["site_name"]))
            status.append("ZERO SLACK")
        rows.append((sym, "0x%X" % fsize, "0x%X" % delta, hole,
                     "OK" if not status else " / ".join(status)))
    for sym, fsize, delta, hole, status in rows:
        print(header % (sym, fsize, delta, "0x%X" % hole, status))

    # fs 补丁表检查要用到 fs 二进制；缺失时只做结构检查
    fs_data = None
    if args.fs and os.path.exists(args.fs):
        with open(args.fs, "rb") as f:
            fs_data = f.read()
        fs_note = "vs %s" % os.path.basename(args.fs)
    else:
        fs_note = "fs binary not found"

    # ---- 3. fs 补丁表（pattern 驱动）：结构 + 分组区间 + 唯一命中 + 落点指令
    print()
    print("fs patch table check (%s):" % args.main)
    table_lines, n_pat, n_blob = check_fs_tables(args.main, fs_data, errors, warnings,
                                                 partial_ok=True)
    for ln in table_lines:
        print(ln)
    print("  (%s; %d pattern + %d blob entries)" % (fs_note, n_pat, n_blob))

    # ---- 4. 拷入 fs 的函数必须位置无关（ASLR：禁绝绝对地址/外部引用）
    print()
    print("position-independence check (copied into fs, ASLR-safe):")
    print(header % ("SYMBOL", "SECTION", "SIZE", "", "STATUS"))
    for entry in FUNCTIONS:
        sym = entry["symbol"]
        syminfo = symbols.get(sym)
        blob = None
        if syminfo is not None:
            blob = read_by_addr(segments, syminfo[0], syminfo[1])
        if blob is None:
            errors.append("%s: cannot read function bytes from ELF -- cannot verify "
                          "position-independence" % sym)
            print(header % (sym, "-", "-", "", "BYTES NOT FOUND"))
            continue
        hits = scan_absolutes(blob)

        # 带哨兵占位的替换体：哨兵必须各自恰好 1 次、成对相邻、按序（补丁器按内容
        # 线性搜索占位对，按占位指令自身的真实地址重编码 adrp+add 覆写它们）
        want_sent = HARVEST_BLOBS.get(sym)
        if want_sent is not None:
            why = sentinel_problem(blob, want_sent)
            if why:
                errors.append("%s: 收割哨兵 %s 不合格 —— %s；补丁器会判 FAILED_HARVEST "
                              "整点不写（该点补丁失效）" % (sym, want_sent, why))
        for off, why in hits:
            errors.append("%s: absolute/external reference in copied code at +0x%X: %s "
                          "-- load address is randomized (ASLR); only PC-relative "
                          "references survive the copy into fs" % (sym, off, why))
        print(header % (sym, "%d bytes" % len(blob), "", "",
                        "OK" if not hits else "%d SUSPECT@%s"
                        % (len(hits), ",".join("+0x%X" % h[0] for h in hits))))

    if warnings:
        print()
        for w in warnings:
            print("warn: %s" % w)

    if errors:
        print()
        for e in errors:
            print("ERROR: %s" % e)
        sys.exit(1)
    print("all %d replacement functions and %d+%d fs patch entries verified"
          % (len(FUNCTIONS), n_pat, n_blob))


if __name__ == "__main__":
    main()
