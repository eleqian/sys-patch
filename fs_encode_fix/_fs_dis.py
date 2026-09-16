#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_fs_dis.py —— fs 固件 RE 辅助工具（本项目专用，取代此前一堆一次性 _dis_*.py）。

用法（默认 fs 路径可用 --fs 或 $FS_KIP1 覆盖）：
  python _fs_dis.py sites                  # 列出 main.cpp 全部补丁点，解码 cmp → patch 指令
  python _fs_dis.py range 0xf4880 0x60     # 反汇编 fs 某个区域
  python _fs_dis.py word 0x710024eb50      # 读 32/64 位字（给 VA 或偏移均可）
  python _fs_dis.py adrp 0xf5860           # 逐位解析 adrp 目标页（不依赖 capstone）

约定：fs 文件偏移 = 0x100 + (VA − 0x7100000000)；VM 基址 0x7100000000 只是分析基址，
运行时地址随机化 —— 分析结论一律用"相对偏移"，不要写死绝对地址。

依赖：反汇编需要 capstone（本机在 managed venv：
  C:/Users/eleqi/.workbuddy/binaries/python/envs/default/Scripts/python.exe）。
"""
import argparse
import os
import re
import struct
import sys

FS_DEFAULT = os.environ.get(
    "FS_KIP1", "D:/Design/NS/ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1")
IMAGE_BASE = 0x7100000000
MAIN_CPP = os.path.join(os.path.dirname(__file__), "..", "sysmod", "src", "main.cpp")


def load(path):
    with open(path, "rb") as f:
        return f.read()


def foff(off_or_va):
    """接受相对偏移或完整 VA，返回文件偏移。"""
    return 0x100 + ((off_or_va - IMAGE_BASE) if off_or_va >= IMAGE_BASE else off_or_va)


def capstone_md():
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        sys.exit("需要 capstone（用 managed venv 的 python 运行本脚本）")
    return Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


# ------------------------------------------------------------------ adrp 解析

def adrp_target(word, insn_off):
    """按 ARM 规范逐位解析 ADRP：目标页 = (PC & ~0xFFF) + SignExtend(imm21)<<12。"""
    if not (word >> 31) & 1 or ((word >> 24) & 0x1F) != 0x10:
        return None
    immlo = (word >> 29) & 3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return ((IMAGE_BASE + insn_off) & ~0xFFF) + (imm << 12)


# --------------------------------------------------------- 从 main.cpp 提补丁点

ARRAY_RE = re.compile(r"const\s+u8\s+(\w+)\s*\[\s*\d*\s*\]\s*=\s*\{(.*?)\}\s*;", re.S)
CALL_RE = re.compile(
    r"fs_patch_function\(\s*handle\s*,\s*mem_info\.addr\s*\+\s*(0x[0-9a-fA-F]+)\s*,"
    r"\s*(\w+)\s*,\s*sizeof\s*\(\s*\2\s*\)\s*,\s*([^,]+?)\s*,", re.S)


def strip_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def collect_arrays(src):
    out = {}
    for m in ARRAY_RE.finditer(src):
        vals = []
        ok = True
        for tok in m.group(2).split(","):
            tok = tok.strip()
            if not tok:
                continue
            if not re.fullmatch(r"0[xX][0-9a-fA-F]+", tok):
                ok = False
                break
            vals.append(int(tok, 16) & 0xFF)
        if ok:
            out[m.group(1)] = bytes(vals)
    return out


def cmd_sites(args):
    src = strip_comments(open(args.main, encoding="utf-8").read())
    arrays = collect_arrays(src)
    md = capstone_md()
    print("补丁点清单（来自 %s）" % os.path.relpath(args.main))
    for m in CALL_RE.finditer(src):
        site = int(m.group(1), 16)
        cmp_b = arrays.get(m.group(2))
        patch_name = re.search(r"(\w+)\s*$", m.group(3))
        patch_b = arrays.get(patch_name.group(1)) if patch_name else None
        print("\n@0x%X  %s" % (site, m.group(2)))
        if cmp_b is None:
            print("    cmp  : <函数替换或数组未找到>")
            continue
        for i in range(0, len(cmp_b), 4):
            cw = struct.unpack_from("<I", cmp_b, i)[0]
            out = []
            for ins in md.disasm(struct.pack("<I", cw), site + i):
                out.append("%s %s" % (ins.mnemonic, ins.op_str))
            line = "    +0x%X  cmp  %s" % (i, " | ".join(out))
            if patch_b and i + 4 <= len(patch_b):
                pw = struct.unpack_from("<I", patch_b, i)[0]
                if pw != cw:
                    pout = []
                    for ins in md.disasm(struct.pack("<I", pw), site + i):
                        pout.append("%s %s" % (ins.mnemonic, ins.op_str))
                    line += "\n           patch 0x%08X -> %s" % (pw, " | ".join(pout))
            print(line)


def cmd_range(args):
    data = load(args.fs)
    md = capstone_md()
    off, length = args.start, args.len
    for ins in md.disasm(data[foff(off):foff(off) + length], off):
        print("%08x  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))


def cmd_word(args):
    data = load(args.fs)
    o = foff(args.addr)
    print("0x%X: u32=0x%08X  u64=0x%016X" % (
        args.addr, struct.unpack_from("<I", data, o)[0],
        struct.unpack_from("<Q", data, o)[0]))


def cmd_adrp(args):
    data = load(args.fs)
    word = struct.unpack_from("<I", data, foff(args.off))[0]
    tgt = adrp_target(word, args.off)
    if tgt is None:
        sys.exit("0x%X 不是 ADRP 指令（word=0x%08X）" % (args.off, word))
    print("adrp @0x%X word=0x%08X -> 目标页 0x%X（相对偏移 0x%X）"
          % (args.off, word, tgt, tgt - IMAGE_BASE))
    print("  若本次指令位于 fs 页内，相对于 fs 基址的偏移是 0x%X"
          % (tgt - IMAGE_BASE))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fs", default=FS_DEFAULT, help="fs KIP1 路径（默认 $FS_KIP1）")
    ap.add_argument("--main", default=MAIN_CPP, help="main.cpp 路径")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("sites", help="列出全部补丁点并解码")

    p = sub.add_parser("range", help="反汇编区域")
    p.add_argument("start", type=lambda s: int(s, 0))
    p.add_argument("len", type=lambda s: int(s, 0))
    p.set_defaults(func=cmd_range)

    p = sub.add_parser("word", help="读 32/64 位字")
    p.add_argument("addr", type=lambda s: int(s, 0))
    p.set_defaults(func=cmd_word)

    p = sub.add_parser("adrp", help="解析 adrp 目标页")
    p.add_argument("off", type=lambda s: int(s, 0))
    p.set_defaults(func=cmd_adrp)

    args = ap.parse_args()
    if args.cmd == "sites":
        cmd_sites(args)
    else:
        args.func(args)


if __name__ == "__main__":
    main()
