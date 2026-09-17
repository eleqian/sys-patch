#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_name_collision_check.py —— 检测"fs 视角同名"的名字冲突（零风险规避手段）。

背景：fs 的名字匹配只拼 **2 字节**比较值
  - ASCII：1 字节（'a'-'z' 折叠为大写）
  - 多字节：`首字节 << 8 | 第一个续字节`
因此 3 字节 UTF-8（全部汉字）只比较高 10 位 ⇒ **U>>6 相同即视为同一个字符**
（常用汉字 20902 个分成 327 组、每组 64 字互相同名；如 `中` 与 `一`、
`历` 与 `厉`）。4 字节字符（emoji）按 U>>12 分组，更宽松。

本脚本把该规则原样复刻，用于**上机前**检查某个目录：
  同一目录下若有两个名字的"比较值序列"完全相同 → fs 会认为它们是同一个文件
  （打开/删除/重命名/覆盖可能命中错误的文件，属数据丢失风险）。

用法：
  python _name_collision_check.py DIR                 # 递归扫描，报告同目录冲突
  python _name_collision_check.py --explain 中文.txt   # 显示某个名字的比较值/同值字符
  python _name_collision_check.py DIR --max-files 5000

注：只按 fs 的**名字匹配**规则判断，不读写任何文件内容，纯只读。
"""
import argparse
import os
import sys
import unicodedata

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def cmp_val(ch, mode="wide"):
    """复刻 fs 匹配函数对单个字符的比较值。

    mode="wide"（当前默认，R1c 打了 24 位比较值后）：
        比较值 = (b0 << 16) | (b2 << 8) | b1 —— 1~3 字节字符完整参与比较（单射，无碰撞）；
        4 字节字符（emoji 等）仍只取前 3 字节，会残留碰撞。
    mode="r1b"（只打了 R1b，未打 R1c）：
        比较值 = (b0 << 8) | ((b2 << 8) | b1) —— 第 3 字节以按位或混入，仍丢位。
    mode="legacy"（R1b 之前）：
        比较值 = (b0 << 8) | b1 —— 只看前两字节，常用汉字 64 字一组互撞。
    """
    b = ch.encode("utf-8")
    if len(b) == 1:
        c = b[0]
        return c - 0x20 if 0x61 <= c <= 0x7A else c   # 'a'-'z' → 大写
    if len(b) == 2:
        return (b[0] << 8) | b[1]                      # 2 字节：完整
    if mode == "legacy":
        return (b[0] << 8) | b[1]
    if mode == "r1b":
        return (b[0] << 8) | ((b[2] << 8) | b[1])
    return (b[0] << 16) | (b[2] << 8) | b[1]           # wide：完整 3 字节


def name_sig(name, mode="wide"):
    return tuple(cmp_val(c, mode) for c in name)


def scan(root, max_files=20000, mode="wide"):
    """按目录分组，返回 [(目录, [(签名组...)]), ...]"""
    files = 0
    problems = []
    for dirpath, dirnames, filenames in os.walk(root):
        buckets = {}
        for fn in filenames:
            files += 1
            if files > max_files:
                problems.append((dirpath, None, "文件数超过上限，已停止扫描"))
                return problems
            buckets.setdefault(name_sig(fn, mode), []).append(fn)
        for sig, names in buckets.items():
            if len(names) > 1:
                problems.append((dirpath, sorted(names), None))
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
    return problems


def explain(name, mode="wide"):
    print("名字: %s (比较值口径: %s)" % (name, mode))
    vals = []
    for ch in name:
        vals.append("%s(U+%04X)=0x%06X" % (ch, ord(ch), cmp_val(ch, mode)))
    print("比较值序列: %s" % " ".join(vals))
    print("\n各字符的「同值」字符（同 64 码位块，fs 无法区分）：")
    for ch in name:
        if len(ch.encode("utf-8")) < 3:
            print("  %s  2 字节以内，不会碰撞" % ch)
            continue
        base = ord(ch) >> 6 << 6
        same = "".join(chr(base + i) for i in range(64)
                       if unicodedata.category(chr(base + i)).startswith("L"))
        print("  %s → %s" % (ch, same[:32] + (" ..." if len(same) > 32 else "")))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", help="要扫描的目录")
    ap.add_argument("--explain", help="显示某个名字的比较值与同值字符")
    ap.add_argument("--mode", choices=("wide", "r1b", "legacy"), default="wide",
                    help="比较值口径：wide(默认，R1c 后) / r1b(仅 R1b) / legacy(R1b 前)")
    ap.add_argument("--max-files", type=int, default=20000)
    args = ap.parse_args()

    if args.explain:
        explain(args.explain, args.mode)
        return
    if not args.path:
        ap.error("需要指定目录，或使用 --explain")

    problems = scan(args.path, args.max_files, args.mode)
    if not problems:
        print("未发现 fs 视角同名的冲突（%s）" % args.path)
        return
    print("发现 %d 处潜在同名冲突（fs 无法区分，操作可能命中错误文件）：" % len(problems))
    for dirpath, names, note in problems:
        if note:
            print("  %s: %s" % (dirpath, note))
            continue
        print("  %s" % dirpath)
        for n in names:
            print("      - %s" % n)
    print("\n规避：把其中一个改名，使其与同目录其它名字的「前两字节」不同"
          "（最简单：加 ASCII 后缀，或换用不同码位块的字）。")


if __name__ == "__main__":
    main()
