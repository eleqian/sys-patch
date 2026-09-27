#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统计 RetroArch 主程序与全部核心的版本字符串，判断配套性。"""
import os, re, io, datetime, sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "F:/"
PAT = re.compile(rb"Version:\s*([0-9][0-9A-Za-z\.\-_]{2,20})")
out = []
def P(*a):
    s = " ".join(str(x) for x in a)
    out.append(s); print(s)

def ver(path):
    try:
        data = open(path, "rb").read()
    except Exception as e:
        return "ERR:" + str(e)[:40]
    m = PAT.search(data)
    return m.group(1).decode("ascii", "ignore").strip() if m else "?"

def t(x):
    return datetime.datetime.fromtimestamp(x).strftime("%Y-%m-%d %H:%M")

main = os.path.join(ROOT, "switch/retroarch_switch.nro")
mv = ver(main)
P("=" * 70)
P("主程序 switch/retroarch_switch.nro")
P("   版本 =", mv, " 时间 =", t(os.path.getmtime(main)))
P("=" * 70)

cd = os.path.join(ROOT, "retroarch/cores")
groups = {}
for e in sorted(os.scandir(cd), key=lambda x: x.name.lower()):
    if not e.is_file() or not e.name.endswith(".nro"):
        continue
    v = ver(e.path)
    groups.setdefault(v, []).append((e.name, t(e.stat().st_mtime)))

P("\n核心版本分布（共 %d 个）:" % sum(len(v) for v in groups.values()))
for v in sorted(groups):
    mark = "  <== 与主程序不一致" if v != mv else "  <== 与主程序一致"
    P(f"  {v}: {len(groups[v])} 个{mark}")
P("")
for v in sorted(groups):
    P(f"--- 版本 {v} ({len(groups[v])} 个)")
    for n, dt in sorted(groups[v], key=lambda x: x[1]):
        P(f"      {n:<50} {dt}")

# info 文件核对
P("\n" + "=" * 70)
P("info 目录")
info = os.path.join(ROOT, "retroarch/info")
if os.path.isdir(info):
    infos = sorted(e.name for e in os.scandir(info) if e.name.endswith(".info"))
    P("  .info 文件 %d 个:" % len(infos))
    for n in infos:
        P("      ", n)
    cores = [e.name for e in os.scandir(cd) if e.name.endswith(".nro")]
    have = {n.replace("_libretro_libnx.nro", "") for n in cores}
    got = {n.replace(".info", "") for n in infos}
    missing = sorted(have - got)
    P("  有核心无 info 的（%d 个）:" % len(missing))
    for n in missing:
        P("      ", n)

with io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "_cores_ver_out.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(out))
