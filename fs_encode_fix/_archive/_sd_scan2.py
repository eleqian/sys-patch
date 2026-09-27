#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""补齐取证：PPSSPP 双目录对比 + RetroArch 版本字符串 + 残留文件。一次跑完。"""
import os, sys, re, io, hashlib, datetime

ROOT = sys.argv[1] if len(sys.argv) > 1 else "F:/"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_sd_scan2_out.txt")
lines = []
def P(*a):
    s = " ".join(str(x) for x in a)
    lines.append(s); print(s)

def t(x):
    return datetime.datetime.fromtimestamp(x).strftime("%Y-%m-%d %H:%M:%S")

def ls(d):
    try:
        return sorted([(e.name, e.is_dir(), e.stat(follow_symlinks=False).st_size,
                        e.stat(follow_symlinks=False).st_mtime) for e in os.scandir(d)],
                      key=lambda x: x[0].lower())
    except Exception as e:
        P("  ERR", d, e); return []

def quickhash(p, n=65536):
    try:
        with open(p, "rb") as f:
            return hashlib.md5(f.read(n)).hexdigest()[:16]
    except Exception as e:
        return "ERR"

# ---------- 1. PPSSPP 双目录 ----------
P("=" * 78); P("[1] PPSSPP 双目录对比"); P("=" * 78)
for d in ["switch/ppsspp", "switch/PPSSPP"]:
    full = os.path.join(ROOT, d)
    P(f"\n--- /{d}  exists={os.path.exists(full)}")
    if not os.path.exists(full):
        continue
    for name, isdir, size, mt in ls(full):
        tag = "[D]" if isdir else "[F]"
        h = "" if isdir else quickhash(os.path.join(full, name))
        P(f"  {tag} {name:<28} {size:>10}  {t(mt)}  {h}")
        if isdir:
            for n2, i2, s2, m2 in ls(os.path.join(full, name)):
                h2 = "" if i2 else quickhash(os.path.join(full, name, n2))
                P(f"      {'[D]' if i2 else '[F]'} {n2:<40} {s2:>10}  {t(m2)}  {h2}")
                if i2:
                    for n3, i3, s3, m3 in ls(os.path.join(full, name, n2)):
                        P(f"          {'[D]' if i3 else '[F]'} {n3:<44} {s3:>10}")

# ---------- 2. 全盘找 ppsspp.ini / PSP 目录 ----------
P("\n" + "=" * 78); P("[2] 全盘 ppsspp.ini / PSP 相关"); P("=" * 78)
hits = []
for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "switch")):
    for f in filenames:
        if "ppsspp" in f.lower() or f.lower().endswith(".ini"):
            hits.append(os.path.join(dirpath, f))
for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "config")):
    for f in filenames:
        if "ppsspp" in f.lower():
            hits.append(os.path.join(dirpath, f))
for h in sorted(hits)[:60]:
    P("  ", os.path.relpath(h, ROOT), os.path.getsize(h), t(os.path.getmtime(h)))
if not hits:
    P("  (无 — PPSSPP 从未成功写入配置)")

# ---------- 3. RetroArch 版本字符串 ----------
P("\n" + "=" * 78); P("[3] RetroArch / core 版本字符串"); P("=" * 78)
def strings(path, pats, maxhit=6):
    try:
        data = open(path, "rb").read()
    except Exception as e:
        return ["ERR " + str(e)]
    res = []
    for pat in pats:
        for m in re.finditer(pat, data):
            try:
                s = m.group(0).decode("ascii", "ignore").strip()
            except Exception:
                continue
            if s and s not in res:
                res.append(s)
            if len(res) >= maxhit:
                break
        if len(res) >= maxhit:
            break
    return res

pats = [rb"[Vv]ersion[\x20\x3a\x3d]{1,3}[0-9][0-9A-Za-z\.\-_]{2,24}",
        rb"1\.[0-9]{1,2}\.[0-9]{1,2}",
        rb"20[0-9]{2}-[0-9]{2}-[0-9]{2}"]
for rel in ["switch/retroarch_switch.nro",
            "retroarch/cores/snes9x_libretro_libnx.nro",
            "retroarch/cores/mgba_libretro_libnx.nro",
            "retroarch/cores/melonds_libretro_libnx.nro",
            "retroarch/cores/dinothawr_libretro_libnx.nro"]:
    p = os.path.join(ROOT, rel)
    if os.path.exists(p):
        P(f"\n--- {rel}  ({os.path.getsize(p)} bytes, {t(os.path.getmtime(p))})")
        for s in strings(p, pats)[:8]:
            P("     ", s)

# ---------- 4. info / cache ----------
P("\n" + "=" * 78); P("[4] retroarch/info 内容摘要"); P("=" * 78)
info = os.path.join(ROOT, "retroarch/info")
for n, i, s, m in ls(info):
    P(f"  {n:<45} {s:>8}  {t(m)}")
    if n.endswith(".info"):
        txt = io.open(os.path.join(info, n), encoding="utf-8", errors="replace").read()
        for ln in txt.splitlines()[:8]:
            P("        ", ln.strip()[:110])
    if n == "core_info.cache":
        txt = io.open(os.path.join(info, n), encoding="utf-8", errors="replace").read()
        P("     cache 行数:", len(txt.splitlines()))
        for ln in txt.splitlines()[:20]:
            P("        ", ln.strip()[:110])

# ---------- 5. sys-patch 备份文件 ----------
P("\n" + "=" * 78); P("[5] sys-patch exefs 备份"); P("=" * 78)
d = os.path.join(ROOT, "atmosphere/contents/420000000000000B")
for n, i, s, m in ls(d):
    P(f"  {'[D]' if i else '[F]'} {n:<45} {s:>9}  {t(m)}")

# ---------- 6. switch 根下的怪文件 ----------
P("\n" + "=" * 78); P("[6] /switch 顶层非目录项 + .star"); P("=" * 78)
for n, i, s, m in ls(os.path.join(ROOT, "switch")):
    if not i:
        P(f"  {n:<45} {s:>10}  {t(m)}")

# ---------- 7. FOUND.000 ----------
P("\n" + "=" * 78); P("[7] FOUND.000"); P("=" * 78)
for n, i, s, m in ls(os.path.join(ROOT, "FOUND.000")):
    P(f"  {n:<30} {s:>10}  {t(m)}")
for n, i, s, m in ls(os.path.join(ROOT, "LOST.DIR")):
    P(f"  LOST.DIR/{n:<25} {s:>10}  {t(m)}")

with io.open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
P("\n>> 写入", OUT)
