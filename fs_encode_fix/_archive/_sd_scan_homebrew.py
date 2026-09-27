#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SD 卡 homebrew 闪退取证扫描 (只读)
用法: python _sd_scan_homebrew.py F:/  [输出文件]

扫描内容:
  1. SD 根目录 / atmosphere / switch 顶层结构
  2. AMS 版本线索 (fusee.bin / package3 / sept 等)
  3. 所有 .nro / .ovl / .elf / .so 清单 (大小 + mtime)
  4. RetroArch 布局 (nro 位置、cores、info、retroarch.cfg、assets/shaders/database)
  5. PPSSPP 布局 (nro、assets)
  6. /config/sys-patch/log.ini (FW/AMS 版本 + 补丁结果)
  7. 非 ASCII / 中文文件名统计 (重点: ROM、核心、目录)
  8. 可能的冲突: atmosphere/contents 下的 sysmodule/exefs patch
"""
import os, sys, time, datetime

def safe(p):
    return os.path.abspath(p)

def lst(path):
    try:
        with os.scandir(path) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                    yield e.name, e.is_dir(follow_symlinks=False), st.st_size, st.st_mtime
                except Exception as ex:
                    yield e.name, False, -1, 0
    except Exception:
        return

def t(ts):
    if not ts:
        return "?"
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

def isnonascii(s):
    return any(ord(c) > 0x7F for c in s)

def walk_collect(root, maxdepth=3, exts=None, out=None, _d=0):
    """收集文件，限制深度"""
    if out is None:
        out = []
    if _d > maxdepth:
        return out
    for name, isdir, size, mt in lst(root):
        full = os.path.join(root, name)
        if isdir:
            walk_collect(full, maxdepth, exts, out, _d + 1)
        else:
            if exts is None or os.path.splitext(name)[1].lower() in exts:
                out.append((full, size, mt))
    return out

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "F:/"
    outf = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "_sd_scan_out.txt")
    lines = []
    def P(*a):
        s = " ".join(str(x) for x in a)
        lines.append(s)
        print(s)

    P("=" * 78)
    P("SD 扫描 roots =", safe(root), " 时间 =", time.strftime("%F %T"))
    P("=" * 78)

    # 1. 顶层
    P("\n### [1] SD 根目录")
    for name, isdir, size, mt in sorted(lst(root), key=lambda x: x[0].lower()):
        P(f"  {'[D]' if isdir else '[F]'} {name:<40} {size:>12}  {t(mt)}")

    # 2. atmosphere
    ams = os.path.join(root, "atmosphere")
    if os.path.isdir(ams):
        P("\n### [2] /atmosphere")
        for name, isdir, size, mt in sorted(lst(ams), key=lambda x: x[0].lower()):
            P(f"  {'[D]' if isdir else '[F]'} {name:<40} {size:>12}  {t(mt)}")
        for sub in ("contents", "exefs_patches", "hosts", "stratosphere"):
            d = os.path.join(ams, sub)
            if os.path.isdir(d):
                P(f"  --- /atmosphere/{sub}:")
                items = sorted(lst(d), key=lambda x: x[0].lower())
                for name, isdir, size, mt in items[:80]:
                    P(f"      {'[D]' if isdir else '[F]'} {name:<50} {size:>10}")
                if len(items) > 80:
                    P(f"      ...({len(items)} 项, 截断)")
                # exefs_patches 下一层
                if sub == "exefs_patches":
                    for name, isdir, size, mt in items:
                        if isdir:
                            dd = os.path.join(d, name)
                            inner = sorted(lst(dd), key=lambda x: x[0].lower())
                            for n2, d2, s2, m2 in inner:
                                P(f"        {name}/{n2:<40} {s2:>10}")
                # contents 下的 sysmodule 标题列表
                if sub == "contents":
                    for name, isdir, size, mt in items:
                        if isdir:
                            dd = os.path.join(d, name)
                            inner = sorted(lst(dd), key=lambda x: x[0].lower())
                            P(f"        title {name}: " + ", ".join(
                                f"{n}{'/' if dd2 else ''}" for n, dd2, s2, m2 in inner[:12]))
                            ex = os.path.join(dd, "exefs.nsp")
                            if os.path.exists(ex):
                                P(f"               exefs.nsp size={os.path.getsize(ex)}")

    # 3. switch 顶层
    sw = os.path.join(root, "switch")
    if os.path.isdir(sw):
        P("\n### [3] /switch 顶层")
        for name, isdir, size, mt in sorted(lst(sw), key=lambda x: x[0].lower()):
            P(f"  {'[D]' if isdir else '[F]'} {name:<45} {size:>12}  {t(mt)}")
    cfgtop = os.path.join(root, "config")
    if os.path.isdir(cfgtop):
        P("\n### [3b] /config 顶层")
        for name, isdir, size, mt in sorted(lst(cfgtop), key=lambda x: x[0].lower()):
            P(f"  {'[D]' if isdir else '[F]'} {name:<45} {size:>12}  {t(mt)}")
        for sub in ("retroarch", "ppsspp", "sys-patch"):
            d = os.path.join(cfgtop, sub)
            if os.path.isdir(d):
                P(f"  --- /config/{sub}:")
                for name, isdir, size, mt in sorted(lst(d), key=lambda x: x[0].lower())[:60]:
                    P(f"      {'[D]' if isdir else '[F]'} {name:<50} {size:>10}  {t(mt)}")

    # 4. 所有 nro/ovl/so/elf
    exe_ext = {".nro", ".ovl", ".elf", ".nso", ".so", ".nsp"}
    P("\n### [4] 可执行文件清单 (nro/ovl/so/elf)")
    try:
        allf = walk_collect(root, maxdepth=4, exts=exe_ext)
        P(f"  共 {len(allf)} 个")
        for full, size, mt in sorted(allf, key=lambda x: x[0].lower()):
            rel = os.path.relpath(full, root)
            mark = "  <<非ASCII" if isnonascii(rel) else ""
            P(f"  {rel:<70} {size:>10}  {t(mt)}{mark}")
    except Exception as e:
        P("  扫描失败:", e)

    # 5. RetroArch
    P("\n### [5] RetroArch 布局")
    ra_dirs = [os.path.join(root, "retroarch"), os.path.join(sw, "retroarch"),
               os.path.join(root, "switch", "retroarch_switch.nro")]
    for d in ra_dirs:
        if os.path.exists(d):
            P(f"  存在: {os.path.relpath(d, root)}")
    for base in (root, sw):
        d = os.path.join(base, "retroarch")
        if os.path.isdir(d):
            P(f"  --- {os.path.relpath(d, root)} 顶层:")
            for name, isdir, size, mt in sorted(lst(d), key=lambda x: x[0].lower()):
                cnt = ""
                if isdir:
                    try:
                        cnt = f"({len(list(lst(os.path.join(d, name))))} 项)"
                    except Exception:
                        pass
                P(f"      {'[D]' if isdir else '[F]'} {name:<40} {size:>10}{cnt}")
            # cores
            cores = os.path.join(d, "cores")
            if os.path.isdir(cores):
                P("  --- cores 清单:")
                pf = sorted(lst(cores), key=lambda x: x[0].lower())
                P(f"      共 {len(pf)} 项")
                for name, isdir, size, mt in pf[:200]:
                    mark = "  <<非ASCII" if isnonascii(name) else ""
                    P(f"      {name:<50} {size:>10}  {t(mt)}{mark}")
            # info
            info = os.path.join(d, "info")
            if os.path.isdir(info):
                P(f"  --- info 目录: {len(list(lst(info)))} 项")

    # 6. PPSSPP
    P("\n### [6] PPSSPP 布局")
    for rel in ("switch/PPSSPP", "switch/ppsspp", "switch/PPSSPP.nro",
                "switch/ppsspp.nro", "switch/PPSSPP-Gold.nro"):
        p = os.path.join(root, rel)
        if os.path.exists(p):
            P(f"  存在: {rel}  size={os.path.getsize(p)}  {t(os.path.getmtime(p))}")
            if os.path.isdir(p):
                for name, isdir, size, mt in sorted(lst(p), key=lambda x: x[0].lower())[:60]:
                    P(f"      {'[D]' if isdir else '[F]'} {name:<45} {size:>10}")

    # 7. sys-patch log
    P("\n### [7] sys-patch 日志")
    for name in ("log.ini", "config.ini"):
        p = os.path.join(cfgtop, "sys-patch", name)
        if os.path.exists(p):
            P(f"--- {name} (size={os.path.getsize(p)}) ---")
            data = open(p, "rb").read()
            for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
                try:
                    txt = data.decode(enc)
                    break
                except Exception:
                    continue
            for ln in txt.splitlines()[:400]:
                P("  " + ln)
        else:
            P(f"  (无) {name}")

    # 8. 非 ASCII 文件名统计
    P("\n### [8] 非 ASCII 文件名统计 (中文/日文路径, fs 编码补丁敏感)")
    counts = {}
    samples = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        if depth > 4:
            dirnames[:] = []
            continue
        try:
            dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d)]
        except Exception:
            pass
        for n in dirnames + filenames:
            if isnonascii(n):
                full = os.path.join(dirpath, n)
                ext = os.path.splitext(n)[1].lower()
                key = (rel, ext)
                counts[key] = counts.get(key, 0) + 1
                if len(samples) < 120:
                    samples.append(os.path.relpath(full, root))
    P(f"  非 ASCII 条目合计: {sum(counts.values())}")
    agg = {}
    for (rel, ext), c in counts.items():
        agg.setdefault(rel, []).append((ext, c))
    for rel in sorted(agg, key=lambda x: sum(v for _, v in agg[x]), reverse=True)[:40]:
        tot = sum(v for _, v in agg[rel])
        exts = ", ".join(f"{e or '(无扩展名)'}:{c}" for e, c in sorted(agg[rel], key=lambda x: -x[1])[:6])
        P(f"  {tot:>5}  {rel}   [{exts}]")
    P("  样例(前 120):")
    for s in samples:
        P("    " + s)

    P("\n### 扫描完成")
    with open(outf, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("\n>> 已写入:", outf)

if __name__ == "__main__":
    main()
