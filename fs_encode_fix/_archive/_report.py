#!/usr/bin/env python3
"""
Render the FS callback/vtable inventory to markdown.

Inputs: _inventory.json  (vptr/slot dumps)
        _vptr_consumers.json (constructor/loader per vptr)
        _fmap.json (function names)
Output: callback_tables.md
"""
import json, re

INV = json.load(open("_inventory.json"))
CONS = json.load(open("_vptr_consumers.json"))
FMAP = {int(k) + (0x7100000000 if int(k) < 0x1000000 else 0): v
        for k, v in json.load(open("_fmap.json")).items()}

FS_RE = re.compile(r"(^fs_|^\w*fs_\w*|_fs_|FAT_|fat_|PFCODE_|nca_|FsObject|FsDrv)", re.I)


def score_slots(r):
    """count how many slots look FS-related (named with fs/fat/nca, or pure/stub)."""
    s = 0
    for a, t, nm in r["slots"]:
        if nm and FS_RE.search(nm):
            s += 2
        elif nm:
            s += 0
    return s


SKIP = {"fs_pure_virtual_function_call", "fs_stub_return_zero", "(zero)", ""}


def label_for(r):
    vp = r["vptr"]
    c = CONS.get(vp, [])
    if c:
        return c[0][1] or ""
    # else derive from first named real method slot (skip pure/stub placeholders)
    for a, t, nm in r["slots"][:8]:
        if nm and nm not in SKIP:
            return nm + " (derived)"
    return ""


rows = sorted(INV, key=lambda r: -score_slots(r))
fs_rows = [r for r in rows if score_slots(r) >= 2]

out = []
out.append("# FS 模块回调/虚函数表遍历清单\n")
out.append(f"- 二进制: `19.exfat.FS.kip1` (KIP1, image base `0x7100000000`)")
out.append(f"- `.got` 中指向 `.data` 的指针槽: **{len(INV)}** 个")
out.append(f"- 其中槽位含 FS/FAT/NCA 命名函数的表: **{len(fs_rows)}** 个\n")
out.append("## 约定\n")
out.append("- 对象内 `vptr` 指向 `vtable[-2]`(`offset_to_top`,`typeinfo`)，因此**方法槽 0 = vptr + 0x10**。")
out.append("- `.got` 条目以 24 位重定位形式存放 `vptr`；`.data` 槽位同理存放 `target - 0x7100000000`。")
out.append("- 槽位里 `0x71001c90e0` = `fs_pure_virtual_function_call`（纯虚占位）；")
out.append("  `0x71001c8fc0` = `fs_stub_return_zero`；`0x7100026574`=`ret`、`0x710002657c`=`mov x0,xzr;ret`（析构桩）。\n")

# ---- codepage callback table (registered at runtime in .bss) -------------
out.append("## 代码页回调表 (PFCODE 上下文, `.bss` 运行时填充)\n")
out.append("由 `PFCODE_CP932_Init` (`0x71000d5150`) 注册。上下文对象基址 = GOT `0x710024eb50` 的值 = `0x7100fcfc38`；")
out.append("`stp/str` 序列把 6 个函数指针写入对象 `+0x18..+0x40`（对应命名全局 `0x7100fcfc50..0x7100fcfc78`）：\n")
out.append("| 槽偏移(自对象基) | 全局符号 | 地址 | 目标函数 | 目标地址 |")
out.append("|--------|----------|------|----------|----------|")
cp = [
    ("+0x18", "pOEM2Unicode", "0x7100fcfc50", "PFCODE_CP932_OEM2Unicode", "0x71000feac0"),
    ("+0x20", "pUnicode2OEM", "0x7100fcfc58", "PFCODE_CP932_Unicode2OEM", "0x71000fec30"),
    ("+0x28", "pOEMCharWidth", "0x7100fcfc60", "PFCODE_CP932_OEMCharWidth", "0x71000fee00"),
    ("+0x30", "pisOEMMBchar", "0x7100fcfc68", "PFCODE_CP932_isOEMMBchar", "0x71000fee40"),
    ("+0x38", "pUnicodeCharWidth", "0x7100fcfc70", "PFCODE_CP932_UnicodeCharWidth", "0x71000fee90"),
    ("+0x40", "pisUnicodeMBchar", "0x7100fcfc78", "PFCODE_CP932_isUnicodeMBchar", "0x71000feea0"),
]
for off, g, addr, fn, faddr in cp:
    out.append(f"| `{off}` | `{g}` | `{addr}` | `{fn}` | `{faddr}` |")
out.append("")
out.append("> 注册指令 (`0x71000d5220` 起)：`stp x19,x8,[x21,#0x10]`（`+0x10`=传入 callback），"
           "`stp x8,x9,[x21,#0x20]`，`stp x8,x9,[x21,#0x30]`，`str x8,[x21,#0x40]`；"
           "其中 `x8/x9` 分别来自 GOT `0x710024eb58/60/68/70/78/80`。")
out.append("> 本 fork 的补丁点 `fs_codepage_patch()` 正作用于 `PFCODE_CP932_OEM2Unicode`/`Unicode2OEM`，"
           "即表中 `pOEM2Unicode`/`pUnicode2OEM` 两个槽的目标函数。\n")
out.append("---\n")

# ---- FS vtable accessor layer -------------------------------------------
ACCESSORS = [
    ("fs_locked_vtable_call_0x10", "0x710011c5bc"), ("fs_locked_vtable_call_0x18", "0x710011c8d4"),
    ("fs_locked_vtable_call_0x20", "0x710011c640"), ("fs_locked_vtable_call_0x28", "0x710011c930"),
    ("fs_locked_vtable_call_0x30", "0x710011c98c"), ("fs_locked_vtable_call_0x38", "0x710011c9e8"),
    ("fs_locked_vtable_call_0x40", "0x710011ca44"), ("fs_locked_vtable_call_0x48", "0x710011caa8"),
    ("fs_locked_vtable_call_0x50", "0x710011cb0c"), ("fs_locked_vtable_call_0x58", "0x710011cb84"),
    ("fs_locked_vtable_call_0x60", "0x710011cbf8"), ("fs_locked_vtable_call_0x68", "0x710011c69c"),
    ("fs_locked_vtable_call_0xa8", "0x710011cc6c"),
    ("fs_locked_file_vtable_call_0x18", "0x710011d204"), ("fs_locked_file_vtable_call_0x28", "0x710011cf84"),
    ("fs_locked_file_vtable_call_0x30", "0x710011cf18"), ("fs_locked_file_vtable_call_0x38", "0x710011d03c"),
    ("fs_call_vtable_method_10", "0x7100087550"), ("fs_call_vtable_method_18", "0x71001ba03c"),
    ("fs_call_vtable_method_indirect", "0x7100063db8"),
]
out.append("## FS 对象 vtable 访问器层 (`fs_locked_vtable_call_0xNN`)\n")
out.append("这些内联访问器按固定偏移调用主 FS 对象的虚方法，直接给出主 vtable 的槽布局：\n")
out.append("| 访问器 | 地址 | 目标槽偏移 |")
out.append("|--------|------|-----------|")
for n_, a in ACCESSORS:
    off = n_.rsplit("0x", 1)[1] if "0x" in n_ else "-"
    out.append(f"| `{n_}` | `{a}` | `+0x{off}` |")
out.append("")
out.append("---\n")

# ---- IDirectory / IFile interface tables --------------------------------
out.append("## `IDirectory_Func_Table` (`0x7100247048`)\n")
out.append("由 `FUN_71000c92f0` 在对象首字写入 (`*obj = &IDirectory_Func_Table`)。表内 `0` 为对齐填充；")
out.append("槽 7 起为内嵌子对象表 `PTR_FUN_7100247080`，槽 17 起为 `PTR_LAB_71002470d0`。\n")
out.append("| # | 槽地址 | 目标 | 名称 |")
out.append("|---|--------|------|------|")
idl = [
    (0, "0x7100247048", "0x71000c93c0", ""),
    (1, "0x7100247050", "0x71000c93d4", "FUN_71000c93d4 (dtor)"),
    (2, "0x7100247058", "0x71000c9408", ""),
    (3, "0x7100247060", "0x71001c8fc0", "fs_stub_return_zero"),
    (4, "0x7100247068", "0x71000c9414", ""),
    (7, "0x7100247080", "0x710004e870", ""),
    (8, "0x7100247088", "0x71000c9420", ""),
    (9, "0x7100247090", "0x710004e130", ""),
    (10, "0x7100247098", "0x710004e27c", ""),
    (11, "0x71002470a0", "0x710004e45c", ""),
    (12, "0x71002470a8", "0x710004e3c0", ""),
    (13, "0x71002470b0", "0x710004e3e8", ""),
    (14, "0x71002470b8", "0x710004e46c", ""),
    (17, "0x71002470d0", "0x71000c95d4", ""),
    (18, "0x71002470d8", "0x71000c95e8", "FUN_71000c95e8 (dtor)"),
    (19, "0x71002470e0", "0x71000c961c", ""),
]
for i, sa, t, n_ in idl:
    out.append(f"| {i} | `{sa}` | `{t}` | {n_} |")
out.append("")
out.append("---\n")

# ---- summary index ------------------------------------------------------
out.append("## 索引\n")
out.append("| vptr | 槽0 | n | 标识 |")
out.append("|------|-----|---|------|")
for r in fs_rows:
    out.append(f"| `{r['vptr']}` | `{r['slot0']}` | {r['n']} | {label_for(r)} |")
out.append("\n---\n")

# ---- detail ------------------------------------------------------------
for r in fs_rows:
    lbl = label_for(r)
    out.append(f"## `{r['vptr']}` → 槽0 = `{r['slot0']}`  (n={r['n']})")
    if lbl:
        out.append(f"- 构造/装载者: `{lbl}`")
    out.append("")
    out.append("| # | 槽地址 | 目标 | 名称 |")
    out.append("|---|--------|------|------|")
    for i, (a, t, nm) in enumerate(r["slots"]):
        out.append(f"| {i} | `{a}` | `{t}` | {nm or ''} |")
    out.append("")

open("callback_tables.md", "w", encoding="utf-8").write("\n".join(out))
print("wrote callback_tables.md,", len(out), "lines;", len(fs_rows), "FS tables")
