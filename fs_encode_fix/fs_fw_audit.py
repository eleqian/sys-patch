#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fs_fw_audit.py —— Switch 固件 fs 驱动自动解包 + 补丁适配审计（本项目专用）。

把"换了一份固件，本项目的 fs 编码补丁还能不能用、偏移要怎么改"这件事全自动化，
一条命令从原始固件包跑到可读报告：

  ① unpack ｜ 固件 zip / NCA 目录 → 解密解包 → BootImagePackage → package2
             → INI1 → FS.kip1 → 解压出明文 FS_unc.kip1（= 补丁目标二进制）
  ② check  ｜ 解析 sysmod/src/fs_codepage.cpp 里的 fs 补丁表（fs_fn_groups[] /
             fs_inst_patches[] / fs_blob_patches[]），拿每条 pattern 在基线 fs 上
             现场命中反推 site + cmp 指纹，再逐点在新 FS 上比对：
             同址命中 / 已漂移（MOVED） / 失效（LOST）
  ③ locate ｜ 失效点分层重定位：
             L0 同址命中 → L1 全代码段唯一命中 → L2 块漂移(共同 delta)投票
             → L3 上下文窗口锚点投票（容忍少量指令变化）→ 给出候选 + 新旧差异
  ④ report ｜ 汇成 markdown 报告（每点状态、新旧偏移、delta、建议 cmp 字节、反汇编差异）

用法（常用）：
  # 全流程：固件 zip → FS_unc.kip1 → 审计报告
  python fs_fw_audit.py audit "D:/Design/NS/ns_reverse/firmware/Firmware 19.0.1.zip"

  # 只解包
  python fs_fw_audit.py unpack "<zip 或含 .nca 的目录>" --work <工作目录>

  # 已经有 FS 二进制，直接审计（对照基线默认取 19.exfat.FS.kip1）
  python fs_fw_audit.py check  --fs <FS_unc.kip1>
  python fs_fw_audit.py audit  --fs <FS_unc.kip1> --base-fs <基线 FS.kip1>

产物（默认落在 --work 目录，未指定则用 .audit/<固件名>/）：
  FS_unc.kip1      解压后的 fs（补丁目标）
  manifest.json    解包元信息（版本 / 段表 / 各步产物 / sha1）
  report.md        审计报告（主交付物）

依赖：Python 3.8+；解包需要 hactool.exe / nstool.exe / prod.keys
（默认在 D:/Design/NS/ns_reverse/，可用参数或环境变量覆盖）；反汇编可选 capstone
（缺失时降级为十六进制对照，不影响判定）。
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ------------------------------------------------------------------ 常量

# fs 镜像基址：**仅分析用**，运行时 ASLR 随机化（结论一律用相对偏移）
IMAGE_BASE = 0x7100000000
# KIP1 头长度：文件偏移 = 0x100 + (VA − 0x7100000000)
KIP1_HEADER = 0x100

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def pick(*cands):
    """返回第一个存在的候选路径（都不存在时返回第一个，便于报错显示）。"""
    for c in cands:
        if c and os.path.exists(c):
            return c
    return cands[0]


# 外部工具默认位置。查找顺序：环境变量 → 脚本同目录 tools/（推荐放新版工具）
# → 脚本同目录 → 逆向工作目录。**务必用新版 hactool**：老版本（如 2020 年构建）
# 读不了新固件（20.x+）的 NCA。
RE_DIR = os.environ.get("NS_RE_DIR", "D:/Design/NS/ns_reverse")
HACTOOL = pick(os.environ.get("HACTOOL", ""),
               os.path.join(SCRIPT_DIR, "tools", "hactool.exe"),
               os.path.join(SCRIPT_DIR, "hactool.exe"),
               os.path.join(RE_DIR, "hactool.exe"))
NSTOOL = pick(os.environ.get("NSTOOL", ""),
              os.path.join(SCRIPT_DIR, "tools", "nstool.exe"),
              os.path.join(SCRIPT_DIR, "nstool.exe"),
              os.path.join(RE_DIR, "nstool.exe"))
KEYS = pick(os.environ.get("PROD_KEYS", ""),
            os.path.join(SCRIPT_DIR, "tools", "prod.keys"),
            os.path.join(SCRIPT_DIR, "prod.keys"),
            os.path.join(RE_DIR, "prod.keys"))

# 补丁基线二进制（本工程全部补丁的推导来源）。脚本被拷到仓库外时，
# 把基线放在脚本同目录（或 baseline/ 子目录）即可自包含。
BASE_FS = pick(os.environ.get("FS_KIP1", ""),
               os.path.join(SCRIPT_DIR, "baseline", "19.exfat.FS.kip1"),
               os.path.join(SCRIPT_DIR, "19.exfat.FS.kip1"),
               os.path.join(RE_DIR, "FS_ghidra_1", "bin", "19.exfat.FS.kip1"))

# 本仓库内的补丁表文件（fs 表权威）。2026-09-19 起 fs 表在 src/fs_codepage.cpp
# （原 main.cpp 的表已拆出）；脚本被拷到仓库外时依次尝试候选路径，**仓库里的那份优先**。
MAIN_CPP = pick(os.environ.get("FS_TABLE_CXX", ""),
                os.path.join(SCRIPT_DIR, "..", "sysmod", "src", "fs_codepage.cpp"),
                "D:/Design/NS/sys-patch/sysmod/src/fs_codepage.cpp",
                os.path.join(SCRIPT_DIR, "fs_codepage.cpp"))

# 构建产物 elf（`holes` 用来读替换函数的实际编译尺寸）
ELF_PATH = pick(os.environ.get("FS_ELF", ""),
                os.path.join(SCRIPT_DIR, "..", "sysmod", "sys-patch.elf"),
                "D:/Design/NS/sys-patch/sysmod/sys-patch.elf")

# 唯一待解包的固件元数据 title：BootImagePackage（普通启动）
BOOT_TITLE = "0100000000000819"

# 七个"整函数替换"补丁位在**基线**（19.exfat.FS.kip1）上的可用空间（洞）。
# 换目标固件版本必须重推 —— 这里只用于在报告里提示"新位置洞是否够用"。
# 洞 = 从补丁点起可以安全覆写的字节数。来源是 Ghidra 函数边界，换固件必须重推。
# boundary = 限制这个洞的那个地址（通常是紧邻的下一个函数入口；若本函数体之后
# 就是 udf 填充，就取填充末尾）。换固件时用锚点在新镜像里定位 boundary，
# 新洞 = 新 boundary − 新补丁点偏移 —— 比"扫描下一个函数序言"的启发式可靠得多
# （转换器那类叶子函数没有栈序言，启发式会漏掉边界并高估洞）。
# ⚠️ 这里的 hole 是**基线洞**（用于投影比对）；构建期守卫
# （sysmod/tools/check_patch_sizes.py 的 FUNCTIONS 表）用的是跨 26 份变体的
# **全局最小洞**（p29 0xB0、M8 0x240 等），两者口径不同、都要维护。
# 键 = 基线偏移（= blob 模板在基线 fs 上的唯一命中点）。
FUNC_HOLES = {
    0xFEAC0: dict(symbol="patch_utf8_to_utf16", boundary=0xFEC30, hole=0x170,
                  note="down to 0x71000fec30 PFCODE_CP932_Unicode2OEM"),
    0xFEC30: dict(symbol="patch_utf16_to_utf8", boundary=0xFEE00, hole=0x1D0,
                  note="down to 0x71000fee00 OEMCharWidth"),
    0xFEE40: dict(symbol="patch_is_oem_mb_char", boundary=0xFEE90, hole=0x50,
                  note="自己 extent 0xfee40..0xfee8c + 0xfee8c 的 udf，须保留 0xfee90 回调 stub"),
    0xF5840: dict(symbol="patch_str_unicode2oem", boundary=0xF5960, hole=0x120,
                  note="down to 0x71000f5960 Str_OEM2Unicode"),
    0xF7C10: dict(symbol="patch_stringdesc_toupper", boundary=0xF7CE0, hole=0xD0,
                  note="down to 0x71000f7ce0 PFCODE_CP932_ConvertWidth；"
                       "14.x/15.x 实测最小 0xB0（守卫按全局最小 0xB0 卡）"),
    0xF4770: dict(symbol="patch_widechar_compare", boundary=0xF4AD0, hole=0x360,
                  note="M6。down to 0x71000f4ad0（原件 ret@0xf4ac8 + udf@0xf4acc）；"
                       "三种形状 0x360/0x370/0x380，守卫按最小 0x360 卡"),
    0xF44E0: dict(symbol="patch_fat_getnextchar", boundary=0xF4770, hole=0x290,
                  note="M8。down to 0x71000f4770 WideChar_Compare；48 变体实测 "
                       "0x240~0x290，守卫按全局最小 0x240 卡"),
}


# ------------------------------------------------------------------ 小工具

RET_W = 0xD65F03C0
NOP_W = 0xD503201F
UDF_W = 0x00000000


def _looks_prologue(w):
    """这条指令像不像函数序言（换固件后函数边界只能靠这类特征推）。"""
    if w in (0xD503237F, 0xD503245F):                 # pacibsp / bti c
        return True
    if w == 0x910003FD:                               # mov x29, sp
        return True
    if (w & 0xFFC003FF) in (0xD10003FF, 0x910003FF):  # sub/add sp, sp, #imm
        return True
    if (w & 0xFFC00000) == 0xA9800000:                # stp ..., [sp, #-N]!
        return True
    if (w & 0xFFC00000) == 0xA9000000:                # stp ..., [sp, #N]
        return True
    return False


def locate_neighbor(code, base, addr, min_ratio=0.9):
    """在 code 里定位基线地址 addr（用作洞边界的相邻函数入口）。

    用锚点投票 + 语义匹配率过滤；边界函数有长有短（有的是几百字节的
    转换器，有的只是几字节的 stub），所以依次试几种窗口大小，返回命中的
    新地址，全试不通返回 None。
    """
    for back, fwd, mr in ((0, 48, min_ratio), (0, 96, min_ratio),
                          (16, 96, min_ratio - 0.05), (0, 192, min_ratio - 0.05)):
        ws, win = window_for(addr, base, back, fwd)
        if len(win) < 16:
            continue
        for cand, same, total, _votes in anchor_locate(code, win):
            if total and same / total >= mr:
                return cand + (addr - ws)
    return None


def estimate_hole(code, site, scan=0x1000):
    """兜底估算：靠"函数尾声 + 下一个函数序言"推洞（仅在无法用锚点定位边界时用）。

    注意：转换器那类叶子函数没有栈序言，这个启发式会**高估**洞，
    所以结果只作参考，权威做法见 locate_neighbor。
    """
    limit = min(len(code) - 4, site + scan)
    seen_ret, prev = False, None
    for p in range(site, limit, 4):
        cw = struct.unpack_from("<I", code, p)[0]
        if seen_ret and p > site and prev in (RET_W, NOP_W, UDF_W) \
                and _looks_prologue(cw):
            return p - site
        if cw == RET_W:
            seen_ret = True
        prev = cw
    return None


def elf_symbol_sizes(path):
    """读 ELF 的 {符号名: (st_value, st_size)}。

    用来拿替换函数的实际编译尺寸 —— 守卫 (check_patch_sizes.py) 的尺寸来源是
    `patch_xxx` 符号的 st_size，这里直接复用，避免两处口径打架。
    """
    if not path or not os.path.exists(path):
        return {}
    data = read_file(path)
    if data[:4] != b"\x7fELF":
        return {}
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    secs = []
    for i in range(e_shnum):
        (sh_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link,
         _info, _align, sh_entsize) = struct.unpack_from(
            "<IIQQQQIIQQ", data, e_shoff + i * e_shentsize)
        secs.append(dict(name=sh_name, type=sh_type, offset=sh_offset,
                         size=sh_size, link=sh_link, entsize=sh_entsize))
    if e_shstrndx >= len(secs):
        return {}
    shstr = secs[e_shstrndx]
    shstrtab = data[shstr["offset"]:shstr["offset"] + shstr["size"]]

    def cstr(tab, off):
        end = tab.find(b"\0", off)
        return tab[off:end].decode("utf-8", "replace")

    out = {}
    for sec in secs:
        if sec["type"] != 2 or not sec["link"]:        # SHT_SYMTAB
            continue
        strsec = secs[sec["link"]]
        strtab = data[strsec["offset"]:strsec["offset"] + strsec["size"]]
        entsize = sec["entsize"] or 24
        for off in range(sec["offset"], sec["offset"] + sec["size"], entsize):
            st_name, _info, _other, _shndx, st_value, st_size = struct.unpack_from(
                "<IBBHQQ", data, off)
            if st_name:
                out[cstr(strtab, st_name)] = (st_value, st_size)
    return out


def log(msg):
    print(msg, flush=True)


def winpath(p):
    """hactool 是 MSVC 程序：它把 `--xxxdir` 的值与文件名用 `\\` 硬拼。
    传正斜杠会得到 "a/b\\name" 这种混合路径，fopen 直接失败且只打一条
    "Failed to open" 就继续，极易误判成"没解出文件"。统一转成反斜杠。
    （配套要求：目标目录必须已存在，hactool 不建 base 目录。）"""
    return os.path.normpath(p).replace("/", "\\") if os.name == "nt" else p


def sha1_of(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def find_all(hay, needle, limit=64):
    """返回 needle 在 hay 中所有出现的偏移（允许重叠），最多 limit 个。"""
    out = []
    start = 0
    while len(out) < limit:
        i = hay.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def ensure_usable_keys(path):
    """hactool 对 key 长度是**硬校验**，值不是 32 位十六进制就直接 exit(1)，
    整条解包链当场断掉（表现是"NCA 头探测不出 Title ID"，很容易误判成固件不支持）。

    实测某些第三方 prod.keys 会把 `*_source_*` 这类 16 字节 key 写成 17 字节
    （末尾多一个 00），hactool 一律拒绝加载。这里做预检：把这种「34 位且以 00
    结尾」的值剥掉尾字节，另存为 `<name>.fixed` 后使用——**原文件不动**。
    """
    try:
        with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
            raw = f.read()
    except OSError:
        return path
    hexdigits = set("0123456789abcdefABCDEF")
    out, fixed = [], []
    for line in raw.split("\n"):
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k, v = [x.strip() for x in s.split("=", 1)]
            if len(v) == 34 and v[-2:] == "00" and all(c in hexdigits for c in v):
                fixed.append(k)
                out.append(line.replace(v, v[:-2]))
                continue
        out.append(line)
    if not fixed:
        return path
    dst = path + ".fixed"
    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out))
    log("[keys] %s 里 %d 个键的值是 34 位十六进制（末尾多一个 00），hactool 会拒绝加载；"
        "已剥掉尾字节另存为 %s 并使用。原始文件未改动。"
        % (os.path.basename(path), len(fixed), os.path.basename(dst)))
    log("[keys] 修正的键：%s" % ", ".join(fixed))
    return dst


def norm_tool_arg(a):
    """把工具命令行里的路径参数统一成 Windows 反斜杠。

    踩过的坑：hactool / nstool 都是 MSVC 程序，路径里混用 `/` 和 `\\` 会直接失败
    —— nstool 报 "Path literal has both forward ('/') and backward ('\\')"，
    hactool 更阴，只在解包时打一行 "Failed to open ..." 然后 rc=0 正常退出。
    """
    if os.name != "nt":
        return a
    if not a.startswith("-") and "=" in a:          # --romfsdir=<path>
        k, v = a.split("=", 1)
        return k + "=" + winpath(v) if ("/" in v or "\\" in v) else a
    if "/" in a or "\\" in a:                        # 裸路径参数
        return winpath(a)
    return a


def run_tool(cmd, logfile=None):
    """运行外部工具；返回 (returncode, stdout+stderr)。"""
    cmd = [norm_tool_arg(x) for x in cmd]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          creationflags=(subprocess.CREATE_NO_WINDOW
                                         if os.name == "nt" else 0))
    out = proc.stdout.decode("utf-8", "replace")
    if logfile:
        with open(logfile, "w", encoding="utf-8") as f:
            f.write("$ %s\n%s" % (" ".join(cmd), out))
    return proc.returncode, out


# ------------------------------------------------------- KIP1 / fs 二进制

def kip1_info(data):
    """解析 KIP1 头，返回 dict（段表 + 代码段范围）。"""
    if data[:4] != b"KIP1":
        raise ValueError("不是 KIP1 文件（magic=%r）—— 请确认传入的是解压后的 FS.kip1"
                         % data[:4])
    name = data[4:16].rstrip(b"\0").decode("utf-8", "replace")
    secs = []
    for i in range(6):
        off, size = struct.unpack_from("<II", data, 0x20 + i * 8)
        secs.append((off, size))
    # 压缩态检测。KIP1 段表项是 0x10 字节：(out_offset, out_size, comp_size, attr)。
    # 压缩态与解压态的**头部完全一样**，只有文件长度不同；按偏移直接取字节会拿到
    # 压缩数据，比对结果"29 点全失效"——极易被误读成"补丁在新固件上全废了"。
    # 判据：① 代码段声明的范围超出文件实际长度；② 代码段 comp_size 小于 out_size。
    # 注意不能简单用"段大小总和 > 文件长度"：第 4 段是 bss，只有大小没有文件内容。
    text_off, text_size = secs[0]
    avail = len(data) - KIP1_HEADER
    comp_size = struct.unpack_from("<I", data, 0x20 + 2 * 4)[0]
    if (text_off + text_size > avail) or (0 < comp_size < text_size):
        raise ValueError(
            "这是**压缩态** KIP1：段表声明代码段 %d 字节，文件只剩 %d 字节"
            "（comp_size=0x%X）\n"
            "       按偏移取到的是压缩数据，比对结果无意义。\n"
            "       先解压再传：hactool -k <keys> -t kip1 --uncompressed=FS_unc.kip1 FS.kip1"
            % (text_size, avail, comp_size))
    # 段表里的偏移是相对 KIP1 头之后（0x100）的；代码段起点即 0x100 + text_off
    text_start = KIP1_HEADER + text_off
    text_end = min(len(data), text_start + text_size)
    return dict(name=name, sections=secs, text_start=text_start,
                text_size=text_end - text_start, rodata_size=secs[1][1])


class FsImage:
    """解压后的 fs 代码镜像。文件偏移 = 0x100 + (VA − IMAGE_BASE)。"""

    def __init__(self, path):
        self.path = path
        self.data = read_file(path)
        info = kip1_info(self.data)
        self.name = info["name"]
        self.text_start = info["text_start"]
        self.text_size = info["text_size"]
        self.code = self.data[self.text_start:self.text_start + self.text_size]

    def off_to_file(self, off):
        return self.text_start + off

    def bytes_at(self, off, n):
        fo = self.off_to_file(off)
        return self.data[fo:fo + n]

    def addr(self, off):
        return IMAGE_BASE + off


# ------------------------------------------- 补丁表解析（sysmod/src/fs_codepage.cpp）

ARRAY_RE = re.compile(r"const\s+u8\s+(\w+)\s*\[\s*(\d*)\s*\]\s*=\s*\{(.*?)\}\s*;", re.S)
CALL_RE = re.compile(
    r"fs_patch_function\(\s*handle\s*,\s*mem_info\.addr\s*\+\s*(0x[0-9a-fA-F]+)\s*,"
    r"\s*(\w+)\s*,\s*sizeof\s*\(\s*\2\s*\)\s*,\s*([^,]+?)\s*,", re.S)
PROGRESS_RE = re.compile(r'fs_(?:stage|progress)\(\s*"([^"]+)"\s*\)')

# --- pattern 驱动的两级表：fs_fn_groups[] / fs_inst_patches[] / fs_blob_patches[]
# 与 sysmod/tools/check_patch_sizes.py 的解析保持一致；`.` 是通配（REGEX_SKIP）。
# ⚠️ 表在 **fs_codepage.cpp**（2026-09-19 从 main.cpp 拆出），改表格式时本文件要同步。
# 条目名 = `<功能名>_<版本范围>`（如 fs_cp_makeshortname_15.0.1-20.5.0；
#           范围沿用原 sys-patch：`a.b.c-d.e.f` / `a.b.c+`，非连续覆盖用 `,` 分段）。
#           故名字允许 `. + - ,`——正则字符集必须包含，否则整条静默丢掉。
# FsInstPatch = { name, pattern, inst_offset, cond, patch }
#            （P1 的 `rules_applied<X>` 列、2026-09-20 的 stage_idx 与 needs_wide_cmp
#              均已删除：谓词位图保证「已打过」分支不可达，条目一律全量应用，
#              pred_idx 由 cond 反查（fs_pred_index），表里没有这一列）
# FsBlobPatch = { name, pattern, entry_offset, FsBlobImpl::X }
# FsFnGroup   = { label, pat_begin, pat_end, blob_begin, blob_end }
FS_PAT_RE = re.compile(
    r'\{\s*"([A-Za-z0-9_.,+-]+)",\s*"(0x[0-9A-Fa-f.]+)",\s*(-?\d+),\s*'
    r'(\w+),\s*(\w+)\s*\}')
FS_BLOB_RE = re.compile(
    r'\{\s*"([A-Za-z0-9_.,+-]+)",\s*"(0x[0-9A-Fa-f.]+)",\s*(-?\d+),\s*FsBlobImpl::(\w+)\s*\}')
FS_STAGE_RE = re.compile(
    r'\{\s*"([^"]+)"\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\}')


def parse_fs_pattern(s):
    """'0xAB.CD' -> [0xAB, None, 0xCD]（None = 通配）；非法返回 None。

    ⚠️ 口径与 C++ 的 `str2hex` 一致：**一个 `.` = 一个通配字节**（逐字符解析）。
    不要写成"`..` = 一个通配字节"——那是历史 PATTERNS.json 的写法，两者混用会让
    槽数翻倍（轻则不命中、重则整表 0 命中）。构建期守卫用的是同一口径。
    """
    body = s[2:]
    out = []
    for ch in body:
        if ch == ".":
            out.append(None)
        elif ch in "0123456789abcdefABCDEF":
            out.append(ch)
        else:
            return None
    # 半字节（奇数个十六进制字符）非法：两两合并成字节
    if len([c for c in out if c is not None]) % 2:
        return None
    res, hi = [], None
    for ch in out:
        if ch is None:
            if hi is not None:
                return None
            res.append(None)
        elif hi is None:
            hi = ch
        else:
            res.append(int(hi + ch, 16))
            hi = None
    return res


def find_pattern(hay, pat, limit=64):
    """通配 pattern 在 hay 里的全部命中（None = 任意字节）。
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
    if bl == 0:
        return []
    anchor = bytes(pat[bs:bs + bl])
    out, i = [], hay.find(anchor)
    while i >= 0 and len(out) < limit:
        st = i - bs
        if st >= 0 and st + n <= len(hay) and \
           all(pat[k] is None or hay[st + k] == pat[k] for k in range(n)):
            out.append(st)
        i = hay.find(anchor, i + 1)
    return out


def group_labels(groups, which, total):
    """把 fs_fn_groups[] 的 [begin,end) 区间摊平成「下标 -> 组名」（与运行期一致）。"""
    labels = ["?"] * total
    for s in groups:
        b, e = (s["pb"], s["pe"]) if which == "p" else (s["bb"], s["be"])
        for i in range(b, min(e, total)):
            labels[i] = s["label"]
    return labels


def strip_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def parse_bytes(blob):
    out = []
    for tok in blob.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if not re.fullmatch(r"0[xX][0-9a-fA-F]+", tok):
            return None
        out.append(int(tok, 16) & 0xFF)
    return bytes(out)


def parse_sites(main_cpp, base_fs=None):
    """解析 fs_codepage.cpp，返回补丁点列表（含 fs_fn_group 分组、cmp 字节）。

    支持两代补丁表格式，都归一到同一套 site dict，下游（重定位 / 报表 / holes）不必区分：

      A) 旧：`fs_patch_function(handle, mem_info.addr + 0xXXXX, cmp, sizeof(cmp), patch, ...)`
         —— 每点一个**硬编码偏移** + cmp/patch 字节数组。
      B) 新（pattern 驱动）：`fs_fn_groups[]` + `fs_inst_patches[]` + `fs_blob_patches[]`，
         偏移不再硬编码：拿 pattern 在**基线 fs** 上现场命中，`site = 命中 + inst_offset`，
         `cmp` 取基线该处的真实字节（指令级 4 字节 / 函数体 16 字节，够做指纹）。

    新格式下同一补丁点可能有多条「变体族」pattern，一份固件只会命中其中一族：
    0 命中的族直接跳过（正常，不是错误）；>=2 命中的族会**跳过并告警**（可能写到别处）。
    """
    with open(main_cpp, encoding="utf-8") as f:
        src = strip_comments(f.read())

    arrays = {}
    for m in ARRAY_RE.finditer(src):
        b = parse_bytes(m.group(3))
        if b is not None:
            arrays[m.group(1)] = b

    if CALL_RE.search(src):
        # ------------------------------------------------ A) 旧格式
        events = []
        for m in PROGRESS_RE.finditer(src):
            events.append((m.start(), "group", m.group(1)))
        for m in CALL_RE.finditer(src):
            events.append((m.start(), "call", m))
        events.sort(key=lambda e: e[0])

        sites = []
        cur_group = "start"
        for _pos, kind, val in events:
            if kind == "group":
                cur_group = val
                continue
            site = int(val.group(1), 16)
            cmp_name = val.group(2)
            pm = re.search(r"(\w+)\s*$", val.group(3))
            patch_name = pm.group(1) if pm else ""
            sites.append(dict(
                site=site,
                name=re.sub(r"^exfat_", "", cmp_name),
                cmp_name=cmp_name,
                cmp=arrays.get(cmp_name),
                patch_name=patch_name,
                patch=arrays.get(patch_name),
                group=cur_group,
                is_func=patch_name.startswith("patch_"),
            ))
        return sites

    # ---------------------------------------------------- B) 新格式
    pats = [dict(name=m.group(1), pattern=m.group(2), off=int(m.group(3)),
                 cond=m.group(4), patch=m.group(5))
            for m in FS_PAT_RE.finditer(src)]
    blobs = [dict(name=m.group(1), pattern=m.group(2), off=int(m.group(3)),
                  impl=m.group(4)) for m in FS_BLOB_RE.finditer(src)]
    groups = [dict(label=m.group(1).strip(), pb=int(m.group(2)), pe=int(m.group(3)),
                   bb=int(m.group(4)), be=int(m.group(5)))
              for m in FS_STAGE_RE.finditer(src)]
    if not (pats or blobs):
        sys.exit("error: %s 里既没有 fs_patch_function(...)（旧格式），也没有 "
                 "fs_inst_patches[] / fs_blob_patches[]（pattern 驱动）—— "
                 "补丁表格式不认识，检查是不是换了写法" % main_cpp)

    base_path = base_fs or BASE_FS
    base = FsImage(base_path).code if base_path and os.path.exists(base_path) else None
    if base is None:
        log("[warn] 基线 fs 不可用（%s）：pattern 驱动表要由基线反推 site/cmp，"
            "本次每个点的 cmp 都算不出来" % base_path)

    plabels = group_labels(groups, "p", len(pats))
    blabels = group_labels(groups, "b", len(blobs))

    sites, nohit, dup, bad = [], [], [], []
    for kind, entries, labels in (("pattern", pats, plabels),
                                  ("blob", blobs, blabels)):
        for i, e in enumerate(entries):
            pat = parse_fs_pattern(e["pattern"])
            if pat is None:
                bad.append(e["name"])
                continue
            site, cmp_b = None, None
            if base is not None:
                hits = find_pattern(base, pat)
                if not hits:
                    nohit.append(e["name"])          # 这份基线上的「别的变体族」
                    continue
                if len(hits) > 1:
                    dup.append("%s(%d 次)" % (e["name"], len(hits)))
                    continue
                site = hits[0] + e["off"]
                n = 16 if kind == "blob" else 4
                cmp_b = bytes(base[site:site + n])
            sites.append(dict(
                site=site,
                name=e["name"],
                cmp_name=e["name"],
                cmp=cmp_b,
                patch_name=e["name"],
                patch=None,          # 新格式没有静态 patch 字节：由 rules_*(inst) 现场生成
                group=labels[i],
                is_func=(kind == "blob"),
            ))

    if bad:
        log("[warn] %d 条 pattern 语法非法，已跳过：%s" % (len(bad), ", ".join(bad)))
    if dup:
        log("[warn] %d 条 pattern 在基线上命中 >=2 次（可能写错函数），已跳过：%s"
            % (len(dup), ", ".join(dup)))
    if nohit:
        log("[备注] %d 条 pattern 在这份基线上 0 命中 —— 属其它版本族，正常跳过：%s"
            % (len(nohit), ", ".join(nohit)))
    return sites


# --------------------------------------------------------- 定位：分层算法

# PC 相对指令的"忽略位移"掩码：(判别掩码, 判别值, 保留掩码)
# 这些指令的编码会随所在位置变化（分支目标、字面量地址），同一处代码在整段平移后
# 这些字会不同。比较时只保留"指令种类 + 寄存器"，否则逻辑上同一点会被误判成大差异。
PCREL_MASKS = (
    (0xFC000000, 0x14000000, 0xFC000000),   # B
    (0xFC000000, 0x94000000, 0xFC000000),   # BL
    (0xFF000010, 0x54000000, 0xFF000010),   # B.cond
    (0x7E000000, 0x34000000, 0x7E00001F),   # CBZ / CBNZ（bit24 是 Z/NZ 标志）
    (0x7E000000, 0x36000000, 0x7E00001F),   # TBZ / TBNZ（同上）
    (0x9F000000, 0x10000000, 0x9F000000),   # ADR
    (0x9F000000, 0x90000000, 0x9F000000),   # ADRP（bit31=1，必须单独一条）
    (0x3B000000, 0x18000000, 0x3B000000),   # LDR / LDRSW (literal)
)

_NORM_CACHE = {}


def norm_word(w):
    """把 PC 相对指令的位移位抹掉，只留"指令种类 + 寄存器"。"""
    hit = _NORM_CACHE.get(w)
    if hit is not None:
        return hit
    out = w
    for mask, val, keep in PCREL_MASKS:
        if (w & mask) == val:
            out = w & keep
            break
    _NORM_CACHE[w] = out
    return out


def similarity_win(a, b):
    """两个等长窗口按 4 字节字比较。

    返回 (严格相同字数, 语义相同字数, 总字数)。语义相同 = 对 PC 相对指令
    忽略位移后的比较：整体平移后同一处的分支/字面量访问仍然算同一指令。"""
    n = min(len(a), len(b)) & ~3
    if n == 0:
        return 0, 0, 0
    raw = sem = 0
    for i in range(0, n, 4):
        wa = struct.unpack_from("<I", a, i)[0]
        wb = struct.unpack_from("<I", b, i)[0]
        if wa == wb:
            raw += 1
            sem += 1
        elif norm_word(wa) == norm_word(wb):
            sem += 1
    return raw, sem, n // 4


def window_ratio(code, win_start, win, site, cand):
    """候选落点 cand 与基线窗口 win 的匹配率 (严格, 语义)。

    win 取自基线 fs 的 [win_start, win_start+len(win))，对应补丁点 site；
    候选 cand 处的对应窗口起点是 cand − (site − win_start)。"""
    wb = cand - (site - win_start)
    if wb < 0 or wb + len(win) > len(code):
        return 0.0, 0.0
    raw, sem, total = similarity_win(win, code[wb:wb + len(win)])
    if not total:
        return 0.0, 0.0
    return raw / total, sem / total


def anchor_locate(new_code, win, max_hits_per_word=8, topk=5):
    """在 new_code 里为窗口 win 做锚点投票定位。

    原理：把窗口按 4 字节字切开，挑出"在新代码段里出现次数少（1..max_hits）"的字
    作锚点；每个锚点的每次出现都给出一个候选基址（出现位置 − 锚点在窗口内的偏移），
    投票最多的基址即最可能的落点。对"整体平移 + 少量指令变化"极稳。
    返回 [(新偏移(相对段内), 语义相同字数, 总字数, 命中票数)]，按票数/相似度排序。
    """
    words = [(i, win[i:i + 4]) for i in range(0, len(win) - 3, 4)]
    votes = {}
    for i, w in words:
        if w == b"\x00\x00\x00\x00":
            continue
        if len(set(w)) <= 1:            # 全同字节的字（如 0x1f1f1f1f）辨别力低
            continue
        hits = find_all(new_code, w, limit=max_hits_per_word + 1)
        if not hits or len(hits) > max_hits_per_word:
            continue
        for h in hits:
            cand = h - i
            if cand < 0 or cand + len(win) > len(new_code):
                continue
            votes[cand] = votes.get(cand, 0) + 1
    if not votes:
        return []
    ranked = sorted(votes.items(), key=lambda kv: -kv[1])[:topk * 4]
    scored = []
    for cand, v in ranked:
        _raw, sem, total = similarity_win(win, new_code[cand:cand + len(win)])
        scored.append((cand, sem, total, v))
    scored.sort(key=lambda t: (-t[3], -t[1]))
    return scored[:topk]


def window_for(site, base: FsImage, back=64, fwd=64):
    """取基线 fs 上该补丁点周围的对齐窗口（用于模糊定位）。"""
    start = max(0, (site - back) & ~3)
    end = ((site + fwd) + 3) & ~3
    if end - start < 16:
        end = start + 16
    return start, base.bytes_at(start, end - start)


# 打分用的窗口变体 (back, fwd)。为什么不用单一 ±64：
# 补丁点常常紧贴函数边界（相邻函数在新固件里改了、或本函数栈帧改版导致
# `ldrb w8,[sp,#0x18]` 这类 imm12 变了），单个大窗口会把这些"窗口内但
# 不属于本点"的正常差异算进来，把正确的落点误报成 FUZZY。
# 取多个局部窗口里的最高语义匹配率，等价于"本点附近有没有对得上的代码"。
SCORE_VARIANTS = ((16, 16), (0, 32), (32, 0))


def best_window_ratio(code, base, site, cand, exact):
    """候选落点 cand 在多个局部窗口上的最高 (严格, 语义) 匹配率。"""
    if base is None:
        return (1.0, 1.0) if exact else (0.0, 0.0)
    best = (0.0, 0.0)
    for back, fwd in SCORE_VARIANTS:
        ws, win = window_for(site, base, back, fwd)
        raw, sem = window_ratio(code, ws, win, site, cand)
        if sem > best[1]:
            best = (raw, sem)
    return best


# ------------------------------------------------------------------ unpack

# zip 输入走「按需解包」：先只抽全部 *.cnmt.nca（每个 3.5KB，100 多个合计 <0.5MB）
# 用于头扫描定位 BootImagePackage，之后再单独抽那一个 package2 容器 NCA。
# 比 extractall() 少写 300MB+/固件 —— 批量跑 20 多个固件时差距很大。
CNMT_SUFFIX = ".cnmt.nca"


def extract_from_zip(src, fw_dir, only_suffix=None, only_name=None):
    """从 zip 里按需抽出 NCA 条目。only_suffix 或 only_name 二选一。"""
    os.makedirs(fw_dir, exist_ok=True)
    got = []
    with zipfile.ZipFile(src) as z:
        for info in z.infolist():
            base = os.path.basename(info.filename)
            if only_suffix is not None and not base.endswith(only_suffix):
                continue
            if only_name is not None and base != only_name:
                continue
            dst = os.path.join(fw_dir, base)
            with z.open(info) as fs, open(dst, "wb") as fd:
                shutil.copyfileobj(fs, fd, 1 << 20)
            got.append(dst)
    return got


def ensure_fw_nca(args, src, fw_dir, filename):
    """确保 fw_dir 下存在指定 NCA（zip 输入则单独抽它）。返回路径或 None。"""
    p = os.path.join(fw_dir, filename)
    if os.path.exists(p) and os.path.getsize(p) > 0:
        return p
    if os.path.isfile(src) and src.lower().endswith(".zip"):
        extract_from_zip(src, fw_dir, only_name=filename)
    return p if os.path.exists(p) and os.path.getsize(p) > 0 else None


def unpack_fs(args, src, work, title, cache_dir=None):
    """解出某个 title 对应的明文 fs → <work>/FS_unc.kip1。返回 manifest dict。

    cache_dir 用于跨 title 共享 zip 解压目录与 cnmt Title ID 扫描缓存 ——
    批量模式下一个固件要跑 fat32(0819)/exfat(081b) 两个 title，扫描只做一次。
    """
    work = os.path.abspath(work)
    cache_dir = os.path.abspath(cache_dir or work)
    os.makedirs(work, exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)

    fs_unc = os.path.join(work, "FS_unc.kip1")
    manifest_path = os.path.join(work, "manifest.json")
    if os.path.exists(fs_unc) and os.path.exists(manifest_path) and not args.force:
        try:
            m = json.load(open(manifest_path, encoding="utf-8"))
            if m.get("sha1"):
                log("[unpack] 复用已有 %s" % fs_unc)
                return m
        except ValueError:
            pass

    manifest = {"title": title}
    for tool in (args.hactool, args.nstool):
        if not os.path.exists(tool):
            sys.exit("error: 找不到工具 %s（用 --hactool/--nstool 指定）" % tool)
    if not os.path.exists(args.keys):
        sys.exit("error: 找不到 keys 文件 %s（用 --keys 指定）" % args.keys)
    args.keys = ensure_usable_keys(args.keys)

    # ---- 0. 定位固件 NCA 所在目录 -------------------------------------
    fw_dir = src
    if os.path.isfile(src) and src.lower().endswith(".zip"):
        fw_dir = os.path.join(cache_dir, "fw")
        done_flag = os.path.join(fw_dir, ".cnmts")
        if not os.path.exists(done_flag) or args.force:
            log("[unpack] 从 %s 抽出全部 cnmt.nca（按需解包）" % os.path.basename(src))
            got = extract_from_zip(src, fw_dir, only_suffix=CNMT_SUFFIX)
            log("[unpack] 抽出 %d 个 cnmt.nca" % len(got))
            open(done_flag, "w").close()
        else:
            log("[unpack] 复用已抽出目录 %s" % fw_dir)
    elif os.path.isfile(src):
        fw_dir = os.path.dirname(src)

    # ---- 1. 定位 BootImagePackage 的程序 NCA ---------------------------
    #    正常路径：固件目录 → 头扫描找 BIP 的 meta NCA → cnmt → ContentInfo id
    #    快捷路径：直接给 BIP 程序 NCA 文件（其 romfs 里就是 nx/package2）
    nca_path = None
    cnmt_file = None
    if os.path.isfile(src) and src.lower().endswith(".nca"):
        nca_path = src
        log("[unpack] 输入是单个 NCA，直接当 BootImagePackage 程序 NCA 处理")
    else:
        cnmt_file = find_boot_cnmt(fw_dir, cache_dir, args, title)
        if cnmt_file is None:
            sys.exit("error: 在 %s 下没找到 BootImagePackage_%s.cnmt"
                     % (fw_dir, title))
        log("[unpack] BootImagePackage cnmt: %s" % cnmt_file)
        manifest["boot_cnmt"] = cnmt_file

        # ---- 2. nstool 解析 cnmt → package2 的 NCA id ------------------
        rc, out = run_tool([args.nstool, "-k", args.keys, cnmt_file],
                           os.path.join(work, "nstool_cnmt.log"))
        if rc != 0:
            sys.exit("error: nstool 解析 cnmt 失败（见 %s/nstool_cnmt.log）" % work)
        ver = re.search(r"Version:\s+(\S+)", out)
        manifest["fw_version"] = ver.group(1) if ver else "?"
        m = re.search(r"Id:\s+([0-9a-fA-F]{32})", out)
        if not m:
            sys.exit("error: 从 nstool 输出里读不到 ContentInfo Id")
        pkg_id = m.group(1).lower()
        manifest["package2_nca_id"] = pkg_id
        log("[unpack] 固件版本 %s；package2 NCA = %s.nca"
            % (manifest["fw_version"], pkg_id))
        nca_path = ensure_fw_nca(args, src, fw_dir, pkg_id + ".nca")
        if nca_path is None:
            sys.exit("error: 找不到 %s（固件目录 %s 不完整？）"
                     % (os.path.join(fw_dir, pkg_id + ".nca"), fw_dir))

    # ---- 3. 解包 BootImagePackage NCA → romfs 里的 package2 ------------
    pkg_out = os.path.join(work, "bip_romfs")
    os.makedirs(pkg_out, exist_ok=True)
    rc, out = run_tool([args.hactool, "-k", args.keys, "-x", nca_path,
                        "--romfsdir=" + winpath(pkg_out)],
                       os.path.join(work, "hactool_bip.log"))
    package2 = None
    for cand in (os.path.join(pkg_out, "nx", "package2"),
                 os.path.join(pkg_out, "a", "package2")):
        if os.path.exists(cand):
            package2 = cand
            break
    if package2 is None:
        sys.exit("error: 解包后未找到 package2（见 %s/hactool_bip.log）" % work)
    log("[unpack] package2: %s (%d bytes)" % (package2, os.path.getsize(package2)))

    # ---- 4. package2 → INI1 → FS.kip1 --------------------------------
    ini1_dir = os.path.join(work, "ini1")
    pk21_out = os.path.join(work, "pk21_out")
    os.makedirs(ini1_dir, exist_ok=True)
    os.makedirs(pk21_out, exist_ok=True)
    rc, out = run_tool([args.hactool, "-k", args.keys, "-t", "pk21", package2,
                        "--outdir=" + winpath(pk21_out),
                        "--ini1dir=" + winpath(ini1_dir)],
                       os.path.join(work, "hactool_pk21.log"))
    fs_kip1 = os.path.join(ini1_dir, "FS.kip1")
    if not os.path.exists(fs_kip1):
        sys.exit("error: 未解出 INI1/FS.kip1（见 %s/hactool_pk21.log）" % work)
    log("[unpack] FS.kip1: %s (%d bytes)" % (fs_kip1, os.path.getsize(fs_kip1)))

    # ---- 5. KIP1 解压 → FS_unc.kip1（补丁目标） -----------------------
    fs_unc = os.path.join(work, "FS_unc.kip1")
    if args.force or not os.path.exists(fs_unc):
        rc, out = run_tool([args.hactool, "-k", args.keys, "-t", "kip1",
                            "--uncompressed=" + fs_unc, fs_kip1],
                           os.path.join(work, "hactool_kip1.log"))
    if not os.path.exists(fs_unc):
        sys.exit("error: KIP1 解压失败（见 %s/hactool_kip1.log）" % work)

    img = FsImage(fs_unc)
    manifest["fs_unc"] = fs_unc
    manifest["fs_size"] = len(img.data)
    manifest["text_size"] = img.text_size
    manifest["sha1"] = sha1_of(fs_unc)
    log("[unpack] FS_unc.kip1: %d bytes，代码段 0x%X" % (len(img.data), img.text_size))
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    log("[unpack] manifest → %s" % manifest_path)
    return manifest


def unpack(args):
    """单 title 解包入口（`unpack` / `all` 子命令用）。"""
    return unpack_fs(args, os.path.abspath(args.input),
                     args.work, args.title, args.work)


def nca_title_id(hactool, keys, path):
    """读一个 NCA 的 Title ID / Content Type。

    NCA 头前 0x200 字节是用 header_key 加密的（连 "NCA3" magic 都看不到），
    纯字节扫描拿不到 title id，只能让 hactool 解。好在 `-i` 单次约 80ms，
    一个固件里 100+ 个 cnmt.nca 全扫也就十秒级，且结果会缓存。
    """
    rc, out = run_tool([hactool, "-k", keys, "-i", path])
    tid = re.search(r"^Title ID:\s+([0-9a-fA-F]{16})", out, re.M)
    ct = re.search(r"^Content Type:\s+(\S+)", out, re.M)
    return (int(tid.group(1), 16) if tid else None), (ct.group(1) if ct else None)


def find_boot_cnmt(fw_dir, cache_dir, args, title):
    """在固件目录里定位 BootImagePackage 的 cnmt。

    顺序：① 已经是 cnmt 文件 / 已有解包结果 → 直接用；
          ② 用 hactool -i 逐个问 cnmt.nca 的 Title ID，命中 title；
          ③ 只解命中那一个 meta NCA 的 section0，拿到 .cnmt。
    这样 1 次解包代替"逐个试解直到撞上"，且结果缓存到 cache_dir/cnmt_titles.json。
    """
    name = "BootImagePackage_%s.cnmt" % title
    if os.path.isfile(fw_dir) and fw_dir.endswith(".cnmt"):
        return fw_dir
    # ① 已解包目录（<nca>.cnmt.nca/section0/<name>.cnmt 或直接放在固件目录）
    for root, _dirs, files in os.walk(fw_dir):
        if name in files:
            return os.path.join(root, name)
    metas = sorted(f for f in os.listdir(fw_dir) if f.endswith(".cnmt.nca"))
    if not metas:
        return None

    # ② 头扫描
    want = int(title, 16)
    os.makedirs(cache_dir, exist_ok=True)
    cache_path = os.path.join(cache_dir, "cnmt_titles.json")
    cache = {}
    if os.path.exists(cache_path) and not args.force:
        try:
            cache = json.load(open(cache_path, encoding="utf-8"))
        except ValueError:
            cache = {}
    log("[unpack] 扫描 %d 个 cnmt.nca 的 Title ID 找 %s…" % (len(metas), title))
    hit, probe = None, 0
    for i, meta in enumerate(metas, 1):
        if meta in cache:
            tid = cache[meta]
        else:
            tid, _ct = nca_title_id(args.hactool, args.keys,
                                    os.path.join(fw_dir, meta))
            cache[meta] = tid
            probe += 1
        if tid == want:
            hit = meta
            break
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=1)
    if hit is None:
        log("[unpack] 头扫描未命中（探测 %d 个新文件）" % probe)
        return None
    log("[unpack] 命中 %s（第 %d/%d 个，探测 %d 个新文件）"
        % (hit, i, len(metas), probe))

    # ③ 解这一个 meta NCA 的 section0
    outdir = os.path.join(cache_dir, "cnmt_scan", hit)
    sec0 = os.path.join(outdir, "section0")
    found = None
    for root, _d, files in os.walk(outdir):
        if name in files:
            found = os.path.join(root, name)
            break
    if found:
        return found
    if args.force or not os.path.exists(os.path.join(outdir, ".done")):
        # hactool 拼输出路径是 `dir\name` 直接字符串相接：
        #   ① 传正斜杠 → 得到 "a/b\name" 混合分隔符，fopen 失败（静默）；
        #   ② 目标目录不存在时它不建 base 目录，同样写失败。
        # 所以这里统一转成 Windows 反斜杠路径 + 预先 makedirs。
        os.makedirs(sec0, exist_ok=True)
        run_tool([args.hactool, "-k", args.keys, "-x",
                  os.path.join(fw_dir, hit),
                  "--romfsdir=" + winpath(outdir),
                  "--section0dir=" + winpath(sec0)],
                 os.path.join(outdir, "hactool.log"))
        open(os.path.join(outdir, ".done"), "w").close()
    for root, _d, files in os.walk(outdir):
        if name in files:
            return os.path.join(root, name)
    return None


# -------------------------------------------------------- check + locate

def audit_image(fs_path, base_path, sites, args):
    """核心：逐点比对 + 分层重定位。返回 (结果列表, 主导 delta, 票数)。

    每点的判定阶梯：
      L0 同址命中                          → OK
      L1 全代码段精确命中                  → 候选（长模式才可信）
      L2 块漂移：其它点共享的 delta 预测   → 候选
      L3 上下文锚点投票（容忍少量变化）    → 候选
    所有候选统一按「上下文窗口字匹配率」打分，取最优：
      得分 ≥0.95 且显著领先   → MOVED（可直接用）
      ≥min_sim 且显著领先     → FUZZY（落点可信，指令需人工核对）
      ≥min_sim 但与他人同分   → AMBIGUOUS（人工判断）
      其余                    → LOST（需人工 RE）
    """
    new = FsImage(fs_path)
    base = FsImage(base_path) if base_path and os.path.exists(base_path) else None
    code = new.code
    min_sim = args.min_sim

    results = []
    for s in sites:
        cmp_b = s["cmp"]
        r = dict(site=s["site"], name=s["name"], group=s["group"],
                 is_func=s["is_func"], patch_name=s["patch_name"],
                 cmp_len=len(cmp_b) if cmp_b else 0,
                 status="?", new_site=None, delta=None, sim="", method="",
                 hits=[], cands=[], suggest=None, note="", ratio=0.0)
        if not cmp_b:
            r.update(status="NO-CMP", note="fs_codepage.cpp 里没解析到 cmp 字节数组")
            results.append(r)
            continue
        if code[s["site"]:s["site"] + len(cmp_b)] == cmp_b:
            r.update(status="OK", new_site=s["site"], delta=0,
                     method="同址命中", ratio=1.0)
            results.append(r)
            continue
        r["status"] = "PENDING"
        results.append(r)

    # ---- 第一轮线索：全代码段精确命中 -------------------------------
    smap = {s["site"]: s for s in sites}
    for r in results:
        if r["status"] == "PENDING":
            r["hits"] = find_all(code, smap[r["site"]]["cmp"], limit=64)

    # ---- 多轮打分：每轮把已确立点的 delta 加回候选池 ----------------
    # 为什么多轮：有些点（函数体重写、指令全变）窗口匹配很低，但它与相邻补丁点
    # 共享同一漂移量 —— 只有等相邻点先定位成功，这条线索才可用。
    delta_support = {}
    dom_delta, dom_count = None, 0
    for _round in range(4):
        delta_support = {}
        for r in results:
            if r["status"] in ("OK", "MOVED", "FUZZY") and r["delta"]:
                delta_support[r["delta"]] = delta_support.get(r["delta"], 0) + 1
        if delta_support:
            dom_delta, dom_count = max(delta_support.items(), key=lambda kv: kv[1])
            if dom_count < 2:
                dom_delta = None
        else:
            dom_delta, dom_count = None, 0

        changed = False
        for r in results:
            if r["status"] != "PENDING":
                continue
            s = smap[r["site"]]
            cmp_b = s["cmp"]
            win = window_for(r["site"], base) if base else None

            raw = []                                # [(候选偏移, 线索来源)]
            short = len(cmp_b) < 12
            if r["hits"] and (not short or len(r["hits"]) <= 8):
                raw += [(h, "精确") for h in r["hits"]]
            if win:
                win_start, w = win
                raw += [(c[0] + (r["site"] - win_start), "锚点")
                        for c in anchor_locate(code, w)]
            for d in sorted(delta_support, key=lambda k: -delta_support[k])[:3]:
                raw.append((r["site"] + d, "块漂移"))

            scored, seen = [], set()
            for c, src in raw:
                if c in seen or c < 0 or c + len(cmp_b) > len(code):
                    continue
                seen.add(c)
                exact = code[c:c + len(cmp_b)] == cmp_b
                r_raw, r_sem = best_window_ratio(code, base, r["site"], c, exact)
                # 宽窗只作参考信息展示（人工核对时看"整片区域像不像"）
                w_sem = 1.0
                if win:
                    _wr, w_sem = window_ratio(code, win[0], win[1], r["site"], c)
                scored.append(dict(off=c, exact=exact, ratio=r_sem, raw=r_raw,
                                   wide=w_sem, src=src,
                                   sup=delta_support.get(c - r["site"], 0)))
            # 排序：语义匹配率 → **cmp 精确命中** → 漂移票数 → 宽窗。
            # `exact` 必须排在 drift 票之前：落到相邻 4 字节而"看着像"的候选
            # （88% 同分）会输给真正 cmp 精确命中的那个 —— cmp 精确命中才决定
            # `fs_patch_function()` 会不会真的打上补丁。
            scored.sort(key=lambda t: (-t["ratio"], not t["exact"], -t["sup"],
                                       -t["wide"]))
            r["cands"] = scored[:6]
            if not scored:
                continue

            best = scored[0]
            second = scored[1] if len(scored) > 1 else None
            gap = best["ratio"] - (second["ratio"] if second else 0.0)
            # 平局打破：cmp 字节在固件里重复时两个候选会同分同宽窗（例如
            # StringDesc_ToUpper 与另一个同形函数）。此时"该漂移量被多少个
            # 已定位点共享"是可靠的判别依据——整段平移会让大量点同 delta。
            lead = (second is None or gap >= 0.10
                    or (best["sup"] >= 2 and best["sup"] > second["sup"])
                    or (best.get("wide", 0.0) - second.get("wide", 0.0) >= 0.25))

            st = note = None
            if best["ratio"] >= 0.95 and lead:
                st, note = "MOVED", ""
            elif best["ratio"] >= min_sim and lead:
                st, note = "FUZZY", "落点可信但窗口内有指令差异，必须人工核对"
            elif best["sup"] >= 2:
                st, note = "FUZZY", ("窗口差异较大，但该漂移量另有 %d 个已定位点共享，"
                                     "落点很可能正确，务必人工核对" % best["sup"])
            elif best["ratio"] >= min_sim:
                # 多个候选得分接近：**先不冻结**。等下一轮把本批其它点的 delta 收进
                # 候选池后，"该漂移量被多少点印证"往往能把平局打破
                # （cmp 字节在固件里重复时两个候选会同 ratio 同宽窗）。
                continue
            if st is None:
                continue                            # 本轮暂无定论，下一轮再看

            r.update(status=st, new_site=best["off"], delta=best["off"] - r["site"],
                     note=note, ratio=best["ratio"], raw_ratio=best["raw"],
                     wide_ratio=best.get("wide", 0.0),
                     method="%s线索，本点语义匹配 %.0f%%（严格 %.0f%%｜±64 宽窗 %.0f%%）%s"
                     % (best["src"], best["ratio"] * 100, best["raw"] * 100,
                        best.get("wide", 0.0) * 100,
                        "，次优 %.0f%%" % (second["ratio"] * 100) if second else ""),
                     sim="本点语义 %.0f%% / 严格 %.0f%% / 宽窗 %.0f%%"
                         % (best["ratio"] * 100, best["raw"] * 100,
                            best.get("wide", 0.0) * 100))
            r["suggest"] = code[r["new_site"]:r["new_site"] + len(cmp_b)]
            changed = True
        if not changed:
            break

    # ---- 收尾：多轮跑完后仍未定论的点（典型：cmp 字节重复且漂移量无票） ----
    for r in results:
        if r["status"] != "PENDING":
            continue
        if not r["cands"]:
            r.update(status="LOST", note="无候选，需人工 RE", method="无候选")
            continue
        best = r["cands"][0]
        nxt = r["cands"][1]["ratio"] if len(r["cands"]) > 1 else 0.0
        w = best.get("wide", 0.0)
        r["suggest"] = code[best["off"]:best["off"] + r["cmp_len"]]
        if best["ratio"] >= 0.95:
            r.update(status="AMBIGUOUS", new_site=best["off"],
                     delta=best["off"] - r["site"], ratio=best["ratio"],
                     wide_ratio=w,
                     sim="本点语义 %.0f%% / 宽窗 %.0f%%" % (best["ratio"] * 100, w * 100),
                     method="%s线索，多个候选同分（次优 %.0f%%）"
                            % (best["src"], nxt * 100),
                     note="cmp 字节在固件里重复，多个候选同分；按反汇编逐条核对")
        elif best["ratio"] >= min_sim:
            r.update(status="FUZZY", new_site=best["off"],
                     delta=best["off"] - r["site"], ratio=best["ratio"],
                     wide_ratio=w,
                     sim="本点语义 %.0f%% / 宽窗 %.0f%%" % (best["ratio"] * 100, w * 100),
                     method="%s线索，本点语义 %.0f%%" % (best["src"], best["ratio"] * 100),
                     note="落点可信但窗口内有指令差异，必须人工核对")
        else:
            r.update(status="LOST", new_site=best["off"],
                     delta=best["off"] - r["site"], ratio=best["ratio"],
                     wide_ratio=w,
                     sim="本点语义 %.0f%%" % (best["ratio"] * 100),
                     method="最佳候选仅 %.0f%%（%s线索）"
                            % (best["ratio"] * 100, best["src"]),
                     note="置信度不足，需人工 RE")

    # ---- 硬指标：cmp 指纹是否在候选位置精确命中 --------------------
    # 换了 pattern 驱动之后，运行期**不再逐字节比对 cmp**：判据是「模板唯一命中 + cond 成立」
    # （由构建期守卫与 _audit/_verify_cpp_table.py 把守）。所以这里的 `cmp 精确命中` 是
    # **重定位健康度指标**，不是安全闸门 —— 它只说明"新位置确实还是同一段代码"。
    for r in results:
        n = r["cmp_len"]
        src = (smap.get(r["site"]) or {}).get("cmp") or b""
        if r["new_site"] is None or not n or len(src) != n:
            r["cmp_exact"] = None
        else:
            r["cmp_exact"] = (code[r["new_site"]:r["new_site"] + n] == src)

    return results, dom_delta, dom_count


# ------------------------------------------------------------------ 报告

def hex_bytes(b, per_line=16):
    if not b:
        return "-"
    return " ".join("0x%02x" % x for x in b)


def disasm_line(word, addr, note=""):
    md = capstone_md()
    if md is None:
        return "0x%08X%s" % (word, note)
    for ins in md.disasm(struct.pack("<I", word), addr):
        return "%s %s%s" % (ins.mnemonic, ins.op_str, note)
    return "0x%08X%s" % (word, note)


_MD = None
_MD_TRIED = False


def capstone_md():
    global _MD, _MD_TRIED
    if not _MD_TRIED:
        _MD_TRIED = True
        try:
            from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
            _MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        except ImportError:
            _MD = None
    return _MD


def write_report(path, fs_path, base_path, sites, results, dom_delta, dom_count, args):
    n_ok = sum(1 for r in results if r["status"] == "OK")
    n_moved = sum(1 for r in results if r["status"] == "MOVED")
    n_fuzzy = sum(1 for r in results if r["status"] == "FUZZY")
    n_amb = sum(1 for r in results if r["status"] == "AMBIGUOUS")
    n_lost = sum(1 for r in results if r["status"] in ("LOST", "NO-CMP"))
    total = len(results)

    L = []
    L.append("# fs 编码补丁适配审计报告")
    L.append("")
    L.append("- 目标 fs：`%s`" % fs_path)
    if base_path:
        L.append("- 比对基线：`%s`（本工程 16 处补丁的推导来源）" % base_path)
    L.append("- 补丁来源：`%s`（%d 个补丁点）" % (os.path.basename(args.main), total))
    L.append("- 结论：**同址可用 %d｜已漂移可用 %d｜需人工确认 %d｜多命中 %d｜失效 %d**"
             % (n_ok, n_moved, n_fuzzy, n_amb, n_lost))
    if dom_delta is not None and dom_count >= 2:
        L.append("- 最大共同漂移：**%+d 字节**（%d 个点共享）；注意同固件内各区段\n"
                 "  漂移量可以不同（函数增删/重排），所以本工具逐点定位而不是整体平移"
                 % (dom_delta, dom_count))
    L.append("- 反汇编地址按分析基址 `0x7100000000` 给出；**运行时 ASLR 随机化**，"
             "更新 fs_codepage.cpp 时必须用相对偏移")
    L.append("")
    if n_lost == 0 and n_amb == 0:
        L.append("> ✅ 全部补丁点都能在新固件上找到落点，但没有人工确认前不要直接上线："
                 "`FUZZY` 点必须核对指令语义与寄存器。")
    else:
        L.append("> ⚠️ 有 %d 个点自动定位失败 / %d 个点多命中，需人工 RE 后更新 `fs_codepage.cpp` 偏移表。"
                 % (n_lost, n_amb))
    L.append("")

    L.append("## 1. 逐点结果")
    L.append("")
    L.append("| # | 补丁点 | 组 | 类型 | 旧偏移 | 新偏移 | delta | 状态 | cmp | 判定依据 | cmp 长度 |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(results, 1):
        old = "0x%X" % r["site"]
        new = "0x%X" % r["new_site"] if r["new_site"] is not None else "-"
        delta = "%+d" % r["delta"] if r["delta"] is not None else "-"
        kind = "函数替换" if r["is_func"] else "指令级"
        ce = r.get("cmp_exact")
        ce = "命中" if ce else ("—" if ce is None else "**不匹配**")
        L.append("| %d | `%s` | %s | %s | %s | %s | %s | **%s** | %s | %s | %d |"
                 % (i, r["name"], r["group"], kind, old, new, delta, r["status"],
                    ce, r["method"], r["cmp_len"]))
    L.append("")

    L.append("## 2. 需要人工处理的点")
    L.append("")
    need = [r for r in results
            if r["status"] in ("LOST", "NO-CMP", "AMBIGUOUS", "FUZZY")]
    if not need:
        L.append("无。")
    else:
        for r in need:
            s = next(x for x in sites if x["site"] == r["site"])
            L.append("### `%s` @0x%X（%s）" % (r["name"], r["site"], r["status"]))
            L.append("")
            L.append("- 组：%s；类型：%s"
                     % (r["group"], "函数替换" if r["is_func"] else "指令级"))
            if r["is_func"]:
                hole = FUNC_HOLES.get(r["site"])
                L.append("- 洞约束：%s" % (("0x%X（%s）—— **换版本必须重推**"
                                           % (hole["hole"], hole["note"])) if hole
                                          else "未知，需重推"))
            if r["new_site"] is not None:
                L.append("- 候选新偏移：**0x%X**（delta %+d），%s"
                         % (r["new_site"], r["delta"], r["method"]))
            else:
                L.append("- 无候选：%s" % r["method"])
            if r["sim"]:
                L.append("- 窗口匹配：%s" % r["sim"])
            if r["cands"]:
                L.append("- 候选：%s" % ", ".join(
                    "0x%X（%.0f%%%s｜%s）" % (c["off"], c["ratio"] * 100,
                                              "，精确命中" if c["exact"] else "", c["src"])
                    for c in r["cands"][:5]))
            if r["note"]:
                L.append("- 备注：%s" % r["note"])
            # 新旧反汇编对照
            old_b = s["cmp"] or b""
            new_b = r["suggest"] or (b"")
            L.append("")
            L.append("```")
            L.append("旧 0x%X:" % r["site"])
            for i in range(0, len(old_b) - 3, 4):
                w = struct.unpack_from("<I", old_b, i)[0]
                mark = ""
                if not r["is_func"] and s["patch"] and i + 4 <= len(s["patch"]):
                    pw = struct.unpack_from("<I", s["patch"], i)[0]
                    if pw != w:
                        mark = "   <- patch 改为 %s" \
                            % disasm_line(pw, IMAGE_BASE + r["site"] + i)
                L.append("  +0x%02X  %08X  %s%s"
                         % (i, w, disasm_line(w, IMAGE_BASE + r["site"] + i), mark))
            if r["new_site"] is not None and new_b:
                L.append("新 0x%X:" % r["new_site"])
                for i in range(0, len(new_b) - 3, 4):
                    w = struct.unpack_from("<I", new_b, i)[0]
                    same = (i + 4 <= len(old_b)
                            and struct.unpack_from("<I", old_b, i)[0] == w)
                    L.append("  +0x%02X  %08X  %s%s"
                             % (i, w, disasm_line(w, IMAGE_BASE + r["new_site"] + i),
                                "" if same else "   <- 与旧版不同"))
            L.append("```")
            L.append("")

    L.append("## 3. 新旧偏移对照表（可直接用于更新 fs_codepage.cpp）")
    L.append("")
    L.append("```c")
    L.append("// 目标固件 fs：%s" % os.path.basename(fs_path))
    if dom_delta is not None and dom_count >= 2:
        L.append("// 主导块漂移 %+d 字节" % dom_delta)
    L.append("")
    for r in results:
        if r["new_site"] is None:
            L.append("// TODO  %-34s 旧 0x%-8X → 需人工定位 (%s)"
                     % (r["name"], r["site"], r["status"]))
        elif r["new_site"] == r["site"]:
            L.append("// ok    %-34s 0x%X" % (r["name"], r["site"]))
        else:
            L.append("// move  %-34s 0x%X → 0x%X  (%+d, %s)"
                     % (r["name"], r["site"], r["new_site"], r["delta"], r["status"]))
    L.append("```")
    L.append("")
    L.append("## 4. 下一步")
    L.append("")
    L.append("1. 对每个 `FUZZY`/`AMBIGUOUS` 点人工核对第 2 节的指令对照，"
             "确认寄存器与语义没变；")
    L.append("2. 对函数替换点，用新偏移重推「洞」（到下一个存活函数的距离），"
             "并更新 `sysmod/tools/check_patch_sizes.py` 的 `FUNCTIONS` 表；")
    L.append("3. 把确认后的新偏移 + 新 cmp 写回 `sysmod/src/fs_codepage.cpp`，"
             "跑 `make`（构建期守卫会逐点复验）；")
    L.append("4. 上机前用 `[options] fs_codepage=0` 保底（条目已无 stage 分级，"
             "只有「整份生效 / 整份跳过」两态）。")
    L.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


# ------------------------------------------------------------------ 主流程

def cmd_unpack(args):
    unpack(args)


def cmd_check(args):
    do_audit(args, write=False)


def cmd_audit(args):
    do_audit(args, write=True)


def do_audit(args, write):
    main_cpp = os.path.abspath(args.main)
    if not os.path.exists(main_cpp):
        sys.exit("error: 找不到 %s（用 --main 指定）" % main_cpp)
    fs_path = args.fs
    work = os.path.abspath(args.work) if args.work else None
    if fs_path is None:
        if not work:
            sys.exit("error: 需要 --fs <FS.kip1> 或 --work <解包目录> 之一")
        fs_path = os.path.join(work, "FS_unc.kip1")
    return audit_at(args, fs_path, work, write)


def audit_at(args, fs_path, work, write=True, report_name="report.md",
             quiet=False, label=""):
    """对一个 fs 二进制做逐点比对 + 重定位。返回 (results, counts)。"""
    main_cpp = os.path.abspath(args.main)
    sites = parse_sites(main_cpp)
    if not os.path.exists(fs_path):
        sys.exit("error: 找不到 fs 二进制 %s" % fs_path)

    base_path = args.base_fs
    if not quiet:
        log("审计 %s" % fs_path)
        log("基线 %s" % base_path)
        log("补丁点 %d 个（来自 %s）" % (len(sites), main_cpp))

    results, dom_delta, dom_count = audit_image(fs_path, base_path, sites, args)

    n_ok = sum(1 for r in results if r["status"] == "OK")
    n_moved = sum(1 for r in results if r["status"] == "MOVED")
    n_fuzzy = sum(1 for r in results if r["status"] == "FUZZY")
    n_amb = sum(1 for r in results if r["status"] == "AMBIGUOUS")
    n_lost = sum(1 for r in results if r["status"] in ("LOST", "NO-CMP"))
    n_exact = sum(1 for r in results if r.get("cmp_exact"))
    counts = dict(total=len(results), ok=n_ok, moved=n_moved, fuzzy=n_fuzzy,
                  ambiguous=n_amb, lost=n_lost, cmp_exact=n_exact,
                  dom_delta=dom_delta, dom_count=dom_count)
    if not quiet:
        log("")
        log("结果：同址 %d ｜ 漂移 %d ｜ 需确认 %d ｜ 多命中 %d ｜ 失效 %d"
            % (n_ok, n_moved, n_fuzzy, n_amb, n_lost))
        log("cmp 精确命中 %d/%d —— 重定位健康度（运行期判据是模板唯一命中 + cond）"
            % (n_exact, len(results)))
        if dom_delta is not None and dom_count >= 2:
            log("主导块漂移 %+d 字节（%d 点共享）" % (dom_delta, dom_count))
        log("")
        log("%-28s %-10s %-10s %-8s %-9s %s"
            % ("补丁点", "旧", "新", "delta", "状态", "cmp"))
        for r in results:
            new = "0x%X" % r["new_site"] if r["new_site"] is not None else "-"
            delta = "%+d" % r["delta"] if r["delta"] is not None else "-"
            ce = r.get("cmp_exact")
            ce = "命中" if ce else ("-" if ce is None else "**不匹配**")
            log("%-28s 0x%-8X %-10s %-8s %-9s %s"
                % (r["name"], r["site"], new, delta, r["status"], ce))

    if write:
        outdir = work or os.path.dirname(os.path.abspath(fs_path))
        os.makedirs(outdir, exist_ok=True)
        out = os.path.join(outdir, report_name)
        write_report(out, fs_path, base_path, sites, results,
                     dom_delta, dom_count, args)
        if not quiet:
            log("")
            log("报告 → %s" % out)
    return results, counts


def _word_at(buf, off):
    if off < 0 or off + 4 > len(buf):
        return None
    return struct.unpack_from("<I", buf, off)[0]


def verify_projected_hole(code, base, site, new_site, hole):
    """边界定位不到时，校验"把旧洞原样投影到新固件"是否成立。

    洞的边界就是下一个函数的入口，或者紧跟一段 udf/nop 填充。这两个特征在
    新固件里应该仍然成立：
      ① 边界处首指令与基线相同（PC 相对位移允许不同）；
      ② 若基线边界紧跟在填充之后，新固件边界前也应是填充。
    """
    b = _word_at(base.code, site + hole)
    n = _word_at(code, new_site + hole)
    if b is None or n is None:
        return False, "越界"
    if b == n or norm_word(b) == norm_word(n):
        return True, "边界首指令一致"
    bp = _word_at(base.code, site + hole - 4)
    np_ = _word_at(code, new_site + hole - 4)
    if bp in (UDF_W, NOP_W) and np_ in (UDF_W, NOP_W):
        return True, "边界前缀填充一致"
    return False, "边界首指令与填充特征都不符"


def compute_holes(new, base, all_sites, results, syms):
    """重推每个「整函数替换」补丁点在新 fs 里的洞（可用空间）。

    做法：用锚点在新镜像里定位洞的**边界地址**（相邻函数入口/填充末尾），
    新洞 = 新边界 − 新补丁点偏移；定位不到时退回「旧洞投影 + 边界特征校验」。
    返回 [{name, site, new_site, hole, old_hole, fsize, margin, verdict, note}]。
    """
    rmap = {r["site"]: r for r in results}
    out = []
    for s in [x for x in all_sites if x["is_func"]]:
        r = rmap.get(s["site"]) or {}
        h = FUNC_HOLES.get(s["site"]) or {}
        oh = h.get("hole")
        fsize = syms.get(h.get("symbol", ""), (0, 0))[1]
        rec = dict(name=s["name"], site=s["site"], new_site=r.get("new_site"),
                   hole=None, old_hole=oh, fsize=fsize, margin=None,
                   verdict="", note="")
        if rec["new_site"] is None:
            rec["verdict"] = "未定位（补丁点重定位失败）"
            out.append(rec)
            continue
        nb = (locate_neighbor(new.code, base, h["boundary"])
              if h.get("boundary") else None)
        nh = (nb - rec["new_site"]) if nb is not None else None
        note = ""
        # 健全性检查：洞不会无故暴涨。边界锚点定位到错误位置时（例如新固件里
        # 该边界函数被删/重排），nh 会变成一个荒谬的大数（实测出现过 0xB7C10）。
        # 超过「旧洞 + 0x800」就判为不可信，退回投影校验/启发式估算。
        if nh is not None and oh and nh > oh + 0x800:
            note = "边界锚点定位到 0x%X 处（洞 0x%X 远大于旧洞，判为不可信）" % (nb, nh)
            nh = None
        if nh is None or nh <= 0:
            if oh:
                okp, why = verify_projected_hole(new.code, base, s["site"],
                                                 rec["new_site"], oh)
            else:
                okp, why = False, "无洞表"
            if okp:
                nh = oh
                note += " " + ("旧洞投影校验通过（%s）" % why)
            else:
                nh = estimate_hole(new.code, rec["new_site"]) or 0
                note += " " + ("边界未定位且投影校验失败（%s）⇒ 洞为启发式估算，"
                               "**必须人工核**" % why)
        # 安全检查：新洞区间内不能再落进其它补丁点
        inside = [x["name"] for x in all_sites
                  if rec["new_site"] < x["site"]
                  + ((rmap.get(x["site"]) or {}).get("delta") or 0)
                  < rec["new_site"] + nh]
        if inside:
            note += " ⚠ 洞内含其它补丁点：%s" % ", ".join(inside)
        rec["hole"] = nh
        if fsize:
            rec["margin"] = nh - fsize
            rec["verdict"] = ("够用" if nh >= fsize
                              else "**不足**：需 0x%X 只有 0x%X ⇒ 改写实现"
                                   % (fsize, nh))
        else:
            rec["verdict"] = "读不到函数尺寸（跑 `make` 自查）"
        rec["note"] = note
        out.append(rec)
    return out


def cmd_holes(args):
    """重推函数替换点的「洞」（可用空间）。

    洞表来自 Ghidra 的函数边界，换固件必须重推，否则构建守卫
    (sysmod/tools/check_patch_sizes.py) 的 FUNCTIONS 表就是错的。
    做法：先用锚点在新镜像里定位洞的**边界地址**（相邻函数入口），
    新洞 = 新边界 − 新补丁点；再读 sys-patch.elf 的符号尺寸算余量。
    """
    main_cpp = os.path.abspath(args.main)
    if not os.path.exists(main_cpp):
        sys.exit("error: 找不到 %s（用 --main 指定）" % main_cpp)
    all_sites = parse_sites(main_cpp)
    sites = [s for s in all_sites if s["is_func"]]
    base = FsImage(args.base_fs)
    syms = elf_symbol_sizes(args.elf)

    log("① 基线自检 —— 洞表 vs 实际边界（%s）" % os.path.basename(args.base_fs))
    log("%-26s %-9s %-9s %-9s %s" % ("补丁点", "旧偏移", "边界", "洞表", "自检"))
    bad = 0
    for s in sites:
        h = FUNC_HOLES.get(s["site"])
        if not h:
            log("%-26s 0x%-7X %-9s %-9s %s" % (s["name"], s["site"], "-", "-", "（无洞表）"))
            continue
        real = h["boundary"] - s["site"]
        good = (real == h["hole"])
        bad += 0 if good else 1
        log("%-26s 0x%-7X 0x%-7X 0x%-7X %s"
            % (s["name"], s["site"], h["boundary"], h["hole"],
               "一致" if good else "**不一致：边界−偏移=0x%X**" % real))
    if bad:
        log("   ⚠ 洞表与边界字段对不上，先修 FUNC_HOLES 再继续。")

    fs_path = args.fs
    if fs_path is None:
        if not args.work:
            log("\n（未指定 --fs / --work，跳过新固件部分）")
            return
        fs_path = os.path.join(os.path.abspath(args.work), "FS_unc.kip1")
    if not os.path.exists(fs_path):
        sys.exit("error: 找不到 fs 二进制 %s" % fs_path)
    new = FsImage(fs_path)
    results, _dd, _dc = audit_image(fs_path, args.base_fs, all_sites, args)

    log("")
    log("② 新固件 —— %s" % fs_path)
    log("%-26s %-9s %-9s %-9s %-9s %-9s %s"
        % ("补丁点", "新偏移", "新洞", "旧洞", "函数尺寸", "余量", "判定"))
    for rec in compute_holes(new, base, all_sites, results, syms):
        fmt = ("%-26s %-9s %-9s %-9s %-9s %-9s %s"
               % (rec["name"],
                  ("0x%X" % rec["new_site"]) if rec["new_site"] is not None else "-",
                  ("0x%X" % rec["hole"]) if rec["hole"] else "-",
                  ("0x%X" % rec["old_hole"]) if rec["old_hole"] else "-",
                  ("0x%X" % rec["fsize"]) if rec["fsize"] else "-",
                  ("%+d" % rec["margin"]) if rec["margin"] is not None else "-",
                  rec["verdict"]))
        if rec["note"]:
            fmt += " " + rec["note"]
        log(fmt)

    log("")
    log("把上面「新偏移 / 新洞」写回 fs_codepage.cpp 与 check_patch_sizes.py 的 FUNCTIONS 表，")
    log("然后跑 `make`（构建期守卫会逐点复验尺寸、空间与每条机器码）。")


def firmware_items(fw_root):
    """列出目录里的固件来源：*.zip 与「含 .nca 的子目录」。"""
    items = []
    for name in sorted(os.listdir(fw_root)):
        p = os.path.join(fw_root, name)
        if os.path.isfile(p) and name.lower().endswith(".zip"):
            items.append((re.sub(r"\.zip$", "", name, flags=re.I), p))
        elif os.path.isdir(p):
            try:
                if any(f.endswith(".nca") for f in os.listdir(p)):
                    items.append((name, p))
            except OSError:
                pass
    return items


def verdict_of(c):
    """把统计量翻成一句可执行的结论。"""
    if c["total"] == 0:
        return "无补丁点"
    all_cmp = (c["cmp_exact"] == c["total"])
    if c["lost"] == 0 and c["ambiguous"] == 0 and c["fuzzy"] == 0:
        if c["moved"] == 0 and all_cmp:
            return "**可直接沿用**（%d 点全部同址、cmp 精确命中）" % c["total"]
        return ("**可用：换新偏移即可**（%d 点漂移；cmp %d/%d 精确命中）"
                % (c["moved"], c["cmp_exact"], c["total"]))
    if c["lost"] == 0:
        return ("**大概率可用，需人工确认**：%d 点自动定位但窗口内有差异；cmp %d/%d"
                % (c["fuzzy"] + c["ambiguous"], c["cmp_exact"], c["total"]))
    return ("**需人工 RE**：%d/%d 点自动定位失败（cmp %d/%d 精确命中）"
            % (c["lost"], c["total"], c["cmp_exact"], c["total"]))


def merge_rows(out_root, new_rows):
    """把本轮结果合并进已有 summary.json，保留未参与本轮的其他行。

    补跑单版本（例如拿到新 prod.keys 后只重验 22.x/23.0.0）时必须用，否则
    write_batch_summary() 会把整张总表覆盖成本轮这几行。
    """
    import json as _json
    p = os.path.join(out_root, "summary.json")
    if not os.path.exists(p):
        return new_rows
    try:
        with open(p, encoding="utf-8") as f:
            old = _json.load(f)
    except (OSError, ValueError) as e:                       # noqa: BLE001
        log("（读不了已有 summary.json：%s；本轮结果单独成表）" % e)
        return new_rows

    def key(r):
        return (r.get("firmware", ""), r.get("tag", ""))

    fresh = {key(r): r for r in new_rows}
    merged, seen = [], set()
    for r in old:                      # 保持原顺序，原位替换本轮重跑的条目
        k = key(r)
        if k in fresh:
            merged.append(fresh[k])
            seen.add(k)
        else:
            merged.append(r)
    for k in sorted(set(fresh) - seen):  # 旧表里没有的按 (固件, 变体) 追加
        merged.append(fresh[k])
    log("合并总表：旧 %d 行 + 本轮 %d 行 → %d 行" % (len(old), len(new_rows), len(merged)))
    return merged


def cmd_batch(args):
    """遍历目录里所有固件包，逐个解包 + 审计，产出每版本报告与总表。

    每个固件跑 `<titles>` 里的全部变体（默认 fat32 0819 + exfat 081b ——
    这两个 title 的 FS 是**两个不同的二进制**，必须分别验证）。
    """
    fw_root = os.path.abspath(args.input)
    if not os.path.isdir(fw_root):
        sys.exit("error: batch 需要传入固件目录（含 *.zip 或已解包子目录）")
    out_root = os.path.abspath(args.work
                               or os.path.join(SCRIPT_DIR, "audit_out"))
    os.makedirs(out_root, exist_ok=True)
    titles = [t.strip() for t in args.titles.split(",") if t.strip()]

    items = firmware_items(fw_root)
    if not items:
        sys.exit("error: %s 下既没有 *.zip 也没有含 .nca 的子目录" % fw_root)

    only = [s.strip().lower() for s in (args.only or "").split(",") if s.strip()]
    if only:
        picked = [(n, s) for (n, s) in items if any(k in n.lower() for k in only)]
        if not picked:
            sys.exit("error: --only %r 没匹配到任何固件来源（共 %d 个）"
                     % (args.only, len(items)))
        log("--only 过滤：%d → %d 个来源（%s）"
            % (len(items), len(picked), ", ".join(n for n, _ in picked)))
        items = picked

    log("批量审计 %d 个固件来源；标题 %s" % (len(items), ", ".join(titles)))
    log("输出根目录 %s" % out_root)

    main_cpp = os.path.abspath(args.main)
    if not os.path.exists(main_cpp):
        sys.exit("error: 找不到 fs_codepage.cpp %s（用 --main 或 FS_TABLE_CXX 指定）" % main_cpp)
    all_sites = parse_sites(main_cpp)
    base_img = FsImage(args.base_fs)
    try:
        syms = elf_symbol_sizes(args.elf)
    except OSError:
        syms = {}
    if not syms:
        log("（读不到 %s 的符号表，洞余量一列留空；在仓库内跑 `make` 后即有）"
            % os.path.basename(args.elf))

    rows = []
    for idx, (name, src) in enumerate(items, 1):
        log("")
        log("=" * 74)
        log("[%d/%d] %s" % (idx, len(items), name))
        log("=" * 74)
        fw_work = os.path.join(out_root, name)
        shared = os.path.join(fw_work, "_shared")
        for title in titles:
            tag = title[-4:]
            tw = os.path.join(fw_work, tag)
            log("")
            log("--- %s / %s ---" % (name, tag))
            rec = dict(firmware=name, title=title, tag=tag, counts=None,
                       fs_sha1="", fs_size=0, text_size=0, holes=[], error="")
            try:
                m = unpack_fs(args, src, tw, title, shared)
                fs_path = m.get("fs_unc")
                if not fs_path or not os.path.exists(fs_path):
                    raise RuntimeError("未产出 FS_unc.kip1")
                rec.update(fs_sha1=m.get("sha1", ""), fs_size=m.get("fs_size", 0),
                           text_size=m.get("text_size", 0))
                results, counts = audit_at(args, fs_path, tw, write=True,
                                           label="%s/%s" % (name, tag))
                rec["counts"] = counts
                rec["holes"] = compute_holes(FsImage(fs_path), base_img,
                                             all_sites, results, syms)
            except SystemExit as e:
                rec["error"] = str(e)
                log("[!] %s / %s 失败：%s" % (name, tag, e))
            except Exception as e:                      # noqa: BLE001
                rec["error"] = "%s: %s" % (type(e).__name__, e)
                log("[!] %s / %s 异常：%s" % (name, tag, rec["error"]))
            rows.append(rec)

    if getattr(args, "merge", False):
        rows = merge_rows(out_root, rows)
    write_batch_summary(out_root, rows, titles, main_cpp, args)
    log("")
    log("总表 → %s" % os.path.join(out_root, "SUMMARY.md"))
    return rows


def write_batch_summary(out_root, rows, titles, main_cpp, args):
    """写 SUMMARY.md（人读）+ summary.json（机读）。"""
    import json as _json
    L = []
    L.append("# 固件 × fs 编码补丁 适配总表")
    L.append("")
    L.append("- 补丁表来源：`%s`（%d 个补丁点）"
             % (main_cpp, len(parse_sites(main_cpp))))
    L.append("- 比对基线：`%s`" % args.base_fs)
    L.append("- 每个固件分别验证 **fat32(0100000000000819)** 与 **exfat(010000000000081b)**"
             " 两个 FS 变体（它们是两个不同的二进制）")
    L.append("- 判定口径：`cmp 精确命中` = 候选位置与基线的 cmp 指纹一致（重定位健康度）；"
             "`失效` = 自动重定位也找不到")
    L.append("")
    L.append("| 固件 | 变体 | cmp 精确命中 | 同址 | 漂移 | 需确认 | 多命中 | 失效 | 结论 |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        c = r["counts"]
        tag = "exfat(081b)" if r["tag"] == "081b" else (
            "fat32(0819)" if r["tag"] == "0819" else r["tag"])
        if r["error"]:
            L.append("| %s | %s | - | - | - | - | - | - | **解包失败**：%s |"
                     % (r["firmware"], tag, r["error"].replace("|", "/")))
            continue
        L.append("| %s | %s | %d/%d | %d | %d | %d | %d | %d | %s |"
                 % (r["firmware"], tag, c["cmp_exact"], c["total"], c["ok"],
                    c["moved"], c["fuzzy"], c["ambiguous"], c["lost"],
                    verdict_of(c)))
    L.append("")
    L.append("## 函数替换点的洞（可用空间）")
    L.append("")
    L.append("| 固件 | 变体 | %s |" % " | ".join(
        "%s 新洞/余量" % s for s in [h["name"] for h in rows[0]["holes"]]
    ) if rows and rows[0]["holes"] else "| 固件 | 变体 | 洞 |")
    L.append("|---|---|" + "---|" * (len(rows[0]["holes"]) if rows and rows[0]["holes"] else 1))
    for r in rows:
        if r["error"] or not r["holes"]:
            continue
        tag = "exfat(081b)" if r["tag"] == "081b" else (
            "fat32(0819)" if r["tag"] == "0819" else r["tag"])
        cells = []
        for h in r["holes"]:
            if h["hole"] is None:
                cells.append("未定位")
            elif h["margin"] is None:
                cells.append("0x%X" % h["hole"])
            else:
                cells.append("0x%X (%+d)" % (h["hole"], h["margin"]))
        L.append("| %s | %s | %s |" % (r["firmware"], tag, " | ".join(cells)))
    L.append("")

    with open(os.path.join(out_root, "SUMMARY.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    with open(os.path.join(out_root, "summary.json"), "w", encoding="utf-8") as f:
        _json.dump([{k: v for k, v in r.items()} for r in rows], f,
                   indent=2, ensure_ascii=False)


def main():
    # 公共参数**只注册在子 parser 上**。曾把 common 同时挂到主 parser，以为
    # `--work x batch .` 与 `batch . --work x` 都能用——实测前者会被子 parser 的
    # 同名默认值静默覆盖（argparse 会把 subnamespace 的**全部**属性 setattr 回来，
    # 包括 default），结果是 --work 丢失、产物跑到 audit_out\ 且不报错。
    # 现在主 parser 不认这些参数，写错位置会直接报 unrecognized arguments。
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--work", help="工作目录（解包产物与报告都放这里）")
    common.add_argument("--fs", help="直接指定 fs 二进制（跳过解包）")
    common.add_argument("--base-fs", default=BASE_FS,
                        help="比对基线 fs（默认 19.exfat.FS.kip1）")
    common.add_argument("--main", default=MAIN_CPP, help="fs 补丁表源码路径（默认 sysmod/src/fs_codepage.cpp）")
    common.add_argument("--elf", default=ELF_PATH,
                        help="sys-patch.elf（holes 用，读替换函数尺寸）")
    common.add_argument("--hactool", default=HACTOOL)
    common.add_argument("--nstool", default=NSTOOL)
    common.add_argument("--keys", default=KEYS)
    common.add_argument("--title", default=BOOT_TITLE,
                        help="BootImagePackage title id（默认 0819）")
    common.add_argument("--force", action="store_true", help="忽略缓存，重做解包")
    common.add_argument("--min-sim", type=float, default=0.6,
                        help="模糊定位接受的最小窗口字匹配率（默认 0.6）")

    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("unpack", parents=[common], help="解包固件出 FS_unc.kip1")
    p.add_argument("input", help="固件 zip / 含 .nca 的目录 / cnmt 文件")
    sub.add_parser("check", parents=[common],
                   help="只看补丁有效性（打印表格）")
    sub.add_parser("audit", parents=[common],
                   help="检查 + 重定位 + 写报告")
    p = sub.add_parser("all", parents=[common], help="unpack + audit")
    p.add_argument("input", help="固件 zip / 含 .nca 的目录")
    sub.add_parser("holes", parents=[common],
                   help="重推各函数替换点在新 fs 里的「洞」（可用空间）")
    p = sub.add_parser("batch", parents=[common],
                       help="遍历目录里所有固件包，逐个解包+审计并出总表")
    p.add_argument("input", help="存放固件 *.zip（或已解包子目录）的目录")
    p.add_argument("--titles", default="0100000000000819,010000000000081b",
                   help="要验证的 BootImagePackage title 列表（逗号分隔）")
    p.add_argument("--only",
                   help="只跑名称含这些子串的固件（逗号分隔、忽略大小写），"
                        "例如 --only 22.,23.0.0")
    p.add_argument("--merge", action="store_true",
                   help="本轮结果合并进已有 summary.json / SUMMARY.md；"
                        "补跑单个版本时必须加，否则总表只剩本轮这几行")

    args = ap.parse_args()

    # 默认工作目录：<工具目录>/.audit/<输入名>（避免污染仓库根）
    if args.cmd in ("unpack", "all") and not args.work:
        name = os.path.basename(os.path.abspath(args.input).rstrip("\\/"))
        name = re.sub(r"\.(zip|nca|cnmt)$", "", name, flags=re.I) or "fw"
        args.work = os.path.join(SCRIPT_DIR, ".audit", name)

    if args.cmd == "unpack":
        unpack(args)
    elif args.cmd == "check":
        do_audit(args, write=False)
    elif args.cmd == "audit":
        do_audit(args, write=True)
    elif args.cmd == "holes":
        cmd_holes(args)
    elif args.cmd == "batch":
        cmd_batch(args)
    else:                                   # all
        unpack(args)
        args.fs = os.path.join(args.work, "FS_unc.kip1")
        do_audit(args, write=True)


if __name__ == "__main__":
    main()
