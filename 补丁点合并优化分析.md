# fs 指令补丁点 —— 设计现状与决策台账

> **本文回答三件事**：现在长什么样、每个方案当初怎么定的现在什么状态、哪些约束不能碰。
>
> | 想了解 | 去读 |
> |---|---|
> | 补丁**怎么实现**（逐函数、逐条目、守卫、排障） | **`fs_encode_fix/re_utf8_patch_final.md`** ← 权威 |
> | 七个整函数替换的**功能合理性**（Ghidra 复核） | `fs_encode_fix/re_整函数替换功能评估.md` |
> | **为什么**这么决策（2026-09-18~20 的时间线论证与实施记录） | `fs_encode_fix/补丁点合并优化分析·演进史.md` |
> | 全部文档的层级与定位 | `fs_encode_fix/README.md` |
>
> **编号约定**：本文**不给章节编号**。全项目里裸写的 `§13`/`§19` 之类**一律指演进史**——
> 它保留了 2026-09-18~19 原始节号（外部文档按 § 引用它），而本文是后来收敛出来的摘要。
>
> 本文曾是一份按时间追加的研究日志（原 §0–§19）。**它的结论会被后文推翻**（原 §9 说 M6 不做 /
> 原 §13 说做了；原 §17 说不做 B / 原 §18 说做了），必须通读全篇才知道现状——因此拆成：
> 本文只留**收敛后的现状与台账**，原始论证全部搬进**演进史**。

---

## 一句话结论

**「零散」的不是补丁的数量，而是补丁的组织维度。** 40 条条目按「站点」扁平排列，于是同一个函数里的
15 个点被拆成 19 条，又因编译期写法差异再分裂出版本族。

分层结论：

| 层次 | 能否压缩 | 现状 |
|---|---|---|
| **改写条数** | ✗ 不可压缩 | 每个站点是一次独立改写，由语义决定 |
| **定位方式** | ✓✓ 可彻底换掉 | 已从「逐站字节模板」升级为**两级表 + 整函数替换**；版本族靠「族内互斥」而非删条目解决（见决策台账 · M2/O6） |
| **扫描 / 写入次数** | ✓✓ 已大幅压缩 | 谓词位图 + P3 三项结构优化（见当前形态 · 扫描结构） |

---

## 当前形态（权威快照）

全部在 `sysmod/src/fs_codepage.cpp`（API `fs_codepage.h`，共享类型 `patch_types.h`）。
**全 pattern 驱动、无硬编码 fs 偏移**——定位靠字节模板，改写靠语义等价规则，寄存器/地址/宽度
**从命中点继承**，因此换固件不需要新偏移。

### 表的规模与结构

| 项 | 值 |
|---|---|
| 一级表 | `fs_fn_groups[12]` —— 每个被改写的 fs 函数一组，切出 pattern / blob 的子区间 |
| 二级表 | `fs_inst_patches[15]`（指令改写）+ `fs_blob_patches[16]`（整函数体替换）= **31 条** |
| 谓词 | `FS_PRED_COUNT = 5`；唯一定义处是 X 宏 `FS_PRED_LIST`，`fs_preds[]` / `fs_pred_mask()` 均由它展开 |
| 整函数替换 | **7** 个（`Utf16ToUtf8` `Utf8ToUtf16` `IsOemMbChar` `StrUnicode2Oem` `StrDescToUpper` `WideCharCompare` `FatGetNextChar`） |
| 覆盖固件 | **26 份变体**（16.1.0–22.5.0 共 22 + 14.1.2 / 15.0.1 各 2） |
| 每份固件写内存 | **14** 次（族内互斥 ⇒ 每点只落地 1 条变体） |
| 扫描参数 | `READ_BUFFER_SIZE = 0x1000`，`FS_OVERLAP = 0x50`（**必须 4 的倍数**），步进 `0x1000 − 0x50` |

### 旧编号 → 功能名（仅历史对照）

2026-09-20 起补丁点**不再有 `pNN` 编号**，条目名 = `fs_cp_<功能名>_<版本范围>`。其余文档里若仍见到
`pNN`（多为分析记录），按下表对号；单位是**逻辑补丁点**，不是条目。

| 旧编号 | 功能（`fs_fn_groups` 组名） | 条目族前缀 | 形态 |
|---|---|---|---|
| p01 | `IDirectory_Read` | `fs_cp_idirectory_read` | 1 条 `nop` |
| p03 | `PFCODE_Converters`（OEM2Unicode） | `fs_cp_pfcode_oem2unicode` | 整函数 `patch_utf8_to_utf16` |
| p02 | `PFCODE_Converters`（Unicode2OEM） | `fs_cp_pfcode_unicode2oem` | 整函数 `patch_utf16_to_utf8` |
| p04 | `PFCODE_Converters`（isOEMMBchar） | `fs_cp_pfcode_is_oem_mb_char` | 整函数 `patch_is_oem_mb_char` |
| p05 + p17 | `FAT_GetNextChar` | `fs_cp_fat_getnextchar` | 整函数替换 **M8** |
| p06 | `FAT_GetNextPathComponent` | `fs_cp_fat_getnextpathcomp_step` | 指令改写 |
| p07 | `StringDesc_AddLeft` | `fs_cp_str_addleft` | 指令改写 |
| p08 | `StringDesc_GetCharCount` | `fs_cp_str_getcharcount` | 指令改写 |
| p09 | `StringDesc_CompareUnicode` | `fs_cp_str_compareunicode` | 指令改写 |
| p10 | `StringDesc_CompareOem` | `fs_cp_str_compareoem` | 指令改写 |
| p11–p16 + p18–p26 | `WideChar_Compare` | `fs_cp_widechar_compare` | 整函数替换 **M6**（15 点折叠） |
| p27 | `FAT_MakeShortName`（宽度钳制） | `fs_cp_makeshortname` | 指令改写（防 `subs w23,w23,#2` 死循环） |
| p28 | `PFCODE_Str_Unicode2OEM` | `fs_cp_str_unicode2oem` | 整函数 `patch_str_unicode2oem` |
| p29 | `StringDesc_ToUpper` | `fs_cp_stringdesc_toupper` | 整函数 `patch_stringdesc_toupper` |

### 两级表为什么必要

条目**按函数分组、同函数相邻**（`FUNC_ORDER`）。原因是像 `WideChar_Compare` 这种函数曾承载 15 个
互相依赖的补丁点——按站点扁平排列时，看表的人无法看出「它们其实是一件事」。M6 之后它塌缩为 **1 条 blob**。
详：演进史 §2（三个根因 R1/R2/R3）、§8.1（M1 落地）。

### 门控：无条目级开关，只有「整份生效 / 整份跳过」

**表里没有任何 per-entry 门控**（既无 `stage_idx` 也无 `needs_wide_cmp`）——条目一律启用；
唯一开关是 `[options] fs_codepage=0`，它让**整份** fs 编码补丁不落地（其余 sys-patch 补丁照常）。

> 半成品状态是危险的：宽度钳制（防 `FAT_MakeShortName` 的 `subs w23,w23,#2` 死循环）晚于它
> 依赖的转换器（`PFCODE_*` / `PFCODE_Str_Unicode2OEM`）⇒ 若允许「转换器已换、钳制未打」，
> **FAT32 建 CJK 长名会挂死 fs**。
> 这正是 `stage_idx` 与 `needs_wide_cmp` 都在 2026-09-20 被删除的原因。
> `fs_progress()` 只是**进度标记**（挂死时停在哪个函数组），与门控无关。

### 扫描结构（P3 三项，均由数据推导）

| 编号 | 机制 | 收益 |
|---|---|---|
| **S1** | **族内互斥兄弟退役**：补丁点 = 族（名字里的 `pNN`），任一变体定位成功即认定同族其余变体不可能命中，不再建位面 / 走位面 / 比对 | 谓词面 5 → 平均 4.5~4.9/块 |
| **S2** | **全族落定空转退出**：块边界统计活条目，全落地就结束扫描 | 块遍历 12141 → **6782**（≈ 每次启动少 206 次 4 KB `svcReadDebugProcessMemory`） |
| **S3** | **blob 车道快筛**：模板偏移 0 或 4 的确定字节作筛子，一位 2 取字节 + 2 查表 + 1 与 | blob 候选 1.607 亿 → **379 万**（−97.6%） |

合计估算扫描指令量 **3.61×** 下降。等价性凭据：`_audit/_opt_equiv.py` 26/26（命中集合 / 站点 / 写入次数三方一致）。
详：演进史 §19；活条目判据 `fs_pat_live()` / `fs_blob_live()` 在 `fs_codepage.cpp`。

### 构建期守卫（`sysmod/tools/check_patch_sizes.py`，`make` 自动跑）

尺寸从 `_end` 汇编标签自动取得（sysmod 需 `-fno-toplevel-reorder`），守卫**从源码文本解析**补丁表
（`--main src/fs_codepage.cpp`）——表条目必须保持 `PAT_RE`/`BLOB_RE`/`GROUP_RE`/`PRED_LIST_RE` 可解析，
**解析不了 = 静默不校验**。完整检查项清单见 `re_utf8_patch_final.md` §4。

尺寸恰好等于洞时报 **`⚠ ZERO SLACK` 告警**（能过，但下次代码生成波动就 `HOLE OVERFLOW`）。

### 七个替换函数的实测尺寸（`make` 实测，全绿）

| 替换函数 | 尺寸 | 洞 | 余量 |
|---|---|---|---|
| `patch_utf8_to_utf16` | 0xEC | 0x170 | 132 |
| `patch_utf16_to_utf8` | 0x8C | 0x1D0 | 324 |
| `patch_is_oem_mb_char` | 0x48 | 0x50 | 8 |
| `patch_str_unicode2oem` | 0xEC | 0x120 | 52 |
| `patch_stringdesc_toupper` | 0x94 | 0xB0 | 28 |
| `patch_widechar_compare` | 0x308 | 0x360 | 88 |
| `patch_fat_getnextchar` | 0x1E8 | 0x240 | 88 |

> 洞是**跨 26 变体的全局最小洞**（守卫口径），不是某一个固件的洞。

---

## 决策台账

「当时结论 → 最终状态」对照。**依据脚本**多在语料目录 `D:/Game/NS/firmware/_audit/`（不在仓库）。

### 表架构

| 编号 | 方案 | 最终结论 | 依据 | 详文 |
|---|---|---|---|---|
| **M1** | 表结构两级化（函数 → 站点） | ✅ **已做**（`fs_fn_groups[12]`） | 结构改动，语义不变 | 演进史 §8.1 |
| **M3** | 谓词位图替代逐条全段扫描 | ✅ **已做**（`fs_pred_plane[5]`） | 谓词命中 ⇒ 模板只可能在该字上匹配（`applied()` 回调证明不可达，已删） | 演进史 §8.2 |
| **M6** | `WideChar_Compare` 整函数替换 | ✅ **已做**（p18–p26 折叠） | 可执行差分 9000/9000（`_m6_oracle.py`） | `re_utf8_patch_final.md` §3.5、演进史 §11–§13 |
| **M7** | p11–p16 也并入 M6 | ✅ **已做**（该函数只剩 blob 一条路径） | 定位模板 22/22 命中，无固件失去补丁 | 演进史 §16 |
| **M8** | `FAT_GetNextChar` 整函数替换 | ✅ **已做**（p05+p17 折叠） | 差分 6 形状 × 2000 例 = 12000/12000 | `re_utf8_patch_final.md` §3.6、演进史 §18 |
| **M2** | 「规则 + 序号」替代字节模板（P2b） | ⛔ **未做**（暂缓，见 O6） | E3 已证可行，但工程量大、与 M6/M8 收益重叠 | 演进史 §3.E3、§4.M2 |
| **M4 / M5** | 扫描窗口收缩 / 写入合并 | ⛔ **不做** | M4 要与函数边界=写死偏移冲突；M5 站点物理上无法合并 | 演进史 §14.4 |

### 剩余优化项（2026-09-19 盘点）

| 编号 | 项 | 最终结论 |
|---|---|---|
| **O1** | 互斥变体族「落地即停兄弟」 | ✅ 已并入 **S1**（当前形态 · 扫描结构） |
| **O2** | blob 扫描改 4 字节步进 + 首字快筛 | ✅ 已并入 **S3** |
| **O4** | `patch_is_oem_mb_char` 零余量告警 | ✅ 已做：显式 `c < 0xC0` 折进无符号比较，0x50 → **0x48**（余 8 B）；守卫加 `ZERO SLACK` |
| O3 | 转换器可读性 | 可做，非必要（尺寸守卫兜底） |
| O5 | 谓词再收敛 / SIMD 化 | 不做：无包含关系可合并，收益换不来复杂度 |
| O6 | M2 规则指纹定位（P2b） | 暂缓：把失效模式从「模板不命中（安全）」换成「直方图不唯一」，需新守卫 |
| O7 | 写入合并 / 窗口收缩 | 不做（同 M4/M5） |

### 2026-09-20 整改（守卫全绿）

| 项 | 内容 |
|---|---|
| **p28 判界** | `patch_str_unicode2oem` 从「逐字符判界、逐字节写」改为**每轮先确认「最多 3 字节 + 结尾 NUL」都在缓冲内**（`limit - out >= 4`），修掉最坏越界 3 B。0xE0 → 0xEC |
| **p27 死循环** | stage 门控整体删除（见当前形态 · 门控），从根上排除「转换器已换、钳制未打」 |
| **`wide_cmp` 删除** | 条目级 `needs_wide_cmp` 开关一并删除；`fs_codepage_set_options()`、`[fs_codepage] wide_cmp` 全部移除 ⇒ 只剩整份生效 / 整份跳过 |
| **M6 折叠修正** | `patch_widechar_compare` 的 ASCII 折叠改为共享 `fold_ascii_upper`（`c-0x20`，等价原版的 16 位截断），修掉旧 15 点补丁引入的进位 bug；0x31C → **0x308**。差分基线由「与旧 15 点补丁一致」改为「与**原版 0 补丁**逐例一致」 |
| **表改名** | `fs_cp_patterns` / `fs_codepage_blobs` → `fs_inst_patches` / `fs_blob_patches`；谓词清单改由 X 宏 `FS_PRED_LIST` 唯一定义，条目表不再有 `pred_idx` 列 |
| **结构体合并** | 三个 fs 对象视图 `FsStrDescLite` / `FsCharIter` / `FsPatStream24` 布局相同（24 B）→ 统一为单一 **`StringDesc`**（按 fs 原型命名，**不用 union**；三处 `+0x10` 本就是同一个「编码/宽度」选择子）。显式声明 `+0x14` 保留字段 ⇒ 恰 24 B **无尾部填充**，`static_assert` 锁尺寸/偏移。`FsNameDesc16`（16 B）是另一种布局，保持独立 |
| **条目改名** | 补丁点名字**去掉 `pNN` 编号**，改 `<功能名>_<版本范围>`（沿用原版 sys-patch 的 `a.b.c-d.e.f` / `a.b.c+` / 逗号并列口径）；范围是**语料实测**覆盖。族号改为**版本范围之前的功能前缀** ⇒ 运行期族内互斥退役与构建守卫同步改判（`fs_family_of()` / `NAME_RE`），行为不变 |
| **转换器差分** | `patch_utf16_to_utf8` 1 字节分支的 NUL 落点按原版写回 `[1]`（原版是 `strb wzr,[x1,#1]`，此前写 `[2]` 会让 `[1]` 留旧字节）。0x7C → 0x8C |
| **O4 零余量** | 见上表 |
| **日志精简** | 删 `[debug] tmp_buffer`/`tmp_addr`/`tmp_size`；`[fs_codepage]` 只列**已定位**条目，未命中数进 `[debug] fs_codepage_unmatched` |
| **连带同步** | 守卫正则、`fs_encode_fix/fs_fw_audit.py` 的表解析正则、`AGENTS.md` / `README.md` / `re_utf8_patch_final.md` 文档；改名后另用 `D:/Game/NS/firmware/_audit/_map_variants.py`（生成覆盖）/`_check_name_ranges.py`（核对名字 vs 语料） |

详：`fs_encode_fix/re_整函数替换功能评估.md` §7（含仍未做项）。

---

## 不变量与铁律

> 完整版（含为什么）在 `AGENTS.md`「FS codepage patch」一节与 `re_utf8_patch_final.md` §3.1；这里只列**不能碰**的。

| 约束 | 违反后果 |
|---|---|
| **ASLR**：进 fs 的代码必须位置无关 | 禁 `MOVZ/MOVK` 宽常量、外部 `BL`、字面量池、`&函数名`（`-fPIE` 下会走 `.data.rel.ro`）。守卫强制扫描 |
| **`FS_OVERLAP` 必须是 4 的倍数**（`0x50`） | 位面按块内字网格建，奇数 overlap 让网格与指令网格错开 → **所有多字节模板静默不命中** |
| **fs 全局槽地址绝不可写死** | 26 份固件里槽有 **18 个不同取值** ⇒ 只对一份有效，其余解引用野指针。一律**现场收割**（哨兵 `0xDEAD0001/2` + 读原函数体的唯一 `adrp`+配对 `ldr`），**收割失败整点跳过** |
| **pattern 两种写法别混** | JSON/离线脚本 `..` = **一个**通配字节；C++ `str2hex` = **一个 `.` 一槽**。漏转换轻则编译失败、**重则整表 0 命中**（已在表侧与 `fs_fw_audit.py` 各踩一次） |
| **绝不手抄字节改机器码** | 只做语义等价改写（`rules_*`），差分目标是**与原版逐位一致** |
| **短分支的 NUL 落点也算差分** | 原版 1 字节路径 NUL 在 `[1]`，只写 `[2]` 会留旧字节 |
| **补丁是「整份生效 / 整份跳过」** | 无 per-entry 开关；`[options] fs_codepage=0` 跳过整份 |
| **改表的连带清单** | `check_patch_sizes.py` + `fs_encode_fix/fs_fw_audit.py`（`FS_PAT_RE`/`FS_BLOB_RE`）漏一个就**静默失效** |
| **条目名格式 `fs_cp_<功能名>_<版本范围>`** | 族号 = 版本范围之前的功能前缀（不是 `pNN`）。名字里的版本号是**语料实测覆盖**，改动后须用 `D:/Game/NS/firmware/_audit/_check_name_ranges.py` 复核（31 条 / 14 族 / 0 重叠），否则守卫 `NAME_RE` 解析不到、族内互斥退役失灵 |

---

## 已知限制与后续方向

- **文件名折叠**：4 字节 UTF-8（非 BMP）→ `'_'`。接口（`uniWidth` / 代理对）天然支持，**这是产品取舍不是实现限制**；
  现状后果不只是显示成下划线——**不同非 BMP 名字会折叠成同一 UTF-16 名字**。已决定不做。
- **`+0xffe0` 折叠已改为 `-0x20`**（2026-09-20）：原版用 `mov wT,#0xffe0; add` 做 ASCII 大写折叠，32 位相加的进位靠随后 `uxth`（16 位）比较丢掉 ⇒ **等价于 `sub #0x20`**。旧的 15 点指令补丁把比较加宽到 24 位后进位不再丢，星号回溯路径 `*a` 匹配不到小写名（`('ba','*a')` 原版=1、旧补丁=0）——**那是补丁的 bug，不是原版怪癖**。现替换体统一用 `fold_ascii_upper(c) = c-0x20`，与**原版 0 补丁**逐例一致。
- **部分调用点仍把 `isOEMMBchar` 返回值当 bool**（`FAT_MakeShortName` / `FAT_ReplaceShortNameNumber`）：
  只有我们 patched 的调用点按字节数步进，其余是 +1/+2 固定推进——**有意为之**（`patch_is_oem_mb_char` 在那里返回 0/1）。
- **差分口径仍是指令产物级**：建议改为**行为级**（比返回值 / 输出缓冲 / 步进量），才能自己现形 p28 越界这类结构性缺陷。见评估报告 §5。
- **待做（不阻塞）**：`_audit/_p28_bound_test.py` 离线边界用例；M2/P2b（O6）视需要再评估。

---

## 文档地图

完整层级与每篇定位见 **`fs_encode_fix/README.md`**。速查：

```
README.md                                 用户向：功能、配置、构建
AGENTS.md                                 智能体入口：构建、布局、硬不变量、文档地图
补丁点合并优化分析.md  ← 本文            设计现状 + 决策台账（无编号）
fs_encode_fix/
    README.md                             文档层级索引（读这一篇定方向）
    re_utf8_patch_final.md                ★ 权威：方案 + 实现 + 守卫 + 排障
    re_整函数替换功能评估.md                七个 blob 的功能合理性（Ghidra）
    补丁点合并优化分析·演进史.md            原 §1–§20 时间线论证（节号稳定，裸 §N 指它）
    re_analysis.md                        FS 对象模型逆向（19.exfat）
    callback_tables.md                    回调/vtable 表清单（参考数据）
    re_fw_compat_design.md                版本兼容选型；fs_fw_audit.py 用法
    re_fw_audit_19.0.1.md                 固件审计工具的 19.0.1 结论
    cp936_vs_utf8.md                      GBK vs UTF-8 方案选型（结论：UTF-8）
    re_ghidra_round19.md                  第十九轮 Ghidra 笔记
    re_boot_hang_2026-09-15.md            事故：开机卡 logo
    re_path_not_found_2026-09-15.md       事故：能枚举打不开
    re_homebrew_crash_2026-09-16.md       事故：模拟器闪退（与本补丁无关）
    re_bigdir_dir_as_file.md              事故：大目录被当文件
    re_improve_plan.md                    改进清单（已实施，历史）
    fs_encode_fix_test_plan.md            上机测试计划
    plan.md                               早期 CP932→UTF-8 接口对照
    _archive/README.md                    已退役脚本（只进不出，勿引用）
M6_Ghidra反编译报告.md                      M6 三个形状的反编译全文（演进史 §10 依据）
```
