# fs_encode_fix —— 文档与工具层级索引

本目录是 fs 相关**逆向笔记 / 设计文档 / 离线工具**的落点。文件多、结论有新旧，
这一页的作用是**先定方向再读细节**：每篇的定位、读者、是否仍是权威口径，都在这里。

**三条入口**（根目录）：

| 文件 | 定位 | 读者 |
|---|---|---|
| `../README.md` | 用户向：功能、配置、构建 | 使用者 |
| `../AGENTS.md` | 智能体入口：规则约束、硬不变量、构建/布局、文档地图 | 改代码的人/智能体 |
| `../补丁点合并优化分析.md` | 设计现状 + 决策台账（哪些做了、哪些没做、为什么） | 要改表结构的人 |

---

## 层级

```
L0 入口      ../README.md · ../AGENTS.md · ../补丁点合并优化分析.md
L1 权威       re_utf8_patch_final.md                    ← 补丁方案与实现的唯一权威
L2 专题       re_整函数替换功能评估.md · re_analysis.md · re_fw_compat_design.md
              cp936_vs_utf8.md · re_ghidra_round19.md · re_improve_plan.md
              fs_encode_fix_test_plan.md · plan.md
L3 参考数据   callback_tables.md · fs_structs.h
L4 事故与历史 补丁点合并优化分析·演进史.md · ../M6_Ghidra反编译报告.md
              re_boot_hang_2026-09-15.md · re_path_not_found_2026-09-15.md
              re_homebrew_crash_2026-09-16.md · re_bigdir_dir_as_file.md
              re_fw_audit_19.0.1.md
L5 归档       _archive/README.md                        ← 已退役，只进不出，勿引用
```

---

## L1 · 权威：`re_utf8_patch_final.md`

**读它就能回答「补丁是什么、怎么实现的、怎么验的、坏了怎么办」。** 这是唯一一处会把方案说全的地方；
其余文档只在**某一维度**上比它更深（见下）。含：原理、补丁清单（16 处逻辑 / 31 条条目 / 26 变体）、
7 个替换函数的实现要点与 ASLR 纪律、构建期守卫的完整检查项、排障与开关、已知限制、复现清单。

> 与 `../补丁点合并优化分析.md` 的分工：本文说**怎么实现**，那篇说**为什么这样设计、各方案结论**。

## L2 · 专题详细

| 文档 | 维度 | 状态 |
|---|---|---|
| `re_整函数替换功能评估.md` | 7 个整函数替换的**功能合理性**（Ghidra 复核编码域结构、P0/P1 问题、缓冲区事实、差分口径建议、2026-09-20 整改进展 §7） | 现行 |
| `re_analysis.md` | fs **对象模型**逆向终版（19.exfat，image base `0x7100000000`）：卷内存池、`FsDrvObject`、目录迭代器、FAT 介质驱动层、exFAT 全环节。`§0` 是**已证伪结论速查** | 现行；比 AGENTS.md 的类型速查深得多 |
| `re_fw_compat_design.md` | 版本兼容**选型**：指令级 vs 整函数替换的逐项对比、选型规则、`fs_fw_audit.py` 的用法（§8） | 现行；§2 有一处已过时描述（文首已标注） |
| `cp936_vs_utf8.md` | 方案**选型**：GBK/CP936 方案 vs UTF-8 方案 | 已决策（UTF-8 胜），保留论证 |
| `re_ghidra_round19.md` | 第十九轮 Ghidra 笔记：`FsDrvObject` 字段、服务层、编码回调注册点与消费面、第 11 个补丁点的发现 | 现行（过程笔记） |
| `re_improve_plan.md` | 改进清单 R1–R7 / H1 的提出与实施状态（`§6` 为准，前面保留原文供追溯） | **已实施**，历史 |
| `fs_encode_fix_test_plan.md` | 上机测试计划（部署、功能、边界、性能、回归） | 现行 SOP |
| `plan.md` | 早期 CP932 ↔ UTF-8 的**接口级对照**（每个 PFCODE_* 的语义、调用点、适配方式） | 现行速查 |

## L3 · 参考数据（查表用，不建议通读）

| 文件 | 内容 |
|---|---|
| `callback_tables.md` | 代码页回调表 / FS vtable / `IDirectory_Func_Table` 等**函数指针表的逐槽清单**（137K，最大的一份） |
| `fs_structs.h` | 结构体偏移定义，packed + `_Static_assert` 校验 |

## L4 · 事故与历史

**事故post-mortem**（结论已沉淀，读它是为了「别再犯」）：

| 文档 | 事件 |
|---|---|
| `re_boot_hang_2026-09-15.md` | 开机卡 logo + 日志为空（硬编码绝对地址 / 诊断日志死锁） |
| `re_path_not_found_2026-09-15.md` | 中文名「能枚举、打不开」（`isOEMMBchar` 忽略 `byte_idx`） |
| `re_homebrew_crash_2026-09-16.md` | PPSSPP / RetroArch 闪退（**与本补丁无关**） |
| `re_bigdir_dir_as_file.md` | 大目录被当文件（目录条目 ARCHIVE 位） |
| `re_fw_audit_19.0.1.md` | 固件审计工具的 19.0.1 结论与换固件写回流程 |

**历史论证**：

| 文档 | 内容 |
|---|---|
| `补丁点合并优化分析·演进史.md` | 主设计文档 2026-09-18~20 的**全文时间线**（§1–§20）。**节号稳定**，外部按 § 引用它（`re_fw_compat_design.md` §19、`re_improve_plan.md` §13/14/16/18/19）。⚠️ 结论会被后文推翻，读前先看文首导读 |
| `../M6_Ghidra反编译报告.md` | M6 三个形状的 Ghidra 反编译全文（演进史 §10 的依据） |

## L5 · 归档

`_archive/README.md` —— 已被取代的一次性脚本与产物。**目录只进不出，不要在新工作里引用。**

---

## 工具（本目录可执行）

| 工具 | 用途 | 依赖 |
|---|---|---|
| `fs_fw_audit.py` | 固件解包 + fs 补丁适配审计（`all` / `check` / `audit` / `unpack` / `holes` / `batch`） | hactool / nstool |
| `_fs_dis.py` | fs 二进制反汇编小工具（`sites` / `range` / `word` / `adrp`） | capstone |
| `_dump_blobs.py` | 从 `sysmod/sys-patch.elf` 反汇编 7 个替换体，打印 size vs 洞 | capstone |
| `_name_collision_check.py` | 「fs 视角同名」冲突检查（`--explain` / `--mode wide`） | — |

> 需要 capstone 的两个用托管 venv 的 python 跑（`~/.workbuddy/binaries/python/envs/default/Scripts/python.exe`）。
> 离线验证脚本（`_verify_cpp_table.py` / `_p1_sim_scan.py` / `_opt_equiv.py` / `_m6_*.py` …）与 26 份固件语料
> 同在 `D:/Game/NS/firmware/_audit/`，**不在本仓库**，避免把上百 MB 语料带进 git。
