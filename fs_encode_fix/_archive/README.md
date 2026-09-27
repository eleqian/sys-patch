# fs_encode_fix/_archive —— 已退役的一次性脚本与产物

这里放的是**已经被取代**的东西，只为留档，不要在新工作里引用。目录保持"只进不出"，
新脚本请留在 `fs_encode_fix/` 并写清用途。

## 为什么它们在这里

| 批次 | 内容 | 为什么退役 |
|---|---|---|
| 2026-09-13 vtable / 回调表 RE | `_inventory.py` `_tables.py` `_vtables.py` `_vtrefs.py` `_consumers.py` `_group.py` `_report.py` `_scan_tables.py` `_parse_tables.py` `_mkmaps.py` `_idirvt{,2,3}.py` + `_fmap.json` `_runs.json` `_tables.json` `_inventory.json` `_vtables.json` `_vtable_refs.json` `_vptr_consumers.json` `_vt{names,idx,pick}.txt` `_idirvt_hex.txt` `_d0.txt` | 那一轮是"从 `.data` 的函数指针表反推 fs 对象模型"。结论已经沉淀进 `callback_tables.md` / `re_analysis.md` / `re_ghidra_round19.md`，脚本本身是一次性的；对象模型之后由 `fs_structs.h`（带 `_Static_assert`）与 Ghidra 侧负责 |
| 2026-09-14/16 归档取证 | `_raw_ls.py` `_raw_hex.py` `_raw_attr_scan.py` `_sd_scan2.py` `_sd_scan_homebrew.py` `_cores_ver.py` + 各自 `*_out.txt` / `_cores_ver.txt` `_ps_probe.txt` `_mem_decoded.txt` | 查 SD 卡 FAT 原始目录项 / homebrew 闪退 / RetroArch 版本配套的一次性取证。结论在 `re_homebrew_crash_2026-09-16.md` |
| 会话辅助 | `_append_mem.py` `_fix_mem.py` `_check_enc.py` | 当时手工维护 `.workbuddy/memory` 与查文件编码用；现在记忆用工具直接写 |
| 更早的补丁原型 | `old-patch.txt` | 早期手工补丁字节草稿，已被 pattern 驱动表 + 构建守卫取代 |

## 还活着的工具（留在上一层）

| 文件 | 用途 |
|---|---|
| `fs_encode_fix/fs_fw_audit.py` | 固件解包 + fs 补丁适配审计（`all` / `check` / `audit` / `unpack` / `holes` / `batch`） |
| `fs_encode_fix/_fs_dis.py` | fs 二进制反汇编小工具（`sites` / `range` / `word` / `adrp`），需 capstone |
| `fs_encode_fix/_name_collision_check.py` | "fs 视角同名"冲突检查 |
| `fs_encode_fix/fs_structs.h` | 结构体偏移（packed + `_Static_assert`） |
| `fs_encode_fix/re_utf8_patch_final.md` | **权威方案 + 实现说明**，先读它 |
| `sysmod/tools/check_patch_sizes.py` | 构建期守卫（`make` 自动跑） |

离线验证脚本（`_verify_cpp_table.py` / `_p1_sim_scan.py` / `_opt_equiv.py` / `_scan_cost.py` /
`_lane_rule.py` / `_opt_probe.py` / `_m6_*.py` / `_n1415_*.py` …）与 26 份固件语料同在
`D:/Game/NS/firmware/_audit/`，**不在本仓库**，避免把上百 MB 语料带进 git。
