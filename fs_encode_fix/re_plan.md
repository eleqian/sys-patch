# exFAT 中文文件名补丁 · 逆向分析方案（初步规划）

## 1. 当前实测状态

| 能力 | 结果 |
|---|---|
| 目录列表显示中文文件名 | 正常 |
| 打开/进入中文文件名（文件或子目录） | 失败 |
| 部分大目录列表 | 异常，子目录被当作文件显示 |

即：**输出方向（UTF-16 → OEM/UTF-8）基本正确，输入方向（OEM/UTF-8 → UTF-16）或元数据（attr）存在问题。**

## 2. 已确认的补丁面（当前 `sysmod/src/main.cpp: fs_codepage_patch`）

| 文件偏移 | 目标函数 | 作用 |
|---|---|---|
| `0xd4af4` | `IDirectory_Read` | NOP 掉“名字含字节 ≥0x7F 则丢弃”的分支，让中文名字能返回 |
| `0xfeac0` | `PFCODE_CP932_OEM2Unicode` | 替换为 UTF-8 → UTF-16 |
| `0xfec30` | `PFCODE_CP932_Unicode2OEM` | 替换为 UTF-16 → UTF-8 |
| `0xfee40` | `PFCODE_CP932_isOEMMBchar` | 按首字节返回 0/1/2/3（UTF-8 字符长度-1） |
| `0xf45d8` | `FAT_GetNextChar` | `add x9,x8,#1` → `add x9,x8,x0`，指针按返回值前进 |
| `0xf4d8c` | `FAT_GetNextPathComponent` | 同上 |
| `0xf77e8` | `StringDesc_AddLeft` | `cinc` → `add ... x0` |
| `0xf7984` | `StringDesc_GetCharCount` | `cinc` → `add ... x0` |
| `0xf7a80` | `StringDesc_CompareUnicode` | `csel` → `add ... x0` |
| `0xf7bd0` | `StringDesc_CompareOem` | `csel` → `add ... x0` |

已核对：上述 6 处“按返回值前进”指令在日常合法 UTF-8 输入下逻辑正确（+ret 再 +1）。

## 3. 待查问题的初步判断

1. **无法打开**：输入方向转换（`PFCODE_Str_OEM2Unicode`）之外，还可能涉及
   - `StringDesc` / 路径长度/字符数计算；
   - 名称匹配（exFAT 用 `exfat_prepare_entry_search → exfat_resolve_path → fat_check_name_match`；FAT32 用 `FAT_MatchFileName1 → FAT_MatchFileName`）；
   - 短名生成/回退路径（读回退到 8.3）。
2. **大目录子目录被当作文件**：`IDirectory_Read` 的 attr 来自 `FsDirInfo.attr`（偏移 `0x478`），最可能是**内存越界写**破坏了该字段（UTF-8 比 CP932 更长，固定缓冲按 CP932 尺寸设计）。

## 4. 细化逆向计划

1. 明确 FS 模块内部的编码模型：`StringDesc`、`StringEncode_e`、OEM 层（prfile2/PFCODE）与 FAT/exFAT 边界。
2. 逐条核对 `isOEMMBchar` 的所有调用点，区分“已 patch / 未 patch”。
3. 计算关键固定缓冲区尺寸，给出越界的最坏情况。
4. 梳理“显示”和“打开”两条完整数据流，标注每一步是否被 patch 覆盖。
5. 形成根因假设清单（按置信度排序）+ 动态验证方案 + 候选修复。

## 5. 交付物

- 本文件：`fs_encode_fix/re_plan.md`
- 细化结果：`fs_encode_fix/re_analysis.md`（函数映射、数据结构、数据流、根因假设、验证与修复建议）
