# 中文路径（codepage）补丁方案改进分析

> **状态：改进项清单（2026-09-15 起草），绝大多数已实施 —— 完成度见下，不要按本文当"待办"。**
> - 已落地：pattern 驱动无硬编码偏移（**P1**）、`WideChar_Compare` 整函数替换（**M6**）、
>   `FAT_GetNextChar` 整函数替换（**M8**）、14.1.2/15.0.1 变体族覆盖、扫描结构三项优化（**P3**）、
>   构建期守卫 + 离线等价性/差分验证。
> - 现状权威文档：`re_utf8_patch_final.md`（方案与实现定稿）、`AGENTS.md`（FS codepage patch 一节）、
>   `../补丁点合并优化分析.md`（设计现状与决策台账）、
>   `补丁点合并优化分析·演进史.md`（§13/§14/§16/§18 为合并决策，§19 为扫描优化）。
> - 本文里"现行补丁面 / `sysmod/src/main.cpp` 的 `fs_codepage_patch()`"指 2026-09-15 的形态：
>   该函数 2026-09-19 已拆到 **`sysmod/src/fs_codepage.cpp`**，表也从 `main.cpp` 迁出。

> 依据：`re_analysis.md`（十二轮逆向，2026-09-14 第十八轮收尾）+ `sysmod/src/main.cpp` 现行实现。
> 目标：把逆向结论转化为可落地的补丁改进项，按优先级排列，每项给出技术方案、影响面与前置验证。

---

## 1. 现行补丁面回顾（sysmod/src/main.cpp fs_codepage_patch）

| 偏移 | 目标 | 方式 |
|---|---|---|
| 0xd4af4 | IDirectory_Read 名字过滤 | NOP（b.cc→nop） |
| 0xfec30 | PFCODE_CP932_Unicode2OEM | 替换为 UTF-16→UTF-8（0x70 字节） |
| 0xfeac0 | PFCODE_CP932_OEM2Unicode | 替换为 UTF-8→UTF-16（0x98 字节） |
| 0xfee40 | PFCODE_CP932_isOEMMBchar | 替换（返回额外字节数） |
| 0xf45d8 / 0xf4d8c / 0xf77e8 / 0xf7984 / 0xf7a80 / 0xf7bd0 | 六处指针步进 | `+1` → `+返回值`（已验证） |

共性风险：全部为**硬编码偏移且无固件版本门控**，仅对派生偏移的那份 FS（19.exfat.FS.kip1）有效。

> **偏移→函数名映射**（2026-09-15 第十九轮补全，换固件重推时按名定位）：
> `0xd4af4`=`IDirectory_Read`(+0xd4)；`0xfeac0`/`0xfec30`/`0xfee40`=`PFCODE_CP932_OEM2Unicode`/
> `Unicode2OEM`/`isOEMMBchar` **函数入口**；`0xf45d8`=`FAT_GetNextChar`(+0xf8)；
> `0xf4d8c`=`FAT_GetNextPathComponent`(+0x1cc)；`0xf77e8`/`0xf7984`/`0xf7a80`/`0xf7bd0`=
> `StringDesc_AddLeft`/`GetCharCount`/`CompareUnicode`/`CompareOem`。
> 规律：3 个入口=换实现，7 个消费点=改步进。详表见 `re_ghidra_round19.md` §5.5。

> **2026-09-15 复核**：上表 P1-1 提到的"改 +返回值"系列，实际落地情况与本节旧描述有出入
> ——`FAT_MakeShortName` 用 `pOEMCharWidth`（非 isMB）、`FAT_ReplaceShortNameNumber` 无需改，
> **以 §6 实施状态为准**（R2 已修、R3 判误报）。本节保留原文仅供追溯。

---

## 2. 最新逆向结论对方案的定性影响

1. **exFAT 匹配/存储全程在 UTF-16 域闭环**（§8.5）：打开路径 `exfat_prepare_entry_search` 只有一处编码依赖（OEM2Unicode 补丁点）；NameHash 与条目集校验和均从同一 FsObject 缓冲派生，创建与打开自洽。
   ⇒ **方向性结论：现有方案对 exFAT 是完备的，不需要新增补丁点**；残余风险集中在 H1（内存破坏）与 R5（越界读），属于"兜底加固"而非"补功能"。
2. **UpCase 表对 CJK 未命中直通**（`exfat_resolve_path`）：大写化不破坏中文，无需伪造 hash 或绕过大写表。
3. **isOEMMBchar/GetNextChar 步进系列只服务 OEM 域比较**（FAT32 匹配、8.3 短名、通配符）⇒ R1/R2/R3/R7 的影响面收敛为"FAT32 与短名回退路径"，exFAT 日常读写不受其影响，优先级可定为 P1。
4. **`<N>` 索引打开**：NameHash 硬门下 `hash("<N>")` 不等于真实名 hash，`<N>` 打开应走枚举路径——列入上机边界测试，暂不改代码。
5. 显示方向（§8.3）只经过 Unicode2OEM 且不依赖 isMB/GetNextChar ⇒ 显示稳定性不依赖 P1 项；H1 是显示方向唯一高危。

> 以下 6–9 条为 **2026-09-15 第十九轮 GHIDRA 复核**新增（详见 `re_ghidra_round19.md` §5.5–5.7）。

6. **CP932 六回调槽全定性**（`PFCODE_CODE_PAGE_CONTEXT` @`0x7100fcfc38`）：
   `+0x18` OEM2Unicode、`+0x20` Unicode2OEM、`+0x28` OEMCharWidth、`+0x30` isOEMMBchar、
   `+0x38` **UnicodeCharWidth（恒 2）**、`+0x40` **isUnicodeMBchar（恒 false）**。
   ⇒ CP932 的 Unicode 通道**没有多字节/变长概念**；若将来把 UTF-8 接进 Unicode 通道，
   变长逻辑必须全部自写，无现成回调可复用。注册点 `PFCODE_CP932_Init` @`0x71000d5150`
   （`0x710010ee40` 是跳过去的 thunk，非第二份实现）。
7. **转换器返回值本就带宽度**：`ConvertWidth(oemW,uniW) = oemW<<16|uniW`，`GetConvertWidth` 解包
   ⇒ 返回值高 16 = 消耗的 OEM 字节数、低 16 = 产生的 UTF-16 码元数。现有消费方并未使用它
   （统一走 `pOEMCharWidth`），故仅在需要时作为"不新增宽度回调"的备选方案。
8. **codepage flag bit16 恒 0**：初始化实参是 `PFCODE_CP932_Init1(0x20000, NULL)`（bit17），
   而 `DAT_7100fcfc44` 只保存 `flags & 0x10000` ⇒ `FAT_GetNextPathComponent`、
   `FAT_MakeShortName` 中的 `(DAT_7100fcfc44._2_1_ & 1) == 0` **恒真**，阅读时可常量折叠。
   `DAT_7100fcfc48`（Init 的 callback 参数）是**死槽**：写入 NULL、全程序无 READ。
9. **isOEMMBchar 消费面完整清单**（8 函数 / 13 处引用）：`StringDesc_GetCharCount`、
   `CompareUnicode`、`CompareOem`、`AddLeft`、`FAT_MatchFileName`、`FAT_GetNextChar`(×2)、
   `FAT_GetNextPathComponent`(×2)、`FAT_MatchWildcardRecursive`(×3)。
   补丁"是否覆盖完整"以此清单为准。

---

## 3. 改进项清单（按优先级）

### P0-1 ｜ H1：`PFCODE_Str_Unicode2OEM` 输出无上限（高危，独立于症状）

- 现状：`fat_init_fs_object_shortname`（0x7100105ba0）向 `dirInfo+0x487`（`lname[513]`）写 OEM 名，无边界检查。CP932 时代最坏 511 ≤ 513 安全；UTF-8 后 ≥171 个 CJK 字符即溢出，紧邻 0x688 的 unicode_name/搜索状态区，可解释"大目录列表异常、子目录显示为文件"。
- **为何不能在 per-char `patch_utf16_to_utf8` 里修**：单字符转换器没有输出缓冲区上下文，不知道写了多远。
- **方案 A（推荐）：整体替换字符串级 `PFCODE_Str_Unicode2OEM`（0x71000f5840）**，实现为循环调用 `patch_utf16_to_utf8` 并累计输出长度，clamp 到 ≤512 字节后写 NUL。
  - 影响面：`fat_init_fs_object_shortname`（正是 H1 现场）与 `fs_convert_string_encoding`。后者目标缓冲更大，截断仅在 >170 个 CJK 字符时触发，可接受。
  - **空间约束**：下一函数 `PFCODE_Str_OEM2Unicode` 在 0x71000f5960，间隔仅 **0x120**。替换函数体必须 ≤0x120 字节（紧凑 C + `-Os` 大概率可行；若超限则需 trampoline + code cave，复杂度上升）。
  - **前置验证**：反编译 0x71000f5840 确认①返回值约定（返回什么：字节数？状态码？）②全部 xref 及各自输出缓冲大小，确认 512 统一上限无副作用。
- 方案 B（备选）：只 patch `fat_init_fs_object_shortname` 调用点做前置 UTF-16 长度检查（>170 字符截断）。改动面最小但需要内联 trampoline，指令级工作量更大，且只堵一个调用点（`fs_convert_string_encoding` 仍裸奔）。

### P0-2 ｜ R7：`patch_is_oem_mb_char` 续字节语义对齐

- 现状：续字节（0x80–0xBF）返回 1；而 `patch_utf8_to_utf16` 对续字节走 else 分支返 `utf8_len=1`（按 1 字节非法字符前进 1）。
- 改法：续字节返回 **0**。配合 GetNextChar 补丁点 `cbz w0 → 跳过 +返回值` 语义，续字节只走原有 +1，前进量与转换器 len=1 自洽，消除失步双跳。
- 4 字节分支返 3 已与转换器 `utf8_len=4`（3+1）自洽，不动。
- 改动量：一行，重新编译即生效；无 cmp_bytes 变化。

### P1-1 ｜ R1/R2/R3：三处"isOEMMBchar 返回值当 bool"调用点改 `+返回值`

- `FAT_MatchWildcardRecursive`（0x71000f4770）：isMB 点 **0xf4874 / 0xf49ac / 0xf4a7c**——短名回退匹配、通配符 3 字节 UTF-8 失步。
- `FAT_MakeShortName`（0x71000f5ac0）：4 处 isMB——8.3 短名按 2 字节/CJK 估算空间，UTF-8 下可能超长/截断（影响创建、重命名）。
- `FAT_ReplaceShortNameNumber`（0x71000f6270）：同型问题（重名短名生成）。
- 改法：与已验证的 6 处同型——`cinc/csel/add #1` → `add wN, wM, w0`（叠加原 +1 后 1/2/3 字节前进 1/2/3）。
- 待办：从 Ghidra 导出 7 处精确指令字节构造 cmp_bytes/patch_bytes（建议先用脚本核对反汇编，避免手抄）；`csel` 型改 `add` 需确认标志位依赖已被消除（原 csel 的条件分支语义是否仅剩"是否多字节"）。
- 注：R2 修复后短名空间按 3 字节/CJK 估算，行为更保守（更早放弃短名化、走 LFN），方向正确。

> **2026-09-15 第十九轮复核（本项旧描述已部分过时，以 §6 为准）**
>
> - **R1 成立**：`FAT_MatchWildcardRecursive` 确为 `isOEMMBchar`(bool) 消费点，
>   3 处调用 @`0xf4874`/`0xf49ac`/`0xf4a7c`，+0x14 处即步进指令（已补 @`0xf4888`/`0xf49c4`/`0xf4a90`）。
> - **R2 归因需修正**：`FAT_MakeShortName` **不是** isMB 问题——宽度取自 `pOEMCharWidth`（ctx+0x28），
>   取宽度本身正确；缺陷在 2 字节拷贝循环。相关硬编码指令 6 条（循环头 `0xf5ea0`、回边 `0xf5f30`）：
>   `0xf5ea4` `add w27,w27,#0x2`（短名写指针）、`0xf5ea8` `add w24,w24,#0x2`（源指针）、
>   `0xf5eac` `subs w23,w23,#0x2`（剩余宽度）、`0xf5ed8` `ldrb w22,[x0,#0x1]`（只读第 2 字节）、
>   `0xf5eb4` `strb w22,[x8,#0x1]`（只写第 2 字节）、`0xf5ebc` `add w8,w8,#0x2`（长度计数器）。
>   宽度 3 时 `subs w23,#2` 永不归零 → 死循环，修复点 `0xf5dcc`（`mov w23,w0`→`mov w23,#2`）位置正确。
> - **R3 误报确认**：`FAT_ReplaceShortNameNumber` 确以 `(*pOEMCharWidth)` 逐字符推进，无需补丁。
> - **方案选型含义**：GB2312/CP936 汉字为 2 字节，与 CP932 双字节同构 ⇒
>   该拷贝循环**天然正确**；只有 UTF-8（CJK 3 字节）才需要 R2 这类修复。
>   这是"CP936 对中文 = 原版 CP932 对日文行为平移"在短名生成路径上的直接证据。

### P1-2 ｜ R6：`patch_utf16_to_utf8` 补 NUL

- 现状：仅 1 字节分支写 `utf8_output[2]='\0'`；2 字节分支 [2] 残留旧值，依赖调用方补 NUL。
- 改法：2 字节分支补 `utf8_output[2]='\0'`，与 1 字节分支及原 CP932 约定对齐；3 字节分支写满 [0..2] 不需要。改前核查全部调用方是否依赖"恒写 [2]"以外的模式。

### P2-1 ｜ R5：`patch_utf8_to_utf16` 输入合法性检查

- 现状：3/4 字节分支无条件读 `in[1]..in[2]`，路径尾截断/NUL 结尾时有越界读（NUL 保护仅限"读到 0 产生非法码点"，读越界页仍崩）。
- 改法：3/4 字节分支先校验续字节为 0x80–0xBF 且非提前 NUL，非法按 1 字节 `'_'` 处理（返 `utf8_len=1`）。同时消除"非法 UTF-8 输入导致 OEM2Unicode 失步"这一 §8.5 指出的互操作残余风险。

### P2-2 ｜ R4：`StringDesc_ToUpper`（0x71000f7c10）OEM 分支 ASCII-only

- 现状：OEM 分支有符号 `toupper` 逐字节，UTF-8 高位字节（≥0x80）可能被改写，破坏写路径名字。
- 改法：≥0x80 原样返回（ASCII-only），或逐字符经转换器在 Unicode 域大写。exFAT 主匹配走 UpCase 表不受影响，此项是 FAT32 写路径兜底。

### P2-3 ｜ 代理对 / 4 字节 UTF-8（可选增强，暂缓）

- 现状双向不对称：UTF-8 4 字节→输出 `'_'`；UTF-16 代理对→被当普通码点按 3 字节错误编码。emoji 等 astral 文件名双向都无法正确打开。
- 若要支持：`patch_utf16_to_utf8` 合成代理对输出 4 字节；`patch_utf8_to_utf16` 输出代理对并返 `(4<<16)|4`。
- **前置验证**：必须先确认 `PFCODE_GetConvertWidth`（0x71000f7cf0）的全部消费方对"低 16 位 UTF-16 宽 = 4"的容忍度，以及字符串层步进是否按宽度推进。风险/收益比差（场景罕见），列为远期。

### P3 ｜ 工程化加固

1. **固件版本门控**：给 10 个 codepage 偏移加 `min_fw_ver/max_fw_ver`（当前仅对 FW 19.x 有效），或维护 per-FW 偏移表；至少在 log.ini 已有 fw_version 记录基础上，让 codepage 失败时明确提示"固件不匹配"。
2. **失败详情落盘**：`fs_patch_function` 失配时已填 `tmp_buffer`（实际字节）+ `tmp_addr/tmp_size` 且已写入 log.ini（main.cpp:988-993），信息够用；建议 result 字符串同时带偏移量（如 `"0xfec30: patch_utf16_to_utf8 failed"`），一眼定位失败点。
3. **fail-fast 策略评估**：当前任一失败即 break、全部不生效。对 H1/R7 这类可独立生效的加固项，建议改为逐项独立应用 + 汇总结果（`"success (3/10)"`），提高部分固件下的可用性；核心四项（IDirectory_Read/两转换器/isMB）可保持原子组。
4. **上机验证顺序**（衔接 `fs_encode_fix_test_plan.md`）：
   - 第一轮：P0-1 + P0-2 + R6（纯加固，不改行为）→ 回归现有测试 1–4；
   - 第二轮：P1-1（R1/R2/R3）→ 重点补测通配符搜索、重名创建、重命名（边界测试 5/6 加长中文名用例，>170 CJK 字符验证不再溢出）；
   - 新增边界用例：`<N>` 数字索引打开（`/中文名/1` 类）、纯符号名、含代理对字符名（预期降级为 `_`，记录行为）。

---

## 4. 实施顺序总览

```
第一步（无新逆向依赖，纯改 C）：
  R7 续字节返 0 ＋ R6 补 NUL ＋ R5 输入校验        ← 重新编译即可
第二步（需 0x71000f5840 返回值约定/xref 终审）：
  H1 方案 A：有界替换 PFCODE_Str_Unicode2OEM（≤0x120 字节）
第三步（需 Ghidra 导出 7 处指令字节）：
  R1/R2/R3 三函数 isMB 调用点 +返回值
第四步（R4 + 工程化）：ToUpper ASCII-only、FW 门控、失败详情、部分生效策略
第五步：按测试计划上机回归，重点长名/通配符/<N> 用例
```

## 5. 风险提示

- H1 方案 A 的替换函数体大小是硬约束（0x120），编码前先看 `-Os` 产物尺寸；超限即转方案 B。
- R1/R2/R3 的 csel→add 改写必须逐处核对原指令的条件语义，防止把"分支选择"误改成"无条件累加"。
- 所有偏移仍无版本门控前，跨固件升级后必须重新核对 `cmp_bytes` 失配日志（`log.ini [debug]`）再放行。

---

## 6. 实施状态（2026-09-14，全部落入 sysmod/src/main.cpp 并编译验证）

| 项 | 状态 | 实现方式 | 关键偏移/尺寸 |
|---|---|---|---|
| R7 | ✅ | isOEMMBchar 续字节返 0（与转换器 len=1 自洽） | 函数尺寸 0x44（原 0x50） |
| R6 | ✅ | utf16_to_utf8 2 字节分支补 `out[2]='\0'` | 函数尺寸 0x7C（原 0x70） |
| R5 | ✅ | 2/3/4 字节分支续字节短路校验（NUL/非法 → `'_'` len=1），防越界读 | 函数尺寸 0xEC（原 0x98） |
| H1 | ✅ | 有界替换 PFCODE_Str_Unicode2OEM：512 字节截断 + NUL，双模式（普通/特殊映射）忠实复刻；经 GOT 0x710024eb50 取 ctx，ctx+0x20 取回调，ctx+0x48 bit1 判模式；返回值恒 0 | @0xf5840，尺寸 0x110 ≤ 0x120 硬约束 |
| R4 | ✅ | 替换 StringDesc_ToUpper：OEM 分支 ASCII-only（≥0x80 直通），Unicode 分支按原语义 | @0xf7c10，尺寸 0x98 ≤ 0xD0 硬约束 |
| R1 | ✅ | 3 处 `add wN,wM,#1/#2` → `add wN,wM,w0` | @0xf4888 / 0xf49c4 / 0xf4a90 |
| R2 | ✅（升级为致命 bug 修复） | Ghidra 复核：MakeShortName 用 pOEMCharWidth 而非 isMB；宽 3 字符使 `subs w23,#2` 拷贝循环永不归零 → FAT32 创建中文名**死循环**。修复：`mov w23,w0`→`mov w23,#2`（宽 3 按 2+1 消费，字节不丢、循环正常退出） | @0xf5dcc |
| R3 | ⛔ 误报 | 复核：ReplaceShortNameNumber 用 pOEMCharWidth（ctx+0x28）逐字符推进，补丁后宽度自动正确，无需补丁 | — |

**函数尺寸纪律**：`PATCH_SZ_*` 常量必须与编译产物精确一致（nm -S 实测；改动任一 patch_* 函数后必须复核）。过小截断指令 → fs 崩溃；过大把相邻 sysmod 代码写入 fs。
**编译验证**：make 全量通过（sysmod sys-patch.nsp 13:59），两个替换函数反汇编复核无 adrp（绝对地址 movz/movk 物化，PC 无关）。
**待上机回归**：FAT32 创建中文文件名（原死循环点）、长中文名（>170 字符截断行为）、通配符搜索、重命名、`<N>` 索引打开。

**2026-09-15 补充**：`PATCH_SZ_*` 宏已废除。每个 patch_* 函数放入独立 `.text.<函数名>`
section，函数体后放 `<函数名>_end` 汇编标签，运行时尺寸 = 标签地址 − 函数地址
（`patch_code_size()`，sysmod/src/main.cpp）。**前提**：sysmod CXXFLAGS 必须带
`-fno-toplevel-reorder`，否则 GCC 把顶层 asm 提前发射、函数体延迟发射，尺寸恒为 0。
构建期守卫 `sysmod/tools/check_patch_sizes.py` 改为校验：标签距离 == ELF st_size
（防标签错位）且 ≤ 空洞（FUNCTIONS 表：0xfeac0→0x170、0xfec30→0x1D0、0xfee40→0x4C、
0xf5840→0x120、0xf7c10→0xD0，换固件版本须重推）。实测尺寸：0xEC/0x7C/0x44/0x110/0x94。

**2026-09-15 第十九轮 Ghidra 复核**（详见 `re_ghidra_round19.md`）

- 独立复核确认：**R2 修复点 `@0xf5dcc` 正确**、**R3 误报判断正确**（依据见 §3 P1-1 复核块），
  R1 三处步进指令与 isMB 调用点偏移关系吻合。§3 原"三处都按 +1 推进"的描述已加注修正。
- 本次**仅文档层复核，未改动任何 patch_* 代码** ⇒ `PATCH_SZ` 尺寸与构建守卫不受影响，
  无需重新 `make`。
- 新增可复用资产：① 补丁偏移→函数名映射（§1）；② 六回调槽全定性（§2-6）；
  ③ **isOEMMBchar 消费面 8 函数 / 13 处清单（§2-9）**——后续调整补丁时用此清单核对覆盖面，
  避免漏改；④ codepage flag bit16 恒 0，可常量折叠（§2-8）。
- 服务层与结构体侧成果（FsDrvObject 字段定性、FsObject 字段同步、`+0x230=drvObj` 交叉验证等）
  记于 `re_ghidra_round19.md`，与本方案无直接耦合，不在此展开。
