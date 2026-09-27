# fs 整函数替换（7 处）功能合理性评估

> 口径：**不看「是否与最早的指令级补丁实现一致」，只看「最终功能是否正确、是否最优」**。
> 方法：Ghidra（`FS_1` 工程，`/19.exfat.FS.kip1`，base `0x7100000000`）反编译原版 + 调用者，
> 与 `sysmod/src/fs_codepage.cpp` 的替换体逐条对照；尺寸/余量取构建期守卫实测（本次重跑）。
> 日期：2026-09-20。

---

## 0. 结论摘要

**架构是对的。** 「把编码域的 5 个原语（UTF-8↔UTF-16 转换器 ×2、isOEMMBchar、有界 Unicode2OEM、
ASCII-only ToUpper）就地重定义 + 修掉 2 处手工窥字节的地方（通配匹配器、FAT_GetNextChar）」
是这套补丁能达到目标的最少改动面，而且 Ghidra 证实**其余所有消费点都通过 ctx 回调或宽度回调
拿宽度，会自动跟随**，不需要替换。7 处替换里没有一处的**定位**是错的。

当时在「有界」「门控」「折叠」三件事上查出 6 个具体问题，其中 **5 个已在 2026-09-20 修复**（§2 的 P0 / §7），仅剩 1 个是**有意的功能取舍**：

| 级别 | 问题 | 状态 |
|---|---|---|
| **P0** | `patch_str_unicode2oem` 的「有界」不成立，最坏越界 **3 字节**（长 CJK 名踩 `lname[513]` 之后） | ✅ 已修（§2 P0-1、§7.1） |
| **P0** | `stage` 门控让「死循环防护」（p27）晚于它依赖的转换器（p02/p03/p04）⇒ `stage ∈ {1,2,3}` 时 FAT32 建 CJK 名 → fs 挂起 | ✅ 已修：**整个 stage 机制删除**（§2 P0-2） |
| P1 | ASCII 折叠照抄原版 `+0xffe0`：原版靠 16 位比较丢进位（等价 `c-0x20`），本实现 32 位比较 ⇒ 进位留下，星号回溯路径匹配不到小写名 | ✅ 已修：改用 `fold_ascii_upper`（`c-0x20`）；对**原版 0 补丁**穷举差分严格类 0 不符（§3 P1-1） |
| P1 | 4 字节 UTF-8（非 BMP）一律变 `'_'` ⇒ 不同非 BMP 名字折叠同名 | ⏸ **有意不做**（产品取舍，接口支持但不实现；§3 P1-2） |
| P2 | `patch_is_oem_mb_char` **0x50/0x50 零余量** | ✅ 已修：压到 `0x48/0x50`（余 8 B，§7.1 O4） |
| P2 | `patch_utf16_to_utf8` 1 字节分支 NUL 落点与原版不符（写 `[2]` 不写 `[1]`） | ✅ 已修（§7.1 P2 差分） |

反过来，有 3 处**看起来不优、实际是约束下的唯一解**，见 §4。

---

## 1. 编码域的真实结构（Ghidra 实测）

fs 的编码域挂在 `.bss` 的 `PFCODE_CODE_PAGE_CONTEXT @0x7100fcfc38`（**运行期才填充**，
Ghidra 读不到内容，但反编译注释已标槽号）；原函数从 `0x710024EB50` 取出该指针。

| ctx 槽 | 目标函数（19.0.1 exfat） | 语义 | 是否被替换 |
|---|---|---|---|
| `+0x18` | `PFCODE_CP932_OEM2Unicode` @ `0xFEAC0` | OEM 串 → UTF-16 单元，返回 `(oemBytes<<16)\|uniBytes` | **p03 → `patch_utf8_to_utf16`** |
| `+0x20` | `PFCODE_CP932_Unicode2OEM` @ `0xFEC30` | UTF-16 单元 → OEM 串 | **p02 → `patch_utf16_to_utf8`** |
| `+0x28` | `PFCODE_CP932_OEMCharWidth` @ `0xFEE00` | **直接调 `+0x18`** 再取宽度 | 否（自动跟随） |
| `+0x30` | `PFCODE_CP932_isOEMMBchar` @ `0xFEE40` | 原为 `bool`（CP932 前导字节判定） | **p04 → `patch_is_oem_mb_char`（改成返回 0..3 的"额外字节数"）** |
| `+0x38` | `PFCODE_CP932_UnicodeCharWidth` @ `0xFEE90` | 恒 `return 2` | 否（常量，正确） |
| `+0x40` | `PFCODE_CP932_isUnicodeMBchar` @ `0xFEEA0` | 恒 `return false` | 否（正确） |
| `+0x48` | `0x7100FCFC80` 标志位 | bit1 = 特殊映射模式（`.`/`' '`/其余→`_`） | 由 p28 读取 |

**返回值契约（关键）**：`PFCODE_CP932_ConvertWidth(oemWidth, uniWidth)` @ `0xF7CE0`
= `oemWidth << 16 | uniWidth`，`PFCODE_GetConvertWidth` @ `0xF7CF0` 反向拆解。
`oemWidth` = **OEM 域字节数**，`uniWidth` = **UTF-16 字节数**（消费点一律 `uniWidth >> 1` 得字符数）。
替换体统一返回 `(utf8_len << 16) | 2` ⇒ 契约自洽。

### 消费点清单（全部核对过）

| 函数 | 19.0.1 地址 | 怎么拿宽度 | 结论 |
|---|---|---|---|
| `PFCODE_Str_OEM2Unicode` | `0xF5960` | `dst += uniW>>1`；`src += oemW` | UTF-8 自洽，**不需要改** |
| `PFCODE_Str_Unicode2OEM` | `0xF5840` | 同上 | 无界 ⇒ H1；**p28 替换** |
| `FAT_GetNextChar` | `0xF44E0` | 手工窥字节（4 个补丁点在 24 B 块内） | **p05/p17 → M8 整体替换** |
| `FAT_MatchWildcardRecursive` | `0xF4770` | 手工窥字节（15 个补丁点） | **p11–p26 → M6 整体替换** |
| `FAT_GetNextPathComponent` | `0xF4BC0` | `pisOEMMBchar(B,1)` 之后**再 +1** | ⇒ p06 的 `add #1 → add Rd,Rn,w0` **语义正确**（w0 = 额外字节，后一处补上那个 1） |
| `FAT_MakeShortName` | `0xF5AC0` | `pOEMCharWidth` → **`subs w23,w23,#2` 拷贝循环** | 奇数宽度不归零 ⇒ **p27 钳制为 2**（见 P0-2） |
| `FAT_ReplaceShortNameNumber` | `0xF6270` | `pOEMCharWidth`，循环 `do{}while(w+idx<=N)` | 安全 |
| `StringDesc_*` ×4 / `IDirectory_Read` | — | `csel/cinc` 逐字节跳 | 指令级 p07/p08/p09/p10/p01 |

**调用者面**：`FAT_GetNextChar` 只有 2 个调用者（`FAT_MatchFileName`、`FAT_MatchWildcardRecursive`）；
`WideChar_Compare` 同样 2 个（两者都在 M6/M8 覆盖内）；`StringDesc_ToUpper` 只有 1 个
（`FAT_GetFsDrvByPath`）。**替换面是闭合的**，没有"漏在外面还用 CP932 口径"的消费点。

### 缓冲区事实（决定界该取多少）

| 缓冲 | 地址/尺寸 | 来源 |
|---|---|---|
| `FsDirInfoInternal.lname` | `[513]` @ `0x487`，紧随 `unicode_name[520]` @ `0x688` | `fs_structs.h` + 偏移差 `0x688-0x487 = 0x201` |
| `FAT_MakeShortName` 栈缓冲 | **512 B**（`memset(...,0x200)`，`add x0,sp,#0x1c`；下界 `sp+0x21C = 0x1C+0x200` 正是下一个局部 `local_74`） | 反汇编 `0x71000f5aec..0x71000f5b00` |
| `fs_convert_string_encoding` 的 `dest` | ≥ `0x208`(520) | 同函数内 `string_strncpy(dest, ..., 0x208)` |

---

## 2. P0 问题（本轮已修 —— 见 §7）

### P0-1 `patch_str_unicode2oem` 的界不成立（最坏越界 3 字节）✅ 已修

```c
u8 *const limit = out + 512;                /* 输出上限 */
...
while (*in != 0 && out < limit) {
    u16 c = *in++;
    else { *out++ = 0xE0|...; *out++ = 0x80|...; *out++ = 0x80|...; }  /* 一次写 3 字节 */
}
*out = '\0';
```

判界是**逐字符**、写入是**逐字节**，且循环后的终止符没有预留：

* `out` 可达 `511`（例如 `1 + 3×170`）。此时循环条件 `511 < 512` 仍成立 → 写 `511/512/513`，
  `out` 变 `514`，再 `*out = '\0'` 落在 **514**。
* 即使 `out` 只到 `510`（3 字节字符）→ `out_final = 513` → 终止符越界 1 字节。
* 纯 1 字节分支（特殊映射模式）最坏 `out_final = 512` → 对 **512 B 栈缓冲**越界 1 字节。

对照目标缓冲：

* `lname[513]`（合法下标 0..512）：越界 **1–2** 字节，落进 `unicode_name`（UTF-16 长名镜像）头部。
* `FAT_MakeShortName` 的 512 B 栈缓冲：越界 **1–3** 字节。好消息是紧随其后的 `local_74`
  只有 4 字节且**随后立即被写覆盖**（`local_74[0]=0` → 循环里再被 `pUnicode2OEM` 写入），
  所以 19.0.1 上"侥幸不致命"；但这是布局巧合，不是设计。

> 也就是说：p28 整函数替换的**唯一动机**（"原版无上限，≥171 个 CJK 就写溢出 513 字节的 lname"）
> 只被解决了"量级"，没有被解决"正确性"——它仍然会溢出。注释里
> 「本实现在 512 字节处截断（含 NUL 共 ≤513）」这句与实现不符。

**修法（最小、够余量）**：把界改成"连终止符一起预留"，并逐字节判：

```c
u8 *const limit = out + 512;                 /* 允许写入的最后一个下标 + 1 含 NUL */
while (*in != 0 && out + 3 <= limit) { ... } /* 普通分支：3 字节最坏 */
while (*in != 0 && out + 1 <= limit) { ... } /* 特殊映射分支 */
```
（特殊分支若要和普通分支共用一个 `limit`，把普通分支的界改成 `out + 3 <= limit`、
`limit = out + 512` 后终止符最坏落在 511，对 512 B 栈缓冲也安全。）

尺寸余量够：`patch_str_unicode2oem` = `0xE0`，洞 `0x120`，**剩 64 B**。

**补一条离线用例**（比现场复现便宜得多）：构造 `1 + 3×170 / 2 + 3×170 / 511 个 ASCII + CJK`
三种长度，喂给替换体和原版，断言「写入下标 < 缓冲长度」。

### P0-2 `stage` 门控把"死循环防护"排在了它依赖的转换器之后 ✅ 已修（整个 stage 机制删除）

Ghidra 实测 `FAT_MakeShortName` 的双字节拷贝循环（`0x71000f5eac`..`0x71000f5ec4`）：

```
71000f5eac: subs w23,w23,#0x2
...
71000f5ec4: b.eq 0x71000f5e84        ; w23 != 0 就回到循环体
```

`w23` 来自 `(*pOEMCharWidth)(x22)`（`0x71000f5d40`/`0x71000f5dcc`），而 `OEMCharWidth` 直接调
被 p03 替换的 `OEM2Unicode` ⇒ **宽度从 CP932 的 {1,2} 变成 UTF-8 的 {1,2,3,4}**。
宽度 3 → `3 → 1 → 0xFFFFFFFF → …` 递减 2 **永远不归零**，循环无限、`shortName` 与源串双双越界。

这正是 p27 存在的理由（`rules_mov_reg_to_movz2` 把 `mov wD,w0` 钳成 `mov wD,#2`，
代码注释也写明了"UTF-8 的 3 字节字符会让循环永不归零（死循环）"）。

**问题在 stage 排序**（下表是历史形态，`stage_idx` 整个机制已于 2026-09-20 删除）：

| 补丁 | 原 stage_idx | 含义 |
|---|---|---|
| p02 / p03 / p04（转换器） | **0** | 换掉编码域 |
| p06 | 1 | — |
| M6 / M8 | 2 | 3 字节感知 |
| **p27（宽度钳制）** | **3** | 防止上面的死循环 |
| p28 / p29 | 4 / 5 | — |

`stage=N` 的语义是"`stage_idx >= N` 不应用"。于是 `N ∈ {1,2,3}` 时：**转换器已换（宽度会返回 3），
而钳制没打** ⇒ FAT32 上创建含 CJK 的长文件名会让 fs 卡死。
默认 `stage=6`（全打）不受影响，但 `stage` 是逃生/二分开关，这个组合是个陷阱。

**修法**：不是重排 `stage_idx`，而是**整套 stage 机制删除**（2026-09-20）——"半成品"状态本身危险，
只保留「整份生效 / 整份跳过（`[options] fs_codepage=0`）」两态。连带删掉条目级 `needs_wide_cmp`
（它同样会造出"转换器已换、下游没换"的半成品）。详见 §7 整改表。

---

## 3. P1 问题

### P1-1 `wc_fold_oem` 的 `+0xffe0` ✅ 已修（改用 `c-0x20`）

原版在 ASCII 折叠里用 `mov wT,#0xffe0; add`（32 位无符号加），对 `'a'` 得到 `0x10041`。**但原版随后用
`uxth`（16 位）比较，进位被丢掉 ⇒ 实际等价于 `c - 0x20`**，所以原版本身是对的（`*a` 能匹配 `ba`）。
问题出在补丁：把比较加宽到 24 位后进位不再丢，`*a` 就匹配不到小写名 —— **这是补丁的真实 bug，
不是需要“复刻”的原版怪癖**。旧的 15 点指令补丁即如此（`_m6_fold_probe.py` 12 例里 6 例偏离原版）。

**修法**：M6 替换体的折叠统一改用 `fold_ascii_upper(c) = ((c-0x61)<0x1a) ? c-0x20 : c`（32 位比较下
显式 `-0x20`），主循环推进与星号回溯路径共用。验证：`_audit/_m6_sem_diff.py` 以**原版 0 补丁**为基线
穷举短串空间（约 2.4 万例），严格类 **0 例不符**（旧的 15 点补丁在此有 33 例不符，全是
`name='Xy' pat='*y'` 型），放宽类 0 例意外差异。

### P1-2 4 字节 UTF-8（非 BMP）→ `'_'`：接口支持，是产品取舍不是实现限制

`patch_utf8_to_utf16` 对 `11110xxx` 序列校验完续字节后写 `'_'`、返回 `len = 4`。
**校验续字节是对的**（防越界 + 防与调用方步进失步），但结果是 `😀`、`𠮷`(U+20BB7) 这类字符
在 fs 内部变成 `_`。后果不只是"显示成下划线"——**不同的非 BMP 名字会折叠成同一个 UTF-16 名字**，
exFAT 的名字比较会把它们判成相等 ⇒ 可能覆盖/打不开文件。这比 p28 的越界更"日常"。

关键是：**契约本来就装得下代理对**。`ConvertWidth` 的 `uniWidth` 是 UTF-16 **字节数**，
所有消费点都是 `uniWidth >> 1` 或按宽度步进 ⇒ 返回 `(4 << 16) | 4` 并写 4 字节即可。
逐调用点核对过缓冲：

| 调用点 | 输出缓冲 | 4 字节是否安全 |
|---|---|---|
| `FAT_GetNextChar` PATH_A | `out = st + 0xc`，栈帧 `u8 st[0x10]` | 12..15 正好 4 字节 ✓（输入 `st+4` 需把 `st[7]` 显式清零） |
| `FAT_MakeShortName` | `local_74[2]`（4 B） | ✓ |
| `Str_OEM2Unicode` / `Str_Unicode2OEM` | ≥512 B | ✓ |
| `FAT_GetNextPathComponent` 后续 `pisOEMMBchar(B,2)` | 只看字节 | 需同步（4 字节首字节 `0xF0..`，`patch_is_oem_mb_char` 已返回 3 ✓） |

**成本**：要扩差分/oracle、要重新过 `make` 守卫（`patch_utf8_to_utf16` 余量 132 B，够）。
**收益**：消除一类静默名字碰撞。**这是 7 处替换里唯一值得新增的功能**。

---

## 4. 看起来不优、其实是约束下唯一解的三处（不建议改）

**D1 同一段 UTF-16→UTF-8 逻辑写了 2 份**（`patch_utf16_to_utf8` 与 `patch_str_unicode2oem` 内联）。
ASLR 铁律禁止替换体之间 `bl`/取址（`-fPIE` 下取函数地址会走指针槽，拷贝后失效），
所以**只能复制**。这是设计约束，不是代码冗余。

**D2 `OEMCharWidth` / `UnicodeCharWidth` / `isUnicodeMBchar` 不替换 —— 正确。**
Ghidra 证明：前者**直接调用**被替换的 `OEM2Unicode`（宽度自动从 1/2 变成 1..4），
后两者是常量 `2` / `false`。替换它们只会多 3 条条目、零收益。

**D3 把 p18/p05 做成整函数替换 —— 正确，而且比指令级更优。**
这两处的补丁点都落在**同一个 24 B 基本块/同一份手工窥字节逻辑**里，而且互相耦合
（步进量、读宽、写宽、值构造必须**同时**成立，否则比较值 2 字节截断）。
指令级只能逐点近似，整函数替换把它们变成原子单元；p18 顺带把 15 个补丁点压成 1 条。
M6 报告里"3 个形状必须维护 3 份实现"的成本，已经被"4 条入口模板 + 2 对哨兵收割"吃掉了。
**唯一代价**是尺寸：`patch_widechar_compare` `0x308`/洞 `0x360`（余 88 B）、
`patch_fat_getnextchar` `0x1E8`/洞 `0x240`（余 88 B）——留白很薄，但守卫兜住了。

---

## 5. 差分口径：以**原版**为基线（已对 M6 采用）

旧的离线对照物是「**原版函数 + 旧指令级补丁**」，比较的是**指令产物**。这条口径会把“原版的 bug
锁成基线”，也让“顺手修一个明显的错”变成需要人工判断的风险动作 —— `+0xffe0` 就是这么被“保下来”的
（见 §3 P1-1：其实原版没这个 bug，是补丁自己引入的）。

**M6 已改为以原版 0 补丁为基线**（`_audit/_m6_sem_diff.py`：穷举短串空间，严格类要求逐例一致），
并在 `_m6_fold_probe.py` 里做 `orig0 / orig+15点 / 当前替换体` 三者对照。

要推广到全部替换体时，比较对象应是**调用者可见的行为**：

```
orig  vs  替换体
  转换器的 (返回宽度, 输出缓冲内容, 消费的输入字节数)
  FAT_GetNextChar 的 (返回值, path->ptr_left 增量)
  通配匹配器的 (bool 结果, nameCtx.len/pos 终值)
```

并显式列出「允许的差异」（如 4 字节支持、p28 边界），这样结构性问题会在行为级差分里直接现形。

---

## 6. 落地清单（按优先级）

> 状态栏是 2026-09-20 整改后的实际结果，详见 §7。

1. ✅ **p28 边界修正**（§2 P0-1）。离线用例 `_audit/_p28_bound_test.py` 尚未落地（见 §7 待办）。
2. ✅ **p27 依赖顺序**（§2 P0-2）—— 没有挪 stage，而是**整个删除 stage 门控**（README/AGENTS.md 同步）：
   半成品状态从根上不可能出现。
3. ✅ **守卫加 `⚠ ZERO SLACK` 告警**，并且顺手把 `patch_is_oem_mb_char` 从 `0x50/0x50` 压到
   `0x48/0x50`（余量 8 B），告警不再亮。
4. ✅ **`patch_utf16_to_utf8` 不光是注释错**：Ghidra 复核原版 `PFCODE_CP932_Unicode2OEM` 的
   1 字节分支是 `strb wT,[x1]` + `strb wzr,[x1,#1]` —— NUL 在 `[1]`，而实现写的是 `[2]`，
   **`[1]` 会留旧字节**。这是真实的差分缺陷，已按原版修正。
5. ⏸ （可选，需拍板）4 字节 UTF-8 → 代理对（§3 P1-2）—— **本轮明确不做**（用户决定）。
6. ✅ 不建议动的三处没动：M6/M8 替换体、`isOEMMBchar` 形状、`OEMCharWidth` 不在替换名单里。

---

## 7. 整改进展（2026-09-20）

按 §6 清单执行，全部改动都过了构建期守卫（`make`，7 个替换函数 + 15+16 条表项全绿）。

### 7.1 代码

| 项 | 改动 | 文件 |
|---|---|---|
| P0-1 界 | `patch_str_unicode2oem` 循环条件 `out < limit` → `(limit - out) >= 4`，`limit` 语义改为「可用字节数 512」，含结尾 NUL 的整个写入不越 512 | `sysmod/src/fs_codepage.cpp` |
| P0-2 依赖 | **删除 stage 门控**：`FsPat`/`FsBlob` 去掉 `stage_idx`，删 `fs_stage_limit`；`fs_stage()` 更名 `fs_progress()`（只是挂死定位的进度标记） | `fs_codepage.cpp` / `fs_codepage.h` / `main.cpp` |
| wide_cmp 删除 | 条目级 `needs_wide_cmp` 开关一并删除，连带删 `fs_codepage_set_options()` 与 `[fs_codepage] wide_cmp` ⇒ 只剩「整份生效 / 整份跳过」 | `fs_codepage.cpp` / `fs_codepage.h` / `main.cpp` |
| P1-1 折叠 | `patch_widechar_compare` 的 ASCII 折叠由 `wc_fold_oem(c, in_star)`（`+0xffe0`）改为共享 `fold_ascii_upper`（`c-0x20`）；`0x31C` → `0x308` | `fs_codepage.cpp` |
| 表改名 | `FsPat`/`FsBlob` → `FsInstPatch`/`FsBlobPatch`；`fs_cp_patterns`/`fs_codepage_blobs` → `fs_inst_patches`/`fs_blob_patches`；谓词清单改由 X 宏 `FS_PRED_LIST` 唯一定义，条目表去掉 `pred_idx` 列 | `fs_codepage.cpp` |
| 结构合并 | 三个同布局 fs 对象视图 `FsStrDescLite`/`FsCharIter`/`FsPatStream24`（皆 24 B）统一为单一 **`StringDesc`**（按 fs 原型命名，不用 union）：`{void *ptr_left; void *ptr_right; u32 encode_type; u32 reserved;}`，三处 `+0x10` 是同一个「编码/宽度」选择子 + `static_assert` 锁尺寸与偏移；`reserved` 显式声明 ⇒ 无尾部填充、整对象拷贝字节数确定。`FsNameDesc16`（16 B）是另一种布局，不合并 | `fs_codepage.cpp` |
| 条目改名 | 补丁点名字**去掉 `pNN` 编号**，改 `fs_cp_<功能名>_<版本范围>`（版本范围沿用原版 sys-patch 的 `a.b.c-d.e.f` / `a.b.c+` / 逗号并列口径，且为**语料实测**覆盖）；`fs_fn_groups[]` 组名同步改功能名。族号改为**版本范围之前的功能前缀** ⇒ `fs_family_of()` 重写 | `fs_codepage.cpp` |
| P2 差分 | `patch_utf16_to_utf8` 1 字节分支补 `utf8_output[1] = '\0'`（原版 `strb wzr,[x1,#1]`）；注释重写为「三条分支都写满 `[0..2]`」 | `fs_codepage.cpp` |
| O4 余量 | `patch_is_oem_mb_char` 删掉显式 `if (c < 0xC0) return 0;`，折进 `(unsigned)extra < 4u`（`c<0xC0 ⇒ extra ≤ 0`，`c≥0xF8 ⇒ extra ≥ 4`，对全输入等价）⇒ `0x50` → `0x48` | `fs_codepage.cpp` |
| 日志精简 | 删 `[debug] tmp_buffer` / `tmp_addr` / `tmp_size`（基址变量 `fs_code_base` 仍在内存里用于换算站点偏移）；`[fs_codepage]` 只写**已定位**的条目，未命中汇总进 `[debug] fs_codepage_unmatched` | `fs_codepage.cpp` |

### 7.2 守卫与离线工具（改表必须同步的那一批）

- `sysmod/tools/check_patch_sizes.py`：`PAT_RE`/`BLOB_RE` 去掉 stage 段；删 `STAGE_IDX_MAX` 与两处范围检查；
  新增 `delta == hole` ⇒ `ZERO SLACK` 告警（warn，不 fail）。
- `fs_encode_fix/fs_fw_audit.py`：`FS_PAT_RE`/`FS_BLOB_RE` 同步；`stage_labels()` → `group_labels()`，
  site dict 的 `stage` 键 → `group`（它本来就是**函数组名**，与门控无关）；
  `STAGE_LIMIT_RE` 删除（指向已不存在的 `fs_stage_limit`）。实测新表解析 31 条不漏（19.0.1 命中 14 = 7+7）。
- `_audit/_verify_cpp_table.py` / `_p1_sim_scan.py` / `_opt_equiv.py` **不受影响** —— 它们从
  `PATTERNS.json` + `_gen_cpp.py` 建表，不解析 `fs_codepage.cpp`（`_verify_cpp_table.py` 读的是冻结快照
  `_cpp_tables.txt`）。
- **2026-09-20 条目改名连带**：守卫 `PAT_RE`/`BLOB_RE` 的条目名字符类由 `\w+` 放宽到
  `([A-Za-z0-9_.,+-]+)`（名字含 `. + - ,`，否则**静默解析成 0 条**）；`point_of()` 改为按
  `fs_cp_<功能名>_<版本范围>` 正则取功能前缀；`fs_fw_audit.py` 的 `FS_PAT_RE`/`FS_BLOB_RE` 同步放宽。
  另新增语料核对：`D:/Game/NS/firmware/_audit/_map_variants.py`（从 26 份 fs 二进制算每条覆盖）与
  `_check_name_ranges.py`（断言名字里的范围 == 实测覆盖 + 族内不相交 ⇒ **31 条 / 14 族 / 0 重叠**）。

### 7.3 守卫实测（改动后）

```
patch_utf8_to_utf16        0xEC/0x170   余 132
patch_utf16_to_utf8        0x8C/0x1D0   余 324   (+0x10：1 字节分支补的 NUL)
patch_is_oem_mb_char       0x48/0x50    余   8   ← O4 不再是零余量
patch_str_unicode2oem      0xEC/0x120   余  52   (+0xC：逐字符判界)
patch_stringdesc_toupper   0x94/0xB0    余  28
patch_widechar_compare     0x308/0x360  余  88   (P1-1 折叠改为 c-0x20)
patch_fat_getnextchar      0x1E8/0x240  余  88
```

### 7.4 仍未做

- `_audit/_p28_bound_test.py`（离线边界用例：长度 {511,512,513,514} × 缓冲 {512,513}）—— 判界逻辑
  已在源码注释与 §3.3 里写成不变量，但还没有可执行证据。
- §5 的差分口径改造（行为级三者比较 + 差异白名单）—— 4 字节字符不做之后优先级下降。
- P1-2（4 字节 UTF-8 → 代理对）：**有意不做**（产品取舍）。

---

## 附：本次复核的 Ghidra 证据索引（19.0.1 exfat，base `0x7100000000`）

| 对象 | 地址 | 用途 |
|---|---|---|
| `FAT_GetNextChar` | `0xF44E0` | p05/p17 原始语义、4 点集中块 |
| `FAT_MatchWildcardRecursive` | `0xF4770` | p11–p26 原始语义、`+0xffe0`、OEM 界 `0xB` |
| `FAT_MakeShortName` | `0xF5AC0` | `subs w23,w23,#2` 死循环路径、512 B 栈缓冲 |
| `FAT_GetNextPathComponent` | `0xF4BC0` | p06 `add #1` 的"额外字节数"语义 |
| `FAT_ReplaceShortNameNumber` | `0xF6270` | 用宽度回调，安全 |
| `PFCODE_Str_Unicode2OEM` | `0xF5840` | 无界循环（H1） |
| `PFCODE_Str_OEM2Unicode` | `0xF5960` | 镜像实现，宽度驱动 |
| `StringDesc_ToUpper` | `0xF7C10` | 唯一调用者 `FAT_GetFsDrvByPath` |
| `PFCODE_CP932_OEM2Unicode` | `0xFEAC0` | ctx `+0x18`，p03 目标 |
| `PFCODE_CP932_Unicode2OEM` | `0xFEC30` | ctx `+0x20`，p02 目标 |
| `PFCODE_CP932_isOEMMBchar` | `0xFEE40` | ctx `+0x30`，p04 目标 |
| `PFCODE_CP932_OEMCharWidth` | `0xFEE00` | ctx `+0x28`，直接调 `+0x18` |
| `PFCODE_CP932_UnicodeCharWidth` | `0xFEE90` | ctx `+0x38`，恒 2 |
| `PFCODE_CP932_isUnicodeMBchar` | `0xFEEA0` | ctx `+0x40`，恒 false |
| `PFCODE_ConvertWidth` / `GetConvertWidth` | `0xF7CE0` / `0xF7CF0` | 返回值契约 |
| 上下文指针槽 | `0x710024EB50` → `0x7100FCFC38` | `.bss`，运行期填充 |

构建期守卫本次实测（`check_patch_sizes.py`，全绿 —— 这是**改动前**的快照，改动后的数字见 §7.3）：

```
patch_utf8_to_utf16        0xEC/0x170   余 132
patch_utf16_to_utf8        0x7C/0x1D0   余 340
patch_is_oem_mb_char       0x50/0x50    余 0     ← P2
patch_str_unicode2oem      0xE0/0x120   余 64
patch_stringdesc_toupper   0x94/0xB0    余 28
patch_widechar_compare     0x31C/0x360  余 68
patch_fat_getnextchar      0x1E8/0x240  余 88
```
