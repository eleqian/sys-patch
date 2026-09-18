# UTF-8 中文路径补丁 —— 方案与实现（定稿）

> 状态（2026-09-18 实测）：系统正常启动 ✓；文件管理器**能看到中文名** ✓；
> **能打开并读取** `F:\test\test2\test中文.txt` ✓；构建期守卫全绿 ✓。
> 目标固件：`19.exfat.FS.kip1`（Ghidra 分析基址 0x7100000000，**运行时地址随机化，该基址仅用于分析**）。
>
> ⚠️ **本文档 §1–§7 的 fs 偏移是 2026-09-17 定稿时的"逻辑清单"（按原版二进制标定），
> 仅用于解释"改什么、为什么"。实现形态此后又走了两步：**
> - **P1（2026-09-18）**：全部改点已 **pattern 化，运行时无任何硬编码 fs 偏移**
>   （二级表 `fs_fn_groups[12]` + `fs_cp_patterns[]`/`fs_codepage_blobs[]`，由 `PATTERNS.json` 机械生成）。
>   §3.3 / §4 / §8 里"固定落在 `fs+0xf5840`、页 `0xf5000`""ADRP 只允许槽 +0x159000/+0xb50"等
>   **静态假设已全部作废**，改为**现场收割**。本文档不再逐条维护这些细节 ——
>   当前形态以 `AGENTS.md`（FS codepage patch 一节）与 `补丁点合并优化分析.md` §8 为准。
> - **M6（2026-09-18）**：`FAT_MatchWildcardRecursive` 的 p18–p26 已改为**整函数替换**
>   （见 §3.5 与 `补丁点合并优化分析.md` §13）。§6 里"整体替换 856 字节递归匹配器…风险高"的
>   取舍说明**已被推翻**（差分验证通过后实施）。

---

## 1. 原理

原版 fs 的路径字节在 "OEM 通道" 内**不透明流转**，编码转换只发生在两个边界各一次：

```
应用（UTF-16）
   │  Unicode → OEM（per-char PFCODE_CP932_Unicode2OEM / 字符串级 PFCODE_Str_Unicode2OEM）
   ▼
fs 内部：OEM 字节串（FAT 侧按 CP932 假设逐字节/双字节步进、比较、拼名字）
   │  OEM → Unicode（per-char PFCODE_CP932_OEM2Unicode / 字符串级 Str_OEM2Unicode）
   ▲
目录项（LFN 以 UTF-16 存储）
```

对非 CP932 字节（中文 UTF-8 的高位字节），原版行为是**抑制**：

- 转换器把它们换成 `'_'`；
- `IDirectory_Read` 里有一处判定会**丢弃含 ≥0x7F 字节的列举结果**（`0xd4af4`）。

因此"看不到中文名、打不开中文路径"是两个独立现象，本补丁分别处理：

| 现象 | 处理 |
|---|---|
| 列表里中文名不出现 | NOP 掉 `0xd4af4` 的判定 + 转换器改成 UTF-8 语义 |
| 中文名可见但 `FsError_PathNotFound` | 修正所有"按 CP932 **双字节**假设步进"的调用点，并让 `isOEMMBchar` 按 `idx` 区分语义 |

**核心设计**：把 CP932 的 2 字节模型整体平移到 UTF-8 的 1~4 字节模型。

---

## 2. 补丁清单（逻辑 16 处 / 29 个补丁点；P1 后落为 22 pattern + 8 blob = 30 条条目）

> 下表是**逻辑清单**（按 19.exfat 标定的原版偏移，用来解释改动的语义）。
> P1 后运行期不依赖这些偏移：条目按 `PATTERNS.json` 生成的字节模板定位。
> M6 后 §2.1 的 `FAT_MatchWildcardRecursive` 一行由"11 处调用点改写"变为**1 处整函数替换**。

### 2.1 函数级替换（整函数写入，**6** 处）

| fs 偏移 | 目标 | 替换为 | 尺寸 / 洞 | 要点 |
|---|---|---|---|---|
| `0xfeac0` | `PFCODE_CP932_OEM2Unicode` | `patch_utf8_to_utf16` | 0xEC / 0x170 | UTF-8 → UTF-16，逐字节续字节校验 |
| `0xfec30` | `PFCODE_CP932_Unicode2OEM` | `patch_utf16_to_utf8` | 0x7C / 0x1D0 | UTF-16 → UTF-8；**返回值约定**：高 16 位=输出字节数、低 16 位=输入字节数（与原版 `0xf7cf0` 宽度 helper 逐位一致） |
| `0xfee40` | `PFCODE_CP932_isOEMMBchar` | `patch_is_oem_mb_char` | **0x50 / 0x50** | 见 §3.2（按 idx 双语义），尺寸顶格 |
| `0xf5840` | `PFCODE_Str_Unicode2OEM` | `patch_str_unicode2oem` | 0xE0 / 0x120 | 字符串级转换 + **512 字节输出上限**（修 `lname[513]` 溢出），内联 UTF-16→UTF-8 |
| `0xf7c10` | `StringDesc_ToUpper` | `patch_stringdesc_toupper` | 0x94 / 0xD0 | OEM 分支改 ASCII-only 大写（原版对 signed char 调 toupper 属未定义行为） |
| `0xf4770` | `FAT_MatchWildcardRecursive` | `patch_widechar_compare` | 0x35C / **0x360（顶格）** | **M6**：折叠 p18–p26 共 12 条 `wide_cmp` 指令条目为一次整函数替换；编码域感知的 `*`/`?` 通配符匹配 + 递归回溯。仅 `wide_cmp=1` 应用，`stage_idx=2`。见 §3.5 |

### 2.2 调用点改写（11 处）

| fs 偏移 | 所在函数 | 原指令 → 补丁 | 语义 |
|---|---|---|---|
| `0xd4af4` | `IDirectory_Read` 内 | `b.cc` → `nop` | 不再丢弃含高位字节的名字 |
| `0xf45d8` | `FAT_GetNextChar` 内 | `add x9,x8,#1` → `add x9,x8,x0`；`ldrb`→`ldrh`；`strb`→`sturh` | 步进改用 isOEMMBchar 返回值（额外字节数；外层循环另有 +1 ⇒ 总长） |
| `0xf4d8c` | `FAT_GetNextPathComponent` 内 | `add x9,x8,#1` → `add x9,x8,x0` | 同上（路径分量切分） |
| `0xf77e8` | `StringDesc_AddLeft` 内 | `cinc w8,w22,ne` → `add w8,w22,w0` | 字符数按"额外字节"累加 |
| `0xf7984` | `StringDesc_GetCharCount` 内 | `cinc x19,x19,ne` → `add x19,x19,x0` | 同上 |
| `0xf7a80` | `StringDesc_CompareUnicode` 内 | `csel x8,x19,x22,eq` → `add x8,x19,x0` | 同上 |
| `0xf7bd0` | `StringDesc_CompareOem` 内 | `csel x20,x20,x23,eq` → `add x20,x20,x0` | 同上 |
| `0xf4888` | `FAT_MatchWildcardRecursive` #1 | `add w10,w9,#1` → `add w10,w9,w0` | w9 已是 idx+1 ⇒ idx+1+额外 = **idx+总长** |
| `0xf49c4` | `FAT_MatchWildcardRecursive` #2 | `add w8,w25,#2` → **`add w8,w27,w0`** | 该点基址是 idx 本身，单指令做不出 `idx+w0+1`；**x27 在 0xf49a4 已算好 idx+1 且 callee-saved** ⇒ 改用它作基址 |
| `0xf4a90` | `FAT_MatchWildcardRecursive` #3 | `add w10,w9,#1` → `add w10,w9,w0` | 同 #1 |
| `0xf5dcc` | `FAT_MakeShortName` 内 | `mov w23,w0` → `mov w23,#2` | 防止宽度 3/4 时 `subs w23,#2` 永不归零的死循环；短名空间估算退回 2 字节/字 |

> FAT32（非 exFAT）路径的整块补丁仍注释保留在 `main.cpp`（`mem_info.addr + 0xced30`），未启用。

---

## 3. 六个替换函数的实现要点

### 3.1 ASLR 纪律（硬性）

这些函数会被**原样拷进 fs 进程执行**，而模块加载地址是**随机**的：

- ❌ 禁止绝对地址（Ghidra 的 `0x7100xxxx` 只在分析时有意义）、禁止 `(uintptr_t)&函数名`
  （本工程 `-fPIE` 下 GCC 会走 `.data.rel.ro` 指针槽，实测反汇编为 `adrp; ldr`）；
- ❌ 禁止调用外部函数（`BL`）、禁止字面量池/外部数据引用、禁止跳出函数的 `B`；
- ✅ 需要 fs 全局时用 **PC 相对**取用。H1 取代码页上下文即原版同款：

```
0xb0000ac3  adrp x3, +0x159000   ; 相对"本指令所在页" → fs+0x24e000
0xf945a863  ldr  x3, [x3, #0xb50]; → fs+0x24eb50 = 代码页上下文指针
```
  页增量是编译期常量：该函数固定落在 `fs+0xf5840`（页 `0xf5000`），洞约束保证不跨页。

### 3.2 `patch_is_oem_mb_char`：**必须按 `byte_idx` 区分两种语义**

| idx | 语义 | 返回 |
|---|---|---|
| 1 | 该字节是不是多字节**首字节** | **额外字节数**（0=ASCII/续字节；1/2/3 对应 2/3/4 字节字符） |
| 2 | 该字节是不是合法的**第二个字节** | 1 = 合法（UTF-8 续字节 0x80–0xBF），0 = 非法 |

`idx=2` 是 `FAT_GetNextPathComponent` 的尾字节校验，返回 0 会**直接走 PathNotFound**：
忽略 idx 会让"中文名能枚举但打不开"（已踩坑，见 `re_path_not_found_2026-09-15.md`）。

取值表（主机 gcc 实测）：

| 字节 | idx=1 | idx=2 |
|---|---|---|
| 0x00–0x7F | 0 | 0 |
| 0x80–0xBF | 0 | **1** |
| 0xC0–0xDF | 1 | 0 |
| 0xE0–0xEF | 2 | 0 |
| 0xF0–0xF7 | 3 | 0 |
| 0xF8–0xFF | 0 | 0 |

`idx=1` 的额外字节数用 `clz((~c & 0xFF) << 24) - 1` 计算（比逐段比较省 12 字节，才塞进 0x50 的洞）。

### 3.3 H1（`patch_str_unicode2oem`）完全自包含

- 普通模式：**内联** UTF-16→UTF-8（等价于 `patch_utf16_to_utf8`），不再调用 `ctx+0x20` 回调；
- 特殊映射模式（MakeShortName 生成 8.3 占位名）：**直接比较 u16**（`'.'`/`' '`/其余→`'_'`），
  不再调用 fs helper `0xde560`；
- 输出上限 512 字节 + NUL，`>`170 个 CJK 字符的长名会被截断（可接受权衡）。

### 3.4 R4（`patch_stringdesc_toupper`）

- `StringDesc` 布局：`ptr_left@0x00`、`ptr_right@0x08`、`encode_type@0x10`（`ENCODE_OEM=1`）；
- OEM 分支只对 `'a'–'z'` 大写，≥0x80 原样保留；Unicode 分支与逐字符大写；
- 两分支都受 `maxLen` 限制并以 NUL 收尾，非 OEM 分支写 u16（与原版两字节/字符一致）。

### 3.5 M6（`patch_widechar_compare`）—— 唯一的「整函数替换」型 M6 实现

- **折叠范围**：p18–p26 共 12 条 `wide_cmp=true` 的指令条目（值构造 `lsl #16`、去 `and #0xffff`、
  去 `cmp … uxth`）+ R1b 的 3 处 `ldrh`，全部由一份实现取代。p11–p16（`wide_cmp=0`）**保留为回退**。
- **入参口径**（差分反证出来的）：`M6(name0 /*x1*/, nd /*x2*/, pat0 /*x3*/, ps /*x4*/)`，
  其中 `name0` 是 `FsNameDesc16 {u64 data; u16 enc; u16 pos; u32 pad}`，
  `ps` 是 `FsPatStream24 {u64 cur; u64 end; u64 mode}`（`mode` 低 32 位 = 宽度，1→1 字节读，否则 2 字节）。
  比较口径 `value = (b0<<16) | (b2<<8) | b1`（即 R1c）。
- **位置无关**：禁宽常量/字面量池/外部 `BL`；ctx 槽与外部 callee（宽度 helper）各用一对哨兵，
  由 patcher 从**原函数字节**现场收割后重编码（`x3` / `x9`），**失败则整点跳过、原函数不动**。
  自递归 `bl patch_widechar_compare` 是 PC 相对编码，显式允许。
- **等价性证据**：`_audit/_m6_oracle.py` 用 unicorn 把真实 `.text` 映射到原地址，
  对打补丁后的原函数与新实现喂同一组输入 —— 3 形状 × 3000 例 = **9000/9000 完全一致**。
- **定位**：两条**入口对齐**模板（AB 家族 40 B / C 家族 36 B），族内取交集、PC 相对字通配；
  22 份二进制上各命中 1 次或 0 次。**不依赖任何版本偏移。**
- **尺寸**：820 字节（`0x334`），洞预算最紧的形状 A 为 `0x360`（864）。
- 细节与实施记录：`补丁点合并优化分析.md` §13。

---

## 4. 构建期守卫（`sysmod/tools/check_patch_sizes.py`，make 钩子自动运行）

`make` 时自动执行，任一失败即中断构建。三类校验：

1. **尺寸/标签**：`patch_*` 函数放在 `.text.<名>` section、函数体后放 `<名>_end` 标签，
   校验"标签距离 == ELF `st_size`"且 ≤ 目标补丁位空洞
   （依赖 `-fno-toplevel-reorder`：否则 GCC 提前发射顶层 asm，尺寸恒 0）。
2. **指令编码**：自动解析 `main.cpp` 每个 `fs_patch_function` 点，被改动的 32 位字只允许
   `nop` / `movz`（Rd 与原指令一致）/ `add Rd,Rn,w0`（**imm6=0、shift=0、Rm=w0、Rd/Rn 不变**）/
   同址访问宽度改写。**手写机器码最易错的正是这里**（历史上 4 处把立即数编码当移位寄存器用，
   导致崩/挂死）。具名例外：`RN_OVERRIDE = {0xF49C4: 27}`（换基址寄存器，理由随代码注释）。
3. **ASLR 位置无关性**：扫描 **6** 个替换函数机器码，禁止 MOVZ/MOVK 宽常量（≥0x1000000）、
   `LDR` 字面量池、**外部 `BL`**、跳出函数的 `B`；`ADRP` 只允许「自相对 +ADD」或
   「收割出来的数据槽 + 配对 `ldr`」。**P1 之后不再允许任何硬编码槽地址** ——
   旧版"槽固定在页 0xf5000 / +0x159000"的断言已删除（实测该槽有 14 个不同取值）。

> **P1/M6 后新增的校验**（同一脚本内）：`fs_fn_groups[]` 区间精确覆盖且非空；谓词表自洽
> （`FS_PRED_COUNT` ↔ `fs_pred_names[]` ↔ `fs_pred_mask()` 位号，且 `fs_pred_names[pred_idx] == cond`）；
> 每条 pattern 在参考二进制上**唯一命中**且落点满足 `cond`、`(hit+inst_offset)%4==0`；
> blob 条目的模板命中点 == 声明入口；**哨兵按内容校验**（各出现一次、成对相邻、有序）；
> **callee 收割校验**（函数体内出界 `bl` 的**不同目标数 == 1**）。

可选：设置 `$FS_KIP1` 指向 fs 二进制时，逐点比对 `cmp` 字节，防偏移/固件不匹配。

---

## 5. 排障与开关

`config.ini`：

```ini
[options]
fs_codepage=1          ; 0 = 完全跳过 fs 编码补丁（其余 sys-patch 补丁照常）→ 救砖
[fs_codepage]
stage=6                ; 逐组应用：0=都不应用 1=+转换器 2=+FAT调用点 3=+R1 4=+R2 5=+H1 6=全部
```

日志（`/config/sys-patch/log.ini`）关键字段：`[debug] fs_codepage`（附加前写入的 start 标记）、
`[debug] fs_codepage_patch_result`（最后到达的组名 / 失败原因 / `success`）、`[debug] tmp_addr`
（**运行时发现的 fs 基址**，可用来核对 ASLR）。

**铁律**：`svcDebugActiveProcess()` 之后目标进程（fs）处于挂起状态，**此时不能写日志/SD**
（必经 fs 服务）→ 会永久阻塞、开机卡 logo。进度只能先记内存、脱附后再落盘。

---

## 6. 已知限制与后续方向

1. **同名误判（最重要）**：匹配函数只拼出 2 字节比较值（`首字节<<8 | 第一个续字节`），
   3 字节汉字只比较高 10 位 ⇒ **`U>>6` 相同即视为同一字符**。

   | UTF-8 形态 | 参与比较 | 碰撞条件 |
   |---|---|---|
   | ASCII | 1 字节（'a'-'z' 折叠大写） | 无 |
   | 2 字节（U+0080–07FF） | 全部 | 无 |
   | **3 字节（U+0800–FFFF，全部汉字）** | 仅高 10 位 | 同一 64 码位块内**全部同名** |
   | 4 字节（emoji） | 仅高 8 位 | 同一 4096 块内同名 |

   实测：常用汉字区 U+4E00–9FA5 共 20902 字，被分成 **327 组、每组 64 字**互相同名
   （`中`≡`一`≡`丁`≡`七`≡`三`…；`历`≡`厉`）。后果：**`中文.txt` 与 `一文.txt` 在 fs 看来是同一个文件**。

   **会出什么事**：枚举/显示用的是 LFN 的 UTF-16 名（看起来完全正常），但按名字的
   **打开/删除/重命名/覆盖/复制**都可能命中"比较值相同"的另一个文件 → **静默操作到错误文件**
   （数据丢失级风险）；创建时也可能被判为"已存在"。

   **规避（立即可用，零风险）**：
   - 工具 `fs_encode_fix/_name_collision_check.py`：扫描目录，报告"fs 视角同名"的名字；
     `--explain 中文.txt` 可看某个字的全部同值字符。
   - 命名规则：同一目录内避免出现"逐字符比较值相同"的两个名字；最简单是加 ASCII 后缀
     （如 `报告1.docx` / `报告2.docx`），或换用不同码位块的字。

   **为什么不能靠改编码规避**：2 字节承载不了 16 位码位，任何"让前两字节唯一"的编码变换都不存在
   （换顺序只会把碰撞搬到别的位上）；把 OEM 形式 ASCII 化虽能消除碰撞，但名字长度翻倍会触发
   `lname[513]` 截断、路径超长等更严重问题。

   **已实施的两步修复（R1b / R1c）**：

   | 步骤 | 内容 | 效果（常用汉字区实测） |
   |---|---|---|
   | **R1b** | 匹配器 3 处内联取字符 `ldrb` → `ldrh`（`0xf4894`/`0xf49cc`/`0xf4a9c`），与 `FAT_GetNextChar`(0xf45e8) 早已改过的 `ldrh` 口径统一 ⇒ 第 3 字节进入比较值 | 同值组 327 → 1424，最大同值字数 64 → 48（`中` 与 `一` 可区分） |
   | **R1c** | 比较值扩到 **24 位**：`value = (b0<<16) \| (b2<<8) \| b1`（1~3 字节字符完整、单射） | **同值组 327 → 20902，最大同值字数 1 ⇒ 汉字零碰撞** |

   R1c 共 10 处（开关 `[fs_codepage] wide_cmp=0` 可退回 R1b 行为）：
   - A. 值构造 `orr wN,w8,wN,lsl #8` → `#16`：`0xf45ec`（FAT_GetNextChar）、`0xf4898`、`0xf49d0`、`0xf4aa0`
   - B. 去掉 16 位掩码 `and w8,wN,#0xffff` → `mov w8,wN`：`0xf47f4`、`0xf48c0`、`0xf480c`、`0xf4918`
   - C. 去掉比较时的扩展 `cmp w8,wN,uxth` → `cmp w8,wN`：`0xf4810`、`0xf491c`
   - 未改：`0xf47dc`/`0xf497c`/`0xf4a48`（全角折叠判定，对汉字是空操作）、`0xf492c`（来自 ctx 的字段，非比较值）

   **残留**：4 字节字符（emoji 等）仍只取前 3 字节，同一"前 3 字节"的不同字符会撞
   （要彻底需再读满 4 字节，待做）。`_name_collision_check.py --mode wide` 已按新口径扫描。

   **方案取舍说明（已更新，2026-09-18）**：原先计划的 (b)「匹配后加二次确认」经查**不成立**——
   匹配器唯一外部调用点 `0xf411c` 在 `bl` 后直接走尾声返回结果，没有"候选→确认"环节；
   (a)「整体替换 856 字节递归匹配器」当时因"需复刻通配/折叠/递归语义且 C 重写可能超过函数自身的洞"
   被判风险高。**该判断已被推翻并实施**：先用 unicorn 做**可执行差分**（9000/9000 一致）证明
   语义等价，再落地（洞预算实为 `0x360`–`0x380`，实现 820 字节）—— 见 §3.5 与
   `补丁点合并优化分析.md` §13。R1b+R1c 的定点改写**保留**，作为 `wide_cmp=0` 的回退路径。
   故 **`wide_cmp=1` 时汉字零碰撞；`wide_cmp=0` 时仍退回 R1b/R1c 的 2 字节口径**。
2. **4 字节字符（emoji 等）**：转换器已支持（额外字节数 3），但匹配仍是 2 字节 → 同上。
3. **FAT32 8.3 短名**：`R2` 只是把宽度钳到 2 避免死循环，短名空间估算仍按 CP932 行为；
   若要 PC 侧正确识别短名，可选"方案 C"（仅 `FAT_MakeShortName` 输出 GBK 短名，远期）。
4. **半角片假名**：CP932↔UTF-8 round-trip 会丢失（历史方案已记录，属已知取舍）。
5. **换固件版本**：全部改点已 pattern 化，**定位无需重推**（模板跨 16.1.0–22.5.0 共 22 份验证通过）。
   仍需重推的只有**收割类**事实：ctx 槽 / 外部 callee 的**原始编码**（由 `fs_harvest_*` 运行时解出，
   离线复核脚本 `_audit/_m6_harvest_check.py` 覆盖）；以及 guard 里 `FUNCTIONS` 表的**洞尺寸**。

---

## 7. 复现与验证清单

```bash
# 1) 构建（自动跑守卫）
make                     # DEVKITPRO 需设置；产物 out/atmosphere/contents/420000000000000B/exefs.nsp

# 2) 单独跑守卫
make check-patch-sizes
#   FS_KIP1=<path/19.exfat.FS.kip1> make check-patch-sizes   # 附带 cmp 字节比对

# 3) 离线三件套（P1/M6 必跑；脚本在 D:/Game/NS/firmware/_audit/，用 managed venv 的 python）
python _verify_cpp_table.py     # 表 == PATTERNS.json（30 条）+ 506/506 站点 == RESOLVED
python _p1_sim_scan.py          # 端到端：22/22 份固件，命中集合/站点/写入次数一致
python _m6_harvest_check.py     # M6 定位 + ctx/callee 收割 + 地址重编码往返，22/22 通过

# 4) 部署：拷贝 exefs.nsp 到 SD 的 atmosphere/contents/420000000000000B/
# 5) 上机检查 log.ini 的 [debug] fs_codepage_patch_result 应为 success
```

验收：① 启动正常；② 列举可见中文名；③ 打开/读取中文文件成功；
④ 新建/重命名中文名；⑤ 英文名功能无回归（这一项由 `stage` 逐级验证过）。

---

## 8. 关键常量速查

| 项 | 值 |
|---|---|
| fs 镜像基址（分析用） | `0x7100000000`（**运行时随机，勿写死**） |
| fs 文件偏移换算 | 文件偏移 = `0x100 + (VA − 0x7100000000)` |
| 代码页上下文 GOT 槽（分析用，**已不写死**） | 19.exfat = `fs + 0x24EB50`；22 份实测 **14 个取值**（16.1.0=0x2797D0、17.0.0=0x23BE90、18.x=0x23D138、19.0.1/fat32=0x240B50、20.x=0x263F40、21.x=0x25CBC8、22.x=0x25FC38）⇒ 运行时由 `fs_harvest_ctx_pair()` 从原函数现场收割 |
| per-char 回调槽 | 上下文 `+0x18`(OEM2Uni) `+0x20`(Uni2OEM) `+0x30`(isOEMMBchar) |
| 模式标志 | 上下文 `+0x48` bit1 = 特殊映射模式 |
| 补齐函数返回值约定 | 高 16 位 = 输出字节数；低 16 位 = 输入字节数 |
| 六个替换函数尺寸 | 0xEC / 0x7C / **0x50（顶格）** / 0xE0 / 0x94 / **0x334（M6，820 B）** |
| 表规模（P1+M6 后） | `fs_fn_groups[12]` + `fs_cp_patterns[22]` + `fs_codepage_blobs[8]`，谓词 11，覆盖 29 个补丁点 |
| M6 定位模板 | `fs_cp_p18_wc_func_replace_a`（AB 家族 20 份，40 B）/ `_b`（C 家族 16.1.0，36 B），入口对齐 |

### 相关文档
- 事故复盘：`re_boot_hang_2026-09-15.md`（卡 logo：机器码错误 / 绝对地址 / 日志死锁）
- 打不开复盘：`re_path_not_found_2026-09-15.md`（idx 语义 + 步进少 1）
- 结构体权威：`fs_structs.h`；分析结论：`re_analysis.md`；改进计划：`re_improve_plan.md`
