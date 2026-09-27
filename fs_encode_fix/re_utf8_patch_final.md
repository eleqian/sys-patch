# UTF-8 中文路径补丁 —— 方案与实现（定稿）

> 状态（2026-09-20）：系统正常启动 ✓；文件管理器**能看到中文名** ✓；**能打开并读取**中文路径 ✓；
> 构建期守卫全绿 ✓；离线验证全绿（26/26 端到端、扫描优化新旧等价、M6 对**原版 0 补丁**的可执行差分）✓。
> 目标固件：`19.exfat.FS.kip1`（Ghidra 分析基址 0x7100000000，**运行时地址随机化，该基址仅用于分析**）。
>
> **本文只描述当前（最终）形态。** 实现是**全 pattern 驱动、运行时零硬编码 fs 偏移**：定位靠字节
> 模板，改写靠语义等价规则，寄存器/地址/宽度**从命中点继承**。因此：
> - §1–§7 里按原版二进制标定的 fs 偏移（如 `0xf5840`、页 `0xf5000`）**只是“逻辑清单”**，
>   用于解释“改什么、为什么”，运行时**不依赖**它们；§3.3/§4/§8 里任何“固定在页 X / 槽 +Y”的
>   静态假设一律作废 —— fs 全局槽与外部 callee 全部**现场收割**（失败整点跳过）。
> - 七个整函数替换（§3.5 / §3.6 与 §2.1）已取代原先的逐指令写法。
> - 扫描侧有三项由数据推导的优化（族内互斥兄弟退役 / 全族落定空转退出 / blob 车道快筛），
>   等价性由 `_audit/_opt_equiv.py` 在 26 份固件上逐条验证。
> - **为什么**是这样、以及过程中被推翻的结论，全在 `补丁点合并优化分析·演进史.md`（§1–§20）；
>   设计现状速查见 `../补丁点合并优化分析.md`。

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

## 2. 补丁清单（逻辑 16 处 / 29 个补丁点；当前落为 **15 条指令条目 + 16 条整函数替换 = 31 条**，覆盖 **26 份 fs 变体**）

> 下表是**逻辑清单**（按 19.exfat 标定的原版偏移，用来解释改动的语义）。
> 运行期不依赖这些偏移：条目按字节模板定位（`fs_codepage.cpp` 的两级表 `fs_fn_groups[]`
> → `fs_inst_patches[]` / `fs_blob_patches[]`）。
> `FAT_MatchWildcardRecursive` 与 `FAT_GetNextChar` 的逐点改写现已由**整函数替换**取代。
>
> **条目数 ≠ 补丁点数**：整函数替换把该函数内的所有点折叠成 1 条；而**跨代变体族**
> （14.1.2/15.0.1 属另一代代码生成：寄存器重分配 + 局部重排）需要各自追加条目。
> 综上：14 个补丁点 → 31 条条目，每份固件实际落地 14 条。
>
> **条目命名（2026-09-20 起）**：`fs_cp_<功能名>_<版本范围>`，版本范围沿用原版 sys-patch 的
> 字符串比较口径（`MAKEHOSVERSION`/`FW_VER_ANY`）：闭区间 `a.b.c-d.e.f`、开区间 `a.b.c+`、
> 多段用逗号并列（如 `14.1.2,21.0.0+`）。**族号 = 版本范围之前的功能前缀**（不再有 `pNN` 编号）；
> 名称里的范围是**实测**的固件覆盖（语料 26 份），不是估计值。**不加**条目级固件版本字段 ——
> 运行期仍是「pattern 命中 + 族内互斥兄弟退役」，名字里的范围只作可读标注。
> 格式的机器可读性由构建守卫 `check_patch_sizes.py` 的 `NAME_RE` 兜底。

### 2.1 函数级替换（整函数写入，**7** 处）

| fs 偏移 | 目标 | 替换为 | 尺寸 / 洞 | 要点 |
|---|---|---|---|---|
| `0xfeac0` | `PFCODE_CP932_OEM2Unicode` | `patch_utf8_to_utf16` | 0xEC / 0x170 | UTF-8 → UTF-16，逐字节续字节校验 |
| `0xfec30` | `PFCODE_CP932_Unicode2OEM` | `patch_utf16_to_utf8` | 0x8C / 0x1D0 | UTF-16 → UTF-8；**返回值约定**：高 16 位=输出字节数、低 16 位=输入字节数（与原版 `0xf7cf0` 宽度 helper 逐位一致）；**三条分支都写满 `[0..2]`**，1/2 字节分支的 NUL 分别落在 `[1]`/`[2]` —— 1 字节分支的 NUL 必须在 `[1]`（原版 `strb wzr,[x1,#1]`），只写 `[2]` 会把紧随的 `[1]` 留给旧字节 |
| `0xfee40` | `PFCODE_CP932_isOEMMBchar` | `patch_is_oem_mb_char` | 0x48 / 0x50（余量 8 B） | 见 §3.2（按 idx 双语义） |
| `0xf5840` | `PFCODE_Str_Unicode2OEM` | `patch_str_unicode2oem` | 0xEC / 0x120 | 字符串级转换 + **512 字节输出上限**（修 `lname[513]` 溢出；见 §3.3），内联 UTF-16→UTF-8 |
| `0xf7c10` | `StringDesc_ToUpper` | `patch_stringdesc_toupper` | 0x94 / 0xB0 | OEM 分支改 ASCII-only 大写（原版对 signed char 调 toupper 属未定义行为） |
| `0xf4770` | `FAT_MatchWildcardRecursive` | `patch_widechar_compare` | 0x308 / 0x360（余 88 B） | **M6**：折叠该函数全部 15 个指令点为一次整函数替换；编码域感知的 `*`/`?` 通配符匹配 + 递归回溯。见 §3.5 |
| `0xf44e0` | `FAT_GetNextChar` | `patch_fat_getnextchar` | 0x1E8 / 0x240（余 88 B） | **M8**：折叠该函数里步进/读宽/写宽 + 24 位值构造（原 4 个相邻指令点）为一次整函数替换；入口 24 B 前缀无通配。见 §3.6 |

> 入口地址 = 19.0.1/exfat 上由构建期守卫核对过的**真实函数入口**（前一函数收尾 + 填充之后）。
> 注意 `fs_fn_groups[]` 注释里旧的 `0xf45c0`/`0xf4764` 是陈旧值，已按守卫实测改为 `0xf44e0`/`0xf4770`。

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

> FAT32（非 exFAT）路径的整块补丁（当年那个 `mem_info.addr + 0xced30` 的注释稿）已删除：
> 现在两条路径都由同一套 pattern 覆盖，不再需要按文件名长度分流的手工补丁。
>
> **★ 折叠情况**：上表 11 行里，`0xf45d8`（`FAT_GetNextChar`）已并入 §2.1 的 M8 整函数替换，
> `0xf4888` / `0xf49c4` / `0xf4a90`（`FAT_MatchWildcardRecursive` #1–#3）已并入 M6，
> 这 4 行不再有独立条目；其余 7 行各对应一个指令改写补丁点（IDirectory_Read、
> FAT_GetNextPathComponent、StringDesc_AddLeft / GetCharCount / CompareUnicode / CompareOem、
> FAT_MakeShortName），因跨版本变体族而展开为 15 条 pattern 条目。

---

## 3. 七个替换函数的实现要点

> **共享对象视图 `StringDesc`**（2026-09-20）：`StringDesc`、字符迭代器、模式流三种 fs 对象的
> **内存布局完全相同**（`+0x00`/`+0x08` 各 8 字节字段，`+0x10` 一个 8 字节槽），原先分别声明为
> `FsStrDescLite` / `FsCharIter` / `FsPatStream24`。现统一成**单一 24 B 结构 `StringDesc`**
> `{void *ptr_left; void *ptr_right; u32 encode_type; u32 reserved;}`，按 fs 原型命名，**不用 union**。
> 三处 `+0x10` 本就是同一个「编码/宽度」选择子（`==1` 单字节 / `ENCODE_OEM`），无需别名；
> 显式写出 `+0x14` 保留字段使结构体恰为 24 B、**无尾部填充**（整对象拷贝 `*ps` 的字节数确定）。
> `static_assert` 锁死尺寸与四个偏移。`FsNameDesc16`（16 B）是**另一种**布局，保持独立、不合并。

### 3.1 ASLR 纪律（硬性）

这些函数会被**原样拷进 fs 进程执行**，而模块加载地址是**随机**的：

- ❌ 禁止绝对地址（Ghidra 的 `0x7100xxxx` 只在分析时有意义）、禁止 `(uintptr_t)&函数名`
  （本工程 `-fPIE` 下 GCC 会走 `.data.rel.ro` 指针槽，实测反汇编为 `adrp; ldr`）；
- ❌ 禁止调用外部函数（`BL`）、禁止字面量池/外部数据引用、禁止跳出函数的 `B`；
- ✅ 需要 fs 全局时用 **PC 相对**取用。H1 取代码页上下文即原版同款：

```
adrp x3, <page>        ; 相对"本指令所在页"
ldr  x3, [x3, #<off>]  ; → 代码页上下文指针
```
  **具体页/偏移不是常量**：26 份固件里该槽有 18 个不同取值。替换体用哨兵对
  `0xDEAD0001/2` 占位，运行时由 `fs_harvest_ctx_slot()` 从**原函数**里解出唯一的
  `adrp + 配对 ldr`，再按哨兵的真实地址重编码（失败整点跳过）。M6 另有外部 callee 用
  `0xDEAD0003/4` 占位（`fs_harvest_callee()`）。

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

`idx=1` 的额外字节数用 `clz((~c & 0xFF) << 24) - 1` 计算（比逐段比较省 12 字节）。
非法情形不另判：`c < 0xC0` ⇒ 结果 ≤ 0（有符号看是负数），`c ≥ 0xF8` ⇒ 结果 ≥ 4，两者都落进
同一个**无符号**比较 `(unsigned)extra < 4 ? extra : 0` ⇒ 再省 8 字节（`cmp`/`b.ls` 一对），
0x48 / 0x50 的 8 字节余量就是这么来的（此前顶格 0x50）。

### 3.3 H1（`patch_str_unicode2oem`）完全自包含

- 普通模式：**内联** UTF-16→UTF-8（等价于 `patch_utf16_to_utf8`），不再调用 `ctx+0x20` 回调；
- 特殊映射模式（MakeShortName 生成 8.3 占位名）：**直接比较 u16**（`'.'`/`' '`/其余→`'_'`），
  不再调用 fs helper `0xde560`；
- 输出上限 512 字节（含结尾 NUL；512 取 `lname[513]` 与 `FAT_MakeShortName` 512 B 栈缓冲的
  更窄者）。判界必须按**最坏单字符宽度**：循环条件 `(limit - out) >= 4` —— 每轮先确认「本字符
  最多 3 字节 + 结尾 NUL」都在缓冲内，收尾的 `*out = '\0'` 才必然落在最后一字节之内。
  只判 `out < limit` 是不够的：逐字节写入会让 `out` 越过 `limit` 1~2 字节、NUL 再越 1。
  `>`170 个 CJK 字符的长名会被截断（可接受权衡）。

### 3.4 R4（`patch_stringdesc_toupper`）

- `StringDesc` 布局：`ptr_left@0x00`、`ptr_right@0x08`、`encode_type@0x10`（`ENCODE_OEM=1`）；
- OEM 分支只对 `'a'–'z'` 大写，≥0x80 原样保留；Unicode 分支与逐字符大写；
- 两分支都受 `maxLen` 限制并以 NUL 收尾，非 OEM 分支写 u16（与原版两字节/字符一致）。

### 3.5 M6（`patch_widechar_compare`）

- **折叠范围 = 该函数全部 15 个指令点**（值构造 `lsl #16`、去 `and #0xffff`、
  去 `cmp … uxth`、R1 的三处步进、R1b 的三处访宽）全部由一份实现取代 —— 该函数**只剩整函数替换一条路径**。
- **入参口径**：`M6(name0 /*x1*/, nd /*x2*/, pat0 /*x3*/, ps /*x4*/)`，
  其中 `name0` 是 `FsNameDesc16 {u64 data; u16 enc; u16 pos; u32 pad}`，
  `ps` 是 `StringDesc`（`ptr_left=cur@0x00; ptr_right=end@0x08; encode_type@0x10`，
  `encode_type` 即模式流的 `mode` 低 32 位 = 宽度，1→1 字节读，否则 2 字节）——
  同一 24 B 布局被 `StringDesc` / 字符迭代器 / 模式流三个视图共用，见 `fs_codepage.cpp`
  的 `StringDesc` 定义与 `static_assert`。
  比较口径 `value = (b0<<16) | (b2<<8) | b1`（24 位）。
- **ASCII 折叠**：原版用 `mov wT,#0xffe0; add`，32 位相加的进位靠随后 `uxth`（16 位）比较丢掉
  ⇒ 等价于 `sub #0x20`。本实现是 32 位比较，必须**显式写 `c-0x20`**（`fold_ascii_upper`）——
  直接照抄 `+0xffe0` 会让进位留下，星号回溯路径匹配不到小写名（旧 15 点补丁的真实 bug）。
- **位置无关**：禁宽常量/字面量池/外部 `BL`；ctx 槽与外部 callee（宽度 helper）各用一对哨兵，
  由 patcher 从**原函数字节**现场收割后重编码（`x3` / `x9`），**失败则整点跳过、原函数不动**。
  自递归 `bl patch_widechar_compare` 是 PC 相对编码，显式允许。
- **等价性证据**：`_audit/_m6_sem_diff.py` 用 unicorn 把真实 `.text` 映射到原地址，**基线是原版 0 补丁**
  （不是旧的 15 点补丁集），穷举短串空间逐例比对；`_m6_fold_probe.py` 的 12 例定点探针里，
  当前实现与**原版 0 补丁全一致**（而旧 15 点补丁在 6 例上偏离原版）；`_m6_oracle.py` 另做抽样差分。
- **定位**：四条**入口对齐**模板（`fs_cp_widechar_compare_{17.0.0+,16.1.0,14.1.2,15.0.1}`，20 / 2 / 2 / 2 份），
  入口 = 实测 `0xF4770`。**不依赖任何版本偏移。**
- **尺寸**：`0x308`（776 B），洞 `0x360`（864 B）—— 余量 88 B（用 `_dump_blobs.py` 查看字节分布）。
- 细节与实施记录：`补丁点合并优化分析·演进史.md` §13 / §16 / §20。

### 3.6 M8（`patch_fat_getnextchar`）—— 第二个「整函数替换」

- **折叠范围**：`FAT_GetNextChar` 内的步进/读宽/写宽 + 同函数的 24 位值构造（共 4 个相邻指令点）。
- **算法**：与原版**逐句等价**的重写（不改行为，只改"按 CP932 双字节假设"为 UTF-8 语义）；
  与原版一致的怪癖照旧复刻（见 `patch_fat_getnextchar` 注释）。
- **定位**：两条**入口对齐**模板（公共 24 B 前缀无通配 / 变体前缀），48 个变体形状。
- **等价性证据**：`_audit/_m8_diff*.log` 差分 **10000/10000** 完全一致（5 个形状 × 2000 例，
  含边界：路径尾截断、续字节非法）。
- **尺寸**：488 字节（`0x1E8`），洞 `0x240`（576）—— 余量 88 B。
- **收割**：只依赖 ctx 槽（无外部 callee），哨兵对 A 一处。

---

## 4. 构建期守卫（`sysmod/tools/check_patch_sizes.py`，make 钩子自动运行）

`make` 时自动执行，任一失败即中断构建。三类校验：

1. **尺寸/标签**：`patch_*` 函数放在 `.text.<名>` section、函数体后放 `<名>_end` 标签，
   校验"标签距离 == ELF `st_size`"且 ≤ 目标补丁位空洞
   （依赖 `-fno-toplevel-reorder`：否则 GCC 提前发射顶层 asm，尺寸恒 0）。
2. **fs 补丁表结构 + 唯一命中**：从 `src/fs_codepage.cpp` 的
   `fs_fn_groups[]` / `fs_inst_patches[]` / `fs_blob_patches[]` **文本**里抽表
   （`--main` 由 Makefile 传入；条目格式必须保持 `PAT_RE`/`BLOB_RE`/`GROUP_RE`/`PRED_LIST_RE`
   可解析，解析不到就相当于"没检"）。检查项：谓词清单（X 宏 `FS_PRED_LIST` 里 `X(名字)` 的
   出现次序 = 位号，名字不重复、个数 ≤ 32；`fs_preds[]` / `fs_pred_mask()` 由同一宏展开，
   「位号 ↔ 名字」不可能脱节）、条目结构（pattern 语法/长度、`inst_offset` 范围与 4 字节对齐、
   `cond` 在谓词白名单里、`cond`/`patch` 配套）、
   尺寸恰好等于洞时报 **`ZERO SLACK` 告警**（能过，但下一次代码生成波动就变 `HOLE OVERFLOW`）、
   `fs_fn_groups[]` 区间**精确覆盖**两条表且组非空、**每条 pattern 在 fs `.text` 恰好命中 1 次**
   且落点是字对齐、且落点指令满足 `cond`、收割哨兵按内容各一次/成对/有序、
   callee 的**去重外跳目标数 == 1**。
   P3 起再加三条护"从数据推导出来的结构"的检查：**族内互斥**（同补丁点在参考固件上 ≤1 条命中）、
   **族名合规**（`fs_cp_<功能名>_<版本范围>`）、**blob 车道筛子可用**（偏移 0 或 4 至少一个确定字节）。
   > 旧的"每条手写机器码必须解码成合法改写（`nop` / `movz` / `add Rd,Rn,w0` …）"那一项
   > **随字节数组表一起消失了**：pattern 驱动之后没有手写指令字，`patch(inst)` 只在运行时
   > 应用语义等价的 `rules_*` 改写，所以那类"把立即数编码当移位寄存器用"的错法不再可能。
3. **ASLR 位置无关性**：扫描 **7** 个替换函数机器码，禁止 MOVZ/MOVK 宽常量（≥0x1000000）、
   `LDR` 字面量池、**外部 `BL`**、跳出函数的 `B`；`ADRP` **只允许「`adrp` + `add` 同寄存器」**
   这一种 PC 相对用法（自包含的模块内引用）。**P1 之后不再允许任何硬编码槽地址** ——
   旧版"槽固定在页 0xf5000 / +0x159000"的断言已删除（实测该槽在 26 份里有 **18** 个不同取值）。
   > P3 整理时连「允许 `adrp +0x159000 / ldr #0xb50` 直读该槽」的分支也一并删了 ——
   > 哨兵收割之后已没有任何替换体用这种编码，留着那条分支（以及"必须落在页 0xf5000"的
   > 伴随断言）只是死代码 + 误导。`scan_absolutes()` 的返回值也从 `(hits, slots)` 简化成 `hits`。

可选：设置 `$FS_KIP1` 指向 fs 二进制时，逐点比对 `cmp` 字节，防偏移/固件不匹配。

---

## 5. 排障与开关

`config.ini`：

```ini
[options]
fs_codepage=1          ; 0 = 完全跳过 fs 编码补丁（其余 sys-patch 补丁照常）→ 救砖
```

**没有任何条目级开关**：条目一律全量应用，补丁只有「整份生效 / 整份跳过」两态。
若允许「打一半」，`FAT_MakeShortName` 的宽度钳制晚于它依赖的编码转换器（`PFCODE_*`）⇒ 转换器已换、钳制未打时
FAT32 建 CJK 名会在 `FAT_MakeShortName` 的 `subs w23,w23,#2` 上死循环。
（`stage_idx` 与 `needs_wide_cmp` 两个开关都在 2026-09-20 移除。）

日志（`/config/sys-patch/log.ini`）关键字段：`[debug] fs_codepage`（附加前写入的 start 标记）、
`[debug] fs_codepage_patch_result`（最后到达的组名 / 失败原因 / `success`）、
`[debug] fs_codepage_unmatched`（未命中条目数）、`[fs_codepage]`（**只列已定位**的条目及其结果，
失败项在此显现）、`[fs_codepage_sites]`（每个命中站点相对模块基址的偏移）。
早期用于诊断的 `[debug] tmp_buffer` / `tmp_addr` / `tmp_size` 三项已于 2026-09-20 删除
（基址仍在内存里用于换算站点偏移，只是不再落盘）。

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

   **汉字零碰撞的两步（历史命名 R1b / R1c，现均为 M6 的一部分）**：

   | 步骤 | 内容 | 效果（常用汉字区实测） |
   |---|---|---|
   | **R1b** | 匹配器 3 处内联取字符 `ldrb` → `ldrh`（`0xf4894`/`0xf49cc`/`0xf4a9c`），与 `FAT_GetNextChar`(0xf45e8) 早已改过的 `ldrh` 口径统一 ⇒ 第 3 字节进入比较值 | 同值组 327 → 1424，最大同值字数 64 → 48（`中` 与 `一` 可区分） |
   | **R1c** | 比较值扩到 **24 位**：`value = (b0<<16) \| (b2<<8) \| b1`（1~3 字节字符完整、单射） | **同值组 327 → 20902，最大同值字数 1 ⇒ 汉字零碰撞** |

   R1c 共 10 处（现全部并入 M6 整函数替换）：
   - A. 值构造 `orr wN,w8,wN,lsl #8` → `#16`：`0xf45ec`（FAT_GetNextChar）、`0xf4898`、`0xf49d0`、`0xf4aa0`
   - B. 去掉 16 位掩码 `and w8,wN,#0xffff` → `mov w8,wN`：`0xf47f4`、`0xf48c0`、`0xf480c`、`0xf4918`
   - C. 去掉比较时的扩展 `cmp w8,wN,uxth` → `cmp w8,wN`：`0xf4810`、`0xf491c`
   - 未改：`0xf47dc`/`0xf497c`/`0xf4a48`（全角折叠判定，对汉字是空操作）、`0xf492c`（来自 ctx 的字段，非比较值）

   **残留**：4 字节字符（emoji 等）仍只取前 3 字节，同一"前 3 字节"的不同字符会撞
   （要彻底需再读满 4 字节，待做）。`_name_collision_check.py --mode wide` 已按新口径扫描。

   **整函数替换的取舍**：当初怀疑「C 重写递归匹配器可能超过函数自身的洞」，实测洞 `0x360` 够用
   （实现 `0x308`），且先用 unicorn 做了**可执行差分**证明语义等价后才落地 —— 见 §3.5。
   R1b/R1c 的 15 个定点改写已全部由 M6 整函数替换取代，所以**汉字零碰撞**；排障时只能整体
   关掉补丁（`[options] fs_codepage=0`）。
2. **4 字节字符（emoji 等）**：转换器已支持（额外字节数 3），但匹配仍是 2 字节 → 同上。
3. **FAT32 8.3 短名**：`R2` 只是把宽度钳到 2 避免死循环，短名空间估算仍按 CP932 行为；
   若要 PC 侧正确识别短名，可选"方案 C"（仅 `FAT_MakeShortName` 输出 GBK 短名，远期）。
4. **半角片假名**：CP932↔UTF-8 round-trip 会丢失（历史方案已记录，属已知取舍）。
5. **换固件版本**：全部改点已 pattern 化，**定位无需重推**（模板在 **26 份**变体上验证通过：
   16.1.0–22.5.0 共 22 份 + 14.1.2/15.0.1 共 4 份）。
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

# 3) 离线验证（脚本在 D:/Game/NS/firmware/_audit/，用 managed venv 的 python）
python _verify_cpp_table.py     # 表 == PATTERNS.json（31 条）+ 364/364 站点 == RESOLVED
python _p1_sim_scan.py          # 端到端：26/26 份固件，命中集合/站点/写入次数一致
python _opt_equiv.py            # 扫描优化（车道筛子/兄弟退役/空转退出）新旧算法等价：26/26 一致
python _m6_sem_diff.py          # M6 行为级差分：基线 = 原版 0 补丁，穷举短串空间逐例比对
python _m6_fold_probe.py        # M6 ASCII 折叠定点探针：12/12 与原版 0 补丁一致
python _m6_oracle.py            # M6 unicorn 抽样差分：3 形状 × 3000 = 9000/9000（基线 = 旧 15 点补丁集）
                                # M8 同口径：见 _m8_diff*.log（5 形状 × 2000 = 10000/10000）
python _m6_harvest_check.py     # M6 定位 + ctx/callee 收割 + 地址重编码往返：26/26 通过

# 3b) 固件适配审计（fs_encode_fix/fs_fw_audit.py；表解析口径 = C++ str2hex 的逐字符）
python fs_fw_audit.py check --fs <FS_unc.kip1>    # 逐点：同址 / 漂移 / cmp 指纹
python fs_fw_audit.py holes --fs <FS_unc.kip1>    # 七个替换点的洞与余量
#   19.0.1 复验：exfat(081b) 14/14 同址、cmp 14/14；fat32(0819) 14/14 块漂移、cmp 14/14
#   （每份固件只有 14 个点存在 —— 变体族兄弟 0 命中属正常）

# 4) 部署：拷贝 exefs.nsp 到 SD 的 atmosphere/contents/420000000000000B/
# 5) 上机检查 log.ini 的 [debug] fs_codepage_patch_result 应为 success
```

验收：① 启动正常；② 列举可见中文名；③ 打开/读取中文文件成功；
④ 新建/重命名中文名；⑤ 英文名功能无回归（无 stage 分级，回归只能整体开关 `[options] fs_codepage`）。

---

## 8. 关键常量速查

| 项 | 值 |
|---|---|
| fs 镜像基址（分析用） | `0x7100000000`（**运行时随机，勿写死**） |
| fs 文件偏移换算 | 文件偏移 = `0x100 + (VA − 0x7100000000)` |
| 代码页上下文 GOT 槽（分析用，**已不写死**） | 19.exfat = `fs + 0x24EB50`；26 份实测 **18 个取值**（16.1.0=0x2797D0、17.0.0=0x23BE90、18.x=0x23D138、19.0.1/fat32=0x240B50、20.x=0x263F40、21.x=0x25CBC8、22.x=0x25FC38）⇒ 运行时由 `fs_harvest_ctx_slot()` 从原函数现场收割 |
| per-char 回调槽 | 上下文 `+0x18`(OEM2Uni) `+0x20`(Uni2OEM) `+0x30`(isOEMMBchar) |
| 模式标志 | 上下文 `+0x48` bit1 = 特殊映射模式 |
| 补齐函数返回值约定 | 高 16 位 = 输出字节数；低 16 位 = 输入字节数 |
| 七个替换函数尺寸（B / 洞） | 236/0x170 · 140/0x1D0 · **72**/0x50（余 8） · 236/0x120 · 148/0xB0 · **776**/0x360（M6，余 88） · 488/0x240（M8，余 88） |
| 表规模 | `fs_fn_groups[12]` + `fs_inst_patches[15]` + `fs_blob_patches[16]`（= 31 条），谓词 **5**，覆盖 **14 个补丁点 / 26 份 fs 变体**；每份固件落地 14 条 |
| M6 定位模板 | `fs_cp_widechar_compare_*` 四条入口对齐模板（20 / 2 / 2 / 2 份），入口 = 实测 `0xF4770` |
| M8 定位模板 | `fs_cp_fat_getnextchar_16.1.0+` / `_14.1.2-15.0.1`（22 / 4 份），入口 = 实测 `0xF44E0` |

### 相关文档
- 事故复盘：`re_boot_hang_2026-09-15.md`（卡 logo：机器码错误 / 绝对地址 / 日志死锁）
- 打不开复盘：`re_path_not_found_2026-09-15.md`（idx 语义 + 步进少 1）
- 结构体权威：`fs_structs.h`；分析结论：`re_analysis.md`；改进计划：`re_improve_plan.md`
