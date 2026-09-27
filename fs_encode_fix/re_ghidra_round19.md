# Ghidra 第十九轮：FsDrvObject 未命名字段定性 + 函数原型补全

日期：2026-09-15 · 目标二进制：`19.exfat.FS.kip1`（image base `0x7100000000`）
方法：Ghidra MCP 桥反编译取证 → `fs_encode_fix/fs_structs.h` 落地 → `gcc -fsyntax-only` 校验偏移 → 回写 Ghidra 类型库 → `save_all_programs`

## 1. FsDrvObject 新增/修正字段

| 偏移 | 旧记 | 新结论 | 证据 |
|------|------|--------|------|
| `0x0b8` | `dwField_0xb8` media-info flags | `dwFatRegionCacheType` FAT 区域缓存类型（写 2） | `exfat_init_cluster_bitmap_cache` @`0x71000e3450` |
| `0x0c0` | `dwField_0xc0` per-volume config | `dwFatRegionCacheFlags` 低 3 位 = 缓存类型（初始化置 2）；位图改写期间置 bit1，收尾按 bit0 置 bit4 | 同上 + `exfat_bitmap_operation` @`0x71000eff10` |
| `0x0c4` / `0x0c6` | max-cluster / cluster-size config | `wFatCacheEntryCount_0xc4` / `_0xc6` 缓存区 A/B 节点数；数据缓冲字节数 = (0xc4 + 0xc6) × 0x200 | `fat_init_fat_region_cache` @`0x71000e32c0` |
| `0x0c8` | `dwCode_page_state`（u32） | 与 `pFatRegionCache_nodes`（u64 指针）**共用**：缓存节点数组基址（`fat_init_fat_region_cache` arg2） | `fat_init_fat_table` @`0x71000e3200` |
| `0x0d0` | `pCode_page_slot` | `pFatRegionCache_slot0`（exFAT 路径置 0；FAT32 = 主 FAT 槽） | 同上 |
| `0x0d8` | `_reserved0xd8[0x10]` | `pFatRegionCache_slot1`（`fat_init_fat_region_cache` arg1 输出；exFAT 位图缓存用此槽） | 同上 |
| `0x0e0` | （同上保留区） | `pFatRegionCache_buffer`（节点 i 数据 = base + i×0x200） | 同上 |
| `0x180` | `_reserved0x168` 区 | `dwBitmapFirstCluster` exFAT 簇位图首簇，0 = 未定位（首次到根目录搜 attr `0x81` 条目后缓存） | `exfat_get_bitmap_info` @`0x71000f0a90` |
| `0x188` | （同上） | `qBitmapSize` 位图字节数（= 位图文件 DataLength）；边界检查 `(cluster-2)>>3 < qBitmapSize` | 同上 + `exfat_check_cluster_allocated` @`0x71000ef470` |
| `0x198` | `_reserved0x190` 区 | `wBitmapOpFlags` 位图改写状态字（进入置 bit1；返回前若 bit0 置位则再置 bit4） | `exfat_bitmap_operation` |
| `0x208` | `reserved_0x1d0[0x48]` | `dwClusterRunGranularity` 连续簇粒度（碎片统计/对齐单位；<2 时跳过统计） | `exfat_scan_free_clusters` @`0x71000f0360`、`exfat_update_free_cluster_count` @`0x71000f0be0` |
| `0x20c` | （同上） | `dwClusterAlignAnchor` 簇对齐锚点（每次比较后按 +0x208 递增） | 同上 |

关键点：`exfat_update_free_cluster_count` 以 `reserved_0x1d0 + 0x38` / `+0x3c` 形式访问，
由此把 demangler 类型里含混的 `struct_2d0[0].field_0x1a8/0x1ac` 精确锚定到 `drvObj+0x208/0x20c`
（换算关系：demangler `field_0xNNN` + `0x60` = 真实 drvObj 偏移）。

## 2. Ghidra 侧改动

- 新建/导入权威 `FsDrvObject`（0x8C8，packed），此前库中只有不可靠的 `FsDrvObject_demangler`。
- 字段改名：`dwField_0xb8→dwFatRegionCacheType`、`dwField_0xc0→dwFatRegionCacheFlags`、
  `wVolume_config_0xc4/_0xc6→wFatCacheEntryCount_0xc4/_0xc6`、
  `pCode_page_slot→pFatRegionCache_slot0`、`_resd8→aFatRegionCache_slots1buf(void *[2])`、
  `reserved_0x1d0→aClusterCfg_0x1d0`。
- 函数参数定型（去 `void *`/`long`/`FsDrvObject_demangler *`）：
  `fs_locate_object`(@`0x7100100280`, param_1/param_4→`FatFileHandle **`)、
  `fs_init_volume_context`、`exfat_get_bitmap_info`、`exfat_check_cluster_allocated`、
  `exfat_bitmap_operation`、`exfat_scan_free_clusters`(param_1→`FsDrvObject *`)。
- 未命名函数命名：`FUN_7100068d6c→fs_stub_not_implemented`、`FUN_7100068d78→fs_stub_not_implemented2`
  （两者均为 `return 0x177202` = `FS_RESULT_NOT_IMPLEMENTED` 的 vtable 占位，xref 22/18 全部来自表项引用，无调用者）。

## 3. 工具链经验（复用）

- `run_script_inline` 被禁用（需 `GHIDRA_MCP_ALLOW_SCRIPTS=1`），无法批量脚本统计。
- `search_functions_enhanced` 对**已命名**函数模式（如 `exfat`、`bitmap`）恒返回 0，对 `FUN_` 前缀正常；
  查已命名函数请用 `search_functions`（子串匹配，可靠）。
- `get_function_signature` 不返回签名字符串（只返统计信息）；判读原型只能 `decompile_function`。
- `find_similar_functions` 基于 metrics（基本块/指令数），`threshold=0.95` 对 3 指令 stub 仍 0 命中，不能用于批量找 stub。
- 未命名函数规模：6200 函数中 4810 个仍是 `FUN_`；`0x71000c`–`0x710013` 主线区间已基本命名完毕，
  剩余集中在 `0x710002`–`0x71000b`（库代码）与 `0x710013`–`0x71001a`（nn::fs 服务层/IPC）。

## 4. 服务层（0x710013–0x71001c）

规模：`0x7100100000`–`0x71001FFFFF` 有 **2341** 个 `FUN_`，其中 xref≥8 的 79 个，无 xref≥15 的
（服务层函数普遍小而碎，多为 helper / 类方法 / wrapper）。

### 4.1 事件等待机制（multiwait）

`FUN_7100195c30` 是构造函数（写 vtable `PTR_FUN_710024ac18`）。读该 vtable 得到 5 个槽，
据此一次性还原整个类：

| 地址 | vtable 槽 | 命名 | 行为 |
|------|-----------|------|------|
| `0x7100195c30` | — | `fs_multiwait_holder_init` | 构造 holder：`[2]=self+1, [3]=[4]=self+3, [5]=0, [6]=ctx`，`[0]=vtable` |
| `0x71001961a0` | — | `fs_multiwait_wait_any` | 等待任一组事件中第一个触发者，返回 holder |
| `0x7100197960` | — | `fs_multiwait_wait_any_core` | 实际等待：遍历链表试槽1；无命中则 `0x71001976b0` 阻塞获取 |
| `0x7100197af4` | 槽0 | `fs_multiwait_holder_is_signaled` | 加锁读 `owner+0x10` 状态字节 |
| `0x7100197b34` | 槽1 | `fs_multiwait_holder_touch_and_test` | 加锁 + 把节点重排到链表（LRU touch）+ 返回状态 |
| `0x7100197b98` | 槽2 | `fs_multiwait_holder_unlink` | 加锁 + 从持有者链表摘除 |

holder 布局（推断）：`+0x18` 链表节点、`+0x20` 链表节点、`+0x30` 指向所属对象
（`+0x10` 状态字节、`+0x1c` 自旋锁）。

### 4.2 设备状态监视线程

`0x71001a5860` → `fs_device_monitor_thread_main`：线程主循环，`SleepThread(param_1[0xc9a] * 1000000)`
秒级轮询；比较外部状态 `FUN_71001bc7a0()` 与期望值 `param_1[0xc99]`，状态翻转时经
`fs_event_signal_all(param_1+0xc84 / +0xc8e)` 广播并回调 `param_1+0xca0/0xca4/0xca8`；
用三个 holder（定时 / 状态变化 / 退出）走 `fs_multiwait_wait_any` 分发。
轮询间隔与期望状态均来自参数块，符合 SD/介质检测线程形态（未最终确认具体设备）。

### 4.3 全局回调 wrapper 簇

`.bss` 中的函数指针槽 `DAT_7100fdb800 / fdb810 / fdb818` **静态读不出来**（未初始化块，`read_memory` 失败），
改用 `get_xrefs_to` 找到写入点 `0x71001365d0`，据此整簇定性：

| 地址 | 命名 | 行为 |
|------|------|------|
| `0x71001365d0` | `fs_set_global_function_ptrs` | 注册：`fdb810 = p1; fdb818 = p2` |
| `0x71001363f0` | `fs_call_global_function_ptr_1` | `fs_lock_enter` + `fdb810(p1)` + `fs_string_cleanup(&fdb7f8)` |
| `0x7100136440` | `fs_call_global_function_ptr_2` | `fs_lock_enter` + `fdb818(p1,p2)` + 同上清理 |
| `0x7100136508` | `fs_call_global_function_ptr_3` | 直接 `fdb800()`，不带锁 |
| `0x71001365c0` | `fs_global_string_cleanup` | `fs_string_cleanup(&DAT_7100fdb7fc)` |

（沿用库中已有命名 `fs_call_global_function_ptr_0` @`0x7100136490` 的风格。）

### 4.4 通用 helper

- `0x7100138cb4` → `fs_align_down_offset`：`*out = (base + off) & -align`
- `0x710013ed8c` → `fs_calc_bitmap_size_aligned`：`(n + 0x1ff) >> 3 & ~0x3f`（位图字节数按 64 字节对齐并多留 64）
- `0x710013a8f0` → `fs_cache_lookup_overlapping_block`：在块数组中找与 `[p2, p3)` 区间重叠者，
  命中后引用计数 +1 并从 LRU 链表（`+0x68/+0x70`）摘除
- `0x7100139530` → `fs_collection_release_all`：释放引用并遍历 0x40 步长元素数组逐个回收

### 4.5 服务层方法学（可复用）

1. **连续地址的小函数簇 = 同一类的方法**（如 `0x710019af80/90/a4/b8`），一次批量反编译可整组命名。
2. **构造函数里出现 `*param_1 = &PTR_xxx` 就是 vtable** → `read_memory` 读该表 → 反编译各槽 → 还原整个类。
3. `.bss` 函数指针槽读不出来时，用 `get_xrefs_to(address)` 找 WRITE 引用定位注册函数。
4. 服务层命名前缀统一用 `fs_`（库里 `fs_lock_enter` / `fs_event_signal_all` / `fs_get_thread_context` 已是此风格）。

## 5. fat/exfat 路径主线

### 5.1 区间已清零

`0x71000c`–`0x710011`（FAT/exFAT 驱动核心）**未命名函数已为 0**；本轮工作量因此集中在
原型与类型正确性，而非命名。已命名函数规模：`fat*` / `FAT*` / `exfat*` 合计 200+ 个
（`search_functions "fat"` 单关键字即返回 120 条，已到工具上限）。

### 5.2 本轮修好的原型

| 函数 | 修改 |
|------|------|
| `FAT_GetNextPathComponent` @`0x71000f4bc0` | 参数 `ctx`: `void *` → `FsDrvObject *`（体内用 `ctx+0x11c` 即 `dwFlags_0x11c`） |
| `FAT_ParsePath` @`0x71000f9800` | `ctx` → `FatFileContext *`，`fsObj` → `FsObject *`，`drv` → `FsDrvObject *`（原为 `*_demangler`） |
| `FAT_GetFsDrvByPath` @`0x71000f51b0` | 返回类型 `FsDrvObject_demangler *` → `FsDrvObject *` |
| `exfat_resolve_path` @`0x71000fb6a0` | 原型定为 `int exfat_resolve_path(FsDrvObject *drv, FsObject *entry, StringDesc *outPath)`（原返回 `undefined`、无调用约定） |

原型依据：`fat_check_name_match` @`0x71000fc580` 中
`exfat_resolve_path(entry->field25_0x230, entry, local_240)` 且返回值与 0 比较。

### 5.3 与中文路径补丁直接相关的代码事实（重要）

出自 `FAT_GetNextPathComponent`（路径逐段解析 + 字符合法性检查）：

- **多字节步进由全局钩子 `*pisOEMMBchar` 决定**：`if (SVar3 == ENCODE_OEM && (*pisOEMMBchar)(*ptr_right,1))`
  命中则一次前进 2 字节；返回假时只前进 1 字节并直接 `return 2`（判为非法）。
  → 这正是 CP932→UTF-8 补丁里"仍按 +1 推进"缺陷的源头之一。
- **非 ASCII 字节不做字符类型校验**：仅当 `-1 < *ptr_right`（即 `< 0x80`）时才查
  `g_charTypeTable[uVar4 - 0x20] & 1`；OEM 通道下 ≥0x80 的字节**直接放行**、不报错。
  UNICODE 通道同理，仅 `*(ushort*)ptr < 0x80` 才校验。
  → 说明原版对高位字节是"绕过检查"而非"拒绝"，补丁只需保证步进正确即可通过。
- 分隔符 `\` 与 `/` 等价处理；`allowWildcard` 控制 `*` / `?` 是否放行。
- `ctx+0x11c` 的 bit4（`dwFlags_0x11c`）参与 `<` 起始字符的特判。

出自 `FAT_CheckPathNumbers` @`0x71000f41d0`：

- 用 `local_64 = {'\x01', '\x02'}` 这两个**控制字符标记**参与 `StringDesc_CompareOem`，
  即 `.` / `..` 在 StringDesc 里有内部标记编码（1=当前、2=父目录），不是字面字符串比较。
- 逐字符扫描上限 8，命中 `\` `/` 空格 或 结束 即停；`isWildcard` 控制 `*`/`?` 判定。

### 5.4 交叉验证（本轮顺带证实的两条旧结论）

- `drvObj+0x120` bit0 = **mounted**：`FAT_GetFsDrvByPath` 中
  `pFVar4->struct_2d0[0].field_0xc0 & 1`（demangler `field_0xc0 + 0x60 = 0x120`）。
- `FsObject+0x230` = **drvObj**：`fat_check_name_match` 传 `entry->field25_0x230` 给
  `exfat_resolve_path` 的第一参数；Ghidra 中该字段已从 `-BAD-` 定名为 `pDrvObj`。

### 5.5 编码回调：注册点、消费面与补丁偏移映射（本轮核心产出）

**注册点** = `PFCODE_CP932_Init` @`0x71000d5150`（WRITE 各槽）。
`PFCODE_CODE_PAGE_CONTEXT` @`0x7100fcfc38` 的六个回调槽现在全部定性：

| 槽偏移 | Ghidra 符号 | 目标函数 | 起始地址 | 行为 |
|--------|------------|----------|----------|------|
| `+0x18` (0xfcfc50) | `pOEM2Unicode` | `PFCODE_CP932_OEM2Unicode` | `0x71000feac0` | 单字符 OEM→UTF-16 |
| `+0x20` (0xfcfc58) | `pUnicode2OEM` | `PFCODE_CP932_Unicode2OEM` | `0x71000fec30` | 单字符 UTF-16→OEM |
| `+0x28` (0xfcfc60) | `pOEMCharWidth` | `PFCODE_CP932_OEMCharWidth` | `0x71000fee00` | OEM→转换→`PFCODE_GetConvertWidth` 取宽度 |
| `+0x30` (0xfcfc68) | `pisOEMMBchar` | `PFCODE_CP932_isOEMMBchar` | `0x71000fee40` | OEM 双字节判定 |
| `+0x38` (0xfcfc70) | `pUnicodeCharWidth` | `PFCODE_CP932_UnicodeCharWidth` | `0x71000fee90` | **恒 2**（UTF-16 无变长） |
| `+0x40` (0xfcfc78) | `pisUnicodeMBchar` | `PFCODE_CP932_isUnicodeMBchar` | `0x71000feea0` | **恒 false** |

（+0x38/+0x40 两槽此前未定性；对 UTF-8 方案意味着 Unicode 通道本身无多字节概念，
若把 UTF-8 接进 Unicode 通道，变长逻辑必须新写。另 `DAT_7100fcfc48 = callback`（Init 参数）
是第 7 个外部回调槽。）

`PFCODE_CP932_Init` 其它要点：flags 只允许 bit16/bit17 单独置位（`& 0xfffcffff == 0` 且
`& 0x30000 != 0x30000`），bit16 存入 `DAT_7100fcfc44`（`FAT_GetNextPathComponent` 检查其 bit16）；
`ULONG_7100fcfc80 = 1`（检查其 bit1）；**静态分配 5 个 FsDrvObject**（`0x7100fd8598/0x7100fd8e60/
0x7100fd9728/0x7100fd9ff0/0x7100fda8b8`，各 0x8C8 = 最多 5 个同时挂载卷）；初始化一组转换表管理
链表头（`0x7100fd8590→0x7100fd1370`、`0x7100fd2a38→0x7100fd2a40` 等）。

**`*pisOEMMBchar` 消费面全清单**（13 处引用 / 8 个函数，编码域的完整钩子面）：
`StringDesc_GetCharCount`、`StringDesc_CompareUnicode`、`StringDesc_CompareOem`、
`StringDesc_AddLeft`、`FAT_MatchFileName`、`FAT_GetNextChar`(×2)、
`FAT_GetNextPathComponent`(×2)、`FAT_MatchWildcardRecursive`(×3)。
另有 `g_charTypeTable` @`0x71001d9ce2`（`undefined[98]`，索引 `c-0x20`，覆盖 0x20..0x81）。

**`fs_codepage_patch()` 十个硬编码偏移 → 函数名映射**（换固件重推时按名定位）：

| 补丁偏移 | 函数 | 函数起始 | 偏移位置 |
|----------|------|----------|----------|
| `0xd4af4` | `IDirectory_Read` | `0x71000d4a20` | 函数内 +0xd4 |
| `0xfeac0` | `PFCODE_CP932_OEM2Unicode` | `0x71000feac0` | **入口** |
| `0xfec30` | `PFCODE_CP932_Unicode2OEM` | `0x71000fec30` | **入口** |
| `0xfee40` | `PFCODE_CP932_isOEMMBchar` | `0x71000fee40` | **入口** |
| `0xf45d8` | `FAT_GetNextChar` | `0x71000f44e0` | 函数内 +0xf8 |
| `0xf4d8c` | `FAT_GetNextPathComponent` | `0x71000f4bc0` | 函数内 +0x1cc |
| `0xf77e8` | `StringDesc_AddLeft` | `0x71000f7790` | 函数内 +0x58 |
| `0xf7984` | `StringDesc_GetCharCount` | `0x71000f7930` | 函数内 +0x54 |
| `0xf7a80` | `StringDesc_CompareUnicode` | `0x71000f7a00` | 函数内 +0x80 |
| `0xf7bd0` | `StringDesc_CompareOem` | `0x71000f7b20` | 函数内 +0xb0 |

规律：3 个是 PFCODE 函数**入口**，7 个是消费 `pisOEMMBchar` 的调用点附近。三个 PFCODE 入口
补丁即"换实现"，七个消费点补丁即"改正步进/去抑制"——与 re_improve_plan 的两阶段思路吻合。

附带：`PFCODE_CP932_ConvertWidth` @`0x71000f7ce0` 与 `PFCODE_GetConvertWidth` @`0x71000f7cf0`
相邻 0x10 字节，前者疑似后者的 10 字节小包装；`PFCODE_CP932_Init` 还有两个变体
（`0x710010ee40`、`PFCODE_CP932_Init1` @`0x710010ee00`，疑 IPC 层注册入口）。

### 5.6 转换返回值编码 + 初始化链（遗留项收尾）

**`ConvertWidth` 是打包 / `GetConvertWidth` 是解包**：

- `PFCODE_CP932_ConvertWidth(int oemWidth, short uniWidth)` @`0x71000f7ce0` → `oemWidth << 16 | uniWidth`
- `PFCODE_GetConvertWidth(int convertRet, ushort *oemWidth, ushort *uniWidth)` @`0x71000f7cf0` → 拆高/低 16 位

⇒ **`OEM2Unicode` / `Unicode2OEM` 的返回值不是布尔，而是打包的两个宽度：
高 16 位 = 消耗的 OEM 字节数，低 16 位 = 产生的 UTF-16 码元数。**
不过**实际消费方并没有用这个返回值**，而是统一走 `pOEMCharWidth` 槽取宽度（见 §5.7），
所以"取 `ret >> 16`"只是候选方案之一，不是必需改动。

### 5.7 短名生成路径：发现第 11 个补丁点（现有 10 个偏移未覆盖）

逐个核对 AGENTS.md 记的"仍按 +1 推进"缺陷，结论与原文**有出入**：

| 函数 | 实际用的回调 | 现状 |
|------|--------------|------|
| `FAT_MatchWildcardRecursive` @`0x71000f4770` | `(*pisOEMMBchar)(ch,1)` | 命中则 `len += 1`（共 2 字节）。**CP932 下正确**；UTF-8 三字节会少进 1 字节 |
| `FAT_ReplaceShortNameNumber` @`0x71000f6270` | `(*pOEMCharWidth)(p)` | **按宽度步进，本身正确，无需改** |
| `FAT_MakeShortName` @`0x71000f5ac0` | `(*pOEMCharWidth)(p)` 取宽度 | 取宽度正确，但**多字节分支硬编码 2 字节** ← 新补丁点 |

`FAT_MakeShortName` 细节（8.3 短名生成，GB2312 短名方案的核心）：

- 单字节分支（宽度 == 1）：仅在 `(DAT_7100fcfc44._2_1_ & 1) == 0` **且**字节 `< 0x80` 时才查
  `g_charTypeTable[c - 0x20] >> 1 & 1` 判非法并替换为 `'_'`。因为 §5.6 已证 bit16 恒 0，
  ⇒ **≥0x80 的字节不会被替换**，直接 `toupper` 写入短名（对高位字节无变化，等于原样保留）。
- **多字节分支（宽度 != 1）——缺陷所在**：
  `for (...; uVar10 != 0; uVar10 = uVar10 - 2)`，循环体内只取 `oem_in[0]` / `oem_in[1]`，
  `uVar21 += 2`，短名写 2 字节。**整个复制假定多字节字符恰好 2 字节**。
  ⇒ UTF-8（CJK 3 字节）/ GBK 换到这里会被**截断成前 2 字节**，短名错误。
- 多字节分支内还有 CP932 片假名归一化：先 `(*pOEM2Unicode)`，若
  `0xffe5 < uni + 0xa5` 则 `uni -= 0x20` 再 `(*pUnicode2OEM)` 转回（半角⇄全角）。

**多字节复制循环的精确指令**（`disassemble_bytes 0x71000f5ea0–0x71000f5f30`，已定位）：

| 地址 | 指令 | 作用 |
|------|------|------|
| `0x71000f5ea4` | `add w27, w27, #0x2` | 短名写指针 `uVar23 += 2` |
| `0x71000f5ea8` | `add w24, w24, #0x2` | 源指针 `uVar21 += 2` |
| `0x71000f5eac` | `subs w23, w23, #0x2` | 剩余宽度 `uVar10 -= 2` |
| `0x71000f5eb4` | `strb w22, [x8, #0x1]` | 写第 2 字节 |
| `0x71000f5ebc` | `add w8, w8, #0x2` | 短名长度计数器 `+= 2` |
| `0x71000f5ed8` | `ldrb w22, [x0, #0x1]` | 只读第 2 字节 |

循环头 `0x71000f5ea0`，回边 `0x71000f5f30`（`b 0x71000f5ea0`）。

**两处回调读取方式与 §5.5 表吻合**：`ldr x26,[0x710024eb50]` 后
`ldr x8,[x26,#0x18]` → `blr`（`pOEM2Unicode`，槽 +0x18）、
`ldr x8,[x26,#0x20]` → `blr`（`pUnicode2OEM`，槽 +0x20），与注册顺序一致。

**对方案选型的影响（关键）**：
GB2312/CP936 的汉字是 **2 字节**，与 CP932 双字节**同构** ⇒
**GB2312 方案下这个循环天然正确，不需要打补丁**；
只有 UTF-8 方案（CJK 3 字节）才必须改造这里（需把定值 2 改成按 `pOEMCharWidth` 返回的宽度循环复制）。
这再次印证"CP936 对中文 = 原版 CP932 对日文的行为平移"。

⇒ 现有 `fs_codepage_patch()` 的 10 个偏移**不包含** `FAT_MakeShortName`。
若采用"UTF-8 主域 + GBK 8.3 短名"方案，这里必须新增补丁，否则短名生成会截断。

**`PFCODE_CP932_Init` 有两份，但只有一份实现**：

- `0x71000d5150` = 真实实现
- `0x710010ee40` = thunk（`UNCONDITIONAL_JUMP` 跳到 `0x71000d5150`）
- 调用链：`fs_prfile2_init_and_mount` → `PFCODE_CP932_Init1` @`0x710010ee00`（带 `CheckError` 包装）
  → call `0x710010ee40` → jump `0x71000d5150`

**初始化实参**（补丁要改的话这里是入口）：`PFCODE_CP932_Init1(0x20000, NULL)`
→ flags = **bit17**（不是 bit16）；`DAT_7100fcfc44` 只保存 `flags & 0x10000`，因此
**`DAT_7100fcfc44` 的 bit16 恒为 0** ⇒ `FAT_GetNextPathComponent` 中
`(DAT_7100fcfc44._2_1_ & 1) == 0` **恒真**（永远走"严格"分支）。
`DAT_7100fcfc48`（Init 的 callback 参数）**确认是死槽**：仅被 Init 写一次（值为 NULL），全程序无 READ。

**`fs_prfile2_init_and_mount` @`0x71000cf120`**（原 `FUN_71000cf120`，本轮命名）初始化顺序：

```
fs_log_assert_check 分配日志对象
FS_init_diskmanager(0,0)
PFCODE_CP932_Init1(0x20000, NULL)          <- 编码回调注册点（失败码 0x274a02）
fat_register_callback_table(0, fs_log_assert_check, fs_log_trace_message)
fat_register_callback_table(1, 0x71000cf730, 0x71000cf750)
fat_register_get_system_time_cb(0x71000cf770)
DAT_7100fcfc00 = 1                          <- 全局"已初始化"标志
FS_open_disk -> FS_open_partition -> fat_mount_multiple_volumes
  -> FS_unmount -> fat_get_volume_config_wrapper -> fat_set_volume_config_and_unmount_wrapper
```

错误路径用 `pcVar19`（"init_diskmanager"/"open_disk"/"open_partition"/"attach"/"unmount"/
"getvolcfg"/"setvolcfg"）经 `fs_map_volume_error_code` / `fs_geterror_last` 上报。

## 6. 待办

1. `reserved_0x1d0` 区还剩 `0x1d0`–`0x207`（56 字节）未定性。
2. Ghidra 中 `FsObject` 字段名仍为旧命名（`aLongName/dwAttr/file_size/...`），且 `0x230` 处是 `-BAD-` 类型，与 `fs_structs.h` 不同步，需统一。
3. `FsDrvObject+0x4c`（现记 `dwData_start_sector`）在 exFAT 路径被当作**簇数上限**使用
   （`exfat_check_cluster_allocated`：`0x4c + 2 <= cluster` 判越界），语义待复核。
4. `0x120` 初始化为 `|= 0x1001`（bit12 亦置位），现注释仅记 bit0/bit4。
5. 4810 个 `FUN_` 函数的批量定性（主线已清完，剩服务层 2341 个 + 库代码；本轮已消化服务层高 xref 部分）。
6. multiwait holder vtable 第 4/5 槽 `0x7100197ae4` / `0x7100197aec` 在库中**还不是函数**（反编译报 not found），
   需先 `create_function` 再确认是否为虚析构等。
7. `DAT_7100fdb800` 的注册点未找到（只定位到 `fdb810`/`fdb818` 的写入点 `fs_set_global_function_ptrs`）。
8. `fs_device_monitor_thread_main` 监视的具体设备未确认（疑 SD/介质检测）：待查 `FUN_71001bc7a0` /
   `FUN_71001bc9e0` 的语义与 `param_1[0xc98..0xc9a]` 参数块来源。
9. **Ghidra `FsObject` 字段重命名部分未生效**：`fileSize` / `pDrvObj` / `wSectorSize` / `nStatus` 成功，
   但 `aLongName` / `dwAttr` / `dwPathOffset` / `dwFirstCluster` / `dwEntryIndex` / `dwDirCluster` /
   `wEntryOffset` / `bStreamFlags` / `dwDirStartCluster` / `bNameLen` / `bEntryNum` / `aShortName` /
   `aSearchPos` 仍为旧名（工具返回 success 但 `get_struct_layout` 未变），疑与 Ghidra 侧匈牙利
   命名校验有关，需换方式重做（偏移本身正确，不影响分析）。
10. 路径主线仍有若干函数使用 `*_demangler` 类型（`FAT_ResolvePath`、`fat_traverse_path_components`、
    `FAT_FindDirectoryEntry2`、`exfat_search_directory`、`fat32_entry_lookup` 等），需逐个替换为权威类型。
11. ~~`*pisOEMMBchar` / `g_charTypeTable` 定位~~ **已完成**（见 §5.5）：注册点 `PFCODE_CP932_Init`
    @`0x71000d5150`；消费面 8 函数 13 处；`g_charTypeTable` @`0x71001d9ce2`（98 字节，索引 c−0x20）。
    遗留：`g_charTypeTable` 类型仍是 `undefined[98]`（可改 `u8[98]` 并补注释）。
12. ~~`DAT_7100fcfc48` 外部回调槽语义~~ 已确认是**死槽**（Init 写 NULL，无 READ），见 §5.6。
13. ~~`PFCODE_CP932_ConvertWidth` / `GetConvertWidth` 关系~~ 已确认是打包/解包，见 §5.6。
15. **新增补丁点（最高优先）**：`FAT_MakeShortName` @`0x71000f5ac0` 多字节分支硬编码 2 字节复制，
    不在现有 10 个偏移内；6 条相关指令已精确定位（见 §5.7）。
    ⇒ **GB2312 方案无需改**（汉字 2 字节与 CP932 同构）；**UTF-8 方案必须改**。
    `FAT_ReplaceShortNameNumber` 已按宽度步进，**不需要**改——
    AGENTS.md 里"三个函数都按 +1 推进"的说法据此应修正。
16. 下一步：把 §5.7 结论并入 `fs_encode_fix/re_improve_plan.md` 的补丁设计章节
    （本次未改该权威文档，仅记于本轮记录）。
14. `fs_prfile2_init_and_mount`（`0x71000cf120`）的 14 个参数语义未拆，param_1 对象
    （+0x10 日志对象 / +0x18 错误对象 / +0x30 恢复对象 / +0x48、+0x38、+0x40 输出槽）未定型。
