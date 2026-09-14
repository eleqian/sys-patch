# FS 逆向分析最终结论（19.exfat.FS.kip1，image base 0x7100000000）

> 状态：FS 卷驱动结构与生命周期分析已闭环（2026-09-13 第十二轮收尾，无阻塞遗留）。
> 第十八轮（2026-09-14）补齐 exFAT 条目处理链全环节（§8.5）：打开/搜索/创建/更新/删除/重命名 + UpCase 表缓存 + NameHash 硬门。
> 本文档是 12 轮逆向分析的整理版，**只保留经机器码验证的正确结论**；历史草稿中的误判见 §0，不再散落在正文。
> 结构体/偏移的权威来源是同目录 **`fs_structs.h`**（packed + `_Static_assert` 全部通过）；
> Ghidra 数据库（FS_1/19.exfat.FS.kip1）已与头文件同步（2026-09-14 复核，含指针宽度修复）。
> 原始遍历数据（476 个 GOT 虚表槽清单）见 `callback_tables.md`；补丁上机测试步骤见 `fs_encode_fix_test_plan.md`。

---

## 0. 已证伪结论速查（防止重新引入）

以下结论曾在早期轮次被记录，后均被机器码证据推翻。**不要引用它们**：

| 旧结论（✗ 错误） | 正确结论 | 定案证据 |
|---|---|---|
| `+0x88` = FatFileObject 池（0x520 步长） | `+0x78 pPool_base` 才是文件池；`+0x88` = **FatDirObject 池（0x510 步长）** | fs_init_volume_context 池切分 + fat_get_volume_handle_stats（第十轮） |
| "双池并存"：pPool_base 0x520 与 0x510 两种池重叠 | 四段连续区域，`dirs*(0x510+0x28)=dirs*0x538` 严格吻合，无重叠 | 同上（第十轮） |
| `+0x98`=目录计数 / `+0x9c`=文件计数 | **互换**：+0x98=文件、+0x9c=目录 | stats 池配对 + open/close 路径 + clear 函数，三重独立验证（第十/十二轮） |
| opendir 分配 0x7D0 但实际足迹 ≥0x7e0 | `fs_log_assert_check(2000)` 的 **2000 是十进制** = 0x7D0，与 FsDirIterObj 精确等大，无越界 | 第十轮 |
| FsDrvObject+0xa0 存在未找到的"递增方" | **全 kip 无递增点**（45.5 万指令穷尽搜索）；0xa0/0xa8/0xb0 是格式化事务持有的根对象上下文 | 第十二轮 |
| `fat_allocate_dir_context` 分配目录池 | 实为按线程分配 FS 上下文节点（0x16c0 链表），改名 `fs_alloc_thread_ctx_node` | 第十轮 |
| `fat_clear_all_file_objects` 清文件池 | 实际清**目录侧两池**（0x510+0x28），改名 `fat_clear_all_dir_object_pools` | 第十二轮 |
| FatFileObject+0x518 只是"validated dir slot 出参" | 完整语义 = **同一 entry 已打开重复实例的反向链接**（关闭时反扫摘链） | fs_validate_directory_entry / fat_close_file_context（第十一轮） |
| `FatFileContext.bSectorShift` 是簇 shift | 是**扇区** shift（`bytesPerSectorShift - 5`） | 第三轮 |
| demangler 结构（FsDirInfoExt、FsObject_demangler、FatFileContext_demangler、FsDirInfoObj_demangler 等） | 偏移全部不可信，已被重建结构替代，仅存于 Ghidra 未清理引用处 | 第一~三轮 |

另：本工程（fs_encode_fix）历史上修过 Ghidra 侧两处结构体缺陷——`FsDrvObject.pDir_object_array`(+0x88)
曾被改成 4 字节宽度（2026-09-14 复核修复为 8 字节 `FatDirObject *`）；FatDirObject 曾因 `void*`
字段与相邻字段重叠（第十轮修复为 qword）。

---

## 1. 卷内存池布局（最终）

`fs_init_volume_context` @0x71000d7420（原型 6 参：drvObj, param_2, volumeIndex,
maxFileObjects, maxClusterCacheNodes, maxDirObjects）做**单次分配**：

```
fs_alloc_memory_by_type(1, files*0x520 + handles*0x48 + dirs*0x538)
```

随后切为四段连续区域，指针存入 FsDrvObject：

| # | 内容 | 步长 | 数量字段 | FsDrvObject 指针 | 分配/使用 |
|---|---|---|---|---|---|
| 1 | FatFileObject（文件对象，fctx mode=2） | 0x520 | +0x6c dwMax_open_file_objects | **+0x78 pPool_base**（区起点） | fat_allocate_file_object |
| 2 | FatDirObject（目录对象，fctx mode=4） | 0x510 | +0x74 dwMax_dir_objects | **+0x88 pDir_object_array** | fat_find_or_alloc_dir_object |
| 3 | FatDirSearchObject（opendir 返回值） | 0x28 | +0x74 dwMax_dir_objects | **+0x90 pDirSearchObj_array** | fs_open_entry_core / fs_close_file_by_context |
| 4 | FatFileHandle / 簇缓存节点（同槽位 0x48） | 0x48 | +0x70 dwMax_cluster_cache_nodes | +0x80 pCluster_cache_node_array | fs_locate_object / fat_alloc_cluster_cache_node |

关键算术：`dirs*0x510 + dirs*0x28 = dirs*0x538` ⇒ 0x510 与 0x28 是**同一组目录对象的
两段配对区域**（目录对象与其搜索对象 1:1 配对），不是双池。

### dwStatus 标记位体系（三类池对象判别）

| 对象 | dwStatus（在用） | 含义 |
|---|---|---|
| FatFileObject | `0x10000003` | bit0=占用，bit24=文件 |
| FatDirObject | `0x40000003` | bit0=占用，**bit2=目录** |
| FatDirSearchObject | `0x80000001` | bit0=占用，bit3=搜索对象 |
| FatFileHandle | `0x20000001`（fat_setup_file_handle 设置） | bit0 也作 I/O 门控 |

空闲判定统一为 `(dwStatus ^ 0xffffffff) & 3 == 0`。

---

## 2. FsDrvObject（卷/驱动对象，0x8C8）关键字段

卷数组在模块全局 `0x7100fd8598`，条目 N（0..4，盘符 'A'..'E'）位于 `base + N*0x8C8`。
反编译中出现的伪基址：`DAT_7100fd86b8` = base+0x120、`DAT_7100fd86c0` = base+0x128、
`DAT_7100fd8620` = base+0x88、`DAT_7100fd8628` = base+0x90、`DAT_7100fd8638` = base+0xa0、
`DAT_7100fd860c` = base+0x74。完整字段表见 `fs_structs.h`，此处只列有跨函数语义的：

| 偏移 | 名称 | 语义 |
|---|---|---|
| 0x00–0x27 | wBpb_* | BPB 镜像（fat_parse_bpb / fat_parse_boot_sector 写入） |
| 0x28 | wMountFlags | bit0=已用 bit1=已挂载 bit2=exFAT bit5=已格式化（0x2a 是镜像） |
| 0x30 | nFat_type | 0=FAT12, 1=FAT16, 2=FAT32, 3=exFAT |
| 0x34/0x35 | bBytesPerSectorShift / bSectorsPerClusterShift | log2；簇 shift = 两者之和 |
| 0x48 | dwMax_cluster_num | 最大有效簇号 |
| 0x6c/0x70/0x74 | dwMax_open_file_objects / dwMax_cluster_cache_nodes / dwMax_dir_objects | 三类池槽数 |
| 0x78/0x80/0x88/0x90 | 四个池指针 | 见 §1 |
| 0x98 | **nOpenFileRefCount** | 打开 FatFileObject 数；fs_open_file / fs_open_directory 成功 +1 |
| 0x9c | **nOpenDirRefCount** | 打开目录对象数；fs_open_entry_by_oem_path +1、fs_close_file_by_context −1 |
| 0xa0 | dwPinCount_0xa0 | 格式化事务 pin（见 §4） |
| 0xa8 | pRootObj_0xa8 | 格式化事务持有的根目录 FatDirObject*（见 §4） |
| 0xb0 | pRootSearchObj_0xb0 | 与 0xa8 配对的 FatDirSearchObject*（0x28） |
| 0xc8/0xd0 | dwCode_page_state / pCode_page_slot | 代码页上下文状态与已分配 PFCODE 槽 |
| 0xf8/0x100 | pLock_0xf8 / qTransaction_thread_context | 当前事务的 FS 上下文与线程上下文（ownerTag 校验基准） |
| 0x11c | dwFlags_0x11c | bit4 = 卷为 exFAT，无 OEM 名 |
| 0x124 | bLetter | 盘符 'A'..'E' |
| 0x148–0x158 | bSectorCache_enabled / wSectorCache_count / qSectorCache_base / dwSectorCache_stride | 扇区缓存（fat_allocate_file_object 读） |
| 0x160/0x164 | dwTransaction_id / dwTransaction_result | 事务 id（0x12 挂载、0x34 配置、0x45 ftruncate）与结果码 |
| 0x1c8 | qStorage_handle_0x1c8 | 存储设备句柄（fs_storage_* 第一参） |
| 0x218 | dirCache[0x6A0] | 目录缓存：fs_get_volume_dir_cache 返回 drvObj+0x218，fs_set_dir_cache 存入，fs_read_current_dir_entry 读取 |

---

## 3. 文件/目录对象生命周期

### 3.1 打开与去重

- 文件：`fs_open_file`(driveId, StringDesc*, openFlags, FatFileHandle**) → 事务 →
  `fs_locate_object` → `fat_allocate_file_object`（0x520 池去重分配）→
  `fat_setup_file_handle` 填 0x48 句柄（dwStatus=0x20000001、dwCurrentCluster=−1 等）。
- 目录：`fs_open_entry_by_oem_path` → `fs_open_entry_core`（要求 attr bit4=目录）→
  `fat_find_or_alloc_dir_object`（0x510 池）+ 从 +0x90 池取 0x28 FatDirSearchObject。
- 去重键 = `entry.pDrvObj / dirCluster / entryOffset`（FsObject@0x230/0x244/0x248）；
  命中已有对象则引用计数 +1（FatFileObject.wRefCount@0x510 / FatDirObject 低 16 位@0x004）。
- 新分配时 memcpy entry 0x480 字节；fctx 用 `fs_init_directory_context` 初始化
  （mode=2 文件 / mode=4 目录）。

### 3.2 重复打开反向链接（+0x518 / +0x508）

- `fs_validate_directory_entry`(dirEntry, &ppOutSlot) @0x7100105cb0：扫描 0x510 池，
  条件 = 在用 + `dwF_0x4fc != 0` + `wFlags_0x4f8` bit1 + `qwOwnerTag_0x500` ==
  当前事务线程上下文，再经 `fs_compare_directory_entries` 按 entry 身份比对，
  命中则 *ppOutSlot = 已打开的同 entry 对象。快速路径：只验 pRootObj_0xa8。
- 打开路径把输出写入 **FatFileObject+0x518**（fs_locate_object）/
  **FatDirObject+0x508**（fs_open_entry_core）→ "同 entry 已有打开实例"链接。

### 3.3 关闭与释放

- `fs_close_file_by_context`(obj, force) @0x7100107cb0：对 5 个卷池做区间校验
  （0x28 步长池 = FatDirSearchObject 专用关闭路径），调 `fat_close_file_context`。
- `fat_close_file_context`(drvObj, handle, forceClose) @0x7100109630：
  - 校验 `handle{dwLastError,dwReserved_0x24}`（qword）== qTransaction_thread_context
    且对象 `qwOwnerTag_0x500` 相同，否则 0x32（force 可越过）；
  - 释放条件：`wFlags_0x4f8 & 0xA == 0xA`（bit1+bit3）；
  - 释放前**反扫两池摘链**：0x520 池中 +0x518==本对象、0x510 池中 +0x508==本对象 → 清零；
  - dwPinCount_0xa0 −1（无条件）；关闭根目录（cluster==1 或 FAT12/16 根簇）时清 0xa8/0xb0。
- 清空函数（对称两组）：
  - `fat_clear_all_file_handles` @0x71000ff790：清 0x520+0x48 池 → 清 **+0x98**；
  - `fat_clear_all_dir_object_pools` @0x7100105820：清 0x510+0x28 池 → 8 字节存储同时清 **+0x9c 与 +0xa0** → 清 0xa8/0xb0。

### 3.4 计数器配对（三次独立验证）

`fat_get_volume_handle_stats` @0x71000da130（drive 'A'..'E' → out[4]）：
out[0]=0x520 池空闲数、out[1]=+0x98（文件）、out[2]=0x510 池空闲数、out[3]=+0x9c（目录）。
与 open 路径（+1）和 clear 函数证据三线吻合。

---

## 4. 格式化事务与根目录对象（0xa0 / 0xa8 / 0xb0 定案）

对全 kip（45.5 万条指令）穷尽搜索（str/stp/stur/add × #0xa0/#0xa8 + 0x8c8 卷步长寻址）结论：

- **+0xa0 无递增点**。全部写入仅 5 处：
  - fat_close_file_context：−1（每次关闭无条件）；
  - fat_mount_volume_core @0x71000d7d10：格式化完成后置 1（有原根对象时），同时 +0x9c=1；
  - fat_clear_all_dir_object_pools：8 字节存储连带清 0x9c+0xa0；
  - fs_format_volume_core：`stp xzr,xzr,[x27,#0xa0]` 成对清 0xa0+0xa4；
  - 其余（fat_unmount_volume_by_letter / fs_check_drive_state）只读。
- **+0xa8 从未写入新指针**：fat_mount_volume_core 的"恢复"写回的就是格式化前读出的同一指针；其余全是清零。
- 0xa4 仅与 0xa0 成对清零，无其他引用 → 保留字段。

**定性**：0xa0/0xa8/0xb0 = **格式化事务（id 0x12）持有的"跨格式化根目录对象上下文"**。
格式化客户端先以同一事务上下文打开根目录（对象驻留 0x510 池，ownerTag==事务 ctx）；
fat_mount_volume_core（实为**格式化/重整核心**，旧名"挂载"不准）以
`0xa0>0 && 0xa8 有效 && ownerTag==事务ctx` 为前置条件（否则 0x31/0x24），格式化前把
0xa8 对象（头 0x50+0x4c0）与 *0xb0（0x28）整体备份到栈，完成后原样恢复。
pin 只在格式化事务窗口内非零——常规 open/close 只减不增是**设计使然**，不是遗漏。

`fs_check_drive_state` @0x71000d6940：`0xa0>=1 && 0xa8 有效 && (dwF_0x4fc==0 ||
wFlags bit1==0 || ownerTag != *(drvObj+0x100))` → 返回"忙碌"，打开路径前置检查（0x31）。
`fat_unmount_volume_by_letter`：0xa0 ≥1 拒绝卸载（0x31，force 除外）。

---

## 5. 目录迭代器（FsDirIterObj 0x7D0）与 opendir 链

- `fs_idirectory_opendir`(IDirectoryObj*, void **ppOutIter, StringDesc*, openFlags)
  @0x71000d1890：路径规范化 `"%c:\%s"` → fs_dispatch_method_cmd(g_pIdirCmd_open_dir=
  0x71002474f0) 得 0x28 FatDirSearchObject → `fs_log_assert_check(2000)` 分配 0x7D0
  迭代器（**2000 是十进制尺寸**，与结构体精确等大，无越界）→ 填控制区，路径补 `\\*` 存 aName。
- FsDirIterObj 布局（= IDirectoryContext 0xBC2 的超集）：vptr@0 = 0x7100247518；
  dwOpenFlags@0x8（bit0=目录 bit1=文件过滤）；aName[0x104]@0xc；dirInfo[0x688]@0x118
  （= FsDirInfoInternal 活动窗口，即 FsDirInfoObj 快照尺寸）；控制区 0x7a0 起：
  bReady@0x7a0（1=首次 FS_fsnext 已完成）、pDirSearchObj@0x7a8、pLogCtx@0x7b0、
  pFatWrapper@0x7b8、字符串槽@0x7c0、ppOwnerFatCtx@0x7c8（=&IDirectoryObj.pFatCtx）。
- 读链：`IDirectory_Read` / `IDirectory_ReadDirEntry` / `IDirectory_GetEntryCount`
  均以此对象为 this；ReadDirEntry 输出 `FsDirInfoObj`（state + dirInfo[0..0x688] 快照）。
- FsDirInfoInternal（0xAAA）核心语义：attr@0x478（0x10=目录，错则目录显示为文件）、
  sname@0x47a、**lname@0x487（char[513]，见 §9 H1）**、unicode_name@0x688、lname_w@0x8aa。

---

## 6. IDirectory 命令派发与虚表农场

### 6.1 命令派发约定

`fs_dispatch_method_cmd`（0x71000ce6a4）调用约定：`(*cmd->ppMethodSlot)(cmd)` ——
**方法收到整个命令结构体指针**，不是对象 this。

```
FsMethodCmd (0x18): { void **ppMethodSlot;  // +0x00 *ppMethodSlot = 方法入口
                      void *out;            // +0x08 open 类=输出指针；close 类=FsDirIterObj*
                      void *arg; }          // +0x10 open 类=OEM 路径 char*
命令槽束 (0x28): [0]=方法 [1]=nop桩(0x71000d1f28) [2]=fs_safe_release_object [3..4]=null
```

派发器同时做耗时统计（上下文 +2/+4/…/+0xc 的 min/max）。已知命令槽：
open_dir=0x71002474f0、close_dir_handle=0x7100247548、open_directory=0x7100247570、
fopen(FAT_OpenDirectory)=0x7100247450。

### 6.2 多层虚表组（0x7100247390）与三段层级

`0x7100247390` 起不是单一 vtable，而是同一 C++ 类族的多个子表：

| 子表 | 基址 | this 类型 | 内容 |
|---|---|---|---|
| A | +0x000 (0x…7390) | IDirectoryObj* | 22 槽服务接口（create/remove/mkdir/rmdir/get_entry_info/clean_dir/move/rename/exists/get_device_info(_light)/fopen/opendir/get_size/sync/stat/…） |
| B | +0x0c0 (0x…7450) | 分发上下文 | {FAT_OpenDirectory, nop, release}，fopen/opendir 命令源 |
| C | +0x0e8 (0x…7478) | FsDirFileObj* | 文件对象接口（dtor×2/read/write/sync/truncate/read_entry_data/io_control） |
| C' | +0x188 (0x…7518) | FsDirIterObj* | 客户端 IDirectory 虚表 16 槽（dtor/dtor_trace/**Read**/**GetEntryCount**/close/callback…） |
| G | +0x248 (0x…75d8) | 设备描述符 | FAT 介质驱动操作表 16 槽（见 §7） |
| H | +0x2d8 (0x…7668) | — | fs_locked_buffer_pool 接口（13 槽） |
| I | +0x350 (0x…76e0) | — | fs_nca_fs_obj + fs_locked_vtable_call_0xNN 访问器层 |

**调用层级** = 客户端虚表 → cmd 蹦床表 {trampoline, nop, release}（经 FsMethodCmd 由
fs_dispatch_method_cmd 二次间接）→ 服务端操作表。共享 nop 槽 0x71000d1f28 被 7 张虚表
引用，是各客户端类型的公共占位。

客户端虚表（0x7100247518）槽位：+0x00 fs_idirectory_destructor、+0x08 dtor_trace、
+0x10 IDirectory_Read、+0x18 IDirectory_GetEntryCount、+0x30 fs_idirectory_cmd_close_dir_handle、
+0x38 nop、+0x40 fs_safe_release_object、+0x60 fs_open_directory_callback、+0x68 nop、
+0x70 thunk（0x71000d4f98 = 链接器 branch island：b→0x71001ca280→b→0x7100188af0，
最终与 +0x40 同为 fs_safe_release_object；**this 调整量 = 0**，纯远距离尾跳）。

### 6.3 FsDirFileObj（0x58）与 IDirectoryObj（0x78）

- IDirectoryObj = 所有 fs_idirectory_* 服务方法的 this（vptr@0=0x7100247380、
  pStrObj@0x8、ppDriveLetter@0x10（路径以 `"%c:\%s"` 构造）、pLogCtx@0x18、
  pFatWrapper@0x30、pFatCtx@0x38、dwModeCopy@0x60、qOwner@0x70）。
- FsDirFileObj = fs_idirectory_fopen 用 `fs_log_assert_check(0x58)` 分配的每开文件对象
  （dwOpenFlags@0x8 bit0=读/bit1=写/bit2=追加、hFatHandle@0x10、pDirSubObj@0x28、
  bFlag@0x38=TLS 目录读跟踪、qTxnObj@0x50 其 +0x40 为写引用计数）。
- fs_idirectory_create 第 3 参 = **初始文件大小**（<0 → 0x2f7202；经
  fs_file_set_size_wrapper 设定）。

---

## 7. FAT 介质驱动接口（G 表）与 PRF2SAFE

### 7.1 G 表（16 槽，基址 0x71002475d8）

所有包装器 `fs_fatdrv_*`（0x7100110210..0x7100110ee0）统一原型
`undefined8 fn(u32 *pDevDesc, u32 *pOut)`：pDevDesc[0]=槽 id、pDevDesc[2]=设备对象指针
（magic **0xAABBCDDD** 校验；+0x04=状态 1=已注册/3=已挂载、+0x1c=最近错误码）。

| 槽 | 包装器 | 核心 callee |
|---|---|---|
| +0x00 | fs_fatdrv_register_device @0x7100110210 | fat_register_device_slot |
| +0x08 | fs_fatdrv_unregister_device @0x71001102b0 | fat_unregister_device_slot |
| +0x10 | fs_fatdrv_init_mount @0x7100110350 | 双路：pMountState[0]==0x12 → 状态机(2→3)（重挂载）；否则 fat_init_fat_data_structures（首次挂载） |
| +0x18 | fs_fatdrv_cleanup_unmount @0x7100110460 | fat_cleanup_fat_data_structures |
| +0x20 | fs_fatdrv_init_recovery @0x7100110540 | fat_init_prf2safe_recovery_v1 |
| +0x28 | fs_fatdrv_dispatch_io @0x7100110610 | fat_dispatch_io_operation |
| +0x30 | fs_fatdrv_set_flag_bit2 @0x7100110710 | fat_set_flag_bit2 |
| +0x38 | fs_fatdrv_compact_dir_entries @0x71001107d0 | fat_compact_directory_entries |
| +0x40 | fs_fatdrv_bitmap_find_free @0x71001108c0 | fat_bitmap_find_free_region |
| +0x48 | fs_fatdrv_bitmap_mark_used @0x7100110990 | fat_bitmap_mark_region_used |
| +0x50 | fs_fatdrv_bitmap_find_used @0x7100110a70 | fat_bitmap_find_used_region |
| +0x58 | fs_fatdrv_set_flag_bit1 @0x7100110b50 | fat_set_flag_bit1 |
| +0x60 | fs_fatdrv_clear_flag_bit1 @0x7100110c10 | fat_clear_flag_bit1 |
| +0x68 | fs_fatdrv_manage_recovery_slot @0x7100110cd0 | fat_prf2safe_manage_recovery_slot |
| +0x70 | fs_fatdrv_alloc_cluster_range @0x7100110dc0 | fat_allocate_cluster_range |
| +0x78 | fs_fatdrv_recovery_dispatch @0x7100110ee0 | fat_prf2safe_recovery_operation_dispatch |

### 7.2 PRF2SAFE 恢复机制（介质驱动层，第十四轮深挖完整版）

`FS_isPRF2SAFE` @0x7100114b90：memcmp "PRF2SAFE" 8 字节。完整字段见 `fs_structs.h`
的 Prf2SafeCtx（0x10C）。

#### 头/日志格式

- 恢复区头 = 2 个镜像 0x200 扇区（`fat_write_prf2safe_recovery_data`
  @0x71001118c0 一次写 2 扇区，位置 = RegionBase + (copy-2)×0xf2）：
  magic@0、ver@0x10=100(='d')/@0x11=0x65、u32@0x16=槽号、u32@0x20=错误码、
  u32@0x24=FAT 数、CRC32@0x1fc（`fs_temp_clear_and_restore` @0x7100114c20：
  清零字段→`fs_crc32_compute`→恢复字段，返回 CRC 值比较）。
- **日志 = 写前备份**：0x20 字节记录 {magic@0, 槽号游标@0x10, 错误码@0x14,
  起始扇区@0x18, 扇区数@0x1c}，双镜像（原位 + count×bps + 0x20 处）；
  每槽占 count+1 扇区（1 记录 + count 扇区备份数据），依次排在头扇区 +2 起；
  9 槽日志表 aSlotStart/aSlotCount（ctx+0x30/0x54）记录已备份区间。

#### 操作码总派发 `fat_prf2safe_recovery_operation_dispatch` @0x7100113680（op 越界→-11）

| op | 功能 |
|----|------|
| 1 | 扫描恢复头：0xac==0xffffffff 时从扇区 1 起逐扇区读（全零扇区跳过）；命中后校验 CRC@0x1fc、版本字节（0x10=='d' 且 0x11<0x66）、错误码@0x20∈(1,RegionEnd)、FAT 数@0x24 == ceil(FatSizeBytes/(bps×8))+0x15。有效→{扇区,1,错误码,FAT 数}；存在但无效→{扇区,2,-1,0}。 |
| 2 | 读第 N 份 FAT 副本头（扇区 = RegionBase+(N-2)×0xf2，主/备镜像 ±1）：校验 magic+CRC+版本 → ctx+0xe0=版本；输出 pArgs[4]=镜像号(1/2)、[5]=错误码@0x20、[6]=槽号@0x16。 |
| 3 | 打开恢复隐藏文件：路径 = 盘符 + `":\"` + ctx+0x98 卷标（13 字节），模式 **"r"**（串@0x71001cd07e）；校验文件大小 == pArgs[3]×bps 且起始簇 == pArgs[2]；ctx+0xa8==1 时额外 `fat_check_cluster_chain_contiguous`（@0x7100114790，读 FAT 项批量校验相邻 +1，允许尾项 0xFFFFFFFF）。pArgs[7]=1 通过 / 2 不符。 |
| 4 | 写全新头扇区：目标 0xffffffff 时从 0xac（否则扇区 1）找全零扇区；填 {magic,100@0x10,0x65@0x11,错误码@0x20,FAT 数@0x24,CRC@0x1fc} 单扇区写+verify（`fat_prf2safe_verify_data_operation` @0x7100114900 = `fs_data_operation_check_v2` 写模式 2）。 |
| 5 | 分配空闲簇范围并格式化恢复区：每副本需 ceil(FAT扇区数)+0x15 扇区、按 bSectorsPerFatCopy(0xf2) 归整后 ×2 簇；`fat_find_free_clusters_range_wrapper` 搜索，命中后 `fat_write_prf2safe_and_verify`（@0x71001145a0，见下）。输出 pArgs[2]=起始簇、[3]=扇区数。 |
| 6 | 恢复文件 IO：同 op3 路径，模式 **"w"**（串@0x71001cd394）；按 pArgs[2] 扇区号 ×bps 字节读出比对（`fat_file_io_operation_by_path` @0x7100111f30）。 |
| 7 | 直接 `fat_write_prf2safe_and_verify(ctx, pArgs[2]副本号)`。 |
| 8/0xf | 读/写 ctx+0x04 状态（op8 输出）。pArgs null → -7。 |
| 9 | `fat_device_state_machine` @0x7100111060：状态 0-4 迁移（2→ioctl(0x104,0x108)；3→查询/设 flags 后 ioctl(0,0)+type0，失败回滚 flags；4→type2 ioctl），写回 ctx+0x04。 |
| 10 | 读卷标（13 字节→pArgs）+ ctx+0xa8/0xac（→pArgs[4]/[5]）。 |
| 0xb | 写卷标（strnlen<0xd）+ 0xa8/0xac（来自指针参数，可 null 跳过）。 |
| 0xc | **日志回放**（最复杂，见下）。 |
| 0xd | `fat_device_check_operation_type2` @0x71001152b0。 |
| 0xe | 写 ctx+0x08 设备状态（限 <2）。 |

#### op0xc 日志回放（pArgs[2]=副本槽, [4]=错误码→0xd4, [5]/[6]=回放键2/1→0xdc/0xd8）

1. 定位日志区 = dwWriteSector(0xd0)+0x14 扇区，读入 pJournalBuf(0x78)；
   清空簇位图 pBitmapBuf(0x20)。
2. 链式遍历日志记录：每条记录 {key1@8, key2@0xc, 副本槽@0x10, 数据扇区数@0x18}，
   占 (count+1) 扇区；key1/key2 与 ctx+0xd8/0xdc 不符即停。
   命中记录：把备份数据（原 0x20 字节头 @槽×bps，原数据 @（槽+count)×bps+0x20）
   写回原扇区（`fs_validate_write_bounds`），并在位图中按 槽>>2..（槽+count-1)>>2
   置位（4 扇区/位）；随后清零日志内备份副本与镜像。
3. 记录链耗尽后走 FAT 备份扇区二次恢复：从副本 +2 起逐段校验
   {key1@0x10, key2@0x14, count@0x1c} 的记录，最多 0x11（17）轮，
   将 0x20 字节块按 @0x18 扇区写回。
4. 中途日志满（剩余 0）时：`fs_ioctl_wrapper(h,0,0)` →
   `fat_cluster_alloc_free_operation` @0x7100111b70 → ioctl(0x104,0x108) 重新扩容。
5. 全部成功后 `fat_write_prf2safe_recovery_data(h,ctx,0,0)` 重写全新头
   （槽 0/错误码 0），清 key1/key2，0xd4=1；任一步失败原样返回（-21 读失败 / -22 写失败）。

#### 初始化与槽管理

- `fat_init_prf2safe_recovery_v1` @0x71001117c0：重复初始化→-13；错误码∈
  {0x13,0x1d,0x6a} 或 (0x34 且设备 flags&0x0A)→-15（这些错误不建恢复点）；
  槽游标 = 旧游标+1（`fat_prf2safe_get_next_slot_index` @0x7100114b80），
  写头（`fat_write_prf2safe_recovery_data`），清位图，日志 9 槽表
  交替填 {0xffffffff,0}，置 flags bit0=1。
- `fat_prf2safe_manage_recovery_slot` @0x7100112bc0（G 槽 +0x68）：入参
  {起始扇区,扇区数}，范围须在 [RegionBase, RegionBase+RegionEnd×0xf2) 内且
  count<FAT扇区数；与 9 槽表逐一求交：已完全覆盖→0（不重复备份），部分重叠
  则裁剪（记录仍要写的剩余区间），跨越多槽尾部越界→-2；新槽追加在首个空闲
  槽位（9 槽满→-2），扇区偏移 = 0xd0 + 2 + Σ(前槽 count+1)，写记录+镜像
  （count+1 扇区）并登记槽表。

### 7.3 FAT 驱动核心层（G 表其余槽 callee，第十五轮）

#### 设备表（全局静态 @0x7100fdb7b0）

- 5 槽设备指针表 0x7100fdb7c0/0xc8/0xd0/0xd8/0xe0，计数 +0xb8，
  惰性初始化标志 +0xb0（首次访问清零全部）。
- `fat_register_device_slot` @0x71001112a0（G+0x00 核心）：设备对象状态
  （+0x04）∈{0,2,4}（掩码 0x15）否则 -1；写状态=1 后入表；已在表→-4，
  表满→-5，成功 count+1。
- `fat_unregister_device_slot` @0x7100111460（G+0x08 核心）：状态清 0，
  ioctl 检查（参数 1），不在表→-6；清槽 count-1。

#### 挂载初始化 `fat_init_fat_data_structures` @0x7100111530（G+0x10 首挂载路）

1. `fat_get_volume_status_info_wrapper(hDrv, ctx+0xe4)` → 卷状态；
   `fat_device_query_info_operation(hDrv, &ctx+0x104, &ctx+0x108)` →
   缓存 ioctl 参数（供状态机 3/日志扩容复用）。
2. `fat_check_fat_type_and_state(ctx)` != 1 → 出参=2（类型/状态不符）。
3. FAT 扇区数 = ceil(FatSizeBytes/(bps×8))；位图字节 = 对齐(ceil(扇区/32)×4)；
   工作缓冲总大小 = 位图字节 + (FAT扇区+1)×bps。
4. 经 ctx+0xc0 分配回调（盘符, 大小, &ptr）分配；无回调/重复分配→-7，
   分配失败→-9（回调来自注册时的设备描述，驱动提供）。
5. **工作缓冲布局**（基址同时存 +0xb0 与 +0x88）：[0,0x20 扇) 扇区缓冲
   （容量 0x20 → +0x90）→ 日志缓冲（+0x78，容量 FAT扇区+1 → +0x80）→
   位图（+0x20，字节数 +0x28，u32 数 +0x2c，bit=日志扇区占用）；
   总字节数 → +0xb8。
6. 状态迁移（+0x04）：1→2；2 保持；3→ioctl(0x104,0x108) 后→2；
   其余→0xffffffff。出参 1=成功。

#### IO 钩子 `fat_dispatch_io_operation` @0x7100111a60（G+0x28 核心）

- 请求类型（param_3+4）∈{0x11, 0x1000} 或 ctx+0x1c≠0（回放中）→ 直通 0。
- 否则按 ctx+0x14（最近错误码）分流：==0x12 → 以当前副本号
  （(0xd0-0x100)/0xf2+2）+ FAT扇区+0x15 扇区重写恢复文件
  （`fat_file_io_operation_by_path`）；其余 → `fat_cluster_alloc_free_operation`
  （日志刷盘）。
- 失败且错误码 ∉ {-21,-22,-26} → 清错误码、重写全新头（slot 0/err 0）；
  重写再失败（<-22）→ 清 flags bit0（去初始化，下次重新 init）。
- **结论：介质层把写前备份/恢复挂在了所有 IO 的公共路径上**，
  0x11/0x1000 是绕过日志的内部命令。

#### 日志刷盘 `fat_cluster_alloc_free_operation` @0x7100111b70

遍历位图置位段（上限 = 日志容量-1）：把日志缓冲中段内数据经扇区缓冲
（分块 ≤0x20 扇）写入磁盘 `总扇区(+0xf8) + FAT字节(+0xec) + 扇区号`
（恢复区数据带），先写后读回校验；段号必须递增（乱序→-2），
IO 失败→-21/-22。op0xc 日志满扩容后也调用它。

#### 位图/簇范围（G+0x40/0x48/0x50/0x70）

- `fat_bitmap_find_free_region` @0x7100112640（+0x40 核心）：在位图上
  （位↔扇区，范围 [总扇区数, 总扇区数+FAT字节)）自入参起点找 count 长
  连续置位区间，就地输出实际 {起始,数量}；越界/未找到→-2。
- `fat_allocate_cluster_range` @0x7100113240（+0x70 核心）：在入参簇范围上
  循环 `fat_allocate_clusters_wrapper` 分配并拼连续链（逐项校验相邻），
  越界检查 RegionEnd+2，`fat_verify_and_write_fat_entries` 写 FAT 项，
  成功后 `fat_free_cluster_chain_wrapper` 释放旧链（范围重分配模式）；
  输出 {数量,起始簇,末簇,起始块}。位图标记/查找两槽（+0x48/+0x50）
  为同族包装。

#### 卸载清理与位图两槽（第十六轮补齐）

- `fat_cleanup_fat_data_structures` @0x71001116e0（+0x18 核心）：ioctl(+0x104,
  +0x108) 后经 **ctx+0xc8 释放回调**（与 +0xc0 分配回调成对）释放工作缓冲
  （+0xb0），清 0xb0/b8/88/90/78/80；状态∈{0,2,4}→回 1。无缓冲/回调→-7，
  释放失败→-10。
- `fat_bitmap_mark_region_used` @0x7100112800（+0x48 核心）：{绝对扇区,数量}
  →FAT 区相对位图，日志缓冲（+0x78）逐位 OR 置位 + 日志占用位图（+0x20）
  按簇粒度置位；输出 {FAT字节+扇区,数量}，越界→-2。
- `fat_bitmap_find_used_region` @0x71001129b0（+0x50 核心）：与 +0x40 同族
  扫描，但按 {起始[0],上界[1],上次结果[2][3]} 续扫首个连续**已用**段，
  输出 [4]/[5]；未命中回显输入区间。
- 标志位三槽（+0x30/+0x58/+0x60）包装守卫一致：设备 state==3（已挂载）+
  设备+0x10 bit0（媒体就绪）+ 设备+0x14 错误码≠0x12，核心
  `fat_set/clear_flag_bit1/bit2` 操作 ctx flags bit1/bit2，失败记设备+0x1c。
  设备对象布局再证：+0=0xAABBCDDD、+0x04=状态、+0x14=错误码、+0x1c=最近错误。
- **G 表 16 槽全部有结论**（位图标记/查找仅行为级）。
- 本轮已同步 Ghidra：Prf2SafeCtx 重建（0x10C，+0x90 改名
  dwSectorBufSectors_0x90、新增 0xb0/0xb8/0xc0/0xc8/0xe4、
  0x1c/0xa8/0xac/0xd4 语义化更名）、12 处 plate 注释，
  已 save_all_programs。

#### 日志压缩 `fat_compact_directory_entries` @0x7100112140（G+0x38 核心，名不副实）

- 类型∈{0x11,0x1000} 或 ctx+0x1c≠0 → 0；扫描位图找连续置位段
  （≤9 段，总扇区 ≤ 日志容量），把每段合并为**单条大记录**
  {magic, key1@8=槽游标(+0x18), key2@0xc=错误码(+0x14), 总扇区@0x14,
  段起始@0x10, 段长@0x18}，双镜像写入恢复文件日志区（0xd0+0x14 起），
  成功后清 ctx+0x10 bit2。
- **关键佐证：op0xc 回放的 key1/key2 即 ctx+0x18（槽游标）/ctx+0x14
  （最近错误码）**——与回放代码中 `dwJournalKey1/2_0xd8/0xdc` 完全对应。
- 标志位槽（+0x30/0x58/0x60）为 ctx+0x10 bit1/bit2 的置/清包装（略）。

---

## 8. codepage 补丁面核对（fork 核心）

### 8.1 转换函数约定

- `PFCODE_CP932_OEM2Unicode`（0xfeac0，已被 `patch_utf8_to_utf16` 替换）：返回
  `(输出字节数<<16)|2`；`PFCODE_CP932_Unicode2OEM`（0xfec30，已被 `patch_utf16_to_utf8`
  替换）同约定。拆分由 `PFCODE_GetConvertWidth`（0x71000f7cf0）完成（高 16=oem 宽，低 16=uni 宽）。
- `PFCODE_CP932_OEMCharWidth`（0xfee00）内部直接调用 OEM2Unicode ⇒ 自动获得 UTF-8 宽度，无需另 patch。

### 8.2 指针步进类（已 patch，逐条验证通过）

`FAT_GetNextChar`(0xf45d8) / `FAT_GetNextPathComponent`(0xf4d8c) / `StringDesc_AddLeft`(0xf77e8) /
`StringDesc_GetCharCount`(0xf7984) / `StringDesc_CompareUnicode`(0xf7a80) / `StringDesc_CompareOem`(0xf7bd0)：
把"若多字节则 +1"改为"+ 返回值"，叠加原有固定 +1 后，1/2/3 字节 UTF-8 字符分别前进 1/2/3。
合法 UTF-8 下正确。

`patch_is_oem_mb_char`（0xfee40）语义缺口见 §9 R7。

### 8.3 显示方向数据流（正常）

```
exFAT File/Stream/Name 目录项
  → fat_process_directory_match / fat_copy_entry_to_fsobj_type85/typeC0/typeC1
  → FsObject.lname_w (UTF-16)
  → fs_find_directory_entry → fs_parse_directory
      → fs_iterate_directory_entries → fat_init_fs_object_from_entry
          → fat_init_fs_object_shortname（encode_flag bit1==0 时）
              → PFCODE_Str_Unicode2OEM(dirInfo+0x487, FsObject.lname_w)   ← patch 生效（但无上限，见 H1）
      → IDirectory_ReadDirEntry → memcpy dirInfo → IDirectory_Read
  → IDirectory_Read 写 nn::fs::DirectoryEntry(0x310)：
       path(+0x000)、attributes(+0x301)=(attr>>4)&3、type(+0x304)=(attr&0x10)==0、size(+0x308)
```

显示只经过 Unicode2OEM，不依赖 isOEMMBchar/GetNextChar ⇒ 显示稳定。
`IDirectory_Read` 的 0xd4af4 NOP 只去掉"字节≥0x7F 即丢弃"的过滤。

### 8.4 打开方向数据流

```
上层路径字节(UTF-8)
  → StringDesc_SetPtr(..., ENCODE_OEM)
  → fs_open_by_path_core / fs_locate_object
      exFAT：exfat_entry_lookup(0x710010ca20)
          → exfat_prepare_entry_search(0x71000fc8f0)
              → PFCODE_Str_OEM2Unicode(FsObject.name, path)        ← patch 生效
              → exfat_resolve_path(大写表) → fat_hash_shortname     (NameHash)
          → FAT_SearchDirectory1 → exfat_search_directory
              → fat_process_directory_match → fat_check_name_match
      FAT32：fat32_entry_lookup → FAT_ProcessDirectoryEntry
          → fat_process_long_filename_entry / FAT_MatchFileName1
              → FAT_MatchFileName → FAT_GetNextChar(已patch) + StringDesc_CompareOem(已patch)
                                   + FAT_MatchWildcardRecursive(未 patch isMB，R1)
```

exFAT 的匹配完全在 UTF-16 域做 ⇒ 只要 OEM2Unicode 输入正确理论上应命中；
"打不开"的残余风险来自 §9 的内存破坏与未覆盖点。

### 8.5 exFAT 条目处理链（第十八轮闭环）

**Stream 条目盘上布局定案**（读 `fat_copy_entry_to_fsobj_typeC0` / 写
`exfat_build_name_entry_buffer` 0x71000fd660 双向对称验证）：
`{0xC0@0, flags@1, rsvd@2, NameLen@3, NameHash@4, ValidDataLength(u64)@8,
rsvd@0x10, FirstCluster@0x14, DataLength(u64)@0x18}`。

FsObject 条目镜像字段：0x208 attr(u16)、0x210 DataLength、0x218–0x22b 时间戳+UTC offset、
0x23c FirstCluster、0x244 dirCluster、0x248 entryOffset、0x24a streamFlags(Stream+1)、
0x260 NameLength(Stream+3)、0x261 SecondaryCount(File+1)、**0x262 SetChecksum(u16, File+2)**、
**0x264 NameHash(Stream+4)**、**0x268 ValidDataLength(u64, Stream+8)**、0x270/0x274 条目集跨簇续写游标。

**打开/搜索链**：exfat_entry_lookup → exfat_prepare_entry_search（UTF-8→UTF-16 经补丁点
PFCODE_Str_OEM2Unicode → `exfat_resolve_path`(0x71000fb6a0) 按盘上 UpCase 表逐字符大写 →
NameHash=rotr1+char 存 +0x264；SecondaryCount=1+ceil(len/15)）→ FAT_SearchDirectory1 →
exfat_search_directory（遍历条目）→ fat_process_directory_match：
- 0x85 File：attr 过滤 + SecondaryCount 装载计数器；同时开始**条目集校验和**累积
  （rotr1+byte，仅 File 条目跳过字节 2-3）；
- 0xC0 Stream：**NameHash 硬门**——stream.NameHash != hash(大写搜索名) ⇒ 整个条目集跳过
  （该文件不可见，而非"名字不匹配"）；
- 0xC1 Name×N：名字片段拼入 FsObject.name（30B/条），每条累积校验和；集齐后
  校验和 == FsObject+0x262 才进入 fat_check_name_match（条目名再大写一次+通配符，双重大写幂等）。

**创建/更新/删除/重命名**：
- 创建：prepare_entry_search(setTime=1) → FAT_SearchDirectory1(name=null 找空位) →
  `fat_write_directory_entries`（0x85+0xC0+0xC1×N；中途失败把已写条目 type&~0x80
  回滚=0x05/0x40/0x41）；
- 更新（flush/write/close 调）：`exfat_write_file_entry`(0x71000fd430) →
  `exfat_prepare_entry_data`(0x71000fd180) 重算条目集校验和 → 存 +0x262 →
  exfat_build_file_entry_buffer(0x85, 0x71000fd380) + exfat_build_name_entry_buffer(0xC0)
  只写两主条目（C1 不动）；
- 删除：`exfat_delete_directory_entry`(0x71000fc720) 逐条目 type&~0x80 写回 + flush；
- 重命名：`exfat_rename_entries`(0x710010bb00) = prepare(新名, setTime=0) + 拷贝时间戳/
  FirstCluster/ValidDataLength + 删源 + 找空位 + 写目标（失败有对称回滚）。

**UpCase 表缓存**（FsDrvObject 新字段，已入 `fs_structs.h` + Ghidra 同步）：
0x1a0 首簇 / 0x1a8 大小 / 0x1b0 校验和 / 0x1b8 内存映射基址 / 0x1c0 容量 /
0x1c4 bit30=已验证驻留。`exfat_verify_upcase_table`(0x71000fbe70) 整表读入并做字节级
rotr1+byte 校验（失败 0x23）。resolve_path 查表未命中或 0xFFFF 压缩段 → 输出原字符（CJK 安全）。

**补丁面结论**：exFAT 匹配/存储全程 UTF-16 域，唯一编码依赖 = OEM2Unicode 补丁点
（prepare_entry_search / search_directory 两处调用）。NameHash 与条目集校验和均从同一
FsObject 缓冲派生，创建与打开自洽；互操作残余风险仅无效 UTF-8 输入（R5 越界读）。
附注："<" 开头的名字在 exfat_entry_lookup 直接返回 2；fat_check_name_match 有
"<N>"→dwEntryIndex 匹配分支，但 NameHash 硬门下 hash("<N>") 不会等于真实名字 hash，
"<N>" 索引打开应走枚举（ReadDirEntry）路径——若上机复现"<N>"打不开，先查这里。

---

## 9. 已确认高危点与风险清单

### 9.1 H1（高置信）：`FsDirInfoInternal.lname[513]` 无上限越界

- `fat_init_fs_object_shortname`（0x7100105ba0）在 OEM 路径下
  `PFCODE_Str_Unicode2OEM(dirInfo+0x487, FsObject.lname_w)`，目标 513 字节，无边界检查
  （`PFCODE_Str_Unicode2OEM` @0x71000f5840 逐字符前进并写 NUL）。
- 原 CP932 ≤255 字符×2B+NUL=511 ≤ 513（安全）；UTF-8 后 ≥171 个 3 字符即溢出，
  最坏 ~253B，紧接 0x688 = unicode_name/搜索模式缓冲/迭代状态标志。
- 可解释"大目录列表异常、子目录显示为文件"；**不能**解释典型短中文名打不开。
- 同类无上限点：exfat_prepare_entry_search / exfat_search_directory 写 FsObject 名字区
  （0x200B，风险较低）；fs_convert_string_encoding 的 Unicode2OEM。

### 9.2 风险点 R1–R7

| 编号 | 位置 | 问题 | 影响面 |
|---|---|---|---|
| R1 | FAT_MatchWildcardRecursive 0x71000f4770（0xf4874/0xf49ac/0xf4a7c） | "若多字节则指针+1"未改，3 字节 UTF-8 失步 | 短名回退匹配、通配符 |
| R2 | FAT_MakeShortName 0x71000f5ac0（0xf5dcc，2026-09-14 复核定案） | 实际用 pOEMCharWidth（ctx+0x28）非 isMB；补丁后宽 3 字符进入 2 字节拷贝循环（`subs w23,#2` 永不归零）→ **FAT32 创建中文文件名死循环**；修复 = `mov w23,w0`→`mov w23,#2`（宽按 2+1 消费，字节不丢） | 创建、重命名（FAT32） |
| R3 | FAT_ReplaceShortNameNumber 0x71000f6270 | **误报（2026-09-14 复核）**：用 pOEMCharWidth（ctx+0x28）逐字符推进（w23+=width），补丁后宽度自动正确，无需补丁 | — |
| R4 | StringDesc_ToUpper 0x71000f7c10 | OEM 分支有符号 toupper 逐字节，UTF-8 高位字节可能被改写 | 大写比较（写路径） |
| R5 | patch_utf8_to_utf16 | 3/4 字节分支无条件读 in[1..2] | 越界读（NUL 保护，低风险） |
| R6 | patch_utf16_to_utf8 | 2/3 字节分支不写 NUL | 依赖调用方补 NUL |
| R7 | patch_is_oem_mb_char | 忽略 byte_idx；续字节返回 1 与 OEM2Unicode 的 len=1 不自洽 | 失步连锁风险 |

### 9.3 动态验证与修复方向（摘要）

日志版 patch（环形缓冲 → /config/sys-patch/log.ini）验证 H1/H2；修复优先级：
① 给 Unicode2OEM 调用点加边界（H1，独立于症状）；② R1/R2/R3 改"+返回值"；
③ R4 逐字符或 ASCII-only；⑥ R6 补 NUL；⑦ R7 对齐续字节语义。
完整方案见早期记录与 `sysmod/src/main.cpp` 现行实现。

**2026-09-14 实施记录**（详见 `re_improve_plan.md` 末尾实施状态）：R7/R6/R5/H1/R4/R1×3/R2 已全部
落入 main.cpp 并编译验证（函数尺寸经 nm 实测）；R3 复核为误报无需补丁。

---

## 10. 函数原型对照表（最终版）

### 10.1 卷/池/对象生命周期

| 地址 | 原型 |
|---|---|
| 0x71000d7420 | `int fs_init_volume_context(FsDrvObject*, undefined8*, char volumeIndex, uint maxFileObjects, uint maxClusterCacheNodes, uint maxDirObjects)` |
| 0x71000ff250 | `FatFileObject * fat_allocate_file_object(FsDrvObject*, FsObject*)` |
| 0x7100109e40 | `FatDirObject * fat_find_or_alloc_dir_object(FsDrvObject*, FsObject*)`（原 fat_find_or_alloc_file_slot，误名已改） |
| 0x7100100280 | `int fs_locate_object(FsDrvObject*, StringDesc*, uint openFlags, FatFileHandle **ppOut)` |
| 0x71001040e0 | `int fs_open_file(uint driveId, StringDesc*, uint openFlags, FatFileHandle **ppOut)` |
| 0x71000fffd0 | `int fs_open_directory(StringDesc*, uint openFlags, FatFileHandle **ppOut)` |
| 0x7100109630 | `int fat_close_file_context(FsDrvObject*, FatFileHandle*, int forceClose)` |
| 0x7100107cb0 | `int fs_close_file_by_context(FsObject-ish handle, int force)`（0x28 池专用关闭路径） |
| 0x71000ff790 | `void fat_clear_all_file_handles(FsDrvObject*)`（清 0x520+0x48 池 → 清 +0x98） |
| 0x7100105820 | `void fat_clear_all_dir_object_pools(FsDrvObject*)`（原 fat_clear_all_file_objects，误名已改；清 0x510+0x28 池 → 清 +0x9c/+0xa0/0xa8/0xb0） |
| 0x71000da130 | `void fat_get_volume_handle_stats(char drive, u32 out[4])` |
| 0x71000d6940 | `bool fs_check_drive_state(FsDrvObject*)`（格式化事务根对象有效性） |
| 0x71000d7d10 | `int fat_mount_volume_core(...)`（**格式化/重整核心**，事务 0x12；根对象备份/恢复） |
| 0x7100105cb0 | `int fs_validate_directory_entry(FsObject*, FatDirObject **ppOut)` |
| 0x7100107b40 | `int fs_open_entry_core(FsDrvObject*, StringDesc*, void **ppOut)` |
| 0x7100109490 | `int fs_open_entry_worker(FsDrvObject*, StringDesc*, void **ppOutSlot)` |
| 0x71000ffbb0 | `void fat_setup_file_handle(FatFileHandle*, uint openFlags)`（dwStatus=0x20000001 等） |
| 0x71000e9320 | `int fs_init_directory_context(FatFileContextPart*, ulong, FsDrvObject*, uint *pClusterIn, byte *pFlagsIn, qword *pAllocatedBytesIn, uint mode)`（mode 2=文件 4=目录） |
| 0x71000d9900 | `fs_alloc_thread_ctx_node`（原 fat_allocate_dir_context，误名已改：线程 FS 上下文节点 0x16c0 链表分配器） |

### 10.2 文件 I/O

| 地址 | 原型 |
|---|---|
| 0x71001032d0 | `int fs_file_open_core(FsDrvObject*, FatFileObject*, FsDirInfoInternal*)` |
| 0x7100100a20 | `int fs_file_write_core(FsDrvObject*, FatFileHandle*, int flushFlag)` |
| 0x7100103ca0 | `int fs_file_set_size_core(FsDrvObject*, FatFileHandle*, ulong newSize)` |
| 0x71001039c0 | `int fs_file_set_size_transactional(...)`（事务 0x45，即 ftruncate；原 fs_file_delete，误名已改） |
| 0x7100116100 | `fs_file_set_size_wrapper`（原 fs_file_delete_wrapper） |
| 0x7100103e20 | `int fs_file_seek(FsDrvObject*, FatFileHandle*, ...)` |
| 0x7100101020 | `int fs_file_read_core(FsDrvObject*, FatFileHandle*, ...)` |
| 0x7100116670 | `fs_close_file_handle`（= fs_close_file_by_context(obj,0)+CheckError；原 fs_open_file_by_oem_path，误名已改） |

### 10.3 目录搜索 / 条目匹配

| 地址 | 原型 |
|---|---|
| 0x7100105e60 | `int fs_find_directory_entry(FsDrvObject*, StringDesc*, int resolveFlag, FsObject*, uint*, void*)` |
| 0x7100106080 | `int fs_update_directory_cache(FsDrvObject*, StringDesc*, FsObject*, uint, void*)` |
| 0x7100106910 | `int fs_parse_directory(..., FsDirInfoInternal*)` |
| 0x7100106de0 | `int fs_iterate_directory_entries(FsDirInfoInternal*, ...)` |
| 0x71001058e0 | `fat_init_fs_object_from_entry(FsDirInfoInternal*, FsObject*)` |
| 0x7100105ba0 | `fat_init_fs_object_shortname(FsDirInfoInternal*, ...)`（写 lname@0x487，H1 现场） |
| 0x71000f8e30 | `int FAT_FindDirectoryEntry1(FatFileContext*, FsObject*, StringDesc*, byte, uint*, uint*, uint*, uint)` |
| 0x71000f8f70 | `int FAT_FindDirectoryEntry(FatFileContext*, FsObject*, StringDesc*, byte, uint*, uint*, uint*, uint)` |
| 0x71000f1530 | `int FAT_FindDirectoryEntry2(FatFileContextPart*, FsObject*, uint, StringDesc*, byte, uint*, uint*)` |
| 0x71000f16e0 | `int FAT_SearchDirectory1(FsObject*, int needFree, FatFileContextPart*, ulong*, StringDesc*, uint, uint*)` |
| 0x71000f9e70 | `int FAT_ProcessDirectoryEntry(FsObject*, FatFileContext*, StringDesc*, byte, uint*, uint)` |
| 0x71000f3c20 | `bool FAT_MatchDirEntry(FsObject*, StringDesc*, uint *isShortMatch, uint *hasTilde)` |
| 0x71000f3f20 | `int FAT_MatchFileName(char*, StringDesc*, uint flags1, uint cmp_unicode)` |
| 0x71000f4770 | `bool FAT_MatchWildcardRecursive(ushort, NameCtx*, ushort, StringDesc*)` |
| 0x71000f5ac0 | `int FAT_MakeShortName(char*, StringDesc*)` |
| 0x71000f6270 | `int FAT_ReplaceShortNameNumber(char*, uint)` |
| 0x71000f4bc0 | `int FAT_GetNextPathComponent(void*, StringDesc*, int allowWildcard)` |
| 0x71000f44e0 | `ushort FAT_GetNextChar(StringDesc*, ushort get_unicode)` |
| 0x71000f4f30 | `int FAT_SplitPath_Inner(void*, StringDesc*, StringDesc*, StringDesc*)` |
| 0x71000f5460 | `void FAT_GetShortNameInner(char*, FatBaseEntry*, uint)`（恒返 0，sname 出参） |
| 0x71000f1100 | `void FAT_GetShortNmae(FsObject*, FatBaseEntry*)` |
| 0x710010c970 | `int exfat_search_directory_entries(FsDrvObject*, uint dirStartCluster, byte attrByte, u64 exfatDataLength, uint targetFatCluster, int *outChainIndex)`（第十七轮坐实：p3=init 类型字节（exFAT=fctx+0x2c8 attr，否则 1，非 sectorShift）；p4=exFAT stream DataLength（fctx+0x2d0，=dirInfo.field_0x38）；p5=目标 FAT 簇号；p6=出参链内序号，-1 未找到→0xd） |
| 0x71000e72a0 | `int fat_find_cluster_by_index(FatFileContextPart*, uint fatClusterNo, uint *outChainIndex)`（沿目录簇链找 fatClusterNo 所在位置：逐项 fat_read_fat_entry_dispatch 直到命中，exFAT 位图路径直接 out=clusterNo-startCluster；参数名 entryIndex 为误名） |
| 0x710010ca20 | `int exfat_entry_lookup(FsDrvObject*, FatFileContext*, StringDesc*, FsDirInfoInternal*)` |
| 0x71000f9db0 | `fs_traverse_directory_path`（缓冲参数 = FsObject*） |

### 10.4 IDirectory 服务接口（0x71000d1bc0 起，26 个）

`FsErrorCode_e fs_idirectory_*` 系列，this 均为 IDirectoryObj*（0x78）：

create(0x71000d1bc0, path, long initialSize)、remove(0xd1f30)、mkdir(0xd2424)、
mkdir_internal(0xd21c0, flags bit1=fs_create_by_oem_path(path,0x30))、rmdir(0xd2430)、
get_entry_info(0xd2660)、clean_dir(0xd2890)、move(0xd2ae0, 仅目录)、rename(0xd2df0, 仅文件)、
exists(0xd0760)、get_device_info(0xd08a8, 总容量=sec×clus×bytes)、get_device_info_light(0xd0a34)、
fopen(0xd1300, → FsDirFileObj**)、**opendir(0xd1890, → 0x7D0 迭代器)**、sync(0xd1198)、
stat(0xd0ec0)、get_timestamps(0xd0bc0)、init_stat_buffer(0xd111c, 清 0xC0)、
get_size(0xd30d0, **stub 恒 0**)、destructor(0x71000cef38/0xcf0f8)。

FsDirFileObj*（0x58）系列：file_obj_destructor(0xd3810/0xd38a4)、file_read(0xd3950，
先经 vtable+0x30 取长度做越界钳制)、write_file(0xd3db0)、sync_file(0xd4170)、
truncate(0xd436c)、read_entry_data(0xd46a4, FS_fgetdta 0x688)、io_control(0xd4844,
cmd=3→pDirSubObj vtable+0x38 / cmd=2→fs_fatwrapper_cleanup_rewind / 其余 0x31a602)。

客户端迭代器（FsDirIterObj*）：`IDirectory_Read`(iter, long *outCount, nn::fs::DirectoryEntry*, long maxCount)、
`IDirectory_GetEntryCount`(iter, long *outCount)、`IDirectory_ReadDirEntry`(iter, FsDirInfoObj *out)
（out[0].state: 1=有项 0=结束；fs_get_last_error()==2=目录尾）、
`fs_open_directory_callback(undefined8 *pDispatchCtx)`。
命令槽方法：`fs_idirectory_cmd_open_dir`(0x71000d4934)、`fs_idirectory_cmd_close_dir_handle`
(0x71000d4d38，原 fs_idirectory_open_file_by_path，误名已改)。
上层包装：`fs_open_dir_by_oem_path`(0x71001165f0，原 fs_idirectory_get_entry_size，误名已改)。

### 10.5 FS 核心辅助（0x71000ce* 区，已全部命名）

fs_idir_cmdobj_construct(0xce014)、fs_idir_cmdobj_set_flag_0x58(0xce040)、
fs_idir_cmdobj_invoke_code_mapped(0xce050)、fs_nop_then_release_object(0xce62c)、
fs_map_error_code_index(0xce670)、fs_fatal_unreachable_thunk(0xce698)、
fs_set_global_7100fcfbf8(0xce7d0)、**fs_fatwrapper_cleanup_rewind**(0xce9d0)、
**fs_fatwrapper_recover_if_error**(0xcea9c)、fs_map_volume_error_code(0xcedc8)、
fs_geterror_last(0xceeac)、fs_set_global_7100fcfc08(0xceef0)、fs_get_const_0x4a000(0xceefc)、
fs_detach_volume_handler(0x71000cefec)、fat_search_directory_entries_by_path(0x710010b820)、
fs_volume_storage_operation_wrapper(0x7100115eb0)、fs_dispatch_method_cmd(0x71000ce6a4)。
⇒ FS 核心区（0x71000ce000–0x7100120000）FUN_ 未命名函数已清零。

### 10.6 卷信息/杂项

| 地址 | 原型 |
|---|---|
| 0x71000d5910 | `int fs_get_volume_dir_cache(FsDrvObject*, void **ppOut)`（返回 drvObj+0x218） |
| 0x71000d5990 | `int fs_set_dir_cache(FsDrvObject*, void*)` |
| 0x71000d5830 | `int fs_read_current_dir_entry(FsDrvObject*, void *out)` |
| 0x7100109990 | `ulong fs_check_and_delete_directory(FsDrvObject*, FsObject*, uint flags)` |
| 0x71000e83c0 | `ulong fat_allocate_clusters_core(FatFileContextPart*, uint startCluster, uint clusterCount, ulong byteCount)` |
| 0x71000eb580 | `ulong fat_find_free_cluster_range(FsDrvObject*, ulong, uint, uint, int, uint*, int*, undefined4*)` |
| 0x710010bda0 | `int exfat_write_zero_clusters(FsDrvObject*, void*, ulong)` |
| 0x71000f51b0 | `FsDrvObject * FAT_GetFsDrvByPath(StringDesc*)` |
| 0x71000f7ce0 | `int PFCODE_CP932_ConvertWidth(int oemWidth, short uniWidth)` |
| 0x71000f7cf0 | `void PFCODE_GetConvertWidth(int convertRet, ushort *oemWidth, ushort *uniWidth)` |
| 0x71000d5150 | `PFCODE_CP932_Init`（注册 6 个代码页回调到 0x7100fcfc38 对象 +0x18..0x40） |

---

## 11. 地址—函数对照（补丁面）

| 文件偏移 | 函数 | 说明 |
|---|---|---|
| 0xd4af4 | IDirectory_Read | 名字非法字节过滤分支（NOP） |
| 0xfeac0 | PFCODE_CP932_OEM2Unicode | UTF-8→UTF-16（替换） |
| 0xfec30 | PFCODE_CP932_Unicode2OEM | UTF-16→UTF-8（替换） |
| 0xfee40 | PFCODE_CP932_isOEMMBchar | 字符长度判定（替换，R7） |
| 0xf45d8 | FAT_GetNextChar | ptr 步进（已 patch） |
| 0xf4d8c | FAT_GetNextPathComponent | ptr 步进（已 patch） |
| 0xf77e8 | StringDesc_AddLeft | ptr 步进（已 patch） |
| 0xf7984 | StringDesc_GetCharCount | ptr 步进（已 patch） |
| 0xf7a80 | StringDesc_CompareUnicode | ptr 步进（已 patch） |
| 0xf7bd0 | StringDesc_CompareOem | ptr 步进（已 patch） |
| 0x71000f5840 | PFCODE_Str_Unicode2OEM | 无上限输出（H1） |
| 0x71000f5960 | PFCODE_Str_OEM2Unicode | 输入转换 |
| 0x7100105ba0 | fat_init_fs_object_shortname | 写 dirInfo+0x487（lname） |
| 0x71001058e0 | fat_init_fs_object_from_entry | 目录项 → FsDirInfo |
| 0x71000f3c20 | FAT_MatchDirEntry | 长/短名匹配入口 |
| 0x71000f4770 | FAT_MatchWildcardRecursive | 未覆盖 isMB（R1） |
| 0x710010ca20 | exfat_entry_lookup | exFAT 打开入口 |
| 0x71000fc8f0 | exfat_prepare_entry_search | 路径→UTF-16 + NameHash |
| 0x71000fa7a0 | exfat_search_directory | exFAT 目录搜索 |
| 0x71000fb6a0 | exfat_resolve_path | UpCase 表逐字符大写（第十八轮） |
| 0x71000fbe70 | exfat_verify_upcase_table | UpCase 表读入+校验（第十八轮） |
| 0x71000fcb10 | fat_hash_shortname | exFAT NameHash（rotr1+char）（第十八轮） |
| 0x71000fd180 | exfat_prepare_entry_data | 构建 0x85/0xC0/0xC1 + 条目集校验和（第十八轮） |
| 0x71000fd380 | exfat_build_file_entry_buffer | 0x85 File 条目缓冲（第十八轮） |
| 0x71000fd430 | exfat_write_file_entry | 条目更新写（flush/write/close）（第十八轮） |
| 0x71000fd660 | exfat_build_name_entry_buffer | 0xC0 Stream 条目缓冲（第十八轮） |
| 0x71000fc720 | exfat_delete_directory_entry | 条目集删除（type&~0x80）（第十八轮） |
| 0x710010bb00 | exfat_rename_entries | 重命名 = 删源+找空位+写目标（第十八轮） |

---

## 12. 范围外与可选后续

- **476 个 vptr 构造函数反查**：正式划出范围——属 nn::ro/NCA/GC 等与 fork 补丁面无关的
  子系统，且本环境 Ghidra 脚本执行被禁；与本工程相关的虚表族（0x7100247xxx 农场）已全部识别。
- ~~**PRF2SAFE 介质层**~~：第十四轮已完整分析（§7.2）——厂商中间件行为，
  与 codepage 补丁无交集，结论仅作记录。
- ~~FsDirFileObj 客户端块成员 / FsDirIterObj thunk 调整量 / exfat_search_directory_entries 参数语义~~：
  第十七轮全部关闭（§6.2/§10.3）——FsDirFileObj 由 fopen 构造路径定名完毕，
  f_0x0c/0x39-0x3f/0x49-0x4f 经全部 7 个方法反编译确认不触碰（保留）；
  +0x70 thunk = branch island→fs_safe_release_object（调整量 0）；
  exfat_search_directory_entries 6 参语义坐实（目标 FAT 簇号→链内序号）。
