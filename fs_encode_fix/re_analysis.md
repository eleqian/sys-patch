# FS 逆向分析最终结论（19.exfat.FS.kip1，image base 0x7100000000）

> 状态：FS 卷驱动结构与生命周期分析已闭环（2026-09-13 第十二轮收尾，无阻塞遗留）。
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
+0x38 nop、+0x40 fs_safe_release_object、+0x60 fs_open_directory_callback、+0x68 nop、+0x70 thunk。

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

### 7.2 PRF2SAFE 恢复机制（介质驱动层，非 fork 补丁面）

- `FS_isPRF2SAFE` @0x7100114b90：memcmp "PRF2SAFE" 8 字节。
- 恢复区头 = 2 个镜像 0x200 扇区：magic@0、ver@0x10=100/@0x11=0x65、u32@0x16=槽号、
  u32@0x20=错误码、u32@0x24=FAT 数、checksum@0x1fc。
- **日志 = 写前备份**：0x20 字节记录 ×2 镜像 {magic, 槽号@0x10, 错误码@0x14,
  起始扇区@0x18, 扇区数@0x1c}；9 槽日志表（Prf2SafeCtx+0x30/0x54）记录已备份区间。
- `fat_prf2safe_recovery_operation_dispatch` @0x7100113680 = 15 操作码总派发
  （op1 扫描校验头 / op4 写头 / op5 分配簇+格式化恢复区 / op6 文件 IO /
  op0xc 日志回放 / op10/0xb 读写卷标等）。完整字段见 `fs_structs.h` 的 Prf2SafeCtx（0x10C）。

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
| R2 | FAT_MakeShortName 0x71000f5ac0（4 处 isMB） | 8.3 短名按 2 字节估算空间，UTF-8 可能超长/截断 | 创建、重命名 |
| R3 | FAT_ReplaceShortNameNumber 0x71000f6270 | 同上 | 重名短名生成 |
| R4 | StringDesc_ToUpper 0x71000f7c10 | OEM 分支有符号 toupper 逐字节，UTF-8 高位字节可能被改写 | 大写比较（写路径） |
| R5 | patch_utf8_to_utf16 | 3/4 字节分支无条件读 in[1..2] | 越界读（NUL 保护，低风险） |
| R6 | patch_utf16_to_utf8 | 2/3 字节分支不写 NUL | 依赖调用方补 NUL |
| R7 | patch_is_oem_mb_char | 忽略 byte_idx；续字节返回 1 与 OEM2Unicode 的 len=1 不自洽 | 失步连锁风险 |

### 9.3 动态验证与修复方向（摘要）

日志版 patch（环形缓冲 → /config/sys-patch/log.ini）验证 H1/H2；修复优先级：
① 给 Unicode2OEM 调用点加边界（H1，独立于症状）；② R1/R2/R3 改"+返回值"；
③ R4 逐字符或 ASCII-only；⑥ R6 补 NUL；⑦ R7 对齐续字节语义。
完整方案见早期记录与 `sysmod/src/main.cpp` 现行实现。

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
| 0x710010c970 | `int exfat_search_directory_entries(FsDrvObject*, uint startCluster, byte sectorShift, ulong clusterIndex, int entryOffset, int *outIndex)`（2/3 参暂定） |
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

---

## 12. 范围外与可选后续

- **476 个 vptr 构造函数反查**：正式划出范围——属 nn::ro/NCA/GC 等与 fork 补丁面无关的
  子系统，且本环境 Ghidra 脚本执行被禁；与本工程相关的虚表族（0x7100247xxx 农场）已全部识别。
- **PRF2SAFE 介质层**：厂商中间件行为，与 codepage 补丁无交集（§7 仅作记录）。
- 可选：FsDirFileObj 服务端表之外的客户端块成员（0x71000d30d0 等）精确定名；
  FsDirIterObj 客户端块 thunk 调整量；exfat_search_directory_entries 2/3 参语义坐实。
