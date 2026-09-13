
## 1.14 第十二轮：0xa0/0xa8 定案（穷尽搜索）+ IDirectory 虚表农场（2026-09-13 深夜）

### dwPinCount_0xa0 / pRootObj_0xa8 / pRootSearchObj_0xb0 — 穷尽式定案

对全 kip（45.5 万条指令）做了指令级穷尽搜索（str/stp/stur/add × #0xa0/#0xa8 偏移 +
0x8c8 卷步长寻址），结论：

- **+0xa0 无递增点**。全部写入仅 5 处：
  - `fat_close_file_context` @0x7100109774: -1（每次关闭无条件）
  - `fat_mount_volume_core` @0x71000d8288 区: 置 1（格式化完成后，且有原根对象时）
  - `fat_clear_all_dir_object_pools`（原 fat_clear_all_file_objects，本轮改名）@0x7100105820:
    `*(u64*)(drvObj+0x9c)=0` 8 字节存储**同时清 0x9c+0xa0**
  - `fs_format_volume_core` @0x710010dcf4/0x710010e3d8: `stp xzr,xzr,[x27,#0xa0]`
    成对清 0xa0+0xa4
  - `fat_unmount_volume_by_letter` / `fs_check_drive_state`: 只读
- **+0xa8 无"新指针"写入点**。恢复（fat_mount_volume_core @0x71000d82d4）写回的
  就是格式化前读出的同一指针；清零点 = fat_close_file_context / 
  fat_clear_all_dir_object_pools / fat_clear_file_table（均 `stp xzr,xzr,[x,#0xa8]`）。
- 交叉复核计数器配对：`fat_clear_all_file_handles`（清 0x520+0x48 池）清 **+0x98**；
  `fat_clear_all_dir_object_pools`（清 0x510+0x28 池，函数名误导，已改名）清 **+0x9c**；
  fat_mount_volume_core 中清 handles/cache 由 +0x98 门控、清目录池由 +0x9c 门控
  → 第十轮 stats 配对第三次独立验证 ✓。
- 0xa4：仅与 0xa0 成对清零，无其他引用 → 保留字段。

**定性**：0xa0/0xa8/0xb0 = **格式化事务（0x12）持有的"跨格式化根目录对象上下文"**。
格式化客户端先以同一事务上下文打开根目录（对象驻留 0x510 池，
qwOwnerTag_0x500==事务 ctx），fat_mount_volume_core 以 0xa0>0 && 0xa8 有效 &&
ownerTag==事务 ctx 为前置条件（否则 0x31/0x24），格式化期间备份/还原该对象对，
完成后置 0xa0=1、0x9c=1。常规 open/close 路径只 -1 / 清零，从不建立该缓存——
递减与递增的不对称是设计使然（pin 只在格式化事务窗口内非零）。
误读消除：第九至十一轮记录的"递增方待查"实为不存在。

### IDirectory 虚表农场（0x7100247400–0x71002475d0）— "三段子表"定案

内存布局（每槽 8 字节）：

```
0x7100247400  IDirectory 客户端块: fs_idirectory_opendir, 0x71000d30d0,
              0x71000656f8/04/10, 0x71000d1198, 0x71000d0ec0, 0x71000d111c
0x7100247450  cmd 表 {FAT_OpenDirectory, fs_idirectory_nop, 0x71000d380c}
              = g_pIdirCmd_open_dir 目标
0x7100247480  FsDirFileObj 服务端操作表（9 项）:
              [0] fs_idirectory_file_obj_destructor
              [1] fs_idirectory_file_obj_destructor_logged
              [2] fs_idirectory_file_read
              [3] fs_idirectory_write_file
              [4] fs_idirectory_sync_file
              [5] fs_idirectory_truncate
              [6] fs_idirectory_read_entry_data
              [7] fs_idirectory_io_control
0x71002474d0  cmd 表 {0x71000d4924, nop, 0x71000d4930}
0x71002474f8  cmd 表 {fs_idirectory_cmd_close_dir_handle, nop, 0x71000d4960}
0x7100247518  FsDirIterObj 客户端虚表 (pVptr, 16 槽):
  +0x00 fs_idirectory_destructor        (opendir 替换迭代器时 +0x08 被调用)
  +0x08 fs_idirectory_destructor_trace
  +0x10 IDirectory_Read
  +0x18 IDirectory_GetEntryCount
  +0x20..0x28 NULL
  +0x30 fs_idirectory_cmd_close_dir_handle
  +0x38 fs_idirectory_nop   ← 7 个虚表共享的 nop 槽 (0x71000d1f28)
  +0x40 fs_safe_release_object
  +0x48..0x58 NULL
  +0x60 fs_open_directory_callback
  +0x68 fs_idirectory_nop
  +0x70 (未命名 thunk 0x71000d4f98)
  +0x78 NULL
```

层级 = **客户端虚表 → cmd 蹦床表 {trampoline, nop, release}（经
FsMethodCmd{ppMethodSlot,pArg,pOut} 由 fs_dispatch_method_cmd 二次间接）→
服务端操作表**。共享 nop 槽 0x71000d1f28（7 处 DATA 引用）是各客户端类型
虚表的公共占位。第五轮遗留的"三段子表层级"就此定案。

### 关于 476 个 vptr 构造函数（第五轮遗留）的处置

该数量级为全 kip C++ 对象构造函数（含 nn::ro/NCA/GC 等与 FS 卷驱动无关的子系统），
在本环境脚本执行被禁（GHIDRA_MCP_ALLOW_SCRIPTS 未开）的情况下逐个反查不可行，
且与 fork 补丁面（fs 文件/目录打开路径、codepage）无交集——**正式划出范围**，
已在 Ghidra 中可见的客户端虚表族（0x7100247xxx 农场）全部完成识别。

### Ghidra 回写（save 完成）

- 改名：fat_clear_all_file_objects → **fat_clear_all_dir_object_pools**
- plate 注释 ×3：fat_clear_all_dir_object_pools / fat_clear_all_file_handles /
  fs_check_drive_state（含穷尽搜索结论）
- fs_structs.h：0xa0/0xa4/0xa8 注释重写（gcc -fsyntax-only 通过）

### 遗留

- 无阻塞遗留。可选后续：FsDirFileObj 服务端表前两项之外的 0x71000d30d0 /
  0x71000d1198 等客户端块成员精确定名；PRF2SAFE 介质层（非 fork 范围）。
6） |
| 0x21e | byte | `modify10ms` | exFAT LastModified10msIncrement（`type85` +0x16） |
| 0x220 | ushort | `accessTime` | exFAT LastAccessedTimestamp 低 16（`type85` +0x10） |
| 0x222 | ushort | `accessDate` | DOS 最后访问日期（`entry[0x12]`；exFAT LastAccessed 高 16） |
| 0x224 | byte | `accessTz` | exFAT LastAccessedUtcOffset（`type85` +0x18） |
| 0x225 | byte | `createTz` | exFAT CreateUtcOffset（`type85` +0x15） |
| 0x226 | ushort | `modifyTime` | DOS 修改时间（`entry[0x16]`；exFAT LastModified 低 16） |
| 0x228 | ushort | `modifyDate` | DOS 修改日期（`entry[0x18]`；exFAT LastModified 高 16） |
| 0x22a | byte | `modifyTz` | exFAT LastModifiedUtcOffset（`type85` +0x17） |
| 0x230 | ptr | `drvObj` | 由外层填入 |
| 0x238 | int | `pathOffset` | 路径解析游标（字符数）；`fat_adjust_path_offset` 对 `..` 回溯时增减 |
| 0x23c | uint | `firstCluster` | 对象自身 FirstCluster（exFAT Stream +0x14；FAT `cluster_h<<16|cluster_l`） |
| 0x240 | uint | `entryIndex` | 目录内条目序号；也用于短名 `~N` 数字尾（`fat_format_number_to_unicode`） |
| 0x244 | uint | `dirCluster` | 条目所在目录簇；写回时用于 `fat_write_cluster_cache` 定位 |
| 0x248 | ushort | `entryOffset` | 条目在目录内的字节偏移；与 0x244 组成 (簇,偏移) |
| 0x24a | byte | `streamFlags` | exFAT Stream GeneralSecondaryFlags（`typeC0` +1；FAT 置 0xff） |
| 0x24c | uint | `dirStartCluster` | 所在目录自身的起始簇（`fs_get_parent_directory_info` 用它打开父目录） |
| 0x250 | byte | `sectorSize` | 搜索暂存：drvObj 每扇区字节数低字节（FAT/exFAT 搜索结果） |
| 0x258 | qword | `dirSearchParam` | 搜索暂存：`ctx_part.pField_0x58` 指向的 8 字节 |
| 0x260 | byte | `nameLen` | exFAT Stream NameLength |
| 0x261 | byte | `entryNum` | exFAT File 项 secondary count / FAT LFN 数目 |
| 0x262 | ushort | `nameArea.setChecksum` | exFAT File 项 SetChecksum 低字节 + `shortName[0]` 为高字节；FAT 时为 LFN 校验和字节 |
| 0x263 | char[13] | `nameArea.name.shortName` | FAT 8.3 短名（与 exFAT 的 NameHash@0x264、ValidDataLength@0x268 重叠） |
| 0x270 | union u32/byte | `status` / `scase` | **FAT**：低字节 = NT case flags（`entry[0xc]`，`fat_copy_entry_info_to_output` 写入、`fat_write_directory_entry` 回读）；**exFAT 匹配**：整体作为 `-1` 哨兵 / 多簇条目集的位置暂存 |
| 0x274 | uint | `searchPos` | exFAT 空闲槽搜索的位置暂存（初始 0xffffffff） |

> `FAT_MatchDirEntry` 里的 `fsObj[1].lname_w + 0x13` 其实等价于 `FsObject+0x263`（short_name），是 demangler 尺寸过小造成的指针数组假象；重建后该假象消失。
>
> 注：Ghidra 里字段名前缀由命名约定重写（如 `aLongName`/`dwFirstCluster`/`nScase`），语义与上表一致；`fs_structs.h` 使用上表拼写。

#### `FsDirInfoInternal`（目录信息，`IDirectoryContext.dirInfo` @ctx+0x118，0xAAA）

| 偏移 | 类型 | 名称 | 说明 |
|---|---|---|---|
| 0x010 | ptr | `drvObj` | |
| 0x018 | uint | `cluster` | 当前目录起始簇 |
| 0x01c | uint | `startIndex` | 下一次迭代的条目索引 |
| 0x020/0x024 | uint | `field4_0x20` / `cluster1` | |
| 0x028 | byte | `encode_flag` | bit1=UNICODE |
| 0x02c | uint | `ch_len` | 字符数<<16 |
| 0x030 | ushort | `entry_num` | |
| 0x032 | ushort | `nameHash` | exFAT NameHash |
| 0x034 | byte | `attr1` | |
| 0x038 | qword | `field_0x38` | `fs_parse_directory` 从 FsObject.file_size 拷入 |
| 0x040 | ushort[260] | `path_w` | 目录宽字符路径 |
| 0x248 | byte | `nameLen` | |
| 0x24a | byte | `attrFilter` | 搜索属性过滤（0x77 等） |
| 0x24b | char[520] | `oemName` | 目录名/OEM 搜索模式，`fs_convert_string_encoding` 输出 |
| 0x454–0x468 | ushort/byte | 时间字段 | modify/access/create |
| 0x470 | qword | `file_size` | |
| **0x478** | ushort | `attr` | **文件属性（0x10=目录）**，错则被当文件 |
| 0x47a | char[13] | `sname` | |
| **0x487** | **char[513]** | `lname` | UTF-8 长名，**紧接 0x688** |
| 0x688 | ushort[?] | `aUnicodeName` | 宽字符搜索模式；首 wchar 兼作迭代状态标志 |
| 0x890 | ushort[13] | `sname_w` | |
| 0x8aa | ushort[256] | `lname_w` | UTF-16 长名 |

- `IDirectory_Read` 输出的长名即 `dirInfo+0x487`、短名 `dirInfo+0x47a`、属性 `dirInfo+0x478`。
- **`lname[513]` 紧接 `aUnicodeName`（0x688）**，UTF-8 越界会先踩坏搜索模式缓冲/状态标志（对应大目录迭代异常）。
- 513 = 256×2+1，为“UTF-16 名字转 CP932（≤2字节/字符）”设计。

> `IDirectoryContext`：`+0x8 filterFlags`、`+0xc name[257]`、`+0x118 dirInfo`（见 §1.5/§11）。`IDirectory_Read` 里的 `local_6f8`（memset 0x690）实际是 `dirInfo[0..0x688]` 的快照 + state，不是完整 `FsDirInfo`。

### 1.5 官方对象/错误码定义（switchbrew 校正）

参考 <https://switchbrew.org/wiki/Filesystem_services> 与 <https://switchbrew.org/wiki/Error_codes>。
以下结构已在 Ghidra 中新建并应用到 `IDirectory_Read`（详见 §11）。

**`nn::fs::DirectoryEntry`（0x310 字节，`IDirectory::Read` 输出数组元素）**

| 偏移 | 大小 | 名称 | 说明 |
|---|---|---|---|
| 0x000 | 0x301 | `path` | UTF-8 C 字符串（`nn::fssrv::sf::FspPath`） |
| 0x301 | 1 | `attributes` | 文件属性：bit0=目录，bit1=archive |
| 0x302 | 2 | padding | |
| 0x304 | 1 | `type` | `nn::fs::DirectoryEntryType`：0=Directory，1=File |
| 0x305 | 3 | padding | |
| 0x308 | 8 | `size` | 文件大小，目录为 0 |

**`nn::fs::DirectoryEntryType`**：`Directory=0`，`File=1`。

**`nn::fssrv::sf::FspPath`**：0x301 字节字符串。

**`nn::fs::OpenMode`（`IFileSystem::OpenFile` 的 mode）**：bit0=可读，bit1=可写，bit2=可追加。

**`nn::fssrv IFileSystem::OpenDirectory` filter_flags**：bit0=目录，bit1=文件。
（对应 `IDirectoryContext.dwFilterFlags`，见 §11。）

**Result 编码**：`result = (module & 0x1FF) | ((description & 0x1FFF) << 9)`；格式化输出 `2000+module`-`description`。
涉及本问题的 Fs（module=2）错误：

| 值 | description | 名称 |
|---|---|---|
| 0x202 | 1 | ResultPathNotFound |
| 0x402 | 2 | ResultPathAlreadyExists |
| 0xE02 | 7 | ResultTargetLocked |
| 0x190202–0x191002 | 3201–3208 | AllocationMemoryFailedInFatFileSystemA–H |
| 0x177202 | 3001 | ResultNotImplemented |
| 0x177602 | 3003 | ResultAlreadyExists |
| 0x177A02 | 3005 | ResultOutOfRange |
| 0x271402 / 0x277E02 / 0x27EC02 | 5002 / 5055 / 5113 | module=2，未在 switchbrew 列出；`IDirectory_ReadDirEntry` 将其视为可恢复 |

> `IDirectory_ReadDirEntry` 的“可恢复错误”判断：`(result&0x1FF)==2 && 0x1249<=desc<=0x125B`（FAT 格式类）或 `result∈{0x271402,0x27EC02,0x277E02}`。

---

## 2. 当前补丁逐条核对

### 2.1 转换函数

- `PFCODE_CP932_OEM2Unicode`（原始 0xfeac0）：CP932→UTF-16，返回 `ConvertWidth(oem_bytes, 2) = (oem_bytes<<16)|2`。
  `patch_utf8_to_utf16` 返回 `(utf8_len<<16)|2`，**约定一致**；对 U+4E2D 等 BMP 码点计算正确。
- `PFCODE_CP932_Unicode2OEM`（原始 0xfec30）：UTF-16→CP932，返回 `(oem_bytes<<16)|2`。
  `patch_utf16_to_utf8` 返回 `(utf8_len<<16)|2`，**约定一致**。
- `PFCODE_CP932_OEMCharWidth`(0xfee00) 内部**直接调用** `PFCODE_CP932_OEM2Unicode`，因此自动获得 UTF-8 宽度，无需另 patch。
- 拆分返回值的是 `PFCODE_GetConvertWidth`：`oem_width = ret>>16; uni_width = ret&0xffff`。

### 2.2 指针步进类（已 patch，逐条验证通过）

`StringDesc_AddLeft` / `StringDesc_GetCharCount` / `StringDesc_CompareUnicode` / `StringDesc_CompareOem` /
`FAT_GetNextChar` / `FAT_GetNextPathComponent`：
把原来的“若多字节则 +1”改成“+ 返回值”，再叠加原有的固定 +1，最终 1/2/3 字节字符分别前进 1/2/3。合法 UTF-8 下正确。

### 2.3 `patch_is_oem_mb_char` 的语义缺口

- 原函数是 **bool**：`byte_idx==1` 判首字节，`byte_idx==2` 判 CP932 尾字节（0x40–0x7E/0x80–0xFC）。
- 新函数**忽略 `byte_idx`**：按 UTF-8 首字节分类返回 0/1/2/3；0x80–0xBF 的续字节落入 else 返回 1。
- 合法 UTF-8 下：
  - `isOEMMBchar(first,1)`：0/1/2/3 → 步进正确；
  - `isOEMMBchar(续字节,2)`：返回 1（真），满足 `FAT_GetNextPathComponent` 的“尾字节合法性”判断。
- **隐患**：若某处把续字节当首字节调用，`isOEMMBchar` 会返回 1（2 字节），而 `patch_utf8_to_utf16` 对续字节返回 `len=1`+`'_'`，两者**不自洽**；一旦某处步进错位就会连锁失步。

---

## 3. 显示方向数据流（正常）

```
exFAT File/Stream/Name 目录项
  → fat_process_directory_match / fat_copy_entry_to_fsobj_type85/typeC0/typeC1
  → FsObject.lname_w (UTF-16)
  → fs_find_directory_entry → fs_parse_directory
      → fs_iterate_directory_entries → fat_init_fs_object_from_entry
          → fat_init_fs_object_shortname                 (encode_flag bit1==0 时)
              → PFCODE_Str_Unicode2OEM(dirInfo+0x487, FsObject.lname_w)   ← patch 生效
      → IDirectory_ReadDirEntry → memcpy dirInfo → IDirectory_Read
  → IDirectory_Read 写 outEntrys[i]（nn::fs::DirectoryEntry，0x310）：
       path(+0x000)、attributes(+0x301)=(attr>>4)&3、type(+0x304)=(attr&0x10)==0、size(+0x308)
```

其中 `type = (attr & 0x10)==0`（0=目录,1=文件）；attr 错则“目录被显示为文件”。

关键点：**显示只经过 `Unicode2OEM`（UTF-16→UTF-8）**，不依赖 `isOEMMBchar`/`GetNextChar`，因此显示稳定。
`IDirectory_Read` 的 `0xd4af4` NOP 只去掉“字节≥0x7F 即丢弃”的过滤，保证高字节名字不被跳过。

---

## 4. 打开方向数据流（失败）

```
上层路径字节(UTF-8)
  → StringDesc_SetPtr(..., ENCODE_OEM)
  → fs_open_by_path_core / fs_locate_object
      exFAT：exfat_entry_lookup
          → exfat_prepare_entry_search
              → PFCODE_Str_OEM2Unicode(FsObject.name, path)        ← patch 生效
              → exfat_resolve_path(大写表) → fat_hash_shortname      (NameHash)
          → FAT_SearchDirectory1 → FAT_SearchDirectory
              → exfat_search_directory
                  → PFCODE_Str_OEM2Unicode + fat_hash_shortname
                  → fat_process_directory_match
                      → fat_check_name_match → exfat_resolve_path + fat_wildcard_match
      FAT32：fat32_entry_lookup → FAT_ProcessDirectoryEntry
          → fat_process_long_filename_entry / FAT_MatchFileName1
              → FAT_MatchFileName → FAT_GetNextChar(已patch) + StringDesc_CompareOem(已patch)
                                   + FAT_MatchWildcardRecursive(未 patch isMB)
```

要点：

1. exFAT 的匹配**完全在 UTF-16 域做**（`exfat_resolve_path` 做大小写折叠，`fat_wildcard_match` 逐 ushort 比较），只要 `OEM2Unicode` 输入转换正确，理论上应命中。
2. 打开链路里出现的 `FAT_GetNextChar`/`CompareOem`/`GetCharCount` 都已 patch，合法 UTF-8 下无步进问题。
3. 因此“输入转换正确但打不开”只剩两类可能：
   - **次生内存破坏**（§5）导致 dirInfo/缓存/路径字段损坏；
   - **NameHash / 大小写 / 规范化**等匹配细节（与编码 patch 正交，但会被破坏放大）。

---

## 5. 已确认的高危点：`lname[513]` 无上限越界

### 5.1 证据

- `fat_init_fs_object_shortname`（0x7100105ba0）在 `encode_flag bit1==0`（OEM 路径）时执行：
  ```c
  PFCODE_Str_Unicode2OEM((char *)(dirInfo + 0x487), FsObject.lname_w);  // 513B 目标，无长度上限
  ```
- `PFCODE_Str_Unicode2OEM`（0x71000f5840）循环 `dst_oem += oem_width;` 并最终写 `*dst_oem='\0'`，**无任何边界检查**。
- `lname` 为 `char[513]`，其末尾即 `dirInfo+0x688 = path_w`。
- 原 CP932：≤255 字符 ×2B + NUL = 511 ≤ 513（安全）。
- patch 后 UTF-8：≥171 个 3 字节字符即 ≥513B，**溢出可达 ~253B**，覆盖 `path_w`（以及更远字段）。

### 5.2 影响

- 破坏同一 `dirInfo` 的 `path_w`（该目录自身路径）→ 后续目录定位/缓存可能错乱。
- 若 `dirInfo` 位于堆且后接其它对象，可破坏堆元数据 → 偶发崩溃。
- 与“部分大目录表现异常、子目录被当成文件”的现象在时序上吻合（同一次列表遍历中前一个长名越界踩坏后续状态）。

### 5.3 同类无上限点

- `exfat_prepare_entry_search` / `exfat_search_directory` 里 `PFCODE_Str_OEM2Unicode` 写入 FsObject 名字区（0x200B）也无上限，但上限 255×3<NUL=766>0x200 时才会溢出，风险低于 `lname`。
- `fs_convert_string_encoding` 里 `PFCODE_Str_Unicode2OEM(dest, srcWide)` 同样无上限。

> 说明：该点能解释“长名/大目录”，但**不能解释典型短中文名打不开**，需结合 §7 动态确认。

---

## 6. 其它未覆盖 / 风险点

| 编号 | 位置 | 问题 | 影响面 |
|---|---|---|---|
| R1 | `FAT_MatchWildcardRecursive` 0x71000f4770（0xf4874/0xf49ac/0xf4a7c 三处 isMB） | “若多字节则指针+1”未改；对 3 字节 UTF-8 短名会失步 | 短名（8.3）回退匹配、通配符查询 |
| R2 | `FAT_MakeShortName` 0x71000f5ac0（0xf5df4 等 4 处 isMB） | 生成 8.3 短名时按 2 字节估算空间，UTF-8 可能超长/截断 | 创建、重命名 |
| R3 | `FAT_ReplaceShortNameNumber` 0x71000f6270 | 同上 | 创建重名短名 |
| R4 | `StringDesc_ToUpper` 0x71000f7c10 | OEM 分支用有符号 `toupper(*pcVar7)` 逐字节处理，UTF-8 高位字节可能被改写 | 短名/大写比较（写路径） |
| R5 | `patch_utf8_to_utf16` | 3/4 字节分支无条件读 `utf8_in[1..2]`，不校验 `ptr_right` | 越界读（一般 NUL 保护，风险低） |
| R6 | `patch_utf16_to_utf8` | 2/3 字节分支不写 NUL（1 字节写 `[2]`，2/3 字节不写） | 依赖调用方统一补 NUL，暂无实测问题 |
| R7 | `patch_is_oem_mb_char` | 忽略 `byte_idx`，续字节返回 1，与 `OEM2Unicode` 的 `len=1` 不一致 | 失步时的连锁风险（见 §2.3） |

---

## 7. 根因假设（按置信度）

| 置信度 | 假设 | 对应症状 | 验证方法 |
|---|---|---|---|
| 高 | **H1：`lname[513]` 越界**破坏 `path_w`/相邻内存 | 大目录异常、子目录显示为文件 | 构造 60/100/170/200 字中文名，观察临界；在 `PFCODE_Str_Unicode2OEM` 入口记录目标指针与逐字符写入长度 |
| 中 | **H2：NameHash/大小写折叠**在 `OEM2Unicode` 正确但 `exfat_resolve_path` 结果与磁盘哈希不一致 | 打开失败（混合中英、含小写） | 在 `fat_hash_shortname` 与 `fat_process_directory_match` 记录双方哈希值 |
| 中 | **H3：写/改名路径未覆盖**（R1/R2/R3/R4）产生坏短名/坏长名条目 | 打开失败、部分条目异常 | 对新建/改名的中文文件复现；检查磁盘目录项 |
| 低 | **H4：末尾 `IDirectory_Read` 0x200 字节上限**导致超长名整条被丢弃 | 个别超长名不显示 | 记录 `uVar10/uVar9` |
| 低 | **H5：`patch_is_oem_mb_char` 续字节不自洽**引发失步 | 偶发 | 在 `OEM2Unicode` 与 `isMB` 同时记录被处理字节 |

---

## 8. 动态验证方案（建议下一步做）

在 `sysmod/src/main.cpp` 的补丁代码里，把 3 个替换函数包一层“日志版”实现，通过全局环形缓冲把记录写到 `/config/sys-patch/log.ini`：

1. `patch_utf8_to_utf16`：记录输入 3 字节、输出码点、返回长度。
2. `patch_utf16_to_utf8`：记录输入码点、输出字节数、**目标指针**（判断是否越界；需要把目标指针也传进来，可另外 hook）。
3. `patch_is_oem_mb_char`：记录 `ch`、`byte_idx`、返回值。
4. 额外 hook `PFCODE_Str_Unicode2OEM` 入口：记录 `dst` 指针、源串长度，逐字符累加输出长度并打印是否 >513、>520。
5. 额外 hook `PFCODE_Str_OEM2Unicode` 入口：记录输入路径字节与输出 UTF-16 长度，用于比对“显示名 vs 打开名”。

> 由于 sys-patch 的补丁函数是裸地址替换，日志版需保持 ABI（返回 `int`、参数 2 个），并避免调用复杂库函数；可用最小自旋写固定缓冲。

---

## 9. 候选修复方向

1. **修 H1（优先、且独立于症状）**：给 `Unicode2OEM` 的调用点加边界。
   - 方案 A：不改通用函数，改为 hook `fat_init_fs_object_shortname`（0x7100105ba0）中 `bl 0x71000f5840` 的调用，替换成带 `max=513` 的受限转换；
   - 方案 B：把 `PFCODE_Str_Unicode2OEM` 整体替换为“带目标上限”的实现，调用点需能提供 buffer 大小（现有 ABI 无此参数，需按调用点分别 patch）。
   - 也可折中：在转换前按字符逐个估算 UTF-8 长度，超过 512 字节则截断并保证 NUL。
2. **补 R1/R2/R3**：把 `FAT_MatchWildcardRecursive`/`FAT_MakeShortName`/`FAT_ReplaceShortNameNumber` 中 “isMB 为真则 +1” 的指令改成 “+ 返回值”，与 §2.2 一致。
3. **补 R4**：`StringDesc_ToUpper` OEM 分支改为逐 UTF-8 字符处理，或直接按字节直通（仅对 ASCII 做 upper）。
4. **修 R6**：`patch_utf16_to_utf8` 在 2/3 字节分支也显式写 `utf8_output[len]='\0'`（若调用方确实不补，则更安全）。
5. **修 R7**：`patch_is_oem_mb_char` 在 `byte_idx==2` 时按“续字节是否 0x80–0xBF”返回 0/1，与 `OEM2Unicode` 对齐。

---

## 10. 附：地址—函数对照

| 文件偏移 | 函数 | 说明 |
|---|---|---|
| 0xd4af4 | `IDirectory_Read` | 名字非法字节过滤分支 |
| 0xfeac0 | `PFCODE_CP932_OEM2Unicode` | UTF-8→UTF-16（替换） |
| 0xfec30 | `PFCODE_CP932_Unicode2OEM` | UTF-16→UTF-8（替换） |
| 0xfee40 | `PFCODE_CP932_isOEMMBchar` | 字符长度判定（替换） |
| 0xf45d8 | `FAT_GetNextChar` | ptr 步进 |
| 0xf4d8c | `FAT_GetNextPathComponent` | ptr 步进 |
| 0xf77e8 | `StringDesc_AddLeft` | ptr 步进 |
| 0xf7984 | `StringDesc_GetCharCount` | ptr 步进 |
| 0xf7a80 | `StringDesc_CompareUnicode` | ptr 步进 |
| 0xf7bd0 | `StringDesc_CompareOem` | ptr 步进 |
| 0x71000f5840 | `PFCODE_Str_Unicode2OEM` | 无上限输出（H1） |
| 0x71000f5960 | `PFCODE_Str_OEM2Unicode` | 输入转换 |
| 0x7100105ba0 | `fat_init_fs_object_shortname` | 写 `dirInfo+0x487`（lname） |
| 0x71001058e0 | `fat_init_fs_object_from_entry` | 目录项 → FsDirInfo |
| 0x71000f3c20 | `FAT_MatchDirEntry` | 长/短名匹配入口 |
| 0x71000f3f20 | `FAT_MatchFileName` | 已覆盖步进 |
| 0x71000f4770 | `FAT_MatchWildcardRecursive` | 未覆盖 isMB（R1） |
| 0x710010ca20 | `exfat_entry_lookup` | exFAT 打开入口 |
| 0x71000fc8f0 | `exfat_prepare_entry_search` | 路径→UTF-16 + NameHash |
| 0x71000fa7a0 | `exfat_search_directory` | exFAT 目录搜索 |

---

## 11. Ghidra 数据库修正记录（switchbrew 校正）

> 上述结构体另导出为 C 头文件 **`fs_encode_fix/fs_structs.h`**（packed，附各字段绝对偏移；已用 C11 `_Static_assert` / C++17 `static_assert` 校验 `sizeof`/`offsetof` 全部通过）。

已按 switchbrew 的定义在 `FS_1/19.exfat.FS.kip1` 中修正：

| 操作 | 对象 | 内容 |
|---|---|---|
| 新建结构 | `nn::fs::DirectoryEntry` | 0x310：`aPath`(FspPath) @0、`bAttributes` @0x301、`bType`(DirectoryEntryType) @0x304、`size` @0x308 |
| 新建结构 | `nn::fssrv::sf::FspPath` | `undefined1[769]` |
| 新建枚举 | `nn::fs::DirectoryEntryType` (1B) | `Directory=0, File=1` |
| 新建枚举 | `nn::fs::Result` (4B) | PathNotFound/PathAlreadyExists/TargetLocked、FatFileSystemA–H、ResultNotImplemented/AlreadyExists/OutOfRange 等 |
| 修正原型 | `IDirectory_Read` @0x71000d4a20 | `outEntrys` 由 `void*` 改为 `nn::fs::DirectoryEntry*` |
| 修正原型 | `fs_open_file` @0x7100103060 | 形参改名并注释 `mode`（bit0 读/bit1 写/bit2 追加） |
| 修正字段 | `IDirectoryContext` | +0x8 字段命名 `dwFilterFlags`（bit0 目录、bit1 文件）；`dirInfo` @0x118、`name` @0xc |
| 添加注释 | `IDirectory_Read` / `fs_open_file` | 记录 `DirectoryEntry` 布局、`0xd4af4` 补丁含义、OpenMode |

### 内部结构（按机器码推断重建，替代失真的 demangler 版本）

| 操作 | 对象 | 内容 |
|---|---|---|
| 重命名 | `FsObject` → `FsObject_demangler` | 保留旧类型，避免引用断裂 |
| 新建结构 | `FsObject`（0x278） | 见 §1.4；修正 attr@0x208、fileSize@0x210、firstCluster@0x23c、shortName@0x263、scase@0x270 等 |
| 命名修正 | `FsObject` 全字段 | 依据 `fat_copy_entry_info_to_output`/`fat_copy_entry_to_fsobj_type83/85/C0/C1`/`fat_write_directory_entry`/`fat_init_root_directory`/`FS_GetParentDirectoryInfo` 等：`awLongName`(260 wchar, 吞并原 0x200 padding)、`create10ms/modify10ms/accessTime/accessTz/createTz/modifyTz`、`pathOffset@0x238`、`entryIndex@0x240`、`dirCluster@0x244`、`entryOffset@0x248`、`dirStartCluster@0x24c`、拆分 `sectorSize@0x250`/`dirSearchParam@0x258`、`nameArea@0x262`、`status/scase@0x270`、`searchPos@0x274` |
| 新建结构 | `FsDirInfoInternal`（0xAAA） | 见 §1.4；修正 attr@0x478、sname@0x47a、lname@0x487（513B）、lname_w@0x8aa |
| 修正字段 | `IDirectoryContext.dirInfo` | `FsDirInfoExt` → `FsDirInfoInternal` |
| 修正原型 | `fs_parse_directory` @0x7100106910 | 第 4 参 → `FsDirInfoInternal*`（原 `FsDirInfoExt*`） |
| 修正原型 | `fs_iterate_directory_entries` @0x7100106de0 | `FsDirInfoInternal*` |
| 修正原型 | `fat_init_fs_object_from_entry` @0x71001058e0 | `(FsDirInfoInternal*, FsObject*)` |
| 修正原型 | `fs_check_directory_state` @0x7100116710 / `fs_reset_directory_state` @0x7100106d00 / `FS_fsnext` @0x7100116690 | `FsDirInfoInternal*` |
| 修正原型 | `fs_find_directory_entry` @0x7100105e60 | `dirBuffer` → `FsObject*`（注：0x71001067d0 是另一个同名 3 参包装） |
| 修正原型 | `fs_traverse_directory_path` @0x71000f9db0 / `fs_validate_directory_entry` @0x7100105cb0 / `fs_update_directory_cache` @0x7100106080 | 缓冲区参数 → `FsObject*` |
| 重命名 | `FsDirInfoObj` → `FsDirInfoObj_demangler` | |
| 新建结构 | `FsDirInfoObj`（0x690） | `state`@0 + `dirInfo`（0x688 快照）；`IDirectory_ReadDirEntry` 的 `dirObj` |
| 修正原型 | `FAT_MatchDirEntry` / `FAT_MatchFileName1` / `FAT_FindDirectoryEntry1/2` / `FAT_SearchDirectory` / `FAT_SearchDirectory1` / `fat_find_directory_entry_by_name` / `fat_process_directory_match` / `fat_check_name_match` / `fat_copy_entry_to_fsobj_type83/85/C0/C1` / `exfat_search_directory` / `exfat_entry_lookup` / `exfat_prepare_entry_search` / `fat_resolve_path_and_find_entry` / `fat_init_fs_object_shortname` / `FAT_GetShortNmae` / `fat_copy_entry_info_to_output` / `fat_copy_file_info_to_output` / `fat_write_fsobject_entry` / `exfat_init_root_fsobject` | 全部由 `FsObject_demangler*`/`undefined` 改为 `FsObject*`，恢复被清空的签名 |
| 修正原型 | `fs_open_entry_core` / `fs_open_entry_worker` / `fs_locate_object` | `(FsDrvObject*, StringDesc*, …)` |
| 补字段 | `FsObject` | 新增 `dwF_0x238`@0x238、`dwF_0x24c`@0x24c（来自 `exfat_init_root_fsobject` / `fat_process_directory_match`） |
| 重命名 | `FatFileContext`/`FatFileContextPart` → `_demangler` | 保留旧类型 |
| 新建结构 | `FatFileContextPart`（0x70）、`FatFileContext`（0xB0） | 见 §1.6 |
| 修正原型 | `fat_seek_directory_entry` / `fat_read_next_directory_entry` / `fat_prepare_directory_search` / `fat_seek_to_dir_entry` / `fat_map_cluster` / `FAT_SeekDirectoryEntry1` / `FAT_ClearFatContext_0x28` / `fs_init_directory_context` | 改用新 `FatFileContext(Part)*` |
| 重命名 | `FatFileObject` → `FatFileObject_demangler` | 修正尺寸 0x882 → 0x520 |
| 新建结构 | `FatFileObject`（0x520） | `status`@0、`fctx`@8、`entry`(FsObject)@0x78、`refCount`@0x510 等 |
| 修正原型 | `fat_allocate_file_object` / `fat_release_file_object` / `fs_cleanup_fat_object` / `fat_clear_all_file_objects` / `fat_validate_file_object_address` | 改用新 `FatFileObject*` |
| 重命名 | `FsDrvObject` → `FsDrvObject_demangler` | 修正尺寸 222832（`struct_2d0[256]`）→ 0x8C8 |
| 新建结构 | `FsDrvObject`（0x8C8） | `fat_type`@0x30、`bytesPerSectorShift`@0x34、`sectorsPerClusterShift`@0x35、`fat_start_sec`@0x38、`max_cluster_num`@0x48、`bLetter`@0x124、`qLock_0x128`@0x128、`dwFlags_0x11c`@0x11c 等 |
| 修正字段 | `FsObject.pDrvObj` / `FsDirInfoInternal.pDrvObj` / `FatFileContext(Part).drvObj` | → 新 `FsDrvObject*` |
| 重命名字段 | `FatFileContextPart` 全部占位名 → 语义名（`dwCluster`/`pClusterIndex`/`pSectorMap`/`pOutParam`/`bFlags`/`qwAllocatedBytes`…） | 证据见 §1.6（2026-09-13 第三轮） |
| 重命名字段 | `FatFileContext` 全部占位名 → 语义名，`clusterShift` → **`bSectorShift`**（是扇区 shift） | 证据见 §1.6 |
| 重命名字段 | `FatFileObject` 全部占位名 → 语义名；0x2f0 保留区 → **`aLongPath_w[260]`**；`refCount` → `wRefCount` | 证据见 §1.6 |
| 修正类型 | `FsObject.pDrvObj`@0x230、`FsDirInfoInternal.pDrvObj`@0x010 | `-BAD-` → `FsDrvObject *` |
| 补字段 | `IDirectoryContext.pFSCtx`@0x000 | FS/事务上下文指针（`fs_open_directory`） |
| 重命名字段 | `FsDrvObject` 0x148/0x14a/0x150/0x158 → `bSectorCache_enabled`/`wSectorCache_count`/`qSectorCache_base`/`dwSectorCache_stride` | 证据：`fat_allocate_file_object` |
| 修正原型 | `FAT_FindDirectoryEntry2` / `fat_prepare_directory_search` / `fat_search_directory_entries` / `fat_allocate_file_object` / `fat_release_file_object` / `fat_set_context_ptr` / `fs_file_open_core` | 改用新 `FatFileContext(Part)*` / `FatFileObject*` / `FsDrvObject*` |

### 第四轮（2026-09-13 · 函数原型推定 + 新结构体）

| 操作 | 对象 | 内容 |
|---|---|---|
| **新建结构** | **`FatFileHandle`（0x48）** | 每次 open 的句柄：`dwStatus`@0、`dwOpenFlags`@4、`pFileObj`@8、`pCtxOut`@0x10、`qwInvalidMarker`@0x18、`dwLastError`@0x20、`qwFilePosition`@0x28、`dwCurrentCluster`@0x30、`dwClusterIndex`@0x34、`wSectorOffset`@0x38、`wRefCount`@0x40；证据见 §1.8.1 |
| 修正类型 | `FatFileHandle.pFileObj` | `-BAD-` → `FatFileObject *` |
| 合并字段 | `FatFileObject` 0x500/0x504 | 两个 u32 → **`qword qwOwnerTag_0x500`**（按 8 字节读写） |
| 补字段 | `FsDrvObject.dirCache`@0x218 | `u8[0x6A0]` 目录缓存（`fs_get_volume_dir_cache`/`set`/`read_current_dir_entry`） |
| 修正类型 | `FatFileContextPart.pDrvObj`@0x48 / `FatFileContext.pDrvObj`@0x08 | `-BAD-` → `FsDrvObject *`（原先反编译显示为匿名 `field16_0x48`） |
| 修正原型 | `fs_init_directory_context` | `int (FatFileContextPart*, ulong, FsDrvObject*, uint*, byte*, qword*, uint mode)`，字段映射见 §1.8.2 |
| 修正原型 | `exfat_search_directory_entries` / `exfat_entry_lookup` / `FAT_FindDirectoryEntry` / `FAT_FindDirectoryEntry1` / `FAT_SearchDirectory1` / `FAT_ProcessDirectoryEntry` / `FAT_GetShortNameInner` / `FAT_GetShortNmae` / `FAT_MatchDirEntry` / `FAT_MatchFileName` / `FAT_MatchWildcardRecursive` / `FAT_MakeShortName` / `FAT_ReplaceShortNameNumber` / `FAT_GetNextPathComponent` / `FAT_GetNextChar` / `FAT_SplitPath_Inner` / `PFCODE_CP932_ConvertWidth` / `PFCODE_GetConvertWidth` / `FAT_GetFsDrvByPath` | 由 `undefined`/`long`/`void*` 改为语义类型 |
| 修正原型 | `fs_open_entry_worker` / `fat_find_or_alloc_file_slot` / `fat_allocate_file_object` | `(FsDrvObject*, …)` |
| 同步文件 | `fs_structs.h` | 加入 `FatFileHandle` + 断言；`FatFileObject` 0x500 → `qwOwnerTag_0x500`；`FsDrvObject` 拆出 `dirCache`；`gcc -std=c11 -fsyntax-only` 通过 |


> 修正后 `IDirectory_ReadDirEntry` / `fs_parse_directory` / `fat_init_fs_object_from_entry` / `FAT_MatchDirEntry` / `fat_process_directory_match` 等反编译已按字段名显示（`dirInfo->wAttr`、`entry->file_size`、`entry->short_name`、`outEntry->dwEntry_cluster` …）。
> 仍保留的 demangler 类型 `FsObject_demangler`/`FsDirInfo`/`FsDirInfoExt`/`FsDirInfoObj_demangler`/`FatFileContext_demangler`/`FatFileContextPart_demangler` 未删除，被少量尚未回改的函数引用；偏移不可信，应以新结构为准。
> `IFile` / `IStorage` / `ISaveData*` 等接口未涉及本问题，未改动。

### 第十轮（2026-09-13 · 卷内存池全景定案 + FatDirObject）

| 操作 | 对象 | 内容 |
|---|---|---|
| **新建结构** | **`FatDirObject`（0x510）** | 目录对象池槽（0x510 步长）：`dwStatus`@0(0x40000003)、`dwRefCount_0x4`@4(低16位)、`fctx`@0x08(mode=4)、`entry`@0x78、`aLongPath_w`@0x2f0、`qwOwnerTag_0x500`、`pvValidateCtx_0x508`；证据见 §1.12 |
| 改名字段 | `FsDrvObject`+0x88 | `pFile_object_array` → **`pDir_object_array`**（FatDirObject 池，旧名是第八轮误记） |
| 改名字段 | `FsDrvObject`+0x90 | `pDir_object_array` → **`pDirSearchObj_array`**（类型 `FatDirSearchObject *`，0x28 步长） |
| 互换字段名 | `FsDrvObject` 0x98/0x9c | `nOpenDirRefCount`↔`nOpenFileRefCount`（`fat_get_volume_handle_stats` 池配对证据） |
| 改名函数 | `fat_find_or_alloc_file_slot` → **`fat_find_or_alloc_dir_object`** | 0x510 目录池分配器，非文件槽 |
| 改名函数 | `fat_allocate_dir_context` → **`fs_alloc_thread_ctx_node`** | 实为按线程 FS 上下文节点（0x16c0 链表）分配器 |
| plate 注释 | fs_init_volume_context / fat_find_or_alloc_dir_object / fat_get_volume_handle_stats / fat_allocate_file_object / fs_idirectory_opendir | 池布局、标记位、计数器配对、0x7D0 足迹 |
| 同步文件 | `fs_structs.h` | `FatDirObject` + 9 条断言；`FatDirSearchObject.pFileObj` → `FatDirObject*`；池字段改名；`gcc -std=c11 -fsyntax-only` 通过 |

### 1.6 FS 基础结构（按机器码推断重建）

**`FatFileContextPart`（0x70）** — 簇/扇区搜索子上下文，被 FAT 簇分配路径与目录搜索路径共用。
字段名于 2026-09-13 依据下列函数逐条重新推导并写回 Ghidra：
`fs_init_directory_context` @0x71000e9320、`fat_map_cluster` @0x71000e6d70、
`fat_lookup_cluster` @0x71000e6bd0、`fat_allocate_cluster_chain` @0x71000ead00、
`fat_allocate_clusters` @0x71000e9410、`fat_find_free_clusters` @0x71000e7a60、
`fat_find_free_cluster_range` @0x71000eb580、`fat_write_fat_entry_dispatch` @0x71000eb250、
`fat_read_fat_entry_dispatch` @0x71000e74f0、`fat_cluster_to_sector` @0x71000e6880、
`fat_free_cluster_chain` @0x71000ea8e0/@0x71000eb040、`FAT_ClearFatContext_0x28` @0x71000e9ae0、
`fat_allocate_file_object` @0x71000ff250、`fat_release_file_object` @0x71000ff480、
`fat_set_context_ptr` @0x71000e9b40。

| 偏移 | 类型 | 名称 | 说明 |
|---|---|---|---|
| 0x00 | uint | `dwCluster` | 簇号；`fat_map_cluster`/搜索用（读作 int，与 1 比较，`pClusterIndex==1` 时被 fs_init 覆盖） |
| 0x04 | uint | `dwReserved_0x4` | |
| 0x08 | `int*` | `pClusterIndex` | 进出参簇索引指针；`*p==1` 表示"新建簇链"，`*p==0` 表示"沿用现有链" |
| 0x10 | uint | `dwStartCluster` | 范围起点，(-1) = 无效；`fat_allocate_clusters` 写为 param_3 |
| 0x14 | uint | `dwEndCluster` | 范围终点，(-1) = 无效；`fat_allocate_clusters` 写为最后分配的簇 |
| 0x18 | uint | `dwClusterRangeStart` | 簇范围起点，(-1) = 无效 |
| 0x1c | uint | `dwClusterRangeEnd` | 簇范围终点，(-1) = 无效 |
| 0x20 | uint | `dwLastAllocatedCluster` | 上次分配链的末簇，(-1) = 无效 |
| 0x24 | uint | `dwReserved_0x24` | |
| 0x28 | `u8*` | `pSectorMap` | 扇区映射/临时数组（`fs_allocate_memory` 分配，`FAT_ClearFatContext_0x28` 按 `dwSectorMapEntryCount*4` 释放）；`fat_map_cluster`/`fat_write_fat_entry_dispatch` 当 `u32[]` / `u16*` 用 |
| 0x30 | ushort | `wCachedRangeCount` | 已缓存 FAT 范围里的簇数（另有 +1 用作每簇扇区数） |
| 0x32 | ushort | `wReserved_0x32` | |
| 0x34 | uint | `dwCachedRangeEnd` | 已缓存 FAT 范围末簇（0xFFFFFFFF = 无效；`fat_cluster_to_sector` 以 `!=0xFFFFFFFF` 判断有效） |
| 0x38 | uint | `dwSectorMapEntryCount` | `pSectorMap` 中 4 字节条目数 |
| 0x3c | uint | `dwReserved_0x3c` | |
| 0x40 | ptr | `pOutParam` | 出参，`fat_map_cluster`/`fat_lookup_cluster`/`fat_find_free_clusters` 写入 `{dwCluster, nextCluster}`；`fat_set_context_ptr` 就是这个 setter |
| 0x48 | `FsDrvObject*` | `pDrvObj` | 所属卷对象 |
| 0x50 | byte | `bFlags` | bit1 = FAT 缓存脏；bit2 = exFAT 连续/流提示（写 3、按 `(~bFlags & 3)==0` 测试） |
| 0x58 | `u8*` | `pFlagsPtr` | 镜像 `bFlags` 的字节指针；p5==NULL 时默认指向 `&bFlags` |
| 0x60 | u64 | `qwAllocatedBytes` | 簇链累计分配字节数（`fat_allocate_cluster_chain` 累加） |
| 0x68 | `u64*` | `pAllocatedBytesPtr` | 指向 `qwAllocatedBytes`；p6==NULL 时默认指向 `&qwAllocatedBytes` |

> 注意 0x28 既是"已分配缓冲区指针"（`FAT_ClearFatContext_0x28` 释放）又被当字节/字数组读写，因此 Ghidra 里类型取 `byte *`。

**`FatFileContext`（0xB0）** — 目录搜索迭代上下文（`fat_prepare_directory_search` @0x71000f8380 构造）。
布局：0x10 字节头部 + 0x10 处内嵌 `FatFileContextPart`。

| 偏移 | 类型 | 名称 | 说明 |
|---|---|---|---|
| 0x00 | uint | `dwCurrentEntryIndex` | 条目号计数器（prepare 时清 0，命中后作为"找到的条目号"回报） |
| 0x04 | uint | `dwField_0x04` | |
| 0x08 | `FsDrvObject*` | `pDrvObj` | 所属卷对象，`fat_prepare_directory_search` 从 `ctx_part.pDrvObj` 拷入 |
| 0x10 | `FatFileContextPart` | `ctx_part` | 内嵌搜索子上下文 |
| 0x80 | uint | `dwCurrentCluster` | 搜索中的当前簇（-1 = 无） |
| 0x84 | uint | `dwCluster` | 持有当前条目的簇（-1 = 无） |
| 0x88 | ushort | `wEntryOffset` | 条目在扇区内的偏移（`(u32)((mask & index) << 5)`） |
| 0x8a | ushort | `wSectorMask` | `~(-1 << bSectorShift)` |
| 0x8c | `FatBaseEntry` | `entry` | 当前原始 32 字节目录项 |
| 0xac | byte | `bSectorShift` | **=`pDrvObj->bBytesPerSectorShift - 5`（是扇区 shift，不是簇 shift——旧注释有误）** |

> 交叉验证：`fat_read_next_directory_entry` @0x71000f89a0 以 `param_1[0x20]/[0x21]/+0x22/[0x2b]`
> 访问 0x80/0x84/0x88/0xac，并调用 `fat_map_cluster(param_1+4, ...)`（即 0x10 处的 `ctx_part`），
> 与本布局完全一致。

**`FatFileObject`（0x520，按 0x520 步进）** — 打开的卷内文件对象。
字段名于 2026-09-13 依据 `fat_allocate_file_object` @0x71000ff250、`fat_release_file_object` @0x71000ff480、
`fat_find_file_context_by_id` @0x71000ff540、`fs_file_open_core` @0x71001032d0、
`fs_file_seek` @0x7100103e20、`fs_file_read_core` @0x7100101020 重新推导。

| 偏移 | 类型 | 名称 | 说明 |
|---|---|---|---|
| 0x000 | uint | `dwStatus` | `0x10000003` = 已用（bit0/bit1）；`(dwStatus ^ 0xffffffff) & 3)==0` 判在用 |
| 0x004 | uint | `dwReserved_0x4` | |
| 0x008 | `FatFileContextPart` | `fctx` | 簇/扇区搜索子上下文；被 `fat_map_cluster`、`fs_init_directory_context` 以 `(FatFileContextPart*)&obj->fctx` 使用 |
| 0x078 | `FsObject` | `entry` | 该文件的已解析目录项；其 `pDrvObj`(+0x230)/`dwDirCluster`(+0x244)/`wEntryOffset`(+0x248) 是去重打开的身份键 |
| 0x2f0 | `u16[260]` | `aLongPath_w` | 文件 UTF-16 长路径（260 字符）；`fs_file_open_core` 用 `strncpy_w(..., 0x104)` 拷出 |
| 0x4f8 | ushort | `wFlags_0x4f8` | 状态位，测试 `(wFlags & 3)`；bit0/bit1 标记打开对象的 I/O 状态；bit1 还在重命名/属性写挂起时置位（`fat_close_file_context` 检查 `(~wFlags & 10) != 0`） |
| 0x4fa | ushort | `wReserved_0x4fa` | 多重打开计数（`wRefCount` 分流用） |
| 0x4fc | uint | `dwF_0x4fc` | 打开的 handle 计数 / "忙"标志（0 = 无打开的 handle；`fat_close_file_context` 以 `== 0` 判无效） |
| **0x500** | **u64** | **`qwOwnerTag_0x500`** | **持有者句柄 / 事务线程上下文标签**。原机器码里是两个 u32（0x500/0x504），但始终作为**一个 qword** 拷贝与比较：打开时设为事务线程上下文（`fs_locate_object` 路径），`fat_close_file_context` 用 `== drvObj->qTransaction_thread_context` 校验，关闭时清零 |
| 0x508 | uint | `dwF_0x508` | 目录对象数组（0x510 步长）的回指槽，记录其 owner（`fs_validate_directory_entry` / `fat_close_file_context` 比对） |
| 0x50c | uint | `dwF_0x50c` | 分配时清零 |
| 0x510 | ushort | `wRefCount` | 打开引用计数（打开 +1，关闭 -1，归零时释放池槽） |
| 0x512 | u8[6] | `reserved_0x512` | |
| 0x518 | u64 | `qwF_0x518` | 出参槽指针：`fat_allocate_file_object` 把它设为已验证的目录槽指针；`fat_close_file_context` 的池扫描按它匹配 owner |

> 池来源：`drvObj->pFile_object_array`（drvObj+0x88），共 `drvObj->dwMax_open_file_objects`（drvObj+0x6c）个 0x520 槽。
> 已回改原型：`fat_allocate_file_object`、`fat_release_file_object`、`fs_file_open_core` 等。
> **第四轮更正**：0x500/0x504 两个 u32 实为一个 **`qword qwOwnerTag_0x500`**；另新增配套的 `FatFileHandle`（0x48），见 §1.8。

**`FsDrvObject`（0x8C8，按盘符 `letter × 0x8c8` 索引）** — 卷/驱动对象（原 demangler 的 222832 + `struct_2d0[256]` 实为错误模型）

> 基础地址：模块全局 `0x7100fd8598`（卷数组），条目 N（0..4）位于 `base + N*0x8C8`。
> 另有两处"伪基址"出现在反编译里，换算关系：
> `DAT_7100fd86b8` = base + 0x120（状态字节）、`DAT_7100fd86c0` = base + 0x128（卷锁）。
>
> **2026-09-13 第二轮回改**：字段名已由以下函数逐条重新推导并写回 Ghidra：
> `fs_init_volume_context` @0x71000d7420（池分配/布局）、
> `fat_parse_bpb` @0x71000e12d0 + `fat_parse_boot_sector` @0x71000dbde0（BPB 镜像）、
> `fat_calculate_fat_geometry` @0x71000e1690（0x50–0x78）、
> `fat_mount_volume_core` @0x71000d7d10、`fs_open_directory` @0x7100100090、
> `fat_set_volume_flags` @0x71000e31e0、`fat_set_volume_config` @0x71000e31f0、
> `FAT_UpdateFSInfo` @0x71000daab0、`fs_check_mount_state` @0x71000d5080。

| 偏移 | 类型 | 名称 | 说明 |
|---|---|---|---|
| 0x000 | ushort | `wBpb_bytes_per_sec` | BPB BytesPerSector（扇区大小） |
| 0x004 | ushort | `wBpb_bytes_per_sector` | BPB 扇区大小的第二份副本 |
| 0x008 | byte | `bBpb_sectors_per_cluster` | BPB SectorsPerCluster |
| 0x00c | uint | `dwBpb_total_sectors` | BPB TotalSectors |
| 0x010 | byte | `bBpb_media_descriptor` | BPB MediaDescriptor（0xF8） |
| 0x014 | uint | `dwBpb_hidden_sectors` | BPB HiddenSectors（分区起始偏移） |
| 0x018 | uint | `dwBpb_fat_size_sectors` | BPB FatSize（每 FAT 表扇区数） |
| 0x020 | ushort | `wBpb_reserved_sector_count` | BPB ReservedSectorCount（FAT32 为 0） |
| 0x022 | ushort | `wBpb_num_fats` | BPB NumFATs（通常 2） |
| 0x024 | ushort | `wBpb_root_entry_count` | BPB RootEntryCount（FAT32 为 0） |
| 0x028 | ushort | `wMountFlags` | bit0=已用 bit1=已挂载 bit2=exFAT bit5=已格式化 |
| 0x02a | ushort | `wF_0x2a` | `wMountFlags` 的镜像 |
| 0x02c | uint | `dwVolume_flags_0x2c` | 卷标志（字节 0x2e = 挂载状态） |
| 0x030 | int | `nFat_type` | **0=FAT12, 1=FAT16, 2=FAT32, 3=exFAT** |
| 0x034 | byte | `bBytesPerSectorShift` | log2(扇区大小) |
| 0x035 | byte | `bSectorsPerClusterShift` | log2(簇大小)；簇移位 = 0x34+0x35 |
| 0x036 | ushort | `wReserved_0x36` | 两字节均由 BPB 写入，未使用 |
| 0x038 | uint | `dwFat_start_sec` | FAT 表起始扇区 |
| 0x03c | uint | （保留） | |
| 0x040 | uint | （保留） | |
| 0x044 | uint | `dwRoot_dir_first_cluster` | FAT32/exFAT 根目录首簇 |
| 0x048 | uint | `dwMax_cluster_num` | 最大有效簇号（几何上界） |
| 0x04c | uint | `dwData_start_sector` | 数据区起始扇区 |
| 0x050 | uint | `dwFirst_data_sector` | 数据区起始扇区（含） |
| 0x054 | uint | `dwLast_alloc_cluster` | 最后分配的簇 |
| 0x058 | uint | `dwNext_free_cluster` | 下一个空闲簇提示（-1=未知） |
| 0x05c | uint | `dwFree_cluster_count` | 空闲簇数（-1=未知） |
| 0x060 | uint | `dwData_sector_count` | 数据区扇区数（init 置 -1） |
| 0x064 | uint | `dwHeap_base_sector` | 堆区起始扇区（init 置 -1） |
| 0x068 | uint | `dwHeap_sector_count` | 堆区扇区数 |
| 0x06c | uint | `dwMax_open_file_objects` | 池槽位数：FatFileObject（每个 0x520） |
| 0x070 | uint | `dwMax_cluster_cache_nodes` | 池槽位数：FatClusterCacheNode（每个 0x48） |
| 0x074 | uint | `dwMax_dir_objects` | 池槽位数：目录对象（每个 0x510） |
| 0x078 | ptr | `pPool_base` | 单次分配 = 文件对象 + 簇缓存节点 + 目录对象 |
| 0x080 | ptr | `pCluster_cache_node_array` | `pPool_base + files + dirs` |
| 0x088 | ptr | `pFile_object_array` | `pPool_base` |
| 0x090 | ptr | `pDir_object_array` | `pPool_base + files` |
| 0x098 | int | `nOpenDirRefCount` | 已打开目录数 |
| 0x09c | int | `nOpenFileRefCount` | 已打开文件数 |
| 0x0a0 | int | `nF_0xa0` | 对象计数（`fs_check_drive_state` 用它守卫 `pField_0xa8`） |
| 0x0a4 | uint | （保留） | |
| 0x0a8 | ptr | `pField_0xa8` | 文件对象池（`fs_check_drive_state` 校验） |
| 0x0b0 | ptr | `pField_0xb0` | |
| 0x0b8 | uint | `dwField_0xb8` | 介质信息标志 |
| 0x0bc | uint | `dwVolume_flags_0xbc` | 介质更换/脏标志 |
| 0x0c0 | uint | `dwField_0xc0` | 每卷配置标志（来自存储驱动） |
| 0x0c4 | ushort | `wVolume_config_0xc4` | 最大簇配置值 |
| 0x0c6 | ushort | `wVolume_config_0xc6` | 簇大小配置值 |
| 0x0c8 | uint | `dwCode_page_state` | 代码页上下文：0=未初始化，1=已初始化 |
| 0x0cc | — | （保留） | |
| 0x0d0 | ptr | `pCode_page_slot` | 已分配的 PFCODE/CP932 槽位 |
| 0x0d8–0x0e7 | — | （保留） | |
| 0x0e8 | uint | `dwVolume_flags_config` | 卷标志配置（`fat_set_volume_flags` 写入） |
| 0x0ec | uint | `dwVolume_config` | 卷配置（`fat_set_volume_config` 写入） |
| 0x0f0/0x0f4 | uint | | |
| 0x0f8 | ptr | `pLock_0xf8` | 当前事务的 FS 上下文 |
| 0x100 | qword | `qTransaction_thread_context` | 当前事务的线程上下文 |
| 0x108 | uint | `dwField_0x108` | 初始化标志（置 1） |
| 0x10c | uint | `dwField_0x10c` | 链表头/自引用 |
| 0x110 | ptr | `pField_0x110` | → `dwField_0x10c`（链表锚点） |
| 0x118 | uint | `dwField_0x118` | |
| **0x11c** | uint | `dwFlags_0x11c` | **bit4 = 卷为 exFAT，不支持 OEM 名** |
| 0x120 | byte | `bF_0x120` | bit0=已挂载 bit4=错误 |
| 0x121 | byte | `bF_0x121` | bit1=卸载进行中 |
| 0x122 | ushort | `wF_0x122` | |
| **0x124** | byte | `bLetter` | 盘符 'A'..'E'（= 索引 + 'A'） |
| 0x125 | byte | （保留） | |
| 0x126 | ushort | `wF_0x126` | |
| 0x128 | ptr | `qLock_0x128` | 每卷锁（同时是 `fat_init_code_page_context` 的目标） |
| 0x130–0x13c | uint×4 | | |
| **0x140** | ushort | `wVolume_state_0x140` | **bit1=有 FSInfo bit2=FSInfo 脏**（`fat_update_fsinfo_if_needed`） |
| 0x142 | ushort | `wF_0x142` | |
| 0x144 | uint | `dwF_0x144` | |
| **0x148** | byte | `bSectorCache_enabled` | **bit0 = 本卷启用扇区缓存**（`fat_allocate_file_object` 读取） |
| 0x149 | byte | （保留） | |
| 0x14a | ushort | `wSectorCache_count` | 扇区缓存条目数（拷入 `fctx.wCachedRangeCount`） |
| 0x14c | uint | `dwF_0x14c` | |
| 0x150 | qword | `qSectorCache_base` | 扇区缓存数组基址；每文件对象槽位 = base + index*`dwSectorCache_stride`*4 |
| 0x158 | uint | `dwSectorCache_stride` | 每文件对象的扇区缓存步长（u32） |
| 0x15c | uint | | |
| **0x160** | uint | `dwTransaction_id` | **事务操作 id（0x12=挂载，0x34=配置）** |
| **0x164** | uint | `dwTransaction_result` | **上次事务的结果码** |
| **0x1c8** | qword | `qStorage_handle_0x1c8` | **存储设备句柄**（传给所有 `fs_storage_*`） |
| **0x218** | **u8[0x6A0]** | **`dirCache`** | **目录缓存（1696 字节）**。`fs_get_volume_dir_cache` @0x71000d5910 直接返回 `drvObj+0x218`，`fs_set_dir_cache` @0x71000d5990 存入，`fs_read_current_dir_entry` @0x71000d5830 读取；用于对同一目录的重复查找走捷径。0x1d0–0x217 为 72 字节未知区 |
| 0x8b8 | u8[0x10] | | 尾部保留 |

> 已重建并回改：`fs_init_volume_context` 签名现为
> `int fs_init_volume_context(FsDrvObject *drvObj, undefined8 *param_2, char volumeIndex, uint maxFileObjects, uint maxClusterCacheNodes, uint maxDirObjects)`；
> `fat_parse_boot_sector` 签名现为 `(FsDrvObject *drvObj, FsDrvObject *outDrv, void *bpb)`。
>
> **2026-09-13 第三轮（其余结构体）**：`FatFileContextPart`、`FatFileContext`、`FatFileObject`
> 三个类型的全部占位字段名已按证据回改（见 §1.6），并顺带修正两处真实错误：
> ① `FatFileObject` 的 0x2f0–0x4f7 不是"保留区"，而是 `aLongPath_w[260]`（文件 UTF-16 长路径）；
> ② `FatFileContext.bSectorShift`(0xac) 是**扇区** shift（`bytesPerSectorShift-5`），不是簇 shift。
> 另修正 `FsObject.pDrvObj`@0x230、`FsDirInfoInternal.pDrvObj`@0x010 的 `-BAD-` 类型为 `FsDrvObject *`，
> 并补 `IDirectoryContext.pFSCtx`@0x000。
> 池布局（`fs_init_volume_context` 复核）：
> `pFile_object_array`(0x88) = `pPool_base`(0x78)，步长 0x520、共 `dwMax_open_file_objects`(0x6c) 个；
> `pDir_object_array`(0x90) = pool + files，步长 0x510、共 `dwMax_dir_objects`(0x74) 个；
> `pCluster_cache_node_array`(0x80) = dirs + `dwMax_dir_objects`*0x28，步长 0x48、共 `dwMax_cluster_cache_nodes`(0x70) 个。
> 已回改原型：`fs_init_directory_context`、`FAT_ClearFatContext_0x28`、`fat_map_cluster`、
> `fat_lookup_cluster`、`FAT_FindDirectoryEntry2`、`fat_prepare_directory_search`、
> `fat_search_directory_entries`、`fat_allocate_file_object`、`fat_release_file_object`、
> `fat_set_context_ptr`、`fs_file_open_core`。

### 1.7 仍未建模（保留 demangler）

| 结构 | 观测偏移 | 含义 / 来源 |
|---|---|---|
| `FatBaseEntry`（已正确，32B） | +0x0b attr、+0x0c scase、+0x0d sub_sec、+0x0e/0x10 时间、+0x1c 大小、+0x14/0x1a 簇 | `fat_copy_entry_info_to_output` |
| `FatClusterCacheNode`（已正确，72B） | 0x00 state、0x02 ref、0x10 data_ptr、0x28 cluster_count、0x30 cluster_base、0x38 file_tag、0x40 prev、0x48 next | `fat_read_cluster_cache` |

> 主要 FS 结构（`FsObject`/`FsDirInfoInternal`/`FsDirInfoObj`/`FatFileContext(Part)`/`FatFileObject`/`FsDrvObject`/`FatBaseEntry`/`FatClusterCacheNode`）已全部按机器码重建或核对。

---

## 1.8 第四轮：`FatFileHandle` 新结构 + 函数原型补齐（2026-09-13）

本轮目标：**沿 fs 调用链推导仍未定型（`long`/`undefined8`/`void*`）的函数原型，并补出缺失的结构体**。

### 1.8.1 新结构 `FatFileHandle`（0x48）—— 每次打开文件的句柄

之前只有 `FatFileObject`（卷池里 0x520 的文件对象），缺少"每次 open 产生一个句柄"这一层的结构。
三处证据交叉锁定该结构：

| 证据 | 说明 |
|---|---|
| `fs_locate_object` @0x7100100280 | 找到空槽后 `pFVar9->pFileObj = obj; fat_setup_file_handle(pFVar9, openFlags); *ppOutHandle = pFVar9;` 且池遍历 `pFVar9 = (drvObj->pCluster_cache_node_array) + i`，步长 0x48 |
| `fat_setup_file_handle` @0x71000ffbb0 | `*p=0x20000001; p[1]=flags; *(u64*)(p+8)=0; *(u16*)(p+0x10)=0; ... p[0xc]=0xffffffff(=dwCurrentCluster@0x30);` |
| `fs_file_read_core` @0x7100101020 | 直接访问 `handle->qwFilePosition@0x28`、`dwCurrentCluster@0x30`、`dwClusterIndex@0x34`、`wSectorOffset@0x38`、`wRefCount@0x40`、`dwLastError@0x20`、`dwOpenFlags@0x04` |
| `fs_file_seek` @0x7100103e20 | 对 handle 做 5 个卷池的区间检查（`base <= handle < base+count-1`），进一步确认为池内对象 |

| 偏移 | 类型 | 名称 | 说明 |
|---|---|---|---|
| 0x00 | uint | `dwStatus` | `0x20000001` = 已用（`fat_setup_file_handle` 设置）；bit0 也在 `fs_file_seek` 里作为 I/O 门控 |
| 0x04 | uint | `dwOpenFlags` | 打开模式位：bit0 读、bit1 写、bit2 追加、bit3 "异步/无缓冲"、bit5 索引映射、bit6 "需 flush" |
| 0x08 | `FatFileObject*` | `pFileObj` | 背后的打开文件对象 |
| 0x10 | ptr | `pCtxOut` | 临时出参，供 `fat_set_context_ptr` / `fat_allocate_file_space` 使用 |
| 0x18 | u64 | `qwInvalidMarker` | `fat_setup_file_handle` 清零；关闭时比较/清零（0 = 无效） |
| 0x20 | uint | `dwLastError` | 本 handle 的最后错误（镜像线程上下文 +0x1690） |
| 0x24 | uint | `dwReserved_0x24` | 与 `dwLastError` 配对成一个 qword 标记 |
| 0x28 | u64 | `qwFilePosition` | 文件字节偏移 |
| 0x30 | uint | `dwCurrentCluster` | 当前簇（-1 = 需要重映射） |
| 0x34 | uint | `dwClusterIndex` | 簇链内索引 |
| 0x38 | ushort | `wSectorOffset` | 当前扇区内偏移 |
| 0x3a | ushort | `wReserved_0x3a` | |
| 0x3c | uint | `dwReserved_0x3c` | |
| 0x40 | ushort | `wRefCount` | 打开引用计数 |
| 0x42 | u8[6] | `aReserved_0x42` | |

> **池共用提示**：`drvObj->pCluster_cache_node_array`（drvObj+0x80）既是 FAT 簇缓存数组（`FatClusterCacheNode` 0x48），又被 `fs_locate_object` 当作 `FatFileHandle` 数组使用——两者槽位大小相同（0x48），按 `dwMax_cluster_cache_nodes`（drvObj+0x70）计数。详见 §1.8.3 的疑点记录。

### 1.8.2 本轮补齐/修正的函数原型（Ghidra，`__cdecl`）

| 地址 | 原型 | 依据 |
|---|---|---|
| 0x7100109630 | `int fat_close_file_context(FsDrvObject*, FatFileHandle*, int forceClose)` | 读 `handle->pFileObj/dwLastError/dwReserved_0x24`，`drvObj->qTransaction_thread_context` |
| 0x71001032d0 | `int fs_file_open_core(FsDrvObject*, FatFileObject*, FsDirInfoInternal*)` | 参数全部映射到 `obj->entry(+0x78)` 的字段 |
| 0x7100100a20 | `int fs_file_write_core(FsDrvObject*, FatFileHandle*, int flushFlag)` | `handle->dwOpenFlags/dwFilePosition/wCurrentCluster…` |
| 0x7100103ca0 | `int fs_file_set_size_core(FsDrvObject*, FatFileHandle*, ulong newSize)` | 同上 |
| 0x7100100280 | `int fs_locate_object(FsDrvObject*, StringDesc*, uint openFlags, FatFileHandle **ppOut)` | 分配 handle、调用 `fat_setup_file_handle` |
| 0x71001040e0 | `int fs_open_file(uint driveId, StringDesc*, uint openFlags, FatFileHandle **ppOut)` | |
| 0x71000fffd0 | `int fs_open_directory(StringDesc*, uint openFlags, FatFileHandle **ppOut)` | |
| 0x7100105e60 | `int fs_find_directory_entry(FsDrvObject*, StringDesc*, int resolveFlag, FsObject*, uint*, void*)` | |
| 0x7100106080 | `int fs_update_directory_cache(FsDrvObject*, StringDesc*, FsObject*, uint, void*)` | |
| 0x71000d5910 | `int fs_get_volume_dir_cache(FsDrvObject*, void **ppOutCache)` | 返回 `drvObj+0x218` |
| 0x71000d5990 | `int fs_set_dir_cache(FsDrvObject*, void *pCache)` | |
| 0x71000d5830 | `int fs_read_current_dir_entry(FsDrvObject*, void *outEntry)` | |
| 0x7100109990 | `ulong fs_check_and_delete_directory(FsDrvObject*, FsObject*, uint flags)` | |
| 0x71000e83c0 | `ulong fat_allocate_clusters_core(FatFileContextPart*, uint startCluster, uint clusterCount, ulong byteCount)` | |
| 0x71000eb580 | `ulong fat_find_free_cluster_range(FsDrvObject*, ulong start, uint end, uint minCount, int mode, uint*, int*, undefined4*)` | |
| 0x710010bda0 | `int exfat_write_zero_clusters(FsDrvObject*, void*, ulong)` | |
| 0x71001094e0 | `int fs_open_entry_worker(FsDrvObject*, StringDesc*, void **ppOutSlot)` | |
| 0x7100109e40 | `FatFileObject * fat_find_or_alloc_file_slot(FsDrvObject*, FsObject*)` | |
| 0x71000ff250 | `FatFileObject * fat_allocate_file_object(FsDrvObject*, FsObject*)` | |
| **0x71000e9320** | `int fs_init_directory_context(FatFileContextPart*, ulong, FsDrvObject*, uint *pClusterIn, byte *pFlagsIn, qword *pAllocatedBytesIn, uint mode)` | 见下方字段映射 |
| **0x710010c970** | `int exfat_search_directory_entries(FsDrvObject*, uint startCluster, byte sectorShift, ulong clusterIndex, int entryOffset, int *outIndex)` | 原为 6 个 `undefined` |
| **0x710010ca20** | `int exfat_entry_lookup(FsDrvObject*, FatFileContext*, StringDesc*, FsDirInfoInternal*)` | `param_1+0x6c/0x98` = `dwMax_open_file_objects`/`nOpenDirRefCount` |
| **0x71000f8e30** | `int FAT_FindDirectoryEntry1(FatFileContext*, FsObject*, StringDesc*, byte, uint*, uint*, uint*, uint)` | |
| **0x71000f8f70** | `int FAT_FindDirectoryEntry(FatFileContext*, FsObject*, StringDesc*, byte, uint*, uint*, uint*, uint)` | |
| **0x71000f16e0** | `int FAT_SearchDirectory1(FsObject*, int needFree, FatFileContextPart*, ulong*, StringDesc*, uint, uint*)` | |
| **0x71000f1530** | `int FAT_FindDirectoryEntry2(FatFileContextPart*, FsObject*, uint, StringDesc*, byte, uint*, uint*)` | |
| **0x71000f9e70** | `int FAT_ProcessDirectoryEntry(FsObject*, FatFileContext*, StringDesc*, byte, uint*, uint)` | |
| **0x71000f5460** | `void FAT_GetShortNameInner(char*, FatBaseEntry*, uint)` | 返回值恒 0，真正结果是 `sname` 出参 |
| **0x71000f1100** | `void FAT_GetShortNmae(FsObject*, FatBaseEntry*)` | |
| **0x71000f3c20** | `bool FAT_MatchDirEntry(FsObject*, StringDesc*, uint *isShortMatch, uint *hasTilde)` | |
| **0x71000f3f20** | `int FAT_MatchFileName(char*, StringDesc*, uint flags1, uint cmp_unicode)` | |
| **0x71000f4770** | `bool FAT_MatchWildcardRecursive(ushort, NameCtx*, ushort, StringDesc*)` | |
| **0x71000f5ac0** | `int FAT_MakeShortName(char*, StringDesc*)` | |
| **0x71000f6270** | `int FAT_ReplaceShortNameNumber(char*, uint)` | |
| **0x71000f4bc0** | `int FAT_GetNextPathComponent(void *ctx, StringDesc*, int allowWildcard)` | |
| **0x71000f44e0** | `ushort FAT_GetNextChar(StringDesc*, ushort get_unicode)` | |
| **0x71000f4f30** | `int FAT_SplitPath_Inner(void *ctx, StringDesc*, StringDesc*, StringDesc*)` | |
| **0x71000f7ce0** | `int PFCODE_CP932_ConvertWidth(int oemWidth, short uniWidth)` | `return oemWidth*0x10000 + uniWidth` |
| **0x71000f7cf0** | `void PFCODE_GetConvertWidth(int convertRet, ushort *oemWidth, ushort *uniWidth)` | 拆高/低 16 位 |
| **0x71000f51b0** | `FsDrvObject * FAT_GetFsDrvByPath(StringDesc*)` | |

> `fs_init_directory_context` 的**字段映射证据**（原始裸偏移 → 结构字段，全部一致）：
> `ctx+0x40 ← p2` = `pOutParam`；`ctx+0x48 ← p3` = `pDrvObj`；`ctx+0x08 ← p4` = `pClusterIndex`；
> `ctx+0x28` = `pSectorMap`（按 `*(u32*)(ctx+0x38)<<2` 释放 ⇒ `dwSectorMapEntryCount`@0x38）；
> `ctx+0x10/0x18/0x20` 置 -1 = `dwStartCluster`/`dwEndCluster`/`dwClusterRangeEnd`；
> `p5==0` 时 `*(u8*)(ctx+0x50)=1` 且 `*(ptr*)(ctx+0x58)=ctx+0x50` ⇒ `bFlags`@0x50 / `pFlagsPtr`@0x58；
> `p6==0` 时 `p6=ctx+0x60` ⇒ `qwAllocatedBytes`@0x60 / `pAllocatedBytesPtr`@0x68；
> `mode = p7 & 7` 是模式选择子（4 = 目录搜索，2 = 文件对象）。
> 该函数同时**证实了 §1.6 中 `FatFileContextPart` 的全部字段命名**。

### 1.8.3 本轮修正的字段（Ghidra 侧，已同步到 `fs_structs.h`）

| 类型 | 修正 |
|---|---|
| 新建 | `FatFileHandle`（0x48），见 §1.8.1 |
| `FatFileObject` | 0x500/0x504 两个 u32 合并为 **`qword qwOwnerTag_0x500`**（证据：`fat_close_file_context` 与 `fat_allocate_file_object` 均按 8 字节读写） |
| `FsDrvObject` | `reserved[0x6f8]` 拆出 **`dirCache[0x6A0]`@0x218**（证据：`fs_get_volume_dir_cache`） |
| `FatFileContextPart` | `pDrvObj`@0x48 的 `-BAD-` → `FsDrvObject *`（原反编译显示为匿名 `field16_0x48`） |
| `FatFileContext` | `pDrvObj`@0x08 的 `-BAD-` → `FsDrvObject *` |
| `FsObject` | `pDrvObj`@0x230 的 `-BAD-` → `FsDrvObject *` |
| `FatFileHandle`（Ghidra 侧） | `pFileObj` 类型补为 `FatFileObject *`；`dwInvalidMarker`/`dwFilePosition` 因 Ghidra 类型前缀约定被强制改回 `dw`（类型仍是 8 字节 `ulong`，属显示层差异，功能正确） |

### 1.8.4 疑点 / 待确认

1. **池共用**：`pCluster_cache_node_array`（0x80）在 `fat_allocate_file_object`/`fat_allocate_cluster_cache_node`
   里按 `FatClusterCacheNode`（0x48）使用，在 `fs_locate_object` 里按 `FatFileHandle`（0x48）使用。
   两者槽位大小一致，但语义不同——需要再核对 `fs_init_volume_context` 的池切分是否真有重叠，
   或是否存在另一个未被识别的池字段。**当前作为发现记录，未在 `fs_structs.h` 中断言其命名。**
2. `exfat_search_directory_entries` 的第 2/3 参（`startCluster`/`sectorShift`）来自调用点
   `fs_file_open_core` 的 `uVar3`/`uVar4`，语义依据较弱，标为暂定。
3. `FatFileHandle.dwOpenFlags` 的 bit 语义由 `fs_file_read_core`/`fs_file_write_core` 的位测试反推，
   与 switchbrew 的 `OpenMode`（bit0 读/bit1 写/bit2 追加）一致，其余位为观测推断。

## 1.10 第六轮：目录/文件对象结构体与函数原型补齐（2026-09-13）

### 1.10.1 IDirectory 服务对象多层虚表组（0x7100247390）

完整解码 `0x7100247390` 起的虚表组（vptr = `0x7100247380`，即 slot0−0x10）。它不是单一 vtable，
而是**同一个 C++ 类的 9 个基类子表**（此前 §1.9.7 的"3 段子表"疑点据此扩展修正）：

| 子表 | 基址 | this 类型 | 内容 |
|---|---|---|---|
| A | +0x000 (0x…7390) | `IDirectoryObj*` | 22 槽服务接口（create/remove/mkdir/rmdir/get_entry_info/clean_dir/move/rename/exists/get_device_info(_light)/fopen/opendir/get_size/sync/stat/init_stat_buffer/get_version×3） |
| B | +0x0c0 (0x…7450) | 分发上下文 | 目录操作回调（`FAT_OpenDirectory`/nop/safe_release），由 `FUN_71000ce6a4(pFatCtx, drive, &{vtable,path,out})` 调用 |
| C | +0x0e8 (0x…7478) | `FsDirFileObj*` | 文件对象接口（dtor×2/file_read/write_file/sync_file/truncate/read_entry_data/io_control） |
| — | +0x138/+0x160 | 分发上下文 | write_zero、get_entry_size 等小节 |
| C' | +0x188 (0x…7518) | 0x7D0 迭代器对象 | 客户端 IDirectory 类（dtor/trace/**Read**/**GetEntryCount**/open_file_by_path 等；opendir 里 `fs_log_assert_check(2000)` 分配的 0x7D0 对象即用此 vptr） |
| — | +0x1e0/+0x208/+0x230 | — | fs_open_directory_callback 及 write_zero_2/3 变体（fopen/create 的分发回调） |
| G | +0x248 (0x…75d8) | ? | 17 个未命名函数 0x7100110210..0x7100110ee0（**待分析**，Ghidra 中尚无函数定义） |
| H | +0x2d8 (0x…7668) | — | fs_locked_buffer_pool 接口（13 槽） |
| I | +0x350 (0x…76e0) | — | fs_nca_fs_obj + fs_locked_vtable_call_0xNN 访问器层 |

### 1.10.2 新建结构体（Ghidra + fs_structs.h 同步）

**`IDirectoryObj`（0x78）** — 所有 `fs_idirectory_*` 服务方法的 `this`：

| 偏移 | 类型 | 字段 | 证据 |
|---|---|---|---|
| 0x00 | void* | `vptr` | ctor `fs_idirectory_constructor` 存 `&…7390` 组 |
| 0x08 | void* | `pStrObj` | 每个方法结尾 `fs_string_cleanup(this+8)` |
| 0x10 | void** | `ppDriveLetter` | `snprintf("%c:\\%s", **(byte**)(this+0x10))` |
| 0x18 | void* | `pLogCtx` | `IDirectory_GetError(*(this+0x18), …)` |
| 0x20 | u32×4 | `f_0x20..` | 子对象基址（fopen 存 `this+0x20` → 文件对象+0x28） |
| 0x30 | void* | `pFatWrapper` | 可恢复错误路径经其 vtable+0x38 seek 复位 |
| 0x38 | void* | `pFatCtx` | `FUN_71000ce6a4(this+0x38, …)` |
| 0x60 | u32 | `dwModeCopy` | fopen 复制到文件对象+0x24 |
| 0x65 | u8 | `bFlag` | fopen 复制到文件对象+0x38 |
| 0x70 | u64 | `qOwner` | fopen 复制到文件对象+0x50 |

**`FsDirFileObj`（0x58）** — `fs_idirectory_fopen` 用 `fs_log_assert_check(0x58)` 分配的每次打开文件对象：

| 偏移 | 字段 | 证据 |
|---|---|---|
| 0x08 | `dwOpenFlags`（bit0=读，bit1=写，bit2=允许扩展） | file_read 测 bit0（错 0x307402）、write_file 测 bit1（0x307602）/bit2、truncate 测 bit1/bit2 |
| 0x10 | `hFatHandle` | `fs_file_seek_wrapper/fs_file_read_wrapper/FS_fgetdta/FS_fsetclstlink` 第一参 |
| 0x18 | `pLogCtx`；0x20 字符串槽；0x24 `dwModeCopy`；0x28 `pDirSubObj`（ioctl 经其 vtable+0x38）；0x30 `pFatWrapper`；0x38 `bFlag`（启用 TLS 目录读取结果跟踪，配合 `fs_set_tls_dir_read_result`）；0x40 `pFatCtx`；0x48 `bDriveLetter`；0x50 `qTxnObj`（其 +0x40 为写事务引用计数，ExclusiveMonitor 保护） | file_read/write_file/sync_file/io_control 全部对上 |

### 1.10.3 本轮回写 Ghidra 的函数原型（26 个）

| 地址 | 原型 |
|---|---|
| 0x71000d1bc0 | `FsErrorCode_e fs_idirectory_create(IDirectoryObj*, StringDesc *path, long size)`（size<0 → 0x2f7202；经 B 表 open → "ftruncate" → "fclose" 链） |
| 0x71000d1f30 | `FsErrorCode_e fs_idirectory_remove(IDirectoryObj*, StringDesc *path)`（拒绝 "/"） |
| 0x71000d2424 | `void fs_idirectory_mkdir(IDirectoryObj*, StringDesc *path)` → `mkdir_internal(…,0)` |
| 0x71000d21c0 | `FsErrorCode_e fs_idirectory_mkdir_internal(IDirectoryObj*, StringDesc*, uint flags)`（bit1 = `fs_create_by_oem_path(path,0x30)`） |
| 0x71000d2430 | `FsErrorCode_e fs_idirectory_rmdir(IDirectoryObj*, StringDesc *path)`（`fs_get_entry_count_by_oem_path` 空目录检查） |
| 0x71000d2660 | `FsErrorCode_e fs_idirectory_get_entry_info(IDirectoryObj*, StringDesc *path)` |
| 0x71000d2890 | `FsErrorCode_e fs_idirectory_clean_dir(IDirectoryObj*, StringDesc *path)`（`fs_rename_by_oem_paths` → `DAT_71001cd078` 模板） |
| 0x71000d2ae0 | `FsErrorCode_e fs_idirectory_move(IDirectoryObj*, StringDesc *src, StringDesc *dst)`（仅目录：isDir==1 → `FS_RenameByStr`） |
| 0x71000d2df0 | `FsErrorCode_e fs_idirectory_rename(IDirectoryObj*, StringDesc *old, StringDesc *new_)`（仅文件：isDir==0） |
| 0x71000d0760 | `int fs_idirectory_exists(IDirectoryObj*, undefined4 *outIsDir, StringDesc *path)` |
| 0x71000d08a8 | `FsErrorCode_e fs_idirectory_get_device_info(IDirectoryObj*, ulong *outTotalSize)`（总容量 = sec×clus×bytes） |
| 0x71000d0a34 | `FsErrorCode_e fs_idirectory_get_device_info_light(IDirectoryObj*, ulong *outFreeSize)` |
| 0x71000d1300 | `FsErrorCode_e fs_idirectory_fopen(IDirectoryObj*, FsDirFileObj **ppOut, StringDesc *path, uint openFlags)` |
| 0x71000d1890 | `FsErrorCode_e fs_idirectory_opendir(IDirectoryObj*, void **ppOutIter, StringDesc *path, uint openFlags)`（分配 0x7D0 迭代器，路径补 `\*`） |
| 0x71000d1198 | `FsErrorCode_e fs_idirectory_sync(IDirectoryObj*)` |
| 0x71000d0ec0 | `FsErrorCode_e fs_idirectory_stat(IDirectoryObj*, ulong *outTs, StringDesc *path)`（非目录转 get_timestamps） |
| 0x71000d0bc0 | `FsErrorCode_e fs_idirectory_get_timestamps(IDirectoryObj*, ulong *outTs[3+1], StringDesc *path)`（`fs_open_by_oem_path` + DOS 时间 → u64） |
| 0x71000d111c | `undefined8 fs_idirectory_init_stat_buffer(undefined8, undefined4 *statBuf)`（清 0xC0 字节 stat 缓冲） |
| 0x71000d30d0 | `undefined8 fs_idirectory_get_size(void)`（**stub，恒 0**） |
| 0x71000cef38 / 0x71000cf0f8 | `void fs_idirectory_destructor(_logged)(IDirectoryObj*)` |
| 0x71000d3810 / 0x71000d38a4 | `void fs_idirectory_file_obj_destructor(_logged)(FsDirFileObj*)` |
| 0x71000d3950 | `FsErrorCode_e fs_idirectory_file_read(FsDirFileObj*, ulong *outRead, long offset, void *dst, ulong size)`（先经自身 vtable+0x30 get_entry_size 取长度做越界钳制；TLS 读取结果回放） |
| 0x71000d3db0 | `FsErrorCode_e fs_idirectory_write_file(FsDirFileObj*, long offset, void *src, long size, undefined4 *option)`（`option->bit0` 或越界写后触发 vtable+0x20 flush） |
| 0x71000d4170 | `FsErrorCode_e fs_idirectory_sync_file(FsDirFileObj*)`（仅 bit1 时有实际动作；qTxnObj 计数保护） |
| 0x71000d436c | `FsErrorCode_e fs_idirectory_truncate(FsDirFileObj*, long newSize)`（bit2=0 时先 `FS_fsetclstlink` 清簇链） |
| 0x71000d46a4 | `FsErrorCode_e fs_idirectory_read_entry_data(FsDirFileObj*, undefined8 *out)`（`FS_fgetdta`，0x688 字节） |
| 0x71000d4844 | `undefined8 fs_idirectory_io_control(FsDirFileObj*, ×2, long cmd, ×4)`（cmd=3 → pDirSubObj vtable+0x38；cmd=2 → `FUN_71000ce9d0(pFatWrapper,0)`；其余 0x31a602） |

plate 注释已更新：`0x7100247390`（多层虚表组全图 + 两个结构体字段表）。

### 1.10.4 疑点 / 待办

1. ~~子表 G（+0x248，0x7100110210..0x7100110ee0）17 个槽位目标在 Ghidra 中**不是已定义函数**~~
   → **已解决（第八轮）**：实为 16 个 FAT 介质驱动操作包装器，见 §1.10.5。
2. `fs_idirectory_open_file_by_path`（C' 表 +0x1b8）的 `this` 经基类调整后 `this+8` 指向 0x7D0 迭代器对象（其 +0x7a8 = 目录句柄），thunk 调整量未确认。
3. ~~0x7D0 迭代器对象布局未建结构体~~ → **已解决（第八轮）**：新建 `FsDirIterObj`（0x7D0），见 §1.10.5。
4. `fs_idirectory_create` 的第 3 参按负值检查与错误链标为 `size`，语义暂定。
5. ~~客户端 `IDirectory_Read`/`IDirectory_ReadDirEntry`/`GetEntryCount` 原型完善~~ → **已解决（第八轮）**。

### 1.10.5 第八轮：客户端迭代器结构体 + FAT 介质驱动接口（同日）

**`FsDirIterObj`（0x7D0）** — `fs_idirectory_opendir` 经 `fs_log_assert_check(2000)` 分配的客户端迭代器（立即数 2000 恰为对象大小）。
关键修正：`IDirectoryContext`（0xBC2）布局与其**前 0xBC2 字节一致**，但 dirInfo 活动窗口只有前 **0x688** 字节
（`IDirectory_ReadDirEntry` 向 `out+8` memcpy 0x688；0x7A0 起为控制字段，与 0x7D0 吻合）：

| 偏移 | 字段 | 证据 |
|---|---|---|
| 0x00 | `vptr` | opendir 存 `&PTR_fs_idirectory_destructor_7100247518`（C' 表基址） |
| 0x08 | `dwOpenFlags`（bit0=目录，bit1=文件） | `ReadDirEntry` 按 attr bit4 选 bit0/bit1 过滤 |
| 0x0c | `aName[0x104]` | opendir 写 `"%s\*"`；`ReadDirEntry` 以其为 `FS_fsnext` 参数 |
| 0x118 | `dirInfo[0x688]` | `ReadDirEntry`：sname@0x592-0x118=0x47a、attr@0x590-0x118=0x478 与 FsDirInfoInternal 字段吻合 |
| 0x7a0 | `bReady`（1=句柄有效） | opendir 置 1；`ReadDirEntry` 首次走 `FS_fsnext`，之后走 `fs_check_directory_state` |
| 0x7a8/0x7b0/0x7b8 | `hDirHandle`/`pLogCtx`/`pFatWrapper` | opendir 存储 + GetEntryCount/ReadDirEntry 使用 |
| 0x7c0 | 字符串槽（`fs_string_cleanup(this+0x7c0)`） | GetEntryCount 结尾清理 |
| 0x7c8 | `pFatCtx` | opendir 存 `param_1+0x38` |

回写原型 4 个：
- `FsErrorCode_e IDirectory_Read(FsDirIterObj*, long *outCount, nn::fs::DirectoryEntry *outEntrys, long maxCount)`
- `FsErrorCode_e IDirectory_GetEntryCount(FsDirIterObj*, long *outCount)`（栈上克隆迭代器循环 ReadDirEntry 计数；无条目时 out[0] state==0）
- `FsErrorCode_e IDirectory_ReadDirEntry(FsDirIterObj*, FsDirInfoObj *outEntry)`（out[0]=state：1=有项，0=结束；`fs_get_last_error()==2` = 目录尾）
- `void fs_open_directory_callback(undefined8 *pDispatchCtx)`（`fs_open_directory_by_path(ctx[2],0)` → `*ctx[1] = 结果`）

**子表 G = FAT 介质驱动操作接口**（16 槽，基址 0x71002475d8）。所有包装器统一模式：
`(u32 *pDevDesc, u32 *pOut)`；`*pOut=0` 先清空；`pDevDesc[2]` → 设备对象指针；**magic 0xAABBCDDD** 校验
（失败返回 0xfffffffd）；设备对象 +0x04 = 状态（1=已注册、3=已挂载）、+0x1c = 最近错误码；错误返回
0xfffffff9（空指针）/0xffffffff（状态错）。槽位 → 核心 callee（Ghidra 已建函数并命名 `fs_fatdrv_*`）：

| 槽 | 包装器 | 核心 callee |
|---|---|---|
| +0x00 | fs_fatdrv_register_device @0x7100110210 | fat_register_device_slot |
| +0x08 | fs_fatdrv_unregister_device @0x71001102b0 | fat_unregister_device_slot |
| +0x10 | fs_fatdrv_init_mount @0x7100110350 | fat_init_fat_data_structures / fat_device_state_machine(2,3) |
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

注：`fs_fatdrv_init_mount` 有双路逻辑 —— `pMountState[0]==0x12` 时走 `fat_device_state_machine`(2→3) 并置 `pMountState[1]=1`（重新挂载路径）；否则走 `fat_init_fat_data_structures`（首次挂载）。

plate 注释（0x7100247390）已更新含 G 表分类与 FsDirIterObj 字段表；`fs_structs.h` 新增 `FsDirIterObj`
（0x7D0 断言通过）与 FAT 驱动接口槽位表注释。



## 1.11 第九轮：IDirectory 命令派发真相 + 5 个误命名纠正 + Prf2SafeCtx（2026-09-13 深夜）

### 命令派发约定（本轮核心发现）

`fs_dispatch_method_cmd`（0x71000ce6a4，原 FUN_71000ce6a4）调用约定：
`(*cmd->ppMethodSlot)(cmd)` —— **方法收到整个命令结构体指针**，不是对象 this。

```
FsMethodCmd (0x18): { void **ppMethodSlot;  // +0x00 指向命令槽基址，*ppMethodSlot=方法
                      void *out;            // +0x08 open 类=输出指针；close 类=FsDirIterObj*
                      void *arg; }          // +0x10 open 类=OEM 路径 char*
命令槽束 (0x28): [0]=方法 [1]=nop桩(0x71000d1f28) [2]=fs_safe_release_object [3..4]=null
```
派发器同时做耗时统计（*pCtx 的 +2/+4/+6/+8/+0xa/+0xc min/max 更新）。
已知命令槽：`g_pIdirCmd_open_dir`=0x71002474f0、`g_pIdirCmd_close_dir_handle`=0x7100247548、
open_directory=0x7100247570、fopen(FAT_OpenDirectory)=0x7100247450。
客户端类 vptr=0x7100247518（dtor/dtor_trace/Read/GetEntryCount）。

### 误命名纠正（5 个，已改名+改原型+plate 注释）

| 旧名 | 地址 | 真实语义 |
|---|---|---|
| fs_idirectory_open_file_by_path | 0x71000d4d38 | **fs_idirectory_cmd_close_dir_handle**：关闭 pIter->pDirSearchObj（无任何路径解析） |
| fs_open_file_by_oem_path | 0x7100116670 | **fs_close_file_handle**：= fs_close_file_by_context(obj,0)+CheckError |
| fs_file_delete | 0x71001039c0 | **fs_file_set_size_transactional**：事务(id 0x45)内调 fs_file_set_size_core，即 ftruncate |
| fs_file_delete_wrapper | 0x7100116100 | **fs_file_set_size_wrapper** |
| fs_idirectory_get_entry_size / fs_get_entry_size_by_oem_path | 0x71000d4934 / 0x71001165f0 | **fs_idirectory_cmd_open_dir / fs_open_dir_by_oem_path**：打开目录返回搜索对象 |

### fs_idirectory_create 第 3 参确认

`fs_idirectory_create(IDirectoryObj*, StringDesc*, long initialSize)`：initialSize<0 → 0x2f7202；
经 fs_file_set_size_wrapper(handle, initialSize) 设定新建文件大小 ⇒ **第 3 参 = 初始文件大小**（上轮"暂定 size"已坐实）。

### opendir 返回值真相 — FatDirSearchObject (0x28)

`fs_open_entry_core`（0x7100107b40）要求 attr bit4（目录），从 `FsDrvObject.pDir_object_array`
按 **0x28 步长**分配搜索对象：`{u32 status(in-use|0x80000000), u32 flags, FatFileObject* @+8,
搜索上下文 @+0x10, 位置字段 @+0x18..0x27}`，存入 `FsDirIterObj+0x7a8`（原记 hDirHandle，
现更名 **pDirSearchObj**；+0x7c8 更名 **ppOwnerFatCtx**=&IDirectoryObj.pFatCtx）。
**前 0x28 字节与 FatFileHandle(0x48) 头部同构**：fs_close_file_by_context（0x7100107cb0，
原型已改 FatDirSearchObject*）的 5 个池校验按 0x28 步长计算；fat_close_file_context 只读共享头。
⇒ 上轮遗留的"0x48 槽位语义重叠"疑点部分澄清：0x28 目录搜索对象与 0x48 文件句柄是不同池、共享头布局。
（fs_open_entry_by_oem_path 成功后 nOpenFileRefCount+1，关闭路径 -1，配对成立。）

### PRF2SAFE 恢复机制（prf2safe 待办完成）

- `FS_isPRF2SAFE`（0x7100114b90）：memcmp "PRF2SAFE" 8 字节。
- 恢复区头 = 2 个镜像 0x200 扇区：magic@0、ver@0x10=100('d')/0x11=0x65、u32@0x16=槽号、
  u32@0x20=错误码、u32@0x24=FAT 数、checksum u32@0x1fc（fs_temp_clear_and_restore）。
- **日志 = 写前备份**：`fat_prf2safe_manage_recovery_slot`（0x7100112bc0）把待改扇区先备份到恢复区，
  0x20 字节记录×2 镜像 {magic, 槽号@0x10, 错误码@0x14, 起始扇区@0x18, 扇区数@0x1c}；
  9 槽日志表 ctx+0x30..0x74 {start,count} 记录已备份区间（含区间重叠裁剪算法）。
- `fat_prf2safe_recovery_operation_dispatch`（0x7100113680）= **15 操作码介质层总派发器**：
  op1 扫描/校验恢复头、op2 读 FAT 副本头、op3 按卷标(pCtx+0x98,13B)开隐藏文件校验、
  op4 写新头、op5 分配簇+格式化恢复区、op6 文件 IO、op7 fat_write_prf2safe_and_verify、
  op8/0xf get/set pCtx+8、op9 设备状态机、op10/0xb 读/写卷标、
  **op0xc 日志回放**（校验记录镜像→位图标记→备份写回原位→重写恢复头）、op0xd 设备检查、op0xe set pCtx+8。
- `Prf2SafeCtx`（0x10C）已建 Ghidra 结构体 + fs_structs.h（0x10C 断言过；补 0x0c/0xfc 两个间隙字段）。
- 调用路径：介质驱动表 G 槽 +0x68（fs_fatdrv_manage_recovery_slot）/ +0x78（fs_fatdrv_recovery_dispatch）。

### FS 服务区 FUN_ 清扫（0x71000ce* + 2 个，16 个全部命名）

fs_idir_cmdobj_construct(0xce014, vptr 0x7100247328)、fs_idir_cmdobj_set_flag_0x58(0xce040)、
fs_idir_cmdobj_invoke_code_mapped(0xce050, 错误码表 DAT_71001d9ab0 映射 0x1c..0x24)、
fs_nop_then_release_object(0xce62c)、fs_map_error_code_index(0xce670)、
fs_fatal_unreachable_thunk(0xce698)、fs_set_global_7100fcfbf8(0xce7d0)、
**fs_fatwrapper_cleanup_rewind**(0xce9d0, = 各处内联的 cleanup_fat_object+string_cleanup+seek尾部模式)、
**fs_fatwrapper_recover_if_error**(0xcea9c, = 特征错误码谓词 + 上者)、
fs_map_volume_error_code(0xcedc8, 位掩码 0x5fff02→0x27ec02 等)、fs_geterror_last(0xceeac)、
fs_set_global_7100fcfc08(0xceef0)、fs_get_const_0x4a000(0xceefc)、
fs_detach_volume_handler(0x71000cefec, "detach"/"close_partition"/"close_disk" 日志串)、
fat_search_directory_entries_by_path(0x710010b820, 路径解析+FAT_ParsePath+带回调搜索)、
fs_volume_storage_operation_wrapper(0x7100115eb0)。
⇒ **FS 核心区（0x71000ce000–0x7100120000）FUN_ 未命名函数已清零**（0x710012b+ 属其他模块）。

### 观察与遗留

- opendir 分配 fs_log_assert_check(2000)=0x7D0 字节，但写 u32@0x7d0 且析构 fs_string_cleanup(0x7d0)
  ——实际足迹 ≥0x7e0，池槽应有对齐余量；记录备查。
- fat_close_file_context 内看到 pPool_base 步长 0x520(+0x518 ptr) 与 pFile_object_array 步长 0x510(+0x508 ptr)
  两种池并存，与上轮"pool_base=0x88=file 数组"记录冲突，待下轮核实（0x510 池身份未定）。
- PRF2SAFE 机制为介质驱动层（厂商中间件）行为，与 fork 的 codepage 补丁无交集。

## 1.12 第十轮：卷内存池全景定案 + FatDirObject（2026-09-13）

本轮解决第九轮两条遗留，两条均**证伪**（旧记录是误判）：

### 卷内存池最终布局（fs_init_volume_context @0x71000d7420 反编译坐实）

单次 `fs_alloc_memory_by_type(1, files*0x520 + handles*0x48 + dirs*0x538)`，四段连续：

| 区域 | 内容 | 步长 | 数量 | FsDrvObject 指针 | 分配/使用函数 |
|---|---|---|---|---|---|
| 1 | FatFileObject（文件对象，mode=2） | 0x520 | +0x6c | **+0x78 pPool_base** | fat_allocate_file_object |
| 2 | **FatDirObject（目录对象，mode=4，0x510）** | 0x510 | +0x74 | **+0x88 pDir_object_array** | fat_find_or_alloc_dir_object（原 fat_find_or_alloc_file_slot，误名已改） |
| 3 | FatDirSearchObject（opendir 返回值） | 0x28 | +0x74 | **+0x90 pDirSearchObj_array** | fs_open_entry_core / fs_close_file_by_context |
| 4 | FatFileHandle / 簇缓存节点 | 0x48 | +0x70 | +0x80 pCluster_cache_node_array | fs_locate_object / fat_alloc_cluster_cache_node |

关键算术：`dirs*0x510 + dirs*0x28 = dirs*0x538`，与总量严格吻合 ⇒ 0x510 与 0x28 是**同一目录组
（dirs 个）的两段配对区域**，不是"双池并存"。目录对象与其搜索对象 1:1 配对
（FatDirSearchObject.pFileObj@0x08 → FatDirObject）。

### dwStatus 标记位体系（三类对象判别）

- FatFileObject = `0x10000003`（bit0=占用，bit24=文件）
- FatDirObject  = `0x40000003`（bit0=占用，bit2=**目录**）
- FatDirSearchObject = `0x80000001`（bit0=占用，bit3=搜索对象）
- 空闲判定统一为 `(dwStatus ^ 0xffffffff) & 3 == 0`

### 计数器互换更正（0x98/0x9c 原命名张冠李戴）

证据 `fat_get_volume_handle_stats` @0x71000da130（out[4] = 空闲文件/开文件/空闲目录/开目录）：
- **+0x98 = nOpenFileRefCount**（配对 0x520 文件池；fs_open_file / fs_open_directory 成功时 +1）
- **+0x9c = nOpenDirRefCount**（配对 0x510 目录池；fs_open_entry_by_oem_path +1、fs_close_file_by_context -1）
Ghidra 结构体与 fs_structs.h 已互换更正。

### 新结构体 FatDirObject（0x510，Ghidra + fs_structs.h 同步）

与 FatFileObject 同构（fctx@0x08 mode=4、entry@0x78 memcpy 0x480、aLongPath_w@0x2f0），
尾部不同：qwOwnerTag_0x500、**pvValidateCtx_0x508（qword，fs_open_entry_core 写入
fs_validate_directory_entry 输出；文件对象侧该指针在 0x518）**，到 0x510 截止。
gcc -fsyntax-only 通过（新增 8 条 FS_ASSERT_OFF + size 断言）。

### 0x7D0 迭代器足迹定案（旧"≥0x7e0"疑点证伪）

`fs_idirectory_opendir` @0x71000d1890：`fs_log_assert_check(2000)` 的 **2000 是十进制尺寸 = 0x7D0**，
与 FsDirIterObj 结构体精确等大；最高字段 ppOwnerFatCtx@0x7c8+8 = 0x7D0，无越界。
内部窗口：aName@0xc(260B) → qwF_0x110@0x110 → aDirInfo@0x118(0x688) → 0x7a0 控制区
（bReady@0x7a0 / pDirSearchObj@0x7a8 / pLogCtx@0x7b0 / pFatWrapper@0x7b8 / dwF_0x7c0 / ppOwnerFatCtx@0x7c8），
客户端虚表 0x7100247518 写 pVptr@0。

### Ghidra 回写清单

- 新结构 `FatDirObject`(0x510)；`FsDrvObject` 字段改名 4 处（0x88→pDir_object_array、
  0x90→pDirSearchObj_array[类型 FatDirSearchObject*]、0x98/0x9c 计数器互换）
- 改名 2 函数：fat_find_or_alloc_file_slot→**fat_find_or_alloc_dir_object**、
  fat_allocate_dir_context→**fs_alloc_thread_ctx_node**（后者原为误名：实为按线程分配
  FS 上下文节点 0x16c0 链表，与目录无关）
- plate 注释 5 个（fs_init_volume_context / fat_find_or_alloc_dir_object /
  fat_get_volume_handle_stats / fat_allocate_file_object / fs_idirectory_opendir）；save_program ×2
