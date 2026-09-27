
---

## 2026-09-14 第六轮：SD 卡上机取证 —— 根因实锤（目录条目的 ARCHIVE 位）

### 环境与工具

- 目标：`F:` = 卷标 **SWITCH SD**，**FAT32**，512B/扇区，128 扇区/簇（簇=64KB），
  reserved=938，FAT@938，data_lba=98304，根目录簇=2；`/Roms` 簇=94695。
- 新增取证脚本（`fs_encode_fix/`）：
  - `_raw_ls.py` —— 直接读 `\\.\F:` 解析 FAT32 目录项（8.3 名 + LFN + attr + 起始簇 + 大小 + 绝对偏移）。
    Windows 原始卷句柄要求 **偏移与长度都按扇区对齐**，脚本内 `pread()` 已处理。
  - `_raw_hex.py` —— 打印指定条目的完整 32 字节原始项（含 NT 字节、时间戳、簇号）。
  - `_raw_attr_scan.py` —— 递归扫描目录 attr 分布（0x10 vs 0x30）。

### ★ 决定性事实：正常/异常列表 == attr 0x10 / 0x30

`/Roms` 下 33 个目录条目：

| attr | 数量 | 目录 |
|---|---|---|
| **0x10**（DIR，无归档位） | 8 | DC、NAOMI、NGC、PC-FX、PCE-CD、PS1、PSP、SS |
| **0x30**（DIR｜ARCHIVE） | 25 | FBNEO ACT/ETC/FLY/STG hack、MAME ACT/ETC/FLY/STG、FC、FC hack、FC-HD、GB、GBA、GBC、MD、MD hack、MD hack(picodrive)、MD-32X、N64、NDS、PCE、SFC、SFC hack、WSC、WII Ware |

**"显示为文件"的目录 == attr 0x30 的 25 个；"正常"的 == attr 0x10 的 8 个**，
与用户给的 8 个正常名单逐一命中。逐字节对比（`_raw_hex.py`）确认两者除 attr 外
无其它差异（名字、NT 字节、时间、簇号均正常）。

- 深层目录扫描（`/Roms` 下 3 层，5585 个目录）**全部为 0x10** → ARCHIVE 位只出现在
  `/Roms` 的**顶层平台目录**上，是某次 PC 侧批量操作/工具留下的。
- Windows 侧 `GetFileAttributesW`：两者都返回 DIR=True（0x10/0x30）→ PC 一切正常
  （Windows 只看 0x10 位，不看归档位），与"PC 能正常查看"完全吻合。
- 主机自己创建的目录均为 0x10（`/Nintendo/{Contents,save,Album}`、`/atmosphere/*`、`/switch/*`），
  证明 0x10 才是"正常目录"形态。

### fs 侧机制：交给上层的"类型"是属性位域，不是规整枚举

`fs_get_file_type_by_path`(0x71000d30e0) 反汇编结尾（逐指令）：

```
71000d31f4: stp xzr,xzr,[sp, #0x8]      ; 清零 stat 输出缓冲（32B，基址 sp+0x8）
71000d31f8: bl  0x7100115ed0            ; FS_fstat(path, out=sp+0x8)
71000d32e8: ldrb w8,[sp, #0x25]         ; w8 = out[0x1D] = 属性字节（fat_copy_file_info_to_output 写入的 dwAttr）
71000d32f0: ubfx w8,w8,#0x4,#0x2        ; w8 = (attr >> 4) & 3
71000d32f4: str w8,[x22]                ; *out = w8     ← 返回值
```

`fat_copy_file_info_to_output`(0x71000ff830)：`outEntry[0x1D] = (dwAttr & 0xff) ? dwAttr : 0x40`
（盘上 attr 原样）。于是：

| 盘上 attr | 返回值 `(attr>>4)&3` | 语义 |
|---|---|---|
| 0x10 目录 | **1** | 目录（无归档） |
| 0x20 文件 | **2** | 文件 |
| **0x30 目录** | **3** | ← **非法/意外值**（目录+归档） |

- 文档契约：`nn::fs::DirectoryEntryType` = **0=Directory / 1=File**（switchbrew），
  libnx `FsDirEntryType_Dir = 0`；而 fs 实际返回的是**属性位域**（bit0=目录位、bit1=归档位）。
- fs 内部对同一字段也是**按位测试**而非枚举比较：`fs_check_is_directory`(0x7100174efc) /
  `fs_check_not_directory`(0x7100175018) 都判定 `(value & 3) == 3`。
- 因此：任何对上层拿到的这个值做**严格比较**的消费方（例如"== 目录值才算目录"或
  "带归档位就当文件"），遇到 0x30 目录得到 3 → 落入"文件"分支
  → **目录显示为文件、大小 0**（目录的 size 在盘上恒为 0）。
- 这一机制一次性解释全部特征：**现象固定**（attr 静态）、**与 codepage 补丁无关**、
  **与大目录无关**、**无需同名文件被打开**、**PC 正常**、**中文/特殊字符无关**。

### 为什么是"部分"目录

ARCHIVE 位是 PC 侧整理/复制/打包工具写上去的（Windows 资源管理器、各类复制/解包工具常会
给目录带上 A 位），主机 fs 自己创建目录时不会加。**只有被这类工具标记过的顶层平台目录才中招**，
其余目录（含所有深层目录）不受影响 —— 与"现象固定在部分子目录"完全对应。

### 修复（推荐，立即可用、可回退、不碰数据）

清掉那 25 个目录条目的 A 位，使其与 8 个正常目录完全同构：

```cmd
attrib -a "F:/Roms/FBNEO ACT hack"
attrib -a "F:/Roms/MAME ACT"      ...（共 25 个）
```

- 验证：`python _raw_attr_scan.py /Roms 1` 应显示 `0x10=33 0x30=0`。
- 可回退：`attrib +a <dir>`；A 位对目录本身在 FAT 语义中无实际用途。
- 注意：若之后再用同类 PC 工具整理库文件，A 位可能被重新打上 → 复现，重新清理即可。

### 备选（工程侧，暂不建议先做）

在 fs 侧把该值归一化（例如令 `(attr>>4)&3 == 3` 时返回 1，即"目录+归档"与"纯目录"同值），
可让所有上层工具不再误判，且不动用户数据。但：① 该字段是 fs 自用的属性位域（内部同样是按位测试），
改它会影响所有消费方；② 未确认目标 app 读的是 `GetEntryType` 返回值还是枚举输出里的
`attributes`(+0x301) 字段（两者值相同，均为 `(attr>>4)&3`），落地前需先确认，属后续可选优化。
¶ç»åä¸æé¤æ¸åï¼éå¯¹"ç°è±¡åºå®ãå¤ä¸ªå­ç®å½ãéååæä»¶"åè¯ï¼

### 对第一轮假说的修正

"同名文件被打开"**不是必要条件**。弱键是 (父目录簇, 项内扇区偏移)，与名字无关：
**任何一个**已打开文件，只要其目录项落在同一个大目录簇里、且项索引 ≡ 被误报项 (mod 每扇区项数 16)，
就会污染该位置。因此：
- **一个**持续打开的文件（app 自己的配置/数据库/日志，或边扫边开的探测句柄）即可同时污染
  同簇内最多 16 个间隔的位置 → "多个子目录显示为文件"且每次固定。
- 被误报项显示的名字/大小 = 那个打开文件的（重复出现），真子目录消失。

### 第二轮新增验证（Ghidra）

- ReadDirEntry 稳态引擎 = `IDirectory_Read`(0x71000d4a20) → `IDirectory_ReadDirEntry`(0x71000d4d50)
  → bReady==0 时 `fs_check_directory_state`(0x7100116710) → `fs_reset_directory_state`(0x7100106d00)
  → `fs_iterate_directory_entries(dirInfo,false)`（迭代器 dirInfo 持久，dwStartIndex=l+1 续扫）。
  bReady!=0 时才走 `FS_fsnext`(0x7100116690)→`fs_parse_directory`（带目录缓存），仅首项/复位用。
- type 唯一来源：快照 FsDirInfoInternal.attr@0x478；exFAT 由 `fat_copy_entry_to_fsobj_type85`
  (0x71000fcc10) 从盘上 0x85+4 的 u16 **原样**拷贝；FAT32 由 `fat_copy_entry_info_to_output`
  从 0x0B 字节原样拷贝。SetChecksum 验证失败/NameHash 失配/名字非法字符（0x7f 检查，0xd4af4 NOP）
  只会导致**条目被跳过（不可见）**，不可能变成 file。
- `fat_seek_directory_entry`(0x71000f8840)/`fat_read_next_directory_entry`(0x71000f89a0) 的
  位置数学自洽（map(index/每扇区项数) + 扇区内偏移），未见跨簇错位。
- 目录缓存（`fs_find_directory_entry`@0x7100105e60 / `fs_update_directory_cache`@0x7100106080，
  每卷单槽：路径 memcmp 全配 @+0x208 + FsObject 0x480@+0x210 + 索引@+0x690）只服务
  按路径解析/open/stat 与 fsnext 首项，不参与稳态枚举的 type 判定。
  `fs_validate_directory_entry`(0x7100105cb0) 也用同一弱键扫 FatDirObject 池（重复打开检测）。

### 判别实验（决定性）

1. **假"文件"的名字**：与目录里某个真实文件完全同名同大小（且该真文件仍存在）→ 弱键复用实锤，
   找出是谁持有句柄（app 自身探测逻辑/播放器/自启 homebrew），关掉后复现应消失。
   若假条目带的是子目录自己的名字 → 弱键复用被排除，转查盘上数据（见 2）。
2. **盘上数据**：PC 用 hex 编辑器查被误报项的 0x85+4 (exFAT) / 0x0B (FAT)：
   Directory 位 (0x10) 是否真的缺失（某些打包/镜像工具写盘丢目录位）。
   若 PC 资源管理器显示为文件夹则此位正常。
3. **位置周期性**：假条目应在同一簇内按每扇区项数（512B 扇区=16）间隔出现，且多项重复
   同一个文件名。
4. **app 侧分类依据**：用 DirectoryEntry.type(+0x304) 还是 GetEntryType 按路径二次确认
   （fs_stat_by_path 同弱键，二次确认同样被污染）。

---

## 2026-09-14 第三轮：全链路「名字↔type 同源性」验证（新证据：假条目带子目录自己的名字、大小 0、PC 正常）

### 本轮钉死的完整输出链（每个 attr 写点）

1. **FAT32**：`FAT_FindDirectoryEntry`(0x71000f8f70) 循环 → `FAT_ProcessDirectoryEntry`(0x71000f9e70)
   → attr 过滤通过时 `fat_copy_entry_info_to_output`(0x71000f1140)：`dwAttr = entry[0x0B]`（盘上原样）。
   LFN 链由 `fat_process_long_filename_entry`(0x71000f11a0) 累积（seq 校验/checksum 校验，失败仅影响名字→回退短名，attr 不受影响）。已删除条目(0xE5)只清名字继续扫。
2. **exFAT**：`fat_find_directory_entry_by_name`(0x71000fa100) → `fat_process_directory_match`(0x71000fa4e0)
   → 0x85 项时 `fat_copy_entry_to_fsobj_type85`(0x71000fcc10)：`dwAttr = u16@entry+4`（盘上原样）。
   NameHash 不自洽/SecondaryCount 异常的 entry-set 只会被【跳过】（不可见），不会变 file。
3. **init**：`fat_init_fs_object_from_entry`(0x71001058e0)：`wAttr@0x478 = entry->dwAttr ? dwAttr : 0x40`
   （★ 唯一的默认值分支：dwAttr==0 → 0x40=ARCHIVE → File。但所有 FOUND 路径都先填了 dwAttr，目录项 attr≥0x10 恒非零，静态上不可达）。
   短名模式分支 `fat_init_fs_object_shortname`(0x7100105ba0) 只写名字字段，attr 仍走公共尾部。
4. **输出过滤**：`IDirectory_ReadDirEntry`(0x71000d4d50)：`. / ..` 按名字前缀跳过；type 过滤 = `(wAttr@0x478 >> 4) & 1` 位测试，无缺陷。
5. **IPC 输出**：`IDirectory_Read`(0x71000d4a20)：
   - `type = ((wAttr@0x478 & 0x10) == 0)`（1=File），`size = type==File ? file_size@0x470 : 0`
     —— **目录即使 type 误判，size 也恒为 0**（目录的 file_size 本来就是 0）→「大小 0」与任何 type 误判来源自洽，无鉴别力。
   - 名字取 aSname@0x47A（无长名时）或 aLname@0x487（OEM/UTF-8 字节流）；
     `≥0x7F` 字节丢弃检查 = **0xd4af4 补丁点本体**（IPC 层）；DOS 非法字符 `"?*<>:|/\` 丢弃。
     丢弃 = 条目不可见，不会变 file。

### 核心结论（第三轮）

**fs 内部从盘到 IPC 输出的整条链上，名字与 type 恒同源（同一 FsObject、同一 init 调用）。
不存在「输出子目录自己的名字 + type=File」的 fs 内部代码路径。** 结合 PC 上正常，
剩余两个可自洽解释全部现象的假说：

### 假说 A：盘上真的存在与子目录同名的 0 字节文件（优先验证）

FAT 的身份是 (8.3 短名 + LFN)，Windows 资源管理器会合并/只显眼地显示文件夹。
rom 库整理/打包工具的典型事故：创建目录前先落了一个 0 字节占位文件（或解压中断），
最终「Game(文件,0B) + Game(目录)」并存——两者 LFN 相同、短名不同（GAME~1 / GAME）。
- 完美解释：名字是自己的、大小 0、固定复现、补丁前后一样、多个目录同时中招、与大目录无关。
- 中文/特殊字符相关性：中文名→8.3 短名生成退化为 `______~N`，工具处理短名冲突时更易出事故。

**判别实验**：PC 命令行在出问题的父目录执行 `dir /a`（显示短名/属性/大小），
或用 Total Commander/Everything 看原始条目——若每个「假文件」对应一个 0 字节同名文件实锤。
也可对比 Switch 端枚举条目数与 PC 文件数（Switch 应多出 N 个条目）。

### 假说 B：app 侧用「按路径二次查询」分类，被弱键污染

枚举输出的 DirectoryEntry.name/type 本身正确；app（rom 前端常见）对每个条目再调
`GetEntryType(path)` / stat 二次确认分类 → `fs_stat_by_path`(0x7100107190) 内含与枚举
相同的 (drvObj, dirCluster, wEntryOffset) 弱键复用分支（round-1 已证）→ 目录条目撞上
已打开文件的身份 → 二次查询返回 File。名字来自枚举（正确）、type 来自污染查询（错）。
- 解释：固定复现（打开句柄集合固定）、一个句柄污染同簇 16 个位置、补丁无关、大小 0（枚举输出）。
- 与假说 A 的区别：A 的「假文件」是独立条目（枚举条目数变多）；B 不多出条目。

**判别实验**：换一个只依赖 DirectoryEntry.type 的枚举器（hbmenu / Tesla 文件管理器）
看同一目录：正常 → B（app 侧）；仍异常 → A（盘上数据）。
另外 `dir /a` 同时能排除 A——两个实验正交，做完即可定案。

---

## 2026-09-14 第四轮：针对「短目录名（GBA/PSP 类 8.3 纯 ASCII 名）」的定向分析

### 短名条目在 fs 里的专属路径核查（全部排除）

短名条目是枚举链里**最简单**的情形：无 LFN 累积（排除 seq/checksum/孤儿链问题）、
名字直接取 aSname@0x47A（0x487 长名指针为空）、attr 依旧盘上原样拷贝
（FAT32: 0x0B；exFAT: 0x85+4）。`FAT_GetShortNmae`(0x71000f1100) 仅做 0x05→0xE5 首字节
替换；`fat_init_fs_object_shortname`(0x7100105ba0) 仅写名字字段。
**短名条目没有任何专属的 type 破坏路径——fs 枚举侧对短名同样排除。**

### ★ 本轮关键发现：枚举过滤器的可见性不对称（0x77 含 hidden/system）

`IDirectory_ReadDirEntry`(0x71000d4d50) 的 bReady 路径硬编码 `FS_fsnext(name, 0x77, dirInfo)`；
0x77 = RO|HIDDEN|SYSTEM|DIR|ARCHIVE|DEVICE。即 **Switch 枚举不隐藏任何文件**；
而 Windows 资源管理器默认不显示隐藏文件。⇒ 若 /roms 根目录存在与平台目录同名的
**隐藏 0 字节文件**，现象就是：PC 看一切正常、Switch 上「GBA/PSP 显示为文件、大小 0」。
（check_attr_flags 语义=任一位相交即通过，已验证 hidden 文件 attr 0x22 必通过 0x77 过滤。）

### 为什么偏偏是 GBA/PSP 这类平台目录

- **假说 A'（隐藏同名 0 字节文件，升级版假说 A）**：rom 库整理/打包工具常在库根目录
  为每个平台留 marker/占位文件，或解压中断残留；平台目录名 = 工具最常触碰的名字。
  纯短名意味着 PC 上文件与目录同名同显示形，资源管理器里紧挨着，极易被当成同一文件夹。
- **假说 B（app 二次查询弱键污染）反而更契合短名场景**：弱键污染要求污染文件与被污染
  条目**同父目录**（dirCluster 相同）——即污染源是 /roms 根目录下的文件（扫描器自己的
  数据库/缓存/索引，扫描期间常开）。GBA/PSP 等平台目录排在库根目录低 index 区，
  正是一个常开句柄能污染到的前 16 个位置；且它们是扫描器 opendir/stat 最密集的路径。

### 判别实验（一次定位，正交）

1. **PC 定案 A'**：`cmd` → 库根目录 → `dir /a`（显示隐藏+短名+大小）。
   若看到 0 字节隐藏 GBA/PSP 文件 → 实锤，直接删除即可（chkdsk 通常也会报 duplicate name）。
2. **Switch 数条目**：枚举条目数 > PC 文件夹数，且多出的条目名=GBA/PSP、type=file、0 字节
   → 同样实锤 A'。
3. **换枚举器判 B**：hbmenu / Tesla 文件管理器看同一目录。
   正常 → app 二次查询被弱键污染（B）；同样异常 → 盘上数据（A'）。

---

## 2026-09-14 第五轮：「子目录内部文件能否污染子目录自身」——机制级否定

### 身份键字段语义钉死（反编译核对）

- `FsObject.dirCluster@0x244` = **承载该条目的目录（父目录）的簇号**（fs_structs.h 注释与反编译一致，
  非条目自身 firstCluster@0x23c）。
- 三处复用查找的键比较逐一对上：
  - 文件池 `fat_find_file_context_by_id`(0x71000ff540)：比较 obj+0x2A8/0x2BC/0x2C0
    = FsObject+0x230(pDrvObj)/0x244(dirCluster)/0x248(wEntryOffset)。
  - 目录池内联扫描（fs_iterate_directory_entries）与 `fat_find_or_alloc_dir_object`(0x7100109e40)：同键。

### 结论：内部文件污染不到父目录里的子目录条目

枚举 /roms 时，弱键里的 dirCluster = **/roms 的簇号**；GBA/PSP 内部文件对象的 dirCluster
= GBA/PSP **自己的簇号** → 永不匹配。内部文件只能污染**同 dirCluster** 的位置，
即只能污染 **GBA/PSP 目录内容的列表**，不可能影响 GBA/PSP 在 /roms 里的条目。
FAT/exFAT 语义亦然：目录内部增删文件、目录扩簇只写 FAT 链与内部条目，从不改写
父目录中该目录条目的 attr（fs 中无此写路径）。

### 顺带修正（比第一轮更精确的分支条件）

- **文件条目**：只要卷上有打开文件即做文件池复用（与是否打开目录无关）。
- **目录条目**：仅当 `drvObj+0x9c`（打开目录计数）== 0 时才走文件池复用；
  有任一目录打开时改为扫**目录池**（同弱键）——命中只会发生在「碰撞的兄弟目录同时打开」，
  返回对方 FsObject 快照：type 仍是 Directory，只会**串名/串内容**，不会变 File。
- **推论**：扫描期间 app 持有 /roms 的 IDirectory 会话 → 0x9c>0 → 目录条目的
  文件池复用分支整体不可达；`fs_stat_by_path` 的复制分支带同样 0x9c 守卫 →
  **假说 B（二次查询污染）对目录条目也被此守卫压制**（前提：扫描时任一目录会话未关闭）。
  假说 A'（盘上隐藏同名 0 字节文件）权重进一步上升。

### 新判别问题（一问定案）

Switch 上枚举 /roms 时，GBA 是「**只出现一次**（作为文件）」还是「**出现两次**
（一个文件夹 + 一个 0 字节文件）」？
- 出现两次 → A' 实锤（盘上确有同名隐藏 0 字节文件，PC 资源管理器合并显示）。
- 只出现一次（真文件夹消失）→ A' 被排除，问题在 app 侧展示/过滤逻辑
  （fs 输出层已证无法产生「自己的名字 + File」）。


---

## 2026-09-17 第七轮：fs 侧补丁规避 ARCHIVE 位问题 —— 可行性与落地方案

用户已实测确认根因 = 目录条目的 ARCHIVE 位（attr 0x30）。本轮论证能否在 fs 侧打补丁规避。

### 1. fs 的两条"类型"出口，且二者不一致

`IDirectory_Read`(0x71000d4a20) 写出 `nn::fs::DirectoryEntry`(0x310)：

| 偏移 | 字段 | 计算式 | attr=0x10 目录 | attr=0x30 目录 | attr=0x20 文件 |
|---|---|---|---|---|---|
| +0x304 | `type` | `(attr & 0x10) == 0` | **0 = Directory（正确）** | **0 = Directory（正确）** | 1 = File |
| +0x301 | `attributes` | `(attr >> 4) & 3` | 1 | **3（非法值）** | 2 |
| +0x308 | `size` | 目录恒 0 | 0 | 0 | 文件大小 |

⇒ **枚举输出里 type 字段本来就是正确的**，坏掉的只有 `attributes`（=3）。
这直接解释了"名字是自己的、大小 0、被当成文件"：app 用的是 `attributes` 做严格等值比较（`==1` 才算目录）。

`fs_get_file_type_by_path`(0x71000d30e0，即 GetEntryType) 结尾同样是 `*out = (attr>>4)&3`。

### 2. ★ 关键约束：fs 内部判定与 app 期望**相反**

```
fs_check_is_directory @0x7100174efc
  7100174f34: ldr  w8,[sp]        ; v
  7100174f38: mov  w9,#0x3
  7100174f3c: bics wzr,w9,w8      ; 3 & ~v
  7100174f40: cset w20,eq         ; 是目录 ⟺ (3 & ~v)==0 ⟺ v == 3
fs_check_not_directory @0x7100175018  — 同一判据
```

**fs 内部把 v==3 当"目录"**（即认为目录本就该带 ARCHIVE 位），而 app/libnx 侧契约是
`DirectoryEntryType` 0=Dir/1=File，只有 **v==1 才是"目录"**，3 是非法值。
⇒ 这就是**不能**直接归一化共享出口（`fs_get_file_type_by_path`）的原因：改它会连带改变
fs 内部这两个检查的语义（0x30 目录将不再被"对目录做文件操作"的守卫拦截）。

### 3. 方案 A（推荐，零风险）：只归一化枚举输出的 `attributes` 字段

位置 `IDirectory_Read` @**0x71000d4b6c / 0xd4b7c / 0xd4b8c**，三条 **1:1 原地改写**（不增指令、不需要代码洞）：

```
; 原                                    ; 改为
0xd4b6c  1F 20 03 D5  nop               09 62 80 52  mov   w9, #0x310        ; 把下面的 mov 提前
0xd4b70  28 17 40 38  ldrb w8,[x25],#1   (不变)
0xd4b74  E8 FF FF 35  cbnz w8, ...       (不变)
0xd4b78  E8 33 49 79  ldrh w8,[sp,#0x498](不变)   w8 = dirInfo.wAttr @0x478
0xd4b7c  09 62 80 52  mov w9,#0x310      0B 15 04 53  ubfx  w11, w8, #4, #2  ; w11 = v
0xd4b80  69 5B 09 9B  madd x9,x27,x9,x22 (不变)
0xd4b84  7B 07 00 91  add x27,x27,#1     (不变)
0xd4b88  1F 01 1C 72  tst w8,#0x10       (不变)   Z=1 ⟺ 非目录（文件）
0xd4b8c  08 15 04 53  ubfx w8,w8,#4,#2   68 05 9F 1A  csinc w8, w11, wzr, eq
0xd4b90  --           cset w10,eq  (type) (不变)
0xd4ba0  --           csel x10,x10,xzr,eq(size) (不变)
```

语义（`csinc Wd,Wn,Wm,cond`：cond 成立取 Wn，否则取 Wm+1）：
- 文件（Z=1）→ `w8 = w11 = v`（2，原样）
- 目录（Z=0）→ `w8 = wzr + 1 = 1`　⇒ **0x10 与 0x30 目录统一为 1**

安全性已逐条验证：
1. `csinc` **不写 NZCV**，后面 `cset w10,eq`(type) 与 `csel x10,x10,xzr,eq`(size) 完全不受影响。
2. `w11` 在 0xd4b7c~0xd4b8c 之间无其它使用者（只有 madd/add/tst）。
3. 0xd4b6c~0xd4b90 区间**没有任何分支跳入**（已扫描函数内全部分支目标）→ 三条指令恒按顺序执行。
4. 1:1 替换，函数尺寸不变；不触碰 fs 内部任何逻辑，只改输出给 app 的一个字节。
5. 与既有 0xd4af4（≥0x7F 名字丢弃）补丁点不在同一位置，无冲突。

整段 36 字节（可直接用于 pattern / cmp）：
- 原：`1F2003D528174038E8FFFF35E833497909628052695B099B7B0700911F011C7208150453`
- 新：`0962805228174038E8FFFF35E83349790B150453695B099B7B0700911F011C7268059F1A`

局限：只覆盖 `ReadDirectory` 的 `attributes`。若目标 app 走 `GetEntryType` 二次查询，见方案 B。

### 4. 方案 B（备选，有语义风险）：归一化 GetEntryType

`fs_get_file_type_by_path` @0x71000d32e8-0x32f4：
```
0x32e8 ldrb w8,[sp,#0x25]   0x32ec mov w19,wzr   0x32f0 ubfx w8,w8,#4,#2   0x32f4 str w8,[x22]
```
归一化需要 ldrb / 算 v / 设标志 / csinc / str 共 **5 条**，可用槽位只有 4 条 ⇒ 必须 trampoline 到函数外空间
（函数尾 0x71000d3328 仅 8 字节 padding，不足 12 字节，需另找代码洞）。
**且会改变 fs_check_is_directory / fs_check_not_directory 的判定**（v 3→1 ⇒ fs 内部不再视其为目录，
"禁止对目录做文件操作"的守卫会失效）。建议：仅在确认 app 确实调用 GetEntryType、且真机验证方案 A 无效后再做。

### 5. 方案 C（不推荐）：源头清 `FsObject.dwAttr` 的 A 位

`fat_copy_entry_info_to_output`(0x71000f1140, FAT32) / `fat_copy_entry_to_fsobj_type85`(0x71000fcc10, exFAT)。
风险：dwAttr 存在被写回磁盘的路径（重命名/删除/属性设置），会把用户目录的真实属性改掉；
且同样改变 fs 内部 v==3 判定。影响面远大于方案 A。

### 6. 工程集成建议（sys-patch）

- 走 `patches[]` 表（fs title `0x0100000000000000`），不要走 `fs_codepage_patch()` 的硬编码偏移套路，
  这样自动获得 fw 门控 + config 开关 + 日志 + overlay 展示。
- 两种写法：
  - **单条目 36 字节 pattern + 36 字节 patch**（原子性好），需把 `PatchData::data[20]` 扩到 ≥36（PatternData 已是 60，够用）。
  - 或 **3 个独立条目**（各 4 字节 patch），无需改结构，但要注意三条 pattern 的唯一性（互不包含）。
- `cond`/`applied`：分别检查首字节是 `1F 20 03 D5`(nop) / `09 62 80 52`(mov w9,#0x310)。
- fw 门控：当前偏移取自 19.x（FS_1/19.exfat.FS.kip1），其它版本需重新定位这三条指令。
- 新增 config 开关（如 `[options] fs_archive_fix`，默认 1），便于一键回退。
- 构建守卫：`sysmod/tools/check_patch_sizes.py` 目前只校验 `fs_patch_function()` 的补丁点，
  patches[] 表不在其列；建议把新点的 cmp 字节也纳入 `--fs` 比对，并加一条"pattern 在 fs 中必须唯一"的检查。

### 7. 验证方法

| 步骤 | 期望 |
|---|---|
| 打补丁前用出问题的 app 看 /Roms | GBA/PSP 等 25 个（attr 0x30）显示为文件、大小 0 |
| 打补丁后 | 全部显示为目录；DC/NAOMI/NGC 等（attr 0x10）始终正常（对照组） |
| 回归 | 文件仍显示为文件且大小正确（attributes 仍为 2，未被 csinc 改变） |
| 交叉验证 | `attrib -a` 清 A 位后不打补丁也应正常 —— 两条路径独立，可互为对照 |


---

## 2026-09-17 第八轮：方案 C 评估 + ★ 重大修正（0x30 目录在 fs 里是被**主动拒绝**的）

用户提问：方案 C（源头清 `FsObject.dwAttr` 的 A 位）实现是否更简单，"改了实际属性也没关系"。

### ★ 决定性新发现：v==3 不只是"显示错"，fs 会主动拒绝访问

`fs_directory_open`(0x7100176664) 反编译（硬代码，非注释推断）：

```c
uVar2 = fs_check_is_directory(param_1, param_2);
if ((uVar2 & 1) == 0) {
    FVar1 = (**(code **)(**(long **)(param_1 + 8) + 0x28))(*(long **)(param_1 + 8), param_2);  // 正常打开
} else {
    FVar1 = fs_log_error_code(0x202, 0xd3f8f8be11f6e415);                                      // 报错
}
```

而 `fs_check_is_directory`(0x7100174efc)：

```
7100174f34: ldr  w8,[sp]        ; v = fs_get_file_type_by_path 的返回值
7100174f38: mov  w9,#0x3
7100174f3c: bics wzr,w9,w8      ; 3 & ~v
7100174f40: cset w20,eq         ; 返回 1 ⟺ (v & 3) == 3
```

`fs_check_not_directory`(0x7100175018) 同判据（`bics` 后 `b.ne` 跳过 → v==3 时同返回 0x202）。

**0x202 = 模块 2(FS)、描述 1 = "Path does not exist"**（switchbrew 错误码表）。

⇒ **attr 0x30 的目录：OpenDirectory 直接返回 PathNotFound，Switch 上根本进不去。**
枚举之所以还能看到它们，是因为枚举路径（`IDirectory_Read` → `fs_iterate_directory_entries`）
**不经过这两个 check**。这完美解释"能列出、但表现异常"。

### 由此推翻第七轮的一个结论

第七轮认为"fs 内部以 v==3 为目录，故禁止改共享出口"——**方向理解反了**。
v==3 不是"目录的正规值"，而是 fs **专门拒绝的非法值**（v==1 的纯目录才正常放行）。
因此第七轮"方案 A 即可"的结论不成立：**方案 A 只改枚举输出的一个显示字节，
目录仍然打不开（PathNotFound）**。

### 方案 C 评估：不更简单，且有一个致命陷阱

**陷阱（必须条件清位）**：无差别清 A 位会误伤文件——
普通文件 attr=0x20 清掉 A 位 → 0x00 → `fat_init_fs_object_from_entry`(0x71001058e0) 的
兜底 `wAttr = dwAttr ? dwAttr : 0x40` 生效 → wAttr=0x40 →
`type = (wAttr & 0x10) == 0` = **0 = Directory** ⇒ **所有文件变成目录**。

必须"仅当目录位(0x10)存在时清 A 位"，需要 +3 条指令：

```
and  w8,w8,#0xffffffdf   ; 121a7908
tst  w8,#0x10            ; 721c011f
csel w8,w9,w8,ne         ; 1a881128
```

**空间不足**：

| 改点 | 可用空间 | 需要 | 结论 |
|---|---|---|---|
| `fat_copy_entry_info_to_output`@0x71000f1140（FAT32，原 0x58B） | 0x60（至 0xf11a0） | 0x64 | **差 4 字节** |
| `fat_copy_entry_to_fsobj_type85`@0x71000fcc10（exFAT，原 0x98B） | 0xA0（至 0xfccb0） | 0xA4 | **差 4 字节** |

两处都必须 trampoline；而 `.text` 内 ≥16 字节的零洞**仅 1 处**（VA 0x71000000c4，60 字节）。
再加上 dwAttr 存在写回磁盘的路径 ⇒ **方案 C 实现复杂度明显高于方案 A/G，不推荐**。

### 方案 G（新推荐，最简单）：改两处判据常量，1:1、零代码洞

把 `bics` 的掩码常量从 3 改成 4。由于 v = (attr>>4)&3 ∈ {0,1,2,3}，**bit2 恒为 0**，
故 `4 & ~v` 恒非 0 → Z 永 0 → check 永不返回"拒绝" → 0x30 目录正常打开。

| 位置 | 原指令 | 原字节 | 新指令 | 新字节 |
|---|---|---|---|---|
| 0x7100174f38（`fs_check_is_directory`） | `mov w9,#0x3` | `69 00 80 52` | `mov w9,#0x4` | `89 00 80 52` |
| 0x71001750c4（`fs_check_not_directory`） | `mov w9,#0x3` | `69 00 80 52` | `mov w9,#0x4` | `89 00 80 52` |

- 1:1 原地改写，函数尺寸不变，无需代码洞；属 movz 且 Rd 不变 → 构建守卫白名单允许。
- 语义代价：不再拒绝 v==3 这一非法组合。但 v==3 语义上就是"带归档位的目录"，
  放行即按目录处理，与 `attrib -a` 的效果一致。

### 组合建议：A + G（共 5 条 1:1 原地改写，零代码洞）

- **G** 解决"打不开"（PathNotFound）——核心问题。
- **A** 解决"显示为文件"（枚举 `attributes`=3）——显示问题（`IDirectory_Read` 0xd4b6c/0xd4b7c/0xd4b8c，第七轮已验证）。
- 二者互补、互不重叠；可先只上 G 验证"能否进入目录"，若显示仍异常再补 A。

### 验证方法

| 步骤 | 期望 |
|---|---|
| 打 G 前，出问题的 app 尝试进入 /Roms/GBA | 失败（PathNotFound 或表现为"不是目录"） |
| 打 G 后 | 可正常进入，且 DC/NAOMI 等 0x10 目录始终正常（对照组） |
| 若显示仍为文件 | 追加方案 A |
| 交叉验证 | `attrib -a` 清 A 位后不打补丁也应正常（两条路径独立，互为对照） |
