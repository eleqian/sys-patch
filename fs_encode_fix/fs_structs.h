/*
 * fs_structs.h - Reconstructed FS module structures (nn::fs / nne::prfile2)
 *
 * Derived by reverse engineering the Nintendo Switch fs sysmodule
 * (19.exfat.FS.kip1), image base 0x7100000000.
 *
 * Sources:
 *   - code-derived offsets (Ghidra project FS_1/19.exfat.FS.kip1)
 *   - IPC structs cross-checked against switchbrew "Filesystem services"
 *
 * All structs are byte-accurate and packed: the FS module uses unaligned
 * fields. Offsets are exactly the ones observed in the original code.
 */
#ifndef FS_STRUCTS_H
#define FS_STRUCTS_H

#include <stdint.h>
#include <stddef.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#pragma pack(push, 1)

/* ------------------------------------------------------------------------- */
/* IPC / public types (switchbrew)                                            */
/* ------------------------------------------------------------------------- */

/* nn::fssrv::sf::FspPath - 0x301 byte UTF-8 string */
typedef struct {
    char str[0x301];                       /* 0x000 */
} FspPath;                                 /* 0x301 */

/* nn::fs::DirectoryEntryType */
typedef enum {
    DIRENT_TYPE_DIRECTORY = 0,
    DIRENT_TYPE_FILE      = 1,
} DirectoryEntryType;

/* nn::fs::DirectoryEntry - element of IDirectory::Read output (0x310 each) */
typedef struct {
    FspPath path;                          /* 0x000 UTF-8 C string */
    u8      attributes;                    /* 0x301 bit0=dir, bit1=archive */
    u8      _reserved0[2];                 /* 0x302 */
    s8      type;                          /* 0x304 DirectoryEntryType */
    u8      _reserved1[3];                 /* 0x305 */
    u64     size;                          /* 0x308 0 for directories */
} DirectoryEntry;                          /* 0x310 */

/* nn::fs::OpenMode (IFileSystem::OpenFile mode) */
typedef enum {
    OPEN_MODE_READ      = 1u << 0,
    OPEN_MODE_WRITE     = 1u << 1,
    OPEN_MODE_READWRITE = (1u << 0) | (1u << 1),
    OPEN_MODE_APPEND    = 1u << 2,
} OpenMode;

/* nne::prfile2::StringEncode_e - only OEM/UNICODE exist; UTF-8 is smuggled
 * into ENCODE_OEM by the sys-patch codepage fork. */
typedef enum {
    ENCODE_OEM     = 1,
    ENCODE_UNICODE = 2,
} StringEncode_e;

/* nne::prfile2::StringDesc */
typedef struct {
    char          *ptr_left;               /* 0x00 */
    char          *ptr_right;              /* 0x08 */
    StringEncode_e encode_type;            /* 0x10 */
    u32            rsvd;                   /* 0x14 */
} StringDesc;                              /* 0x18 */

/* ------------------------------------------------------------------------- */
/* FAT / exFAT on-disk + parsed structures                                    */
/* ------------------------------------------------------------------------- */

/* 32-byte FAT directory entry (on-disk / raw). */
typedef struct {
    u8  sname[8];                          /* 0x00 8.3 name */
    u8  sext[3];                           /* 0x08 extension */
    u8  attr;                              /* 0x0b attributes */
    u8  scase;                             /* 0x0c NT case flags */
    u8  sub_sec;                           /* 0x0d creation 10ms/seconds */
    u16 create_time;                       /* 0x0e */
    u16 create_date;                       /* 0x10 */
    u16 access_date;                       /* 0x12 */
    u16 cluster_h;                         /* 0x14 */
    u16 modify_time;                       /* 0x16 */
    u16 modify_date;                       /* 0x18 */
    u16 cluster_l;                         /* 0x1a */
    u32 file_size;                         /* 0x1c */
} FatBaseEntry;                            /* 0x20 */

/* Overlapping name region inside FsObject (abs 0x263).
 * For FAT this is the 8.3 short name; for exFAT the stream-extension
 * NameHash / ValidDataLength overlay the first 13 bytes. */
typedef union {
    u8  shortName[13];                     /* +0x00 FAT 8.3 short name */
    struct {
        u8  _pad0[1];
        u16 streamNameHash;                /* abs 0x264 exFAT Stream NameHash */
        u8  _pad1[2];
        u64 validDataLength;               /* abs 0x268 exFAT ValidDataLength */
    };
} FsObjectName;                            /* 0x0D */

/* exFAT File-entry SetChecksum (u16 @0x262) overlays FAT LFN checksum byte
 * and the first byte of the 8.3 short name (name starts at 0x263). */
typedef union {
    u16 setChecksum;                       /* 0x262 exFAT SetChecksum / FAT LFN checksum */
    struct {
        u8  _pad0[1];                      /* 0x262 */
        FsObjectName name;                 /* 0x263 */
    };
} FsObjectNameArea;                        /* 0x0E (0x262..0x26f) */

/* 0x270 is reused: FAT stores the NT case-flags byte (scase); the exFAT
 * matcher uses the full dword as a scratch/free-entry position (-1 sentinel). */
typedef union {
    u32 status;                            /* exFAT search position / 0xffffffff */
    u8  scase;                             /* FAT NT case flags (bit3 base, bit4 ext) */
} FsObjectStatus;                          /* 0x04 */

struct FsDrvObject;

/* Parsed directory entry (FsObject, 0x278). Fills from the on-disk
 * FatBaseEntry (FAT32) or the exFAT 0x85/0xC0/0xC1 entry set. */
typedef struct {
    u16          awLongName[260];          /* 0x000 UTF-16 long name (LFN/exFAT), 0x208 bytes */
    u32          attr;                     /* 0x208 file attributes (FAT byte / exFAT u16) */
    u8           _padB[4];                 /* 0x20c */
    u64          fileSize;                 /* 0x210 exFAT DataLength / FAT size */
    u8           create10ms;               /* 0x218 exFAT Create10msIncrement / FAT sub_sec */
    u8           _padC[1];                 /* 0x219 */
    u16          createTime;               /* 0x21a DOS creation time */
    u16          createDate;               /* 0x21c DOS creation date */
    u8           modify10ms;               /* 0x21e exFAT LastModified10msIncrement */
    u8           _padC2[1];                /* 0x21f */
    u16          accessTime;               /* 0x220 exFAT LastAccessed time */
    u16          accessDate;               /* 0x222 DOS last-access date */
    u8           accessTz;                 /* 0x224 exFAT LastAccessedUtcOffset */
    u8           createTz;                 /* 0x225 exFAT CreateUtcOffset */
    u16          modifyTime;               /* 0x226 DOS modification time */
    u16          modifyDate;               /* 0x228 DOS modification date */
    u8           modifyTz;                 /* 0x22a exFAT LastModifiedUtcOffset */
    u8           _padD[5];                 /* 0x22b */
    struct FsDrvObject *drvObj;            /* 0x230 backing volume */
    s32          pathOffset;               /* 0x238 running path cursor (chars) */
    u32          firstCluster;             /* 0x23c object's own FirstCluster */
    u32          entryIndex;               /* 0x240 directory entry index (for ~N tail) */
    u32          dirCluster;               /* 0x244 cluster that holds this entry */
    u16          entryOffset;              /* 0x248 byte offset of entry within dir */
    u8           streamFlags;              /* 0x24a exFAT GeneralSecondaryFlags */
    u8           _padE[1];                 /* 0x24b */
    u32          dirStartCluster;          /* 0x24c directory's own first cluster */
    u16          sectorSize;               /* 0x250 search scratch (drv bytes/sector) */
    u8           _padF[6];                 /* 0x252 */
    u64          dirSearchParam;           /* 0x258 search scratch (ctx pField_0x58) */
    u8           nameLen;                  /* 0x260 exFAT NameLength */
    u8           entryNum;                 /* 0x261 exFAT SecondaryCount / LFN count */
    FsObjectNameArea nameArea;             /* 0x262 (SetChecksum | shortName@0x263) */
    FsObjectStatus   status;               /* 0x270 status.scase / exFAT scratch */
    u32          searchPos;                /* 0x274 exFAT free-entry position scratch */
} FsObject;                                /* 0x278 */

/*
 * Volume / drive object (FsDrvObject, 0x8C8). Indexed by drive letter:
 * the array lives at module-global 0x7100fd8598 and entry N (0..4) is at
 * base + N * 0x8C8. Field names were re-derived from:
 *   fs_init_volume_context @0x71000d7420  (allocation + pool layout)
 *   fat_parse_bpb @0x71000e12d0 + fat_parse_boot_sector @0x71000dbde0 (BPB)
 *   fat_calculate_fat_geometry @0x71000e1690 (0x50..0x78)
 *   fat_mount_volume_core @0x71000d7d10, fs_open_directory @0x7100100090
 *
 * NOTE on 0x00..0x38: this is a byte-for-byte mirror of the on-disk BPB
 * (with the exFAT/Egyptian fields at 0x20..0x24 in FAT order), so the
 * "Bpb" prefix marks raw disk data; 0x2c and 0x30 onward are computed.
 */
typedef struct FsDrvObject {
    u16  wBpb_bytes_per_sec;               /* 0x000 BPB BytesPerSector (sector size) */
    u16  _reserved0x2;                     /* 0x002 */
    u16  wBpb_bytes_per_sector;            /* 0x004 BPB bytes/sector (exFAT copy) */
    u16  _reserved0x6;                     /* 0x006 */
    u8   bBpb_sectors_per_cluster;         /* 0x008 BPB SectorsPerCluster */
    u8   _reserved0x9[3];                  /* 0x009 */
    u32  dwBpb_total_sectors;              /* 0x00c BPB TotalSectors (small) */
    u8   bBpb_media_descriptor;            /* 0x010 BPB MediaDescriptor (0xF8) */
    u8   _reserved0x11[3];                 /* 0x011 */
    u32  dwBpb_hidden_sectors;             /* 0x014 BPB HiddenSectors (partition offset) */
    u32  dwBpb_fat_size_sectors;           /* 0x018 BPB FatSize16/32 (sectors per FAT) */
    u32  dwRoot_dir_cluster;               /* 0x01c root directory first cluster (exFAT);
                                            *      read as *pClusterIndex by
                                            *      fs_init_directory_context for FAT32/exFAT */
    u16  wBpb_reserved_sector_count;       /* 0x020 BPB ReservedSectorCount (FAT16, 0 for FAT32) */
    u16  wBpb_num_fats;                    /* 0x022 BPB NumFATs (usually 2) */
    u16  wBpb_root_entry_count;            /* 0x024 BPB RootEntryCount (FAT12/16, 0 for FAT32) */
    u8   _reserved0x26[2];                 /* 0x026 */
    u16  wMountFlags;                      /* 0x028 bit0=used bit1=mounted bit2=exFAT bit5=formatted */
    u16  wF_0x2a;                          /* 0x02a mirror of wMountFlags */
    u32  dwVolume_flags_0x2c;              /* 0x02c volume flags (bF_0x2e = mount state byte) */
    s32  nFat_type;                        /* 0x030 3=exFAT, 2=FAT32, 1=FAT16, 0=FAT12 */
    u8   bBytesPerSectorShift;             /* 0x034 log2(sector size) */
    u8   bSectorsPerClusterShift;          /* 0x035 log2(cluster size); cluster shift = 0x34+0x35 */
    u16  wReserved_0x36;                   /* 0x036 both bytes written from BPB (unused) */
    u32  dwFat_start_sec;                  /* 0x038 first FAT table sector */
    u32  dwReserved_0x3c;                  /* 0x03c */
    u32  dwReserved_0x40;                  /* 0x040 */
    u32  dwRoot_dir_first_cluster;         /* 0x044 FAT32/exFAT root dir first cluster */
    u32  dwMax_cluster_num;                /* 0x048 max valid cluster number (geo bound) */
    u32  dwData_start_sector;              /* 0x04c first data sector */
    u32  dwFirst_data_sector;              /* 0x050 first data sector (inclusive) */
    u32  dwLast_alloc_cluster;             /* 0x054 last allocated cluster */
    u32  dwNext_free_cluster;              /* 0x058 next free cluster hint (-1 = unknown) */
    u32  dwFree_cluster_count;             /* 0x05c free cluster count ((-1) = unknown) */
    u32  dwData_sector_count;              /* 0x060 data sector count (-1 at init) */
    u32  dwHeap_base_sector;               /* 0x064 heap area base sector (-1 at init) */
    u32  dwHeap_sector_count;              /* 0x068 heap sector count */
    u32  dwMax_open_file_objects;          /* 0x06c pool slots: FatFileObject (0x520 each) */
    u32  dwMax_cluster_cache_nodes;        /* 0x070 pool slots: FatClusterCacheNode (0x48 each) */
    u32  dwMax_dir_objects;                /* 0x074 pool slots: dir objects (0x510 data + 0x28
                                            *      aux = 0x538 each) */
    void *pPool_base;                      /* 0x078 single alloc of
                                            *      maxFileObjects*0x520 +
                                            *      maxClusterCacheNodes*0x48 +
                                            *      maxDirObjects*0x538 (fs_init_volume_context) */
    void *pCluster_cache_node_array;       /* 0x080 FatFileHandle / cluster-cache array
                                            *      (0x48 stride, dwMax_cluster_cache_nodes);
                                            *      = pDirSearchObj_array + maxDirObjects*0x28 */
    void *pDir_object_array;               /* 0x088 FatDirObject array, stride 0x510, count
                                            *      dwMax_dir_objects (0x74). Allocator:
                                            *      fat_find_or_alloc_dir_object.
                                            *      Corrected 2026-09-13 round 10 (was
                                            *      pFile_object_array = pool_base, wrong) */
    void *pDirSearchObj_array;             /* 0x090 FatDirSearchObject array, stride 0x28,
                                            *      count dwMax_dir_objects (0x74). Used by
                                            *      fs_open_entry_core / fs_close_file_by_context.
                                            *      Corrected 2026-09-13 round 10 (was
                                            *      pDir_object_array = stride 0x510, wrong) */
    s32  nOpenFileRefCount;                /* 0x098 open FatFileObject count (0x520 pool);
                                            *      +1 in fs_open_file / fs_open_directory on
                                            *      fs_locate_object success. Renamed round 10
                                            *      (was nOpenDirRefCount - swapped) */
    s32  nOpenDirRefCount;                 /* 0x09c open dir-object count (0x510 pool);
                                            *      +1 in fs_open_entry_by_oem_path, -1 in
                                            *      fs_close_file_by_context. Renamed round 10
                                            *      (was nOpenFileRefCount - swapped) */
    s32  dwPinCount_0xa0;                  /* 0x0a0 format-transaction pin count: unmount
                                            *      refuses (0x31) while >=1 unless forced
                                            *      (fat_unmount_volume_by_letter);
                                            *      fat_close_file_context -1 per close;
                                            *      format core sets 1; cleared together
                                            *      with 0x9c by an 8-byte store in
                                            *      fat_clear_all_dir_object_pools.
                                            *      Round 12: NO increment site exists
                                            *      anywhere in the kip (exhaustive
                                            *      instruction search) - the count is
                                            *      maintained solely by the format
                                            *      flow, never by normal opens */
    u32  dwField_0xa4;                     /* 0x0a4 cleared in pair with 0xa0 by
                                            *      fs_format_volume_core (stp xzr,xzr);
                                            *      no other references - reserved */
    struct FatDirObject
                 *pRootObj_0xa8;           /* 0x0a8 root-directory open object owned by
                                            *      the format transaction (0x12):
                                            *      fat_mount_volume_core backs it up
                                            *      (head 0x50 + 0x4c0) before
                                            *      formatting and restores it after,
                                            *      with dwPinCount_0xa0=1. Cleared when
                                            *      the root is closed
                                            *      (fat_close_file_context) and by
                                            *      the pool/table clear paths. Round
                                            *      12: never assigned a fresh pointer
                                            *      anywhere - restored pointer is the
                                            *      same one read; owner-tag gate in
                                            *      fat_mount_volume_core requires it
                                            *      to equal the transaction context
                                            *      (fs_check_drive_state likewise
                                            *      compares against drvObj+0x100) */
    struct FatDirSearchObject
                 *pRootSearchObj_0xb0;     /* 0x0b0 FatDirSearchObject (0x28) paired with
                                            *      pRootObj_0xa8; saved/restored by
                                            *      fat_mount_volume_core the same way */
    u32  dwFatRegionCacheType;             /* 0x0b8 FAT 区域缓存类型: exfat_init_cluster_bitmap_cache
                                            *      与 fat_init_fat_table 均写 2 (2=exFAT/FAT32 缓存) */
    u32  dwVolume_flags_0xbc;              /* 0x0bc media-change / dirty flags */
    u32  dwFatRegionCacheFlags;            /* 0x0c0 低 3 位 = 缓存类型 (初始化置 2); 位图改写期间
                                            *      置 bit1, 结束后按 bit0 置 bit4
                                            *      (exfat_bitmap_operation 0x71000eff10) */
    u16  wFatCacheEntryCount_0xc4;         /* 0x0c4 缓存区 A 节点数 (旧记 max-cluster config) */
    u16  wFatCacheEntryCount_0xc6;         /* 0x0c6 缓存区 B 节点数 (旧记 cluster-size config);
                                            *      数据缓冲字节数 = (0xc4 + 0xc6) * 0x200 */
    /* --- FAT 区域 / exFAT 簇位图缓存描述符 (第十九轮:
     *     exfat_init_cluster_bitmap_cache @0x71000e3450, fat_init_fat_table @0x71000e3200,
     *     fat_init_fat_region_cache @0x71000e32c0 机器码验证) ---
     * 缓存节点 0x28 字节/个, 数据 0x200 字节/个; 节点数 = wFatCacheEntryCount_0xc4 + _0xc6。
     * FAT32 用两个槽 (主 FAT type=4 / 备 FAT type=8), exFAT 只用 slot1 (type=0x10)。 */
    union {
        u32  dwCode_page_state;            /* 0x0c8 低 32 位 = code-page ctx state (0=uninit, 1=init);
                                            *      fat_init_code_page_context 以 qLock_0x128 为对象槽 */
        void *pFatRegionCache_nodes;       /* 0x0c8 缓存节点数组基址 (fat_init_fat_region_cache arg2) */
    };
    void *pFatRegionCache_slot0;           /* 0x0d0 缓存描述符槽 0 (exFAT 路径置 0; FAT32 = 主 FAT) */
    void *pFatRegionCache_slot1;           /* 0x0d8 缓存描述符槽 1 = fat_init_fat_region_cache arg1
                                            *      (写入节点数组基址; exFAT 位图缓存用此槽) */
    void *pFatRegionCache_buffer;          /* 0x0e0 缓存数据缓冲基址 (节点 i 数据 = base + i*0x200) */
    u32  dwVolume_flags_config;            /* 0x0e8 volume flags config (fat_set_volume_flags) */
    u32  dwVolume_config;                  /* 0x0ec volume config (fat_set_volume_config) */
    u32  dwField_0xf0;                     /* 0x0f0 */
    u32  dwField_0xf4;                     /* 0x0f4 */
    void *pLock_0xf8;                      /* 0x0f8 FS context of the active transaction */
    u64  qTransaction_thread_context;      /* 0x100 thread context of the active transaction */
    u32  dwField_0x108;                    /* 0x108 init flag (set to 1) */
    u32  dwField_0x10c;                    /* 0x10c list head / self-referential */
    void *pField_0x110;                    /* 0x110 -> dwField_0x10c (list anchor) */
    u32  dwField_0x118;                    /* 0x118 */
    u32  dwFlags_0x11c;                    /* 0x11c bit4 = volume is exFAT, no OEM names */
    u8   bF_0x120;                         /* 0x120 bit0=mounted bit4=error */
    u8   bF_0x121;                         /* 0x121 bit1=unmount in progress */
    u16  wF_0x122;                         /* 0x122 */
    u8   bLetter;                          /* 0x124 drive letter 'A'..'E' */
    u8   _reserved0x125;                   /* 0x125 */
    u16  wF_0x126;                         /* 0x126 */
    void *qLock_0x128;                     /* 0x128 per-volume lock (also code-page ctx) */
    u32  dwF_0x130;                        /* 0x130 */
    u32  dwF_0x134;                        /* 0x134 */
    u32  dwF_0x138;                        /* 0x138 */
    u32  dwF_0x13c;                        /* 0x13c */
    u16  wVolume_state_0x140;              /* 0x140 bit1=has FSInfo bit2=FSInfo dirty */
    u16  wF_0x142;                         /* 0x142 */
    u32  dwF_0x144;                        /* 0x144 */
    u8   bSectorCache_enabled;             /* 0x148 bit0 = sector-cache enabled for this volume
                                            *      (read by fat_allocate_file_object) */
    u8   _reserved0x149;                   /* 0x149 */
    u16  wSectorCache_count;               /* 0x14a sector-cache entry count (copied into
                                            *      fctx.wCachedRangeCount) */
    u32  dwF_0x14c;                        /* 0x14c */
    u64  qSectorCache_base;                /* 0x150 sector-cache array base; per-file-object
                                            *      slot is base + index*dwF_0x158*4 */
    u32  dwSectorCache_stride;             /* 0x158 per-file-object sector-cache stride (u32) */
    u32  dwF_0x15c;                        /* 0x15c */
    u32  dwTransaction_id;                 /* 0x160 transaction op id (0x12 mount, 0x34 config) */
    u32  dwTransaction_result;             /* 0x164 result of the last transaction */
    u8   _reserved0x168[0x18];             /* 0x168 .. 0x17f */
    /* --- exFAT Allocation Bitmap 定位信息 (第十九轮: exfat_get_bitmap_info
     *     @0x71000f0a90 读写, exfat_check_cluster_allocated @0x71000ef470 /
     *     exfat_bitmap_operation @0x71000eff10 消费) --- */
    s32  dwBitmapFirstCluster;             /* 0x180 位图首簇; 0=未定位 (首次调用时到根目录搜
                                            *      attr 0x81 的位图条目并缓存) */
    u8   _padBitmap_0x184[4];              /* 0x184 (u64 对齐间隙) */
    u64  qBitmapSize;                      /* 0x188 位图字节数 (= 位图文件 DataLength);
                                            *      边界检查: (cluster-2)>>3 < qBitmapSize */
    u8   _reserved0x190[8];                /* 0x190 .. 0x197 */
    u16  wBitmapOpFlags;                   /* 0x198 位图改写状态: exfat_bitmap_operation 进入时置 bit1,
                                            *      返回前若 bit0 置位则再置 bit4 (脏/失败标记) */
    u8   _reserved0x19a[6];                /* 0x19a .. 0x19f */
    /* --- exFAT UpCase 表缓存（第十八轮: exfat_resolve_path 0x71000fb6a0 +
     *     exfat_verify_upcase_table 0x71000fbe70 机器码验证）--- */
    u32  dwUpcase_first_cluster;           /* 0x1a0 UpCase 表首簇 (0xffffffff=未定位) */
    u8   _padUpcase_0x1a4[4];              /* 0x1a4 (u64 对齐间隙) */
    u64  qUpcase_size;                     /* 0x1a8 UpCase 表 DataLength (字节) */
    u32  dwUpcase_checksum;                /* 0x1b0 表校验和 (字节级 rotr1+byte) */
    u8   _padUpcase_0x1b4[4];              /* 0x1b4 (指针对齐间隙) */
    void *pUpcase_cache;                   /* 0x1b8 已映射表的内存缓存基址 */
    u32  dwUpcase_cache_capacity;          /* 0x1c0 缓存容量 */
    u32  dwUpcase_flags;                   /* 0x1c4 bit30=表已读入并校验通过(驻留) */
    u64  qStorage_handle_0x1c8;            /* 0x1c8 storage device handle (arg to fs_storage_*) */
    u8   reserved_0x1d0[0x38];             /* 0x1d0 .. 0x207 (56 bytes, 内容未定性) */
    /* --- 簇运行粒度 / 对齐锚点 (第十九轮: exfat_scan_free_clusters 0x71000f0360 与
     *     exfat_update_free_cluster_count 0x71000f0be0 机器码验证; 二者均以
     *     "reserved_0x1d0 + 0x38 / +0x3c" 形式访问) --- */
    u32  dwClusterRunGranularity;          /* 0x208 连续簇粒度 (碎片统计/对齐单位; <2 时跳过统计) */
    u32  dwClusterAlignAnchor;             /* 0x20c 簇对齐锚点 (每次比较后按 +0x208 递增) */
    u8   _reserved0x210[8];                /* 0x210 .. 0x217 */
    u8   dirCache[0x6A0];                  /* 0x218 directory cache (1696 bytes).
                                            *      Handed out by fs_get_volume_dir_cache
                                            *      (returns drvObj+0x218), stored by
                                            *      fs_set_dir_cache, read by
                                            *      fs_read_current_dir_entry; used to short-
                                            *      circuit repeated lookups of the same dir. */
    u8   reserved_0x8b8[0x10];             /* 0x8b8 .. 0x8c7 */
} FsDrvObject;                             /* 0x8C8 */

/* Directory-search sub-context (FatFileContextPart, 0x70).
 * Renamed 2026-09-13 from evidence: fs_init_directory_context @0x71000e9320,
 * fat_map_cluster @0x71000e6d70, fat_lookup_cluster @0x71000e6bd0,
 * fat_allocate_cluster_chain @0x71000ead00, fat_allocate_clusters @0x71000e9410,
 * fat_find_free_clusters @0x71000e7a60, fat_write_fat_entry_dispatch @0x71000eb250,
 * fat_read_fat_entry_dispatch @0x71000e74f0, fat_cluster_to_sector @0x71000e6880,
 * FAT_ClearFatContext_0x28 @0x71000e9ae0.
 * Used by both the FAT cluster-allocation path and the directory-search path;
 * the first 0x28 bytes are a sector-cache descriptor, the rest is search state. */
typedef struct {
    u32  dwCluster;                        /* 0x00 cluster number for fat_map_cluster / search
                                            *      (read as int, compared ==1, overwritten by
                                            *      fs_init_directory_context when pClusterIndex==1) */
    u32  dwReserved_0x4;                   /* 0x04 */
    int *pClusterIndex;                    /* 0x08 in/out cluster-index pointer; *p==1 means
                                            *      "start a new cluster chain", *p==0 means
                                            *      "follow the existing chain" */
    u32  dwStartCluster;                   /* 0x10 range start, (-1) = invalid sentinel;
                                            *      set by fat_allocate_clusters to param_3 */
    u32  dwEndCluster;                     /* 0x14 range end, (-1) = invalid sentinel;
                                            *      set by fat_allocate_clusters to the last
                                            *      allocated cluster */
    u32  dwClusterRangeStart;              /* 0x18 range start, (-1) = invalid sentinel */
    u32  dwClusterRangeEnd;                /* 0x1c range end, (-1) = invalid sentinel */
    u32  dwLastAllocatedCluster;           /* 0x20 last allocated cluster of the last
                                            *      allocation, (-1) = invalid sentinel */
    u32  dwReserved_0x24;                  /* 0x24 */
    u8  *pSectorMap;                       /* 0x28 sector-map / scratch array (allocated via
                                            *      fs_allocate_memory, freed by
                                            *      FAT_ClearFatContext_0x28 with
                                            *      dwSectorMapEntryCount * 4 bytes) */
    u16  wCachedRangeCount;                /* 0x30 number of clusters in the cached FAT range */
    u16  wReserved_0x32;                   /* 0x32 */
    u32  dwCachedRangeEnd;                 /* 0x34 end of the cached FAT range (0xFFFFFFFF=invalid) */
    u32  dwSectorMapEntryCount;            /* 0x38 number of 4-byte entries in pSectorMap */
    u32  dwReserved_0x3c;                  /* 0x3c */
    void *pOutParam;                       /* 0x40 out-parameter written with {dwCluster,
                                            *      nextCluster} by fat_map_cluster /
                                            *      fat_lookup_cluster / fat_find_free_clusters */
    FsDrvObject *pDrvObj;                  /* 0x48 owning volume object */
    u8   bFlags;                           /* 0x50 bit1 = FAT cache dirty, bit2 = exFAT
                                            *      "contiguous/stream" hint (written as 3 and
                                            *      tested as (~bFlags & 3) == 0) */
    u8   reserved50[7];                    /* 0x51 */
    u8  *pFlagsPtr;                        /* 0x58 pointer to the byte that bFlags mirrors;
                                            *      defaults to &bFlags when p5 == NULL */
    u64  qwAllocatedBytes;                 /* 0x60 running total of bytes allocated by the
                                            *      cluster chain (accumulated by
                                            *      fat_allocate_cluster_chain) */
    u64  *pAllocatedBytesPtr;              /* 0x68 pointer to qwAllocatedBytes; defaults to
                                            *      &qwAllocatedBytes when p6 == NULL */
} FatFileContextPart;                      /* 0x70 */

/* Directory-search iteration context (FatFileContext, 0xB0).
 * Renamed 2026-09-13 from evidence: fat_prepare_directory_search @0x71000f8380,
 * fat_search_directory_entries @0x71000fb4c0, FAT_FindDirectoryEntry2 @0x71000f1530,
 * fat_read_next_directory_entry / FAT_SeekDirectoryEntry1.
 * Layout: a 0x10-byte header, then an embedded FatFileContextPart at 0x10. */
typedef struct {
    u32  dwCurrentEntryIndex;              /* 0x00 running entry index (reset to 0 on prepare,
                                            *      reported back as the found entry index) */
    u32  dwField_0x04;                     /* 0x04 */
    FsDrvObject *pDrvObj;                  /* 0x08 owning volume object, copied from
                                            *      ctx_part.pDrvObj by fat_prepare_directory_search */
    FatFileContextPart ctx_part;           /* 0x10 embedded search sub-context */
    u32  dwCurrentCluster;                 /* 0x80 current cluster of the search (-1 = none) */
    u32  dwCluster;                        /* 0x84 cluster holding the current entry (-1 = none) */
    u16  wEntryOffset;                     /* 0x88 entry offset within the sector (<<5) */
    u16  wSectorMask;                      /* 0x8a mask = ~(-1 << bSectorShift) */
    FatBaseEntry entry;                    /* 0x8c current raw 32-byte directory entry */
    u8   bSectorShift;                     /* 0xac = pDrvObj->bBytesPerSectorShift - 5
                                            *      (NOT a cluster shift) */
    u8   reserved[3];                      /* 0xad */
} FatFileContext;                          /* 0xB0 */

/* Cluster cache node (FatClusterCacheNode, 0x48). */
typedef struct FatClusterCacheNode {
    u16  state;                            /* 0x00 */
    u16  ref_count;                        /* 0x02 */
    u32  f_0x04;                           /* 0x04 */
    u8  *buffer;                           /* 0x08 */
    u8  *data_ptr;                         /* 0x10 */
    u8  *dirty_start;                      /* 0x18 */
    u8  *dirty_end;                        /* 0x20 */
    u32  cluster_count;                    /* 0x28 */
    u32  cluster_base;                     /* 0x2c */
    u64  file_tag;                         /* 0x30 */
    struct FatClusterCacheNode *prev;      /* 0x38 */
    struct FatClusterCacheNode *next;      /* 0x40 */
} FatClusterCacheNode;                     /* 0x48 */

/* Open file object (FatFileObject, 0x520). Stride in the volume pool; the pool
 * starts at drvObj->pPool_base (drvObj+0x78) with dwMax_open_file_objects
 * (drvObj+0x6c) slots of 0x520 bytes.
 * Corrected 2026-09-13 round 10: pool base is +0x78 (was misdocumented as
 * +0x88; +0x88 is the FatDirObject pool, see below).
 * Evidence: fs_init_volume_context @0x71000d7420 (pool split),
 * fat_allocate_file_object @0x71000ff250 (0x520 stride over +0x78),
 * fat_release_file_object @0x71000ff480, fat_find_file_context_by_id @0x71000ff540,
 * fs_file_open_core @0x71001032d0, fs_file_seek @0x7100103e20,
 * fs_file_read_core @0x7100101020.
 *
 * Lifetime: dwStatus == 0x10000003 ("in use"); wRefCount incremented on open,
 * decremented on close and the object freed (pool slot released) at zero. */
typedef struct {
    u32           dwStatus;                /* 0x000 0x10000003 = in use */
    u32           dwReserved_0x4;          /* 0x004 */
    FatFileContextPart fctx;               /* 0x008 cluster/sector search sub-context;
                                            *      passed to fat_map_cluster and
                                            *      fs_init_directory_context as
                                            *      (FatFileContextPart *)&obj->fctx */
    FsObject      entry;                   /* 0x078 parsed directory entry for this file
                                            *      (its pDrvObj / dirCluster / entryOffset
                                            *      are the identity used to dedupe opens) */
    u16           aLongPath_w[260];        /* 0x2f0 UTF-16 long path of the file (260 chars);
                                            *      copied out by fs_file_open_core */
    u16           wFlags_0x4f8;            /* 0x4f8 state bits tested as (wFlags & 3):
                                            *      bit0/bit1 mark the open object's I/O state;
                                            *      bit1 also set while a rename/attr write is
                                            *      pending (checked in fat_close_file_context) */
    u16           wReserved_0x4fa;         /* 0x4fa */
    u32           dwF_0x4fc;               /* 0x4fc open-handle count / "busy" flag
                                            *      (0 => no open handle) */
    u64           qwOwnerTag_0x500;        /* 0x500 owning handle / transaction-thread-context
                                            *      tag. Two u32 dwords (0x500/0x504) in the raw
                                            *      code, but always copied and compared as one
                                            *      qword: set to the transaction thread context
                                            *      on open (fs_locate_object path), compared in
                                            *      fat_close_file_context, cleared on close. */
    u32           dwF_0x508;               /* 0x508 lower half of a pointer written 8 bytes
                                            *      at once by some writers; zeroed on alloc */
    u32           dwF_0x50c;               /* 0x50c reset on alloc */
    u16           wRefCount;               /* 0x510 open reference count */
    u8            reserved_0x512[6];       /* 0x512 */
    u64           qwF_0x518;               /* 0x518 duplicate-open back-link (round 11):
                                            *      written by fs_locate_object = output of
                                            *      fs_validate_directory_entry, i.e. pointer
                                            *      to an already-open instance of the SAME
                                            *      entry (file or dir object); cleared by
                                            *      fat_close_file_context which scans the
                                            *      file pool for +0x518 == closing object */
} FatFileObject;                           /* 0x520 */

/* Open directory object (FatDirObject, 0x510). Directory counterpart of
 * FatFileObject. Pool = drvObj->pDir_object_array (drvObj+0x88), stride 0x510,
 * count dwMax_dir_objects (drvObj+0x74). Each directory also owns a paired
 * 0x28 FatDirSearchObject in the pDirSearchObj_array (+0x90); the two regions
 * are carved from the same single allocation as files*0x520 + handles*0x48 +
 * dirs*(0x510+0x28) = dirs*0x538 (fs_init_volume_context).
 *
 * Derived 2026-09-13 round 10 from evidence:
 *   fs_init_volume_context     @0x71000d7420  (pool layout, 0x538 = 0x510+0x28)
 *   fat_find_or_alloc_dir_object @0x7100109e40 (0x510 stride, dwStatus=0x40000003,
 *                              refcount at 0x004 low u16, entry copy 0x480,
 *                              fs_init_directory_context mode=4)
 *   fs_open_entry_core         @0x7100107b40  (writes +0x508, scans +0x90 @0x28)
 *   fat_get_volume_handle_stats @0x71000da130 (pairs +0x88/0x510 with +0x9c)
 *   fs_close_file_by_context   @0x7100107cb0  (pool range checks on +0x90)
 *
 * dwStatus markers: file = 0x10000003, dir = 0x40000003 (bit2 = dir),
 * FatDirSearchObject = 0x80000001 (bit3 = search object). */
typedef struct FatDirObject {
    u32           dwStatus;                /* 0x000 0x40000003 = in use (dir) */
    u32           dwRefCount_0x4;          /* 0x004 low u16 = open refcount (inc on
                                            *      dedup hit, dec on close; slot freed
                                            *      when it reaches 0) */
    FatFileContextPart fctx;               /* 0x008 initialized with mode=4 (directory);
                                            *      file objects use mode=2 */
    FsObject      entry;                   /* 0x078 parsed directory entry of the dir
                                            *      (identity key, copied with 0x480) */
    u16           aLongPath_w[260];        /* 0x2f0 assumed same role as FatFileObject
                                            *      (not directly evidenced for dirs) */
    u16           wFlags_0x4f8;            /* 0x4f8 zeroed on alloc */
    u16           wReserved_0x4fa;         /* 0x4fa zeroed on alloc */
    u32           dwF_0x4fc;               /* 0x4fc zeroed on alloc */
    u64           qwOwnerTag_0x500;        /* 0x500 zeroed on alloc */
    u64           pvValidateCtx_0x508;     /* 0x508 duplicate-open back-link (dir-pool twin
                                            *      of FatFileObject+0x518, round 11):
                                            *      fs_open_entry_core stores the output of
                                            *      fs_validate_directory_entry (already-open
                                            *      instance of the same entry); zeroed on
                                            *      alloc; fat_close_file_context scans the
                                            *      dir pool for +0x508 == closing object */
} FatDirObject;                            /* 0x510 */

/* Open-file handle (FatFileHandle, 0x48). One per open file, allocated from
 * drvObj->pCluster_cache_node_array (drvObj+0x80) with stride 0x48 and count
 * dwMax_cluster_cache_nodes (drvObj+0x70). NOTE: the same 0x48-stride pool is
 * also used as the FAT cluster-cache array, so the two share a slot size.
 *
 * Derived 2026-09-13 from evidence:
 *   fs_locate_object       @0x7100100280  (fills pFileObj, calls fat_setup_file_handle)
 *   fat_setup_file_handle  @0x71000ffbb0  (*p=0x20000001, p[1]=flags, qwFilePosition=0,
 *                                          wSectorOffset=0, dwCurrentCluster=-1, ...)
 *   fs_file_read_core      @0x7100101020  (qwFilePosition/currentCluster/clusterIndex/
 *                                          wSectorOffset/wRefCount/dwLastError)
 *   fs_file_seek           @0x7100103e20  (handle range-checks per volume pool)
 *   fs_file_write_core     @0x7100100a20
 *   fs_file_set_size_core  @0x7100103ca0
 */
typedef struct {
    u32           dwStatus;                /* 0x00 0x20000001 = in use (set by
                                            *      fat_setup_file_handle); bit0 also
                                            *      gates I/O in fs_file_seek */
    u32           dwOpenFlags;             /* 0x04 open-mode bits: bit0 read, bit1 write,
                                            *      bit2 append, bit3 "async/no-buffer",
                                            *      bit5 index-map, bit6 "needs flush" */
    struct FatFileObject *pFileObj;        /* 0x08 backing open file object */
    void         *pCtxOut;                 /* 0x10 scratch out-param used by
                                            *      fat_set_context_ptr / fat_allocate_file_space */
    u64           qwInvalidMarker;         /* 0x18 reset to 0 by fat_setup_file_handle;
                                            *      compared/cleared on close (0 => invalid) */
    u32           dwLastError;             /* 0x20 last error stored on this handle (mirrors
                                            *      the thread-context result at +0x1690) */
    u32           dwReserved_0x24;         /* 0x24 high dword paired with dwLastError as a
                                            *      qword marker */
    u64           qwFilePosition;          /* 0x28 current byte offset in the file */
    u32           dwCurrentCluster;        /* 0x30 current cluster (-1 = need remap) */
    u32           dwClusterIndex;          /* 0x34 cluster index within the chain */
    u16           wSectorOffset;           /* 0x38 offset within the current sector */
    u16           wReserved_0x3a;          /* 0x3a */
    u32           dwReserved_0x3c;         /* 0x3c */
    u16           wRefCount;               /* 0x40 open reference count */
    u8            aReserved_0x42[6];       /* 0x42 */
} FatFileHandle;                           /* 0x48 */

/* ------------------------------------------------------------------------- */
/* FS core directory-info structures                                          */
/* ------------------------------------------------------------------------- */

/*
 * Internal directory info (FsDirInfoInternal, 0xAAA). This is what
 * IDirectoryContext.dirInfo points at and what IDirectory::Read snapshots.
 *
 * WARNING (known bug H1): lname is char[513], sized for CP932 (<=2 bytes per
 * char). The sys-patch UTF-8 conversion has no output bound, so long CJK names
 * (>=171 3-byte chars) overflow into unicode_name / adjacent fields.
 */
typedef struct {
    u8   reserved0[16];                    /* 0x000 */
    FsDrvObject *drvObj;                   /* 0x010 owning volume object (field1_0x10);
                                            *      verified in fs_iterate_directory_entries,
                                            *      fat_init_fs_object_from_entry */
    u32  cluster;                          /* 0x018 start cluster of the directory */
    u32  start_index;                      /* 0x01c search start index (entry index) */
    u32  field_0x20;                       /* 0x020 written by FAT_FindDirectoryEntry2 */
    u32  cluster1;                         /* 0x024 cluster copy set at open */
    u8   encode_flag;                      /* 0x028 bit1 = UNICODE (else OEM) */
    u8   reserved1[3];                     /* 0x029 */
    u32  ch_len;                           /* 0x02c char count << 16 */
    u16  entry_num;                        /* 0x030 exFAT SecondaryCount */
    u16  name_hash;                        /* 0x032 exFAT NameHash */
    u8   attr1;                            /* 0x034 exFAT stream/attr byte */
    u8   reserved3[3];                     /* 0x035 */
    u64  field_0x38;                       /* 0x038 exFAT stream DataLength / search scratch */
    u16  path_w[260];                      /* 0x040 directory path (UTF-16) */
    u8   name_len;                         /* 0x248 name length in chars */
    u8   field_0x249;                      /* 0x249 exFAT stream flags (default 1) */
    u8   attr_filter;                      /* 0x24a search attr filter */
    u8   oem_name[520];                    /* 0x24b OEM/UTF-8 search pattern */
    u8   _padA[1];                         /* 0x453 */
    u16  f_0x454;                          /* 0x454 create TZ (exFAT) / 0xffff */
    u16  modify_time;                      /* 0x456 DOS modification time */
    u16  modify_date;                      /* 0x458 DOS modification date */
    u8   f_0x45a;                          /* 0x45a exFAT LastModifiedUtcOffset */
    u8   _padB[1];                         /* 0x45b */
    u16  f_0x45c;                          /* 0x45c exFAT LastAccessed time / 0xffff */
    u16  access_date;                      /* 0x45e DOS last-access date */
    u8   f_0x460;                          /* 0x460 exFAT LastAccessedUtcOffset */
    u8   _padC[1];                         /* 0x461 */
    u16  sub_sec;                          /* 0x462 exFAT Create10msIncrement / FAT sub_sec */
    u16  create_time;                      /* 0x464 DOS creation time */
    u16  create_date;                      /* 0x466 DOS creation date */
    u8   f_0x468;                          /* 0x468 exFAT LastModified10msIncrement */
    u8   reserved2[7];                     /* 0x469 */
    u64  file_size;                        /* 0x470 exFAT DataLength / FAT size */
    u16  attr;                             /* 0x478 0x10 = directory (0x40 default) */
    u8   sname[13];                        /* 0x47a 8.3 name (OEM) */
    u8   lname[513];                       /* 0x487 UTF-8 long name (overflow risk, see above) */
    u8   unicode_name[520];                /* 0x688 UTF-16 long name (aLname_w mirror) */
    u16  sname_w[13];                      /* 0x890 UTF-16 8.3 name */
    u16  lname_w[256];                     /* 0x8aa UTF-16 long name */
} FsDirInfoInternal;                       /* 0xAAA */

/* Snapshot returned by IDirectory_ReadDirEntry (FsDirInfoObj, 0x690):
 * state byte + copy of FsDirInfoInternal[0..0x688]. */
typedef struct {
    u8  state;                             /* 0x00 */
    u8  reserved[7];                       /* 0x01 */
    u8  dirInfo[0x688];                    /* 0x08 */
} FsDirInfoObj;                            /* 0x690 */

/* nn::fs IDirectory client iterator (FsDirIterObj, 0x7D0), allocated by
 * fs_idirectory_opendir via fs_log_assert_check(2000).  The first 0xBC2 bytes
 * mirror IDirectoryContext (ctx/filter_flags/name/dirInfo); the active dirInfo
 * window is only the first 0x688 bytes (FsDirInfoObj snapshot size), the
 * control fields start at 0x7a0.  Class vtable group base = 0x7100247518
 * (dtor/trace/Read/GetEntryCount). */
typedef struct {
    void *vptr;                            /* 0x000 */
    u32  dwOpenFlags;                      /* 0x008 bit0=dirs, bit1=files (filter) */
    char aName[0x104];                     /* 0x00c search pattern (path + "\\*") */
    u64  f_0x110;
    u8   dirInfo[0x688];                   /* 0x118 FsDirInfoInternal[0..0x688] working set
                                            *     (IDirectory_ReadDirEntry memcpy source) */
    u8   bReady;                           /* 0x7a0 1 = pDirSearchObj valid, first FS_fsnext done */
    u8   f_0x7a1[7];
    struct FatDirSearchObject *pDirSearchObj;
                                           /* 0x7a8 opendir 命令 (cmd 槽 0x71002474f0) 返回的
                                            *     0x28 目录搜索对象; 析构时经关闭命令槽
                                            *     (0x7100247548) 释放。旧记 hDirHandle 有误 */
    void *pLogCtx;                         /* 0x7b0 = IDirectoryObj.pLogCtx */
    void *pFatWrapper;                     /* 0x7b8 = IDirectoryObj.pFatWrapper */
    u32  f_0x7c0;                          /* 0x7c0 string slot (fs_string_cleanup(this+0x7c0)) */
    u32  f_0x7c4;
    void *ppOwnerFatCtx;                   /* 0x7c8 = &IDirectoryObj.pFatCtx (传给
                                            *     fs_dispatch_method_cmd 的上下文列表) */
} FsDirIterObj;                            /* 0x7D0 */

_Static_assert(sizeof(FsDirIterObj) == 0x7D0, "FsDirIterObj size mismatch");

/* FAT media-driver operation table (sub-table G of the IDirectory vtable group,
 * base 0x71002475d8, 16 slots).  Every entry is a thin wrapper with the uniform
 * prototype  undefined8 fn(u32 *pDevDesc, u32 *pOut)  — pDevDesc[0] = slot id,
 * pDevDesc[2] = device object ptr (checked against magic 0xAABBCDDD; +0x04 =
 * state, +0x1c = last error).  Slot order:
 *   +0x00 register_device   +0x08 unregister_device   +0x10 init_mount
 *   +0x18 cleanup_unmount   +0x20 init_recovery        +0x28 dispatch_io
 *   +0x30 set_flag_bit2     +0x38 compact_dir_entries  +0x40 bitmap_find_free
 *   +0x48 bitmap_mark_used  +0x50 bitmap_find_used     +0x58 set_flag_bit1
 *   +0x60 clear_flag_bit1   +0x68 manage_recovery_slot +0x70 alloc_cluster_range
 *   +0x78 recovery_dispatch
 * Wrappers: fs_fatdrv_* @0x7100110210..0x7100110ee0. */

/* nn::fs IDirectory context (IDirectoryContext, 0xBC2).
 * 0x00 holds the FS context/transaction pointer captured at open time;
 * the search state (FsDirInfoInternal) starts at 0x118. */
typedef struct {
    void *pFSCtx;                          /* 0x000 FS context / transaction ctx (arg to
                                            *      fs_get_fs_context, stored per open) */
    u32  filter_flags;                     /* 0x008 bit0=dirs, bit1=files */
    char name[257];                        /* 0x00c search name */
    u8   reserved_0x10d[11];               /* 0x10d */
    FsDirInfoInternal dirInfo;             /* 0x118 search state (directory iterator) */
} IDirectoryContext;                       /* 0xBC2 */

/* fs IDirectory service object (IDirectoryObj, 0x78).
 * The `this` of every fs_idirectory_* vtable method (dispatch table group at
 * 0x7100247390, vptr = 0x7100247380).  All path-taking methods build the OEM
 * path as "%c:\%s" from the drive letter at *(char**)(this+0x10). */
typedef struct {
    void *vptr;                            /* 0x000 &IDirectory service vtable group */
    void *pStrObj;                         /* 0x008 inline string slot (fs_string_cleanup(this+8)) */
    void **ppDriveLetter;                  /* 0x010 ptr to char* drive letter (deref'd twice) */
    void *pLogCtx;                         /* 0x018 error/log context (IDirectory_GetError arg1) */
    u32  f_0x20;                           /* 0x020 sub-object base (fopen stores this+0x20
                                            *      into file obj +0x28) */
    u32  f_0x24;
    u32  f_0x28;
    u32  f_0x2c;
    void *pFatWrapper;                     /* 0x030 FAT object wrapper (recoverable-error
                                            *      path: seek-reset via its vtable+0x38) */
    void *pFatCtx;                         /* 0x038 FAT context (FUN_71000ce6a4 arg1) */
    u64  f_0x40;
    u64  f_0x48;
    u64  f_0x50;
    u64  f_0x58;
    u32  dwModeCopy;                       /* 0x060 copied into FsDirFileObj.dwModeCopy_0x24 */
    u32  f_0x64;                           /* 0x064 ctor zeroes u16 here; +0x65 -> file obj +0x38 */
    u64  f_0x68;
    u64  qOwner_0x70;                      /* 0x070 copied into FsDirFileObj.qTxnObj_0x50 */
} IDirectoryObj;                           /* 0x078 */

/* Per-open file object (FsDirFileObj, 0x58), allocated by fs_idirectory_fopen
 * (fs_log_assert_check(0x58)); vtable = file-obj group at 0x7100247478. */
typedef struct {
    void *vptr;                            /* 0x000 */
    u32  dwOpenFlags;                      /* 0x008 bit0=read, bit1=write, bit2=allow-extend
                                            *      (write: bit2=0 时 offset+size>filesize→0x307202;
                                            *       truncate: bit2=0 才 fsetclstlink 重置簇链) */
    u32  f_0x0c;                           /* 0x0c fopen 构造不写；全 7 方法均未访问，确认保留 */
    void *hFatHandle;                      /* 0x010 FAT handle (FS_fread/fsetpos/fflush/...) */
    void *pLogCtx;                         /* 0x018 */
    u32  f_0x20;                           /* 0x020 string slot (fs_string_cleanup(this+0x20)) */
    u32  dwModeCopy_0x24;                  /* 0x024 from IDirectoryObj.dwModeCopy */
    void *pDirSubObj;                      /* 0x028 IDirectoryObj+0x20 (ioctl target vtable+0x38) */
    void *pFatWrapper;                     /* 0x030 */
    u8   bFlag_0x38;                       /* 0x038 = IDirectoryObj+0x65 (fopen 拷入),
                                            *      enables TLS dir-read result tracking */
    u8   f_0x39;                           /* 0x39-0x3f fopen 构造不写；全 7 方法均未访问，确认保留 */
    u8   f_0x3a;
    u8   f_0x3b;
    u32  f_0x3c;
    void *pFatCtx;                         /* 0x040 = &IDirectoryObj.pFatCtx (存指针的地址,
                                            *      供 fs_dispatch_method_cmd 上下文列表) */
    u8   bDriveLetter_0x48;                /* 0x048 drive letter char (dtor/close 派发用) */
    u32  f_0x49;                           /* 0x49-0x4f fopen 构造不写；全 7 方法均未访问，确认保留 */
    u8   f_0x4d;
    u8   f_0x4e;
    u8   f_0x4f;
    u64  qTxnObj_0x50;                     /* 0x050 transaction object; its +0x40 is a
                                            *      write-refcount guarded by exclusive monitors */
} FsDirFileObj;                            /* 0x058 */

_Static_assert(sizeof(IDirectoryObj) == 0x78, "IDirectoryObj size mismatch");
_Static_assert(sizeof(FsDirFileObj) == 0x58, "FsDirFileObj size mismatch");

/* ------------------------------------------------------------------------- */
/* PFCODE code-page callback table (PFCODE_CODE_PAGE_CONTEXT)                 */
/* ------------------------------------------------------------------------- */

/* The runtime code-page conversion object filled in by PFCODE_CP932_Init
 * (0x71000d5150).  Base = 0x7100fcfc38 (in .bss, i.e. zero at rest); the six
 * function-pointer slots live at +0x18..+0x40.  The named Ghidra globals
 * pOEM2Unicode/pUnicode2OEM/... at 0x7100fcfc50..0x7100fcfc78 are the same
 * slots (base+0x18 == 0x7100fcfc50).
 *
 * Registration (PFCODE_CP932_Init @0x71000d5220):
 *      stp x19, x8, [x21, #0x10]   // +0x10 = caller-supplied callback, +0x18 = pOEM2Unicode
 *      stp x8,  x9, [x21, #0x20]   // +0x20 = pUnicode2OEM,  +0x28 = pOEMCharWidth
 *      stp x8,  x9, [x21, #0x30]   // +0x30 = pisOEMMBchar,   +0x38 = pUnicodeCharWidth
 *      str x8,      [x21, #0x40]   // +0x40 = pisUnicodeMBchar
 * where x8/x9 come from GOT slots 0x710024eb58/60/68/70/78/80.
 *
 * NOTE: fs_codepage_patch() patches pOEM2Unicode and pUnicode2OEM (slots 0/1).
 * The struct is declared with only the leading fields that are observed; the
 * trailing region (0x48 .. 0x88e0) is memset(0) by the init function. */
typedef struct {
    u32  reserved_00[4];                   /* 0x00..0x0f  (memset by init) */
    void *cbCallback;                      /* 0x10 caller callback (foreign GOT ptr) */
    void *pOEM2Unicode;                    /* 0x18 PFCODE_CP932_OEM2Unicode     @0x71000feac0 */
    void *pUnicode2OEM;                    /* 0x20 PFCODE_CP932_Unicode2OEM     @0x71000fec30 */
    void *pOEMCharWidth;                   /* 0x28 PFCODE_CP932_OEMCharWidth    @0x71000fee00 */
    void *pisOEMMBchar;                    /* 0x30 PFCODE_CP932_isOEMMBchar     @0x71000fee40 */
    void *pUnicodeCharWidth;               /* 0x38 PFCODE_CP932_UnicodeCharWidth @0x71000fee90 */
    void *pisUnicodeMBchar;                /* 0x40 PFCODE_CP932_isUnicodeMBchar @0x71000feea0 */
    u8   reserved_48[0x88e0 - 0x48];       /* 0x48..0x88df (memset by init) */
} PFCODE_CODE_PAGE_CONTEXT;                /* 0x88E0 */

/* ------------------------------------------------------------------------- */
/* Error codes (Result)                                                       */
/* ------------------------------------------------------------------------- */

/* result = (module & 0x1FF) | ((description & 0x1FFF) << 9) */
#define FS_RESULT(module, desc)  (((u32)(module) & 0x1FFu) | (((u32)(desc) & 0x1FFFu) << 9))
#define FS_RESULT_MODULE(r)      ((u32)(r) & 0x1FFu)
#define FS_RESULT_DESC(r)        (((u32)(r) >> 9) & 0x1FFFu)

#define FS_MODULE_FS              2u

#define FS_RESULT_PATH_NOT_FOUND        0x202u    /* desc 1    */
#define FS_RESULT_PATH_ALREADY_EXISTS   0x402u    /* desc 2    */
#define FS_RESULT_TARGET_LOCKED         0xE02u    /* desc 7    */
#define FS_RESULT_NOT_IMPLEMENTED       0x177202u /* desc 3001 */
#define FS_RESULT_ALREADY_EXISTS        0x177602u /* desc 3003 */
#define FS_RESULT_OUT_OF_RANGE          0x177A02u /* desc 3005 */

#define FS_ALLOC_FAILED_FAT_A           0x190202u /* desc 3201 */
#define FS_ALLOC_FAILED_FAT_B           0x190402u
#define FS_ALLOC_FAILED_FAT_C           0x190602u
#define FS_ALLOC_FAILED_FAT_D           0x190802u
#define FS_ALLOC_FAILED_FAT_E           0x190A02u
#define FS_ALLOC_FAILED_FAT_F           0x190C02u
#define FS_ALLOC_FAILED_FAT_G           0x190E02u
#define FS_ALLOC_FAILED_FAT_H           0x191002u /* desc 3208 */

#pragma pack(pop)

/* ------------------------------------------------------------------------- */
/* Offset guards                                                              */
/* ------------------------------------------------------------------------- */
#if defined(__cplusplus) ? 1 : 1
#define FS_ASSERT_OFF(type, field, off)                                        \
    _Static_assert(offsetof(type, field) == (off),                             \
                   #type "." #field " must be at " #off)
#else
#define FS_ASSERT_OFF(type, field, off)
#endif

FS_ASSERT_OFF(FsDrvObject, wBpb_bytes_per_sector,       0x004);
FS_ASSERT_OFF(FsDrvObject, bBpb_sectors_per_cluster,    0x008);
FS_ASSERT_OFF(FsDrvObject, dwBpb_total_sectors,         0x00c);
FS_ASSERT_OFF(FsDrvObject, dwBpb_hidden_sectors,        0x014);
FS_ASSERT_OFF(FsDrvObject, dwBpb_fat_size_sectors,      0x018);
FS_ASSERT_OFF(FsDrvObject, wBpb_reserved_sector_count,  0x020);
FS_ASSERT_OFF(FsDrvObject, wBpb_num_fats,               0x022);
FS_ASSERT_OFF(FsDrvObject, wMountFlags,                 0x028);
FS_ASSERT_OFF(FsDrvObject, nFat_type,                   0x030);
FS_ASSERT_OFF(FsDrvObject, bBytesPerSectorShift,        0x034);
FS_ASSERT_OFF(FsDrvObject, bSectorsPerClusterShift,     0x035);
FS_ASSERT_OFF(FsDrvObject, dwFat_start_sec,             0x038);
FS_ASSERT_OFF(FsDrvObject, dwRoot_dir_cluster,          0x01c);
FS_ASSERT_OFF(FsDrvObject, dwRoot_dir_first_cluster,    0x044);
FS_ASSERT_OFF(FsDrvObject, dwMax_cluster_num,           0x048);
FS_ASSERT_OFF(FsDrvObject, dwFirst_data_sector,         0x050);
FS_ASSERT_OFF(FsDrvObject, dwNext_free_cluster,         0x058);
FS_ASSERT_OFF(FsDrvObject, dwFree_cluster_count,        0x05c);
FS_ASSERT_OFF(FsDrvObject, dwData_sector_count,         0x060);
FS_ASSERT_OFF(FsDrvObject, dwMax_open_file_objects,     0x06c);
FS_ASSERT_OFF(FsDrvObject, dwMax_cluster_cache_nodes,   0x070);
FS_ASSERT_OFF(FsDrvObject, dwMax_dir_objects,           0x074);
FS_ASSERT_OFF(FsDrvObject, pPool_base,                  0x078);
FS_ASSERT_OFF(FsDrvObject, pCluster_cache_node_array,   0x080);
FS_ASSERT_OFF(FsDrvObject, pDir_object_array,           0x088);
FS_ASSERT_OFF(FsDrvObject, pDirSearchObj_array,         0x090);
FS_ASSERT_OFF(FsDrvObject, nOpenFileRefCount,           0x098);
FS_ASSERT_OFF(FsDrvObject, nOpenDirRefCount,            0x09c);
FS_ASSERT_OFF(FsDrvObject, dwCode_page_state,           0x0c8);
FS_ASSERT_OFF(FsDrvObject, pFatRegionCache_slot0,       0x0d0);
FS_ASSERT_OFF(FsDrvObject, pFatRegionCache_slot1,       0x0d8);
FS_ASSERT_OFF(FsDrvObject, pFatRegionCache_buffer,      0x0e0);
FS_ASSERT_OFF(FsDrvObject, dwBitmapFirstCluster,        0x180);
FS_ASSERT_OFF(FsDrvObject, qBitmapSize,                 0x188);
FS_ASSERT_OFF(FsDrvObject, wBitmapOpFlags,              0x198);
FS_ASSERT_OFF(FsDrvObject, dwClusterRunGranularity,     0x208);
FS_ASSERT_OFF(FsDrvObject, dwClusterAlignAnchor,        0x20c);
FS_ASSERT_OFF(FsDrvObject, dwVolume_flags_config,       0x0e8);
FS_ASSERT_OFF(FsDrvObject, dwVolume_config,             0x0ec);
FS_ASSERT_OFF(FsDrvObject, pLock_0xf8,                  0x0f8);
FS_ASSERT_OFF(FsDrvObject, qTransaction_thread_context, 0x100);
FS_ASSERT_OFF(FsDrvObject, dwFlags_0x11c,               0x11c);
FS_ASSERT_OFF(FsDrvObject, bF_0x120,                    0x120);
FS_ASSERT_OFF(FsDrvObject, bLetter,                     0x124);
FS_ASSERT_OFF(FsDrvObject, qLock_0x128,                 0x128);
FS_ASSERT_OFF(FsDrvObject, wVolume_state_0x140,         0x140);
FS_ASSERT_OFF(FsDrvObject, dwTransaction_id,            0x160);
FS_ASSERT_OFF(FsDrvObject, dwTransaction_result,        0x164);
FS_ASSERT_OFF(FsDrvObject, dwUpcase_first_cluster,      0x1a0);
FS_ASSERT_OFF(FsDrvObject, qUpcase_size,                0x1a8);
FS_ASSERT_OFF(FsDrvObject, dwUpcase_checksum,           0x1b0);
FS_ASSERT_OFF(FsDrvObject, pUpcase_cache,               0x1b8);
FS_ASSERT_OFF(FsDrvObject, dwUpcase_cache_capacity,     0x1c0);
FS_ASSERT_OFF(FsDrvObject, dwUpcase_flags,              0x1c4);
FS_ASSERT_OFF(FsDrvObject, qStorage_handle_0x1c8,       0x1c8);
FS_ASSERT_OFF(FsDrvObject, dirCache,                    0x218);

/* FatFileContextPart (0x70) — cluster/sector search sub-context */
FS_ASSERT_OFF(FatFileContextPart, dwCluster,               0x00);
FS_ASSERT_OFF(FatFileContextPart, pClusterIndex,           0x08);
FS_ASSERT_OFF(FatFileContextPart, dwStartCluster,          0x10);
FS_ASSERT_OFF(FatFileContextPart, dwEndCluster,            0x14);
FS_ASSERT_OFF(FatFileContextPart, dwClusterRangeStart,     0x18);
FS_ASSERT_OFF(FatFileContextPart, dwClusterRangeEnd,       0x1c);
FS_ASSERT_OFF(FatFileContextPart, dwLastAllocatedCluster,  0x20);
FS_ASSERT_OFF(FatFileContextPart, pSectorMap,              0x28);
FS_ASSERT_OFF(FatFileContextPart, wCachedRangeCount,       0x30);
FS_ASSERT_OFF(FatFileContextPart, dwCachedRangeEnd,        0x34);
FS_ASSERT_OFF(FatFileContextPart, dwSectorMapEntryCount,   0x38);
FS_ASSERT_OFF(FatFileContextPart, pOutParam,               0x40);
FS_ASSERT_OFF(FatFileContextPart, pDrvObj,                 0x48);
FS_ASSERT_OFF(FatFileContextPart, bFlags,                  0x50);
FS_ASSERT_OFF(FatFileContextPart, pFlagsPtr,               0x58);
FS_ASSERT_OFF(FatFileContextPart, qwAllocatedBytes,        0x60);
FS_ASSERT_OFF(FatFileContextPart, pAllocatedBytesPtr,      0x68);

/* FatFileContext (0xB0) — directory search iteration */
FS_ASSERT_OFF(FatFileContext, dwCurrentEntryIndex,         0x00);
FS_ASSERT_OFF(FatFileContext, pDrvObj,                     0x08);
FS_ASSERT_OFF(FatFileContext, ctx_part,                    0x10);
FS_ASSERT_OFF(FatFileContext, dwCurrentCluster,            0x80);
FS_ASSERT_OFF(FatFileContext, dwCluster,                   0x84);
FS_ASSERT_OFF(FatFileContext, wEntryOffset,                0x88);
FS_ASSERT_OFF(FatFileContext, wSectorMask,                 0x8a);
FS_ASSERT_OFF(FatFileContext, entry,                       0x8c);
FS_ASSERT_OFF(FatFileContext, bSectorShift,                0xac);

/* FatFileObject (0x520) — open file object */
FS_ASSERT_OFF(FatFileObject, dwStatus,                     0x000);
FS_ASSERT_OFF(FatFileObject, fctx,                         0x008);
FS_ASSERT_OFF(FatFileObject, entry,                        0x078);
FS_ASSERT_OFF(FatFileObject, aLongPath_w,                  0x2f0);
FS_ASSERT_OFF(FatFileObject, wFlags_0x4f8,                 0x4f8);
FS_ASSERT_OFF(FatFileObject, qwOwnerTag_0x500,             0x500);
FS_ASSERT_OFF(FatFileObject, wRefCount,                    0x510);
FS_ASSERT_OFF(FatFileObject, qwF_0x518,                    0x518);

/* FatDirObject (0x510) — open directory object (round 10) */
FS_ASSERT_OFF(FatDirObject, dwStatus,                      0x000);
FS_ASSERT_OFF(FatDirObject, dwRefCount_0x4,                0x004);
FS_ASSERT_OFF(FatDirObject, fctx,                          0x008);
FS_ASSERT_OFF(FatDirObject, entry,                         0x078);
FS_ASSERT_OFF(FatDirObject, aLongPath_w,                   0x2f0);
FS_ASSERT_OFF(FatDirObject, wFlags_0x4f8,                  0x4f8);
FS_ASSERT_OFF(FatDirObject, qwOwnerTag_0x500,              0x500);
FS_ASSERT_OFF(FatDirObject, pvValidateCtx_0x508,           0x508);

/* FatFileHandle (0x48) — per-open-file handle */
FS_ASSERT_OFF(FatFileHandle, dwStatus,                     0x00);
FS_ASSERT_OFF(FatFileHandle, dwOpenFlags,                  0x04);
FS_ASSERT_OFF(FatFileHandle, pFileObj,                     0x08);
FS_ASSERT_OFF(FatFileHandle, qwFilePosition,               0x28);
FS_ASSERT_OFF(FatFileHandle, dwCurrentCluster,             0x30);
FS_ASSERT_OFF(FatFileHandle, dwClusterIndex,               0x34);
FS_ASSERT_OFF(FatFileHandle, wSectorOffset,                0x38);
FS_ASSERT_OFF(FatFileHandle, wRefCount,                    0x40);

/* FsObject (0x278) — parsed directory entry */
FS_ASSERT_OFF(FsObject, awLongName,                        0x000);
FS_ASSERT_OFF(FsObject, attr,                              0x208);
FS_ASSERT_OFF(FsObject, fileSize,                          0x210);
FS_ASSERT_OFF(FsObject, drvObj,                            0x230);
FS_ASSERT_OFF(FsObject, firstCluster,                      0x23c);
FS_ASSERT_OFF(FsObject, dirCluster,                        0x244);
FS_ASSERT_OFF(FsObject, entryOffset,                       0x248);
FS_ASSERT_OFF(FsObject, streamFlags,                       0x24a);
FS_ASSERT_OFF(FsObject, dirStartCluster,                   0x24c);
FS_ASSERT_OFF(FsObject, nameLen,                           0x260);
FS_ASSERT_OFF(FsObject, entryNum,                          0x261);

/* FsDirInfoInternal (0xAAA) — directory iterator / open-directory state */
FS_ASSERT_OFF(FsDirInfoInternal, drvObj,                   0x010);
FS_ASSERT_OFF(FsDirInfoInternal, cluster,                  0x018);
FS_ASSERT_OFF(FsDirInfoInternal, start_index,              0x01c);
FS_ASSERT_OFF(FsDirInfoInternal, encode_flag,              0x028);
FS_ASSERT_OFF(FsDirInfoInternal, ch_len,                   0x02c);
FS_ASSERT_OFF(FsDirInfoInternal, entry_num,                0x030);
FS_ASSERT_OFF(FsDirInfoInternal, name_hash,                0x032);
FS_ASSERT_OFF(FsDirInfoInternal, attr1,                    0x034);
FS_ASSERT_OFF(FsDirInfoInternal, path_w,                   0x040);
FS_ASSERT_OFF(FsDirInfoInternal, name_len,                 0x248);
FS_ASSERT_OFF(FsDirInfoInternal, attr_filter,              0x24a);
FS_ASSERT_OFF(FsDirInfoInternal, oem_name,                 0x24b);
FS_ASSERT_OFF(FsDirInfoInternal, modify_time,              0x456);
FS_ASSERT_OFF(FsDirInfoInternal, modify_date,              0x458);
FS_ASSERT_OFF(FsDirInfoInternal, create_time,              0x464);
FS_ASSERT_OFF(FsDirInfoInternal, create_date,              0x466);
FS_ASSERT_OFF(FsDirInfoInternal, file_size,                0x470);
FS_ASSERT_OFF(FsDirInfoInternal, attr,                     0x478);
FS_ASSERT_OFF(FsDirInfoInternal, sname,                    0x47a);
FS_ASSERT_OFF(FsDirInfoInternal, lname,                    0x487);
FS_ASSERT_OFF(FsDirInfoInternal, unicode_name,             0x688);
FS_ASSERT_OFF(FsDirInfoInternal, sname_w,                  0x890);
FS_ASSERT_OFF(FsDirInfoInternal, lname_w,                  0x8aa);

/* IDirectoryContext (0xBC2) */
FS_ASSERT_OFF(IDirectoryContext, pFSCtx,                   0x000);
FS_ASSERT_OFF(IDirectoryContext, filter_flags,             0x008);
FS_ASSERT_OFF(IDirectoryContext, name,                     0x00c);
FS_ASSERT_OFF(IDirectoryContext, dirInfo,                  0x118);

/* PFCODE_CODE_PAGE_CONTEXT (0x88E0) — codepage callback table (see def above) */
FS_ASSERT_OFF(PFCODE_CODE_PAGE_CONTEXT, pOEM2Unicode,       0x018);
FS_ASSERT_OFF(PFCODE_CODE_PAGE_CONTEXT, pUnicode2OEM,       0x020);
FS_ASSERT_OFF(PFCODE_CODE_PAGE_CONTEXT, pOEMCharWidth,      0x028);
FS_ASSERT_OFF(PFCODE_CODE_PAGE_CONTEXT, pisOEMMBchar,       0x030);
FS_ASSERT_OFF(PFCODE_CODE_PAGE_CONTEXT, pUnicodeCharWidth,  0x038);
FS_ASSERT_OFF(PFCODE_CODE_PAGE_CONTEXT, pisUnicodeMBchar,   0x040);

_Static_assert(sizeof(FsDrvObject)          == 0x8C8, "FsDrvObject size");
_Static_assert(sizeof(FsObject)             == 0x278, "FsObject size");
_Static_assert(sizeof(FatFileObject)        == 0x520, "FatFileObject size");
_Static_assert(sizeof(FatDirObject)         == 0x510, "FatDirObject size");
_Static_assert(sizeof(FatFileHandle)        == 0x48,  "FatFileHandle size");
_Static_assert(sizeof(FsDirInfoInternal)    == 0xAAA, "FsDirInfoInternal size");
_Static_assert(sizeof(FsDirInfoObj)         == 0x690, "FsDirInfoObj size");
_Static_assert(sizeof(FatFileContext)       == 0xB0,  "FatFileContext size");
_Static_assert(sizeof(FatFileContextPart)   == 0x70,  "FatFileContextPart size");
_Static_assert(sizeof(FatClusterCacheNode)  == 0x48,  "FatClusterCacheNode size");
_Static_assert(sizeof(IDirectoryContext)    == 0xBC2, "IDirectoryContext size");
_Static_assert(sizeof(PFCODE_CODE_PAGE_CONTEXT) == 0x88E0, "PFCODE_CODE_PAGE_CONTEXT size");

/* ============ 第九轮 (2026-09-13 晚)：IDirectory 命令派发 / 目录搜索对象 / PRF2SAFE ============ */
#pragma pack(push, 1)

/* FsMethodCmd (0x18) — fs_dispatch_method_cmd (0x71000ce6a4) 的命令结构。
 * 调用约定: (*cmd->ppMethodSlot)(cmd)，即方法收到整个命令结构体指针。
 * open 类命令: out=输出指针(+8), arg=OEM 路径(+0x10)；
 * close 类命令: arg(+8)=FsDirIterObj*。
 * 命令槽基址为 0x28 字节束: [0]=方法 [1]=nop 桩(0x71000d1f28) [2]=fs_safe_release_object
 * [3..4]=null。已知槽: open_dir=0x71002474f0, close_dir_handle=0x7100247548,
 * open_directory=0x7100247570, fopen=FAT_OpenDirectory=0x7100247450。 */
typedef struct FsMethodCmd {
    void **ppMethodSlot;                   /* 0x00 *ppMethodSlot = 方法入口 */
    void *out;                             /* 0x08 open 类: 输出; close 类: FsDirIterObj* */
    void *arg;                             /* 0x10 open 类: OEM 路径 char* */
} FsMethodCmd;                             /* 0x18 */

/* FatDirSearchObject (0x28) — opendir 实际返回的目录搜索对象。
 * 从 FsDrvObject.pDirSearchObj_array(+0x90) 分配 (fs_open_entry_core, 步长 0x28):
 *   +0x00 {in_use=1, 0, 0, 0x80}, +0x08 = FatDirObject*, +0x10 = 搜索上下文
 *   (fs_reset_search_context), +0x18..0x27 迭代位置(清零)。
 * 前 0x28 字节与 FatFileHandle (0x48) 头部同构: fs_close_file_by_context
 * (0x7100107cb0) 的 5 个池校验均按 0x28 步长计算，即此对象专用关闭路径；
 * fat_close_file_context (0x7100109630) 只读共享头字段，两种对象通吃。 */
typedef struct FatDirSearchObject {
    u32  dwStatus;                         /* 0x00 bit0=in-use; byte3=0x80 (符号位=有效标记) */
    u32  dwFlags_0x04;                     /* 0x04 分配时未初始化（槽复用残留） */
    struct FatDirObject *pFileObj;         /* 0x08 -> 配对的 FatDirObject (0x510 池) */
    u8   aSearchCtx_0x10[0x10];            /* 0x10 fs_reset_search_context 区 */
    u32  dwLastError_0x20;                 /* 0x20 关闭路径按 {0x20,0x24} 成对读取 */
    u32  dwReserved_0x24;                  /* 0x24 */
} FatDirSearchObject;                      /* 0x28 */

/* Prf2SafeCtx (0x10C) — FAT 介质驱动层 PRF2SAFE 恢复上下文。
 * "PRF2SAFE" 魔数（FS_isPRF2SAFE=0x7100114b90, 8 字节比较）标识恢复区头部/日志记录。
 * 恢复区 = 隐藏文件（卷标 pCtx+0x98 + 13 字节路径）中的 2 个镜像 0x200 字节头扇区:
 *   magic@0, ver@0x10=100/'d' @0x11=0x65, u32@0x16=槽号, u32@0x20=错误码,
 *   u32@0x24=FAT 数, checksum u32@0x1fc (fs_temp_clear_and_restore)。
 * 日志(写前备份)记录 0x20 字节×2 镜像: magic@0, u32@0x10=槽号游标, @0x14=错误码,
 *   @0x18=起始扇区, @0x1c=扇区数。
 * 9 槽日志表 aSlotStart/aSlotCount 记录已备份的 {起始扇区,扇区数} 区间;
 *   每槽占扇区数 = count+1 (1 条 0x20 日志记录 + count 扇区备份数据), 依次排在
 *   头扇区后 +2 起; 记录双镜像 (原位置 + count*bps + 0x20 处各一份)。
 * 工作缓冲 (init 分配一次) 布局: [0, 0x20 扇) 扇区缓冲(+0x88) → 日志缓冲(+0x78,
 *   容量 FAT 扇区数+1) → 位图(+0x20, 字节数 +0x28, bit=日志扇区占用)。
 * 回放键: key1 = 槽游标 ctx+0x18, key2 = 最近错误码 ctx+0x14 (op0xc 匹配用)。
 * 经介质驱动表 G (fs_fatdrv_manage_recovery_slot / fs_fatdrv_recovery_dispatch)
 * 间接调用; fat_prf2safe_recovery_operation_dispatch (0x7100113680) 为 15 操作码总派发。 */
typedef struct Prf2SafeCtx {
    u32  dwReserved_0x00;                  /* 0x00 (0x04 起才有字段, 0x00 未见访问) */
    u32  dwState_0x04;                     /* 0x04 op8 写入目标 */
    u32  dwDeviceState_0x08;               /* 0x08 设备状态 (op0xe/0xf, 限 <2) */
    u32  dwF_0x0c;                         /* 0x0c */
    u32  dwFlags_0x10;                     /* 0x10 bit0=已初始化 (v1 拒绝重复初始化) */
    u32  dwLastErrorCode_0x14;             /* 0x14 初始化传入的错误码 (拒 0x13/0x1d/0x6a/0x34&0x0A) */
    u32  dwSlotIndexCursor_0x18;           /* 0x18 槽号游标 (get_next_slot_index = +1) */
    u32  dwF_0x1c;                         /* 0x1c 日志活动/重入标志 (非 0 时 IO 直通不写日志) */
    void *pBitmapBuf_0x20;                 /* 0x20 簇位图缓冲 (回放时置位) */
    u32  dwBitmapBufSize_0x28;             /* 0x28 */
    u32  dwReserved_0x2c;
    u32  aSlotStart_0x30[9];               /* 0x30 日志槽起始扇区 (0xffffffff=空闲) */
    u32  aSlotCount_0x54[9];               /* 0x54 日志槽扇区数 */
    void *pJournalBuf_0x78;                /* 0x78 日志缓冲 */
    u32  dwJournalCapacity_0x80;           /* 0x80 日志容量(扇) = FAT 扇区数+1 (init 写入) */
    u32  dwReserved_0x84;
    void *pSectorBuf_0x88;                 /* 0x88 通用扇区缓冲 (=工作缓冲基址, 同 +0xb0) */
    u32  dwSectorBufSectors_0x90;          /* 0x90 扇区缓冲容量(扇) = 0x20 (init 固定写入; 非旧记的 FAT 扇区数!) */
    u32  dwReserved_0x94;
    char szVolumeLabel_0x98[13];           /* 0x98 卷标/隐藏文件路径 (op0xb 写, op10 读) */
    u8   bPad_0xa5[3];
    u32  dwF_0xa8;                         /* 0xa8 连续性要求标志 (op3 恢复文件=1 时校验簇链连续, op0xb 写) */
    u32  dwF_0xac;                         /* 0xac 已定位恢复头扇区 (op1 扫描起点, 0xffffffff=未定位) */
    void *pWorkBuf_0xb0;                   /* 0xb0 工作缓冲基址 (init 分配, 同 +0x88) */
    u32  dwWorkBufSize_0xb8;               /* 0xb8 工作缓冲总字节数 */
    u8   aPad_0xbc_0[4];
    void (*pfnAllocBuf_0xc0)(u8, u32, void **); /* 0xc0 缓冲分配回调 (盘符,大小,out; 缺失/重复分配→-7, 失败→-9) */
    void (*pfnFreeBuf_0xc8)(u8, void *);   /* 0xc8 缓冲释放回调 (cleanup 调用; 缺失→-7, 失败→-10) */
    u32  dwWriteSector_0xd0;               /* 0xd0 恢复副本基扇区 = RegionBase+(copy-2)*0xf2; 日志区在 +0x14 扇 */
    u32  dwF_0xd4;                         /* 0xd4 成功/日志就绪标志 (格式化与回放成功路径置 1) */
    u32  dwJournalKey1_0xd8;               /* 0xd8 回放匹配键1 */
    u32  dwJournalKey2_0xdc;               /* 0xdc 回放匹配键2 */
    u8   bVersion_0xe0;                    /* 0xe0 头版本字节 */
    u8   aReserved_0xe1[3];
    u32  dwVolumeStatus_0xe4;              /* 0xe4 卷状态 (fat_get_volume_status_info_wrapper 输出) */
    u32  dwRegionEnd_0xe8;                 /* 0xe8 保护区终止扇区 */
    u32  dwFatSizeBytes_0xec;              /* 0xec FAT 字节数 */
    u16  wBytesPerSector_0xf0;             /* 0xf0 */
    u8   bSectorsPerFatCopy_0xf2;          /* 0xf2 每副本间隔 */
    u8   aReserved_0xf3[5];
    u32  dwTotalSectors_0xf8;              /* 0xf8 */
    u32  dwF_0xfc;                         /* 0xfc */
    u32  dwRegionBase_0x100;               /* 0x100 保护区基址扇区 */
    u32  dwIoctlArg1_0x104;                /* 0x104 */
    u32  dwIoctlArg2_0x108;                /* 0x108 */
} Prf2SafeCtx;                             /* 0x10C */

#pragma pack(pop)

FS_ASSERT_OFF(FsMethodCmd, arg,                              0x10);
FS_ASSERT_OFF(FatDirSearchObject, pFileObj,                  0x08);
FS_ASSERT_OFF(FatDirSearchObject, dwLastError_0x20,          0x20);
FS_ASSERT_OFF(Prf2SafeCtx, aSlotStart_0x30,                  0x30);
FS_ASSERT_OFF(Prf2SafeCtx, aSlotCount_0x54,                  0x54);
FS_ASSERT_OFF(Prf2SafeCtx, szVolumeLabel_0x98,               0x98);
FS_ASSERT_OFF(Prf2SafeCtx, dwWriteSector_0xd0,               0xd0);
FS_ASSERT_OFF(Prf2SafeCtx, wBytesPerSector_0xf0,             0xf0);
FS_ASSERT_OFF(Prf2SafeCtx, dwRegionBase_0x100,               0x100);
FS_ASSERT_OFF(FsDirIterObj, pDirSearchObj,                   0x7a8);
FS_ASSERT_OFF(FsDirIterObj, ppOwnerFatCtx,                   0x7c8);

_Static_assert(sizeof(FsMethodCmd)          == 0x18,  "FsMethodCmd size");
_Static_assert(sizeof(FatDirSearchObject)   == 0x28,  "FatDirSearchObject size");
_Static_assert(sizeof(Prf2SafeCtx)          == 0x10C, "Prf2SafeCtx size");

#endif /* FS_STRUCTS_H */
