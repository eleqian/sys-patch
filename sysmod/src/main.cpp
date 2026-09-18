#include <cstring>
#include <span>
#include <iterator> // std::size
#include <algorithm> // for std::min
#include <bit> // for std::byteswap
#include <utility> // std::unreachable
#include "switch.h"
#include "minIni/minIni.h"

namespace {

constexpr u64 INNER_HEAP_SIZE = 0x1000; // Size of the inner heap (adjust as necessary).
constexpr u64 READ_BUFFER_SIZE = 0x1000; // size of static buffer which memory is read into
constexpr u32 FW_VER_ANY = 0x0;
constexpr u16 REGEX_SKIP = 0x100;

u32 FW_VERSION{}; // set on startup
u32 AMS_VERSION{}; // set on startup
u32 AMS_TARGET_VERSION{}; // set on startup
u8 AMS_KEYGEN{}; // set on startup
u64 AMS_HASH{}; // set on startup
bool VERSION_SKIP{}; // set on startup

template<typename T>
constexpr void str2hex(const char* s, T* data, u8& size) {
    // skip leading 0x (if any)
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }

    // invalid string will cause a compile-time error due to no return
    constexpr auto hexstr_2_nibble = [](char c) -> u8 {
        if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
        if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
        if (c >= '0' && c <= '9') { return c - '0'; }
    };

    // parse and convert string
    while (*s != '\0') {
        if (sizeof(T) == sizeof(u16) && *s == '.') {
            data[size] = REGEX_SKIP;
            s++;
        } else {
            data[size] |= hexstr_2_nibble(*s++) << 4;
            data[size] |= hexstr_2_nibble(*s++) << 0;
        }
        size++;
    }
}

struct PatternData {
    constexpr PatternData(const char* s) {
        str2hex(s, data, size);
    }

    u16 data[60]{}; // reasonable max pattern length, adjust as needed
    u8 size{};
};

struct PatchData {
    constexpr PatchData(const char* s) {
        str2hex(s, data, size);
    }

    template<typename T>
    constexpr PatchData(T v) {
        for (u32 i = 0; i < sizeof(T); i++) {
            data[size++] = v & 0xFF;
            v >>= 8;
        }
    }

    constexpr auto cmp(const void* _data) -> bool {
        return !std::memcmp(data, _data, size);
    }

    u8 data[20]{}; // reasonable max patch length, adjust as needed
    u8 size{};
};

enum class PatchResult {
    NOT_FOUND,
    SKIPPED,
    DISABLED,
    PATCHED_FILE,
    PATCHED_SYSPATCH,
    FAILED_WRITE,
    FAILED_HARVEST,   // fs 补丁专用：现场收割（ctx 取指对）失败，整点主动放弃不写
};

struct Patterns {
    const char* patch_name; // name of patch
    const PatternData byte_pattern; // the pattern to search

    const s32 inst_offset; // instruction offset relative to byte pattern
    const s32 patch_offset; // patch offset relative to inst_offset

    bool (*const cond)(u32 inst); // check condition of the instruction
    PatchData (*const patch)(u32 inst); // the patch data to be applied
    bool (*const applied)(const u8* data, u32 inst); // check to see if patch already applied

    bool enabled; // controlled by config.ini

    const u32 min_fw_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
    const u32 max_fw_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
    const u32 min_ams_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
    const u32 max_ams_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore

    PatchResult result{PatchResult::NOT_FOUND};
};

struct PatchEntry {
    const char* name; // name of the system title
    const u64 title_id; // title id of the system title
    const std::span<Patterns> patterns; // list of patterns to find
    const u32 min_fw_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
    const u32 max_fw_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
};

// naming convention should if possible adhere to either an arm instruction + _cond,
// example: "bl_cond"
// or naming it specific to what is being patched, and including all possible bytes within the address being tested for the given patch.
// example: "ctest_cond"

constexpr auto sub_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0xD1; // sub sp, sp, #0x150
}

constexpr auto cmp_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0x6B || // cmp w0, w1
           type == 0xF1;   // cmp x0, #0x1
}

constexpr auto bl_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0x25 ||
           type == 0x94 ||
           type == 0x97;
}

constexpr auto tbz_cond(u32 inst) -> bool {
    return ((inst >> 24) & 0x7F) == 0x36;
}

constexpr auto adr_cond(u32 inst) -> bool {
    return (inst >> 24) == 0x10; // adr x2, LAB
}

constexpr auto block_fw_updates_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0xA8 ||
           type == 0xA9 ||
           type == 0xF8 ||
           type == 0xF9;
}

constexpr auto es_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0xD1 ||
           type == 0xA9 ||
           type == 0xAA ||
           type == 0x2A ||
           type == 0x92;
}

constexpr auto ctest_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0xF9 ||
           type == 0xA9 ||
           type == 0xF8;
}


// to view patches, use https://armconverter.com/?lock=arm64
constexpr PatchData ret0_patch_data{ "0xE0031F2A" };
constexpr PatchData ret1_patch_data{ "0x200080D2" };
constexpr PatchData mov0_ret_patch_data{ "0xE0031F2AC0035FD6" };
constexpr PatchData nop_patch_data{ "0x1F2003D5" };
//mov x0, xzr
constexpr PatchData mov0_patch_data{ "0xE0031FAA" };
//mov x2, xzr
constexpr PatchData mov2_patch_data{ "0xE2031FAA" };
constexpr PatchData cmp_patch_data{ "0x00" };
constexpr PatchData ctest_patch_data{ "0x00309AD2001EA1F2610100D4E0031FAAC0035FD6" };

constexpr auto ret0_patch(u32 inst) -> PatchData { return ret0_patch_data; }
constexpr auto ret1_patch(u32 inst) -> PatchData { return ret1_patch_data; }
constexpr auto mov0_ret_patch(u32 inst) -> PatchData { return mov0_ret_patch_data; }
constexpr auto nop_patch(u32 inst) -> PatchData { return nop_patch_data; }
constexpr auto mov0_patch(u32 inst) -> PatchData { return mov0_patch_data; }
constexpr auto mov2_patch(u32 inst) -> PatchData { return mov2_patch_data; }
constexpr auto cmp_patch(u32 inst) -> PatchData { return cmp_patch_data; }
constexpr auto ctest_patch(u32 inst) -> PatchData { return ctest_patch_data; }

constexpr auto ret0_applied(const u8* data, u32 inst) -> bool {
    return ret0_patch(inst).cmp(data);
}

constexpr auto ret1_applied(const u8* data, u32 inst) -> bool {
    return ret1_patch(inst).cmp(data);
}

constexpr auto nop_applied(const u8* data, u32 inst) -> bool {
    return nop_patch(inst).cmp(data);
}

constexpr auto cmp_applied(const u8* data, u32 inst) -> bool {
    return cmp_patch(inst).cmp(data);
}

constexpr auto mov0_ret_applied(const u8* data, u32 inst) -> bool {
    return mov0_ret_patch(inst).cmp(data);
}

constexpr auto mov0_applied(const u8* data, u32 inst) -> bool {
    return mov0_patch(inst).cmp(data);
}

constexpr auto mov2_applied(const u8* data, u32 inst) -> bool {
    return mov2_patch(inst).cmp(data);
}

constexpr auto ctest_applied(const u8* data, u32 inst) -> bool {
    return ctest_patch(inst).cmp(data);
}

constinit Patterns fs_patterns[] = {
    { "noacidsigchk_1.0.0-9.2.0", "0xC8FE4739", -24, 0, bl_cond, ret0_patch, ret0_applied, true, FW_VER_ANY, MAKEHOSVERSION(9,2,0) }, // moved to loader 10.0.0
    { "noacidsigchk_1.0.0-9.2.0", "0x0210911F000072", -5, 0, bl_cond, ret0_patch, ret0_applied, true, FW_VER_ANY, MAKEHOSVERSION(9,2,0) }, // moved to loader 10.0.0
    { "noncasigchk_10.0.0-16.1.0", "0x1E48391F.0071..0054", -17, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(10,0,0), MAKEHOSVERSION(16,1,0) },
    { "noncasigchk_17.0.0+", "0x0694..00.42.0091", -18, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(17,0,0), FW_VER_ANY },
    { "nocntchk_10.0.0-18.1.0", "0x00..0240F9....08.....00...00...0037", 6, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(10,0,0), MAKEHOSVERSION(18,1,0) },
    { "nocntchk_19.0.0-20.5.0", "0x00..0240F9....08.....00...00...0054", 6, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(19,0,0), MAKEHOSVERSION(20,5,0) },
    { "nocntchk_21.0.0+", "0x00..0240F9....E8.....00...00...0054", 6, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(21,0,0), FW_VER_ANY },
};

constinit Patterns ldr_patterns[] = {
    { "noacidsigchk_10.0.0+", "0x009401C0BE121F00", 6, 2, cmp_cond, cmp_patch, cmp_applied, true, FW_VER_ANY }, // 1F00016B - cmp w0, w1 patched to 1F00006B - cmp w0, w0
};

constinit Patterns erpt_patterns[] = {
    { "no_erpt", "0x...D1FD7B02A9FD830091F76305A9", 0, 0, sub_cond, mov0_ret_patch, mov0_ret_applied, true, FW_VER_ANY }, // FF4305D1 - sub sp, sp, #0x150 patched to E0031F2AC0035FD6 - mov w0, wzr, ret
};

constinit Patterns es_patterns[] = {
    { "es_1.0.0-8.1.1", "0x....E8.00...FF97.0300AA..00.....E0.0091..0094.7E4092.......A9", 36, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(1,0,0), MAKEHOSVERSION(8,1,1) },
    { "es_9.0.0-11.0.1", "0x00...............00.....A0..D1...97.......A9", 30, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(9,0,0), MAKEHOSVERSION(11,0,1) },
    { "es_12.0.0-18.1.0", "0x02.00...........00...00.....A0..D1...97.......A9", 32, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(12,0,0), MAKEHOSVERSION(18,1,0) },
    { "es_19.0.0+", "0xA1.00...........00...00.....A0..D1...97.......A9", 32, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY },
};

constinit Patterns olsc_patterns[] = {
    { "olsc_6.0.0-14.1.2", "0x00.73..F968024039..00...00", 42, 0, bl_cond, ret1_patch, ret1_applied, true, MAKEHOSVERSION(6,0,0), MAKEHOSVERSION(14,1,2) },
    { "olsc_15.0.0-18.1.0", "0x00.73..F968024039..00...00", 38, 0, bl_cond, ret1_patch, ret1_applied, true, MAKEHOSVERSION(15,0,0), MAKEHOSVERSION(18,1,0) },
    { "olsc_19.0.0+", "0x00.73..F968024039..00...00", 42, 0, bl_cond, ret1_patch, ret1_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY },
};

constinit Patterns nifm_patterns[] = {
    { "ctest_1.0.0-19.0.1", "0x03.AAE003.AA...39..04F8....E0", -29, 0, ctest_cond, ctest_patch, ctest_applied, true, FW_VER_ANY, MAKEHOSVERSION(19,0,1) },
    { "ctest_20.0.0+", "0x03.AA...AA.........0314AA..14AA", -17, 0, ctest_cond, ctest_patch, ctest_applied, true, MAKEHOSVERSION(20,0,0), FW_VER_ANY },
};

constinit Patterns nim_patterns[] = {
    { "blankcal0crashfix_17.0.0+", "0x00351F2003D5...............97..0094..00.....61", 6, 0, adr_cond, mov2_patch, mov2_applied, true, MAKEHOSVERSION(17,0,0), FW_VER_ANY },
    { "blockfirmwareupdates_1.0.0-5.1.0", "0x1139F30301AA81.40F9E0.1191", -30, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(1,0,0), MAKEHOSVERSION(5,1,0) },
    { "blockfirmwareupdates_6.0.0-6.2.0", "0xF30301AA.4E40F9E0..91", -40, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(6,0,0), MAKEHOSVERSION(6,2,0) },
    { "blockfirmwareupdates_7.0.0-11.0.1", "0xF30301AA014C40F9F40300AAE0..91", -36, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(7,0,0), MAKEHOSVERSION(11,0,1) },
    { "blockfirmwareupdates_12.0.0+", "0x280841F9084C00F9E0031F.C0035FD6", 16, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(12,0,0), FW_VER_ANY },
};

// NOTE: add system titles that you want to be patched to this table.
// a list of system titles can be found here https://switchbrew.org/wiki/Title_list
constinit PatchEntry patches[] = {
    { "fs", 0x0100000000000000, fs_patterns },
    // ldr needs to be patched in fw 10+
    { "ldr", 0x0100000000000001, ldr_patterns, MAKEHOSVERSION(10,0,0) },
    // erpt no write patch
    { "erpt", 0x010000000000002B, erpt_patterns, MAKEHOSVERSION(10,0,0) },
    // es was added in fw 2
    { "es", 0x0100000000000033, es_patterns, MAKEHOSVERSION(2,0,0) },
    // olsc was added in fw 6
    { "olsc", 0x010000000000003E, olsc_patterns, MAKEHOSVERSION(6,0,0) },
    { "nifm", 0x010000000000000F, nifm_patterns },
    { "nim", 0x0100000000000025, nim_patterns },
};

struct EmummcPaths {
    char unk[0x80];
    char nintendo[0x80];
};

void smcAmsGetEmunandConfig(EmummcPaths* out_paths) {
    SecmonArgs args{};
    args.X[0] = 0xF0000404; /* smcAmsGetEmunandConfig */
    args.X[1] = 0; /* EXO_EMUMMC_MMC_NAND*/
    args.X[2] = (u64)out_paths; /* out path */
    svcCallSecureMonitor(&args);
}

auto is_emummc() -> bool {
    EmummcPaths paths{};
    smcAmsGetEmunandConfig(&paths);
    return (paths.unk[0] != '\0') || (paths.nintendo[0] != '\0');
}

/* 命中站点记录（仅诊断）：fs 的补丁扫描命中后把补丁位的**绝对地址**记下来，
 * 由调用方换算成「相对模块基址的偏移」写进 log.ini，便于与 RESOLVED.md 逐点核对。
 * 只存内存不落盘 —— 附加调试后 fs 是挂起的，此时任何写 SD 的操作都会永久阻塞。
 * （只有 fs 代码页补丁用；系统 title 的 patcher() 不需要。） */
struct FsSiteSink {
    struct Rec { const char* name; u64 addr; };
    Rec recs[64]{};
    u32 n{};

    void add(const char* name, u64 addr) {
        if (n < std::size(recs)) {
            recs[n].name = name;
            recs[n].addr = addr;
            n++;
        }
    }
};

void patcher(Handle handle, const u8* data, size_t data_size, u64 addr, std::span<Patterns> patterns,
             FsSiteSink* sink = nullptr) {
    for (auto& p : patterns) {
        // skip if disabled (controller by config.ini)
        if (p.result == PatchResult::DISABLED) {
            continue;
        }

        // skip if version isn't valid
        if (VERSION_SKIP &&
            ((p.min_fw_ver && p.min_fw_ver > FW_VERSION) ||
            (p.max_fw_ver && p.max_fw_ver < FW_VERSION) ||
            (p.min_ams_ver && p.min_ams_ver > AMS_VERSION) ||
            (p.max_ams_ver && p.max_ams_ver < AMS_VERSION))) {
            p.result = PatchResult::SKIPPED;
            continue;
        }

        // skip if already patched
        if (p.result == PatchResult::PATCHED_FILE || p.result == PatchResult::PATCHED_SYSPATCH) {
            continue;
        }

        for (u32 i = 0; i < data_size; i++) {
            if (i + p.byte_pattern.size >= data_size) {
                break;
            }

            // loop through every byte of the pattern data to find a match
            // skipping over any bytes if the value is REGEX_SKIP
            u32 count{};
            while (count < p.byte_pattern.size) {
                if (p.byte_pattern.data[count] != data[i + count] && p.byte_pattern.data[count] != REGEX_SKIP) {
                    break;
                }
                count++;
            }

            // if we have found a matching pattern
            if (count == p.byte_pattern.size) {
                // fetch the instruction
                u32 inst{};
                const auto inst_offset = i + p.inst_offset;
                std::memcpy(&inst, data + inst_offset, sizeof(inst));

                // check if the instruction is the one that we want
                if (p.cond(inst)) {
                    const auto patch_data = p.patch(inst);
                    const auto patch_offset = addr + inst_offset + p.patch_offset;

                    // todo: log failed writes, although this should in theory never fail
                    if (R_FAILED(svcWriteDebugProcessMemory(handle, &patch_data, patch_offset, patch_data.size))) {
                        p.result = PatchResult::FAILED_WRITE;
                    } else {
                        p.result = PatchResult::PATCHED_SYSPATCH;
                    }
                    // move onto next pattern
                    break;
                } else if (p.applied(data + inst_offset + p.patch_offset, inst)) {
                    // patch already applied by sigpatches
                    p.result = PatchResult::PATCHED_FILE;
                    break;
                }
            }
        }
    }
}

auto apply_patch(PatchEntry& patch) -> bool {
    Handle handle{};
    DebugEventInfo event_info{};

    u64 pids[0x50]{};
    s32 process_count{};
    constexpr u64 overlap_size = 0x4f;
    static u8 buffer[READ_BUFFER_SIZE + overlap_size];

    std::memset(buffer, 0, sizeof(buffer));

    // skip if version isn't valid
    if (VERSION_SKIP &&
        ((patch.min_fw_ver && patch.min_fw_ver > FW_VERSION) ||
        (patch.max_fw_ver && patch.max_fw_ver < FW_VERSION))) {
        for (auto& p : patch.patterns) {
            p.result = PatchResult::SKIPPED;
        }
        return true;
    }

    if (R_FAILED(svcGetProcessList(&process_count, pids, 0x50))) {
        return false;
    }

    for (s32 i = 0; i < (process_count - 1); i++) {
        if (R_SUCCEEDED(svcDebugActiveProcess(&handle, pids[i])) &&
            R_SUCCEEDED(svcGetDebugEvent(&event_info, handle)) &&
            patch.title_id == event_info.info.create_process.program_id) {
            MemoryInfo mem_info{};
            u64 addr{};
            u32 page_info{};

            for (;;) {
                if (R_FAILED(svcQueryDebugProcessMemory(&mem_info, &page_info, handle, addr))) {
                    break;
                }
                addr = mem_info.addr + mem_info.size;

                // if addr=0 then we hit the reserved memory section
                if (!addr) {
                    break;
                }
                // skip memory that we don't want
                if (!mem_info.size || (mem_info.perm & Perm_Rx) != Perm_Rx || ((mem_info.type & 0xFF) != MemType_CodeStatic)) {
                    continue;
                }

                for (u64 sz = 0; sz < mem_info.size; sz += READ_BUFFER_SIZE - overlap_size) {
                    const auto actual_size = std::min(READ_BUFFER_SIZE, mem_info.size - sz);
                    if (R_FAILED(svcReadDebugProcessMemory(buffer + overlap_size, handle, mem_info.addr + sz, actual_size))) {
                        break;
                    } else {
                        patcher(handle, buffer, actual_size + overlap_size, mem_info.addr + sz - overlap_size, patch.patterns);
                        if (actual_size >= overlap_size) {
                            memcpy(buffer, buffer + READ_BUFFER_SIZE, overlap_size);
                            std::memset(buffer + overlap_size, 0, READ_BUFFER_SIZE);
                        } else {
                            const auto bytes_to_overlap = std::min<u64>(overlap_size, actual_size);
                            memcpy(buffer, buffer + READ_BUFFER_SIZE + (actual_size - bytes_to_overlap), bytes_to_overlap);
                            std::memset(buffer + bytes_to_overlap, 0, sizeof(buffer) - bytes_to_overlap);
                        }
                    }
                }
            }
            svcCloseHandle(handle);
            return true;
        } else if (handle) {
            svcCloseHandle(handle);
            handle = 0;
        }
    }

    return false;
}

// creates a directory, non-recursive!
auto create_dir(const char* path) -> bool {
    Result rc{};
    FsFileSystem fs{};
    char path_buf[FS_MAX_PATH]{};

    if (R_FAILED(fsOpenSdCardFileSystem(&fs))) {
        return false;
    }

    strcpy(path_buf, path);
    rc = fsFsCreateDirectory(&fs, path_buf);
    fsFsClose(&fs);
    return R_SUCCEEDED(rc);
}

// same as ini_get but writes out the default value instead
auto ini_load_or_write_default(const char* section, const char* key, long _default, const char* path) -> long {
    if (!ini_haskey(section, key, path)) {
        ini_putl(section, key, _default, path);
        return _default;
    } else {
        return ini_getbool(section, key, _default, path);
    }
}

auto patch_result_to_str(PatchResult result) -> const char* {
    switch (result) {
        case PatchResult::NOT_FOUND: return "Unpatched";
        case PatchResult::SKIPPED: return "Skipped";
        case PatchResult::DISABLED: return "Disabled";
        case PatchResult::PATCHED_FILE: return "Patched (file)";
        case PatchResult::PATCHED_SYSPATCH: return "Patched (sys-patch)";
        case PatchResult::FAILED_WRITE: return "Failed (svcWriteDebugProcessMemory)";
        case PatchResult::FAILED_HARVEST: return "Failed (fs ctx harvest)";
    }

    std::unreachable();
}

void num_2_str(char*& s, u16 num) {
    u16 max_v = 1000;
    if (num > 9) {
        while (max_v >= 10) {
            if (num >= max_v) {
                while (max_v != 1) {
                    *s++ = '0' + (num / max_v);
                    num -= (num / max_v) * max_v;
                    max_v /= 10;
                }
            } else {
                max_v /= 10;
            }
        }
    }
    *s++ = '0' + (num); // always add 0 or 1's
}

void ms_2_str(char* s, u32 num) {
    u32 max_v = 100;
    *s++ = '0' + (num / 1000); // add seconds
    num -= (num / 1000) * 1000;
    *s++ = '.';

    while (max_v >= 10) {
        if (num >= max_v) {
            while (max_v != 1) {
                *s++ = '0' + (num / max_v);
                num -= (num / max_v) * max_v;
                max_v /= 10;
            }
        }
        else {
           *s++ = '0'; // append 0
           max_v /= 10;
        }
    }
    *s++ = '0' + (num); // always add 0 or 1's
    *s++ = 's'; // in seconds
}

// eg, 852481 -> 13.2.1
void version_to_str(char* s, u32 ver) {
    for (int i = 0; i < 3; i++) {
        num_2_str(s, (ver >> 16) & 0xFF);
        if (i != 2) {
            *s++ = '.';
        }
        ver <<= 8;
    }
}

// eg, 0xAF66FF99 -> AF66FF99
void hash_to_str(char* s, u32 hash) {
    for (int i = 0; i < 4; i++) {
        const auto num = (hash >> 24) & 0xFF;
        const auto top = (num >> 4) & 0xF;
        const auto bottom = (num >> 0) & 0xF;

        constexpr auto a = [](u8 nib) -> char {
            if (nib >= 0 && nib <= 9) { return '0' + nib; }
            return 'a' + nib - 10;
        };

        *s++ = a(top);
        *s++ = a(bottom);

        hash <<= 8;
    }
}

void keygen_to_str(char* s, u8 keygen) {
    num_2_str(s, keygen);
}

} // namespace

extern "C" {
// R5：续字节校验——3/4 字节分支会读 in[1..3]，必须确认是 0x80~0xBF
// 的合法续字节，防止路径尾截断时越界读 + 防止与调用方步进失步。
static inline bool utf8_cont_ok(u8 b) { return (b & 0xC0) == 0x80; }

__attribute__((used, section(".text.patch_utf8_to_utf16")))
static int patch_utf8_to_utf16(const u8 *utf8_in, u16 *utf16_out) {
    u32 cp = 0;          // 临时存放码点
    u8 first = utf8_in[0];
    int utf8_len = 0;

    // 1字节UTF-8：0xxxxxxx
    if (first <= 0x7F) {
        cp = first;
        *utf16_out = (u16)cp;
        utf8_len = 1;
    }
    // 2字节UTF-8：110xxxxx 10xxxxxx
    else if ((first & 0xE0) == 0xC0) {
        if (!utf8_cont_ok(utf8_in[1])) {
            *utf16_out = L'_';
            return (1 << 16) | 2;   // 非法输入按 1 字节 '_' 处理
        }
        cp = ((first & 0x1F) << 6) | (utf8_in[1] & 0x3F);
        *utf16_out = (u16)cp;
        utf8_len = 2;
    }
    // 3字节UTF-8：1110xxxx 10xxxxxx 10xxxxxx
    else if ((first & 0xF0) == 0xE0) {
        if (!utf8_cont_ok(utf8_in[1]) || !utf8_cont_ok(utf8_in[2])) {
            *utf16_out = L'_';
            return (1 << 16) | 2;
        }
        cp = ((first & 0x0F) << 12) | ((utf8_in[1] & 0x3F) << 6) | (utf8_in[2] & 0x3F);
        *utf16_out = (u16)cp;
        utf8_len = 3;
    }
    // 4字节UTF-8：11110xxx ...（对应U+10000~U+10FFFF），需代理对，不支持
    else if ((first & 0xF8) == 0xF0) {
        // 4字节UTF-8：11110xxx ...（对应U+10000~U+10FFFF），需代理对，不支持。
        // 短路校验续字节（R5）：前一字节非法/NUL 时不再读后续字节，
        // 防止越过字符串结尾的越界读；无效输入按 1 字节 '_' 处理。
        if (!utf8_cont_ok(utf8_in[1]) || !utf8_cont_ok(utf8_in[2]) || !utf8_cont_ok(utf8_in[3])) {
            *utf16_out = L'_';
            return (1 << 16) | 2;
        }
        *utf16_out = L'_';
        utf8_len = 4;
    } else {
        *utf16_out = L'_';
        utf8_len = 1;
    }

    return (utf8_len << 16) | 2;
}

// 函数体结束标签：尺寸 = patch_utf8_to_utf16_end − patch_utf8_to_utf16（自动，构建期守卫校验）
__asm__(".section .text.patch_utf8_to_utf16,\"ax\",@progbits\n\t.global patch_utf8_to_utf16_end\npatch_utf8_to_utf16_end:\n\t.previous");
}

extern "C" {
__attribute__((used, section(".text.patch_utf16_to_utf8")))
static int patch_utf16_to_utf8(const u16 *utf16_in, u8 *utf8_output)
{
    u16 utf16_char = *utf16_in;
    int utf8_len = 0;

    // 检查是否为代理对（U+D800 ~ U+DFFF），本函数不支持此类输入
    // if (utf16_char >= 0xD800 && utf16_char <= 0xDFFF) {
    //     return -1;  // 错误：遇到代理对，无法单独转换
    // }

    if (utf16_char <= 0x007F) {
        // 1字节UTF-8：0xxxxxxx
        utf8_output[0] = (uint8_t)utf16_char;
        utf8_output[2] = '\0';
        utf8_len = 1;
    } else if (utf16_char <= 0x07FF) {
        // 2字节UTF-8：110xxxxx 10xxxxxx
        utf8_output[0] = 0xC0 | (uint8_t)(utf16_char >> 6);      // 高5位
        utf8_output[1] = 0x80 | (uint8_t)(utf16_char & 0x3F);    // 低6位
        utf8_output[2] = '\0';                                   // R6: 与1字节分支及原CP932约定对齐
        utf8_len = 2;
    } else {
        // 3字节UTF-8：1110xxxx 10xxxxxx 10xxxxxx
        utf8_output[0] = 0xE0 | (uint8_t)(utf16_char >> 12);          // 高4位
        utf8_output[1] = 0x80 | (uint8_t)((utf16_char >> 6) & 0x3F);  // 中间6位
        utf8_output[2] = 0x80 | (uint8_t)(utf16_char & 0x3F);         // 低6位
        utf8_len = 3;
    }

    return (utf8_len << 16) | 2;
}

// 函数体结束标签：尺寸 = patch_utf16_to_utf8_end − patch_utf16_to_utf8（自动，构建期守卫校验）
__asm__(".section .text.patch_utf16_to_utf8,\"ax\",@progbits\n\t.global patch_utf16_to_utf8_end\npatch_utf16_to_utf8_end:\n\t.previous");
}

extern "C" {
__attribute__((used, section(".text.patch_is_oem_mb_char")))
static int patch_is_oem_mb_char(u8 ch, int byte_idx)
{
    const unsigned c = ch;

    /* ⚠️ 必须按 byte_idx 区分两种语义（原版 CP932 亦如此，见 0xfee40 结尾的两次 csel）：
     *   idx=1：首字节 → 返回"后面还有几个字节"（0=单字节/ASCII），补丁点用它做步进；
     *   idx=2：第二字节 → 只判"是否为合法尾字节"（1/0），FAT_GetNextPathComponent
     *          用它校验多字节字符的第二个字节，cbz 即判为非法 → 直接 PathNotFound。
     *   曾因忽略 idx、让续字节一律返回 0，导致中文名能枚举但打不开（FsError_PathNotFound）。
     * 尺寸硬约束：≤0x50（0x71000fee40..0x71000fee90，之后是回调表引用的 stub）。 */
    if (byte_idx != 1) {
        return (byte_idx == 2) && ((c >> 6) == 2);   /* 10xxxxxx = UTF-8 续字节 */
    }
    if (c < 0xC0) {
        return 0;                                    /* ASCII 与续字节：按单字节步进（R7） */
    }
    /* 0xC0..0xFF：额外字节数 = 首字节前导 1 的个数 − 1（1/2/3；≥4 视为非法 → 0）。
     * 用 clz 一条指令算完，比逐段比较省 12 字节代码，才塞得进 0x50 的洞。 */
    const int extra = __builtin_clz(((~c) & 0xFFu) << 24) - 1;
    return (extra < 4) ? extra : 0;
}

// 函数体结束标签：尺寸 = patch_is_oem_mb_char_end − patch_is_oem_mb_char（自动，构建期守卫校验）
__asm__(".section .text.patch_is_oem_mb_char,\"ax\",@progbits\n\t.global patch_is_oem_mb_char_end\npatch_is_oem_mb_char_end:\n\t.previous");
}

extern "C" {
/* H1：字符串级 Unicode→OEM 转换有界替换（原 PFCODE_Str_Unicode2OEM @fs+0xf5840）。
 * 原版对输出缓冲无上限——fat_init_fs_object_shortname 向 dirInfo+0x487 的
 * lname[513] 写入时，UTF-8 下 ≥171 个 CJK 字符即溢出（H1）。
 * 本替换在 512 字节处截断（含 NUL 共 ≤513），修复溢出。
 *
 * **ASLR 纪律（重要）**：本函数被原样拷进 fs 进程执行，而 Switch 模块有加载地址
 * 随机化，Ghidra/ELF 里的绝对地址（0x7100xxxx）在运行时毫无意义。因此本函数：
 *   - 不出现任何绝对地址物化、不调用外部函数、不引用外部数据；
 *   - 需要 fs 的代码页上下文时，由**补丁器在覆写前现场收割**（见下方 fs_harvest_ctx_pair）：
 *     从原函数体里读出原版自己的 `adrp xN,页 + ldr xN,[xN,#imm]`，解码出目标槽，
 *     再按占位对的实际地址重编码成 x3 版本填进本函数的前两条指令。
 *   - 普通模式的 UTF-16→UTF-8 直接内联（等价于 patch_utf16_to_utf8），
 *     特殊映射模式直接比较 u16，因此不再需要调用 fs 内部 helper（0xde560）。
 * 注意：不要写 `(uintptr_t)&函数名` —— -fPIE 下 GCC 会走 .data.rel.ro 指针槽，
 * 拷贝进 fs 后同样失效（守卫会拦）。
 * 构建期守卫 check_patch_sizes.py 会扫描函数体，禁止绝对地址物化。
 * 返回值恒 0（与原版一致）。
 * 尺寸硬约束：fs+0xf5960 是下一个函数（Str_OEM2Unicode），本函数体必须 ≤0x120。
 *
 * ⚠️ 为什么必须「现场收割」而不是写死槽地址：fs 存上下文指针的那个槽，地址**逐版本都不同**
 * （已实测 22 个 fs 二进制：19.0.1/exfat=0x24eb50，19.0.1/fat32=0x240b50，
 *   16.1.0=0x2797d0/0x26c7d0，17.0.0=0x23be90/0x22ee90，18.x=0x23d138/0x230138，
 *   20.x=0x263f40/0x256f40，21.x=0x25cbc8/0x24fbc8，22.x=0x25fc38/0x252c38），
 * 而且 adrp 页增量、ldr 立即数也都随时间变（0x159/0x195/0x154/0x163/0x145…）。
 * 曾硬编码成 19.0.1/exfat 的一对编码 —— 在别的固件上会解析出**野指针**再解引用，
 * 属于会崩的严重缺陷。信息其实就在我们即将覆写的原函数字节里，读出来即可。 */

__attribute__((used, section(".text.patch_str_unicode2oem")))
static int patch_str_unicode2oem(char *dst_oem, const u16 *src_uni)
{
    const u8 *ctx;
    /* ── 占位对（不是最终指令）────────────────────────────────────────────
     * 下面两条 `.inst` 是**哨兵**，补丁器会用收割到的 (adrp,ldr) 覆写它们：
     *   前一条 ← adrp x3, <原版目标页>（按占位对自身地址重编码，故与页无关）
     *   后一条 ← ldr  x3, [x3, #<原版立即数>]（Rd/Rn/Rt 归一到 x3）
     * 哨兵值必须与 FS_CTX_SENTINEL_A/B 一致（运行期会核对，构建期守卫也查）；
     * 若收割失败，补丁器**整点不写**，所以哨兵永远不会被执行到。 */
    __asm__ volatile(
        ".inst 0xDEAD0001\n\t"
        ".inst 0xDEAD0002\n\t"
        "mov %0, x3\n"
        : "=r"(ctx)
        :
        : "x3");
    u8 *out = (u8 *)dst_oem;
    u8 *const limit = out + 512;                /* H1：输出上限 */
    const u16 *in = src_uni;

    if (ctx[0x48] & 2) {
        /* 特殊映射模式：'.'→'.'、' '→' '、其余→'_' */
        while (*in != 0 && out < limit) {
            u16 c = *in++;
            *out++ = (c == 0x2e) ? '.' : ((c == 0x20) ? ' ' : '_');
        }
    } else {
        /* 普通转换模式：内联 UTF-16→UTF-8（1~3 字节/字符） */
        while (*in != 0 && out < limit) {
            u16 c = *in++;
            if (c <= 0x7f) {
                *out++ = (u8)c;
            } else if (c <= 0x7ff) {
                *out++ = (u8)(0xc0 | (c >> 6));
                *out++ = (u8)(0x80 | (c & 0x3f));
            } else {
                *out++ = (u8)(0xe0 | (c >> 12));
                *out++ = (u8)(0x80 | ((c >> 6) & 0x3f));
                *out++ = (u8)(0x80 | (c & 0x3f));
            }
        }
    }
    *out = '\0';
    return 0;
}

// 函数体结束标签：尺寸 = patch_str_unicode2oem_end − patch_str_unicode2oem（自动，构建期守卫校验）
__asm__(".section .text.patch_str_unicode2oem,\"ax\",@progbits\n\t.global patch_str_unicode2oem_end\npatch_str_unicode2oem_end:\n\t.previous");
}

extern "C" {
/* R4：StringDesc_ToUpper 有界替换（原 @0x71000f7c10）。
 * 原版 OEM 分支对 signed char 调 toupper，UTF-8 高位字节（≥0x80）被当作
 * 负数传入 ctype 表，行为未定义且可能改写名字字节。
 * 本替换 OEM 分支改 ASCII-only：仅 'a'-'z' 大写，≥0x80 原样保留。
 * Unicode 分支与原版一致（u16 逐字符，'a'-'z' 大写）。
 * StringDesc 布局见 fs_structs.h：ptr_left@0x00、encode_type@0x10（ENCODE_OEM=1）。
 * 尺寸硬约束：0x71000f7ce0 是下一个函数（PFCODE_CP932_ConvertWidth），
 * 本函数体必须 ≤0xD0。 */
typedef struct {
    void *ptr_left;
    void *ptr_right;
    int   encode_type;
    u32   rsvd;
} FsStrDescLite;

__attribute__((used, section(".text.patch_stringdesc_toupper")))
static void patch_stringdesc_toupper(FsStrDescLite *path, short maxLen, char *dst)
{
    if (path->encode_type != 1 /* ENCODE_OEM */) {
        u16 *p = (u16 *)path->ptr_left;
        u16 *d = (u16 *)dst;
        while (maxLen != 0) {
            u16 c = *p++;
            if (c == 0) {
                break;
            }
            if ((unsigned)(c - 'a') < 26u) {
                c = (u16)(c - 0x20);
            }
            *d++ = c;
            maxLen--;
        }
        *d = 0;
    } else {
        u8 *p = (u8 *)path->ptr_left;
        while (maxLen != 0) {
            u8 c = *p;
            if (c == 0) {
                break;
            }
            if ((unsigned)(c - 'a') < 26u) {
                c = (u8)(c - 0x20);
            }
            *dst++ = (char)c;
            p++;
            maxLen--;
        }
        *dst = '\0';
    }
}

// 函数体结束标签：尺寸 = patch_stringdesc_toupper_end − patch_stringdesc_toupper（自动，构建期守卫校验）
__asm__(".section .text.patch_stringdesc_toupper,\"ax\",@progbits\n\t.global patch_stringdesc_toupper_end\npatch_stringdesc_toupper_end:\n\t.previous");
}

extern "C" {
/* M6：WideChar_Compare 整函数替换（原 @fs+0xf4770，参考 19.0.1/exfat）。
 *
 * 这是「编码域感知的宽字符通配符匹配」：`*`(0x2a) / `?`(0x3f) + 递归回溯。
 * 原版靠 12 条**按版本寄存器变体重写**的指令补丁（p18–p26：orr/and/cmp 从 16 位
 * 扩到 24 位）才能比较 3 字节字符 —— 那些条目对寄存器分配极其敏感。这里用一份
 * 自包含实现把 12 条折叠掉，语义 == 15 点全打（p11–p26）。
 *
 * 等价性证据（离线，见 _audit/_m6_oracle.py）：
 *   · 参照物 = apply_group_patch() 打完全部 15 点后的原件（断言 n==15）；
 *   · 在 unicorn 里把 fs 的 3 个 ctx 回调（f18/f20/f30）打桩，原件与替换体看到
 *     完全相同的环境 ⇒ 逐例比较返回值即可判行为一致；
 *   · 3 种形状 × 3000 例随机用例（含全角/通配符/多字节）：**9000/9000 全同**。
 *
 * 结构体布局（由调用者 0xf3f20 反推、并经差分自测确认）：
 *   FsNameDesc16  = {u64 data; u16 enc; u16 pos; u32 pad}   16 B —— x1
 *     enc==1 → UTF-16（pos 步进 2）；否则 OEM（步进 1）。pos 已经是「越过当前字符」
 *     的字节偏移。data 是裸缓冲。
 *   FsPatStream24 = {u64 cur; u64 end; u64 mode}            24 B —— x3
 *     mode 低 32 位是宽度：==1 → 按 1 字节读，否则按 2 字节读。
 *     ⚠️ 这是**独立的流对象**，不是名字的 StringDesc —— 原版 callee 0xf44e0
 *     （FAT_GetNextChar）读的是 {cur,end,mode}，不是 {data,enc,pos}。
 *   调用约定：外部调用者先推进 name desc 一次、折叠当前名字字符，再调 0xf44e0(ps,enc)
 *   取到第一个模式字符，然后 `bl 本函数(name0, nd, pat0, ps)` —— name0/pat0 已是当前字符。
 *
 * **ASLR 纪律**（同 patch_str_unicode2oem，本文件最严格的约束）：
 *   - 整段代码被拷进 fs 执行，而模块有加载地址随机化 ⇒ 不得出现任何绝对地址物化、
 *     字面量池、`&函数名`；外部调用一律走经收割地址的 `blr`。
 *   - 唯一的两处「版本相关值」——编码上下文槽（第一行就读的那个全局槽）与被调用的
 *     callee —— 由补丁器**现场收割**：函数体里放 4 条哨兵占位，收割器从**即将被
 *     覆写的原件字节**里读出原版自己的 `adrp+ldr`（→ 槽）与唯一的「跳出函数体的 bl」
 *     （→ callee），按占位指令自身的真实地址重编码成 `adrp x3/x9 + add` 覆写掉它们。
 *     （哨兵由**内容**查找、位置无关 —— 编译器会把栈帧前导排在 inline asm 之前。）
 *     收割失败 ⇒ 该点整点不写（FAILED_HARVEST），保留原函数。
 *     为什么不能写死：22 份 fs 实测槽地址有 14 个不同取值、callee 有 A/B/C 三种
 *     形状（-0x290/-0x260/-0x280），写死一份会在别的固件上解引用野指针。
 *   - 自递归调用 `bl 本函数` 是允许的：它的立即数相对自身 PC，整段拷贝后偏移恒等。
 *
 * 尺寸硬约束：本函数体必须 ≤0x360（0x71000f5960 之外，本函数下方 0x360 处是下一函数；
 * 实测原件 0x35c，替换体 0x334，剩余尾部为死字节）。 */
typedef struct { u64 data; u16 enc; u16 pos; u32 pad; } FsNameDesc16;   /* 16 B */
typedef struct { u64 cur; u64 end; u64 mode; }           FsPatStream24; /* 24 B */
typedef u32 (*FsNextChar)(FsPatStream24 *, u32);

/* 名字字符归一化：ASCII 小写→大写，全角小写→半角大写（两段折叠，故叫 fold2）。 */
__attribute__((always_inline)) static inline u32 wc_fold2(u32 c)
{
    u32 t = c - 0x61u;
    if (t < 0x1au) { c = c - 0x20u; }
    t = (c + 0xbfu) & 0xffffu;
    if (t < 0x1au) { c = c - 0x20u; }
    return c;
}

__attribute__((noinline, used, optimize("Os"),
               section(".text.patch_widechar_compare")))
static u32 patch_widechar_compare(u32 name_char, FsNameDesc16 *nd,
                                  u32 pat_char, FsPatStream24 *ps)
{
    const u8 *ctxp;
    FsNextChar nx;
    /* ── 两对哨兵占位（不是最终指令）───────────────────────────────────────
     * 哨兵对 A（0xDEAD0001/2）← `adrp x3,<槽页> + add x3,x3,#lo12`（槽地址）
     * 哨兵对 B（0xDEAD0003/4）← `adrp x9,<callee 页> + add x9,x9,#lo12`
     * 两对都由收割器按**占位对自身地址**重编码，故与页边界无关。
     * 哨兵值必须与 FS_CTX_SENTINEL_* / FS_CALL_SENTINEL_* 一致；构建期守卫会查
     * 「各自恰好出现 1 次、成对相邻、按序」（收割器按内容线性搜索，故与位置无关，
     * 编译器把栈帧前导排在这段 asm 之前也没关系）。
     * 收割失败时补丁器整点不写，因此哨兵永远不会被执行到。 */
    __asm__ volatile(
        ".inst 0xDEAD0001\n\t"
        ".inst 0xDEAD0002\n\t"
        ".inst 0xDEAD0003\n\t"
        ".inst 0xDEAD0004\n\t"
        "mov %0, x3\n\t"
        "mov %1, x9\n"
        : "=r"(ctxp), "=r"(nx)
        :
        : "x3", "x9");
    const u8 *ctx = *(const u8 *const *)ctxp;

    u32 w22 = name_char, w2 = pat_char, w1 = nd->enc;
    u32 w21, w24 = 0xffe0u, n, c, t;
    u8 *p;
    FsNameDesc16  nd2;
    FsPatStream24 ps2;
    u32 c13;

    goto L47F4;

L47B0:
    p = (u8 *)nd->data;
    w1 = 1;
    c = *(u16 *)(p + nd->pos);
    nd->pos = (u16)(nd->pos + 2);
    w22 = wc_fold2(c);
    goto L47E8;

L47E8:
    w2 = nx(ps, w1);
    /* fallthrough */

L47F4:
    if (w2 == 0x3fu) {
        if ((w22 & 0xffffu) == 0) { goto L4AA8; }
    } else if (w2 == 0u) {
        return (w22 & 0xffffu) == 0u;
    } else if (w2 == 0x2au) {
        goto L48B4;
    } else if (w22 != w2) {
        goto L4AA8;
    }
    w1 = nd->enc;
    if (w1 == 1u) {
        if (nd->pos <= 0x20au) { goto L47B0; }
        w22 = 0;
        w1 = 1;
    } else {
        if (nd->pos <= 0xbu) { goto L4860; }
        w22 = 0;
    }
    goto L47E8;

L4860:
    p = (u8 *)nd->data;
    w1 = 1;
    {
        u32 pp = nd->pos;
        nd->pos = (u16)(pp + 1);
        w21 = p[pp];
    }
    /* 多字节判定走 fs 上下文里的回调 ctx[0x30](byte, 1) → 返回字节数（0 = 单字节）。
     * 这是本函数唯一的外部依赖，经 ctx 槽间接取用，因此只需收割槽地址。 */
    n = (u32)(*(u32 (*)(u32, u32))(*(const void **)(ctx + 0x30)))(w21, 1u);
    if (n != 0u) {
        const u32 q = nd->pos;
        nd->pos = (u16)(q + n);
        w21 = (u32)(*(u16 *)(p + q)) | (w21 << 16);
    }
    w1 = nd->enc;
    t = w21 - 0x61u;
    w22 = (t < 0x1au) ? (w21 - 0x20u) : w21;
    goto L47E8;

L48B4:
    for (;;) {
        u32 r;
        w1 = nd->enc;
        r = nx(ps, w1);
        if (r == 0x2au) { continue; }
        if (r == 0x3fu) { continue; }
        w2 = r;
        break;
    }
    if (w2 == 0u) { return 1u; }
    if ((w22 & 0xffffu) == 0u) { goto L4AA8; }
    w21 = w2;
    w24 = 0xffe0u;

L4918:
    if (w22 != w21) { goto L4A08; }
    nd2 = *nd;
    ps2 = *ps;
    if (nd2.enc == 1u) {
        if (nd2.pos > 0x20au) {
            c13 = 0;
        } else {
            const u32 old = nd2.pos;
            nd2.pos = (u16)(old + 2);
            c13 = wc_fold2(*(u16 *)((u8 *)nd2.data + old));
        }
    } else {
        if (nd2.pos > 0xbu) {
            c13 = 0;
        } else {
            u8 *q0 = (u8 *)nd2.data;
            const u32 old = nd2.pos;
            u32 b;
            nd2.pos = (u16)(old + 1);
            b = q0[old];
            n = (u32)(*(u32 (*)(u32, u32))(*(const void **)(ctx + 0x30)))(b, 1u);
            if (n == 0u) {
                c13 = b;
            } else {
                const u32 q = nd2.pos;
                nd2.pos = (u16)(q + n);
                c13 = (u32)(*(u16 *)(q0 + q)) | (b << 16);
            }
            t = c13 - 0x61u;
            if (t < 0x1au) { c13 = c13 + w24; }
        }
    }
    {
        const u32 uVar10 = nx(&ps2, nd->enc);
        if (patch_widechar_compare(c13, &nd2, uVar10, &ps2) != 0u) { return 1u; }
    }
    /* fallthrough */

L4A08:
    {
        const u32 enc = nd->enc;
        const u32 pos = nd->pos;
        if (enc == 1u) {
            if (pos > 0x20au) { goto L4AA8; }
            p = (u8 *)nd->data;
            c = *(u16 *)(p + pos);
            nd->pos = (u16)(pos + 2);
            w22 = wc_fold2(c);
            if ((w22 & 0xffffu) != 0u) { goto L4918; }
            goto L4AA8;
        } else {
            if (pos > 0xbu) { goto L4AA8; }
            p = (u8 *)nd->data;
            nd->pos = (u16)(pos + 1);
            w22 = p[pos];
            n = (u32)(*(u32 (*)(u32, u32))(*(const void **)(ctx + 0x30)))(w22, 1u);
            if (n != 0u) {
                const u32 q = nd->pos;
                nd->pos = (u16)(q + n);
                w22 = (u32)(*(u16 *)(p + q)) | (w22 << 16);
            }
            goto L4900;
        }
    }

L4900:
    t = w22 - 0x61u;
    if (t < 0x1au) { w22 = w22 + w24; }
    if ((w22 & 0xffffu) == 0u) { goto L4AA8; }
    goto L4918;

L4AA8:
    return 0u;
}

// 函数体结束标签：尺寸 = patch_widechar_compare_end − patch_widechar_compare（自动，构建期守卫校验）
__asm__(".section .text.patch_widechar_compare,\"ax\",@progbits\n\t.global patch_widechar_compare_end\npatch_widechar_compare_end:\n\t.previous");
}

const char *fs_codepage_patch_result = "default";

/* 补丁函数尺寸自动获取：每个 patch_* 函数放入独立 .text.<函数名> section，
 * 函数体后紧跟 <函数名>_end 汇编标签，尺寸 = 标签地址 − 函数地址
 * （同 section 内的链接期常量距离），不再手工维护 PATCH_SZ_* 宏。
 * 构建期守卫 tools/check_patch_sizes.py（make 钩子自动运行）校验：
 *   1) _end 标签地址 − 函数地址 == ELF 符号表 st_size（防标签错位/函数被延迟发射）；
 *   2) 尺寸 ≤ 补丁位空洞（脚本 FUNCTIONS 表，Ghidra 函数边界推导，
 *      换目标固件版本时必须重新推导）；
 *   3) 下面 fs_cp_patterns[] / fs_codepage_blobs[] 结构合法，且每条 pattern 在目标
 *      fs 二进制里恰好唯一命中 —— 这是 pattern 驱动方案的核心安全属性。
 * 已知硬约束：patch_str_unicode2oem ≤ 0x120（0x71000f5960 为下一函数）、
 *             patch_stringdesc_toupper ≤ 0xD0（0x71000f7ce0 为下一函数）、
 *             patch_widechar_compare ≤ 0x360（0xf4ad0 = WideChar_Compare + 0x360；
 *               三种形状的洞分别为 0x360/0x370/0x380，取最小者）。 */
template <typename T>
static size_t patch_code_size(T start, const void *end)
{
    return (size_t)((uintptr_t)end - (uintptr_t)(const void *)start);
}

extern "C" const u8 patch_utf8_to_utf16_end[];
extern "C" const u8 patch_utf16_to_utf8_end[];
extern "C" const u8 patch_is_oem_mb_char_end[];
extern "C" const u8 patch_str_unicode2oem_end[];
extern "C" const u8 patch_stringdesc_toupper_end[];
extern "C" const u8 patch_widechar_compare_end[];

static char tmp_buffer[256] = {0};
u64 tmp_addr = 0;
u64 tmp_size = 0;

void buff_to_str(char *str, const u8 *buff, u32 len)
{
    u32 i;

    constexpr auto a = [](u8 nib) -> char {
        if (nib >= 0 && nib <= 9) {
            return '0' + nib;
        } else {
            return 'a' + nib - 10;
        }
    };

    for (i = 0; i < len; i++) {
        *str++ = a(buff[i] >> 4);
        *str++ = a(buff[i] & 0xf);
        *str++ = ' ';
    }

    *str = 0;
}

/* u32 -> "0x000f45d8"（log 里报站点偏移用；minIni 只有十进制）
 * 目标缓冲区至少 11 字节。 */
void u32_to_hex_str(char *s, u32 v)
{
    s[0] = '0';
    s[1] = 'x';
    for (u32 i = 0; i < 8; i++) {
        const u32 nib = (v >> (28 - 4 * i)) & 0xF;
        s[2 + i] = (nib < 10) ? (char)('0' + nib) : (char)('a' + nib - 10);
    }
    s[10] = '\0';
}

// ===========================================================================
// fs 编码补丁：pattern 驱动的定位 + 寄存器自适应的指令改写
// ===========================================================================
//
// 旧实现把 29 个补丁位的 fs 内偏移写死成 `mem_info.addr + 0xXXXX`，只能用于
// 推导它的那一份固件（19.0.1 exfat）。这里换成原版 sys-patch 的做法：
//
//   * 每条补丁位配一条**跨版本通配 pattern**，在 fs 的 .text 里全文搜索；
//     随版本变化（寄存器分配、立即数、邻域指令）的字节写成 `.`（REGEX_SKIP）。
//   * 命中后由 patch(inst) 从**命中到的真实指令**现场算出补丁字节 ——
//     Rd/Rn/偏移/访问宽度全部继承，所以改写规则本身与版本、寄存器无关。
//   * 每条 pattern 都验证过「在本变体的 .text 里恰好唯一命中一次、且命中位置正确」。
//
// 于是同一份 sysmod 覆盖多个固件版本（当前 48 个变体 / 22 个不同的 fs 二进制）；
// 换到没验证过的固件时最坏结果是 NOT_FOUND（不写），而不是写错地方。
//
// 数据来源与复核：
//   fs_fw_audit.py batch 产出 RESOLVED.md（48 变体 × 29 点的偏移+cmp+patch）
//   -> _pattern_gen.py 求跨 22 个二进制的字节交集、逐变体验证
//   -> _gen_cpp.py 机械转成本文件的两张表（下面的 pattern 字符串不可手改）
//   -> _verify_cpp_table.py 解析本文件重新验证一遍（682 个站点全过）
namespace {

constexpr u32 FS_NOP = 0xD503201F;   // nop

// ---- AArch64 位域小工具 ---------------------------------------------------
constexpr u32 rules_bit(u32 inst, u32 hi, u32 lo)
{
    return (inst >> lo) & ((1u << (hi - lo + 1)) - 1);
}

constexpr u32 rules_setbits(u32 inst, u32 hi, u32 lo, u32 v)
{
    const u32 w = hi - lo + 1;
    const u32 m = (1u << w) - 1;
    return (inst & ~(m << lo)) | ((v & m) << lo);
}

// ---- 改写规则：cond(inst) 判定「这就是要改的那类指令」，patch(inst) 现场算补丁 --
// 规则号与命名对应 fs_encode_fix 侧 _fsrules.py 的 RULES；每条都已验证
// patch(RESOLVED.cmp) == RESOLVED.patch（22 个 fs 二进制 × 全部命中点）。

// #1：IDirectory_Read 的 `b.<cc> name_check_err`（不校验名字字符是否合法，
// 否则非英文名一律被拒）-> nop
constexpr bool rules_is_bcond(u32 inst) { return (inst & 0xFF000010u) == 0x54000000u; }
constexpr PatchData rules_nop(u32 inst) { return PatchData{FS_NOP}; }

// FAT_GetNextChar / FAT_GetNextPathComponent / 通配符三处的 `add Rd,Rn,#1`：
// 改成 `add Rd,Rn,w0`（w0 = isOEMMBchar 返回的「额外字节数」），
// 使指针按 1/2/3 字节 UTF-8 字符分别前进 1/2/3 字节。
constexpr bool rules_is_add_imm(u32 inst) { return (inst & 0x7F000000u) == 0x11000000u; }
constexpr PatchData rules_add_imm_to_add0(u32 inst)
{
    const u32 sf = rules_bit(inst, 31, 31);
    const u32 rn = rules_bit(inst, 9, 5);
    const u32 rd = rules_bit(inst, 4, 0);
    // add Rd,Rn,x0/w0 = 移位寄存器形式，shift=LSL#0、imm6=0、Rm=0
    return PatchData{(sf << 31) | 0x0B000000u | (rn << 5) | rd};
}

// 通配符里唯一一处 `add Rd,w25,#2`（CP932 双字节语义）：UTF-8 下需要
// 「idx + 字符总长」，而 w27 在本处之前已算好 idx+1（callee-saved），
// 所以改用 w27 作基址：new = (idx+1) + w0。
constexpr bool rules_is_add_w25_2(u32 inst)
{
    return (inst & 0x7F000000u) == 0x11000000u &&
           rules_bit(inst, 9, 5) == 25 && rules_bit(inst, 21, 10) == 2;
}
constexpr PatchData rules_add_w25_2_to_add_w27(u32 inst)
{
    return PatchData{0x0B000000u | (27u << 5) | rules_bit(inst, 4, 0)};
}

// ldrb -> ldrh：把比较值从单字节扩到 16 位（后续再 orr 到高字节），
// 与 FAT_GetNextChar 早已改过的 ldrh 口径统一。
constexpr bool rules_is_ldrb_imm(u32 inst) { return (inst & 0xFFC00000u) == 0x39400000u; }
constexpr PatchData rules_ldrb_imm_to_ldrh(u32 inst) { return PatchData{inst | 0x40000000u}; }

constexpr bool rules_is_ldrb_reg(u32 inst) { return (inst & 0xFFE00C00u) == 0x38600800u; }
constexpr PatchData rules_ldrb_reg_to_ldrh(u32 inst) { return PatchData{inst | 0x40000000u}; }

// 另一版本族把该 ldrb 写成了非缩放的 imm9 形式：ldrb wT,[xN,#imm] -> ldurh
constexpr PatchData rules_ldrb_imm_to_ldurh(u32 inst)
{
    const u32 imm = rules_bit(inst, 21, 10);
    const u32 rn = rules_bit(inst, 9, 5);
    const u32 rt = rules_bit(inst, 4, 0);
    return PatchData{0x78400000u | (imm << 12) | (rn << 5) | rt};
}

// FAT_GetNextChar 里把刚读到的两个字节存回栈：strb -> sturh（同址同寄存器，只改宽度）
constexpr bool rules_is_strb_imm_sp(u32 inst)
{
    return (inst & 0xFFC00000u) == 0x39000000u && rules_bit(inst, 9, 5) == 31;
}
constexpr PatchData rules_strb_sp_to_sturh(u32 inst)
{
    const u32 imm = rules_bit(inst, 21, 10);
    const u32 rt = rules_bit(inst, 4, 0);
    return PatchData{0x78000000u | (imm << 12) | (31u << 5) | rt};   // sturh wT,[sp,#imm]
}

// R1c：比较值构造 orr wD,wN,wD,lsl #8 -> lsl #16，
// 把第 3 个字节放进高字节（配合下面去掉掩码/扩展，得到 24 位单射比较值）。
constexpr bool rules_is_orr_lsl8(u32 inst)
{
    return rules_bit(inst, 31, 31) == 0 && rules_bit(inst, 30, 29) == 0b01 &&
           rules_bit(inst, 28, 24) == 0b01010 && rules_bit(inst, 23, 22) == 0 &&
           rules_bit(inst, 21, 21) == 0 && rules_bit(inst, 15, 10) == 8;
}
constexpr PatchData rules_orr_lsl8_to_16(u32 inst)
{
    return PatchData{rules_setbits(inst, 15, 10, 16)};
}

// 16.1.0 把同一处写成了 BFI wD,wN,#8,#8（= BFM immr=24,imms=7）；
// 改为 #16,#8 即 BFM immr=16,imms=7，语义与 orr lsl #16 相同。
constexpr bool rules_is_bfi_8_8(u32 inst)
{
    return rules_bit(inst, 31, 31) == 0 && rules_bit(inst, 30, 29) == 0b01 &&
           rules_bit(inst, 28, 23) == 0b100110 &&
           rules_bit(inst, 21, 16) == 24 && rules_bit(inst, 15, 10) == 7;
}
constexpr PatchData rules_bfi_8_8_to_16_8(u32 inst)
{
    return PatchData{rules_setbits(inst, 21, 16, 16)};
}

// StringDesc 消费点：原版 `csel/cinc Rd,Rn,...`（条件选择，用于跳过 1/2 个字节）
// 改成无条件 `add Rd,Rn,w0`（推进 w0 个字节）。宽/窄（sf）保留。
constexpr bool rules_is_csel_cinc(u32 inst)
{
    const u32 sel = rules_bit(inst, 11, 10);
    return (inst & 0x7FE00000u) == 0x1A800000u && (sel == 0b00 || sel == 0b01);
}
constexpr PatchData rules_csel_cinc_to_add(u32 inst)
{
    const u32 sf = rules_bit(inst, 31, 31);
    const u32 rn = rules_bit(inst, 9, 5);
    const u32 rd = rules_bit(inst, 4, 0);
    return PatchData{(sf << 31) | 0x0B000000u | (rn << 5) | rd};
}

// R1c：and wD,wN,#0xffff -> mov wD,wN（去掉 16 位掩码，保留第 3 个字节）
constexpr bool rules_is_and_ffff(u32 inst)
{
    return rules_bit(inst, 31, 31) == 0 && rules_bit(inst, 30, 29) == 0b00 &&
           rules_bit(inst, 28, 23) == 0b100100 && rules_bit(inst, 22, 22) == 0 &&
           rules_bit(inst, 21, 16) == 0 && rules_bit(inst, 15, 10) == 15;
}
constexpr PatchData rules_and_ffff_to_mov(u32 inst)
{
    const u32 rn = rules_bit(inst, 9, 5);
    const u32 rd = rules_bit(inst, 4, 0);
    return PatchData{0x2A0003E0u | (rn << 16) | rd};   // mov wD,wN = orr wD,wzr,wN
}

// R1c：cmp wD,wN,uxth -> cmp wD,wN（32 位下 UXTH 扩展是空操作，去掉后
// 比较的就是完整 24 位值；扩展寄存器形式要切回移位寄存器形式）
constexpr bool rules_is_cmp_uxth(u32 inst)
{
    return (inst & 0xFF20001Fu) == 0x6B20001Fu && rules_bit(inst, 15, 13) == 0b001;
}
constexpr PatchData rules_cmp_uxth_to_cmp(u32 inst)
{
    return PatchData{rules_setbits(inst, 15, 10, 0) & ~(1u << 21)};
}

// R2：FAT_MakeShortName 把 OEMCharWidth 的返回值当字符宽度走 2 字节拷贝循环，
// UTF-8 的 3 字节字符会让循环永不归零（死循环）。
// mov wD,w0 -> mov wD,#2（钳制为 2，字节不丢、循环正常退出）
constexpr bool rules_is_mov_w0(u32 inst) { return (inst & 0xFFFFFFE0u) == 0x2A0003E0u; }
constexpr PatchData rules_mov_reg_to_movz2(u32 inst)
{
    return PatchData{0x52800000u | (2u << 5) | rules_bit(inst, 4, 0)};
}

// 21.x/22.x 把同一处折叠成了 movz wD,#0x2e（'a'..'z' 大写比较用的常量）
constexpr bool rules_is_movz_2e(u32 inst)
{
    return (inst & 0xFF800000u) == 0x52800000u && rules_bit(inst, 20, 5) == 0x2E;
}
constexpr PatchData rules_movz_2e_to_movz2(u32 inst)
{
    return PatchData{rules_setbits(inst, 20, 5, 2)};
}

// applied = 「补丁已经打过了」的判定：现场算出的补丁字节是否已就位
//（原版 sys-patch 的 applied 回调，用于识别 sigpatch 之类先行改过的文件）
template <auto PatchFn>
constexpr bool rules_applied(const u8* data, u32 inst)
{
    return PatchFn(inst).cmp(data);
}

// ---- 整函数体替换条目 -----------------------------------------------------
// 这 5 个点无法用「改一条指令」表达：要把 fs 里整个函数体换成我们的实现
// （UTF-8/UTF-16 转换器、isOEMMBchar、有界 Unicode2OEM、ASCII-only ToUpper）。
// pattern 只负责**定位**（各版本函数体位置不同），写入的是自包含、位置无关的实现。
// 函数签名各不相同，直接往表里放地址要 reinterpret_cast —— 那不是常量表达式，
// 会让表退化成运行期初始化（sysmodule 里不想依赖 .init_array），
// 所以表里存种类，运行期 switch 取址。

enum class FsBlobImpl : u8 {
    Utf16ToUtf8,     // patch_utf16_to_utf8
    Utf8ToUtf16,     // patch_utf8_to_utf16
    IsOemMbChar,     // patch_is_oem_mb_char
    WideCharCompare, // patch_widechar_compare（M6：折叠 p18–p26）
    StrUnicode2Oem,  // patch_str_unicode2oem
    StrDescToUpper,  // patch_stringdesc_toupper
};

struct FsBlob {
    const char* patch_name;        // 同时是 log.ini 里的键名
    const PatternData byte_pattern;
    const s32 entry_offset;        // 函数入口 = pattern 命中处 + entry_offset
    const FsBlobImpl impl;

    // 门控与 FsPat 同口径（M6 需要：同一函数里 wide_cmp=1 的替换体要与
    // wide_cmp=0 的指令条目共存 —— 组级表达不了，只能在条目级开关）。
    const u8 stage_idx;            // stage=N 时 stage_idx >= N 的一律不应用
    const bool needs_wide_cmp;     // wide_cmp=0 时跳过

    PatchResult result{PatchResult::NOT_FOUND};
};

struct FsBlobRange {
    const void* code;
    u32 size;
};

// ---- P1 二级表 ------------------------------------------------------------
// 一级：函数组（同一被改写函数里的站点归一组）。组只负责组织与日志，不承担门控。
// 二级：FsPat（指令改写条目）/ FsBlob（整函数体替换条目）的连续子区间。
//
// 门控为什么要下放到条目级：p5 与 p17 同函数但分属不同 stage；p11_p26_WideChar_Compare
// 里 p11–p16 是 wide_cmp=0 的指令条目、M6 替换体是 wide_cmp=1 的整函数替换 —— 同函数、
// 不同形态、不同 wide_cmp 归属，组级表达不了。条目级反而与原版语义逐条等价。
struct FsFnGroup {
    const char* label;      // 进 [debug] fs_codepage_patch_result 的进度名
    u32 pat_begin, pat_end;
    u32 blob_begin, blob_end;
};

struct FsPat {
    const char* patch_name;        // 同时是 log.ini 里的键名
    const PatternData byte_pattern;
    const s32 inst_offset;
    const s32 patch_offset;

    bool (*const cond)(u32 inst);
    PatchData (*const patch)(u32 inst);

    const u8 pred_idx;             // M3：该条目在 fs_pred_names[] / 位图里的位号
    const u8 stage_idx;            // 原版 stage 语义：stage=N 时 stage_idx >= N 的一律不应用
    const bool needs_wide_cmp;     // 原 wide_cmp stage 成员：wide_cmp=0 时跳过
    bool enabled;

    // 没有 applied 回调：M3 的位图预筛会跳过「模板命中但 cond 失败」的位置，而那正是
    // applied() 唯一被求值的地方。_p1_prefilter_check.py 在 22 个二进制上构造「站点已
    // 被打过」的文本验证过：模板在那类站点上根本不可能命中，该分支不可达。fs 代码页
    // 补丁只此一家，也没有别的补丁器会先改它们。要恢复此能力，见该脚本的 D 段。
    PatchResult result{PatchResult::NOT_FOUND};
};

// ⚠️ 下面的表由 _gen_cpp.py 从 PATTERNS.json 机械生成，不要手改；
//    改完用 _verify_cpp_table.py 复核（22 个 fs 二进制、682 个站点必须全过）。
//
// 【P1 二级表】一级 = fs_fn_groups[]（按**被改写的函数**分组，成组关系跨 22 个
//   fs 二进制恒定）；二级 = fs_cp_patterns[] / fs_codepage_blobs[] 的连续子区间。
//   组不承担门控 —— stage=N / wide_cmp 的开关下放到**条目**级（stage_idx /
//   needs_wide_cmp），因此既能按函数组织，又与原版 7 个语义 stage 逐条等价。
//   （必要的：p5 与 p17 同函数却不同 stage；p11–p16 与 M6 同函数而门控
//     不同 —— 前者 wide_cmp=0 的指令条目、后者 wide_cmp=1 的整函数替换。）
//
// 【M3 谓词位图】每条条目声明它需要的谓词（pred_idx -> fs_pred_names[]）。扫描时
//   对每个 4 字节字算一次「命中哪些谓词」的位掩码，只在该位被置上的字对齐位置做
//   字节模板比对 —— 成本从 O(模板数 × 段长) 降到 O(谓词数 × 段长/4)，与补丁点数解耦。
//
// M3 的安全性前提（已离线验证，_p1_prefilter_check.py）：
//   ① 每条 pattern 的唯一命中位置与指令同字对齐（(i+inst_offset)%4==0）；
//   ② 位图用的谓词就是该条目的 cond 本身 —— 只跳过「cond 必然失败」的位置；
//   ③ applied() 慢路径不可达（模板命中但 cond 失败的站点上，模板不可能命中已打过
//      的字节），故 fs 扫描不再需要 applied 回调。
constexpr u32 FS_PRED_COUNT = 11;

[[maybe_unused]] constinit const char* const fs_pred_names[FS_PRED_COUNT] = {
    "rules_is_bcond",            // [0]
    "rules_is_add_imm",          // [1]
    "rules_is_add_w25_2",        // [2]
    "rules_is_ldrb_imm",         // [3]
    "rules_is_ldrb_reg",         // [4]
    "rules_is_strb_imm_sp",      // [5]
    "rules_is_orr_lsl8",         // [6]
    "rules_is_bfi_8_8",          // [7]
    "rules_is_csel_cinc",        // [8]
    "rules_is_mov_w0",           // [9]
    "rules_is_movz_2e",          // [10]
};

// 每字一掩码：bit k = fs_pred_names[k] 在该字上成立。直调序列（不走函数指针表），
// nmask 在同一块内恒定 → 分支可预测；谓词本体是 constexpr 位掩码测试，会被内联。
inline u32 fs_pred_mask(u32 inst, u32 nmask)
{
    u32 m = 0;
    if (nmask & (1u <<  0)) { if (rules_is_bcond(inst)) { m |= (1u <<  0); } }  // rules_is_bcond
    if (nmask & (1u <<  1)) { if (rules_is_add_imm(inst)) { m |= (1u <<  1); } }  // rules_is_add_imm
    if (nmask & (1u <<  2)) { if (rules_is_add_w25_2(inst)) { m |= (1u <<  2); } }  // rules_is_add_w25_2
    if (nmask & (1u <<  3)) { if (rules_is_ldrb_imm(inst)) { m |= (1u <<  3); } }  // rules_is_ldrb_imm
    if (nmask & (1u <<  4)) { if (rules_is_ldrb_reg(inst)) { m |= (1u <<  4); } }  // rules_is_ldrb_reg
    if (nmask & (1u <<  5)) { if (rules_is_strb_imm_sp(inst)) { m |= (1u <<  5); } }  // rules_is_strb_imm_sp
    if (nmask & (1u <<  6)) { if (rules_is_orr_lsl8(inst)) { m |= (1u <<  6); } }  // rules_is_orr_lsl8
    if (nmask & (1u <<  7)) { if (rules_is_bfi_8_8(inst)) { m |= (1u <<  7); } }  // rules_is_bfi_8_8
    if (nmask & (1u <<  8)) { if (rules_is_csel_cinc(inst)) { m |= (1u <<  8); } }  // rules_is_csel_cinc
    if (nmask & (1u <<  9)) { if (rules_is_mov_w0(inst)) { m |= (1u <<  9); } }  // rules_is_mov_w0
    if (nmask & (1u << 10)) { if (rules_is_movz_2e(inst)) { m |= (1u << 10); } }  // rules_is_movz_2e
    return m;
}

// 一级表：12 个函数组（注释里的地址 = 参考二进制 19.0.1/exfat 的函数起点）
constinit FsFnGroup fs_fn_groups[] = {
    { "p01_IDirectory_Read           ",  0,  1,  0,  0 },   // 0xD4AF4   1 pattern / 0 blob
    { "p05_p17_FAT_GetNextChar       ",  1,  7,  0,  0 }, // 0xF45C0   6 pattern / 0 blob
    { "p11_p26_WideChar_Compare      ",  7, 14,  0,  2 }, // 0xF4764   7 pattern / 2 blob
    { "p06_FAT_GetNextPathComponent  ", 14, 15,  2,  2 }, // 0xF4BBC   1 pattern / 0 blob
    { "p27_FAT_MakeShortName         ", 15, 17,  2,  2 }, // 0xF5AC0   2 pattern / 0 blob
    { "p07_StringDesc_AddLeft        ", 17, 18,  2,  2 }, // 0xF7788   1 pattern / 0 blob
    { "p08_StringDesc_GetCharCount   ", 18, 19,  2,  2 }, // 0xF7924   1 pattern / 0 blob
    { "p09_StringDesc_CompareUnicode ", 19, 20,  2,  2 }, // 0xF79F4   1 pattern / 0 blob
    { "p10_StringDesc_CompareOem     ", 20, 22,  2,  2 }, // 0xF7B14   2 pattern / 0 blob
    { "p02_p04_PFCODE_Converters     ", 22, 22,  2,  5 }, // -         0 pattern / 3 blob
    { "p28_PFCODE_Str_Unicode2OEM    ", 22, 22,  5,  7 }, // 0xF5840   0 pattern / 2 blob
    { "p29_StringDesc_ToUpper        ", 22, 22,  7,  8 }, // 0xF7C10   0 pattern / 1 blob
};

// 二级表：22 条指令改写条目（按函数组顺序落地；fs_fn_groups 用下标切子区间）
constinit FsPat fs_cp_patterns[] = {
    // #1 IDirectory_Read  [nop]  22 组  -> p01_IDirectory_Read (stage 0)
    { "fs_cp_p01_idirectory_read", "0x..FD0151....0131......54", 8, 0,
      rules_is_bcond, rules_nop,  0, 0, false, true },
    // #5 FAT_GetNextChar  [add_imm_to_add0]  22 组  -> p05_p17_FAT_GetNextChar (stage 1)
    { "fs_cp_p05_fat_getnextchar_step", "0x..0240F909050091..0200F9", 4, 0,
      rules_is_add_imm, rules_add_imm_to_add0,  1, 1, false, true },
    // #5 FAT_GetNextChar  [ldrb_imm_to_ldrh]  22 组  -> p05_p17_FAT_GetNextChar (stage 1)
    { "fs_cp_p05_fat_getnextchar_ldrh", "0x..0200F908014039........", 4, 0,
      rules_is_ldrb_imm, rules_ldrb_imm_to_ldrh,  3, 1, false, true },
    // #5 FAT_GetNextChar  [strb_sp_to_sturh]  2 组  -> p05_p17_FAT_GetNextChar (stage 1)
    { "fs_cp_p05_fat_getnextchar_strh_a", "0x08014039E8170039A81E1833", 4, 0,
      rules_is_strb_imm_sp, rules_strb_sp_to_sturh,  5, 1, false, true },
    // #5 FAT_GetNextChar  [strb_sp_to_sturh]  20 组  -> p05_p17_FAT_GetNextChar (stage 1)
    { "fs_cp_p05_fat_getnextchar_strh_b", "0x..21..2AE8170039..3E0012", 4, 0,
      rules_is_strb_imm_sp, rules_strb_sp_to_sturh,  5, 1, false, true },
    // #17 orr_lsl16_a  [bfi_8_8_to_16_8]  2 组  -> p05_p17_FAT_GetNextChar (stage 2, wide_cmp)
    { "fs_cp_p17_orr_lsl16_a_bfi", "0xE8170039A81E1833693E0012", 4, 0,
      rules_is_bfi_8_8, rules_bfi_8_8_to_16_8,  7, 2, true , true },
    // #17 orr_lsl16_a  [orr_lsl8_to_16]  20 组  -> p05_p17_FAT_GetNextChar (stage 2, wide_cmp)
    { "fs_cp_p17_orr_lsl16_a", "0x08014039..21..2AE8170039", 4, 0,
      rules_is_orr_lsl8, rules_orr_lsl8_to_16,  6, 2, true , true },
    // #11 wc_add1_a  [add_imm_to_add0]  22 组  -> p11_p26_WideChar_Compare (stage 2)
    { "fs_cp_p11_wc_add1_a", "0x....0034891640792A050011", 8, 0,
      rules_is_add_imm, rules_add_imm_to_add0,  1, 2, false, true },
    // #12 wc_add2  [add_w25_2_to_add_w27]  22 组  -> p11_p26_WideChar_Compare (stage 2)
    { "fs_cp_p12_wc_add2", "0x..000034280B0011A8A31F78", 4, 0,
      rules_is_add_w25_2, rules_add_w25_2_to_add_w27,  2, 2, false, true },
    // #13 wc_add1_b  [add_imm_to_add0]  22 组  -> p11_p26_WideChar_Compare (stage 2)
    { "fs_cp_p13_wc_add1_b", "0x..F3FF34891640792A050011", 8, 0,
      rules_is_add_imm, rules_add_imm_to_add0,  1, 2, false, true },
    // #14 wc_ldrh_a  [ldrb_reg_to_ldrh]  22 组  -> p11_p26_WideChar_Compare (stage 2)
    { "fs_cp_p14_wc_ldrh_a", "0x....0034891640792A050011880240F98A16007908696938", 20, 0,
      rules_is_ldrb_reg, rules_ldrb_reg_to_ldrh,  4, 2, false, true },
    // #15 wc_ldrh_b  [ldrb_imm_to_ldurh]  2 组  -> p11_p26_WideChar_Compare (stage 2)
    { "fs_cp_p15_wc_ldrh_b_ldurh", "0xA8A31F7848074039C81E1833", 4, 0,
      rules_is_ldrb_imm, rules_ldrb_imm_to_ldurh,  3, 2, false, true },
    // #15 wc_ldrh_b  [ldrb_reg_to_ldrh]  20 组  -> p11_p26_WideChar_Compare (stage 2)
    { "fs_cp_p15_wc_ldrh_b", "0xA8A31F78486B7B38..21..2A", 4, 0,
      rules_is_ldrb_reg, rules_ldrb_reg_to_ldrh,  4, 2, false, true },
    // #16 wc_ldrh_c  [ldrb_reg_to_ldrh]  22 组  -> p11_p26_WideChar_Compare (stage 2)
    { "fs_cp_p16_wc_ldrh_c", "0x..F3FF34891640792A050011880240F98A16007908696938", 20, 0,
      rules_is_ldrb_reg, rules_ldrb_reg_to_ldrh,  4, 2, false, true },
    // #6 FAT_GetNextPathComponent  [add_imm_to_add0]  22 组  -> p06_FAT_GetNextPathComponent (stage 1)
    { "fs_cp_p06_fat_getnextpathcomp_step", "0x..00805209050091690600F9", 4, 0,
      rules_is_add_imm, rules_add_imm_to_add0,  1, 1, false, true },
    // #27 makeshortname_movz2  [mov_reg_to_movz2]  14 组  -> p27_FAT_MakeShortName (stage 3)
    { "fs_cp_p27_makeshortname_movz2_a", "0xE80740B9F703002A1F21..6B", 4, 0,
      rules_is_mov_w0, rules_mov_reg_to_movz2,  9, 3, false, true },
    // #27 makeshortname_movz2  [movz_2e_to_movz2]  8 组  -> p27_FAT_MakeShortName (stage 3)
    { "fs_cp_p27_makeshortname_movz2_b", "0xF703002ACD0580521F21..6B", 4, 0,
      rules_is_movz_2e, rules_movz_2e_to_movz2, 10, 3, false, true },
    // #7 AddLeft  [csel_cinc_to_add]  22 组  -> p07_StringDesc_AddLeft (stage 0)
    { "fs_cp_p07_str_addleft", "0x94060051C806961A9F3E0072", 4, 0,
      rules_is_csel_cinc, rules_csel_cinc_to_add,  8, 0, false, true },
    // #8 GetCharCount  [csel_cinc_to_add]  22 组  -> p08_StringDesc_GetCharCount (stage 0)
    { "fs_cp_p08_str_getcharcount", "0x940600117306939A601E4038", 4, 0,
      rules_is_csel_cinc, rules_csel_cinc_to_add,  8, 0, false, true },
    // #9 CompareUnicode  [csel_cinc_to_add]  22 组  -> p09_StringDesc_CompareUnicode (stage 0)
    { "fs_cp_p09_str_compareunicode", "0xA11300D16802969A13050091", 4, 0,
      rules_is_csel_cinc, rules_csel_cinc_to_add,  8, 0, false, true },
    // #10 CompareOem  [csel_cinc_to_add]  8 组  -> p10_StringDesc_CompareOem (stage 0)
    { "fs_cp_p10_str_compareoem_a", "0x1F000071........89....9A", 8, 0,
      rules_is_csel_cinc, rules_csel_cinc_to_add,  8, 0, false, true },
    // #10 CompareOem  [csel_cinc_to_add]  14 组  -> p10_StringDesc_CompareOem (stage 0)
    { "fs_cp_p10_str_compareoem_b", "0x1F0000719402979A..264078", 4, 0,
      rules_is_csel_cinc, rules_csel_cinc_to_add,  8, 0, false, true },
};

// 8 条整函数体替换条目：pattern 只负责定位，写入的是自包含、位置无关的替换实现
constinit FsBlob fs_codepage_blobs[] = {
    // #18 WideChar_Compare -> patch_widechar_compare（M6：折叠 p18–p26 共 12 条；AB 家族 20 组 / C 家族 2 组，仅 wide_cmp=1 应用）  —— 20 组  -> p11_p26_WideChar_Compare (stage 2, wide_cmp)
    { "fs_cp_p18_wc_func_replace_a", "0xFF4302D1FD7B03A9FB2300F9FA6705A9F85F06A9F65707A9F44F08A9FDC30091........F30303AA", 0, FsBlobImpl::WideCharCompare, 2, true  },
    // #18 WideChar_Compare -> patch_widechar_compare（M6：折叠 p18–p26 共 12 条；AB 家族 20 组 / C 家族 2 组，仅 wide_cmp=1 应用）  —— 2 组  -> p11_p26_WideChar_Compare (stage 2, wide_cmp)
    { "fs_cp_p18_wc_func_replace_b", "0xFF0302D1FD7B03A9FA6704A9F85F05A9F65706A9F44F07A9FDC30091........F30303AA", 0, FsBlobImpl::WideCharCompare, 2, true  },
    // #2 PFCODE_CP932_Unicode2OEM -> patch_utf16_to_utf8（入口前一条是 ldrh w11,[x0]）  —— 22 组  -> p02_p04_PFCODE_Converters (stage 0)
    { "fs_cp_p02_pfcode_unicode2oem", "0x00000000..004079..FD0171", 4, FsBlobImpl::Utf16ToUtf8, 0, false },
    // #3 PFCODE_CP932_OEM2Unicode -> patch_utf8_to_utf16  —— 22 组  -> p02_p04_PFCODE_Converters (stage 0)
    { "fs_cp_p03_pfcode_oem2unicode", "0x........0800C039..1D0012", 4, FsBlobImpl::Utf8ToUtf16, 0, false },
    // #4 PFCODE_CP932_isOEMMBchar -> patch_is_oem_mb_char（0x50 空洞刚好用满）  —— 22 组  -> p02_p04_PFCODE_Converters (stage 0)
    { "fs_cp_p04_pfcode_is_oem_mb_char", "0x08..........................00....078052......7A", 0, FsBlobImpl::IsOemMbChar, 0, false },
    // #28 PFCODE_Str_Unicode2OEM -> patch_str_unicode2oem（H1 有界转换；21.x/22.x 入口在命中点后 4 字节）  —— 14 组  -> p28_PFCODE_Str_Unicode2OEM (stage 4)
    { "fs_cp_p28_str_unicode2oem_a", "0x3F482838C0035FD600000000FF4301D1", 12, FsBlobImpl::StrUnicode2Oem, 4, false },
    // #28 PFCODE_Str_Unicode2OEM -> patch_str_unicode2oem（H1 有界转换；21.x/22.x 入口在命中点后 4 字节）  —— 8 组  -> p28_PFCODE_Str_Unicode2OEM (stage 4)
    { "fs_cp_p28_str_unicode2oem_b", "0x3F482838C0035FD60000000000000000FF0301D1", 16, FsBlobImpl::StrUnicode2Oem, 4, false },
    // #29 StringDesc_ToUpper -> patch_stringdesc_toupper（R4 OEM 分支改 ASCII-only）  —— 22 组  -> p29_StringDesc_ToUpper (stage 5)
    { "fs_cp_p29_stringdesc_toupper", "0xFD7BBDA9F50B00F9F44F02A9FD030091081040B9", 0, FsBlobImpl::StrDescToUpper, 5, false },
};

static_assert(std::size(fs_cp_patterns) == 22);
static_assert(std::size(fs_codepage_blobs) == 8);
static_assert(std::size(fs_fn_groups) == 12);
static_assert(FS_PRED_COUNT <= 32);   // 位图挤在一个 u32 里
// 站点记录（诊断）：命中的补丁位绝对地址；调用方换算成相对 .text 基址的偏移写进 log
static FsSiteSink fs_sites;

static auto fs_blob_range(FsBlobImpl impl) -> FsBlobRange
{
    switch (impl) {
        case FsBlobImpl::Utf8ToUtf16:
            return { (const void*)patch_utf8_to_utf16,
                     (u32)patch_code_size(patch_utf8_to_utf16, patch_utf8_to_utf16_end) };
        case FsBlobImpl::Utf16ToUtf8:
            return { (const void*)patch_utf16_to_utf8,
                     (u32)patch_code_size(patch_utf16_to_utf8, patch_utf16_to_utf8_end) };
        case FsBlobImpl::IsOemMbChar:
            return { (const void*)patch_is_oem_mb_char,
                     (u32)patch_code_size(patch_is_oem_mb_char, patch_is_oem_mb_char_end) };
        case FsBlobImpl::WideCharCompare:
            return { (const void*)patch_widechar_compare,
                     (u32)patch_code_size(patch_widechar_compare, patch_widechar_compare_end) };
        case FsBlobImpl::StrUnicode2Oem:
            return { (const void*)patch_str_unicode2oem,
                     (u32)patch_code_size(patch_str_unicode2oem, patch_str_unicode2oem_end) };
        case FsBlobImpl::StrDescToUpper:
            return { (const void*)patch_stringdesc_toupper,
                     (u32)patch_code_size(patch_stringdesc_toupper, patch_stringdesc_toupper_end) };
    }

    std::unreachable();
}

/* 两个门控开关（config.ini 控制）。定义放在最前，因为位图构建与扫描都要用：
 *  - fs_stage_limit：允许应用到第几 stage。`stage_idx >= 该值` 的条目全部不应用。
 *    数值语义与原版 fs_stages 的 limit_idx 一一对应，所以旧的 stage=N 行为不变。
 *  - fs_wide_cmp：R1c 的 24 位比较值开关。=0 时退回「只到第 2 字节」的保守行为。 */
static int fs_stage_limit = 99;
static bool fs_wide_cmp = true;

/* 分块 overlap —— 必须是 4 的倍数（原版是 0x4f = 79，奇数）。
 * 为什么：M3 把谓词位面建在 buffer 的 4 字节字网格上，再用「指令字下标」去索引，
 * 这就要求 buffer 的字网格与 fs 里指令的字网格重合。第一块 base = 段首 − overlap，
 * 之后每块步长 = READ_BUFFER_SIZE − overlap；段首页对齐（4 对齐）、READ_BUFFER_SIZE
 * = 0x1000 也是 4 的倍数，所以只要 overlap 是 4 的倍数，每块 base 都落在 fs 的字边界
 * 上，指令必然与 buffer 的某个字重合。overlap 只影响跨块匹配（≥ 最长模板 42 字节即
 * 可，取 80 余量充分），因此这个改动没有别的副作用。
 * ⚠️ 别改回 0x4f：那样 3/4 的块里指令落在 buffer 两个字之间，位面索引全部错位，
 * 表现为「模板静默不命中」。_p1_sim_scan.py 用 0x4f 复现过这个坑。 */
constexpr u64 FS_OVERLAP = 0x50;
static_assert(FS_OVERLAP % 4 == 0, "M3 的位面索引要求块基址对齐 fs 的 4 字节字网格");

/* ── M3：谓词位图（按谓词分层的位面 bit-plane）────────────────────────────────
 * 扫描从「每条模板各扫一遍全段」改成「全段算一遍谓词位图，各条目只走自己的置位」：
 *   - 一遍全段：每个 4 字节字算出「命中哪些谓词」的掩码，把置位的谓词各自记进
 *     该谓词自己的位面（`fs_pred_plane[k]` 的第 w 位 = 第 w 个字命中谓词 k）；
 *   - 每条条目只遍历**自己那一位面**里置位的字（17 个 u64/块），按 ctz 逐个取。
 * 成本 ≈ 谓词数 × 段长/4（建位面）+ 条目数 × 段长/256（扫位面），与补丁点数基本解耦，
 * 而旧实现是 模板数 × 段长（逐字节）。
 *
 * 位面按 4 字节字对齐。pattern 的 inst_offset 全是 4 的倍数（生成器已强制），所以
 * 指令字下标 q = (i + inst_offset)/4，反解 i = 4q − inst_offset 仍是字对齐位置。
 *
 * 正确性：位面里的谓词**就是条目的 cond 本身**，预筛只跳过「cond 必然失败」的位置
 * —— 那种位置写在任何地方都不算命中。三条前提（命中位置与指令同字对齐、模板唯一
 * 命中、applied() 慢路径不可达）已由 _p1_prefilter_check.py 在 22 个 fs 二进制 ×
 * 40 条目上离线验证（682/682 站点）。 */
constexpr u32 FS_SCAN_BYTES = READ_BUFFER_SIZE + FS_OVERLAP;     // 单块最大字节数（含 overlap）
constexpr u32 FS_BIT_WORDS = (FS_SCAN_BYTES / 4 + 63) / 64;       // 每个位面的 u64 个数
static u64 fs_pred_plane[FS_PRED_COUNT][FS_BIT_WORDS];

static void fs_build_pred_bits(const u8* data, size_t data_size, u32 nmask)
{
    const size_t nwords = data_size / 4;
    std::memset(fs_pred_plane, 0, sizeof(fs_pred_plane));
    for (size_t w = 0; w < nwords; w++) {
        u32 inst{};
        std::memcpy(&inst, data + w * 4, sizeof(inst));
        u32 m = fs_pred_mask(inst, nmask);
        while (m) {
            const u32 k = (u32)std::countr_zero(m);
            m &= m - 1;
            fs_pred_plane[k][w >> 6] |= (1ull << (w & 63));
        }
    }
}

/* 仍需扫描的条目所占用的谓词并集。已落地 / 被 stage 或 wide_cmp 门控掉的条目不再
 * 占用建位面的开销 —— 所以每一块的实际谓词数是随补丁陆续落地而收缩的。
 * 注意「永不命中的版本族条目」会一直留在集合里，那是本方案的成本地板。 */
static u32 fs_pred_need_mask(void)
{
    u32 m = 0;
    for (auto& p : fs_cp_patterns) {
        if (p.result != PatchResult::NOT_FOUND) {
            continue;
        }
        if (fs_stage_limit <= p.stage_idx) {
            continue;
        }
        if (p.needs_wide_cmp && !fs_wide_cmp) {
            continue;
        }
        m |= (1u << p.pred_idx);
    }
    return m;
}

/* 指令改写扫描：只遍历该条目谓词位面上置位的字。
 * 位面已保证 cond(inst) 成立，命中即可直接落补丁，无需再验一次 cond。 */
static void fs_pat_scan(Handle handle, const u8* data, size_t data_size, u64 addr,
                        std::span<FsPat> pats, FsSiteSink* sink)
{
    const size_t nplane = (data_size / 4 + 63) / 64;

    for (auto& p : pats) {
        // 本块之前已经打过（跨块会重复看到同一条模板）
        if (p.result == PatchResult::PATCHED_SYSPATCH) {
            continue;
        }
        if (fs_stage_limit <= p.stage_idx) {
            continue;                       // stage=N：第 N 组起不再应用
        }
        if (p.needs_wide_cmp && !fs_wide_cmp) {
            continue;                       // wide_cmp=0 退回「只到第 2 字节」的保守行为
        }

        const u64* plane = fs_pred_plane[p.pred_idx];
        const u32 plen = p.byte_pattern.size;
        const u32 q_min = (u32)p.inst_offset / 4;     // 保证 i = 4q - inst_offset >= 0
        bool done = false;

        // 旧实现从 i=0 逐字节扫；这里只走字对齐位置。已离线验证：每条模板的唯一
        // 命中位置都使指令落在字边界上（(i+inst_offset)%4==0），所以不会漏。
        // q 递增 ⇒ i 递增，因此「首个命中即采用」的行为与旧实现一致。
        for (size_t wi = 0; wi < nplane && !done; wi++) {
            u64 bits = plane[wi];
            while (bits) {
                const u32 q = (u32)(wi * 64) + (u32)std::countr_zero(bits);
                bits &= bits - 1;
                if (q < q_min) {
                    continue;
                }
                const u32 i = q * 4 - (u32)p.inst_offset;
                if (i + plen >= data_size) {
                    done = true;            // i 单调增，往后只会更越界
                    break;
                }

                u32 count{};
                while (count < plen) {
                    if (p.byte_pattern.data[count] != data[i + count] &&
                        p.byte_pattern.data[count] != REGEX_SKIP) {
                        break;
                    }
                    count++;
                }
                if (count != plen) {
                    continue;
                }

                u32 inst{};
                std::memcpy(&inst, data + q * 4, sizeof(inst));
                const auto patch_data = p.patch(inst);
                const auto patch_offset = addr + q * 4 + p.patch_offset;

                // todo: log failed writes, although this should in theory never fail
                if (R_FAILED(svcWriteDebugProcessMemory(handle, &patch_data, patch_offset, patch_data.size))) {
                    p.result = PatchResult::FAILED_WRITE;
                } else {
                    p.result = PatchResult::PATCHED_SYSPATCH;
                    if (sink) { sink->add(p.patch_name, patch_offset); }
                }
                done = true;
                break;
            }
        }
    }
}

/* ══ 现场收割：把替换体里的哨兵占位指令改成真实地址 ════════════════════════
 * 为什么必须收割而不是写死：fs 把「代码页上下文指针」放在一个数据槽里，而**槽地址、
 * adrp 页增量、ldr 立即数逐固件都不同**（22 份实测出 14 个不同槽地址）。写死一对编码
 * 只在一个固件上成立，其它固件会解引用**野指针** → 崩。信息就在**即将被覆写的原函数
 * 字节**里：原版自己就是用 `adrp xN,页 + ldr xN,[xN,#imm]` 取这个槽的。
 *
 * 收割只依赖「占位指令自身的真实地址」，所以跨页、跨版本都成立：
 *   ① ctx 槽：在原件前 FS_CTX_SCAN 字节里找**唯一**一条 adrp，以及它**唯一**配对的
 *      ldr（Rn = Rt = adrp 的 Rd）→ 解出槽地址 → 重编码成 `adrp x3 + add x3,#lo12`
 *      覆写哨兵对 A；替换体随后 `ldr x3,[x3]` 解引用得到 ctx。
 *   ② callee：在原件前 FS_CALL_SCAN 字节里找**目标跳出函数体**的 bl。这类 bl 可能
 *      出现多次（M6 的目标函数实测 3 条，全指向同一个 callee），所以判据是「**去重后
 *      的目标恰好 1 个**」而不是「bl 恰好 1 条」。重编码成 `adrp x9 + add x9,#lo12`
 *      覆写哨兵对 B；替换体用 `blr x9` 调用它。
 *      （外部调用必须走 blr：整段覆写后 BL 的相对偏移不再指向原目标。）
 *      注：函数体内「跳到函数入口」的自递归 bl 不算外部调用 —— 它相对自身 PC，整段
 *      拷贝后偏移恒等，由编译器直接发射即可，不进收割。
 * 任一项收割失败 → **该点整点不写**（FAILED_HARVEST），保留原版函数，
 * 绝不写会解引用可疑指针的代码。 */
constexpr u32 FS_CTX_SENTINEL_A = 0xDEAD0001u;
constexpr u32 FS_CTX_SENTINEL_B = 0xDEAD0002u;
constexpr u32 FS_CALL_SENTINEL_A = 0xDEAD0003u;
constexpr u32 FS_CALL_SENTINEL_B = 0xDEAD0004u;
constexpr u32 FS_CTX_SCAN = 0x120;           // ctx 槽扫描窗口（= 最小洞 0x120）
constexpr u32 FS_CALL_SCAN = 0x300;          // callee 扫描窗口：必须 ≥ 最后一条外跳 bl 的
                                             // 偏移（M6 三种形状实测 +0x27c/+0x27c/+0x294），
                                             // 又要 < 最小函数体 0x35c（否则会吃进下一个函数）
constexpr u64 FS_CTX_MAX_DELTA = 0x400000;   // 槽与代码的合理最大距离（实测 1.3~1.7 MB）

static u8 fs_harvest_buf[0xA00];
/* 收割源：从目标内存**另读一段**，而不是复用扫描块。
 * 为什么：扫描块步长 = READ_BUFFER_SIZE − overlap（0x1000 − 0x50），块尾可能装不下
 * 整个收割窗；那样入口在「块尾 0x300 内」的固件上会永远收不到（静默不写）。
 * 直接按 site 读 FS_CALL_SCAN 字节，位置无关、也不必去放大 overlap。
 * fs 在 svcDebugActiveProcess 之后是挂起的，这里读的是**原版未打补丁**的字节，
 * 正好是收割想要的东西（不受同一函数里 p11–p16 指令补丁的影响）。 */
static u8 fs_harvest_orig[FS_CALL_SCAN];

static inline u32 fs_rd32(const u8* p) { u32 v; std::memcpy(&v, p, 4); return v; }
static inline void fs_wr32(u8* p, u32 v) { std::memcpy(p, &v, 4); }
static inline bool fs_is_adrp(u32 w) { return (w & 0x9F000000u) == 0x90000000u; }
static inline bool fs_is_ldr64_imm(u32 w) { return (w & 0xFFC00000u) == 0xF9400000u; }
static inline bool fs_is_bl(u32 w) { return (w & 0xFC000000u) == 0x94000000u; }

static inline u64 fs_adrp_page(u32 w, u64 pc)
{
    s32 imm = (s32)((((w >> 5) & 0x7FFFFu) << 2) | ((w >> 29) & 3u));
    if (imm & (1 << 20)) { imm -= (1 << 21); }
    return (pc & ~0xFFFull) + ((s64)imm << 12);
}

static inline u32 fs_enc_adrp(u32 rd, u64 pc, u64 target)
{
    const u32 imm = (u32)((s64)(target - (pc & ~0xFFFull)) >> 12) & 0x1FFFFFu;
    return 0x90000000u | ((imm & 3u) << 29) | (0b10000u << 24) |
           (((imm >> 2) & 0x7FFFFu) << 5) | rd;
}

static inline u32 fs_enc_add_imm(u32 rd, u32 rn, u32 imm12)
{
    return 0x91000000u | ((imm12 & 0xFFFu) << 10) | (rn << 5) | rd;
}

/* ① ctx 槽地址。返回 0 = 收割失败。 */
static u64 fs_harvest_ctx_slot(const u8* orig, u64 fn_va)
{
    int k = -1;
    u32 aw = 0;
    for (u32 o = 0; o < FS_CTX_SCAN; o += 4) {
        const u32 w = fs_rd32(orig + o);
        if (!fs_is_adrp(w)) { continue; }
        if (k >= 0) { return 0; }                    // adrp 不唯一 ⇒ 不收
        k = (int)o; aw = w;
    }
    if (k < 0) { return 0; }

    const u32 rd = aw & 0x1Fu;
    const u64 page = fs_adrp_page(aw, fn_va + (u64)k);

    int j = -1;
    u32 lw = 0;
    for (u32 o = (u32)k + 4; o < FS_CTX_SCAN; o += 4) {
        const u32 w = fs_rd32(orig + o);
        if (!fs_is_ldr64_imm(w) || (w & 0x1Fu) != rd || ((w >> 5) & 0x1Fu) != rd) { continue; }
        if (j >= 0) { return 0; }                    // 配对 ldr 不唯一 ⇒ 不收
        j = (int)o; lw = w;
    }
    if (j < 0) { return 0; }

    const u64 slot = page + (u64)((lw >> 10) & 0xFFFu) * 8u;
    if (slot <= fn_va || slot - fn_va > FS_CTX_MAX_DELTA) { return 0; }
    return slot;
}

/* ② callee 地址：原件里「目标跳出函数体」的 bl 的**去重目标**。返回 0 = 收割失败。
 * 注意按**去重目标数**判唯一，而不是按 bl 条数：M6 的目标函数实测有 3 条外跳 bl
 * （+0x7c/+0x14c/+0x27c 或 +0x7c/+0x158/+0x294），全都指向同一个 callee。
 * 只要有 2 个不同目标就说明情况超出预期 ⇒ 整点不写。 */
static u64 fs_harvest_callee(const u8* orig, u32 span, u64 fn_va)
{
    u64 found = 0;
    bool any = false;
    for (u32 o = 0; o + 4 <= span; o += 4) {
        const u32 w = fs_rd32(orig + o);
        if (!fs_is_bl(w)) { continue; }
        s32 imm = (s32)(w & 0x3FFFFFFu);
        if (imm & (1 << 25)) { imm -= (1 << 26); }
        const s64 tgt = (s64)(fn_va + o) + ((s64)imm << 2);
        if (tgt >= (s64)fn_va && tgt < (s64)(fn_va + span)) { continue; }  // 体内 = 自递归
        if (!any) { any = true; found = (u64)tgt; }
        else if ((u64)tgt != found) { return 0; }
    }
    return any ? found : 0;
}

/* 把替换体里的一对哨兵改成 `adrp rd,<页>` + `add rd,rd,#页内偏移` 指向 target。
 * pc 取自占位对自身的真实地址 ⇒ 与页边界无关。 */
static bool fs_fill_addr_pair(u8* blob, u32 size, u32 sent_a, u32 sent_b,
                              u32 rd, u64 target, u64 blob_va)
{
    for (u32 o = 0; o + 8 <= size; o += 4) {
        if (fs_rd32(blob + o) != sent_a || fs_rd32(blob + o + 4) != sent_b) { continue; }
        const u64 pc = blob_va + o;
        fs_wr32(blob + o,     fs_enc_adrp(rd, pc, target));
        fs_wr32(blob + o + 4, fs_enc_add_imm(rd, rd, (u32)target & 0xFFFu));
        return true;
    }
    return false;
}

/* 该替换体是否带哨兵占位（需要现场收割）。M6 用满两对：ctx 对 + callee 对。 */
static bool fs_blob_needs_harvest(FsBlobImpl impl)
{
    return impl == FsBlobImpl::StrUnicode2Oem || impl == FsBlobImpl::WideCharCompare;
}

/* 整函数体替换的定位器：扫描逻辑与 fs_pat_scan 相同（同一套 REGEX_SKIP 通配规则），
 * 区别只是写进去的是替换实现的整段代码，而不是 4 字节补丁。
 * blob 只有 8 条、模板都很长且唯一，而且写的是整段代码（没法先缓后写），所以这里
 * 仍走逐字节扫描 —— 为它单独加一类谓词不划算。 */
void fs_blob_patcher(Handle handle, const u8* data, size_t data_size, u64 addr,
                     std::span<FsBlob> blobs, FsSiteSink* sink)
{
    for (auto& b : blobs) {
        // 已命中过（跨块重复看到同一条 pattern）就不用再看
        if (b.result == PatchResult::PATCHED_FILE || b.result == PatchResult::PATCHED_SYSPATCH) {
            continue;
        }
        // 门控与 FsPat 同口径（M6 的替换体只在 wide_cmp=1 时应用，wide_cmp=0 走
        // p11–p16 的指令条目）。定义域外的条目连扫描都不必做。
        if (fs_stage_limit <= b.stage_idx) {
            continue;
        }
        if (b.needs_wide_cmp && !fs_wide_cmp) {
            continue;
        }

        for (u32 i = 0; i + b.byte_pattern.size <= data_size; i++) {
            u32 count{};
            while (count < b.byte_pattern.size) {
                if (b.byte_pattern.data[count] != data[i + count] &&
                    b.byte_pattern.data[count] != REGEX_SKIP) {
                    break;
                }
                count++;
            }
            if (count != b.byte_pattern.size) {
                continue;
            }

            const auto entry = (u32)(i + b.entry_offset);
            if (entry + 16 > data_size) {
                break;   // 本块装不下，下一块（带 overlap）会再命中
            }

            const u64 site = addr + entry;
            const auto range = fs_blob_range(b.impl);

            // 已被别的途径改过（sigpatch 等）：入口前 16 字节 == 替换实现的前 16 字节。
            // 取 16 而不是 4 字节：本文件 6 个替换实现的首字节都与原函数不同（已逐条
            // 反汇编核对），取 16 字节进一步排除「某版本原函数首指令碰巧相同」的误判。
            if (!std::memcmp(data + entry, range.code, 16)) {
                b.result = PatchResult::PATCHED_FILE;
                if (sink) { sink->add(b.patch_name, site); }
                break;
            }

            // 诊断：入口原字节记一条（换固件后核对定位是否落对）
            if (tmp_buffer[0] == 0) {
                buff_to_str(tmp_buffer, data + entry, 16);
            }

            // 现场收割：带哨兵占位的替换体先拷到暂存区改成真实地址，再写进去。
            // 任一项收割失败 ⇒ 整点不写（保留原版），绝不写可疑代码。
            const void* to_write = range.code;
            u32 write_size = range.size;
            if (fs_blob_needs_harvest(b.impl)) {
                if (range.size > sizeof(fs_harvest_buf)) {
                    b.result = PatchResult::FAILED_HARVEST;
                    break;
                }
                // 收割源直接按 site 另读（见 fs_harvest_orig 的说明）
                if (R_FAILED(svcReadDebugProcessMemory(fs_harvest_orig, handle, site,
                                                       FS_CALL_SCAN))) {
                    b.result = PatchResult::FAILED_HARVEST;
                    break;
                }
                const u8* orig = fs_harvest_orig;
                const u64 slot = fs_harvest_ctx_slot(orig, site);
                if (!slot) {
                    b.result = PatchResult::FAILED_HARVEST;
                    break;
                }
                std::memcpy(fs_harvest_buf, range.code, range.size);
                if (!fs_fill_addr_pair(fs_harvest_buf, range.size,
                                       FS_CTX_SENTINEL_A, FS_CTX_SENTINEL_B, 3, slot, site)) {
                    b.result = PatchResult::FAILED_HARVEST;
                    break;
                }
                // 第二对（只有 M6 用）：callee 走 blr，必须现场收割目标地址。
                if (b.impl == FsBlobImpl::WideCharCompare) {
                    const u64 callee = fs_harvest_callee(orig, FS_CALL_SCAN, site);
                    if (!callee ||
                        !fs_fill_addr_pair(fs_harvest_buf, range.size,
                                           FS_CALL_SENTINEL_A, FS_CALL_SENTINEL_B, 9, callee, site)) {
                        b.result = PatchResult::FAILED_HARVEST;
                        break;
                    }
                }
                to_write = fs_harvest_buf;
                write_size = range.size;
            }

            // todo: log failed writes, although this should in theory never fail
            if (R_FAILED(svcWriteDebugProcessMemory(handle, to_write, site, write_size))) {
                b.result = PatchResult::FAILED_WRITE;
            } else {
                b.result = PatchResult::PATCHED_SYSPATCH;
                if (sink) { sink->add(b.patch_name, site); }
            }
            break;
        }
    }
}

// 该函数组是否还有未落地的条目（决定要不要为它打进度标记、调扫描）
static auto fs_group_pending(const FsFnGroup& g) -> bool
{
    for (u32 k = g.pat_begin; k < g.pat_end; k++) {
        if (fs_cp_patterns[k].result == PatchResult::NOT_FOUND) {
            return true;
        }
    }
    for (u32 k = g.blob_begin; k < g.blob_end; k++) {
        if (fs_codepage_blobs[k].result == PatchResult::NOT_FOUND) {
            return true;
        }
    }
    return false;
}

} // namespace

/* fs 分步进度（诊断）：
 * ⚠️ 附加为调试进程后目标进程（fs）是**挂起**的，此时任何写 SD 的日志操作
 * （要经过 fs 服务）都会永久阻塞 —— 曾因此造成开机卡 logo。所以这里只更新
 * 内存里的步骤名，由 main() 在全部补丁结束、脱附之后统一落盘。
 * 若补丁过程中真的挂死，日志会是空的，此时用 config.ini 的
 * [fs_codepage] stage=N 逐组二分定位。
 * P1 起进度名是**函数组名**（如 p11_p26_WideChar_Compare），不再是语义 stage 名；
 * stage=N 的数值语义未变（stage_idx 的取值与原 limit_idx 一一对应）。 */
static void fs_stage(const char *stage)
{
    fs_codepage_patch_result = stage;
}

/* fs 编码补丁主流程：pattern 驱动 + 函数组二级表（P1）。
 * 与旧实现（写死 mem_info.addr + 0xXXXX）的区别：
 *   - 偏移不再来自编译期常量，而是每条 pattern 在 fs 的 .text 里搜出来的；
 *   - 补丁字节由改写规则从命中指令现场算出（继承寄存器/地址/宽度）；
 *   - 未命中只记 NOT_FOUND，绝不写错地方。
 * 因此同一份 sysmod 可覆盖多个固件版本（当前 22 个不同的 fs 二进制）。
 *
 * 扫描范围仍与原版一致：只处理第一个 ≥1 MiB 的 Rx/CodeStatic 段（fs 主 .text）
 * —— 它同时就是模块基址，所以 log 里的站点偏移与 RESOLVED.md / Ghidra 的 VA 同口径。 */
void fs_codepage_patch(void)
{
    Handle handle{};
    DebugEventInfo event_info{};
    u64 pids[0x50]{};
    s32 process_count{};
    constexpr u64 overlap_size = FS_OVERLAP;
    static u8 buffer[READ_BUFFER_SIZE + overlap_size];

    fs_stage("start");
    fs_sites.n = 0;
    tmp_buffer[0] = '\0';

    if (R_FAILED(svcGetProcessList(&process_count, pids, 0x50))) {
        return;
    }

    for (s32 i = 0; i < (process_count - 1); i++) {
        if (R_SUCCEEDED(svcDebugActiveProcess(&handle, pids[i])) &&
            R_SUCCEEDED(svcGetDebugEvent(&event_info, handle)) &&
            0x0100000000000000 == event_info.info.create_process.program_id) {
            MemoryInfo mem_info{};
            u64 addr{};
            u32 page_info{};

            for (;;) {
                if (R_FAILED(svcQueryDebugProcessMemory(&mem_info, &page_info, handle, addr))) {
                    break;
                }
                addr = mem_info.addr + mem_info.size;

                // if addr=0 then we hit the reserved memory section
                if (!addr) {
                    break;
                }
                // skip memory that we don't want
                if (!mem_info.size || (mem_info.perm & Perm_Rx) != Perm_Rx || ((mem_info.type & 0xFF) != MemType_CodeStatic)) {
                    continue;
                }

                // 跳过 emummc 等小代码段
                if (mem_info.size < 0x100000) {
                    continue;
                }

                // 只处理第一个大代码段 —— 它就是 fs 主 .text（也是模块基址）
                tmp_addr = mem_info.addr;
                tmp_size = mem_info.size;

                std::memset(buffer, 0, sizeof(buffer));

                for (u64 sz = 0; sz < mem_info.size; sz += READ_BUFFER_SIZE - overlap_size) {
                    const auto actual_size = std::min<u64>(READ_BUFFER_SIZE, mem_info.size - sz);
                    if (R_FAILED(svcReadDebugProcessMemory(buffer + overlap_size, handle, mem_info.addr + sz, actual_size))) {
                        break;
                    }

                    // 首块 base = 段首 - overlap（buffer 前 overlap 字节是补的 0）；
                    // 之后每块 base 前移 overlap，使跨块 pattern 能完整匹配。
                    const u64 chunk_base = mem_info.addr + sz - overlap_size;
                    const u32 chunk_size = (u32)(actual_size + overlap_size);
                    const u32 sink_begin = fs_sites.n;

                    // M3：本块只算一次谓词位图，12 个函数组共享。
                    // 谓词集合按「还需扫描的条目」收缩，越往后位图越便宜。
                    fs_build_pred_bits(buffer, chunk_size, fs_pred_need_mask());

                    for (auto& g : fs_fn_groups) {
                        if (!fs_group_pending(g)) {
                            continue;           // 该组已全部落地，连进度标记都不必打
                        }
                        fs_stage(g.label);
                        fs_pat_scan(handle, buffer, chunk_size, chunk_base,
                                std::span<FsPat>{fs_cp_patterns}
                                    .subspan(g.pat_begin, g.pat_end - g.pat_begin),
                                &fs_sites);
                        fs_blob_patcher(handle, buffer, chunk_size, chunk_base,
                                std::span<FsBlob>{fs_codepage_blobs}
                                    .subspan(g.blob_begin, g.blob_end - g.blob_begin),
                                &fs_sites);
                    }

                    // 本块新命中的站点：绝对地址 -> 相对 .text 基址的偏移（与 RESOLVED 同口径）
                    for (u32 k = sink_begin; k < fs_sites.n; k++) {
                        fs_sites.recs[k].addr -= tmp_addr;
                    }

                    // 滚动 overlap（与 apply_patch 一致）：块尾若干字节留给下一块做跨块匹配
                    if (actual_size >= overlap_size) {
                        memcpy(buffer, buffer + READ_BUFFER_SIZE, overlap_size);
                        std::memset(buffer + overlap_size, 0, READ_BUFFER_SIZE);
                    } else {
                        const auto bytes_to_overlap = std::min<u64>(overlap_size, actual_size);
                        memcpy(buffer, buffer + READ_BUFFER_SIZE + (actual_size - bytes_to_overlap), bytes_to_overlap);
                        std::memset(buffer + bytes_to_overlap, 0, sizeof(buffer) - bytes_to_overlap);
                    }
                }

                fs_stage("success");
                break;
            }

            svcCloseHandle(handle);
            return;
        } else if (handle) {
            svcCloseHandle(handle);
            handle = 0;
        }
    }
}

int main(int argc, char* argv[]) {
    constexpr auto ini_path = "/config/sys-patch/config.ini";
    constexpr auto log_path = "/config/sys-patch/log.ini";

    create_dir("/config/");
    create_dir("/config/sys-patch/");
    ini_remove(log_path);

    // load options
    const auto patch_sysmmc = ini_load_or_write_default("options", "patch_sysmmc", 1, ini_path);
    const auto patch_emummc = ini_load_or_write_default("options", "patch_emummc", 1, ini_path);
    const auto enable_logging = ini_load_or_write_default("options", "enable_logging", 1, ini_path);
    // 逃生开关：置 0 可完全跳过 fs 编码补丁（其余 sys-patch 补丁照常），
    // 用于排障/救砖，改 config.ini 即可生效，无需重新编译。
    const auto fs_codepage_enabled = ini_load_or_write_default("options", "fs_codepage", 1, ini_path);
    // 逐组二分开关：0 = 一组都不应用，1..5 = 应用到该组，6/未设置 = 全部应用。
    // 补丁把 fs 打挂时，日志写不出来（附加调试后 fs 被挂起），用这个开关二分定位。
    fs_stage_limit = ini_load_or_write_default("fs_codepage", "stage", 6, ini_path);
    // wide_cmp=0 可退回"只到第 3 字节按位或"的 R1b 行为（同名误判概率更高但更保守）。
    fs_wide_cmp = ini_load_or_write_default("fs_codepage", "wide_cmp", 1, ini_path) != 0;
    VERSION_SKIP = ini_load_or_write_default("options", "version_skip", 1, ini_path);

    // load patch toggles
    for (auto& patch : patches) {
        for (auto& p : patch.patterns) {
            p.enabled = ini_load_or_write_default(patch.name, p.patch_name, p.enabled, ini_path);
            if (!p.enabled) {
                p.result = PatchResult::DISABLED;
            }
        }
    }

    const auto emummc = is_emummc();
    bool enable_patching = true;

    // check if we should patch sysmmc
    if (!patch_sysmmc && !emummc) {
        enable_patching = false;
    }

    // check if we should patch emummc
    if (!patch_emummc && emummc) {
        enable_patching = false;
    }

    // speedtest
    const auto ticks_start = armGetSystemTick();

    if (enable_patching) {
        for (auto& patch : patches) {
            apply_patch(patch);
        }
        if (fs_codepage_enabled) {
            // 附加调试进程后 fs 会被挂起，此后不能再写日志，所以先落一条标记
            if (enable_logging) {
                ini_puts("debug", "fs_codepage", "start", log_path);
            }
            fs_codepage_patch();
        } else {
            fs_codepage_patch_result = "disabled_by_config";
        }
    }

    const auto ticks_end = armGetSystemTick();
    const auto diff_ns = armTicksToNs(ticks_end) - armTicksToNs(ticks_start);

    if (enable_logging) {
        for (auto& patch : patches) {
            for (auto& p : patch.patterns) {
                if (!enable_patching) {
                    p.result = PatchResult::SKIPPED;
                }
                ini_puts(patch.name, p.patch_name, patch_result_to_str(p.result), log_path);
            }
        }

        // fw of the system
        char fw_version[12]{};
        // atmosphere version
        char ams_version[12]{};
        // lowest fw supported by atmosphere
        char ams_target_version[12]{};
        // ???
        char ams_keygen[3]{};
        // git commit hash
        char ams_hash[9]{};
        // how long it took to patch
        char patch_time[20]{};

        version_to_str(fw_version, FW_VERSION);
        version_to_str(ams_version, AMS_VERSION);
        version_to_str(ams_target_version, AMS_TARGET_VERSION);
        keygen_to_str(ams_keygen, AMS_KEYGEN);
        hash_to_str(ams_hash, AMS_HASH >> 32);
        ms_2_str(patch_time, diff_ns/1000ULL/1000ULL);

        // defined in the Makefile
        #define DATE (DATE_DAY "." DATE_MONTH "." DATE_YEAR " " DATE_HOUR ":" DATE_MIN ":" DATE_SEC)

        ini_puts("stats", "version", VERSION_WITH_HASH, log_path);
        ini_puts("stats", "build_date", DATE, log_path);
        ini_puts("stats", "fw_version", fw_version, log_path);
        ini_puts("stats", "ams_version", ams_version, log_path);
        ini_puts("stats", "ams_target_version", ams_target_version, log_path);
        ini_puts("stats", "ams_keygen", ams_keygen, log_path);
        ini_puts("stats", "ams_hash", ams_hash, log_path);
        ini_putl("stats", "is_emummc", emummc, log_path);
        ini_putl("stats", "heap_size", INNER_HEAP_SIZE, log_path);
        ini_putl("stats", "buffer_size", READ_BUFFER_SIZE, log_path);
        ini_puts("stats", "patch_time", patch_time, log_path);

        ini_puts("debug", "fs_codepage_patch_result", fs_codepage_patch_result, log_path);
        ini_puts("debug", "tmp_buffer", tmp_buffer, log_path);
        char tmp_str[64] = "";
        buff_to_str(tmp_str, (u8 *)&tmp_addr, sizeof(tmp_addr));
        ini_puts("debug", "tmp_addr", tmp_str, log_path);
        buff_to_str(tmp_str, (u8 *)&tmp_size, sizeof(tmp_size));
        ini_puts("debug", "tmp_size", tmp_str, log_path);

        // pattern 驱动的 fs 编码补丁：逐条结果。
        // "Unpatched" = 该 pattern 在本固件上没命中（要么该点不存在，要么是新版本
        // 还没适配）—— 这种情况下一个字节都不会写，所以是安全失败，不是错误。
        // tmp_buffer = 第一个整函数体替换点（入口 16 字节），tmp_addr/tmp_size = 命中的代码段。
        for (auto& p : fs_cp_patterns) {
            ini_puts("fs_codepage", p.patch_name, patch_result_to_str(p.result), log_path);
        }
        for (auto& b : fs_codepage_blobs) {
            ini_puts("fs_codepage", b.patch_name, patch_result_to_str(b.result), log_path);
        }
        // 命中站点的偏移（相对 fs 主 .text 基址，也就是模块基址）——
        // 与 RESOLVED.md / Ghidra 的 VA 偏移同口径，可直接逐点核对。
        for (u32 k = 0; k < fs_sites.n; k++) {
            char off_str[12] = "";
            u32_to_hex_str(off_str, (u32)fs_sites.recs[k].addr);
            ini_puts("fs_codepage_sites", fs_sites.recs[k].name, off_str, log_path);
        }
    }

    // note: sysmod exits here.
    // to keep it running, add a for (;;) loop (remember to sleep!)
    return 0;
}

// libnx stuff goes below
extern "C" {

// Sysmodules should not use applet*.
u32 __nx_applet_type = AppletType_None;

// Sysmodules will normally only want to use one FS session.
u32 __nx_fs_num_sessions = 1;

// Newlib heap configuration function (makes malloc/free work).
void __libnx_initheap(void) {
    static char inner_heap[INNER_HEAP_SIZE];
    extern char* fake_heap_start;
    extern char* fake_heap_end;

    // Configure the newlib heap.
    fake_heap_start = inner_heap;
    fake_heap_end   = inner_heap + sizeof(inner_heap);
}

// Service initialization.
void __appInit(void) {
    Result rc{};

    // Open a service manager session.
    if (R_FAILED(rc = smInitialize()))
        fatalThrow(rc);

    // Retrieve the current version of Horizon OS.
    if (R_SUCCEEDED(rc = setsysInitialize())) {
        SetSysFirmwareVersion fw{};
        if (R_SUCCEEDED(rc = setsysGetFirmwareVersion(&fw))) {
            FW_VERSION = MAKEHOSVERSION(fw.major, fw.minor, fw.micro);
            hosversionSet(FW_VERSION);
        }
        setsysExit();
    }

    // get ams version
    if (R_SUCCEEDED(rc = splInitialize())) {
        u64 v{};
        u64 hash{};
        if (R_SUCCEEDED(rc = splGetConfig((SplConfigItem)65000, &v))) {
            AMS_VERSION = (v >> 40) & 0xFFFFFF;
            AMS_KEYGEN = (v >> 32) & 0xFF;
            AMS_TARGET_VERSION = v & 0xFFFFFF;
        }
        if (R_SUCCEEDED(rc = splGetConfig((SplConfigItem)65003, &hash))) {
            AMS_HASH = hash;
        }

        splExit();
    }

    if (R_FAILED(rc = fsInitialize()))
        fatalThrow(rc);

    // Add other services you want to use here.
    if (R_FAILED(rc = pmdmntInitialize()))
        fatalThrow(rc);

    // Close the service manager session.
    smExit();
}

// Service deinitialization.
void __appExit(void) {
    pmdmntExit();
    fsExit();
}

} // extern "C"
