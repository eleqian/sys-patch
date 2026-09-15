#include <cstring>
#include <span>
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

void patcher(Handle handle, const u8* data, size_t data_size, u64 addr, std::span<Patterns> patterns) {
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
    if (ch <= 0x7F) {
        // 1字节UTF-8：0xxxxxxx
        return 0;
    } else if ((ch & 0xE0) == 0xC0) {
        // 2字节UTF-8：110xxxxx 10xxxxxx
        return 1;
    } else if ((ch & 0xF0) == 0xE0) {
        // 3字节UTF-8：1110xxxx 10xxxxxx 10xxxxxx
        return 2;
    } else if ((ch & 0xF8) == 0xF0) {
        // 4字节UTF-8：11110xxx ...（对应U+10000~U+10FFFF）
        return 3;
    } else {
        // 续字节/非法字节（R7）：与 patch_utf8_to_utf16 对续字节按 len=1
        // 处理保持自洽——返回 0 使 GetNextChar 补丁点只走原有固定 +1，
        // 避免转换器(前进1)与步进(前进2)失步。byte_idx 忽略。
        (void)byte_idx;
        return 0;
    }
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
 *   - 需要 fs 的代码页上下文时，用**原版同样的 PC 相对方式**取 fs 的 GOT 槽：
 *       adrp x3, +0x159000   ; 相对"本指令所在页" → fs+0x24e000
 *       ldr  x3, [x3, #0xb50]; → fs+0x24eb50 槽内容 = 上下文指针
 *     （页增量是编译期常量：本函数固定落在 fs+0xf5840，页 0xf5000；
 *       洞约束 ≤0x120 保证函数不跨页。构建期守卫会校验这两条指令的编码。）
 *   - 普通模式的 UTF-16→UTF-8 直接内联（等价于 patch_utf16_to_utf8），
 *     特殊映射模式直接比较 u16，因此不再需要调用 fs 内部 helper（0xde560）。
 * 注意：不要写 `(uintptr_t)&函数名` —— -fPIE 下 GCC 会走 .data.rel.ro 指针槽，
 * 拷贝进 fs 后同样失效（守卫会拦）。
 * 构建期守卫 check_patch_sizes.py 会扫描函数体，禁止绝对地址物化。
 * 返回值恒 0（与原版一致）。
 * 尺寸硬约束：fs+0xf5960 是下一个函数（Str_OEM2Unicode），本函数体必须 ≤0x120。 */
#define FS_CTX_GOT_OFFSET          0x24EB50u   /* fs 内 GOT 槽：代码页上下文指针 */

__attribute__((used, section(".text.patch_str_unicode2oem")))
static int patch_str_unicode2oem(char *dst_oem, const u16 *src_uni)
{
    const u8 *ctx;
    /* PC 相对取 fs 的上下文指针
     * 0xb0000ac3 = adrp x3, +0x159000（相对本指令所在页 → fs+0x24e000）
     * 0xf945a863 = ldr  x3, [x3, #0xb50]（→ fs+0x24eb50 槽 = 上下文指针） */
    __asm__ volatile(
        ".inst 0xb0000ac3\n\t"
        ".inst 0xf945a863\n\t"
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

const char *fs_codepage_patch_result = "default";

/* 补丁函数尺寸自动获取：每个 patch_* 函数放入独立 .text.<函数名> section，
 * 函数体后紧跟 <函数名>_end 汇编标签，尺寸 = 标签地址 − 函数地址
 * （同 section 内的链接期常量距离），不再手工维护 PATCH_SZ_* 宏。
 * 构建期守卫 tools/check_patch_sizes.py（make 钩子自动运行）校验：
 *   1) _end 标签地址 − 函数地址 == ELF 符号表 st_size（防标签错位/函数被延迟发射）；
 *   2) 尺寸 ≤ 补丁位空洞（脚本 FUNCTIONS 表，Ghidra 函数边界推导，
 *      换目标固件版本时必须重新推导）。
 * 已知硬约束：patch_str_unicode2oem ≤ 0x120（0x71000f5960 为下一函数）、
 *             patch_stringdesc_toupper ≤ 0xD0（0x71000f7ce0 为下一函数）。 */
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

int fs_patch_function(Handle handle, u64 addr, const u8 *cmp_bytes, int cmp_len, const void *func_addr, int func_size)
{
    u8 buffer[0x20] = {0};

    if (R_FAILED(svcReadDebugProcessMemory(buffer, handle, addr, cmp_len))) {
        return -1;
    }

    if (memcmp(buffer, cmp_bytes, cmp_len) != 0) {
        buff_to_str(tmp_buffer, buffer, cmp_len);
        return -2;
    }

    if (R_FAILED(svcWriteDebugProcessMemory(handle, func_addr, addr, func_size))) {
        return -3;
    }

    return 0;
}

/* fs 分步进度落盘（关键诊断手段）：
 * 补丁一旦打坏 fs，fs 会挂死；而 sys-patch 写 SD 日志需要 fs 服务，此后
 * 日志再也写不进去。因此在每一步“之前”就把步骤名写进 log.ini——挂死时
 * 日志里最后一条 [debug] fs_stage 就是罪魁步骤。
 * 仅当 enable_logging 打开时写（fs_stage_log_path != nullptr）。 */
static const char *fs_stage_log_path = nullptr;

static void fs_stage(const char *stage)
{
    fs_codepage_patch_result = stage;
    if (fs_stage_log_path != nullptr) {
        ini_puts("debug", "fs_stage", stage, fs_stage_log_path);
    }
}

void fs_codepage_patch(void)
{
    Handle handle{};
    DebugEventInfo event_info{};
    u64 pids[0x50]{};
    s32 process_count{};
    int ret = 0;

    fs_stage("start");

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

                tmp_addr = mem_info.addr;
                tmp_size = mem_info.size;

                // 跳过emummc等代码
                if (mem_info.size < 0x100000) {
                    continue;
                }

                // fat32
                // const u8 fat32_cmp_bytes[16] = {
                //     0x0b, 0x00, 0x40, 0x79, 0x7f, 0xfd, 0x01, 0x71, 0xc8, 0x00, 0x00, 0x54, 0x2b, 0x00, 0x00, 0x39
                // };
                // fs_patch_function(handle, mem_info.addr + 0xced30, fat32_cmp_bytes, sizeof(fat32_cmp_bytes),
                //     (void *)patch_utf16_to_utf8, (uintptr_t)patch_utf16_to_utf8_end - (uintptr_t)patch_utf16_to_utf8);

                // exfat

                // patch IDirectory_Read，不校验字符是否合法，解决只能返回英文的问题
                fs_stage("converters");
                const u8 exfat_IDirectory_Read[] = {0xe3, 0xfc, 0xff, 0x54}; // b.cc name_check_err
                const u8 exfat_IDirectory_Read_patch[] = {0x1F, 0x20, 0x03, 0xD5}; // nop
                ret = fs_patch_function(handle, mem_info.addr + 0xd4af4, exfat_IDirectory_Read, sizeof(exfat_IDirectory_Read),
                    exfat_IDirectory_Read_patch, sizeof(exfat_IDirectory_Read_patch));
                if (ret != 0) {
                    fs_codepage_patch_result = "exfat_IDirectory_Read_patch failed";
                    break;
                }
                // patch PFCODE_CP932_Unicode2OEM
                const u8 exfat_PFCODE_CP932_Unicode2OEM[16] = {
                    0x0a, 0x00, 0x40, 0x79, 0x5f, 0xfd, 0x01, 0x71, 0xc8, 0x00, 0x00, 0x54, 0x2a, 0x00, 0x00, 0x39
                };
                ret = fs_patch_function(handle, mem_info.addr + 0xfec30, exfat_PFCODE_CP932_Unicode2OEM, sizeof(exfat_PFCODE_CP932_Unicode2OEM),
                    (void *)patch_utf16_to_utf8, (int)patch_code_size(patch_utf16_to_utf8, patch_utf16_to_utf8_end));
                if (ret != 0) {
                    fs_codepage_patch_result = "patch_utf16_to_utf8 failed";
                    break;
                }

                // patch PFCODE_CP932_OEM2Unicode
                const u8 exfat_PFCODE_CP932_OEM2Unicode[16] = {
                    0x08, 0x00, 0xc0, 0x39, 0x0a, 0x1d, 0x00, 0x12, 0xa8, 0x00, 0xf8, 0x37, 0x20, 0x00, 0x80, 0x52
                };
                ret = fs_patch_function(handle, mem_info.addr + 0xfeac0, exfat_PFCODE_CP932_OEM2Unicode, sizeof(exfat_PFCODE_CP932_OEM2Unicode),
                    (void *)patch_utf8_to_utf16, (int)patch_code_size(patch_utf8_to_utf16, patch_utf8_to_utf16_end));
                if (ret != 0) {
                    fs_codepage_patch_result = "patch_utf8_to_utf16 failed";
                    break;
                }

                // patch PFCODE_CP932_isOEMMBchar
                const u8 exfat_PFCODE_CP932_isOEMMBchar[16] = {
                    0x08, 0x00, 0x01, 0x51, 0x49, 0x00, 0x80, 0x12, 0x3f, 0x81, 0x20, 0x6b, 0x08, 0x1d, 0x00, 0x12
                };
                ret = fs_patch_function(handle, mem_info.addr + 0xfee40, exfat_PFCODE_CP932_isOEMMBchar, sizeof(exfat_PFCODE_CP932_isOEMMBchar),
                    (void *)patch_is_oem_mb_char, (int)patch_code_size(patch_is_oem_mb_char, patch_is_oem_mb_char_end));
                if (ret != 0) {
                    fs_codepage_patch_result = "patch_is_oem_mb_char failed";
                    break;
                }

                // 以下是对isOEMMBchar调用处进行patch

                // patch FAT_GetNextChar (0xf45d8): 将 add x9, x8, #1 改为 add x9, x8, x0
                fs_stage("fat_callsites");
                // 使ptr_left根据patch_is_oem_mb_char的返回值跳过1/2/3个字节
                const u8 exfat_FAT_GetNextChar[] = {
                    0xe0, 0x00, 0x00, 0x34, // cbz w0, label_continue
                    0x88, 0x02, 0x40, 0xf9, // ldr x8, [x20]
                    0x09, 0x05, 0x00, 0x91, // add x9, x8, #0x1  <-- 需要修改
                    0x89, 0x02, 0x00, 0xf9, // str x9, [x20]
                    0x08, 0x01, 0x40, 0x39, // ldrb w8, [x8]
                    0x15, 0x21, 0x15, 0x2a, // orr w21, w8, w21, lsl #8
                    0xe8, 0x17, 0x00, 0x39, // strb w8, [sp, #0x5]
                    0x68, 0x3e, 0x00, 0x12  // and w8, w19, #0xff
                };
                const u8 exfat_FAT_GetNextChar_patch[] = {
                    0xe0, 0x00, 0x00, 0x34, // cbz w0, label_continue
                    0x88, 0x02, 0x40, 0xf9, // ldr x8, [x20]
                    0x09, 0x01, 0x00, 0x8b, // add x9, x8, x0  <-- 用w0做增量（0x8B000109）
                    0x89, 0x02, 0x00, 0xf9, // str x9, [x20]
                    0x08, 0x01, 0x40, 0x79, // ldrh w8, [x8]
                    0x15, 0x21, 0x15, 0x2a, // orr w21, w8, w21, lsl #8
                    0xe8, 0x53, 0x00, 0x78, // strh w8, [sp, #0x5]
                    0x68, 0x3e, 0x00, 0x12  // and w8, w19, #0xff
                };
                ret = fs_patch_function(handle, mem_info.addr + 0xf45d8, exfat_FAT_GetNextChar, sizeof(exfat_FAT_GetNextChar),
                    exfat_FAT_GetNextChar_patch, sizeof(exfat_FAT_GetNextChar_patch));
                if (ret != 0) {
                    fs_codepage_patch_result = "exfat_FAT_GetNextChar failed";
                    break;
                }

                const u8 exfat_FAT_GetNextPathComponent[] = {0x09, 0x05, 0x00, 0x91}; // add x9, x8, #0x1
                const u8 exfat_FAT_GetNextPathComponent_patch[] = {0x09, 0x01, 0x00, 0x8B}; // add x9, x8, x0
                ret = fs_patch_function(handle, mem_info.addr + 0xf4d8c, exfat_FAT_GetNextPathComponent, sizeof(exfat_FAT_GetNextPathComponent),
                    exfat_FAT_GetNextPathComponent_patch, sizeof(exfat_FAT_GetNextPathComponent_patch));
                if (ret != 0) {
                    fs_codepage_patch_result = "exfat_FAT_GetNextPathComponent failed";
                    break;
                }

                const u8 exfat_AddLeft[] = {0xC8, 0x06, 0x96, 0x1A}; // cinc w8, w22, ne
                const u8 exfat_AddLeft_patch[] = {0xC8, 0x02, 0x00, 0x0B}; // add w8, w22, w0
                ret = fs_patch_function(handle, mem_info.addr + 0xf77e8, exfat_AddLeft, sizeof(exfat_AddLeft),
                    exfat_AddLeft_patch, sizeof(exfat_AddLeft_patch));
                if (ret != 0) {
                    fs_codepage_patch_result = "exfat_AddLeft_patch failed";
                    break;
                }

                const u8 exfat_GetCharCount[] = {0x73, 0x06, 0x93, 0x9a}; // cinc x19 ,x19 ,ne
                const u8 exfat_GetCharCount_patch[] = {0x73, 0x02, 0x00, 0x8B}; // add x19, x19, x0
                ret = fs_patch_function(handle, mem_info.addr + 0xf7984, exfat_GetCharCount, sizeof(exfat_GetCharCount),
                    exfat_GetCharCount_patch, sizeof(exfat_GetCharCount_patch));
                if (ret != 0) {
                    fs_codepage_patch_result = "exfat_GetCharCount_patch failed";
                    break;
                }

                const u8 exfat_CompareUnicode[] = {0x68, 0x02, 0x96, 0x9a}; // csel x8, x19, x22, eq
                const u8 exfat_CompareUnicode_patch[] = {0x68, 0x02, 0x00, 0x8B}; // add x8, x19, x0
                ret = fs_patch_function(handle, mem_info.addr + 0xf7a80, exfat_CompareUnicode, sizeof(exfat_CompareUnicode),
                    exfat_CompareUnicode_patch, sizeof(exfat_CompareUnicode_patch));
                if (ret != 0) {
                    fs_codepage_patch_result = "exfat_CompareUnicode_patch failed";
                    break;
                }

                const u8 exfat_CompareOem[] = {0x94, 0x02, 0x97, 0x9A}; // csel x20, x20, x23, eq
                const u8 exfat_CompareOem_patch[] = {0x94, 0x02, 0x00, 0x8B}; // add x20, x20, x0
                ret = fs_patch_function(handle, mem_info.addr + 0xf7bd0, exfat_CompareOem, sizeof(exfat_CompareOem),
                    exfat_CompareOem_patch, sizeof(exfat_CompareOem_patch));
                if (ret != 0) {
                    fs_codepage_patch_result = "exfat_CompareOem_patch failed";
                    break;
                }

                // R1: FAT_MatchWildcardRecursive 三处 isOEMMBchar 调用点，
                // “多字节则 idx 再 +1”改为“+ 返回值”（返回值=额外字节数），
                // 使 1/2/3 字节 UTF-8 字符分别前进 1/2/3 字节。
                // add w10,w9,#1 → add w10,w9,w0
                // 编码注意：移位寄存器形式必须 imm6=0（add w10,w9,w0 = 0x0B00012A）。
                // 曾误写成 0x0B00054A = add w10,w10,w0,lsl #1（丢失 Rn 并带位移），
                // 会把索引算成垃圾值 —— 构建期守卫 check_patch_sizes.py 现已拦截此类错误。
                fs_stage("wildcard_r1");
                const u8 wc_add1_cmp[] = {0x2A, 0x05, 0x00, 0x11};
                const u8 wc_add1_patch[] = {0x2A, 0x01, 0x00, 0x0B};
                ret = fs_patch_function(handle, mem_info.addr + 0xf4888, wc_add1_cmp, sizeof(wc_add1_cmp),
                    wc_add1_patch, sizeof(wc_add1_patch));
                if (ret != 0) {
                    fs_codepage_patch_result = "wildcard_0xf4888 failed";
                    break;
                }
                // add w8,w25,#2 → add w8,w25,w0  (0x0B000328，imm6=0)
                const u8 wc_add2_cmp[] = {0x28, 0x0B, 0x00, 0x11};
                const u8 wc_add2_patch[] = {0x28, 0x03, 0x00, 0x0B};
                ret = fs_patch_function(handle, mem_info.addr + 0xf49c4, wc_add2_cmp, sizeof(wc_add2_cmp),
                    wc_add2_patch, sizeof(wc_add2_patch));
                if (ret != 0) {
                    fs_codepage_patch_result = "wildcard_0xf49c4 failed";
                    break;
                }
                // add w10,w9,#1 → add w10,w9,w0
                ret = fs_patch_function(handle, mem_info.addr + 0xf4a90, wc_add1_cmp, sizeof(wc_add1_cmp),
                    wc_add1_patch, sizeof(wc_add1_patch));
                if (ret != 0) {
                    fs_codepage_patch_result = "wildcard_0xf4a90 failed";
                    break;
                }

                // R2: FAT_MakeShortName 多字节宽度钳制。
                // 原版按 OEMCharWidth 返回值 w0 作为字符宽度走 2 字节拷贝循环
                // （subs w23,#2 直到 0）；UTF-8 宽 3/4 时循环永不归零 → 死循环。
                // 钳制为 2：3 字节字符按 2+1 消费（字节不丢、循环正常退出），
                // 8.3 短名空间估算退回 CP932 的 2 字节/字行为。
                // mov w23,w0 → mov w23,#2
                fs_stage("makeshortname_r2");
                const u8 msn_movw23_cmp[] = {0xF7, 0x03, 0x00, 0x2A};
                const u8 msn_movw23_patch[] = {0x57, 0x00, 0x80, 0x52};
                ret = fs_patch_function(handle, mem_info.addr + 0xf5dcc, msn_movw23_cmp, sizeof(msn_movw23_cmp),
                    msn_movw23_patch, sizeof(msn_movw23_patch));
                if (ret != 0) {
                    fs_codepage_patch_result = "makeshortname_0xf5dcc failed";
                    break;
                }

                // H1: PFCODE_Str_Unicode2OEM 有界替换（输出 ≤512 字节 + NUL），
                // 修复 fat_init_fs_object_shortname 向 lname[513] 的溢出。
                // 替换函数体必须 ≤0x120（0x71000f5960 是下一个函数）。
                fs_stage("h1_unicode2oem");
                const u8 exfat_Str_Unicode2OEM[16] = {
                    0xFF, 0x43, 0x01, 0xD1, 0xFD, 0x7B, 0x01, 0xA9,
                    0xF7, 0x13, 0x00, 0xF9, 0xF6, 0x57, 0x03, 0xA9
                };
                ret = fs_patch_function(handle, mem_info.addr + 0xf5840, exfat_Str_Unicode2OEM, sizeof(exfat_Str_Unicode2OEM),
                    (void *)patch_str_unicode2oem, (int)patch_code_size(patch_str_unicode2oem, patch_str_unicode2oem_end));
                if (ret != 0) {
                    fs_codepage_patch_result = "patch_str_unicode2oem failed";
                    break;
                }

                // R4: StringDesc_ToUpper OEM 分支 ASCII-only 替换
                // （原版对 signed char 调 toupper，高位字节未定义行为）。
                // 替换函数体必须 ≤0xD0（0x71000f7ce0 是下一个函数）。
                fs_stage("r4_toupper");
                const u8 exfat_StringDesc_ToUpper[16] = {
                    0xFD, 0x7B, 0xBD, 0xA9, 0xF5, 0x0B, 0x00, 0xF9,
                    0xF4, 0x4F, 0x02, 0xA9, 0xFD, 0x03, 0x00, 0x91
                };
                ret = fs_patch_function(handle, mem_info.addr + 0xf7c10, exfat_StringDesc_ToUpper, sizeof(exfat_StringDesc_ToUpper),
                    (void *)patch_stringdesc_toupper, (int)patch_code_size(patch_stringdesc_toupper, patch_stringdesc_toupper_end));
                if (ret != 0) {
                    fs_codepage_patch_result = "patch_stringdesc_toupper failed";
                    break;
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
            fs_stage_log_path = enable_logging ? log_path : nullptr;
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
