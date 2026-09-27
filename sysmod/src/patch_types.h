#pragma once
// sys-patch 共享补丁类型：pattern 字符串解析、补丁数据、补丁结果。
// main.cpp（通用补丁）与 fs_codepage.cpp（fs 字符集补丁）共用。

#include <cstring>
#include "switch.h"

// pattern 字符串里的通配槽（str2hex 遇到 '.' 时写入）
constexpr u16 REGEX_SKIP = 0x100;

// 补丁扫描的读内存块大小（main 与 fs 补丁共用；fs 的分块 overlap 建立在其上）
constexpr u64 READ_BUFFER_SIZE = 0x1000;

// 把 "0xAB.CD.." 之类的 pattern 字符串在编译期解析成字节数组：
// 两个十六进制字符 = 一个字节；一个 '.' = 一个通配槽（REGEX_SKIP）。
// 注意：是**逐字符**解析 —— 相邻两个 '.' 就是两个独立的通配字节。
// 非法字符会导致编译期错误（hexstr_2_nibble 无返回分支）。
template<typename T>
constexpr void str2hex(const char* s, T* data, u8& size) {
    // skip leading 0x (if any)
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }

    constexpr auto hexstr_2_nibble = [](char c) -> u8 {
        if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
        if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
        if (c >= '0' && c <= '9') { return c - '0'; }
    };

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

// 搜索模板：data 容量须覆盖最长 pattern（构建期守卫按 PATTERN_MAX 校验）
struct PatternData {
    constexpr PatternData(const char* s) {
        str2hex(s, data, size);
    }

    u16 data[60]{};
    u8 size{};
};

// 补丁数据：既可由 pattern 字符串构造（固定字节），也可由 u32/u64 构造
// （指令改写现场算出的机器码）
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

    u8 data[20]{};
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

inline auto patch_result_to_str(PatchResult result) -> const char* {
    switch (result) {
        case PatchResult::NOT_FOUND: return "Unpatched";
        case PatchResult::SKIPPED: return "Skipped";
        case PatchResult::DISABLED: return "Disabled";
        case PatchResult::PATCHED_FILE: return "Patched (file)";
        case PatchResult::PATCHED_SYSPATCH: return "Patched (sys-patch)";
        case PatchResult::FAILED_WRITE: return "Failed (svcWriteDebugProcessMemory)";
        case PatchResult::FAILED_HARVEST: return "Failed (fs ctx harvest)";
    }

    return "Unknown";
}
