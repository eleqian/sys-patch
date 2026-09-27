// ============================================================================
// fs 字符集补丁（fork 专属）：把 fs 的 CP932 (Shift-JIS)↔UTF-16 例程替换为
// UTF-8↔UTF-16，使 FAT/exFAT 支持 3 字节 CJK 文件名。
//
// 文件结构（按出现顺序）：
//   §0 具名常量   把魔鬼数字收成有含义的名字（全部编译期常量）
//   §1 patch_*    会被整段拷进 fs 执行的替换实现（7 个）
//   §2 rules_*    指令改写条目用的 cond/patch 函数对
//   §3 表结构     谓词清单 + FsBlobImpl / FsInstPatch / FsBlobPatch / FsFnGroup
//   §4 补丁表      fs_fn_groups / fs_inst_patches / fs_blob_patches
//   §5 扫描器      谓词位图、族退役、两条扫描循环
//   §6 现场收割    把替换体里的哨兵占位改成真实地址
//   §7 入口与日志  fs_codepage_patch() / fs_codepage_write_log()
//
// 定位方式：pattern 驱动，无硬编码 fs 偏移。每条补丁位配一条跨版本通配 pattern
// （一个 '.' = 一个通配字节），在 fs 的 .text 里搜索，随版本变化的字节写成通配。
// 指令改写条目的补丁字节由 rules_*(inst) 从命中的真实指令现场算出（寄存器/偏移/
// 访问宽度全部继承）；整函数替换条目的 pattern 只负责定位。每条 pattern 保证恰好
// 唯一命中，未命中只记 NOT_FOUND、一个字节都不写 ⇒ 换到未验证的固件时最坏是安全
// 失败。表格式由构建期守卫 tools/check_patch_sizes.py 从源码文本解析校验，改格式
// 必须同步它和 fs_encode_fix/fs_fw_audit.py。
//
// ★ ASLR 纪律：§1 的函数会被**原样拷贝**进 fs 地址空间执行，而模块加载地址随机化
//   ⇒ 函数体内禁止任何绝对地址物化（MOVZ/MOVK 宽常量、字面量池、LDR-literal），
//   禁止调用外部函数或引用外部数据（含 `&函数名` —— -fPIE 下会走指针槽）。
//   唯一的版本相关值 —— fs 编码上下文槽与外部 callee —— 由补丁器在覆写前
//   **现场收割**（§6）：替换体里放哨兵占位，收割器从即将被覆写的原版函数字节里
//   读出原版自己的取址对、按占位指令的真实地址重编码覆写。这些不变量由守卫逐函数校验。
// ============================================================================

#include <span>
#include <iterator> // std::size
#include <algorithm> // std::min
#include <bit> // std::countr_zero
#include <utility> // std::unreachable
#include <cstring>
#include <cstddef> // offsetof
#include "switch.h"
#include "minIni/minIni.h"
#include "patch_types.h"
#include "fs_codepage.h"

// ───────────────────────────────────────────────────────────────────────────
// §0 具名常量 —— 全部是编译期常量，展开后与原字面量逐位相同（不改代码生成）
// ───────────────────────────────────────────────────────────────────────────

/* fs 名字对象的「编码/宽度」选择子。它在两种对象里落在同一个槽、但极性相反。 */
constexpr u32 ENCODE_OEM     = 1;    // StringDesc::encode_type == 1 ⇒ OEM（单字节名字）
constexpr u16 NAME_ENC_UTF16 = 1;    // FsNameDesc16::enc == 1 ⇒ UTF-16（每次推进 2 字节）

/* FAT_GetNextChar 的第二参数：决定走哪条转换路径。 */
constexpr u32 FS_ENC_OEM2UNI = 1;    // 路径 A：OEM → Unicode 后折叠返回
constexpr u32 FS_ENC_UNI2OEM = 0;    // 路径 C：Unicode → OEM 后返回

/* fs 代码页上下文（PFCODE_CODE_PAGE_CONTEXT）里本实现用到的槽。 */
constexpr u32 FS_CTX_OEM2UNI      = 0x18;  // (oem_bytes, wchar_out) 转换器
constexpr u32 FS_CTX_UNI2OEM      = 0x20;  // (wchar_in, oem_bytes_out) 转换器
constexpr u32 FS_CTX_MBLEN        = 0x30;  // (lead, 1) → 后续字节数，0 = 单字节
constexpr u32 FS_CTX_FLAGS        = 0x48;  // 特殊映射标志
constexpr u32 FS_CTX_FLAG_SPECIAL = 2;     // 置位 ⇒ '.'/' ' 原样、其余 → '_'

/* isOEMMBchar 的 byte_idx 语义（原版 CP932 亦然）。 */
constexpr int FS_MBLEN_LEAD  = 1;    // 首字节：返回「后面还有几个字节」（0 = 单字节）
constexpr int FS_MBLEN_TRAIL = 2;    // 第二字节：是否为合法 UTF-8 续字节

/* UTF-8 编解码位模式。 */
constexpr u8  UTF8_1B_MAX       = 0x7F;    // 0xxxxxxx
constexpr u8  UTF8_2B_PREFIX    = 0xC0;    // 110xxxxx
constexpr u8  UTF8_3B_PREFIX    = 0xE0;    // 1110xxxx
constexpr u8  UTF8_4B_PREFIX    = 0xF0;    // 11110xxx（需代理对，本实现不支持）
constexpr u8  UTF8_CONT_PREFIX  = 0x80;    // 10xxxxxx
constexpr u8  UTF8_CONT_MASK    = 0xC0;    // 取续字节前导 2 位
constexpr u8  UTF8_LEAD2_MASK   = 0xE0;    // 判 2 字节前导用（注意：数值同 3 字节前导）
constexpr u8  UTF8_LEAD3_MASK   = 0xF0;
constexpr u8  UTF8_LEAD4_MASK   = 0xF8;
constexpr u8  UTF8_PAYLOAD_4    = 0x0F;    // 3/4 字节前导里的码点载荷位数
constexpr u8  UTF8_PAYLOAD_5    = 0x1F;    // 2 字节前导里的载荷
constexpr u8  UTF8_PAYLOAD_6    = 0x3F;    // 续字节 / 1 字节 UTF-16 的载荷
constexpr u16 UTF16_1B_MAX      = 0x007F;  // 能编成 1 字节 UTF-8 的上界
constexpr u16 UTF16_2B_MAX      = 0x07FF;  // 能编成 2 字节 UTF-8 的上界

/* ASCII / 全角 的大小写折叠。 */
constexpr u32 ASCII_CASE_BIT        = 'a' - 'A';  // 0x20：小写减去它 = 大写
constexpr u32 ASCII_ALPHA_LEN       = 26;         // 'z' − 'a' + 1
constexpr u32 FULLWIDTH_FOLD_OFFSET = 0xBF;       // 'ａ'(U+FF41) + 它 == 0x10000

/* 名字比较值 / 16 位参数只取低 16 位（为 0 ⇒ 名字已尽）；低 8 位掩码用于判 NUL。 */
constexpr u32 MASK16 = 0xFFFF;
constexpr u32 MASK8  = 0xFF;

/* 名字缓冲上界（原版即如此）：再推进一次（2/1 字节）就正好越过缓冲区。 */
constexpr u32 NAME_POS_MAX_UTF16 = 0x20A;
constexpr u32 NAME_POS_MAX_OEM   = 0xB;

/* 有界 Unicode2OEM 的输出上界（含结尾 NUL）：取两个目标缓冲的更窄者
 * （lname[513] 与 FAT_MakeShortName 的 512 B 栈缓冲）。 */
constexpr u32 FS_OEM_OUT_MAX    = 512;
constexpr u32 FS_OEM_BOUND_STEP = 4;   // 单轮判界余量：最坏 3 字节字符 + 结尾 NUL

/* isOEMMBchar 的额外字节数上界：≥ 4 视为非法（UTF-8 最多 3 个续字节）。 */
constexpr u32 FS_UTF8_EXTRA_MAX = 4;
constexpr u32 BYTE_TOP_BITS     = 24;  // 把 1 个字节移到 u32 最高位（clz 计数用）

/* 转换例程的打包返回值：高半 = 输出字节数，低半 = 输入字节数（与原版 CP932 例程
 * `mov w0,#len; mov w1,#2; b ConvertWidth` 的口径一致）。 */
constexpr u32 FS_CONV_OUT_SHIFT = 16;
constexpr u32 FS_IN_BYTES_UTF16 = 2;

/* 通配符模式字符。 */
constexpr u32 PAT_STAR = '*';
constexpr u32 PAT_QUES = '?';

/* 名字比较值里各字节的移位（24 位单射值：b0 | b1<<8 | b2<<16）。原版最远只到第 2 字节。 */
constexpr u32 NAME_BYTE1_SHIFT = 8;
constexpr u32 NAME_BYTE2_SHIFT = 16;

/* 现场收割的哨兵占位（值任意，只需唯一、成对相邻、按序；守卫按值核对）。
 * 用宏而非 constexpr —— 它们要同时出现在 C++ 与 `.inst` 指令串里，后者靠
 * FS_ASM_STR() 把宏值字符串化（C++ 字符串字面量本身不会被预处理宏展开）。 */
#define FS_CTX_SENTINEL_A  0xDEAD0001
#define FS_CTX_SENTINEL_B  0xDEAD0002
#define FS_CALL_SENTINEL_A 0xDEAD0003
#define FS_CALL_SENTINEL_B 0xDEAD0004
#define FS_ASM_STR_(x) #x
#define FS_ASM_STR(x)  FS_ASM_STR_(x)

// ───────────────────────────────────────────────────────────────────────────
// §1 拷入 fs 的替换实现（独立 .text.<函数名> section；函数体后紧跟 <函数名>_end
// 汇编标签，尺寸 = 标签地址 − 函数地址，由构建期守卫校验）
// ───────────────────────────────────────────────────────────────────────────

/* fs 交给被替换函数的「轻量对象视图」：StringDesc / 字符迭代器 / 模式流三处内存
 * 布局完全一致（+0x00、+0x08 各一个 8 字节字段；+0x10 一个「编码/宽度」选择子），
 * 故统一按 fs 原型的 StringDesc 命名，只保留一份定义（static_assert 钉死）。
 * +0x14 的保留字段一并声明，使结构体恰为 24 B、无尾部填充 —— 整对象拷贝 `*ps` 的
 * 字节数因此完全确定，不依赖编译器对 padding 的处理。 */
typedef struct {
    void *ptr_left;    /* +0x00  左指针 / 游标 cur */
    void *ptr_right;   /* +0x08  右指针 / 末尾 end */
    u32   encode_type; /* +0x10  ENCODE_OEM / 宽度（== 1 ⇒ 单字节读） */
    u32   reserved;    /* +0x14  原 StringDesc 保留字段，本实现不碰 */
} StringDesc;

static_assert(sizeof(StringDesc) == 24, "StringDesc 必须是 24 字节（三个 fs 对象视图共用）");
static_assert(offsetof(StringDesc, ptr_left) == 0x00 && offsetof(StringDesc, ptr_right) == 0x08
              && offsetof(StringDesc, encode_type) == 0x10 && offsetof(StringDesc, reserved) == 0x14,
              "StringDesc 字段偏移（ptr_left/ptr_right/encode_type/reserved）");

extern "C" {
// 续字节校验：3/4 字节分支必须确认 in[1..3] 是合法续字节（10xxxxxx），
// 防止路径尾截断时越界读、并防止与调用方步进失步。
static inline bool utf8_cont_ok(u8 b) { return (b & UTF8_CONT_MASK) == UTF8_CONT_PREFIX; }

// UTF-8 → UTF-16 单字符转换。返回值 = (输入字节数 << 16) | 输出 UTF-16 字节数。
// 非法输入按 1 字节 '_' 处理；4 字节序列（U+10000~，需代理对）不支持，输出 '_'。
__attribute__((used, section(".text.patch_utf8_to_utf16")))
static int patch_utf8_to_utf16(const u8 *utf8_in, u16 *utf16_out) {
    u32 cp = 0;
    const u8 first = utf8_in[0];
    int utf8_len = 0;

    if (first <= UTF8_1B_MAX) {                                 /* 1 字节：0xxxxxxx */
        cp = first;
        *utf16_out = (u16)cp;
        utf8_len = 1;
    } else if ((first & UTF8_LEAD2_MASK) == UTF8_2B_PREFIX) {   /* 2 字节：110xxxxx */
        if (!utf8_cont_ok(utf8_in[1])) {
            *utf16_out = L'_';
            return (1 << FS_CONV_OUT_SHIFT) | FS_IN_BYTES_UTF16;
        }
        cp = ((first & UTF8_PAYLOAD_5) << 6) | (utf8_in[1] & UTF8_PAYLOAD_6);
        *utf16_out = (u16)cp;
        utf8_len = 2;
    } else if ((first & UTF8_LEAD3_MASK) == UTF8_3B_PREFIX) {   /* 3 字节：1110xxxx */
        if (!utf8_cont_ok(utf8_in[1]) || !utf8_cont_ok(utf8_in[2])) {
            *utf16_out = L'_';
            return (1 << FS_CONV_OUT_SHIFT) | FS_IN_BYTES_UTF16;
        }
        cp = ((first & UTF8_PAYLOAD_4) << 12) | ((utf8_in[1] & UTF8_PAYLOAD_6) << 6)
             | (utf8_in[2] & UTF8_PAYLOAD_6);
        *utf16_out = (u16)cp;
        utf8_len = 3;
    } else if ((first & UTF8_LEAD4_MASK) == UTF8_4B_PREFIX) {   /* 4 字节：不支持 */
        if (!utf8_cont_ok(utf8_in[1]) || !utf8_cont_ok(utf8_in[2]) || !utf8_cont_ok(utf8_in[3])) {
            *utf16_out = L'_';
            return (1 << FS_CONV_OUT_SHIFT) | FS_IN_BYTES_UTF16;
        }
        *utf16_out = L'_';
        utf8_len = 4;
    } else {                                                    /* 非法首字节 */
        *utf16_out = L'_';
        utf8_len = 1;
    }

    return (utf8_len << FS_CONV_OUT_SHIFT) | FS_IN_BYTES_UTF16;
}

__asm__(".section .text.patch_utf8_to_utf16,\"ax\",@progbits\n\t.global patch_utf8_to_utf16_end\npatch_utf8_to_utf16_end:\n\t.previous");
}

extern "C" {
// UTF-16 → UTF-8 单字符转换（1~3 字节）。返回 (utf8_len << 16) | 2
// —— 高半 = 输出字节数、低半 = 输入 UTF-16 字节数（2），与原版 CP932 例程
// `mov w0,#len; mov w1,#2; b ConvertWidth` 的打包口径一致。
//
// ★ 三条分支都写满 [0..2]，但**短分支的 NUL 落点**是与原版逐位一致的硬约束：
//   原版 1 字节路径是 `strb wT,[x1]` + `strb wzr,[x1,#1]`（NUL 在 [1]），只写 [2]
//   会让 [1] 残留旧字节。故 1/2 字节分支在 [1]/[2] 各补一个 NUL。
// ★ 3 字节输出是 fork 的固有代价：所有经 ctx[UNI2OEM] 的调用点都必须容得下 3 字节
//   （调用方按返回值高半推进输出指针）。
__attribute__((used, section(".text.patch_utf16_to_utf8")))
static int patch_utf16_to_utf8(const u16 *utf16_in, u8 *utf8_output)
{
    const u16 utf16_char = *utf16_in;
    int utf8_len = 0;

    if (utf16_char <= UTF16_1B_MAX) {
        utf8_output[0] = (uint8_t)utf16_char;
        utf8_output[1] = '\0';      /* 与原版一致：短分支的 NUL 在 [1] */
        utf8_output[2] = '\0';
        utf8_len = 1;
    } else if (utf16_char <= UTF16_2B_MAX) {
        utf8_output[0] = UTF8_2B_PREFIX | (uint8_t)(utf16_char >> 6);
        utf8_output[1] = UTF8_CONT_PREFIX | (uint8_t)(utf16_char & UTF8_PAYLOAD_6);
        utf8_output[2] = '\0';
        utf8_len = 2;
    } else {
        utf8_output[0] = UTF8_3B_PREFIX | (uint8_t)(utf16_char >> 12);
        utf8_output[1] = UTF8_CONT_PREFIX | (uint8_t)((utf16_char >> 6) & UTF8_PAYLOAD_6);
        utf8_output[2] = UTF8_CONT_PREFIX | (uint8_t)(utf16_char & UTF8_PAYLOAD_6);  /* 非 NUL */
        utf8_len = 3;
    }

    return (utf8_len << FS_CONV_OUT_SHIFT) | FS_IN_BYTES_UTF16;
}

__asm__(".section .text.patch_utf16_to_utf8,\"ax\",@progbits\n\t.global patch_utf16_to_utf8_end\npatch_utf16_to_utf8_end:\n\t.previous");
}

extern "C" {
// isOEMMBchar 替换：按 byte_idx 区分两种语义（原版 CP932 亦然）—— 首字节问「后面
// 还有几个字节」（补丁点用它做步进），第二字节只判「是否合法 UTF-8 续字节」
// （FAT_GetNextPathComponent 用它校验多字节字符的第二字节）。
// 0xC0..0xFF 的额外字节数 = 前导 1 的个数 − 1，用 clz 一条指令算完才塞得进 0x50 的洞。
// ★ 不显式判 `c < 0xC0` —— 折进下面的**无符号**比较即可：c<0xC0 ⇒ extra ≤ 0
//   （负数以无符号看是巨值）、c≥0xF8 ⇒ extra ≥ 4，两种非法情形共用一次比较，省两条指令。
// 尺寸硬约束：≤0x50（洞之后是回调表引用的 stub）。
__attribute__((used, section(".text.patch_is_oem_mb_char")))
static int patch_is_oem_mb_char(u8 ch, int byte_idx)
{
    const unsigned c = ch;

    if (byte_idx != FS_MBLEN_LEAD) {
        /* 第二字节：按 >>6 判 10xxxxxx（比 and+cmp 省一条，且与原版同形） */
        return (byte_idx == FS_MBLEN_TRAIL) && ((c >> 6) == (UTF8_CONT_PREFIX >> 6));
    }
    const int extra = __builtin_clz(((~c) & MASK8) << BYTE_TOP_BITS) - 1;
    return ((unsigned)extra < FS_UTF8_EXTRA_MAX) ? extra : 0;
}

__asm__(".section .text.patch_is_oem_mb_char,\"ax\",@progbits\n\t.global patch_is_oem_mb_char_end\npatch_is_oem_mb_char_end:\n\t.previous");
}

extern "C" {
// 有界版 Unicode→OEM 字符串转换。原版对输出缓冲无上限，UTF-8 下 ≥171 个 CJK
// 字符即写溢出；本实现把整个写入（含结尾 NUL）限制在 FS_OEM_OUT_MAX 字节以内。
// ★ 判界必须按**最坏单字符宽度**：每轮先确认「本字符最多 3 字节 + 结尾 NUL」都还在
//   缓冲里，循环后写 NUL 才必然落在界内。只判 `out < limit` 不够 —— 逐字节写会让 out
//   越过 limit 1~2 字节。
// ★ 开头的哨兵对是 ctx 槽的占位指令，由补丁器现场收割（§6）；失败 ⇒ 整点不写。
// 普通模式内联 UTF-16→UTF-8；特殊映射模式直接比较 u16。返回值恒 0（与原版一致）。
// 尺寸硬约束：≤0x120（之后是下一个 fs 函数）。
__attribute__((used, section(".text.patch_str_unicode2oem")))
static int patch_str_unicode2oem(char *dst_oem, const u16 *src_uni)
{
    const u8 *ctx;
    __asm__ volatile(
        ".inst " FS_ASM_STR(FS_CTX_SENTINEL_A) "\n\t"
        ".inst " FS_ASM_STR(FS_CTX_SENTINEL_B) "\n\t"
        "mov %0, x3\n"
        : "=r"(ctx)
        :
        : "x3");
    u8 *out = (u8 *)dst_oem;
    u8 *const limit = out + FS_OEM_OUT_MAX;     /* 可用字节数（含结尾 NUL） */
    const u16 *in = src_uni;

    if (ctx[FS_CTX_FLAGS] & FS_CTX_FLAG_SPECIAL) {
        /* 特殊映射模式：'.'→'.'、' '→' '、其余→'_' */
        while (*in != 0 && (u32)(limit - out) >= FS_OEM_BOUND_STEP) {
            const u16 c = *in++;
            *out++ = (c == '.') ? '.' : ((c == ' ') ? ' ' : '_');
        }
    } else {
        /* 普通转换模式：内联 UTF-16→UTF-8（1~3 字节/字符） */
        while (*in != 0 && (u32)(limit - out) >= FS_OEM_BOUND_STEP) {
            const u16 c = *in++;
            if (c <= UTF16_1B_MAX) {
                *out++ = (u8)c;
            } else if (c <= UTF16_2B_MAX) {
                *out++ = (u8)(UTF8_2B_PREFIX | (c >> 6));
                *out++ = (u8)(UTF8_CONT_PREFIX | (c & UTF8_PAYLOAD_6));
            } else {
                *out++ = (u8)(UTF8_3B_PREFIX | (c >> 12));
                *out++ = (u8)(UTF8_CONT_PREFIX | ((c >> 6) & UTF8_PAYLOAD_6));
                *out++ = (u8)(UTF8_CONT_PREFIX | (c & UTF8_PAYLOAD_6));
            }
        }
    }
    *out = '\0';                                /* out ≤ limit-1 ⇒ 落在缓冲内 */
    return 0;
}

__asm__(".section .text.patch_str_unicode2oem,\"ax\",@progbits\n\t.global patch_str_unicode2oem_end\npatch_str_unicode2oem_end:\n\t.previous");
}

extern "C" {
// StringDesc_ToUpper 替换：OEM 分支改 ASCII-only（仅 'a'-'z' 大写，非 ASCII 字节原样
// 保留 —— 原版把高位字节当 signed char 传给 ctype 表是未定义行为）；Unicode 分支与原版
// 逐句一致。尺寸硬约束：≤0xB0（各固件变体实测最小洞）。
__attribute__((used, section(".text.patch_stringdesc_toupper")))
static void patch_stringdesc_toupper(StringDesc *path, short maxLen, char *dst)
{
    if (path->encode_type != ENCODE_OEM) {
        u16 *p = (u16 *)path->ptr_left;
        u16 *d = (u16 *)dst;
        while (maxLen != 0) {
            u16 c = *p++;
            if (c == 0) {
                break;
            }
            if ((unsigned)(c - 'a') < ASCII_ALPHA_LEN) {
                c = (u16)(c - ASCII_CASE_BIT);
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
            if ((unsigned)(c - 'a') < ASCII_ALPHA_LEN) {
                c = (u8)(c - ASCII_CASE_BIT);
            }
            *dst++ = (char)c;
            p++;
            maxLen--;
        }
        *dst = '\0';
    }
}

__asm__(".section .text.patch_stringdesc_toupper,\"ax\",@progbits\n\t.global patch_stringdesc_toupper_end\npatch_stringdesc_toupper_end:\n\t.previous");
}

extern "C" {
/* WideChar_Compare 整函数替换（把原版散落在该函数里的 15 个指令补丁点折叠成一份实现）：
 * 编码域感知的宽字符通配符匹配 —— '*' / '?' + 递归回溯。
 *
 * 对象布局（由调用方反推并经差分自测确认）：
 *   FsNameDesc16 = {u64 data; u16 enc; u16 pos; u32 pad}（16 B，x1）
 *     enc == 1 → UTF-16（pos 步进 2），否则 OEM（步进 1）；pos 是越过当前字符的字节
 *     偏移，data 是裸缓冲。
 *   StringDesc（模式流视图，x3）：ptr_left/ptr_right 是游标与末尾，encode_type 是
 *     宽度选择子。这只是布局同型的**另一个**对象，不是名字的那个 StringDesc。
 *   调用约定：调用者先推进一次 name desc、折叠当前名字字符，再取到第一个模式字符。
 *
 * ★ 语义目标：**原版行为 × 24 位比较值意图**（不是与那 15 点补丁逐位对偶）。两处必须
 *   复刻的原版细节：+FULLWIDTH_FOLD_OFFSET 全角折叠判定、OEM 名缓冲上界。唯一刻意
 *   偏离原版机器码的是 ASCII 折叠写法（见 fold_ascii_upper）。
 * ★ 两对哨兵占位由补丁器现场收割（§6），失败 ⇒ 整点不写，哨兵永远不会被执行到；
 *   哨兵按**内容**查找（成对相邻、按序），与位置无关。自递归 bl 相对自身 PC，
 *   整段拷贝后偏移恒等，允许由编译器直接发射。
 * 尺寸硬约束：≤0x360（三种固件形状的洞取最小）。 */
typedef struct { u64 data; u16 enc; u16 pos; u32 pad; } FsNameDesc16;   /* 16 B */
typedef u32 (*FsNextChar)(StringDesc *, u32);                          /* 模式流读者（收割 callee）*/

/* ASCII 小写→大写（对已大写的值幂等）。名字侧与模式侧必须同形，否则两侧永远比不相等。
 * ★ 故意不写原版机器码的 `mov wT,#0xffe0; add` —— 那要靠 16 位比较丢掉进位才等价于
 *   `sub #0x20`；本实现用 32 位比较，必须写不带进位的减法，否则就是复刻旧 15 点补丁的
 *   bug（OEM 单字节名在星号回溯路径上匹配不到小写字母）。
 *   凭据：`_audit/_m6_sem_diff.py`（短串穷举 vs 原版 0 补丁）、`_audit/_m6_fold_probe.py`。 */
__attribute__((always_inline)) static inline u32 fold_ascii_upper(u32 c)
{
    return ((c - 'a') < ASCII_ALPHA_LEN) ? (c - ASCII_CASE_BIT) : c;
}

/* 名字字符归一化：ASCII 小写→大写，全角小写→半角大写。第二段的 & MASK16 是原版就有
 * 的（全角 'ａ' + FULLWIDTH_FOLD_OFFSET == 0x10000，掩掉才是 0 ⇒ 折叠）。 */
__attribute__((always_inline)) static inline u32 wc_fold2(u32 c)
{
    c = fold_ascii_upper(c);
    if (((c + FULLWIDTH_FOLD_OFFSET) & MASK16) < ASCII_ALPHA_LEN) { c -= ASCII_CASE_BIT; }
    return c;
}

/* fs 多字节长度回调：ctx[MBLEN](首字节, 1) → 后续字节数（0 = 单字节）。
 * 本函数对 fs 上下文的唯一依赖（另一处是被收割的取模式字符 callee）。 */
__attribute__((always_inline)) static inline u32 wc_mb_len(const u8 *ctx, u32 lead)
{
    return (*(u32 (*)(u32, u32))(*(const void **)(ctx + FS_CTX_MBLEN)))(lead, 1u);
}

/* 读名字流的下一个字符并推进 desc；名字耗尽返回 0。返回折叠后的比较值：
 *   UTF-16：读 2 字节、两段折叠；
 *   OEM：读 1 字节，若 fs 判为多字节首字节再补读 2 字节，拼成 24 位比较值
 *        （杜绝 2 字节截断碰撞）；折叠只做 ASCII 单段。
 * 上界与原版一致：再推进一次（2/1 字节）就正好越过名字缓冲区。 */
__attribute__((always_inline)) static inline u32 wc_next_name_char(FsNameDesc16 *d, const u8 *ctx)
{
    u8 *p = (u8 *)d->data;
    const u32 pos = d->pos;

    if (d->enc == NAME_ENC_UTF16) {                  /* UTF-16：2 字节一步 */
        if (pos > NAME_POS_MAX_UTF16) { return 0u; }
        const u32 c = *(const u16 *)(p + pos);
        d->pos = (u16)(pos + 2);
        return wc_fold2(c);
    }
    if (pos > NAME_POS_MAX_OEM) { return 0u; }       /* OEM：1 字节起步 */
    u32 c = p[pos];
    d->pos = (u16)(pos + 1);
    const u32 n = wc_mb_len(ctx, c);
    if (n != 0u) {                                   /* 多字节：再吃 2 字节拼 24 位 */
        c = ((u32)*(const u16 *)(p + pos + 1)) | (c << NAME_BYTE2_SHIFT);
        d->pos = (u16)(pos + 1 + n);
    }
    return fold_ascii_upper(c);
}

__attribute__((noinline, used, optimize("Os"),
               section(".text.patch_widechar_compare")))
static u32 patch_widechar_compare(u32 name_char, FsNameDesc16 *nd,
                                  u32 pat_char, StringDesc *ps)
{
    const u8 *ctxp;
    FsNextChar nx;
    __asm__ volatile(
        ".inst " FS_ASM_STR(FS_CTX_SENTINEL_A) "\n\t"
        ".inst " FS_ASM_STR(FS_CTX_SENTINEL_B) "\n\t"
        ".inst " FS_ASM_STR(FS_CALL_SENTINEL_A) "\n\t"
        ".inst " FS_ASM_STR(FS_CALL_SENTINEL_B) "\n\t"
        "mov %0, x3\n\t"
        "mov %1, x9\n"
        : "=r"(ctxp), "=r"(nx)
        :
        : "x3", "x9");
    const u8 *ctx = *(const u8 *const *)ctxp;

    /* 主循环。不变量：name_char = 名字当前字符（调用者已折叠；低 16 位 0 = 名字已尽），
     * pat_char = 模式当前字符（0 = 模式已尽）。 */
    for (;;) {
        if (pat_char == PAT_QUES) {
            /* '?'：通配任意一个字符，但名字必须还有字符。 */
            if ((name_char & MASK16) == 0u) { return 0u; }
        } else if (pat_char == 0u) {
            return (name_char & MASK16) == 0u;      /* 模式尽：名字也尽才算匹配 */
        } else if (pat_char == PAT_STAR) {
            /* '*'：吞掉模式里连续的 '*'/'?'，停在第一个普通字符或模式尾（nx 仍会推进
             * ps，与原版一致）；再让首个普通字符依次尝试名字的每个位置。 */
            do {
                pat_char = nx(ps, nd->enc);
            } while (pat_char == PAT_STAR || pat_char == PAT_QUES);
            if (pat_char == 0u) { return 1u; }               /* 尾部 '*'：通配到底 */
            if ((name_char & MASK16) == 0u) { return 0u; }   /* '*' 之后名字已尽 */
            const u32 target = pat_char;
            for (;;) {
                if (name_char == target) {
                    /* 命中 ⇒ 在状态**副本**上递归（原 nd/ps 不动 ⇒ 失败可无损回退）。 */
                    FsNameDesc16 nd2 = *nd;
                    StringDesc   ps2 = *ps;
                    const u32 next_name = wc_next_name_char(&nd2, ctx);
                    const u32 next_pat  = nx(&ps2, nd->enc);
                    if (patch_widechar_compare(next_name, &nd2, next_pat, &ps2) != 0u) {
                        return 1u;
                    }
                }
                name_char = wc_next_name_char(nd, ctx);
                if ((name_char & MASK16) == 0u) { return 0u; }
            }
        } else if (name_char != pat_char) {
            return 0u;                              /* 普通字符：24 位精确比较 */
        }
        name_char = wc_next_name_char(nd, ctx);      /* 匹配掉一个字符，两侧各推进一次 */
        pat_char = nx(ps, nd->enc);
    }
}

__asm__(".section .text.patch_widechar_compare,\"ax\",@progbits\n\t.global patch_widechar_compare_end\npatch_widechar_compare_end:\n\t.previous");
}

/* ══ FAT_GetNextChar 整函数替换（把原版 4 个相邻的指令补丁点折叠成一份实现）══
 * 原函数取「名字流的下一个字符」并折叠成比较值。4 个补丁点全落在同一个 24 B 基本块内，
 * 折叠点分别是：步进量 #1 → 运行期宽度 n；ldrb → ldrh；strb → sturh；lsl #8 → lsl #16
 * （拼 24 位比较值，避开 2 字节截断碰撞）。
 * 可行性依据：本函数 bl = 0（无直接外部调用）。唯一的外部依赖是 fs 编码上下文槽 ——
 * 三个回调都是 `ldr xN,[ctx,#off] + blr xN`，收割 ctx 槽后自动指向已被替换的转换器
 * （与 WideChar_Compare 收割的是同一个槽）。
 * ★ 差分纪律：目标是与「4 点指令级补丁全打」逐位等价，不是"写得更正确"；原版怪癖
 *   （全角折叠判定、rev+lsr 字节序重排、两处分别的 csel 折叠、双字节路径的判空写法）
 *   全部原样复刻。
 * 尺寸硬约束：≤0x240（各固件变体实测最小洞）。 */

/* ctx 回调签名（都是 `ldr xN,[ctx,#off]` + `blr xN`，收割槽后自动正确）。 */
typedef void (*FsConvert)(const void *src, void *dst);
typedef u32 (*FsMbLen)(u32 lead, u32 one);

/* 全角小写→半角大写（全角平假名区间判定，与 wc_fold2 的第二段同源）。 */
__attribute__((always_inline)) static inline u32 gnc_fold_full(u32 c)
{
    return (((c + FULLWIDTH_FOLD_OFFSET) & MASK16) < ASCII_ALPHA_LEN) ? (c - ASCII_CASE_BIT) : c;
}

/* patch_fat_getnextchar / patch_widechar_compare 包在 extern "C" 块里：构建期守卫按
 * **未改名**的符号（patch_* / *_end）从 ELF 取函数体做尺寸与位置无关性校验，而 C++
 * 语言链接会给静态函数改名。（extern "C" 不能与 static 写在同一处，故用块形式。） */
extern "C" {

/* 原函数栈帧槽（sp == st；x29 = sp + 0x10 ⇒ x29 − 4 == st + FS_ST_RET）。这些槽会被
 * 转换回调直接读写，必须真实存在于栈上 —— 一律经指针访问。 */
constexpr u32 FS_ST_PAIR    = 0x0;   /* 路径 D：OEM→Unicode 转换的输出（u16） */
constexpr u32 FS_ST_CHAR    = 0x4;   /* 字符缓冲：3 字节 + 1 字节对齐 */
constexpr u32 FS_ST_OEM2UNI = 0x8;   /* 路径 C：Unicode→OEM 转换的输出（u16） */
constexpr u32 FS_ST_RET     = 0xC;   /* 返回值暂存（= x29 − 4） */
constexpr u32 FS_ST_SIZE    = 0x10;  /* 帧大小（x29 = sp + 帧大小） */

__attribute__((noinline, used, optimize("Os"),
               section(".text.patch_fat_getnextchar")))
static u32 patch_fat_getnextchar(StringDesc *d, u32 enc)
{
    /* 哨兵对（ctx 槽地址，本函数唯一的版本相关量）由补丁器现场收割（§6）；失败 ⇒ 整点不写。 */
    const u8 *ctxp;
    __asm__ volatile(
        ".inst " FS_ASM_STR(FS_CTX_SENTINEL_A) "\n\t"
        ".inst " FS_ASM_STR(FS_CTX_SENTINEL_B) "\n\t"
        "mov %0, x3\n"
        : "=r"(ctxp)
        :
        : "x3");
    const u8 *ctx = *(const u8 *const *)ctxp;

    u8 st[FS_ST_SIZE];
    u8 *const chr = st + FS_ST_CHAR;
    *(u16 *)(st + FS_ST_PAIR)    = 0;
    *(u16 *)chr                  = 0;
    chr[2]                       = 0;
    *(u16 *)(st + FS_ST_OEM2UNI) = 0;
    *(u16 *)(st + FS_ST_RET)     = 0;

    u16 *const out = (u16 *)(st + FS_ST_RET);
    const u64 cur = (u64)d->ptr_left;
    const u32 e16 = enc & MASK16;
    u32 c;
    bool folded = false;

    if (d->encode_type == ENCODE_OEM) {
        /* ── 单字节名字（OEM / UTF-8）────────────────────────────────── */
        const u8 *p = (const u8 *)cur;
        d->ptr_left = (void *)(cur + 1);
        c = *p;
        chr[1] = 0;
        chr[0] = (u8)c;
        if (c == 0u) { return 0u; }                        /* 名字结束 */
        if ((u64)d->ptr_right < cur + 1) { return 0u; }    /* 越界 */
        const u32 n = ((FsMbLen)*(const void **)(ctx + FS_CTX_MBLEN))(c, 1u);
        if (n != 0u) {
            /* 折叠点：步进 n、按 2 字节读写、按 24 位拼值（原版只够 CP932 双字节）。 */
            const u32 hi = *(const u16 *)(p + 1);
            d->ptr_left = (void *)(cur + 1 + n);
            *(u16 *)(chr + 1) = (u16)hi;
            c = hi | (c << NAME_BYTE2_SHIFT);
        }
        *out = (u16)c;
        if (e16 == FS_ENC_OEM2UNI) {
            /* 路径 A：OEM→Unicode 转换后折叠返回 */
            ((FsConvert)*(const void **)(ctx + FS_CTX_OEM2UNI))(chr, out);
            return gnc_fold_full(fold_ascii_upper(*out));
        }
    } else {
        /* ── 2 字节名字（UTF-16）────────────────────────────────────── */
        const u32 v = *(const u16 *)cur;
        chr[0] = (u8)v;
        chr[1] = (u8)(v >> 8);
        chr[2] = 0;
        d->ptr_left = (void *)(cur + 2);
        if (((v | (v >> 8)) & MASK8) == 0u) { return 0u; }   /* 读到 NUL */
        if ((u64)d->ptr_right < cur + 2) { return 0u; }
        c = v & MASK16;
        *out = (u16)c;
        if (e16 == FS_ENC_UNI2OEM) {
            /* 路径 C：Unicode→OEM，再按首字节问这条 OEM 序列有多长 */
            ((FsConvert)*(const void **)(ctx + FS_CTX_UNI2OEM))(out, st + FS_ST_OEM2UNI);
            const u32 r32 = __builtin_bswap32(*(const u16 *)(st + FS_ST_OEM2UNI));
            *(u16 *)(st + FS_ST_OEM2UNI) = (u16)(r32 >> 16);
            const u32 r = ((FsMbLen)*(const void **)(ctx + FS_CTX_MBLEN))(r32 >> BYTE_TOP_BITS, 1u);
            const u32 w = *(const u16 *)(st + FS_ST_OEM2UNI);
            c = (r == 0u) ? (w >> 8) : w;
        } else {
            c = fold_ascii_upper(c);
            *out = (u16)c;
            folded = true;
            if (e16 == FS_ENC_OEM2UNI) { return gnc_fold_full(c); }
        }
    }

    /* 汇合点：路径 C 之后 c 是新算出来的，还没折叠 */
    if (!folded) {
        c = fold_ascii_upper(c);
        *out = (u16)c;
    }

    /* 路径 D：OEM→Unicode → 全角折叠 → Unicode→OEM → 字节序重排 */
    ((FsConvert)*(const void **)(ctx + FS_CTX_OEM2UNI))(chr, st + FS_ST_PAIR);
    const u32 v0 = *(const u16 *)(st + FS_ST_PAIR);
    if ((((v0 + FULLWIDTH_FOLD_OFFSET) & MASK16) >= ASCII_ALPHA_LEN)) { return *out; }
    *(u16 *)(st + FS_ST_PAIR) = (u16)(v0 - ASCII_CASE_BIT);
    ((FsConvert)*(const void **)(ctx + FS_CTX_UNI2OEM))(st + FS_ST_PAIR, st + FS_ST_PAIR);
    return __builtin_bswap32(*(const u16 *)(st + FS_ST_PAIR)) >> 16;
}

} // extern "C"

__asm__(".section .text.patch_fat_getnextchar,\"ax\",@progbits\n\t.global patch_fat_getnextchar_end\npatch_fat_getnextchar_end:\n\t.previous");

// 补丁函数运行期尺寸：独立 section + _end 标签（同 section 内的链接期常量距离），
// 构建期守卫校验「标签差 == ELF st_size」与「尺寸 ≤ 补丁位空洞」。
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
extern "C" const u8 patch_fat_getnextchar_end[];

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

// §2 改写规则：cond(inst) 判定「这就是要改的那类指令」，patch(inst) 现场算补丁 ——
// 寄存器/地址/访问宽度全部继承命中现场，规则本身与固件版本、寄存器分配无关。

/* 通配符里那一处 `add Rd,w25,#2` 的实测寄存器/立即数（该版本寄存器分配的定值）。 */
constexpr u32 WC_ADD_BASE_REG = 25;   // 原指令的基址寄存器 w25
constexpr u32 WC_ADD_IMM      = 2;    // 原立即数（CP932 双字节语义）
constexpr u32 WC_IDX_REG      = 27;   // 已算好 idx+1 的 callee-saved 寄存器 w27

/* BFI/BFM 立即数编码：immr = (32 − lsb) mod 32，imms = width − 1（width 恒 8）。 */
constexpr u32 BFM_IMMR_LSB8  = 24;   // BFI #8,#8  → immr
constexpr u32 BFM_IMMR_LSB16 = 16;   // BFI #16,#8 → immr
constexpr u32 BFM_IMMS_W8    = 7;    // width 8 − 1

/* FAT_MakeShortName 的拷贝宽度钳制值（防止 3 字节字符让 subs 永不归零）。 */
constexpr u32 FS_COPY_WIDTH_CLAMP = 2;

/* 该版本族在 MakeShortName 处直接写成 `movz wD,#imm`，立即数是形态指纹（不参与语义）。 */
constexpr u32 MSN_MOVZ_SRC_IMM = 0x2E;

/* AArch64 栈指针寄存器号。 */
constexpr u32 REG_SP = 31;

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

// 通配符里唯一一处 `add Rd,w25,#2`（CP932 双字节语义）：UTF-8 下需要「idx + 字符总长」，
// 而 w27 在本处之前已算好 idx+1（callee-saved），所以改用 w27 作基址：new = (idx+1) + w0。
constexpr bool rules_is_add_w25_2(u32 inst)
{
    return (inst & 0x7F000000u) == 0x11000000u &&
           rules_bit(inst, 9, 5) == WC_ADD_BASE_REG && rules_bit(inst, 21, 10) == WC_ADD_IMM;
}
constexpr PatchData rules_add_w25_2_to_add_w27(u32 inst)
{
    return PatchData{0x0B000000u | (WC_IDX_REG << 5) | rules_bit(inst, 4, 0)};
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
    return (inst & 0xFFC00000u) == 0x39000000u && rules_bit(inst, 9, 5) == REG_SP;
}
constexpr PatchData rules_strb_sp_to_sturh(u32 inst)
{
    const u32 imm = rules_bit(inst, 21, 10);
    const u32 rt = rules_bit(inst, 4, 0);
    return PatchData{0x78000000u | (imm << 12) | (REG_SP << 5) | rt};   // sturh wT,[sp,#imm]
}

// 比较值构造 orr wD,wN,wD,lsl #8 -> lsl #16，
// 把第 3 个字节放进高字节（配合下面去掉掩码/扩展，得到 24 位单射比较值）。
constexpr bool rules_is_orr_lsl8(u32 inst)
{
    return rules_bit(inst, 31, 31) == 0 && rules_bit(inst, 30, 29) == 0b01 &&
           rules_bit(inst, 28, 24) == 0b01010 && rules_bit(inst, 23, 22) == 0 &&
           rules_bit(inst, 21, 21) == 0 && rules_bit(inst, 15, 10) == NAME_BYTE1_SHIFT;
}
constexpr PatchData rules_orr_lsl8_to_16(u32 inst)
{
    return PatchData{rules_setbits(inst, 15, 10, NAME_BYTE2_SHIFT)};
}

// 16.1.0 把同一处写成了 BFI wD,wN,#8,#8；改为 #16,#8，语义与 orr lsl #16 相同。
constexpr bool rules_is_bfi_8_8(u32 inst)
{
    return rules_bit(inst, 31, 31) == 0 && rules_bit(inst, 30, 29) == 0b01 &&
           rules_bit(inst, 28, 23) == 0b100110 &&
           rules_bit(inst, 21, 16) == BFM_IMMR_LSB8 && rules_bit(inst, 15, 10) == BFM_IMMS_W8;
}
constexpr PatchData rules_bfi_8_8_to_16_8(u32 inst)
{
    return PatchData{rules_setbits(inst, 21, 16, BFM_IMMR_LSB16)};
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

// and wD,wN,#0xffff -> mov wD,wN（去掉 16 位掩码，保留第 3 个字节）
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

// cmp wD,wN,uxth -> cmp wD,wN（32 位下 UXTH 扩展是空操作，去掉后
// 比较的就是完整 24 位值；扩展寄存器形式要切回移位寄存器形式）
constexpr bool rules_is_cmp_uxth(u32 inst)
{
    return (inst & 0xFF20001Fu) == 0x6B20001Fu && rules_bit(inst, 15, 13) == 0b001;
}
constexpr PatchData rules_cmp_uxth_to_cmp(u32 inst)
{
    return PatchData{rules_setbits(inst, 15, 10, 0) & ~(1u << 21)};
}

// FAT_MakeShortName 把 OEMCharWidth 的返回值当字符宽度走 2 字节拷贝循环，
// UTF-8 的 3 字节字符会让循环永不归零（死循环）。
// mov wD,w0 -> mov wD,#2（钳制为 2，字节不丢、循环正常退出）
constexpr bool rules_is_mov_w0(u32 inst) { return (inst & 0xFFFFFFE0u) == 0x2A0003E0u; }
constexpr PatchData rules_mov_reg_to_movz2(u32 inst)
{
    return PatchData{0x52800000u | (FS_COPY_WIDTH_CLAMP << 5) | rules_bit(inst, 4, 0)};
}

// 21.x/22.x 把同一处折叠成了 `movz wD,#imm`（立即数是形态指纹，见 MSN_MOVZ_SRC_IMM）
constexpr bool rules_is_movz_2e(u32 inst)
{
    return (inst & 0xFF800000u) == 0x52800000u && rules_bit(inst, 20, 5) == MSN_MOVZ_SRC_IMM;
}
constexpr PatchData rules_movz_2e_to_movz2(u32 inst)
{
    return PatchData{rules_setbits(inst, 20, 5, FS_COPY_WIDTH_CLAMP)};
}

// ============================================================================
// 补丁表
//
// 一级：fs_fn_groups[]  —— 按「被改写的 fs 函数」分组，只管组织与日志进度。
// 二级：fs_inst_patches[]（指令改写）/ fs_blob_patches[]（整函数替换），两组各自
//       连续排布，组用下标切子区间。
//
// ⚠️ 行内格式由构建期守卫按正则从**源码文本**解析，改格式必须同步
//    tools/check_patch_sizes.py 与 fs_encode_fix/fs_fw_audit.py：
//   patch_name    log.ini 键名；格式 `<功能名>_<版本范围>`，族号 = 版本范围之前的
//                 功能前缀（fs_family_of）。范围沿用原 sys-patch：`a.b.c-d.e.f` 闭区间 /
//                 `a.b.c+` 开区间；非连续覆盖用 `,` 分段。
//   byte_pattern  定位模板；"0x" 之后一个 '.' = 一个通配字节
//   inst_offset   落点指令 = 命中处 + inst_offset（字长的倍数）
//   cond / patch  指令改写：cond(inst) 判定，patch(inst) 现场算等价新指令
//   entry_offset  整函数替换：函数入口 = 命中处 + entry_offset
//   impl          整函数替换：写哪个替换体（fs_blob_range）
// 没有门控列：补丁只有「整份生效」/「[options] fs_codepage=0 整份跳过」两态。
// ============================================================================

// §3 表结构 · 谓词清单 + 条目类型 ───────────────────────────────────────────────
// ── 谓词清单（唯一定义处：位号 = 列出次序）──────────────────────────────────
// 展开成两处：fs_preds[]（cond → 位号的反查表，条目表因此不需要 pred_idx 列）与
// fs_pred_mask()（每字一次的直调序列；位号是常量，全部折叠成立即数）。
#define FS_PRED_LIST(X)       \
    X(rules_is_bcond)         /* b.<cc> 条件分支 → nop */          \
    X(rules_is_add_imm)       /* add Rd,Rn,#imm → add Rd,Rn,w0 */  \
    X(rules_is_csel_cinc)     /* csel/cinc → 无条件 add Rd,Rn,w0 */ \
    X(rules_is_mov_w0)        /* mov wD,w0 → movz wD,#2 */         \
    X(rules_is_movz_2e)       /* movz wD,#0x2e → movz wD,#2 */

constexpr bool (*const fs_preds[])(u32 inst) = {
#define FS_PRED_ARRAY_ENTRY_(name) name,
    FS_PRED_LIST(FS_PRED_ARRAY_ENTRY_)
#undef FS_PRED_ARRAY_ENTRY_
};
constexpr u32 FS_PRED_COUNT = std::size(fs_preds);

// cond → 位号。返回 FS_PRED_COUNT 表示「不在清单里」：位图永不置它的位，该条目
// 永远命中不了（fs_pat_live 会拦住它，构建期守卫也会报错）。
constexpr u32 fs_pred_index(bool (*cond)(u32 inst))
{
    for (u32 k = 0; k < FS_PRED_COUNT; k++) {
        if (fs_preds[k] == cond) { return k; }
    }
    return FS_PRED_COUNT;
}

// 每字一掩码：bit k = 谓词 k 在该字上成立。nmask（本块需要算哪些谓词）在一整块内
// 恒定 ⇒ 分支可预测；谓词本体是 constexpr 位掩码测试，会被内联。
inline u32 fs_pred_mask(u32 inst, u32 nmask)
{
    u32 m = 0;
    u32 k = 0;
#define FS_PRED_TEST_(name)                                          \
    if ((nmask & (1u << k)) && name(inst)) { m |= (1u << k); }       \
    k++;
    FS_PRED_LIST(FS_PRED_TEST_)
#undef FS_PRED_TEST_
    return m;
}

// ── 整函数替换条目（换掉整个函数体）────────────────────────────────────────
// 这些点无法用「改一条指令」表达（转换器、isOEMMBchar、有界 Unicode2OEM、ASCII-only
// ToUpper、通配符匹配、FAT_GetNextChar），pattern 只负责定位。替换体签名各不相同，
// 表里存种类、运行期 fs_blob_range() switch 取址（放函数地址不是常量表达式）。

enum class FsBlobImpl : u8 {
    Utf16ToUtf8,     // patch_utf16_to_utf8
    Utf8ToUtf16,     // patch_utf8_to_utf16
    IsOemMbChar,     // patch_is_oem_mb_char
    WideCharCompare, // patch_widechar_compare
    FatGetNextChar,  // patch_fat_getnextchar
    StrUnicode2Oem,  // patch_str_unicode2oem
    StrDescToUpper,  // patch_stringdesc_toupper
};

struct FsBlobPatch {
    const char* patch_name;
    const PatternData byte_pattern;
    const s32 entry_offset;        // 函数入口 = pattern 命中处 + entry_offset
    const FsBlobImpl impl;

    PatchResult result{PatchResult::NOT_FOUND};
};

struct FsBlobRange {
    const void* code;
    u32 size;
};

struct FsFnGroup {
    const char* label;             // 进 [debug] fs_codepage_patch_result 的进度名
    u32 pat_begin, pat_end;
    u32 blob_begin, blob_end;
};

// 指令改写条目。落点指令读出后 cond(inst) 判定、patch(inst) 出等价新指令，
// 寄存器/地址/宽度全部继承自命中现场 ⇒ 与固件版本、寄存器分配无关。
struct FsInstPatch {
    const char* patch_name;
    const PatternData byte_pattern;
    const s32 inst_offset;

    bool (*const cond)(u32 inst);
    PatchData (*const patch)(u32 inst);

    // 谓词位号由 cond 推出（fs_pred_index）——表里没有这一列，
    // 「pred_idx 与 cond 脱节」这类改动因此从结构上不可能发生。
    const u8 pred_idx = (u8)fs_pred_index(cond);

    // 没有 applied 回调：谓词位图保证模板只在 cond 成立的位置才可能命中，
    // 「补丁已存在」的分支不可达。
    PatchResult result{PatchResult::NOT_FOUND};
};

// §4 补丁表 · ⚠️ 任何改动都必须通过构建期守卫 tools/check_patch_sizes.py
//    （结构不变量 + 唯一命中 + 落点指令满足 cond + 收割可行性）。
//
// 一级表：12 个函数组。四列 = 本组在 fs_inst_patches[] / fs_blob_patches[] 里的
// 下标区间（左闭右开）。注释里的地址 = 参考二进制 19.0.1/exfat 的实测函数入口，
// 由构建期守卫核对；进度日志打的也是 label。
constinit FsFnGroup fs_fn_groups[] = {
    { "IDirectory_Read          ",  0,  2,  0,  0 }, // 0xD4AF4   2 指令
    { "FAT_GetNextChar          ",  2,  2,  0,  2 }, // 0xF44E0   2 替换
    { "WideChar_Compare         ",  2,  2,  2,  6 }, // 0xF4770   4 替换
    { "FAT_GetNextPathComponent ",  2,  4,  6,  6 }, // 0xF4BBC   2 指令
    { "FAT_MakeShortName        ",  4,  6,  6,  6 }, // 0xF5AC0   2 指令
    { "StringDesc_AddLeft       ",  6,  8,  6,  6 }, // 0xF7788   2 指令
    { "StringDesc_GetCharCount  ",  8, 10,  6,  6 }, // 0xF7924   2 指令
    { "StringDesc_CompareUnicode", 10, 12,  6,  6 }, // 0xF79F4   2 指令
    { "StringDesc_CompareOem    ", 12, 15,  6,  6 }, // 0xF7B14   3 指令
    { "PFCODE_Converters        ", 15, 15,  6, 11 }, // -         5 替换
    { "PFCODE_Str_Unicode2OEM   ", 15, 15, 11, 14 }, // 0xF5840   3 替换
    { "StringDesc_ToUpper       ", 15, 15, 14, 16 }, // 0xF7C10   2 替换
};

// 15 条指令改写条目（顺序 = 上面各组的指令区间）。
// 名字 = `<功能名>_<版本范围>`（范围写法沿用原 sys-patch 约定：`a.b.c-d.e.f` 闭区间 /
// `a.b.c+` 开区间；非连续覆盖用 `,` 分段）。同一功能名的多条模板 = **跨版本互斥的
// 变体族**（见「族」机制：族号就是从名字里剥掉版本范围后的功能前缀）。
constinit FsInstPatch fs_inst_patches[] = {
    // IDirectory_Read：名字字符校验分支 b.<cc> → nop（否则非英文名一律被拒）
    { "fs_cp_idirectory_read_16.1.0+",          "0x.FD0151..0131...54", 8, rules_is_bcond, rules_nop },
    { "fs_cp_idirectory_read_14.1.2-15.0.1",    "0x.FDFF54.890051....", 0, rules_is_bcond, rules_nop },
    // FAT_GetNextPathComponent：步进 add Rd,Rn,#1 → add Rd,Rn,w0（按 UTF-8 字符长前进）
    { "fs_cp_fat_getnextpathcomp_step_15.0.1+", "0x.00805209050091690600F9", 4, rules_is_add_imm, rules_add_imm_to_add0 },
    { "fs_cp_fat_getnextpathcomp_step_14.1.2",  "0x680640F909050091690600F9", 4, rules_is_add_imm, rules_add_imm_to_add0 },
    // FAT_MakeShortName：宽度钳制 → movz wD,#2
    //   （原版按 OEMCharWidth 走 2 字节拷贝循环，UTF-8 的 3 字节字符会让 subs 永不归零）
    //   同一功能的两种源指令形态：15.0.1–20.5.0 是 `mov wD,w0`；14.1.2 与 21.0.0+ 是
    //   `movz wD,#0x2e`（故后者的版本范围分两段）。
    { "fs_cp_makeshortname_15.0.1-20.5.0",      "0xE80740B9F703002A1F21.6B", 4, rules_is_mov_w0, rules_mov_reg_to_movz2 },
    { "fs_cp_makeshortname_14.1.2,21.0.0+",     "0xF703002ACD0580521F21.6B", 4, rules_is_movz_2e, rules_movz_2e_to_movz2 },
    // StringDesc 消费点（AddLeft / GetCharCount / CompareUnicode / CompareOem）：
    //   csel/cinc（跳 1 或 2 字节）→ 无条件 add Rd,Rn,w0
    { "fs_cp_str_addleft_15.0.1+",              "0x94060051C806961A9F3E0072", 4, rules_is_csel_cinc, rules_csel_cinc_to_add },
    { "fs_cp_str_addleft_14.1.2",               "0xC806961A940600519F3E007216050011", 0, rules_is_csel_cinc, rules_csel_cinc_to_add },
    { "fs_cp_str_getcharcount_16.1.0+",         "0x940600117306939A601E4038", 4, rules_is_csel_cinc, rules_csel_cinc_to_add },
    { "fs_cp_str_getcharcount_14.1.2-15.0.1",   "0x.06.9A....60.40..FFFF35..........41.", 0, rules_is_csel_cinc, rules_csel_cinc_to_add },
    { "fs_cp_str_compareunicode_16.1.0+",       "0xA11300D16802969A13050091", 4, rules_is_csel_cinc, rules_csel_cinc_to_add },
    { "fs_cp_str_compareunicode_14.1.2-15.0.1", "0x..969A....A80E40F9...............78......0034.01..", 0, rules_is_csel_cinc, rules_csel_cinc_to_add },
    { "fs_cp_str_compareoem_16.1.0-18.1.0",     "0x1F000071....89..9A", 8, rules_is_csel_cinc, rules_csel_cinc_to_add },
    { "fs_cp_str_compareoem_19.0.1+",           "0x1F0000719402979A.264078", 4, rules_is_csel_cinc, rules_csel_cinc_to_add },
    { "fs_cp_str_compareoem_14.1.2-15.0.1",     "0x.06.9A................0001094B...A9....FD7B...03..", 0, rules_is_csel_cinc, rules_csel_cinc_to_add },
};

// 16 条整函数替换条目：pattern 只负责定位，写入的是自包含、位置无关的替换实现。
// 名字规则同 fs_inst_patches（功能名 + 版本范围）。
constinit FsBlobPatch fs_blob_patches[] = {
    // FAT_GetNextChar → patch_fat_getnextchar（折叠该函数里全部 4 个指令点）
    { "fs_cp_fat_getnextchar_16.1.0+",            "0xFF0301D1FD7B01A9F65702A9F44F03A9FD430091091040B9",          0, FsBlobImpl::FatGetNextChar },
    { "fs_cp_fat_getnextchar_14.1.2-15.0.1",      "0xFF0301D1FD7B01A9FD430091F65702A9F44F03A9.1040B9F303012A",    0, FsBlobImpl::FatGetNextChar },
    // WideChar_Compare → patch_widechar_compare（折叠该函数里全部 15 个指令点）
    { "fs_cp_widechar_compare_17.0.0+",           "0xFF4302D1FD7B03A9FB2300F9FA6705A9F85F06A9F65707A9F44F08A9FDC30091....F30303AA", 0, FsBlobImpl::WideCharCompare },
    { "fs_cp_widechar_compare_16.1.0",            "0xFF0302D1FD7B03A9FA6704A9F85F05A9F65706A9F44F07A9FDC30091....F30303AA",     0, FsBlobImpl::WideCharCompare },
    { "fs_cp_widechar_compare_14.1.2",            "0xFF4302D1FD7B03A9FDC30091FB2300F9FA6705A9F85F06A9F65707A9F44F08A9.0C00D0",     0, FsBlobImpl::WideCharCompare },
    { "fs_cp_widechar_compare_15.0.1",            "0xFF4302D1FD7B03A9FDC30091FB2300F9FA6705A9F85F06A9F65707A9F44F08A9..00.F30303AA", 0, FsBlobImpl::WideCharCompare },
    // PFCODE 三个编码原语（ctx 回调表指向的函数）→ UTF-8 实现
    { "fs_cp_pfcode_unicode2oem_14.1.2+",         "0x00000000.004079.FD0171",                              4, FsBlobImpl::Utf16ToUtf8 },
    { "fs_cp_pfcode_oem2unicode_16.1.0+",         "0x....0800C039.1D0012",                                 4, FsBlobImpl::Utf8ToUtf16 },
    { "fs_cp_pfcode_is_oem_mb_char_16.1.0+",      "0x08.............00..078052...7A",                      0, FsBlobImpl::IsOemMbChar },
    { "fs_cp_pfcode_oem2unicode_14.1.2-15.0.1",   "0x0A00C039.1D0012.03.2A0A03F836.7D0111",                0, FsBlobImpl::Utf8ToUtf16 },
    { "fs_cp_pfcode_is_oem_mb_char_14.1.2-15.0.1","0x0A000151..00..1C00...00...00.EA279F1A3F010071",      0, FsBlobImpl::IsOemMbChar },
    // PFCODE_Str_Unicode2OEM → patch_str_unicode2oem（有界转换；21.x/22.x 入口在命中点后 4 字节）
    { "fs_cp_str_unicode2oem_16.1.0-20.5.0",      "0x3F482838C0035FD600000000FF4301D1",                   12, FsBlobImpl::StrUnicode2Oem },
    { "fs_cp_str_unicode2oem_21.0.0+",            "0x3F482838C0035FD60000000000000000FF0301D1",           16, FsBlobImpl::StrUnicode2Oem },
    { "fs_cp_str_unicode2oem_14.1.2-15.0.1",      "0xFF4301D1FD7B01A9FD430091F71300F9F65703A9F44F04A9BF3B0079", 0, FsBlobImpl::StrUnicode2Oem },
    // StringDesc_ToUpper → patch_stringdesc_toupper（OEM 分支改 ASCII-only）
    { "fs_cp_stringdesc_toupper_16.1.0+",         "0xFD7BBDA9F50B00F9F44F02A9FD030091081040B9",           0, FsBlobImpl::StrDescToUpper },
    { "fs_cp_stringdesc_toupper_14.1.2-15.0.1",   "0xFD7BBDA9F50B00F9FD030091F44F02A9081040B9",           0, FsBlobImpl::StrDescToUpper },
};

static_assert(std::size(fs_inst_patches) == 15);
static_assert(std::size(fs_blob_patches) == 16);
static_assert(std::size(fs_fn_groups) == 12);
static_assert(FS_PRED_COUNT <= 32);   // 位图挤在一个 u32 里

/* 命中站点记录（仅诊断）：fs 的补丁扫描命中后把补丁位的**绝对地址**记下来，
 * 由调用方换算成「相对模块基址的偏移」写进 log.ini。只存内存不落盘 ——
 * 附加调试后 fs 是挂起的，此时任何写 SD 的操作都会永久阻塞。 */
constexpr u32 FS_SITE_MAX = 64;   // ≥ 31 条条目（15 指令 + 16 替换），留余量

struct FsSiteSink {
    struct Rec { const char* name; u64 addr; };
    Rec recs[FS_SITE_MAX]{};
    u32 n{};

    void add(const char* name, u64 addr) {
        if (n < std::size(recs)) {
            recs[n].name = name;
            recs[n].addr = addr;
            n++;
        }
    }
};

static FsSiteSink fs_sites;

// 被扫描代码段（fs 主 .text）的基址：命中站点记的是绝对地址，落盘前换算成
// 「相对模块基址的偏移」，与 RESOLVED.md / Ghidra 的 VA 同口径。
static u64 fs_code_base = 0;

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
        case FsBlobImpl::FatGetNextChar:
            return { (const void*)patch_fat_getnextchar,
                     (u32)patch_code_size(patch_fat_getnextchar, patch_fat_getnextchar_end) };
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

// 位面的索引单位：AArch64 指令 = 4 字节（字），位图按 64 位一组。二者都要求块基址
// 落在 fs 的字网格上，故 overlap 必须是字长的整数倍。
constexpr u32 FS_WORD_BYTES = 4;
constexpr u32 FS_WORD_BITS  = 64;
constexpr u64 FS_OVERLAP    = 0x50;   // ≥ 最长模板 42 字节；奇数会让位面索引全部错位
static_assert(FS_OVERLAP % FS_WORD_BYTES == 0,
              "M3 的位面索引要求块基址对齐 fs 的 4 字节字网格");

// §5 扫描器 · 谓词位图（按谓词分层的 bit-plane）──────────────────────────────
// 每块先算一遍谓词位图：每个字算出命中哪些谓词，记进各谓词自己的位面。每条条目只
// 遍历自己位面里置位的字，再做字节模板比对 —— 成本与补丁点数解耦。
// 前提（守卫逐条校验）：pattern 的 inst_offset 是字长的倍数，且唯一命中位置与指令
// 同字对齐；位面里的谓词就是条目的 cond 本身 ⇒ 预筛不会漏。
constexpr u32 FS_SCAN_BYTES = READ_BUFFER_SIZE + FS_OVERLAP;     // 单块最大字节数（含 overlap）
constexpr u32 FS_BIT_WORDS  = (FS_SCAN_BYTES / FS_WORD_BYTES + FS_WORD_BITS - 1) / FS_WORD_BITS;
static u64 fs_pred_plane[FS_PRED_COUNT][FS_BIT_WORDS];

static void fs_build_pred_bits(const u8* data, size_t data_size, u32 nmask)
{
    const size_t nwords = data_size / FS_WORD_BYTES;
    std::memset(fs_pred_plane, 0, sizeof(fs_pred_plane));
    for (size_t w = 0; w < nwords; w++) {
        u32 inst{};
        std::memcpy(&inst, data + w * FS_WORD_BYTES, sizeof(inst));
        u32 m = fs_pred_mask(inst, nmask);
        while (m) {
            const u32 k = (u32)std::countr_zero(m);
            m &= m - 1;
            fs_pred_plane[k][w / FS_WORD_BITS] |= (1ull << (w % FS_WORD_BITS));
        }
    }
}

// ── 族（补丁点）与「兄弟姐妹提前退役」──────────────────────────────────────
// 一个补丁点常带多条**跨版本互斥变体**：同一份固件上至多一条命中（26 份语料逐份校验
// 过，构建期守卫再兜一次）。于是任一变体定位成功 ⇒ 同族其余变体在这份固件上永远命中
// 不了，不必再为它们建位面、走位面、做字节比对 —— 这是启动成本的大头。
//
// 族 = 条目名里版本范围之前的功能前缀（名字规则 `<功能名>_<版本范围>`，见 §4）：同名 =
// 同族，异名 = 异族。前缀边界 = 第一个「`_` + 数字」，与守卫 point_of() 同口径。
// 登记表满则返回 FS_FAM_NONE ⇒ 该条目不参与退役判定，退化为「不跳兄弟」（仍正确，只是慢）。
constexpr u32 FS_FAM_NONE = 0xFFFFFFFFu;
constexpr u32 FS_FAM_COUNT = 32;                 // 族号位图挤在一个 u32 里

static const char* fs_fam_key[FS_FAM_COUNT];     // 每个族号对应的功能前缀
static u32         fs_fam_keylen[FS_FAM_COUNT];
static u32         fs_fam_used = 0;

static u32 fs_family_of(const char* name)
{
    u32 n = 0;                                   // 功能前缀长度
    while (name[n] != '\0') {
        if (name[n] == '_' && name[n + 1] >= '0' && name[n + 1] <= '9') {
            break;                               // 版本范围从这里开始
        }
        n++;
    }
    if (n == 0) {
        return FS_FAM_NONE;
    }
    for (u32 k = 0; k < fs_fam_used; k++) {
        if (fs_fam_keylen[k] == n && std::memcmp(fs_fam_key[k], name, n) == 0) {
            return k;
        }
    }
    if (fs_fam_used >= FS_FAM_COUNT) {
        return FS_FAM_NONE;
    }
    fs_fam_key[fs_fam_used] = name;
    fs_fam_keylen[fs_fam_used] = n;
    return fs_fam_used++;
}

/* 族号 -> 位掩码。FS_FAM_NONE 取 0 位（恒不置位），避免 `1u << 0xFFFFFFFF` 的 UB。 */
static inline u32 fs_fam_bit(u32 fam) { return (fam >= FS_FAM_COUNT) ? 0u : (1u << fam); }

static u32 fs_pat_fam[std::size(fs_inst_patches)];
static u32 fs_blob_fam[std::size(fs_blob_patches)];

static void fs_build_families(void)
{
    for (u32 k = 0; k < std::size(fs_inst_patches); k++) {
        fs_pat_fam[k] = fs_family_of(fs_inst_patches[k].patch_name);
    }
    for (u32 k = 0; k < std::size(fs_blob_patches); k++) {
        fs_blob_fam[k] = fs_family_of(fs_blob_patches[k].patch_name);
    }
}

/* 「已解决族」位掩码：任一成员**定位成功**（打过/已被别人打过/写失败/收割失败 ——
 * 都说明 pattern 在这份固件上找到了位置）即置位。每块重算一次，只在 31 条上走一遍，
 * 不引入跨调用状态。 */
static u32 fs_fam_collect(void)
{
    u32 m = 0;
    for (u32 k = 0; k < std::size(fs_inst_patches); k++) {
        if (fs_inst_patches[k].result != PatchResult::NOT_FOUND) {
            m |= fs_fam_bit(fs_pat_fam[k]);
        }
    }
    for (u32 k = 0; k < std::size(fs_blob_patches); k++) {
        if (fs_blob_patches[k].result != PatchResult::NOT_FOUND) {
            m |= fs_fam_bit(fs_blob_fam[k]);
        }
    }
    return m;
}

static u32 fs_fam_done = 0;                      // 当前块的「已解决族」快照

/* 条目还需要扫描吗？**唯一判据**，建位面、组调度、两条扫描循环都走它。
 * fam_solved 由调用方传入：建位面/调度用每块快照 fs_fam_done；扫描循环用本块内
 * 就地退役的 fam_local（同族兄弟在本块刚落地 ⇒ 立刻停扫）。
 * pred_idx >= FS_PRED_COUNT 表示 cond 不在谓词清单里：位图永不为它置位 ⇒ 恒不命中。
 * 这里显式判掉（顺便挡住拿它当位面下标的越界），构建期守卫另有报错。
 * FAILED_* 的条目不再跨块重试：同一位置重试必然同样失败（结果由该点的字节决定）。 */
static bool fs_pat_live(const FsInstPatch& p, u32 fam_solved)
{
    return p.result == PatchResult::NOT_FOUND
        && p.pred_idx < FS_PRED_COUNT
        && !(fam_solved & fs_fam_bit(fs_pat_fam[(u32)(&p - fs_inst_patches)]));
}

static bool fs_blob_live(const FsBlobPatch& b, u32 fam_solved)
{
    return b.result == PatchResult::NOT_FOUND
        && !(fam_solved & fs_fam_bit(fs_blob_fam[(u32)(&b - fs_blob_patches)]));
}

/* 全表是否还有活条目？全没了就该收工 —— 剩下的块只是在读内存、建位面、逐组空走。
 * 补丁点的落地位置都在 .text 的 46%~56% 区间，尾部近一半的块原本全是白跑。 */
static bool fs_any_live(void)
{
    for (auto& p : fs_inst_patches) {
        if (fs_pat_live(p, fs_fam_done)) { return true; }
    }
    for (auto& b : fs_blob_patches) {
        if (fs_blob_live(b, fs_fam_done)) { return true; }
    }
    return false;
}

// 仍需扫描的条目所占用的谓词并集。已落地的条目不再占用建位面的开销 ——
// 每一块的实际谓词数随补丁陆续落地而收缩。
static u32 fs_pred_need_mask(void)
{
    u32 m = 0;
    for (auto& p : fs_inst_patches) {
        if (fs_pat_live(p, fs_fam_done)) {
            m |= (1u << p.pred_idx);
        }
    }
    return m;
}

// 指令改写扫描：只遍历该条目谓词位面上置位的字。
// 位面已保证 cond(inst) 成立，命中即可直接落补丁，无需再验一次 cond。
static void fs_inst_scan(Handle handle, const u8* data, size_t data_size, u64 addr,
                         std::span<FsInstPatch> pats, FsSiteSink* sink)
{
    const size_t nplane = (data_size / FS_WORD_BYTES + FS_WORD_BITS - 1) / FS_WORD_BITS;
    u32 fam_local = fs_fam_done;            // 本块内先落地的兄弟 ⇒ 就地退役

    for (auto& p : pats) {
        const u32 fam_bit = fs_fam_bit(fs_pat_fam[(u32)(&p - fs_inst_patches)]);
        // 已落地（跨块会重复看到同一条模板）/ 同族兄弟已解决 / cond 不在谓词清单
        if (!fs_pat_live(p, fam_local)) {
            continue;
        }

        const u64* plane = fs_pred_plane[p.pred_idx];
        const u32 plen = p.byte_pattern.size;
        const u32 q_min = (u32)p.inst_offset / FS_WORD_BYTES;   // 保证 i = 字索引*4 − 偏移 ≥ 0
        bool done = false;

        // 只走字对齐位置（q 递增 ⇒ i 递增）。「首个命中即采用」。
        for (size_t wi = 0; wi < nplane && !done; wi++) {
            u64 bits = plane[wi];
            while (bits) {
                const u32 q = (u32)(wi * FS_WORD_BITS) + (u32)std::countr_zero(bits);
                bits &= bits - 1;
                if (q < q_min) {
                    continue;
                }
                const u32 i = q * FS_WORD_BYTES - (u32)p.inst_offset;
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
                std::memcpy(&inst, data + q * FS_WORD_BYTES, sizeof(inst));
                const auto patch_data = p.patch(inst);
                const u64 site = addr + q * FS_WORD_BYTES;   // 落点指令地址 = 写入地址

                // todo: log failed writes, although this should in theory never fail
                if (R_FAILED(svcWriteDebugProcessMemory(handle, &patch_data, site, patch_data.size))) {
                    p.result = PatchResult::FAILED_WRITE;
                } else {
                    p.result = PatchResult::PATCHED_SYSPATCH;
                    if (sink) { sink->add(p.patch_name, site); }
                }
                fam_local |= fam_bit;       // 本点已定位 ⇒ 本块内不再试同族兄弟
                done = true;
                break;
            }
        }
    }
}

// §6 现场收割：把替换体里的哨兵占位改成真实地址 ══════════════════════════════
// fs 的代码页上下文槽地址逐固件都不同（实测 18 个取值）—— 写死会在其它固件上解引用
// 野指针。信息就在即将被覆写的原函数字节里（原版自己就用 adrp+ldr 取这个槽）：
//   ① ctx 槽：在原件前 FS_CTX_SCAN 字节里找唯一一条 adrp 及其唯一配对的 ldr
//      （Rn = Rt = adrp 的 Rd）→ 解出槽地址 → 重编码成 `adrp x3 + add x3,#lo12`
//      覆写 ctx 哨兵对；替换体随后 `ldr x3,[x3]` 得到 ctx。
//   ② callee：在原件前 FS_CALL_SCAN 字节里找「目标跳出函数体」的 bl，按**去重后的
//      目标数 == 1** 判定（同一 callee 可被多条 bl 调用）→ 重编码成 `adrp x9 + add`
//      覆写 callee 哨兵对；替换体用 `blr x9` 调用（整段覆写后 BL 的相对偏移不再有效）。
//      体内自递归 bl 相对自身 PC、拷贝后恒等，不算外部调用。
// 任一项失败 → 该点整点不写（FAILED_HARVEST），保留原版函数，绝不写会解引用可疑
// 指针的代码。哨兵值本身定义在 §0。
constexpr u32 FS_CTX_HARVEST_REG  = 3;   // 替换体里收 ctx 槽用的寄存器（x3）
constexpr u32 FS_CALL_HARVEST_REG = 9;   // 替换体里收 callee 用的寄存器（x9）

constexpr u32 FS_CTX_SCAN  = 0x120;          // ctx 槽扫描窗口（= 最小洞 0x120）
constexpr u32 FS_CALL_SCAN = 0x300;          // callee 扫描窗口：≥ 最后一条外跳 bl 的偏移，
                                             // 又 < 最小函数体 0x35c（否则会吃进下一个函数）
constexpr u64 FS_CTX_MAX_DELTA = 0x400000;   // 槽与代码的合理最大距离（实测 1.3~1.7 MB）
constexpr u32 FS_HARVEST_BUF_SIZE = 0xA00;   // ≥ 最大替换体（0x360）+ 余量
constexpr u32 FS_ENTRY_PROBE_BYTES = 16;     // 「已被别人打过」的逐字节比对长度

static u8 fs_harvest_buf[FS_HARVEST_BUF_SIZE];
// 收割源：按 site 直接另读一段原版字节，不复用扫描块 —— 扫描块步长可能装不下整个
// 收割窗；直接读位置无关，也不用放大 overlap。fs 挂起后这里读到的正是未打补丁的原版字节。
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
 * 注意按**去重目标数**判唯一，而不是按 bl 条数：同一 callee 可被多条 bl 调用。
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

/* 该替换体是否带哨兵占位（需要现场收割）。WideChar_Compare 用满两对：ctx 对 + callee 对。 */
static bool fs_blob_needs_harvest(FsBlobImpl impl)
{
    return impl == FsBlobImpl::StrUnicode2Oem || impl == FsBlobImpl::WideCharCompare
        || impl == FsBlobImpl::FatGetNextChar;
}

/* 定位成功后的落地动作：已被别人打过 / 现场收割 / 写内存。返回后 b.result 必然不再
 * 是 NOT_FOUND —— 无论成功还是失败，都表示「本点在这份固件上已定位」，可退役。 */
static void fs_blob_apply(Handle handle, FsBlobPatch& b, const u8* data, u32 entry, u64 addr,
                          FsSiteSink* sink)
{
    const u64 site = addr + entry;
    const auto range = fs_blob_range(b.impl);

    // 已被别的途径改过（sigpatch 等）：入口前若干字节 == 替换实现的开头。取 FS_ENTRY_PROBE_BYTES
    // 字节是为了排除「某版本原函数首指令碰巧相同」的误判。
    if (!std::memcmp(data + entry, range.code, FS_ENTRY_PROBE_BYTES)) {
        b.result = PatchResult::PATCHED_FILE;
        if (sink) { sink->add(b.patch_name, site); }
        return;
    }

    // 现场收割：带哨兵占位的替换体先拷到暂存区改成真实地址，再写进去。
    // 任一项收割失败 ⇒ 整点不写（保留原版），绝不写可疑代码。
    const void* to_write = range.code;
    if (fs_blob_needs_harvest(b.impl)) {
        if (range.size > sizeof(fs_harvest_buf)) {
            b.result = PatchResult::FAILED_HARVEST;
            return;
        }
        // 收割源直接按 site 另读（见 fs_harvest_orig 的说明）
        if (R_FAILED(svcReadDebugProcessMemory(fs_harvest_orig, handle, site, FS_CALL_SCAN))) {
            b.result = PatchResult::FAILED_HARVEST;
            return;
        }
        const u8* orig = fs_harvest_orig;
        const u64 slot = fs_harvest_ctx_slot(orig, site);
        if (!slot) {
            b.result = PatchResult::FAILED_HARVEST;
            return;
        }
        std::memcpy(fs_harvest_buf, range.code, range.size);
        if (!fs_fill_addr_pair(fs_harvest_buf, range.size,
                               FS_CTX_SENTINEL_A, FS_CTX_SENTINEL_B,
                               FS_CTX_HARVEST_REG, slot, site)) {
            b.result = PatchResult::FAILED_HARVEST;
            return;
        }
        // 第二对（只有 WideChar_Compare 用）：callee 走 blr，必须现场收割目标地址。
        if (b.impl == FsBlobImpl::WideCharCompare) {
            const u64 callee = fs_harvest_callee(orig, FS_CALL_SCAN, site);
            if (!callee ||
                !fs_fill_addr_pair(fs_harvest_buf, range.size,
                                   FS_CALL_SENTINEL_A, FS_CALL_SENTINEL_B,
                                   FS_CALL_HARVEST_REG, callee, site)) {
                b.result = PatchResult::FAILED_HARVEST;
                return;
            }
        }
        to_write = fs_harvest_buf;
    }

    // todo: log failed writes, although this should in theory never fail
    if (R_FAILED(svcWriteDebugProcessMemory(handle, to_write, site, range.size))) {
        b.result = PatchResult::FAILED_WRITE;
    } else {
        b.result = PatchResult::PATCHED_SYSPATCH;
        if (sink) { sink->add(b.patch_name, site); }
    }
}

/* ── 车道快筛（blob 的位置预筛）───────────────────────────────────────────────
 * blob 模板长且唯一，加谓词不划算，本来只能逐条把整段扫一遍（16 条 × 段长/4 次字节
 * 比对）。但每条模板的**偏移 0 或偏移 4** 上几乎都有确定字节：于是每个候选位置只需
 * 两次取字节（data[i]、data[i+4]）各查一次 256 项位图、按位与，就得到「本位置可能是
 * 哪几条 blob 的起点」。位图 bit = 条目下标，**未用该车道的条目位恒为 1**（不约束）
 * ⇒ 两个车道可以无干扰地并进同一个掩码。
 * 筛子字节取自模板的确定字节 ⇒ 模板整体匹配必然蕴含筛子命中，快筛不会漏。
 * 实测每位置候选条目数 0.51~0.56（26 份语料），相对逐条线性扫描压缩约 28 倍。 */
constexpr u32 FS_LANE_COUNT = 2;         // 只取模板偏移 0 / 4 两处当筛子
constexpr u32 FS_FILTER_NONE = 0xFF;     // 偏移 0 与 4 都是通配槽 ⇒ 该条目不做预筛
/* 位置循环的右界余量：车道 1 的取样点在 i+4，所以必须先给这 4 字节留位；
 * 再多留 4 字节（i 只能取 4 的倍数，i+4 == data_size 时 data[i+4] 就越界了）。
 * 合法命中要求 i + entry_offset + 16 ≤ data_size ⇒ i ≤ data_size−16，远在界内，不会漏。 */
constexpr u32 FS_BLOB_LOOP_MARGIN = 8;
static u32 fs_blob_lane[FS_LANE_COUNT][256];

static u32 fs_blob_lane_of(const PatternData& pat)
{
    if (pat.size > 0 && pat.data[0] != REGEX_SKIP) { return 0; }
    if (pat.size > 4 && pat.data[4] != REGEX_SKIP) { return 1; }
    return FS_FILTER_NONE;               // 安全降级：每位置都试这条
}

static void fs_build_lanes(void)
{
    for (u32 l = 0; l < FS_LANE_COUNT; l++) {
        for (u32 v = 0; v < 256; v++) { fs_blob_lane[l][v] = ~0u; }   // 默认「不约束」
    }
    for (u32 e = 0; e < std::size(fs_blob_patches); e++) {
        const auto& pat = fs_blob_patches[e].byte_pattern;
        const u32 l = fs_blob_lane_of(pat);
        if (l == FS_FILTER_NONE) { continue; }
        const u32 keep = pat.data[l * 4];
        u32* lane = fs_blob_lane[l];
        for (u32 v = 0; v < 256; v++) {
            if (v != keep) { lane[v] &= ~(1u << e); }   // 该条目在本车道只接受 keep
        }
    }
}

/* 整函数替换定位器：与 fs_inst_scan 同一套 REGEX_SKIP 通配规则，但写的是替换实现的
 * 整段代码。
 *
 * ★ 步进取字长：blob 条目的 entry_offset 都是字长的倍数，命中处是 AArch64 函数入口
 *   （字对齐），块基址也对齐 ⇒ 块内合法命中下标 i 必为字长的倍数。按字长步进不会漏掉
 *   任何合法命中，只跳过「就算命中也会写到非对齐地址」的伪命中。
 *
 * ★ 遍历次序：位置外层、条目内层（条目由车道掩码挑出，按下标升序）。每个条目落地在
 *   「该条目在全段里最早的合法命中」，与逐条扫描逐位一致；只有 sink 的登记先后变了
 *   （仅影响 log 里站点列表的排列）。
 *
 * ★ 同族退役：任一变体定位成功 ⇒ 同族其余变体在这份固件上不可能命中（互斥），就地
 *   从 pending 里摘掉，不再为它们做字节比对。粒度是「本块内即时」+「跨块持久」。 */
static void fs_blob_scan(Handle handle, const u8* data, size_t data_size, u64 addr,
                         std::span<FsBlobPatch> blobs, FsSiteSink* sink)
{
    static_assert(FS_OVERLAP % FS_WORD_BYTES == 0,
                  "块基址必须落在 4 字节字网格上，否则下面的按字长步进不成立");
    static_assert(std::size(fs_blob_patches) <= 32, "车道位图是一个 u32");

    const u32 g_begin = (u32)(blobs.data() - fs_blob_patches);
    const u32 g_end = g_begin + (u32)blobs.size();
    u32 fam_local = fs_fam_done;
    u32 pending = 0;
    for (u32 e = g_begin; e < g_end; e++) {
        if (fs_blob_live(fs_blob_patches[e], fs_fam_done)) { pending |= (1u << e); }
    }
    if (!pending) { return; }

    for (u32 i = 0; i + FS_BLOB_LOOP_MARGIN <= data_size; i += FS_WORD_BYTES) {
        // 两次取字节 + 两次查表 + 一次与：本位置的全部候选条目
        u32 cand = fs_blob_lane[0][data[i]] & fs_blob_lane[1][data[i + FS_WORD_BYTES]] & pending;

        while (cand) {
            const u32 e = (u32)std::countr_zero(cand);
            cand &= cand - 1;
            auto& b = fs_blob_patches[e];

            if (i + b.byte_pattern.size > data_size) {
                pending &= ~(1u << e);   // i 单调增：本块内再无机会，下一块（带 overlap）再看
                continue;
            }
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

            const u32 entry = i + (u32)b.entry_offset;
            if (entry + FS_ENTRY_PROBE_BYTES > data_size) {
                pending &= ~(1u << e);   // 本块装不下「入口 + 核对字节」，交给下一块
                continue;
            }

            fs_blob_apply(handle, b, data, entry, addr, sink);

            // 本点已定位（成功 / 写失败 / 收割失败 / 已被别人打过）⇒ 退役本点与同族
            pending &= ~(1u << e);
            fam_local |= fs_fam_bit(fs_blob_fam[e]);
            for (u32 k = g_begin; k < g_end; k++) {
                if (fam_local & fs_fam_bit(fs_blob_fam[k])) { pending &= ~(1u << k); }
            }
        }
    }
}

// 该函数组是否还有值得扫描的条目（决定要不要为它打进度标记、调扫描）
static auto fs_group_pending(const FsFnGroup& g) -> bool
{
    for (u32 k = g.pat_begin; k < g.pat_end; k++) {
        if (fs_pat_live(fs_inst_patches[k], fs_fam_done)) {
            return true;
        }
    }
    for (u32 k = g.blob_begin; k < g.blob_end; k++) {
        if (fs_blob_live(fs_blob_patches[k], fs_fam_done)) {
            return true;
        }
    }
    return false;
}

/* u32 -> "0x000f45d8"（log 里报站点偏移用；minIni 只有十进制）。
 * 目标缓冲区至少 11 字节。 */
static void u32_to_hex_str(char *s, u32 v)
{
    s[0] = '0';
    s[1] = 'x';
    for (u32 i = 0; i < 8; i++) {
        const u32 nib = (v >> (28 - 4 * i)) & 0xF;
        s[2 + i] = (nib < 10) ? (char)('0' + nib) : (char)('a' + nib - 10);
    }
    s[10] = '\0';
}

} // namespace

const char *fs_codepage_patch_result = "default";

/* 进度标记（诊断）：只更新内存里的名字，由 fs_codepage_write_log 在补丁全部结束、
 * fs 脱附之后统一落盘 —— fs 被附加调试挂起期间，任何写 SD 的操作（要经过 fs 服务）
 * 都会永久阻塞。补丁真挂死时日志是空的，此时该值停在**最后进入的那个函数组**上
 * （start → <组名> → success），它指向元凶。
 * 注意：这里不再有 stage 语义 —— 条目一律全量应用，二分开关只有
 * [options] fs_codepage=0（整份跳过）。 */
static void fs_progress(const char *label)
{
    fs_codepage_patch_result = label;
}

/* §7 入口用的常量。 */
constexpr u64 FS_PROGRAM_ID    = 0x0100000000000000;  // fs 的 CreateProcess 事件 PID
constexpr u32 FS_MAX_PROCESS   = 0x50;               // 进程表容量
constexpr u64 FS_TEXT_MIN_SIZE = 0x100000;           // 主 .text 段最小尺寸（1 MiB）

/* §7 入口：fs 编码补丁主流程（pattern 驱动 + 函数组二级表）。
 * 偏移来自每条 pattern 在 fs .text 里的搜索结果，补丁字节由改写规则从命中指令现场
 * 算出；未命中只记 NOT_FOUND，绝不写错地方。
 * 只处理第一个 ≥ FS_TEXT_MIN_SIZE 的 Rx/CodeStatic 段（fs 主 .text，同时就是模块
 * 基址，log 里的站点偏移与 Ghidra 的 VA 同口径）。 */
void fs_codepage_patch(void)
{
    Handle handle{};
    DebugEventInfo event_info{};
    u64 pids[FS_MAX_PROCESS]{};
    s32 process_count{};
    constexpr u64 overlap_size = FS_OVERLAP;
    static u8 buffer[READ_BUFFER_SIZE + overlap_size];

    fs_progress("start");
    fs_sites.n = 0;
    fs_build_families();
    fs_build_lanes();
    fs_fam_done = 0;

    if (R_FAILED(svcGetProcessList(&process_count, pids, FS_MAX_PROCESS))) {
        return;
    }

    for (s32 i = 0; i < (process_count - 1); i++) {
        if (R_SUCCEEDED(svcDebugActiveProcess(&handle, pids[i])) &&
            R_SUCCEEDED(svcGetDebugEvent(&event_info, handle)) &&
            FS_PROGRAM_ID == event_info.info.create_process.program_id) {
            MemoryInfo mem_info{};
            u64 addr{};
            u32 page_info{};

            for (;;) {
                if (R_FAILED(svcQueryDebugProcessMemory(&mem_info, &page_info, handle, addr))) {
                    break;
                }
                addr = mem_info.addr + mem_info.size;

                if (!addr) {
                    break;                  // addr=0 ⇒ 走到保留内存区，收工
                }
                // 只要 Rx 的可执行静态代码段，且跳过 emummc 等小段
                if (!mem_info.size || (mem_info.perm & Perm_Rx) != Perm_Rx ||
                    ((mem_info.type & 0xFF) != MemType_CodeStatic)) {
                    continue;
                }
                if (mem_info.size < FS_TEXT_MIN_SIZE) {
                    continue;
                }

                // 只处理第一个大代码段 —— 它就是 fs 主 .text（也是模块基址）
                fs_code_base = mem_info.addr;

                std::memset(buffer, 0, sizeof(buffer));

                for (u64 sz = 0; sz < mem_info.size; sz += READ_BUFFER_SIZE - overlap_size) {
                    // 每块开始前刷新「已解决族」快照；全部补丁点都定位完毕就直接收工 ——
                    // 剩下的块只是在读内存、建位面、逐组空走。补丁点的落地位置都在 .text
                    // 的 46%~56% 区间，尾部近一半的块原本全是白跑。
                    fs_fam_done = fs_fam_collect();
                    if (!fs_any_live()) {
                        break;
                    }

                    const auto actual_size = std::min<u64>(READ_BUFFER_SIZE, mem_info.size - sz);
                    if (R_FAILED(svcReadDebugProcessMemory(buffer + overlap_size, handle, mem_info.addr + sz, actual_size))) {
                        break;
                    }

                    // 首块 base = 段首 - overlap（buffer 前 overlap 字节是补的 0）；
                    // 之后每块 base 前移 overlap，使跨块 pattern 能完整匹配。
                    const u64 chunk_base = mem_info.addr + sz - overlap_size;
                    const u32 chunk_size = (u32)(actual_size + overlap_size);
                    const u32 sink_begin = fs_sites.n;

                    // 本块只算一次谓词位图，12 个函数组共享。
                    // 谓词集合按「还需扫描的条目」收缩，越往后位图越便宜。
                    fs_build_pred_bits(buffer, chunk_size, fs_pred_need_mask());

                    for (auto& g : fs_fn_groups) {
                        if (!fs_group_pending(g)) {
                            continue;           // 该组已全部落地，连进度标记都不必打
                        }
                        fs_progress(g.label);
                        fs_inst_scan(handle, buffer, chunk_size, chunk_base,
                                std::span<FsInstPatch>{fs_inst_patches}
                                    .subspan(g.pat_begin, g.pat_end - g.pat_begin),
                                &fs_sites);
                        fs_blob_scan(handle, buffer, chunk_size, chunk_base,
                                std::span<FsBlobPatch>{fs_blob_patches}
                                    .subspan(g.blob_begin, g.blob_end - g.blob_begin),
                                &fs_sites);
                    }

                    // 本块新命中的站点：绝对地址 -> 相对 .text 基址的偏移
                    for (u32 k = sink_begin; k < fs_sites.n; k++) {
                        fs_sites.recs[k].addr -= fs_code_base;
                    }

                    // 滚动 overlap：块尾若干字节留给下一块做跨块匹配
                    if (actual_size >= overlap_size) {
                        memcpy(buffer, buffer + READ_BUFFER_SIZE, overlap_size);
                        std::memset(buffer + overlap_size, 0, READ_BUFFER_SIZE);
                    } else {
                        const auto bytes_to_overlap = std::min<u64>(overlap_size, actual_size);
                        memcpy(buffer, buffer + READ_BUFFER_SIZE + (actual_size - bytes_to_overlap), bytes_to_overlap);
                        std::memset(buffer + bytes_to_overlap, 0, sizeof(buffer) - bytes_to_overlap);
                    }
                }

                fs_progress("success");
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

void fs_codepage_write_log(const char* log_path)
{
    // 挂死定位：补丁真把 fs 打挂时日志写不出来，此时该值停在最后一个进入的函数组上。
    ini_puts("debug", "fs_codepage_patch_result", fs_codepage_patch_result, log_path);

    // 精简后的逐条结果：**只记已定位的条目**（打过 / 已被打过 / 收割或写入失败），
    // 未命中的只汇总个数。31 条里大部分是跨版本互斥变体，在一份固件上本就该 0 命中
    // （"Unpatched" 是安全失败，不是错误），逐条写全是噪音。
    // 「哪个补丁点没落地」看 [fs_codepage_sites] 即可：同名功能前缀（族）的任一成员
    // 出现在站点表里就说明该点已落地；整族缺席才是新固件未适配。
    u32 unmatched = 0;
    for (auto& p : fs_inst_patches) {
        if (p.result == PatchResult::NOT_FOUND) {
            unmatched++;
        } else {
            ini_puts("fs_codepage", p.patch_name, patch_result_to_str(p.result), log_path);
        }
    }
    for (auto& b : fs_blob_patches) {
        if (b.result == PatchResult::NOT_FOUND) {
            unmatched++;
        } else {
            ini_puts("fs_codepage", b.patch_name, patch_result_to_str(b.result), log_path);
        }
    }
    ini_putl("debug", "fs_codepage_unmatched", (long)unmatched, log_path);

    // 命中站点的偏移（相对 fs 主 .text 基址，也就是模块基址），可直接逐点核对。
    for (u32 k = 0; k < fs_sites.n; k++) {
        char off_str[12] = "";
        u32_to_hex_str(off_str, (u32)fs_sites.recs[k].addr);
        ini_puts("fs_codepage_sites", fs_sites.recs[k].name, off_str, log_path);
    }
}
