#pragma once
// fs 字符集补丁（CP932→UTF-8）对外接口。实现见 fs_codepage.cpp。

// 本模块**没有**任何选项：补丁要么整份生效，要么由 main() 按 config.ini 的
// [options] fs_codepage=0 整份跳过（"打了一半"的状态本身是危险的 —— 转换器换了
// 而配套的宽度钳制没打，会在 FAT_MakeShortName 里死循环）。

// 附加调试 fs 进程并执行全部字符集补丁。只处理第一个 >=1MiB 的 Rx/CodeStatic 段
// （fs 主 .text，即模块基址）。注意：本函数运行期间 fs 处于挂起状态，
// 调用方在此期间不得做任何要经过 fs 服务的操作（如写 SD 日志）。
void fs_codepage_patch(void);

// 把补丁结果写进 log.ini（[fs_codepage] / [fs_codepage_sites] / [debug] 三节）。
// 只应在 fs_codepage_patch() 返回（fs 已脱附）之后调用。
// [fs_codepage] 只列**已定位**的条目（未命中的汇总进 [debug] fs_codepage_unmatched），
// [fs_codepage_sites] 列每个命中站点相对模块基址的偏移。
void fs_codepage_write_log(const char* log_path);

// 当前补丁进度名（最后进入的函数组名 / "start" / "success" / "disabled_by_config"），
// 供 main() 在禁用 fs 补丁时置值，以及写日志时读取。补丁挂死时它就是元凶组名。
extern const char* fs_codepage_patch_result;
