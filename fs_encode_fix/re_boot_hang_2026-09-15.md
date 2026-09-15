# 开机卡 logo + log.ini 为空 —— 事故取证与修复（2026-09-15）

## 现象

- Switch 卡在启动 logo，无法进入系统。
- SD 卡 `/config/sys-patch/log.ini` 为 **0 字节**（9/14 23:30）。
- SD 上部署的 `exefs.nsp` 时间戳 9/14 15:16、53,299 字节 —— 即 **第 20 轮补丁版**
  （commit `77b5cf9`，带手工尺寸宏），**不是**随后的"自动尺寸"版（commit `b63fd92`，
  53,359 字节，从未上机）。
- `/atmosphere/fatal_errors/` 与 `crash_reports/` 均无 9/14 的记录。

## 为什么 log.ini 为空能定位范围

`main()` 开头 `ini_remove(log_path)`，所有日志写入都在补丁循环**之后**；而写 SD 需要
fs 服务。因此"文件为空"⇒ sys-patch 在写日志之前就死掉或卡死（补丁阶段），或 fs 被
补丁打坏后连同日志写入一起挂死。

## 根因（用 capstone 逐条解码 main.cpp 里全部手工字节补丁 + 反汇编 fs 目标位置）

| 位置 | 原指令 | 实际写进去的 | 应为 | 危害 |
|---|---|---|---|---|
| 0xf4888 / 0xf4a90（R1） | `add w10,w9,#1` | **`add w10,w10,w0,lsl #1`** | `add w10,w9,w0` | Rn 字段丢失 + 残留移位（实现形式误用立即数编码的位域），索引算成垃圾值 |
| 0xf49c4（R1） | `add w8,w25,#2` | **`add w8,w25,w0,lsl #2`** | `add w8,w25,w0` | 同上（imm6=2） |
| 0xf45d8（FAT_GetNextChar） | `add x9,x8,#1` | **`add x9,x0,x0`** | `add x9,x8,x0` | 把 `2*w0`（2/4/6）当指针存回 `[x20]`，下一轮解引用野地址 |

- 三处 R1 是第 20 轮（`77b5cf9`）新引入 —— 与"这次开机卡死"时间线吻合。
- `0xf45d8` 的错误自早先提交 `1b96083` 就存在，一直没被上机验证过；用户 SD 上另有
  4/21 的 `exefs.nsp.bak`，说明 4 月之后累积的补丁改动很可能从未真正跑起来过。
- 共同点：**改的是移位寄存器形式（`add Rd,Rn,Rm`），却照着立即数形式（`add Rd,Rn,#imm`）
  的字节改了高字节**，于是 Rn 错位、imm6 残留。cmp 字节对了（那是原样抄的），所以
  `fs_patch_function` 不会报错 —— 补丁"成功"应用，随后 fs 崩/挂。

## 修复

1. 机器码改正：
   - 0xf4888 / 0xf4a90：`2A 01 00 0B`（`add w10,w9,w0`）
   - 0xf49c4：`28 03 00 0B`（`add w8,w25,w0`）
   - 0xf45d8：`09 01 00 8B`（`add x9,x8,x0`）
2. **构建期守卫扩展**（`sysmod/tools/check_patch_sizes.py`）：自动解析 main.cpp 里每个
   `fs_patch_function` 补丁点，对**每个被改动的 32 位字**做结构性校验：
   - 允许 `nop`；允许 `movz`（Rd 必须与原指令一致）；
   - 允许 `add Rd,Rn,w0/x0`（**必须 imm6=0、shift=0、Rm=w0，且 Rd/Rn 与原指令一致**）；
   - 允许 `同一地址同一寄存器的访问宽度改写`（`ldrb→ldrh`、`strb→sturh`）。
   另外若存在 fs 目标二进制（`$FS_KIP1` 或本机 RE 副本），逐点比对 cmp 字节，防偏移/固件
   不匹配。自带最小 AArch64 解码，不依赖 capstone。**上述 4 处错误全部会被拦下（已做负向测试）。**
3. **分步进度落盘**（关键诊断）：`fs_stage()` 在每组补丁**之前**把步骤名写进
   `log.ini` 的 `[debug] fs_stage`（`start → converters → fat_callsites → wildcard_r1 →
   makeshortname_r2 → h1_unicode2oem → r4_toupper → success`）。fs 一旦被补丁打坏就会
   挂死、之后再也写不了日志 —— 所以挂死时日志里**最后一条 fs_stage 就是罪魁步骤**。
4. **逃生开关**：`config.ini` 新增 `[options] fs_codepage=1`。置 0 可完全跳过 fs 编码
   补丁（其余 sys-patch 补丁照常），改配置即生效、无需重编译，用于救砖与二分定位。

## 顺带复核（本次一并验证，结论：正确，无需改）

- 两个 per-char 转换器的返回约定：高 16 位 = 输出字节数、低 16 位 = 输入字节数。
  原版宽度 helper `0xf7cf0` 就是 `[x1]=(ret>>16); [x2]=(ret&0xffff)` —— 与我们
  `patch_str_unicode2oem` 的内联计算完全一致；`Str_OEM2Unicode`(0xf5960) 与 H1 原版的
  推进方式也一致（分别按 low、high 前进）。
- H1 里的硬编码绝对地址：`0x710024eb50`（adrp 页 `0x710024e000` + 0xb50 逐位解出）与
  helper `0x71000de560` 均正确（前提：fs 按链接基址 `0x7100000000` 加载，KIP 固定装载）。
- 五个替换函数体内无 adrp/adr/字面量 PC 相对引用（拷贝进 fs 后地址无关）。

## 下次上机的判读方法

1. 正常启动：`log.ini` 里 `[debug] fs_stage=success`、`fs_codepage_patch_result=success`。
2. 仍卡 logo：读 `log.ini` 的 `[debug] fs_stage` —— 它指向的**下一步**就是元凶
   （例：最后是 `wildcard_r1` ⇒ R1 组把 fs 打坏了）。
3. 想快速回到可用状态：`config.ini` 里 `fs_codepage=0` 再重启。
