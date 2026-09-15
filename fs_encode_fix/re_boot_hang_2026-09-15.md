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

## 根因 2（更致命）：拷贝进 fs 的函数里写死了绝对地址 —— 而加载地址是随机的

Switch 的模块有**加载地址随机化（ASLR）**，Ghidra/ELF 里的 `0x7100xxxx` 只是分析基址，
运行时毫无意义；只有**相对地址（PC 相对）**才有效。而 H1 的替换函数里有两处绝对地址：

| 代码 | 问题 |
|---|---|
| `u8 *ctx = *(u8 **)0x710024eb50ULL;` | 直接读"绝对地址"取代码页上下文 → 运行时那里是别的模块/未映射内存 |
| `patch_strncmpw_fn sw = (patch_strncmpw_fn)0x71000de560ULL;` | 绝对地址调 fs 内部 helper → 跳到随机地址 |

H1 是第 20 轮新引入的，且会在**每次 FAT 短名/路径编码转换**时执行（fs_convert_string_encoding、
fat_init_fs_object_shortname）——读到的"上下文指针"是垃圾 → 紧接着解引用 `ctx[0x48]` 即数据中止
→ fs 挂死 → 系统卡 logo、日志写不出来。**这与现场完全吻合。**

同类陷阱：`-fPIE` 下 `(uintptr_t)&函数名` 也会走 `.data.rel.ro` 指针槽（不是 PC 相对），
拷贝进 fs 同样是错的（实测 GCC 生成了 `adrp; ldr` 去读 .data.rel.ro.local）。

**修复**：H1 改为完全位置无关、完全自包含：
- 用**原版同款** PC 相对方式取 fs 上下文槽（两条指令，页增量是编译期常量）：
  `adrp x3, +0x159000` → `fs+0x24e000`；`ldr x3, [x3, #0xb50]` → `fs+0x24eb50` 槽；
- 普通模式的 UTF-16→UTF-8 直接**内联**（等价于 patch_utf16_to_utf8），不再调用 fs 回调；
- 特殊映射模式直接比较 u16，不再调用 helper `0xde560`；
- 函数体内不得出现绝对地址物化、外部函数调用、外部数据/字面量池引用。
- 页增量的前提：本函数固定落在 `fs+0xf5840`（页 `0xf5000`），洞约束 ≤0x120 保证不跨页 —— 守卫里已断言。

## 根因 3：我自己加的诊断日志造成死锁（第 3 次卡机的直接原因）

现场：`log.ini` 只剩

```
[debug]
fs_stage=start
```

即"start"之后、"converters"之前就没再写下去——但这两者之间**一个补丁都还没应用**。

原因：`svcDebugActiveProcess()` 附加到 fs 后，**fs 的线程是挂起的**（调试附加语义，
必须 `svcContinueDebugEvent` 才会继续）。而我新加的 `fs_stage()` 在附加之后去写
`log.ini` —— 写 SD 必须经过 fs 服务 → **永久阻塞** → sys-patch 永远不返回 →
boot2 阶段卡在 logo。

**教训**：附加调试期间**不能做任何依赖被调试进程的操作**（写 SD 日志尤甚）。log.ini
为空时不要只想到"补丁打坏了 fs"，也可能是"日志自己卡住了"。

修正：
- `fs_stage()` 改为只更新内存里的步骤名，落盘交给 main() 在脱附之后统一做；
- 附加之前由 main() 先写一条 `fs_codepage=start` 标记（此时 fs 还活着，安全）。
- 补丁阶段若真挂死，日志必然为空，因此改用 `config.ini` 的逐组开关二分定位（见下）。

## 逐组二分开关（排障用，改配置即可，无需重编）

`config.ini`：

```
[options]
fs_codepage=1          ; 0 = 完全跳过 fs 编码补丁（救砖）
[fs_codepage]
stage=6                ; 应用到第几组：0=都不应用 1=转换器 2=+FAT调用点 3=+R1
                       ;               4=+R2短名 5=+H1 6=全部（默认）
```

判定：能起来就往上加一级，卡住则该级就是元凶；`fs_codepage_patch_result` 会记录
最后到达的组名。

## 根因汇总与修复

1. H1 去绝对地址（见上）：改为 PC 相对取 fs 上下文槽 + 内联转换，函数完全自包含。
2. 机器码改正：
   - 0xf4888 / 0xf4a90：`2A 01 00 0B`（`add w10,w9,w0`）
   - 0xf49c4：`28 03 00 0B`（`add w8,w25,w0`）
   - 0xf45d8：`09 01 00 8B`（`add x9,x8,x0`）
3. **构建期守卫扩展**（`sysmod/tools/check_patch_sizes.py`），现在覆盖三类错误：
   a) **尺寸/标签**：`.text.<名>` + `<名>_end` 标签距离 == ELF st_size，且 ≤ 补丁位空洞；
   b) **指令编码**：解析 main.cpp 每个 `fs_patch_function` 点，被改动的 32 位字只允许
      `nop` / `movz`（Rd 与原指令一致）/ `add Rd,Rn,w0`（imm6=0、shift=0、Rm=w0、Rd/Rn 不变）/
      同址访问宽度改写（`ldrb→ldrh`、`strb→sturh`）；
   c) **ASLR 位置无关性**（新增，扫描 5 个替换函数的机器码）：禁止 MOVZ/MOVK 拼出 ≥0x1000000
      的宽常量（绝对地址）、`LDR` 字面量池、`BL` 调用、跳出函数的 `B`；`ADRP` 只允许
      "自相对 +ADD" 或"fs 上下文槽 +0x159000/+0xb50" 一种形式，并断言该指令仍落在
      fs 页 0xf5000（否则页增量算错）。
   另外若存在 fs 目标二进制（`$FS_KIP1` 或本机 RE 副本），逐点比对 cmp 字节，防偏移/固件
   不匹配。自带最小 AArch64 解码，不依赖 capstone。
   **负向测试**：4 处错误编码、以及 H1 的旧绝对地址版本，全部会被拦下（退出码 1）。
4. **分步进度落盘**（关键诊断）：`fs_stage()` 在每组补丁**之前**把步骤名写进
   `log.ini` 的 `[debug] fs_stage`（`start → converters → fat_callsites → wildcard_r1 →
   makeshortname_r2 → h1_unicode2oem → r4_toupper → success`）。fs 一旦被补丁打坏就会
   挂死、之后再也写不了日志 —— 所以挂死时日志里**最后一条 fs_stage 就是罪魁步骤**。
5. **逃生开关**：`config.ini` 新增 `[options] fs_codepage=1`。置 0 可完全跳过 fs 编码
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
