# PPSSPP / RetroArch 闪退诊断（2026-09-16）

机器环境：FW 19.0.1、AMS 1.10.2、emuMMC、SD 卡 380GB FAT32（卷标 SWITCH SD）
sys-patch：`1.5.9-5d84498-dirty`（2026-09-15 23:50:57 自编译），`fs_codepage=1`，
`fs_codepage_patch_result=success`，`[fs_codepage] stage=6`（= 全量应用）。

---

## 一、结论速览

| # | 结论 | 把握 |
|---|------|------|
| 1 | **RetroArch：主程序 1.22.1 vs 核心 1.22.2，46/48 核心不配套** | **确凿** |
| 2 | **崩溃点是"退出时的二次崩溃"，不是第一现场** | 确凿 |
| 3 | **与 9/15 启用的 fs 编码补丁无关**（4 月同址同型崩溃在补丁之前） | 高 |
| 4 | PPSSPP：换 nro（2/12）之后就再没起来过；启动即扫 `/Roms/PSP`（中文名目录） | 高（因果待上机验证） |
| 5 | SD 卡有 FAT 损坏史（`FOUND.000`，2026-02-15） | 确凿，背景风险 |

---

## 二、RetroArch —— 版本不配套（铁证）

从 nro 二进制里提取的版本字符串：

| 组件 | Version 字符串 | 时间 | 数量 |
|---|---|---|---|
| `switch/retroarch_switch.nro`（主程序） | **1.22.1** | 2026-01-13 23:52 | 1 |
| `retroarch/cores/*.nro` | **1.22.2** | 2026-02-10 ~ 02-11 | **46** |
| `retroarch/cores/*.nro` | 1.22.1 | 2025-11-16 | 2（dinothawr、dosbox_svn） |

**46 个核心比主程序高一个小版本。** Switch 版 RetroArch 的核心与主程序是静态链接、
必须同一构建，差一个小版本就 ABI 不兼容 —— 与"菜单正常、load core 闪退"完全吻合。

成因链条（来自 `retroarch/retroarch.cfg`）：

```
core_updater_buildbot_cores_url =
    "http://buildbot.libretro.com/nightly/nintendo/switch/libnx/latest/"
```

主程序是 1/13 手动放的 release，核心是 2/11 用**内置 core updater 拉的 nightly**
—— 更新器只更新核心，不会更新主 nro。

附带问题：
- `retroarch/info/` 只有 6 个 `.info`（全是 1/13 那批），**48 个核心全部缺 info**；
  `core_info.cache` 是 1/13 的陈旧二进制缓存。
- `cores/` 目录下混进了 `savefiles/`、`savestates/`、`system/` 三个子目录。

---

## 三、崩溃现场：为什么"崩溃点不是第一现场"

昨夜 `00:02:52`–`00:06:34` 连续 7 份报告，两个 program id 交替：

- `01524d47b3c10000` → Process Name "Retroarch F"
- `05446530aca7e000` → Process Name "Application"（PPSSPP）

全部 7 份特征一致：

```
Result: 0x4A8 (2168-0002)
Type:   Data Abort
X[0]  = X[20] = 0xFFFFFFFxxxxxxxxx   ← 被解引用的 this 指针（每次不同）
X[1]  = PC - 0x14
Fault Address: 0x0
```

反汇编 `PC-0x14`：PPSSPP_GL / retroarch_switch / appstore / NX-Shell
四个**毫无关系**的 nro 在该处是**逐字节相同的代码**：

```asm
cbz  x0, ret_null              ; if (this == NULL) return
stp  x29, x30, [sp,#-0x20]!
mov  x29, sp
stp  x19, x20, [sp,#0x10]
mov  x20, x0
ldr  x19, [x0]                 ; ← 崩溃点：解引用垃圾 this
cbz  x19, skip
loop:
add  x0, x19, #0x50            ; 节点 payload
ldr  x19, [x19, #0x20]         ; next
bl   <destroy>                 ; 逐个销毁
cbnz x19, loop
mov  x0, x20
b    <operator delete>         ; tail-call 释放容器
```

再追调用者（PPSSPP `+0xb9b32c`）：遍历 27 个条目（`cmp x19, #0x1b`）、
按 bitmask 判活、逐个 `blr x1` —— 即 libstdc++ **`__cxa_finalize` 静态对象析构**。

**含义**：程序已经走到 `exit()`，清理静态对象时才炸。用户看到的"闪退"
= 启动/加载失败 → 退出 → 清理阶段二次崩溃。所以崩溃报告里的 PC 是**结果不是原因**。

### 4 月对照样本（排除自家补丁的关键）

| 报告 | 时间 | X1 |
|---|---|---|
| `01776610819_01524d47b3c10000` | 2026-04-19 23:00 | `PPSSPPSDL + 0xe1c6d0` |
| `01776701096_05446530aca7e000` | 2026-04-21 00:04 | `PPSSPPSDL + 0xe1c6d0` |
| `01789488221_01524d47b3c10000` | 2026-09-16 00:03 | `PPSSPPSDL + 0xe1c6d0` |

同文件、同偏移、同异常类型。**4 月崩溃时 fs 编码补丁尚不存在**（9/15 才启用）→ 补丁非根因。
（补丁本身状态也正常：`stage=6` 在源码里是"全部 7 组都应用"，不是截断。）

---

## 四、PPSSPP

配置**是存在的**（此前扫描因 SD 读卡器掉线误判为"无配置"，已修正）：

`switch/ppsspp/config/ppsspp/PSP/SYSTEM/ppsspp.ini`（14040 B，2026-01-21 00:05）

```
[General]
RunCount          = 3            ← 总共只成功启动过 3 次
CurrentDirectory  = /Roms/PSP    ← 启动即扫这个目录
Language          = zh_CN
GameListScrollPosition = 925.5   ← 曾成功显示过游戏列表
[Recent]
MaxRecent         = 60           ← 但一条 RecentIsos 都没有 = 从未成功载入过游戏
```

时间线：

- **2026-01-21**：配置最后一次落盘 = 最后一次成功运行
- **2026-02-12 02:04**：`PPSSPP_GL.nro` + assets 更新
- 此后：一直是闪退（4 月、9 月的崩溃报告为证）

即：**换了新 nro 之后就再没起来过**。

nro 与 assets 时间戳同为 2026-02-12 02:04，assets 内容完整
（lang/ shaders/ vfpu/ flash0/ themes/ debugger/ 及各 atlas 齐全），**二者是配套的**，
所以不是"assets 与 nro 版本不匹配"这类简单问题。

### 两个待验证嫌疑

1. **启动即扫中文名目录（主嫌疑）**
   `CurrentDirectory = /Roms/PSP`，而该目录是全卡非 ASCII 重灾区之一：
   33 个 `.iso` + 2 个 `.cso` 中文名，外加 `media/` 下 416 个中文名封面文件。

2. **`/switch/ppsspp` 与 `/switch/PPSSPP` 两个仅大小写不同的目录并存**
   逐文件核对（前 64KB md5）：**内容完全相同的重复拷贝**，白占约 27MB。
   Switch 的 fs 路径大小写不敏感，两份同名目录属未定义行为。

---

## 五、与 fs 编码补丁的关系

- 补丁状态正常：`fs_codepage=1`、`stage=6`（= 全量）、`result=success`。
- 4 月的同址同型崩溃证明问题早于补丁 → **补丁不是根因**。
- 仍建议做一次零成本排除：`/config/sys-patch/config.ini` 改 `fs_codepage=0`
  → 重启 → 复测。若关掉后依旧闪退，即可彻底排除。

---

## 六、其他背景风险

- SD 卡根目录 `FOUND.000`（2026-02-15，内含 `FILE0000.CHK`）—— chkdsk 曾修复丢失簇，
  文件系统出过问题。**先整卡备份再考虑 chkdsk / 重格。**
- 全卡 **8309 个非 ASCII 条目**，集中在 `Roms/`（FC/GBA/SFC/…/PSP）；
  RetroArch 的 `rgui_browser_directory` 也指向 `/Roms`。
- SaltyNX（`0000000000534C56`）在跑，但 `/SaltySD` 下**无 plugins 目录**，
  只有 core 与 bootstrap，未发现实际注入插件 —— 暂不列嫌疑。

---

## 七、处理顺序

1. **整卡备份**（有损坏史）。
2. **RetroArch**（确定性问题）：不要用内置 updater 单独更新核心。
   取同一构建源（1.22.2 的 nightly 或 release）把 `retroarch_switch.nro`
   + `cores/` + `info/` **整套替换**；换前把 `cores/`、`info/` 整个删掉，别覆盖混装。
   替换后删掉 `cores/` 下的 `savefiles/ savestates/ system/` 三个目录。
3. **PPSSPP**：
   a. 先做最小验证 —— 把 `ppsspp.ini` 的 `CurrentDirectory` 从 `/Roms/PSP`
      临时改成 `/`，重启 PPSSPP。能起来 ⇒ 就是中文 ROM 目录这条线；
      仍闪退 ⇒ 回到 nro 本身（重下完整包）。
   b. 删掉重复的 `/switch/PPSSPP`（省空间 + 消除大小写歧义）。
4. **排除自家补丁**：`fs_codepage=0` 重启复测。
5. 都试过仍不行，再处理 SD 卡文件系统。
