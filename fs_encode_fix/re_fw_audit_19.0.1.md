# 固件兼容性审计工具与 19.0.1 结论

> 配套工具：`fs_encode_fix/fs_fw_audit.py`
> 权威方案文档仍是 `re_utf8_patch_final.md`；本文只解决「换固件后 fs 偏移还能不能用、新偏移是多少」。

## 1. 工具用法

```bash
PY="C:/Users/eleqi/.workbuddy/binaries/python/envs/default/Scripts/python.exe"

# 一条命令：固件 zip/目录 → 解包 → 逐点比对 → 写 report.md
"$PY" fs_encode_fix/fs_fw_audit.py all "D:/Design/NS/ns_reverse/firmware/19.0.1" \
      --work "D:/Design/NS/ns_reverse/_work/e2e19"

"$PY" fs_encode_fix/fs_fw_audit.py check  --fs <FS_unc.kip1>   # 只看表格
"$PY" fs_encode_fix/fs_fw_audit.py audit  --fs <FS_unc.kip1> --work <目录>
"$PY" fs_encode_fix/fs_fw_audit.py holes  --fs <FS_unc.kip1>   # 重推「洞」
"$PY" fs_encode_fix/fs_fw_audit.py unpack <固件 zip|目录|单个 BIP NCA>
```

解包链路完全按 `ns_reverse/cmd.txt` 自动化：

```
固件目录
  └─ hactool -i 逐个问 cnmt.nca 的 Title ID == 0100000000000819   ← 定位 BootImagePackage
       └─ hactool -x --section0dir   解出 BootImagePackage_0100000000000819.cnmt
            └─ nstool  读 ContentInfo Id  → package2 的 NCA 文件名
                 └─ hactool -x --romfsdir  → romfs/nx/package2
                      └─ hactool -t pk21 --ini1dir  → ini1/FS.kip1
                           └─ hactool -t kip1 --uncompressed → FS_unc.kip1（补丁目标）
```

## 2. 三个已内置的坑（都曾导致误判）

| 现象 | 真因 | 处理 |
|---|---|---|
| 解包"成功"但目录空 | NCA 头前 0x200 字节用 header_key 加密，连 `NCA3` magic 都看不到 ⇒ **纯字节扫描读不到 Title ID** | 用 `hactool -i` 问（单次 ~80ms，116 个约 10s，结果缓存到 `cnmt_titles.json`） |
| `hactool` 返回 0 但文件没写出来，只打一行 `Failed to open ...section0\BootImagePackage...` | 它把 `--xxxdir` 的值与文件名用 `\` 硬拼：传正斜杠就成混合路径；且**不创建 base 目录** | 路径统一转反斜杠 + 预先 `makedirs`；`nstool` 则是直接报 `Path literal has both forward and backward separators` |
| 所有 29 点全部显示失效 | 传进去的是**压缩态** KIP1。压缩/解压态**头部逐字节相同**，只有文件长度不同，按偏移取到的是压缩数据 | 段表 `out_size` 超出文件实际长度或 `comp_size < out_size` 即报错并提示先 `--uncompressed` |

## 3. 定位算法

对 `main.cpp` 里每个 `fs_patch_function` 点分层定位，候选打分：

1. **同址命中** → `OK`（delta 0）
2. **全代码段精确命中**，唯一即 `MOVED`；多命中交给打分
3. **锚点投票**：取基线该点 ±64B 窗口，按 4 字节字切块，挑在新区里出现次数少的字作锚点，每次出现投一个候选基址，票高者为落点
4. **块漂移印证**：多轮迭代，把已定点的 delta 回灌候选池（"整段平移"会让大量点共享同一 delta）

打分用**语义匹配率**：`B` / `B.cond` / `CBZ` / `CBNZ` / `TBZ` / `TBNZ` / `ADR` / `ADRP` / literal `LDR` 的位移位比较时全部掩掉 —— 否则纯平移会被误读成"代码变了"。打分窗口取 `±16` / `[0,+32]` / `[-32,0]` 三个变体的**最高**值，因为补丁点常紧贴函数边界（相邻函数改了、或本函数栈帧改版），单一 ±64 宽窗会把窗口内但不属于本点的差异算进来。

`cmp 精确命中 N/29` 是关键指标：`fs_patch_function()` 打补丁前逐字节比对 `cmp`，不匹配就返回 `-2` 整点跳过。所以"定位看着对"不够，必须 cmp 命中才谈得上落地。

## 4. 结论：19.0.1（对照基线 19.exfat）

**29/29 全部定位成功，0 需人工确认、0 多命中、0 失效；cmp 精确命中 29/29。**

还有一个独立验证：把所有**指令级**补丁点在新固件里的"原始指令"与基线逐一比对，**0 处不一致** —— 即新固件待改写的位置仍是原来的指令，补丁语义不变（不是被错误地址上的相似代码骗过）。

### 4.1 新偏移（等宽字体对齐）

| 补丁点 | 旧偏移 | 新偏移 | delta |
|---|---|---|---|
| `IDirectory_Read` | 0xD4AF4 | 0xD4A94 | −96 |
| `PFCODE_CP932_OEM2Unicode` | 0xFEAC0 | 0xECD20 | −73120 |
| `PFCODE_CP932_Unicode2OEM` | 0xFEC30 | 0xECE90 | −73120 |
| `PFCODE_CP932_isOEMMBchar` | 0xFEE40 | 0xED0A0 | −73120 |
| `FAT_GetNextChar` | 0xF45D8 | 0xF9288 | +19632 |
| `FAT_GetNextPathComponent` | 0xF4D8C | 0xF995C | +19408 |
| `wc_add1_cmp` | 0xF4888 | 0xF9538 | +19632 |
| `wc_ldrb_cmp` | 0xF4894 | 0xF9544 | +19632 |
| `and_w0_cmp` | 0xF48C0 | 0xF9570 | +19632 |
| `orr_lsl8_cmp` | 0xF4898 | 0xF9548 | +19632 |
| `wc_add2_cmp` | 0xF49C4 | 0xF9674 | +19632 |
| `wc_ldrb_cmp2` | 0xF49CC | 0xF967C | +19632 |
| `orr_lsl8_cmp_b` | 0xF49D0 | 0xF9680 | +19632 |
| `wc_add1_cmp`(2) | 0xF4A90 | 0xF9740 | +19632 |
| `wc_ldrb_cmp`(2) | 0xF4A9C | 0xF974C | +19632 |
| `orr_lsl8_cmp_b`(2) | 0xF4AA0 | 0xF9750 | +19632 |
| `and_w2_cmp` | 0xF47F4 | 0xF94A4 | +19632 |
| `and_w22_cmp` | 0xF480C | 0xF94BC | +19632 |
| `cmp_uxth_w2` | 0xF4810 | 0xF94C0 | +19632 |
| `and_w22_cmp`(2) | 0xF4918 | 0xF95C8 | +19632 |
| `cmp_uxth_w21` | 0xF491C | 0xF95CC | +19632 |
| `orr_lsl8_cmp`(2) | 0xF45EC | 0xF929C | +19632 |
| `Str_Unicode2OEM` | 0xF5840 | 0xFA410 | +19408 |
| `msn_movw23_cmp` | 0xF5DCC | 0xFA8DC | +19216 |
| `AddLeft` | 0xF77E8 | 0xFC2F8 | +19216 |
| `GetCharCount` | 0xF7984 | 0xFC494 | +19216 |
| `CompareUnicode` | 0xF7A80 | 0xFC590 | +19216 |
| `CompareOem` | 0xF7BD0 | 0xFC6E0 | +19216 |
| `StringDesc_ToUpper` | 0xF7C10 | 0xFC720 | +19216 |

（完整逐点反汇编对照见审计报告 `report.md` 第 2 / 3 节。`_fs_dis.py sites` 打印的是**基线**偏移，换版本后要按本表替换。）

**注意同固件内各区段 delta 并不相同**（本版本就有 −73120 / −96 / +19408 / +19216 / +19632 五种），所以必须逐点定位，不能整体平移。

### 4.2 洞（可用空间）—— 与基线完全一致

| 替换函数 | 新偏移 | 洞 | 函数尺寸 | 余量 |
|---|---|---|---|---|
| `patch_utf8_to_utf16` | 0xECD20 | 0x170 | 0xEC | +0x84 |
| `patch_utf16_to_utf8` | 0xECE90 | 0x1D0 | 0x7C | +0x154 |
| `patch_is_oem_mb_char` | 0xED0A0 | 0x50 | 0x50 | **+0（恰好用满）** |
| `patch_str_unicode2oem` | 0xFA410 | 0x120 | 0xE0 | +0x40 |
| `patch_stringdesc_toupper` | 0xFC720 | 0xD0 | 0x94 | +0x3C |

洞边界用「锚点定位基线的相邻函数入口」推出（3/5 命中，结果与基线洞完全相同）；剩下 2 处边界函数是小 stub 或紧跟 udf 填充，改用「旧洞投影 + 边界首指令/填充特征校验」通过。函数尺寸读自 `sysmod/sys-patch.elf` 符号表。

`patch_is_oem_mb_char` 仍然**一点余量都没有** —— 以后任何改动都得先扩洞（见 `re_improve_plan.md`）。

## 5. 其它固件的比对结果（验证"能不能检出失效"）

| 样本 | 同址 | 漂移 | 需确认 | 失效 | cmp 命中 | 解读 |
|---|---|---|---|---|---|---|
| 19.exfat（基线自检） | 29 | 0 | 0 | 0 | 29/29 | 自检通过，口径正确 |
| **19.0.1（新解）** | 0 | **29** | 0 | 0 | **29/29** | 可平移升级 |
| 19.FS.kip1 | 0 | 15 | 11 | 3 | — | 该构建差异较大，连 `cmp` 都搜不到，需人工 RE |
| 1.0.0 | 0 | 0 | 8 | 21 | — | 跨 18 个大版本，绝大多数点无法自动定位（符合预期） |
| 老样本 `FS_ghidra_4/FS_unc.kip1` | 0 | 1 | 11 | 17 | — | 同上 |

对 19.FS.kip1 / 1.0.0 这类**多数点无法自动定位**的版本，工具会给出每个点的最佳候选 + 语义匹配率 + 候选集，用于人工判断；这几行也说明失效检测不是"永远报绿"。

## 6. 写回 main.cpp 的流程

1. 用 `fs_patch_function()` 的新偏移替换 `main.cpp` 里的 10 个 `0xd4af4 / 0xfeac0 / 0xfec30 / 0xfee40 / 0xf45d8 / 0xf4d8c / 0xf77e8 / 0xf7984 / 0xf7a80 / 0xf7bd0`；
2. 用 §4.1 的新偏移 + `report.md` 里各点的 `suggest` 字节更新 `cmp`；
3. 用 §4.2 的新洞更新 `sysmod/tools/check_patch_sizes.py` 的 `FUNCTIONS` 表；
4. `make` —— 构建期守卫会逐点复验尺寸、空间与每条手写机器码；
5. 上机时先留 `[options] fs_codepage=0` 保底，再用 `[fs_codepage] stage=N` 逐组验证。

`holes` 目前只用 FsImage 的**偏移含义**（文件偏移 = 0x100 + VA − 0x7100000000）估算，写回 main.cpp 时务必用**相对偏移**，运行时是 ASLR 的。
