# M6 目标函数 · Ghidra 逆向与跨版本功能对比

> 目标：用 Ghidra 反编译 `p11–p26`（15 个补丁点）所共用的那个函数，
> 输出可读伪代码，并判定 **22 个固件版本里该函数的实现是否功能等效**。

---

## 1. 怎么让 Ghidra 加载 fs 固件

fs 是 **KIP1** 格式（`FS_unc.kip1`），Ghidra **没有 KIP1 loader**。
直接把 KIP1 当 raw binary 喂进去也不行 —— Ghidra 会对 2.4 MB 做盲目代码扫描，
而且 `adrp` 指向的 fs 编码上下文槽（在 `.rwdata`）无法解析成数据引用。

做法：把 KIP1 的段拼成一个极简 **AArch64 ET_EXEC ELF**（`_m6_ghidra_prep.py`）。

| 段 | 文件偏移 | 运行期地址 | 权限 |
|---|---|---|---|
| `.text` | `0x100` | `0x0` | R+X |
| `.rodata` | `0x100 + text_size` | `page_align(text_size)` | R |
| `.rwdata` | `0x100 + text_size + rodata_size` | `header[0x40]` | RW |

模块基址取 `0x7100000000`（本工程统一约定）。

⚠️ **踩到的坑**：文件里三段是**紧挨着**的，但运行期 `.rodata/.rwdata` 有页对齐
（例如 19.0.1/081b 的 text 数据只有 `0x1CB0E4`，rodata 运行期却在 `0x1CC000`，
差 `0xF1C`）—— **文件偏移 ≠ 运行期偏移**，必须逐段换算。
公式 `0x100 + text_size(0x24) + rodata_size(0x34) + rwdata_size(0x44) == 文件大小`
在 **48 个变体上 100% 成立**，据此定段。

反编译用 `analyzeHeadless -noanalysis` + 脚本 `M6Decomp.java`（定向反汇编目标范围、
就地建函数、`DecompInterface` 出 C）。全程序分析要 90–120 秒且会被环境回收，
定向方案是秒级。

---

## 2. 各版本反编译结果

| 形状 | 固件（fs 二进制代表） | 入口偏移 | 反编译的函数 | 字节 | 指令 | 栈帧 | fs 编码槽 |
|---|---|---|---|---|---|---|---|
| A | 17.0.0 / 18.x | `0xe7a30` | `FUN_71000e7a30` | 860 | 215 | 0x90 | `0x23be90` |
| A | 18.0.0 / 18.0.1 / 18.1.0 | `0xe87f0` | `FUN_71000e87f0` | 860 | 215 | 0x90 | `0x23d138` |
| A | 19.0.1 fat32(0819) | `0xf9420` | `M6_target` | 860 | 215 | 0x90 | `0x240b50` |
| A | 19.0.1 exfat(081b) | `0xf4770` | `M6_target` | 860 | 215 | 0x90 | `0x24eb50` |
| A | 20.0.0–20.5.0 | `0xff500` | `M6_target` | 860 | 215 | 0x90 | `0x263f40` |
| B | 21.0.0 / 21.0.1 / 21.1.0 / 21.2.0 | `0x104e00` | `M6_target` | 876 | 219 | 0x90 | `0x25cbc8` |
| B | 22.0.0 / 22.1.0 / 22.5.0 | `0x107660` | `FUN_7100107660` | 876 | 219 | 0x90 | `0x25fc38` |
| C | 16.1.0 | `0xe32b0` | `M6_target` | 892 | 223 | 0x80 | `0x2797d0` |

全部 8 个代表性版本反编译成功（`decompile = OK`）。

---

## 3. 这个函数是什么

伪代码（以 19.0.1 exfat / 081b 为例，已重命名便于阅读）：

```c
// 参数：c1 = 模式串当前字符，s1 = 模式串描述符
//       c2 = 输入串当前字符，s2 = 输入串描述符
// 返回：是否匹配
bool match(uint c1, StringDesc *s1, uint c2, StringDesc *s2)
{
    Ctx *ctx = *(Ctx **)0x710024EB50;   // fs 编码上下文（.rwdata）
    for (;;) {
        if ((c2 & 0xffff) == '?') { if ((c1 & 0xffff) == 0) goto FAIL; }   // '?' 恰好吃 1 个字符
        else {
            if ((c2 & 0xffff) == 0) return (c1 & 0xffff) == 0;              // 同时结束 = 匹配
            if ((c2 & 0xffff) == '*') goto STAR;                            // '*': 回溯匹配
            if ((c1 & 0xffff) != (c2 & 0xffff)) goto FAIL;
        }
        c1 = next_char(s1);   // 从 s1 读下一个字符（下详）
        c2 = next_char2(s2);
    }
}
```

`next_char` 是**编码域感知**的（这正是整个补丁系列要改写的地方）：

- `encode_type == 1`（UTF-16）：按 `u16` 读，`pos += 2`，边界 `pos < 0x20B`；
- 否则（OEM/ASCII）：按 `u8` 读，`pos += 1`，边界 `pos < 0xB`；
  再调 `(*(ctx + 0x30))(byte, 1)` 判「是否多字节前导」→ 是则再读一字节，
  用 `CONCAT11(b0, b1)` 合成双字节；
- 然后做两次**大小写折叠**：`'a'..'z' → -0x20`，再 `'A'..'Z' → -0x20`
  （即 `+0xBF` / `-0x61` 那两组比较）。

`STAR` 分支是标准的通配符回溯：跳过连续的 `*`/`?`，若到串尾则匹配成功；
否则对 `s2` 的每个剩余位置**递归调用自身** `match(...)`，任一成功即成功。

> 这也解释了 M6 报告里的两个发现：函数读的全局就是 `patch_str_unicode2oem`
> 收割的那个 **fs 编码上下文槽**；且函数含 **1 处自递归 `bl`**。

---

## 4. 跨版本归一化对比

对 8 份反编译结果做 5 层递进归一化，逐层剥掉噪声：

| 层级 | 归一化内容 | 分组数 |
|---|---|---|
| N0 raw | 原样 | 8 |
| N1 sym | 函数名/标签/代码地址符号化 | 5 |
| N2 ctx | 再把 fs 编码槽归一成 `CTX` | 5 |
| N3 var | 再把 Ghidra 局部变量名归一 | **3** |
| N4 skeleton | 再剥掉类型/标识符，只留控制流与运算符 | **3** |
| N5 set | N4 + 抹掉跳转标签编号（顺序无关） | **3** |

**N3 起稳定为 3 组，与指令级分析（capstone）得到的 3 个形状完全对应：**

| 组 | 成员 | 对应形状 |
|---|---|---|
| 1 | 16.1.0 | **C** |
| 2 | 17.0.0, 18.0.0, 19.0.1(0819/081b), 20.0.0 | **A** |
| 3 | 21.0.0, 22.0.0 | **B** |

### 常数指纹（最直接的等效证据）

从 C 代码里抽出全部非地址立即数：**8 个版本全部是同一集合，14/14 完全相同**。

```
0xb  0xc  0x10  0x19  0x20  0x2a  0x30  0x3f
0x61 0xbf 0x20a 0x20b 0xffe0 0xffff
```

（`0xb/0xc` = OEM 路径边界，`0x20a/0x20b` = UTF-16 路径边界，`0x2a/0x3f` = `*`/`?`，
`0x61/0x19/0xbf/0xffe0` = 大小写折叠，`0x30` = ctx 内回调偏移，`0x20` = 空格。）

---

## 5. 差异到底在哪

### A ↔ A（同形状内，如 19.0.1 的 fat32/exfat，17.0.0 vs 20.0.0）

N3 后逐字相同。差异只有：

- **数据槽地址**（`0x240B50` / `0x24EB50` / `0x23BE90` / `0x263F40` …）
- Ghidra 栈槽命名（`uStack_58` ↔ `uStack_68`）与指针/数组的书写形式

### A ↔ C（16.1.0）

骨架层只差 **5 行**，且全是**书写形式**：

```diff
- = CONCAT11 ( , [ 1 ] ) ;
+ = CONCAT11 ( , * ( + + 1 ) ) ;        // A[B] 与 *(A+B) 同一件事
- = ( + ) ;
+ = * ( + ) ;
```

另外 16.1.0 的栈帧是 `sub sp,#0x80`，A/B 是 `sub sp,#0x90`（差 16 字节）。
已知这对应 M6 报告里的 **bfi 族（2 个二进制）vs orr 族（20 个）**。

### A ↔ B（21/22）

这是差异最大的一对（N3 后 38 行），但**全部是编译产物差异**：

1. **基本块排列顺序不同** —— A 把「UTF-16 读取块」放前面、OEM 块放后面；
   B 反过来。两者被同一个循环用 `if (encode_type == 1)` 选择。
2. **等价指令选择不同**：

   | 语义 | A（orr 族） | B |
   |---|---|---|
   | `x - 0x20` | `add w, w, #0xffe0` | `sub w, w, #0x20` |
   | `(x - 0x61) < 0x1a` | `cmp w, #0x1a` on `sub #0x61` | `add #0xbf` + `and #0xffff` + `cmp` |
   | 组装双字节 | `orr wD, wN, wM, lsl #8` | `bfi wN, wM, #8, #8` |

   这些正是 E3 指纹分析里「orr 族 20 个 / bfi 族 2 个」的来源。
3. 由此产生的跳转标签编号位移（`LAB_3/4/5` ↔ `CODE_1/LAB_1/3/4`）。

**没有任何一项改变语义**：所有边界常量、通配符处理、回调调用、
双字节合成、大小写折叠、递归结构在两版里完全一致。

---

## 6. 结论

1. **功能等效。** Ghidra 反编译层与指令级分析独立收敛到**同一组 3 形状**，
   14 个立即数在所有版本里完全相同；差异可 100% 归因为
   *数据槽地址 / 栈帧布局 / 寄存器分配 / 等价指令选择 / 基本块顺序*。
2. **这对 M6 是好消息也是坏消息：**
   - 好消息：只需 **3 份实现**（不是 22 份）；
   - 坏消息：**不是 1 份**。M6 若要做，得维护 3 份整函数实现，
     并承担每版本 8 处 PC 相对引用回填 —— 详见 `fs_encode_fix/补丁点合并优化分析·演进史.md` §9。
3. **副产品**：形状 A 的函数体（12 个二进制逐字节相同）可当 **P2 的定位校验器**。

---

## 附录 · 三个形状的代表反编译全文

### 形状 A · 19.0.1 exfat(081b)（入口偏移 `0x19.0.1_081b`）

```c
bool M6_target(uint param_1,long *param_2,uint param_3,undefined8 *param_4)

{
  long lVar1;
  long lVar2;
  byte bVar3;
  ushort uVar4;
  ushort uVar5;
  long lVar6;
  bool bVar7;
  int iVar8;
  uint uVar9;
  undefined4 uVar10;
  short sVar11;
  uint uVar12;
  uint uVar13;
  ulong uVar14;
  undefined8 uStack_88;
  undefined8 uStack_80;
  undefined8 uStack_78;
  long lStack_70;
  undefined8 uStack_68;
  
  lVar6 = lRam000000710024eb50;
  do {
    if ((param_3 & 0xffff) == 0x3f) {
      if ((param_1 & 0xffff) == 0) goto LAB_71000f4aa8;
    }
    else {
      if ((param_3 & 0xffff) == 0) {
        return (param_1 & 0xffff) == 0;
      }
      if ((param_3 & 0xffff) == 0x2a) goto LAB_71000f48b4;
      if ((param_1 & 0xffff) != (param_3 & 0xffff)) goto LAB_71000f4aa8;
    }
    sVar11 = (short)param_2[1];
    uVar4 = *(ushort *)((long)param_2 + 10);
    if (sVar11 == 1) {
      if (uVar4 < 0x20b) {
        sVar11 = 1;
        uVar5 = *(ushort *)(*param_2 + (ulong)uVar4);
        *(ushort *)((long)param_2 + 10) = uVar4 + 2;
        uVar12 = uVar5 - 0x20;
        if (0x19 < uVar5 - 0x61) {
          uVar12 = (uint)uVar5;
        }
        param_1 = uVar12 - 0x20;
        if (0x19 < (uVar12 + 0xbf & 0xffff)) {
          param_1 = uVar12;
        }
      }
      else {
        sVar11 = 1;
        param_1 = 0;
      }
    }
    else if (uVar4 < 0xc) {
      *(ushort *)((long)param_2 + 10) = uVar4 + 1;
      bVar3 = *(byte *)(*param_2 + (ulong)uVar4);
      uVar12 = (uint)bVar3;
      iVar8 = (**(code **)(lVar6 + 0x30))(bVar3,1);
      if (iVar8 != 0) {
        uVar4 = *(ushort *)((long)param_2 + 10);
        *(ushort *)((long)param_2 + 10) = uVar4 + 1;
        uVar12 = (uint)CONCAT11(bVar3,*(undefined1 *)(*param_2 + (ulong)uVar4));
      }
      sVar11 = (short)param_2[1];
      param_1 = uVar12 + 0xffe0;
      if (0x19 < uVar12 - 0x61) {
        param_1 = uVar12;
      }
    }
    else {
      param_1 = 0;
    }
    param_3 = func_0x0071000f44e0(param_4,sVar11);
  } while( true );
code_r0x0071000f4a18:
  if (0x20a < uVar4) goto LAB_71000f4aa8;
  uVar5 = *(ushort *)(*param_2 + (ulong)uVar4);
  *(ushort *)((long)param_2 + 10) = uVar4 + 2;
  uVar12 = uVar5 - 0x20;
  if (0x19 < uVar5 - 0x61) {
    uVar12 = (uint)uVar5;
  }
  param_1 = uVar12 - 0x20;
  if (0x19 < (uVar12 + 0xbf & 0xffff)) {
    param_1 = uVar12;
  }
  goto joined_r0x0071000f48f0;
LAB_71000f48b4:
  do {
    do {
      uVar9 = func_0x0071000f44e0(param_4,(short)param_2[1]);
      uVar12 = uVar9 & 0xffff;
    } while (uVar12 == 0x2a);
  } while (uVar12 == 0x3f);
  if (uVar12 == 0) {
LAB_71000f48d8:
    bVar7 = true;
  }
  else {
joined_r0x0071000f48f0:
    if ((param_1 & 0xffff) != 0) {
      do {
        if ((param_1 & 0xffff) == (uVar9 & 0xffff)) {
          lVar1 = *param_2;
          lVar2 = param_2[1];
          uStack_88 = *param_4;
          uStack_80 = param_4[1];
          uStack_68._2_2_ = (ushort)((ulong)lVar2 >> 0x10);
          uVar4 = uStack_68._2_2_;
          uVar14 = (ulong)uStack_68._2_2_;
          uStack_78 = param_4[2];
          uStack_68._0_2_ = (undefined2)lVar2;
          uStack_68._4_4_ = (undefined4)((ulong)lVar2 >> 0x20);
          lStack_70 = lVar1;
          if (((uint)lVar2 & 0xffff) == 1) {
            if (uStack_68._2_2_ < 0x20b) {
              uStack_68._0_4_ = CONCAT22(uStack_68._2_2_ + 2,(undefined2)uStack_68);
              uVar4 = *(ushort *)(lVar1 + uVar14);
              uVar12 = uVar4 - 0x20;
              if (0x19 < uVar4 - 0x61) {
                uVar12 = (uint)uVar4;
              }
              uVar13 = uVar12 - 0x20;
              if (0x19 < (uVar12 + 0xbf & 0xffff)) {
                uVar13 = uVar12;
              }
            }
            else {
LAB_71000f4998:
              uVar13 = 0;
              uStack_68 = lVar2;
            }
          }
          else {
            if (0xb < uStack_68._2_2_) goto LAB_71000f4998;
            uStack_68._0_4_ = CONCAT22((short)(uVar14 + 1),(undefined2)uStack_68);
            bVar3 = *(byte *)(lVar1 + uVar14);
            uVar12 = (uint)bVar3;
            iVar8 = (**(code **)(lVar6 + 0x30))(bVar3,1);
            if (iVar8 != 0) {
              uStack_68._0_4_ = CONCAT22(uVar4 + 2,(undefined2)uStack_68);
              uVar12 = (uint)CONCAT11(bVar3,*(undefined1 *)(lVar1 + uVar14 + 1));
            }
            uVar13 = uVar12 + 0xffe0;
            if (0x19 < uVar12 - 0x61) {
              uVar13 = uVar12;
            }
          }
          uVar10 = func_0x0071000f44e0(&uStack_88,(short)param_2[1]);
          iVar8 = M6_target(uVar13,&lStack_70,uVar10,&uStack_88);
          if (iVar8 != 0) goto LAB_71000f48d8;
        }
        uVar4 = *(ushort *)((long)param_2 + 10);
        if ((short)param_2[1] == 1) goto code_r0x0071000f4a18;
        if (0xb < uVar4) break;
        *(ushort *)((long)param_2 + 10) = uVar4 + 1;
        bVar3 = *(byte *)(*param_2 + (ulong)uVar4);
        uVar12 = (uint)bVar3;
        iVar8 = (**(code **)(lVar6 + 0x30))(bVar3,1);
        if (iVar8 != 0) {
          uVar4 = *(ushort *)((long)param_2 + 10);
          *(ushort *)((long)param_2 + 10) = uVar4 + 1;
          uVar12 = (uint)CONCAT11(bVar3,*(undefined1 *)(*param_2 + (ulong)uVar4));
        }
        param_1 = uVar12 + 0xffe0;
        if (0x19 < uVar12 - 0x61) {
          param_1 = uVar12;
        }
        if ((param_1 & 0xffff) == 0) break;
      } while( true );
    }
LAB_71000f4aa8:
    bVar7 = false;
  }
  return bVar7;
}
```

### 形状 B · 21.0.0 / 21.0.1 / 21.1.0 / 21.2.0（入口偏移 `0x21.0.0_081b`）

```c
bool M6_target(uint param_1,long *param_2,uint param_3,undefined8 *param_4)

{
  long lVar1;
  long lVar2;
  byte bVar3;
  ushort uVar4;
  ushort uVar5;
  long lVar6;
  bool bVar7;
  int iVar8;
  uint uVar9;
  undefined4 uVar10;
  short sVar11;
  uint uVar12;
  uint uVar13;
  ulong uVar14;
  undefined8 uStack_88;
  undefined8 uStack_80;
  undefined8 uStack_78;
  long lStack_70;
  undefined8 uStack_68;
  
  lVar6 = lRam000000710025cbc8;
  do {
    if ((param_3 & 0xffff) == 0x3f) {
      if ((param_1 & 0xffff) == 0) goto LAB_7100105148;
    }
    else {
      if ((param_3 & 0xffff) == 0) {
        return (param_1 & 0xffff) == 0;
      }
      if ((param_3 & 0xffff) == 0x2a) goto LAB_7100104f44;
      if ((param_1 & 0xffff) != (param_3 & 0xffff)) goto LAB_7100105148;
    }
    sVar11 = (short)param_2[1];
    uVar4 = *(ushort *)((long)param_2 + 10);
    if (sVar11 == 1) {
      if (uVar4 < 0x20b) {
        sVar11 = 1;
        uVar5 = *(ushort *)(*param_2 + (ulong)uVar4);
        *(ushort *)((long)param_2 + 10) = uVar4 + 2;
        uVar9 = uVar5 - 0x20;
        if (0x19 < uVar5 - 0x61) {
          uVar9 = (uint)uVar5;
        }
        param_1 = uVar9 - 0x20;
        if (0x19 < (uVar9 + 0xbf & 0xffff)) {
          param_1 = uVar9;
        }
      }
      else {
        sVar11 = 1;
        param_1 = 0;
      }
    }
    else if (uVar4 < 0xc) {
      *(ushort *)((long)param_2 + 10) = uVar4 + 1;
      bVar3 = *(byte *)(*param_2 + (ulong)(uint)uVar4);
      uVar9 = (uint)bVar3;
      iVar8 = (**(code **)(lVar6 + 0x30))(bVar3,1);
      if (iVar8 != 0) {
        uVar4 = *(ushort *)((long)param_2 + 10);
        *(ushort *)((long)param_2 + 10) = uVar4 + 1;
        uVar9 = (uint)CONCAT11(bVar3,*(undefined1 *)(*param_2 + (ulong)uVar4));
      }
      sVar11 = (short)param_2[1];
      param_1 = uVar9 + 0xffe0;
      if (0x19 < uVar9 - 0x61) {
        param_1 = uVar9;
      }
    }
    else {
      param_1 = 0;
    }
    param_3 = func_0x007100104ba0(param_4,sVar11);
  } while( true );
LAB_7100105100:
  if (0xb < uVar4) goto LAB_7100105148;
  *(ushort *)((long)param_2 + 10) = uVar4 + 1;
  bVar3 = *(byte *)(*param_2 + (ulong)(uint)uVar4);
  uVar12 = (uint)bVar3;
  iVar8 = (**(code **)(lVar6 + 0x30))(bVar3,1);
  if (iVar8 != 0) {
    uVar4 = *(ushort *)((long)param_2 + 10);
    *(ushort *)((long)param_2 + 10) = uVar4 + 1;
    uVar12 = (uint)CONCAT11(bVar3,*(undefined1 *)(*param_2 + (ulong)uVar4));
  }
  param_1 = uVar12 + 0xffe0;
  if (0x19 < uVar12 - 0x61) {
    param_1 = uVar12;
  }
  goto joined_r0x007100104f80;
LAB_7100104f44:
  do {
    do {
      uVar9 = func_0x007100104ba0(param_4,(short)param_2[1]);
    } while ((uVar9 & 0xffff) == 0x2a);
  } while ((uVar9 & 0xffff) == 0x3f);
  if ((uVar9 & 0xffff) == 0) {
LAB_7100104f68:
    bVar7 = true;
  }
  else {
joined_r0x007100104f80:
    if ((param_1 & 0xffff) != 0) {
      do {
        if ((param_1 & 0xffff) == (uVar9 & 0xffff)) {
          lVar1 = *param_2;
          lVar2 = param_2[1];
          uStack_88 = *param_4;
          uStack_80 = param_4[1];
          uStack_68._2_2_ = (ushort)((ulong)lVar2 >> 0x10);
          uVar4 = uStack_68._2_2_;
          uVar14 = (ulong)uStack_68._2_2_;
          uStack_78 = param_4[2];
          uStack_68._0_2_ = (undefined2)lVar2;
          uStack_68._4_4_ = (undefined4)((ulong)lVar2 >> 0x20);
          lStack_70 = lVar1;
          if (((uint)lVar2 & 0xffff) == 1) {
            if (uStack_68._2_2_ < 0x20b) {
              uStack_68._0_4_ = CONCAT22(uStack_68._2_2_ + 2,(undefined2)uStack_68);
              uVar4 = *(ushort *)(lVar1 + uVar14);
              uVar12 = uVar4 - 0x20;
              if (0x19 < uVar4 - 0x61) {
                uVar12 = (uint)uVar4;
              }
              uVar13 = uVar12 - 0x20;
              if (0x19 < (uVar12 + 0xbf & 0xffff)) {
                uVar13 = uVar12;
              }
            }
            else {
LAB_7100105028:
              uVar13 = 0;
              uStack_68 = lVar2;
            }
          }
          else {
            if (0xb < uStack_68._2_2_) goto LAB_7100105028;
            uStack_68._0_4_ = CONCAT22((short)(uVar14 + 1),(undefined2)uStack_68);
            bVar3 = *(byte *)(lVar1 + uVar14);
            uVar12 = (uint)bVar3;
            iVar8 = (**(code **)(lVar6 + 0x30))(bVar3,1);
            if (iVar8 != 0) {
              uStack_68._0_4_ = CONCAT22(uVar4 + 2,(undefined2)uStack_68);
              uVar12 = (uint)CONCAT11(bVar3,*(undefined1 *)(lVar1 + uVar14 + 1));
            }
            uVar13 = uVar12 + 0xffe0;
            if (0x19 < uVar12 - 0x61) {
              uVar13 = uVar12;
            }
          }
          uVar10 = func_0x007100104ba0(&uStack_88,(short)param_2[1]);
          iVar8 = M6_target(uVar13,&lStack_70,uVar10,&uStack_88);
          if (iVar8 != 0) goto LAB_7100104f68;
        }
        uVar4 = *(ushort *)((long)param_2 + 10);
        if ((short)param_2[1] != 1) goto LAB_7100105100;
        if (0x20a < uVar4) break;
        uVar5 = *(ushort *)(*param_2 + (ulong)uVar4);
        *(ushort *)((long)param_2 + 10) = uVar4 + 2;
        uVar12 = uVar5 - 0x20;
        if (0x19 < uVar5 - 0x61) {
          uVar12 = (uint)uVar5;
        }
        param_1 = uVar12 - 0x20;
        if (0x19 < (uVar12 + 0xbf & 0xffff)) {
          param_1 = uVar12;
        }
        if ((param_1 & 0xffff) == 0) break;
      } while( true );
    }
LAB_7100105148:
    bVar7 = false;
  }
  return bVar7;
}
```

### 形状 C · 16.1.0（入口偏移 `0x16.1.0_081b`）

```c
bool M6_target(uint param_1,long *param_2,uint param_3,undefined8 *param_4)

{
  byte *pbVar1;
  long lVar2;
  byte bVar3;
  ushort uVar4;
  ushort uVar5;
  long lVar6;
  bool bVar7;
  int iVar8;
  uint uVar9;
  undefined4 uVar10;
  short sVar11;
  uint uVar12;
  uint uVar13;
  ulong uVar14;
  undefined8 uStack_78;
  undefined8 uStack_70;
  undefined8 uStack_68;
  long lStack_60;
  undefined8 uStack_58;
  
  lVar6 = lRam00000071002797d0;
  do {
    if ((param_3 & 0xffff) == 0x3f) {
      if ((param_1 & 0xffff) == 0) goto LAB_71000e360c;
    }
    else {
      if ((param_3 & 0xffff) == 0) {
        return (param_1 & 0xffff) == 0;
      }
      if ((param_3 & 0xffff) == 0x2a) goto LAB_71000e3400;
      if ((param_1 & 0xffff) != (param_3 & 0xffff)) goto LAB_71000e360c;
    }
    sVar11 = (short)param_2[1];
    uVar4 = *(ushort *)((long)param_2 + 10);
    if (sVar11 == 1) {
      if (uVar4 < 0x20b) {
        sVar11 = 1;
        uVar5 = *(ushort *)(*param_2 + (ulong)uVar4);
        *(ushort *)((long)param_2 + 10) = uVar4 + 2;
        uVar12 = uVar5 - 0x20;
        if (0x19 < uVar5 - 0x61) {
          uVar12 = (uint)uVar5;
        }
        param_1 = uVar12 - 0x20;
        if (0x19 < (uVar12 + 0xbf & 0xffff)) {
          param_1 = uVar12;
        }
      }
      else {
        sVar11 = 1;
        param_1 = 0;
      }
    }
    else if (uVar4 < 0xc) {
      *(ushort *)((long)param_2 + 10) = uVar4 + 1;
      bVar3 = *(byte *)(*param_2 + (ulong)uVar4);
      uVar12 = (uint)bVar3;
      iVar8 = (**(code **)(lVar6 + 0x30))(bVar3,1);
      if (iVar8 != 0) {
        uVar4 = *(ushort *)((long)param_2 + 10);
        *(ushort *)((long)param_2 + 10) = uVar4 + 1;
        uVar12 = (uint)CONCAT11(bVar3,*(undefined1 *)(*param_2 + (ulong)uVar4));
      }
      sVar11 = (short)param_2[1];
      param_1 = uVar12 + 0xffe0;
      if (0x19 < uVar12 - 0x61) {
        param_1 = uVar12;
      }
    }
    else {
      param_1 = 0;
    }
    param_3 = func_0x0071000e3030(param_4,sVar11);
  } while( true );
code_r0x0071000e3570:
  if (0x20a < uVar4) goto LAB_71000e360c;
  uVar5 = *(ushort *)(*param_2 + (ulong)uVar4);
  *(ushort *)((long)param_2 + 10) = uVar4 + 2;
  uVar12 = uVar5 - 0x20;
  if (0x19 < uVar5 - 0x61) {
    uVar12 = (uint)uVar5;
  }
  param_1 = uVar12 - 0x20;
  if (0x19 < (uVar12 + 0xbf & 0xffff)) {
    param_1 = uVar12;
  }
  goto joined_r0x0071000e343c;
LAB_71000e3400:
  do {
    do {
      uVar9 = func_0x0071000e3030(param_4,(short)param_2[1]);
      uVar12 = uVar9 & 0xffff;
    } while (uVar12 == 0x2a);
  } while (uVar12 == 0x3f);
  if (uVar12 == 0) {
LAB_71000e3424:
    bVar7 = true;
  }
  else {
joined_r0x0071000e343c:
    if ((param_1 & 0xffff) != 0) {
      do {
        if ((param_1 & 0xffff) == (uVar9 & 0xffff)) {
          lStack_60 = *param_2;
          lVar2 = param_2[1];
          uStack_78 = *param_4;
          uStack_70 = param_4[1];
          uStack_58._2_2_ = (ushort)((ulong)lVar2 >> 0x10);
          uVar4 = uStack_58._2_2_;
          uVar14 = (ulong)uStack_58._2_2_;
          uStack_68 = param_4[2];
          uStack_58._0_2_ = (undefined2)lVar2;
          uStack_58._4_4_ = (undefined4)((ulong)lVar2 >> 0x20);
          if (((uint)lVar2 & 0xffff) == 1) {
            if (uStack_58._2_2_ < 0x20b) {
              uStack_58._0_4_ = CONCAT22(uStack_58._2_2_ + 2,(undefined2)uStack_58);
              uVar4 = *(ushort *)(lStack_60 + uVar14);
              uVar12 = uVar4 - 0x20;
              if (0x19 < uVar4 - 0x61) {
                uVar12 = (uint)uVar4;
              }
              uVar13 = uVar12 - 0x20;
              if (0x19 < (uVar12 + 0xbf & 0xffff)) {
                uVar13 = uVar12;
              }
            }
            else {
LAB_71000e34e8:
              uVar13 = 0;
              uStack_58 = lVar2;
            }
          }
          else {
            if (0xb < uStack_58._2_2_) goto LAB_71000e34e8;
            uStack_58._0_4_ = CONCAT22(uStack_58._2_2_ + 1,(undefined2)uStack_58);
            pbVar1 = (byte *)(lStack_60 + uVar14);
            bVar3 = *pbVar1;
            uVar12 = (uint)bVar3;
            iVar8 = (**(code **)(lVar6 + 0x30))(bVar3,1);
            if (iVar8 != 0) {
              uStack_58._0_4_ = CONCAT22(uVar4 + 2,(undefined2)uStack_58);
              uVar12 = (uint)CONCAT11(bVar3,pbVar1[1]);
            }
            uVar13 = uVar12 + 0xffe0;
            if (0x19 < uVar12 - 0x61) {
              uVar13 = uVar12;
            }
          }
          uVar10 = func_0x0071000e3030(&uStack_78,(short)param_2[1]);
          iVar8 = M6_target(uVar13,&lStack_60,uVar10,&uStack_78);
          if (iVar8 != 0) goto LAB_71000e3424;
        }
        uVar4 = *(ushort *)((long)param_2 + 10);
        if ((short)param_2[1] == 1) goto code_r0x0071000e3570;
        if (0xb < uVar4) break;
        *(ushort *)((long)param_2 + 10) = uVar4 + 1;
        bVar3 = *(byte *)(*param_2 + (ulong)uVar4);
        uVar12 = (uint)bVar3;
        iVar8 = (**(code **)(lVar6 + 0x30))(bVar3,1);
        if (iVar8 != 0) {
          uVar4 = *(ushort *)((long)param_2 + 10);
          *(ushort *)((long)param_2 + 10) = uVar4 + 1;
          uVar12 = (uint)CONCAT11(bVar3,*(undefined1 *)(*param_2 + (ulong)uVar4));
        }
        param_1 = uVar12 + 0xffe0;
        if (0x19 < uVar12 - 0x61) {
          param_1 = uVar12;
        }
        if ((param_1 & 0xffff) == 0) break;
      } while( true );
    }
LAB_71000e360c:
    bVar7 = false;
  }
  return bVar7;
}
```

---

## 附录 · 复现步骤

```bash
cd D:/Game/NS/firmware/_audit
python _m6_ghidra_prep.py --fw Firmware.19.0.1.Rebootless --variant 081b --tag 19.0.1_081b
# Ghidra：
#   analyzeHeadless <proj> M6 -import <tag>.elf -scriptPath _ghidra_scripts \
#       -noanalysis -postScript M6Decomp.java <off> <len> <out> -deleteProject
python _m6_decomp_diff.py
```

脚本：`_m6_ghidra_prep.py`（KIP1→ELF）、`_ghidra_scripts/M6Decomp.java`（反编译）、
`_m6_decomp_diff.py`（归一化对比）、`_m6_equiv.py`（指令级等效性）。