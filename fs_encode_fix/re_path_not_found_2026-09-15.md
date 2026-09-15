# 中文名"能枚举、打不开"（FsError_PathNotFound）—— 定位与修复（2026-09-15）

## 现象

- 系统已能正常启动（卡 logo 问题见 `re_boot_hang_2026-09-15.md`）。
- 文件管理器里能看到中文名：`F:\test\test2\test中文.txt`。
- 打开该文件返回 **FsError_PathNotFound**（0x202）。

枚举能用 ⇒ LFN→UTF-16→上层显示这条链路是通的；打不开 ⇒ **路径查找/名字匹配**出问题。

## 根因 1（主因）：`isOEMMBchar` 忽略了 `byte_idx` —— idx=2 是"尾字节合法性校验"

原版 `PFCODE_CP932_isOEMMBchar(ch, idx)` 对 idx 有**两种语义**（见 0xfee40 结尾的两次 csel）：

| idx | 语义 | 返回值 |
|---|---|---|
| 1 | 该字节是不是多字节首字节 | 0/1（CP932）|
| 2 | 该字节是不是合法的**第二个字节** | 0/1 |

`FAT_GetNextPathComponent` 两个都用了：

```
0f4d78  ldrb w0, [x9]          ; 首字节
0f4d7c  blr  x8                ; isOEMMBchar(c, 1)   → 非 0 则继续
...
0f4d98  ldrb w0, [x8, #1]      ; 第二个字节
0f4d9c  blr  x9                ; isOEMMBchar(c2, 2)  → cbz 即判为非法路径
0f4da0  cbz  w0, #0xf4f08      ; ← 走到这里 = PathNotFound
```

而我们的替换函数**完全忽略 idx**（`(void)byte_idx`），R7 又让 UTF-8 续字节返回 0 ——
于是中文名的第二个字节（0x80–0xBF）被判为非法 → 路径解析直接失败 → PathNotFound。
（ASCII 名不受影响，所以英文名一直能打开。）

**修复**：按 idx 区分语义（index 1 → 额外字节数；index 2 → 续字节合法则 1）。

## 根因 2：通配符匹配点 0xf49c4 的步进少 1

`FAT_MatchWildcardRecursive` 三处 isOEMMBchar 调用点原语义都是 "idx + 1 + 多字节标志"：

| 点 | 原指令 | 语义 |
|---|---|---|
| 0xf4888 / 0xf4a90 | `add w10,w9,#1`（w9 = idx+1，见 0xf4864/0xf486c） | idx+2（CP932 双字节）|
| 0xf49c4 | `add w8,w25,#2`（w25 = idx） | idx+2 |

UTF-8 需要 **idx + 字符总长 = idx + 1 + 额外字节数**：
- 站点 1/3 用 `add w10,w9,w0`（w9 已是 idx+1）→ idx+1+extra = idx+总长 ✓
- 站点 2 的基址是 idx，单指令做不出 `idx+w0+1`；而 **x27 在 0xf49a4 已算好 idx+1**
  且为 callee-saved（调用后仍有效）→ 改用 `add w8,w27,w0`（0x0B000368）→ idx+1+extra ✓
  （3 字节中文从此前进 3 字节，之前只前进 2 → 后续字符全部错位 → 匹配失败）。

构建守卫为此加了**具名例外** `RN_OVERRIDE = {0xF49C4: 27}`（允许该点换基址寄存器）。

## 尺寸约束（很紧）

`patch_is_oem_mb_char` 的洞原本按原函数体算作 0x4C；实测 0xfee8c 是一个 `udf` 填充字
（4 字节可用），其后 0xfee90 的 `mov w0,#2; ret` 是**回调表引用的 stub，不能覆盖** ⇒
洞 = **0x50**。带 idx 判断的版本一开始是 0x58（超限，被守卫拦下），改用
`clz((~c & 0xFF) << 24) - 1` 算额外字节数后压到 **恰好 0x50**（80 字节）。
**以后再改这个函数极易超限，构建会直接报错，属预期行为。**

## 主机侧验证（gcc 实测取值表）

| 首字节 | idx=1 | idx=2 |
|---|---|---|
| 0x00–0x7F (ASCII) | 0 | 0 |
| 0x80–0xBF (续字节) | 0 | **1** |
| 0xC0–0xDF | 1 | 0 |
| 0xE0–0xEF | 2 | 0 |
| 0xF0–0xF7 | 3 | 0 |
| 0xF8–0xFF | 0 | 0 |

`中` = E4 B8 AD → 首字节 idx=1 ⇒ 2（前进 3 字节），续字节 B8 的 idx=2 ⇒ 1（校验通过）。

## 已知遗留（下一步再议）

匹配函数只拼出 **2 字节**比较值（lead<<8 | 第一个续字节），因此**前两字节相同**的
不同汉字（如 `一`=E4 B8 80 与 `丁`=E4 B8 81）会**误判为同名**。要彻底解决需把比较
宽度扩到 3 字节，属于对 `FAT_MatchWildcardRecursive` 的结构性改写，暂不在字节补丁范围内。
