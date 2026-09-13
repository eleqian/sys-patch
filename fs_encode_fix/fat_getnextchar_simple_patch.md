# FAT_GetNextChar 简单补丁方案

## 理解您的建议
根据您的指示："只需要把原始path->ptr_left指针传给pOEM2Unicode，不用把值取出来存局部变量，pisOEMMBchar的返回结果只用于增加path->ptr_left指针"

这意味着：
1. `FAT_GetNextChar`的主要作用是调整`path->ptr_left`指针
2. 字符转换由`pOEM2Unicode`函数处理
3. `patch_is_oem_mb_char`的返回值表示需要跳过的字节数

## 新补丁设计
在原32字节空间内实现：

### 原始代码（需要替换）：
```
e0 00 00 34  // cbz w0, label_continue
88 02 40 f9  // ldr x8, [x20]
09 05 00 91  // add x9, x8, #1  // 总是增加1
89 02 00 f9  // str x9, [x20]
08 01 40 39  // ldrb w8, [x8]
15 21 15 2a  // orr w21, w8, w21, lsl #8
e8 17 00 39  // strb w8, [sp, #0x5]
68 3e 00 12  // and w8, w19, #0xff
```

### 新代码设计：
```
// 检查w0是否为0
e0 00 00 34  // cbz w0, label_continue (保持不变)

// 根据w0的值增加ptr_left
88 02 40 f9  // ldr x8, [x20]           ; 加载ptr_left
09 00 00 8b  // add x9, x8, x0          ; x9 = x8 + w0 (根据返回值增加)
89 02 00 f9  // str x9, [x20]           ; 存储回ptr_left

// 跳过原始的数据处理逻辑
// 原始：ldrb w8, [x8] + orr w21, w8, w21, lsl #8 + strb w8, [sp, #0x5]
// 新：用nop填充或简单处理
1f 20 03 d5  // nop (4字节)
1f 20 03 d5  // nop (4字节)
1f 20 03 d5  // nop (4字节)

68 3e 00 12  // and w8, w19, #0xff (保持不变)
```

### 更完整的版本（处理数据读取）：
如果仍然需要读取数据，但根据w0的值读取不同数量的字节：

```
// 检查w0是否为0
e0 00 00 34  // cbz w0, label_continue

// 加载ptr_left并根据w0增加
88 02 40 f9  // ldr x8, [x20]
09 00 00 8b  // add x9, x8, x0          ; x9 = x8 + w0
89 02 00 f9  // str x9, [x20]

// 根据w0的值读取字节
1f 00 00 71  // cmp w0, #0
e0 03 00 54  // b.eq skip_read          ; w0==0，跳过读取

// 读取第一个字节（总是需要）
08 01 40 39  // ldrb w8, [x8]
15 21 15 2a  // orr w21, w8, w21, lsl #8
e8 17 00 39  // strb w8, [sp, #0x5]

// 检查是否需要读取更多字节
3f 04 00 71  // cmp w1, #1              ; w1 = w0 - 1?
a1 00 00 54  // b.eq skip_read          ; 如果只需要1个字节，跳过

// 读取第二个字节（w0 >= 2）
0a 05 40 39  // ldrb w10, [x8, #1]
15 21 35 2a  // orr w21, w10, w21, lsl #8
ea 1b 00 39  // strb w10, [sp, #0x6]

// 检查是否需要读取第三个字节（w0 == 3）
3f 08 00 71  // cmp w1, #2
c1 00 00 54  // b.eq skip_read

// 读取第三个字节（w0 == 3）
0b 09 40 39  // ldrb w11, [x8, #2]
15 21 55 2a  // orr w21, w11, w21, lsl #8
eb 1f 00 39  // strb w11, [sp, #0x7]

skip_read:
68 3e 00 12  // and w8, w19, #0xff
```

## 实现步骤
1. 修改`exfat_FAT_GetNextChar_patch`数组
2. 使用`add x9, x8, x0`替换`add x9, x8, #1`
3. 可能需要调整其他指令以适应空间限制