# FAT_GetNextChar 补丁重新设计分析

## 原始代码分析
地址：0x71000f45d8
原始代码（32字节，8条指令）：
```
e0 00 00 34  // cbz w0, label_continue  ; 如果w0==0，跳转
88 02 40 f9  // ldr x8, [x20]           ; 加载ptr_left到x8
09 05 00 91  // add x9, x8, #1          ; x9 = x8 + 1
89 02 00 f9  // str x9, [x20]           ; 存储回ptr_left
08 01 40 39  // ldrb w8, [x8]           ; 读取字节到w8
15 21 15 2a  // orr w21, w8, w21, lsl #8 ; 合并到w21
e8 17 00 39  // strb w8, [sp, #0x5]     ; 存储到栈
68 3e 00 12  // and w8, w19, #0xff      ; w8 = w19 & 0xff
```

## 问题
1. 只处理了`w0 == 1`的情况（读取1个额外字节）
2. 当`w0 == 2`（3字节UTF8）时，需要读取2个额外字节，但代码只读取1个
3. 当`w0 == 3`（4字节UTF8）时，需要读取3个额外字节

## 新设计思路
在原32字节空间内重新设计指令，处理所有情况：

### 方案1：条件分支处理
```
// 检查w0值
cmp w0, #1
b.eq handle_1byte_extra  // w0==1: 读取1个额外字节
cmp w0, #2
b.eq handle_2byte_extra  // w0==2: 读取2个额外字节
cmp w0, #3
b.eq handle_3byte_extra  // w0==3: 读取3个额外字节
b continue               // w0==0: 直接继续

handle_1byte_extra:
// 读取1个额外字节（原始逻辑）
ldr x8, [x20]
add x9, x8, #1
str x9, [x20]
ldrb w8, [x8]
orr w21, w8, w21, lsl #8
strb w8, [sp, #0x5]
b continue

handle_2byte_extra:
// 读取2个额外字节
ldr x8, [x20]
add x9, x8, #2          // 增加2
str x9, [x20]
ldrb w10, [x8, #0]      // 第一个字节
ldrb w11, [x8, #1]      // 第二个字节
orr w21, w10, w21, lsl #8
orr w21, w11, w21, lsl #8
strb w10, [sp, #0x5]
strb w11, [sp, #0x6]
b continue

handle_3byte_extra:
// 读取3个额外字节（4字节UTF8）
ldr x8, [x20]
add x9, x8, #3          // 增加3
str x9, [x20]
ldrb w10, [x8, #0]      // 第一个字节
ldrb w11, [x8, #1]      // 第二个字节
ldrb w12, [x8, #2]      // 第三个字节
orr w21, w10, w21, lsl #8
orr w21, w11, w21, lsl #8
orr w21, w12, w21, lsl #8
strb w10, [sp, #0x5]
strb w11, [sp, #0x6]
strb w12, [sp, #0x7]
b continue

continue:
and w8, w19, #0xff
```

### 方案2：使用循环（更紧凑）
由于空间有限（32字节），可能需要更紧凑的设计。或者考虑使用跳转到扩展函数，但使用更小的跳转。

## 实际约束
- 只有32字节空间
- 需要保持寄存器使用一致
- 不能破坏原有逻辑

## 建议方案
使用跳转到扩展函数可能是最简单的，但可以优化跳转目标，使用更近的地址。