# 中文文件名支持解决方案

## 问题分析

1. **现有补丁已经实现了**：
   - `patch_utf8_to_utf16` - 替换 `PFCODE_CP932_OEM2Unicode`
   - `patch_utf16_to_utf8` - 替换 `PFCODE_CP932_Unicode2OEM`
   - `patch_is_oem_mb_char` - 替换 `PFCODE_CP932_isOEMMBchar`
   - 已经对多个调用点进行了指令patch

2. **主要问题**：
   - `FAT_GetNextChar`（即`StringDesc_GetNextChar`）最多只读2字节，但UTF8中文需要3字节
   - 现有的`patch_is_oem_mb_char`函数返回0/1/2/3，但调用点可能没有正确处理返回值

3. **关键函数分析**：
   - `FAT_GetNextChar` 在地址 `0x71000f45c0`
   - 调用 `PFCODE_CP932_isOEMMBchar` (偏移0x30) 检查是否为多字节字符
   - 如果返回非0，则读取额外的一个字节（总共2字节）
   - 但UTF8中文需要3字节，`patch_is_oem_mb_char` 返回2

## 解决方案

### 方案1：修改 `FAT_GetNextChar` 函数（推荐）

我们需要修改 `FAT_GetNextChar` 函数，使其能够根据 `patch_is_oem_mb_char` 的返回值读取1、2或3个额外字节。

**需要修改的汇编代码**（地址 `0x71000f45dc-0x71000f45f0`）：
```
0x71000f45d8: cbz w0,0x71000f45f4
0x71000f45dc: ldr x8,[x20]
0x71000f45e0: add x9,x8,#0x1
0x71000f45e4: str x9,[x20]
0x71000f45e8: ldrb w8,[x8]
0x71000f45ec: orr w21,w8,w21, LSL #0x8
0x71000f45f0: strb w8,[sp, #0x5]
```

**修改思路**：
1. 保存 `patch_is_oem_mb_char` 的返回值
2. 根据返回值读取相应数量的额外字节
3. 组合成完整的UTF8字符

**具体实现**：
我们需要用新的汇编代码替换这段代码，新代码应该：
1. 检查返回值 `w0`
2. 如果 `w0 == 0`：跳转到原地址 `0x71000f45f4`
3. 如果 `w0 == 1`：读取1个额外字节（原行为）
4. 如果 `w0 == 2`：读取2个额外字节
5. 如果 `w0 == 3`：读取3个额外字节（但4字节UTF8不支持，应返回错误）

### 方案2：修改 `patch_is_oem_mb_char` 函数

另一种方案是修改 `patch_is_oem_mb_char`，使其对于3字节UTF8字符返回1（而不是2），然后修改其他相关代码。

但这种方法更复杂，因为需要修改多个调用点。

## 实现步骤

### 步骤1：分析 `FAT_GetNextChar` 的内存布局

我们需要知道要替换的代码的确切字节。从现有补丁代码看，已经有一些比对字节：
```cpp
const u8 exfat_cmp_bytes3[16] = {
    0x08, 0x00, 0x01, 0x51, 0x49, 0x00, 0x80, 0x12, 0x3f, 0x81, 0x20, 0x6b, 0x08, 0x1d, 0x00, 0x12
};
```

### 步骤2：编写新的 `FAT_GetNextChar` 补丁函数

我们需要编写一个新的函数来处理UTF8字符读取，然后替换 `FAT_GetNextChar` 中的相关代码。

### 步骤3：更新现有补丁代码

修改 `sysmod/src/main.cpp` 中的 `fs_codepage_patch` 函数，添加对 `FAT_GetNextChar` 的补丁。

## 测试计划

1. 编译并部署补丁
2. 创建中文文件名测试
3. 测试文件打开、读取、写入操作
4. 测试目录遍历

## 风险与注意事项

1. **兼容性**：确保补丁不影响非中文文件名
2. **性能**：UTF8处理可能比CP932慢
3. **内存安全**：确保不会读取越界
4. **错误处理**：正确处理无效UTF8序列