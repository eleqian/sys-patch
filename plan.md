# 接口

## int PFCODE_CP932_OEM2Unicode(char *oem_in,ushort *uni_out)
单个OEM字符转UTF16LE字符，返回OEM字符字节数（1/2）和UTF16LE字节数（固定2）。
### 调用点
- StringDesc_CompareUnicode：将字符串依次转成UTF16LE进行比较
- StringDesc_CompareOem：将字符串依次转成UTF16LE进行比较
- FAT_GetNextChar：先转换成UTF16LE尝试转换为大写，再转回OEM
- PFCODE_Str_OEM2Unicode：循环完成字符串转换
- FAT_MakeShortName：先转换成UTF16LE尝试转换为大写，再转回OEM
### 适配
直接替换为UTF8转UTF16LE。

## int PFCODE_CP932_Unicode2OEM(wchar_t *uni_in,char *oem_out)
单个UTF16LE字符转OEM字符，返回OEM字符字节数（1/2）和UTF16LE字节数（固定2）。
### 调用点
- FAT_GetNextChar：先转换成UTF16LE尝试转换为大写，再转回OEM
- PFCODE_Str_Unicode2OEM：循环完成字符串转换
- FAT_MakeShortName：先转换成UTF16LE尝试转换为大写，再转回OEM
### 适配
直接替换为UTF16LE转UTF8。

## ushort PFCODE_CP932_OEMCharWidth(char *oem_ch)
获取单个OEM字符的字节数（1/2），内部是调用PFCODE_CP932_OEM2Unicode实现。
### 调用点
- FAT_MakeShortName：判断短文件名空间是否够
- FAT_ReplaceShortNameNumber：判断短文件名空间是否够
### 适配
无需单独适配，内部的PFCODE_CP932_OEM2Unicode已经适配，实现获取UTF8字节数。

## bool PFCODE_CP932_isOEMMBchar(char oem_ch,int byte_idx)
判断是否是合法的多字节OEM字符，支持分别判断第一个和第二个字节。
### 调用点
- StringDesc_AddLeft：OEM字符串指针+1或+2，不能直接支持UTF8
- StringDesc_GetCharCount：OEM字符串指针+1或+2，不能直接支持UTF8
- StringDesc_CompareUnicode：OEM字符串指针+1或+2，不能直接支持UTF8
- StringDesc_CompareOem：OEM字符串指针+1或+2，不能直接支持UTF8
- FAT_GetNextChar：获取16位OEM编码或者8位OEM编码，OEM字符串指针+1或+2，不能直接支持UTF8
- FAT_MatchFileName：OEM字符串指针+1或+2，不能直接支持UTF8
- FAT_MatchWildcardRecursive：OEM字符串指针+1或+2，不能直接支持UTF8
- FAT_GetNextPathComponent：判断OEM字符是否合法，包括第一和第二字节，非法字符返回失败，不能直接支持UTF8
### 适配
UTF8中文占用3字节，无法直接兼容：
1. 接口根据首字节判断UTF8字节数，返回0~2（0-单字节，1-双字节，2-三字节，跟原来兼容），非首字节返回1（跟FAT_GetNextPathComponent处理兼容）；
2. 对增加指针的进行指令patch，接口返回0/1/2对应指针+1/+2/+3；
3. FAT_GetNextChar最多只读2字节，UTF8需要3字节，需要patch指令，正确增加指针和读取3字节内容；
4. FAT_GetNextPathComponent可以放宽检查规则，不用完整读取3字节UTF8进行校验。

## int PFCODE_CP932_UnicodeCharWidth(ushort *uni_ch)
获取单个UTF16LE字符的字节数，固定返回2，不支持代理对。

## bool PFCODE_CP932_isUnicodeMBchar(ushort uni_ch,uint byte_idx)
判断是否是多字UTF16LE字符，固定返回false，不支持代理对。
