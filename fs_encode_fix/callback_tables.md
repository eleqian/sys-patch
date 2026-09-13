# FS 模块回调/虚函数表遍历清单

- 二进制: `19.exfat.FS.kip1` (KIP1, image base `0x7100000000`)
- `.got` 中指向 `.data` 的指针槽: **476** 个
- 其中槽位含 FS/FAT/NCA 命名函数的表: **171** 个

## 约定

- 对象内 `vptr` 指向 `vtable[-2]`(`offset_to_top`,`typeinfo`)，因此**方法槽 0 = vptr + 0x10**。
- `.got` 条目以 24 位重定位形式存放 `vptr`；`.data` 槽位同理存放 `target - 0x7100000000`。
- 槽位里 `0x71001c90e0` = `fs_pure_virtual_function_call`（纯虚占位）；
  `0x71001c8fc0` = `fs_stub_return_zero`；`0x7100026574`=`ret`、`0x710002657c`=`mov x0,xzr;ret`（析构桩）。

## 代码页回调表 (PFCODE 上下文, `.bss` 运行时填充)

由 `PFCODE_CP932_Init` (`0x71000d5150`) 注册。上下文对象基址 = GOT `0x710024eb50` 的值 = `0x7100fcfc38`；
`stp/str` 序列把 6 个函数指针写入对象 `+0x18..+0x40`（对应命名全局 `0x7100fcfc50..0x7100fcfc78`）：

| 槽偏移(自对象基) | 全局符号 | 地址 | 目标函数 | 目标地址 |
|--------|----------|------|----------|----------|
| `+0x18` | `pOEM2Unicode` | `0x7100fcfc50` | `PFCODE_CP932_OEM2Unicode` | `0x71000feac0` |
| `+0x20` | `pUnicode2OEM` | `0x7100fcfc58` | `PFCODE_CP932_Unicode2OEM` | `0x71000fec30` |
| `+0x28` | `pOEMCharWidth` | `0x7100fcfc60` | `PFCODE_CP932_OEMCharWidth` | `0x71000fee00` |
| `+0x30` | `pisOEMMBchar` | `0x7100fcfc68` | `PFCODE_CP932_isOEMMBchar` | `0x71000fee40` |
| `+0x38` | `pUnicodeCharWidth` | `0x7100fcfc70` | `PFCODE_CP932_UnicodeCharWidth` | `0x71000fee90` |
| `+0x40` | `pisUnicodeMBchar` | `0x7100fcfc78` | `PFCODE_CP932_isUnicodeMBchar` | `0x71000feea0` |

> 注册指令 (`0x71000d5220` 起)：`stp x19,x8,[x21,#0x10]`（`+0x10`=传入 callback），`stp x8,x9,[x21,#0x20]`，`stp x8,x9,[x21,#0x30]`，`str x8,[x21,#0x40]`；其中 `x8/x9` 分别来自 GOT `0x710024eb58/60/68/70/78/80`。
> 本 fork 的补丁点 `fs_codepage_patch()` 正作用于 `PFCODE_CP932_OEM2Unicode`/`Unicode2OEM`，即表中 `pOEM2Unicode`/`pUnicode2OEM` 两个槽的目标函数。

---

## FS 对象 vtable 访问器层 (`fs_locked_vtable_call_0xNN`)

这些内联访问器按固定偏移调用主 FS 对象的虚方法，直接给出主 vtable 的槽布局：

| 访问器 | 地址 | 目标槽偏移 |
|--------|------|-----------|
| `fs_locked_vtable_call_0x10` | `0x710011c5bc` | `+0x10` |
| `fs_locked_vtable_call_0x18` | `0x710011c8d4` | `+0x18` |
| `fs_locked_vtable_call_0x20` | `0x710011c640` | `+0x20` |
| `fs_locked_vtable_call_0x28` | `0x710011c930` | `+0x28` |
| `fs_locked_vtable_call_0x30` | `0x710011c98c` | `+0x30` |
| `fs_locked_vtable_call_0x38` | `0x710011c9e8` | `+0x38` |
| `fs_locked_vtable_call_0x40` | `0x710011ca44` | `+0x40` |
| `fs_locked_vtable_call_0x48` | `0x710011caa8` | `+0x48` |
| `fs_locked_vtable_call_0x50` | `0x710011cb0c` | `+0x50` |
| `fs_locked_vtable_call_0x58` | `0x710011cb84` | `+0x58` |
| `fs_locked_vtable_call_0x60` | `0x710011cbf8` | `+0x60` |
| `fs_locked_vtable_call_0x68` | `0x710011c69c` | `+0x68` |
| `fs_locked_vtable_call_0xa8` | `0x710011cc6c` | `+0xa8` |
| `fs_locked_file_vtable_call_0x18` | `0x710011d204` | `+0x18` |
| `fs_locked_file_vtable_call_0x28` | `0x710011cf84` | `+0x28` |
| `fs_locked_file_vtable_call_0x30` | `0x710011cf18` | `+0x30` |
| `fs_locked_file_vtable_call_0x38` | `0x710011d03c` | `+0x38` |
| `fs_call_vtable_method_10` | `0x7100087550` | `+0x-` |
| `fs_call_vtable_method_18` | `0x71001ba03c` | `+0x-` |
| `fs_call_vtable_method_indirect` | `0x7100063db8` | `+0x-` |

---

## `IDirectory_Func_Table` (`0x7100247048`)

由 `FUN_71000c92f0` 在对象首字写入 (`*obj = &IDirectory_Func_Table`)。表内 `0` 为对齐填充；
槽 7 起为内嵌子对象表 `PTR_FUN_7100247080`，槽 17 起为 `PTR_LAB_71002470d0`。

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247048` | `0x71000c93c0` |  |
| 1 | `0x7100247050` | `0x71000c93d4` | FUN_71000c93d4 (dtor) |
| 2 | `0x7100247058` | `0x71000c9408` |  |
| 3 | `0x7100247060` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100247068` | `0x71000c9414` |  |
| 7 | `0x7100247080` | `0x710004e870` |  |
| 8 | `0x7100247088` | `0x71000c9420` |  |
| 9 | `0x7100247090` | `0x710004e130` |  |
| 10 | `0x7100247098` | `0x710004e27c` |  |
| 11 | `0x71002470a0` | `0x710004e45c` |  |
| 12 | `0x71002470a8` | `0x710004e3c0` |  |
| 13 | `0x71002470b0` | `0x710004e3e8` |  |
| 14 | `0x71002470b8` | `0x710004e46c` |  |
| 17 | `0x71002470d0` | `0x71000c95d4` |  |
| 18 | `0x71002470d8` | `0x71000c95e8` | FUN_71000c95e8 (dtor) |
| 19 | `0x71002470e0` | `0x71000c961c` |  |

---

## 索引

| vptr | 槽0 | n | 标识 |
|------|-----|---|------|
| `0x7100243950` | `0x7100243960` | 129 |  |
| `0x7100244b60` | `0x7100244b70` | 54 |  |
| `0x7100247380` | `0x7100247390` | 22 | fs_idirectory_destructor (derived) |
| `0x71002445c0` | `0x71002445d0` | 22 |  |
| `0x71002476d0` | `0x71002476e0` | 22 | fs_nca_fs_obj_destructor (derived) |
| `0x710024b518` | `0x710024b528` | 53 | FUN_71001a17cc (derived) |
| `0x7100247970` | `0x7100247980` | 22 | fs_nca_fs_obj_destroy (derived) |
| `0x71002460f0` | `0x7100246100` | 17 |  |
| `0x71002458a8` | `0x71002458b8` | 16 |  |
| `0x7100245f00` | `0x7100245f10` | 15 |  |
| `0x7100247658` | `0x7100247668` | 13 | fs_locked_buffer_pool_cleanup_entries (derived) |
| `0x710024a690` | `0x710024a6a0` | 13 |  |
| `0x710023fb98` | `0x710023fba8` | 12 | FUN_7100025e10 |
| `0x71002459a8` | `0x71002459b8` | 12 |  |
| `0x710024b3e0` | `0x710024b3f0` | 37 | FUN_71001a70bc (derived) |
| `0x7100244788` | `0x7100244798` | 11 |  |
| `0x7100249ff8` | `0x710024a008` | 22 | FUN_71001751a8 (derived) |
| `0x710024a7c8` | `0x710024a7d8` | 10 |  |
| `0x7100244940` | `0x7100244950` | 10 |  |
| `0x7100247790` | `0x71002477a0` | 8 | fs_obj_destructor (derived) |
| `0x7100247a30` | `0x7100247a40` | 8 | fs_nca_buffer_node_destructor (derived) |
| `0x710024c698` | `0x710024c6a8` | 9 |  |
| `0x71002422b8` | `0x71002422c8` | 8 | fs_ifile_destructor (derived) |
| `0x7100245c78` | `0x7100245c88` | 8 |  |
| `0x7100245d18` | `0x7100245d28` | 8 |  |
| `0x71002457c8` | `0x71002457d8` | 8 |  |
| `0x710024c360` | `0x710024c370` | 12 | FUN_71001b00d4 (derived) |
| `0x7100243db0` | `0x7100243dc0` | 7 |  |
| `0x7100243e88` | `0x7100243e98` | 7 |  |
| `0x7100246308` | `0x7100246318` | 7 |  |
| `0x7100245b10` | `0x7100245b20` | 7 |  |
| `0x7100244830` | `0x7100244840` | 6 |  |
| `0x7100246400` | `0x7100246410` | 6 |  |
| `0x71002446c0` | `0x71002446d0` | 6 | FUN_7100088830 |
| `0x7100245a58` | `0x7100245a68` | 6 |  |
| `0x7100245b98` | `0x7100245ba8` | 6 |  |
| `0x71002477e0` | `0x71002477f0` | 4 | fs_obj_destructor_v2 (derived) |
| `0x7100241bf8` | `0x7100241c08` | 22 | FUN_71000601a0 (derived) |
| `0x71002417e0` | `0x71002417f0` | 22 | FUN_710005390c (derived) |
| `0x71002418b8` | `0x71002418c8` | 26 | FUN_7100054a00 (derived) |
| `0x71002423a0` | `0x71002423b0` | 5 | FUN_7100067248 (derived) |
| `0x7100242c20` | `0x7100242c30` | 23 | FUN_710006c020 (derived) |
| `0x7100246478` | `0x7100246488` | 5 |  |
| `0x7100244e00` | `0x7100244e10` | 5 | FUN_7100092c00 |
| `0x7100244d58` | `0x7100244d68` | 5 |  |
| `0x7100245708` | `0x7100245718` | 5 |  |
| `0x7100247810` | `0x7100247820` | 8 | fs_aligned_write_forward (derived) |
| `0x7100247dc0` | `0x7100247dd0` | 8 | FUN_710012d750 |
| `0x7100249c08` | `0x7100249c18` | 22 | FUN_710016a4cc (derived) |
| `0x710024b048` | `0x710024b058` | 4 |  |
| `0x710023f880` | `0x710023f890` | 8 | fs_nca_fs_obj_init_full |
| `0x7100241510` | `0x7100241520` | 23 | FUN_7100051190 (derived) |
| `0x7100241f68` | `0x7100241f78` | 5 | FUN_7100063d84 (derived) |
| `0x7100242308` | `0x7100242318` | 5 | FUN_7100065bcc (derived) |
| `0x7100242340` | `0x7100242350` | 3 | fs_ifile_reset (derived) |
| `0x7100242368` | `0x7100242378` | 5 | FUN_7100067140 (derived) |
| `0x7100242640` | `0x7100242650` | 22 | FUN_71000689c4 (derived) |
| `0x71002433b0` | `0x71002433c0` | 22 | FUN_7100077270 (derived) |
| `0x7100244700` | `0x7100244710` | 2 |  |
| `0x7100245bf8` | `0x7100245c08` | 4 | FUN_71000a9bd0 (derived) |
| `0x7100247348` | `0x7100247358` | 5 | fs_empty_function (derived) |
| `0x7100247860` | `0x7100247870` | 22 | fs_nca_fs_obj_destructor_full (derived) |
| `0x7100247a80` | `0x7100247a90` | 4 | fs_nca_obj_destroy (derived) |
| `0x7100247ab0` | `0x7100247ac0` | 27 | fs_nca_obj_init (derived) |
| `0x71002491f8` | `0x7100249208` | 22 | FUN_710015d940 (derived) |
| `0x7100249338` | `0x7100249348` | 22 | FUN_710015e3f0 (derived) |
| `0x7100249478` | `0x7100249488` | 22 | FUN_710015f140 (derived) |
| `0x71002495f8` | `0x7100249608` | 22 | FUN_7100164640 (derived) |
| `0x710024a240` | `0x710024a250` | 5 | FUN_71001845b0 (derived) |
| `0x710024a300` | `0x710024a310` | 12 | FUN_7100184b44 (derived) |
| `0x710024a5b8` | `0x710024a5c8` | 13 |  |
| `0x710024b9c0` | `0x710024b9d0` | 8 | FUN_71001aa114 (derived) |
| `0x710024bb48` | `0x710024bb58` | 13 |  |
| `0x710024bd18` | `0x710024bd28` | 13 |  |
| `0x710024bc20` | `0x710024bc30` | 2 |  |
| `0x710024bf10` | `0x710024bf20` | 8 | FUN_71001ac3f0 (derived) |
| `0x710024c098` | `0x710024c0a8` | 13 |  |
| `0x710024c6f0` | `0x710024c700` | 4 | FUN_71001b1c04 (derived) |
| `0x710024c310` | `0x710024c320` | 8 | FUN_71001b00d4 (derived) |
| `0x7100242558` | `0x7100242568` | 4 | FUN_7100063be8 (derived) |
| `0x710023f378` | `0x710023f388` | 5 | FUN_71000028b4 (derived) |
| `0x710023f740` | `0x710023f750` | 5 | FUN_7100024130 (derived) |
| `0x710023f7a8` | `0x710023f7b8` | 5 | FUN_7100024660 (derived) |
| `0x710023f810` | `0x710023f820` | 5 | FUN_7100024ad8 (derived) |
| `0x710023f848` | `0x710023f858` | 5 | FUN_7100024c58 (derived) |
| `0x710023f9d0` | `0x710023f9e0` | 5 | FUN_7100025a00 (derived) |
| `0x7100250058` | `0x7100250068` | 3 | FUN_710004a3a0 (derived) |
| `0x7100241eb0` | `0x7100241ec0` | 5 | FUN_7100061a5c (derived) |
| `0x7100241f30` | `0x7100241f40` | 5 | FUN_7100063d28 (derived) |
| `0x7100242150` | `0x7100242160` | 5 | FUN_71000644fc (derived) |
| `0x7100242188` | `0x7100242198` | 5 | FUN_7100064670 (derived) |
| `0x7100242460` | `0x7100242470` | 5 | FUN_7100067768 (derived) |
| `0x71002424e8` | `0x71002424f8` | 5 | FUN_7100067c50 (derived) |
| `0x7100242588` | `0x7100242598` | 3 | FUN_7100068350 (derived) |
| `0x71002425e0` | `0x71002425f0` | 3 | FUN_7100068760 (derived) |
| `0x7100242608` | `0x7100242618` | 5 | FUN_7100068968 (derived) |
| `0x7100242700` | `0x7100242710` | 3 | FUN_7100068f10 (derived) |
| `0x7100242728` | `0x7100242738` | 5 | FUN_7100068fb0 (derived) |
| `0x7100242760` | `0x7100242770` | 3 | FUN_71000692d4 (derived) |
| `0x7100242a80` | `0x7100242a90` | 5 | FUN_710006bfd8 (derived) |
| `0x7100242950` | `0x7100242960` | 5 | FUN_710006b8c4 (derived) |
| `0x71002429d8` | `0x71002429e8` | 5 | FUN_710006bcac (derived) |
| `0x7100242a10` | `0x7100242a20` | 5 | FUN_710006bda4 (derived) |
| `0x7100242a48` | `0x7100242a58` | 5 | FUN_710006be94 (derived) |
| `0x7100242db0` | `0x7100242dc0` | 9 | FUN_710006ce1c (derived) |
| `0x7100242e40` | `0x7100242e50` | 5 | FUN_710006d16c (derived) |
| `0x7100243078` | `0x7100243088` | 5 | FUN_710006de80 (derived) |
| `0x7100243138` | `0x7100243148` | 5 | FUN_710006f120 (derived) |
| `0x71002432d8` | `0x71002432e8` | 5 | FUN_7100070b3c (derived) |
| `0x7100243340` | `0x7100243350` | 5 | FUN_7100070e74 (derived) |
| `0x7100243378` | `0x7100243388` | 5 | FUN_7100077224 (derived) |
| `0x71002434c0` | `0x71002434d0` | 5 | FUN_71000777e8 (derived) |
| `0x71002451a0` | `0x71002451b0` | 5 | FUN_710009c284 (derived) |
| `0x71002440a0` | `0x71002440b0` | 5 | FUN_710007e994 (derived) |
| `0x71002440d8` | `0x71002440e8` | 22 | FUN_710007e9e0 (derived) |
| `0x7100244198` | `0x71002441a8` | 5 | FUN_710007ed6c (derived) |
| `0x71002466b8` | `0x71002466c8` | 5 | FUN_71000bf0e4 (derived) |
| `0x7100246768` | `0x7100246778` | 5 | FUN_71000bf534 (derived) |
| `0x71002467d8` | `0x71002467e8` | 5 | FUN_71000bf95c (derived) |
| `0x7100246848` | `0x7100246858` | 5 | FUN_71000bfdb0 (derived) |
| `0x71002468b0` | `0x71002468c0` | 5 | FUN_71000c0384 (derived) |
| `0x7100246918` | `0x7100246928` | 5 | FUN_71000c07e8 (derived) |
| `0x7100246350` | `0x7100246360` | 5 | FUN_71000b8ddc (derived) |
| `0x7100246388` | `0x7100246398` | 5 | FUN_71000b8fb0 (derived) |
| `0x7100245d68` | `0x7100245d78` | 5 | FUN_71000ad160 (derived) |
| `0x7100245df0` | `0x7100245e00` | 5 | FUN_71000ae1d8 (derived) |
| `0x7100246680` | `0x7100246690` | 5 | FUN_71000be288 (derived) |
| `0x71002464b0` | `0x71002464c0` | 5 | FUN_71000bc830 (derived) |
| `0x7100246538` | `0x7100246548` | 5 | FUN_71000bcc14 (derived) |
| `0x7100246570` | `0x7100246580` | 5 | FUN_71000bce08 (derived) |
| `0x71002465a8` | `0x71002465b8` | 5 | FUN_71000bd1e0 (derived) |
| `0x71002442b0` | `0x71002442c0` | 5 | FUN_7100082bc0 (derived) |
| `0x71002441f0` | `0x7100244200` | 5 | FUN_7100082798 (derived) |
| `0x7100244278` | `0x7100244288` | 5 | FUN_7100082aa0 (derived) |
| `0x71002443e8` | `0x71002443f8` | 5 | FUN_7100084828 (derived) |
| `0x7100244470` | `0x7100244480` | 5 | FUN_7100084b1c (derived) |
| `0x7100244870` | `0x7100244880` | 5 | FUN_710008bc78 (derived) |
| `0x71002448a8` | `0x71002448b8` | 5 | FUN_710008bd88 (derived) |
| `0x7100244d90` | `0x7100244da0` | 5 | FUN_7100092564 (derived) |
| `0x71002450f8` | `0x7100245108` | 5 | FUN_710009ae34 (derived) |
| `0x7100244ec8` | `0x7100244ed8` | 5 | FUN_71000990e4 (derived) |
| `0x7100245070` | `0x7100245080` | 5 | FUN_710009a1d4 (derived) |
| `0x7100245440` | `0x7100245450` | 5 | FUN_71000a7c1c (derived) |
| `0x71002454d8` | `0x71002454e8` | 5 | FUN_71000a7ea8 (derived) |
| `0x7100246d60` | `0x7100246d70` | 5 | FUN_71000c6da4 (derived) |
| `0x7100246f60` | `0x7100246f70` | 5 | FUN_71000c8048 (derived) |
| `0x7100247038` | `0x7100247048` | 5 | FUN_71000c93d4 (derived) |
| `0x71002470c0` | `0x71002470d0` | 5 | FUN_71000c95e8 (derived) |
| `0x7100247290` | `0x71002472a0` | 5 | FUN_71000cde70 (derived) |
| `0x7100247920` | `0x7100247930` | 8 | fs_resource_pool_destructor (derived) |
| `0x7100248348` | `0x7100248358` | 28 | FUN_7100136640 (derived) |
| `0x7100248908` | `0x7100248918` | 8 | fs_buffer_queue_reset (derived) |
| `0x7100248618` | `0x7100248628` | 8 | fs_object_list_cleanup (derived) |
| `0x7100248668` | `0x7100248678` | 28 | FUN_710013c458 (derived) |
| `0x7100248868` | `0x7100248878` | 8 | fs_object_destructor (derived) |
| `0x7100248958` | `0x7100248968` | 8 | fs_resource_pool_destroy (derived) |
| `0x7100248b80` | `0x7100248b90` | 5 | FUN_7100155d34 (derived) |
| `0x7100248bb8` | `0x7100248bc8` | 5 | FUN_7100155f64 (derived) |
| `0x7100248bf0` | `0x7100248c00` | 5 | FUN_7100156078 (derived) |
| `0x7100248c28` | `0x7100248c38` | 5 | FUN_71001563c4 (derived) |
| `0x7100248cb0` | `0x7100248cc0` | 5 | FUN_7100156734 (derived) |
| `0x7100248ce8` | `0x7100248cf8` | 5 | FUN_71001568e4 (derived) |
| `0x7100248d20` | `0x7100248d30` | 5 | FUN_7100156a88 (derived) |
| `0x7100248da8` | `0x7100248db8` | 5 | FUN_7100156d14 (derived) |
| `0x7100248de0` | `0x7100248df0` | 5 | FUN_7100156ed8 (derived) |
| `0x7100248e68` | `0x7100248e78` | 5 | FUN_710015751c (derived) |
| `0x7100248ef0` | `0x7100248f00` | 5 | FUN_7100157d74 (derived) |
| `0x7100248f28` | `0x7100248f38` | 5 | FUN_7100157e64 (derived) |
| `0x7100248f60` | `0x7100248f70` | 5 | FUN_7100157fa4 (derived) |
| `0x7100249738` | `0x7100249748` | 29 | FUN_7100166570 (derived) |
| `0x710024ad10` | `0x710024ad20` | 1 |  |

---

## `0x7100243950` → 槽0 = `0x7100243960`  (n=129)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100243960` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100243968` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100243970` | `0x7100026574` |  |
| 3 | `0x7100243978` | `0x710002657c` |  |
| 4 | `0x7100243980` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100243988` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100243990` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x7100243998` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x71002439a0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x71002439a8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x71002439b0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 11 | `0x71002439b8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 12 | `0x71002439c0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 13 | `0x71002439c8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 14 | `0x71002439d0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 15 | `0x71002439d8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 16 | `0x71002439e0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 17 | `0x71002439e8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 18 | `0x71002439f0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 19 | `0x71002439f8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 20 | `0x7100243a00` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 21 | `0x7100243a08` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 22 | `0x7100243a10` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 23 | `0x7100243a18` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 24 | `0x7100243a20` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 25 | `0x7100243a28` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 26 | `0x7100243a30` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 27 | `0x7100243a38` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 28 | `0x7100243a40` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 29 | `0x7100243a48` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 30 | `0x7100243a50` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 31 | `0x7100243a58` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 32 | `0x7100243a60` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 33 | `0x7100243a68` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 34 | `0x7100243a70` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 35 | `0x7100243a78` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 36 | `0x7100243a80` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 37 | `0x7100243a88` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 38 | `0x7100243a90` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 39 | `0x7100243a98` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 40 | `0x7100243aa0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 41 | `0x7100243aa8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 42 | `0x7100243ab0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 43 | `0x7100243ab8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 44 | `0x7100243ac0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 45 | `0x7100243ac8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 46 | `0x7100243ad0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 47 | `0x7100243ad8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 48 | `0x7100243ae0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 49 | `0x7100243ae8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 50 | `0x7100243af0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 51 | `0x7100243af8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 52 | `0x7100243b00` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 53 | `0x7100243b08` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 54 | `0x7100243b10` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 55 | `0x7100243b18` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 56 | `0x7100243b20` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 57 | `0x7100243b28` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 58 | `0x7100243b30` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 59 | `0x7100243b38` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 60 | `0x7100243b40` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 61 | `0x7100243b48` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 62 | `0x7100243b50` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 63 | `0x7100243b58` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 64 | `0x7100243b60` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 65 | `0x7100243b68` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 66 | `0x7100243b70` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 67 | `0x7100243b78` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 68 | `0x7100243b80` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 69 | `0x7100243b88` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 70 | `0x7100243b90` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 71 | `0x7100243b98` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 72 | `0x7100243ba0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 73 | `0x7100243ba8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 74 | `0x7100243bb0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 75 | `0x7100243bb8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 76 | `0x7100243bc0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 77 | `0x7100243bc8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 78 | `0x7100243bd0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 79 | `0x7100243bd8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 80 | `0x7100243be0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 81 | `0x7100243be8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 82 | `0x7100243bf0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 83 | `0x7100243bf8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 84 | `0x7100243c00` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 85 | `0x7100243c08` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 86 | `0x7100243c10` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 87 | `0x7100243c18` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 88 | `0x7100243c20` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 89 | `0x7100243c28` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 90 | `0x7100243c30` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 91 | `0x7100243c38` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 92 | `0x7100243c40` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 93 | `0x7100243c48` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 94 | `0x7100243c50` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 95 | `0x7100243c58` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 96 | `0x7100243c60` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 97 | `0x7100243c68` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 98 | `0x7100243c70` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 99 | `0x7100243c78` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 100 | `0x7100243c80` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 101 | `0x7100243c88` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 102 | `0x7100243c90` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 103 | `0x7100243c98` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 104 | `0x7100243ca0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 105 | `0x7100243ca8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 106 | `0x7100243cb0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 107 | `0x7100243cb8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 108 | `0x7100243cc0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 109 | `0x7100243cc8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 110 | `0x7100243cd0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 111 | `0x7100243cd8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 112 | `0x7100243ce0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 113 | `0x7100243ce8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 114 | `0x7100243cf0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 115 | `0x7100243cf8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 116 | `0x7100243d00` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 117 | `0x7100243d08` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 118 | `0x7100243d10` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 119 | `0x7100243d18` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 120 | `0x7100243d20` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 121 | `0x7100243d28` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 122 | `0x7100243d30` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 123 | `0x7100243d38` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 124 | `0x7100243d40` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 125 | `0x7100243d48` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 126 | `0x7100243d50` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 127 | `0x7100243d58` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 128 | `0x7100243d60` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100244b60` → 槽0 = `0x7100244b70`  (n=54)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244b70` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100244b78` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100244b80` | `0x7100026574` |  |
| 3 | `0x7100244b88` | `0x710002657c` |  |
| 4 | `0x7100244b90` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100244b98` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100244ba0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x7100244ba8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x7100244bb0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x7100244bb8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x7100244bc0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 11 | `0x7100244bc8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 12 | `0x7100244bd0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 13 | `0x7100244bd8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 14 | `0x7100244be0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 15 | `0x7100244be8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 16 | `0x7100244bf0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 17 | `0x7100244bf8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 18 | `0x7100244c00` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 19 | `0x7100244c08` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 20 | `0x7100244c10` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 21 | `0x7100244c18` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 22 | `0x7100244c20` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 23 | `0x7100244c28` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 24 | `0x7100244c30` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 25 | `0x7100244c38` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 26 | `0x7100244c40` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 27 | `0x7100244c48` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 28 | `0x7100244c50` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 29 | `0x7100244c58` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 30 | `0x7100244c60` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 31 | `0x7100244c68` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 32 | `0x7100244c70` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 33 | `0x7100244c78` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 34 | `0x7100244c80` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 35 | `0x7100244c88` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 36 | `0x7100244c90` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 37 | `0x7100244c98` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 38 | `0x7100244ca0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 39 | `0x7100244ca8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 40 | `0x7100244cb0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 41 | `0x7100244cb8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 42 | `0x7100244cc0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 43 | `0x7100244cc8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 44 | `0x7100244cd0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 45 | `0x7100244cd8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 46 | `0x7100244ce0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 47 | `0x7100244ce8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 48 | `0x7100244cf0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 49 | `0x7100244cf8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 50 | `0x7100244d00` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 51 | `0x7100244d08` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 52 | `0x7100244d10` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 53 | `0x7100244d18` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100247380` → 槽0 = `0x7100247390`  (n=22)
- 构造/装载者: `fs_idirectory_destructor (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247390` | `0x71000cef38` | fs_idirectory_destructor |
| 1 | `0x7100247398` | `0x71000cf0f8` | fs_idirectory_destructor_logged |
| 2 | `0x71002473a0` | `0x71000d1bc0` | fs_idirectory_create |
| 3 | `0x71002473a8` | `0x71000d1f30` | fs_idirectory_remove |
| 4 | `0x71002473b0` | `0x71000d2424` | fs_idirectory_mkdir |
| 5 | `0x71002473b8` | `0x71000d2430` | fs_idirectory_rmdir |
| 6 | `0x71002473c0` | `0x71000d2660` | fs_idirectory_get_entry_info |
| 7 | `0x71002473c8` | `0x71000d2890` | fs_idirectory_clean_dir |
| 8 | `0x71002473d0` | `0x71000d2ae0` | fs_idirectory_move |
| 9 | `0x71002473d8` | `0x71000d2df0` | fs_idirectory_rename |
| 10 | `0x71002473e0` | `0x71000d0760` | fs_idirectory_exists |
| 11 | `0x71002473e8` | `0x71000d08a8` | fs_idirectory_get_device_info |
| 12 | `0x71002473f0` | `0x71000d0a34` | fs_idirectory_get_device_info_light |
| 13 | `0x71002473f8` | `0x71000d1300` | fs_idirectory_fopen |
| 14 | `0x7100247400` | `0x71000d1890` | fs_idirectory_opendir |
| 15 | `0x7100247408` | `0x71000d30d0` | fs_idirectory_get_size |
| 16 | `0x7100247410` | `0x71000656f8` | fs_idirectory_get_version |
| 17 | `0x7100247418` | `0x7100065704` | fs_get_version |
| 18 | `0x7100247420` | `0x71000d1198` | fs_idirectory_sync |
| 19 | `0x7100247428` | `0x71000d0ec0` | fs_idirectory_stat |
| 20 | `0x7100247430` | `0x7100065710` | fs_get_version |
| 21 | `0x7100247438` | `0x71000d111c` | fs_idirectory_init_stat_buffer |

## `0x71002445c0` → 槽0 = `0x71002445d0`  (n=22)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002445d0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x71002445d8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x71002445e0` | `0x7100026574` |  |
| 3 | `0x71002445e8` | `0x710002657c` |  |
| 4 | `0x71002445f0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x71002445f8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100244600` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x7100244608` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x7100244610` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x7100244618` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x7100244620` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 11 | `0x7100244628` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 12 | `0x7100244630` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 13 | `0x7100244638` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 14 | `0x7100244640` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 15 | `0x7100244648` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 16 | `0x7100244650` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 17 | `0x7100244658` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 18 | `0x7100244660` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 19 | `0x7100244668` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 20 | `0x7100244670` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 21 | `0x7100244678` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x71002476d0` → 槽0 = `0x71002476e0`  (n=22)
- 构造/装载者: `fs_nca_fs_obj_destructor (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002476e0` | `0x710011ae30` | fs_nca_fs_obj_destructor |
| 1 | `0x71002476e8` | `0x710011b16c` | fs_nca_fs_obj_release |
| 2 | `0x71002476f0` | `0x710011c5bc` | fs_locked_vtable_call_0x10 |
| 3 | `0x71002476f8` | `0x710011c8d4` | fs_locked_vtable_call_0x18 |
| 4 | `0x7100247700` | `0x710011c640` | fs_locked_vtable_call_0x20 |
| 5 | `0x7100247708` | `0x710011c930` | fs_locked_vtable_call_0x28 |
| 6 | `0x7100247710` | `0x710011c98c` | fs_locked_vtable_call_0x30 |
| 7 | `0x7100247718` | `0x710011c9e8` | fs_locked_vtable_call_0x38 |
| 8 | `0x7100247720` | `0x710011ca44` | fs_locked_vtable_call_0x40 |
| 9 | `0x7100247728` | `0x710011caa8` | fs_locked_vtable_call_0x48 |
| 10 | `0x7100247730` | `0x710011cb0c` | fs_locked_vtable_call_0x50 |
| 11 | `0x7100247738` | `0x710011cb84` | fs_locked_vtable_call_0x58 |
| 12 | `0x7100247740` | `0x710011cbf8` | fs_locked_vtable_call_0x60 |
| 13 | `0x7100247748` | `0x710011c69c` | fs_locked_vtable_call_0x68 |
| 14 | `0x7100247750` | `0x710011c7b8` |  |
| 15 | `0x7100247758` | `0x710011cb80` |  |
| 16 | `0x7100247760` | `0x71000656f8` | fs_idirectory_get_version |
| 17 | `0x7100247768` | `0x7100065704` | fs_get_version |
| 18 | `0x7100247770` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x7100247778` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x7100247780` | `0x7100065710` | fs_get_version |
| 21 | `0x7100247788` | `0x710011cc6c` | fs_locked_vtable_call_0xa8 |

## `0x710024b518` → 槽0 = `0x710024b528`  (n=53)
- 构造/装载者: `FUN_71001a17cc (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024b528` | `0x71001a17c4` |  |
| 1 | `0x710024b530` | `0x71001a17cc` | FUN_71001a17cc |
| 2 | `0x710024b538` | `0x71001a1844` | FUN_71001a1844 |
| 3 | `0x710024b540` | `0x71001a7194` |  |
| 4 | `0x710024b548` | `0x71001a71f4` | FUN_71001a71f4 |
| 5 | `0x710024b550` | `0x71001a727c` | FUN_71001a727c |
| 6 | `0x710024b558` | `0x71001a7e04` |  |
| 7 | `0x710024b560` | `0x71001a7ff0` |  |
| 8 | `0x710024b568` | `0x71001a8070` |  |
| 9 | `0x710024b570` | `0x71001a810c` |  |
| 10 | `0x710024b578` | `0x71001a82e0` | FUN_71001a82e0 |
| 11 | `0x710024b580` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 12 | `0x710024b588` | `0x71001a7288` | FUN_71001a7288 |
| 13 | `0x710024b590` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 14 | `0x710024b598` | `0x71001a72d0` | FUN_71001a72d0 |
| 15 | `0x710024b5a0` | `0x71001a7368` | FUN_71001a7368 |
| 16 | `0x710024b5a8` | `0x71001a8434` | FUN_71001a8434 |
| 17 | `0x710024b5b0` | `0x71001a18cc` |  |
| 18 | `0x710024b5b8` | `0x71001a18d4` |  |
| 19 | `0x710024b5c0` | `0x71001a849c` | FUN_71001a849c |
| 20 | `0x710024b5c8` | `0x71001a18dc` |  |
| 21 | `0x710024b5d0` | `0x71001a84f4` | FUN_71001a84f4 |
| 22 | `0x710024b5d8` | `0x71001a7404` | FUN_71001a7404 |
| 23 | `0x710024b5e0` | `0x71001a18e4` |  |
| 24 | `0x710024b5e8` | `0x71001a18ec` |  |
| 25 | `0x710024b5f0` | `0x71001a741c` |  |
| 26 | `0x710024b5f8` | `0x71001a7424` |  |
| 27 | `0x710024b600` | `0x71001a8540` | FUN_71001a8540 |
| 28 | `0x710024b608` | `0x71001a85ac` | FUN_71001a85ac |
| 29 | `0x710024b610` | `0x71001a18f4` |  |
| 30 | `0x710024b618` | `0x71001a7570` | FUN_71001a7570 |
| 31 | `0x710024b620` | `0x71001a7624` | FUN_71001a7624 |
| 32 | `0x710024b628` | `0x71001a18fc` |  |
| 33 | `0x710024b630` | `0x71001a8600` | FUN_71001a8600 |
| 34 | `0x710024b638` | `0x71001a8710` |  |
| 35 | `0x710024b640` | `0x71001a1904` |  |
| 36 | `0x710024b648` | `0x71001a190c` |  |
| 37 | `0x710024b650` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 38 | `0x710024b658` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 39 | `0x710024b660` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 40 | `0x710024b668` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 41 | `0x710024b670` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 42 | `0x710024b678` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 43 | `0x710024b680` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 44 | `0x710024b688` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 45 | `0x710024b690` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 46 | `0x710024b698` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 47 | `0x710024b6a0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 48 | `0x710024b6a8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 49 | `0x710024b6b0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 50 | `0x710024b6b8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 51 | `0x710024b6c0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 52 | `0x710024b6c8` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100247970` → 槽0 = `0x7100247980`  (n=22)
- 构造/装载者: `fs_nca_fs_obj_destroy (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247980` | `0x7100127200` | fs_nca_fs_obj_destroy |
| 1 | `0x7100247988` | `0x7100127600` | fs_nca_fs_obj_destroy_and_release |
| 2 | `0x7100247990` | `0x710012a3bc` | fs_nca_buffer_pool_read |
| 3 | `0x7100247998` | `0x710012a6d4` | fs_nca_buffer_pool_op8_wrapper |
| 4 | `0x71002479a0` | `0x710012a440` | fs_nca_buffer_pool_operation |
| 5 | `0x71002479a8` | `0x710012a730` | fs_nca_buffer_pool_op18_wrapper |
| 6 | `0x71002479b0` | `0x710012a78c` | fs_nca_buffer_pool_op28_wrapper |
| 7 | `0x71002479b8` | `0x710012a7e8` | fs_nca_buffer_pool_op38_wrapper |
| 8 | `0x71002479c0` | `0x710012a844` | fs_nca_buffer_pool_op40_wrapper |
| 9 | `0x71002479c8` | `0x710012a8a8` | fs_nca_buffer_pool_op48_wrapper |
| 10 | `0x71002479d0` | `0x710012a90c` | fs_nca_buffer_pool_op50_wrapper |
| 11 | `0x71002479d8` | `0x710012a980` | fs_nca_buffer_pool_op58_wrapper |
| 12 | `0x71002479e0` | `0x710012a9f4` | fs_nca_buffer_pool_op60_wrapper |
| 13 | `0x71002479e8` | `0x710012a49c` | fs_nca_buffer_alloc |
| 14 | `0x71002479f0` | `0x710012a5b8` |  |
| 15 | `0x71002479f8` | `0x710012b214` |  |
| 16 | `0x7100247a00` | `0x710012b220` |  |
| 17 | `0x7100247a08` | `0x710012b24c` |  |
| 18 | `0x7100247a10` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x7100247a18` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x7100247a20` | `0x7100065710` | fs_get_version |
| 21 | `0x7100247a28` | `0x710012aa68` | fs_nca_buffer_pool_opA8_wrapper |

## `0x71002460f0` → 槽0 = `0x7100246100`  (n=17)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246100` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100246108` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100246110` | `0x7100026574` |  |
| 3 | `0x7100246118` | `0x710002657c` |  |
| 4 | `0x7100246120` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100246128` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100246130` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x7100246138` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x7100246140` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x7100246148` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x7100246150` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 11 | `0x7100246158` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 12 | `0x7100246160` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 13 | `0x7100246168` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 14 | `0x7100246170` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 15 | `0x7100246178` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 16 | `0x7100246180` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x71002458a8` → 槽0 = `0x71002458b8`  (n=16)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002458b8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x71002458c0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x71002458c8` | `0x7100026574` |  |
| 3 | `0x71002458d0` | `0x710002657c` |  |
| 4 | `0x71002458d8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x71002458e0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x71002458e8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x71002458f0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x71002458f8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x7100245900` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x7100245908` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 11 | `0x7100245910` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 12 | `0x7100245918` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 13 | `0x7100245920` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 14 | `0x7100245928` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 15 | `0x7100245930` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100245f00` → 槽0 = `0x7100245f10`  (n=15)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245f10` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100245f18` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100245f20` | `0x7100026574` |  |
| 3 | `0x7100245f28` | `0x710002657c` |  |
| 4 | `0x7100245f30` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100245f38` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100245f40` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x7100245f48` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x7100245f50` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x7100245f58` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x7100245f60` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 11 | `0x7100245f68` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 12 | `0x7100245f70` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 13 | `0x7100245f78` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 14 | `0x7100245f80` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100247658` → 槽0 = `0x7100247668`  (n=13)
- 构造/装载者: `fs_locked_buffer_pool_cleanup_entries (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247668` | `0x71001180ac` | fs_locked_buffer_pool_cleanup_entries |
| 1 | `0x7100247670` | `0x7100118104` | fs_locked_buffer_pool_destroy_and_release |
| 2 | `0x7100247678` | `0x7100117a08` | fs_locked_string_op |
| 3 | `0x7100247680` | `0x7100117b84` | fs_locked_buffer_pool_free |
| 4 | `0x7100247688` | `0x7100117be8` | fs_locked_buffer_pool_alloc |
| 5 | `0x7100247690` | `0x7100117d6c` | fs_locked_buffer_pool_free_by_addr |
| 6 | `0x7100247698` | `0x7100117f20` |  |
| 7 | `0x71002476a0` | `0x7100117f28` | fs_locked_buffer_pool_get_free_size |
| 8 | `0x71002476a8` | `0x7100117f68` | fs_locked_buffer_pool_cleanup_entry |
| 9 | `0x71002476b0` | `0x7100117fac` | fs_locked_buffer_pool_get_entry_data |
| 10 | `0x71002476b8` | `0x7100117fe4` | fs_locked_buffer_pool_get_entry_data_and_cleanup |
| 11 | `0x71002476c0` | `0x710011801c` | fs_locked_buffer_pool_get_entry_data2_and_cleanup |
| 12 | `0x71002476c8` | `0x7100118054` | fs_locked_buffer_pool_reset_entry_data |

## `0x710024a690` → 槽0 = `0x710024a6a0`  (n=13)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024a6a0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024a6a8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024a6b0` | `0x7100026574` |  |
| 3 | `0x710024a6b8` | `0x710002657c` |  |
| 4 | `0x710024a6c0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x710024a6c8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x710024a6d0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x710024a6d8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x710024a6e0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x710024a6e8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x710024a6f0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 11 | `0x710024a6f8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 12 | `0x710024a700` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x710023fb98` → 槽0 = `0x710023fba8`  (n=12)
- 构造/装载者: `FUN_7100025e10`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710023fba8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710023fbb0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710023fbb8` | `0x7100026574` |  |
| 3 | `0x710023fbc0` | `0x710002657c` |  |
| 4 | `0x710023fbc8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x710023fbd0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x710023fbd8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x710023fbe0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x710023fbe8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x710023fbf0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x710023fbf8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 11 | `0x710023fc00` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x71002459a8` → 槽0 = `0x71002459b8`  (n=12)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002459b8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x71002459c0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x71002459c8` | `0x7100026574` |  |
| 3 | `0x71002459d0` | `0x710002657c` |  |
| 4 | `0x71002459d8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x71002459e0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x71002459e8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x71002459f0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x71002459f8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x7100245a00` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x7100245a08` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 11 | `0x7100245a10` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x710024b3e0` → 槽0 = `0x710024b3f0`  (n=37)
- 构造/装载者: `FUN_71001a70bc (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024b3f0` | `0x71001a17c4` |  |
| 1 | `0x710024b3f8` | `0x71001a70bc` | FUN_71001a70bc |
| 2 | `0x710024b400` | `0x71001a7144` | FUN_71001a7144 |
| 3 | `0x710024b408` | `0x71001a7194` |  |
| 4 | `0x710024b410` | `0x71001a71f4` | FUN_71001a71f4 |
| 5 | `0x710024b418` | `0x71001a727c` | FUN_71001a727c |
| 6 | `0x710024b420` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x710024b428` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x710024b430` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x710024b438` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x710024b440` | `0x71001a7670` | FUN_71001a7670 |
| 11 | `0x710024b448` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 12 | `0x710024b450` | `0x71001a7288` | FUN_71001a7288 |
| 13 | `0x710024b458` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 14 | `0x710024b460` | `0x71001a72d0` | FUN_71001a72d0 |
| 15 | `0x710024b468` | `0x71001a7368` | FUN_71001a7368 |
| 16 | `0x710024b470` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 17 | `0x710024b478` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 18 | `0x710024b480` | `0x71001a18d4` |  |
| 19 | `0x710024b488` | `0x71001a7388` | FUN_71001a7388 |
| 20 | `0x710024b490` | `0x71001a18dc` |  |
| 21 | `0x710024b498` | `0x71001a73cc` | FUN_71001a73cc |
| 22 | `0x710024b4a0` | `0x71001a7404` | FUN_71001a7404 |
| 23 | `0x710024b4a8` | `0x71001a18e4` |  |
| 24 | `0x710024b4b0` | `0x71001a18ec` |  |
| 25 | `0x710024b4b8` | `0x71001a741c` |  |
| 26 | `0x710024b4c0` | `0x71001a7424` |  |
| 27 | `0x710024b4c8` | `0x71001a7430` | FUN_71001a7430 |
| 28 | `0x710024b4d0` | `0x71001a74dc` | FUN_71001a74dc |
| 29 | `0x710024b4d8` | `0x71001a18f4` |  |
| 30 | `0x710024b4e0` | `0x71001a7570` | FUN_71001a7570 |
| 31 | `0x710024b4e8` | `0x71001a7624` | FUN_71001a7624 |
| 32 | `0x710024b4f0` | `0x71001a767c` |  |
| 33 | `0x710024b4f8` | `0x71001a7684` | FUN_71001a7684 |
| 34 | `0x710024b500` | `0x71001a7690` | FUN_71001a7690 |
| 35 | `0x710024b508` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 36 | `0x710024b510` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100244788` → 槽0 = `0x7100244798`  (n=11)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244798` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x71002447a0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x71002447a8` | `0x7100026574` |  |
| 3 | `0x71002447b0` | `0x710002657c` |  |
| 4 | `0x71002447b8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x71002447c0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x71002447c8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x71002447d0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x71002447d8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x71002447e0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x71002447e8` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100249ff8` → 槽0 = `0x710024a008`  (n=22)
- 构造/装载者: `FUN_71001751a8 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024a008` | `0x71001751a8` | FUN_71001751a8 |
| 1 | `0x710024a010` | `0x71001751d4` | FUN_71001751d4 |
| 2 | `0x710024a018` | `0x7100176090` |  |
| 3 | `0x710024a020` | `0x71001763e4` | fs_file_delete |
| 4 | `0x710024a028` | `0x7100176570` | fs_file_create |
| 5 | `0x710024a030` | `0x7100176664` | fs_directory_open |
| 6 | `0x710024a038` | `0x71001766e8` | fs_directory_open_recursive |
| 7 | `0x710024a040` | `0x710017680c` | fs_directory_open_recursive_alt |
| 8 | `0x710024a048` | `0x7100176914` |  |
| 9 | `0x710024a050` | `0x7100176bbc` | fs_file_create_or_open_check |
| 10 | `0x710024a058` | `0x71001751fc` | fs_check_file_exists |
| 11 | `0x710024a060` | `0x7100175348` | FUN_7100175348 |
| 12 | `0x710024a068` | `0x71001753b8` | FUN_71001753b8 |
| 13 | `0x710024a070` | `0x7100175a84` |  |
| 14 | `0x710024a078` | `0x7100175c84` |  |
| 15 | `0x710024a080` | `0x7100176fd8` | FUN_7100176fd8 |
| 16 | `0x710024a088` | `0x7100177020` | FUN_7100177020 |
| 17 | `0x710024a090` | `0x7100065704` | fs_get_version |
| 18 | `0x710024a098` | `0x7100175498` | FUN_7100175498 |
| 19 | `0x710024a0a0` | `0x7100175428` | FUN_7100175428 |
| 20 | `0x710024a0a8` | `0x7100176e38` | fs_file_create_or_open_by_path |
| 21 | `0x710024a0b0` | `0x7100177078` | FUN_7100177078 |

## `0x710024a7c8` → 槽0 = `0x710024a7d8`  (n=10)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024a7d8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024a7e0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024a7e8` | `0x7100026574` |  |
| 3 | `0x710024a7f0` | `0x710002657c` |  |
| 4 | `0x710024a7f8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x710024a800` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x710024a808` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x710024a810` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x710024a818` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x710024a820` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100244940` → 槽0 = `0x7100244950`  (n=10)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244950` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100244958` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100244960` | `0x7100026574` |  |
| 3 | `0x7100244968` | `0x710002657c` |  |
| 4 | `0x7100244970` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100244978` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100244980` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x7100244988` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x7100244990` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x7100244998` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100247790` → 槽0 = `0x71002477a0`  (n=8)
- 构造/装载者: `fs_obj_destructor (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002477a0` | `0x710011ccf8` | fs_obj_destructor |
| 1 | `0x71002477a8` | `0x710011cd24` | fs_obj_destructor_logged |
| 2 | `0x71002477b0` | `0x710011cd4c` | fs_locked_file_read |
| 3 | `0x71002477b8` | `0x710011ce30` | fs_locked_file_write |
| 4 | `0x71002477c0` | `0x710011cff0` | fs_locked_file_flush |
| 5 | `0x71002477c8` | `0x710011cf84` | fs_locked_file_vtable_call_0x28 |
| 6 | `0x71002477d0` | `0x710011cf18` | fs_locked_file_vtable_call_0x30 |
| 7 | `0x71002477d8` | `0x710011d03c` | fs_locked_file_vtable_call_0x38 |

## `0x7100247a30` → 槽0 = `0x7100247a40`  (n=8)
- 构造/装载者: `fs_nca_buffer_node_destructor (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247a40` | `0x710012ac68` | fs_nca_buffer_node_destructor |
| 1 | `0x7100247a48` | `0x710012ac94` | fs_nca_buffer_node_destructor_trace |
| 2 | `0x7100247a50` | `0x710012acbc` | fs_nca_buffer_node_read |
| 3 | `0x7100247a58` | `0x710012ada0` | fs_nca_buffer_node_read2 |
| 4 | `0x7100247a60` | `0x710012af94` | fs_nca_buffer_node_op20_wrapper |
| 5 | `0x7100247a68` | `0x710012af28` | fs_nca_buffer_node_op28_wrapper |
| 6 | `0x7100247a70` | `0x710012aebc` | fs_nca_buffer_node_op30_wrapper |
| 7 | `0x7100247a78` | `0x710012afe0` | fs_nca_buffer_node_op38_wrapper |

## `0x710024c698` → 槽0 = `0x710024c6a8`  (n=9)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024c6a8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024c6b0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024c6b8` | `0x7100026574` |  |
| 3 | `0x710024c6c0` | `0x710002657c` |  |
| 4 | `0x710024c6c8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x710024c6d0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x710024c6d8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x710024c6e0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 8 | `0x710024c6e8` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x71002422b8` → 槽0 = `0x71002422c8`  (n=8)
- 构造/装载者: `fs_ifile_destructor (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002422c8` | `0x7100065720` | fs_ifile_destructor |
| 1 | `0x71002422d0` | `0x71000657a0` | fs_ifile_destructor_logged |
| 2 | `0x71002422d8` | `0x710006582c` | fs_ifile_read |
| 3 | `0x71002422e0` | `0x71000658f0` | fs_ifile_write |
| 4 | `0x71002422e8` | `0x71000659b4` | FUN_71000659b4 |
| 5 | `0x71002422f0` | `0x71000659ec` | fs_ifile_set_size |
| 6 | `0x71002422f8` | `0x7100065ad0` | FUN_7100065ad0 |
| 7 | `0x7100242300` | `0x7100065af8` | fs_ifile_operation_router |

## `0x7100245c78` → 槽0 = `0x7100245c88`  (n=8)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245c88` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100245c90` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100245c98` | `0x7100026574` |  |
| 3 | `0x7100245ca0` | `0x710002657c` |  |
| 4 | `0x7100245ca8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100245cb0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100245cb8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x7100245cc0` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100245d18` → 槽0 = `0x7100245d28`  (n=8)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245d28` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100245d30` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100245d38` | `0x7100026574` |  |
| 3 | `0x7100245d40` | `0x710002657c` |  |
| 4 | `0x7100245d48` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100245d50` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100245d58` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x7100245d60` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x71002457c8` → 槽0 = `0x71002457d8`  (n=8)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002457d8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x71002457e0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x71002457e8` | `0x7100026574` |  |
| 3 | `0x71002457f0` | `0x710002657c` |  |
| 4 | `0x71002457f8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100245800` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100245808` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 7 | `0x7100245810` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x710024c360` → 槽0 = `0x710024c370`  (n=12)
- 构造/装载者: `FUN_71001b00d4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024c370` | `0x71001b00d4` | FUN_71001b00d4 |
| 1 | `0x710024c378` | `0x71001b0034` | FUN_71001b0034 |
| 2 | `0x710024c380` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 3 | `0x710024c388` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 4 | `0x710024c390` | `0x71001afe54` |  |
| 5 | `0x710024c398` | `0x71001afe60` |  |
| 6 | `0x710024c3a0` | `0x71001b0154` |  |
| 7 | `0x710024c3a8` | `0x71000040ac` |  |
| 8 | `0x710024c3b0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 9 | `0x710024c3b8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 10 | `0x710024c3c0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 11 | `0x710024c3c8` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100243db0` → 槽0 = `0x7100243dc0`  (n=7)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100243dc0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100243dc8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100243dd0` | `0x7100026574` |  |
| 3 | `0x7100243dd8` | `0x710002657c` |  |
| 4 | `0x7100243de0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100243de8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100243df0` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100243e88` → 槽0 = `0x7100243e98`  (n=7)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100243e98` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100243ea0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100243ea8` | `0x7100026574` |  |
| 3 | `0x7100243eb0` | `0x710002657c` |  |
| 4 | `0x7100243eb8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100243ec0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100243ec8` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100246308` → 槽0 = `0x7100246318`  (n=7)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246318` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100246320` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100246328` | `0x7100026574` |  |
| 3 | `0x7100246330` | `0x710002657c` |  |
| 4 | `0x7100246338` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100246340` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100246348` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100245b10` → 槽0 = `0x7100245b20`  (n=7)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245b20` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100245b28` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100245b30` | `0x7100026574` |  |
| 3 | `0x7100245b38` | `0x710002657c` |  |
| 4 | `0x7100245b40` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100245b48` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 6 | `0x7100245b50` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100244830` → 槽0 = `0x7100244840`  (n=6)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244840` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100244848` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100244850` | `0x7100026574` |  |
| 3 | `0x7100244858` | `0x710002657c` |  |
| 4 | `0x7100244860` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100244868` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100246400` → 槽0 = `0x7100246410`  (n=6)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246410` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100246418` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100246420` | `0x7100026574` |  |
| 3 | `0x7100246428` | `0x710002657c` |  |
| 4 | `0x7100246430` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100246438` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x71002446c0` → 槽0 = `0x71002446d0`  (n=6)
- 构造/装载者: `FUN_7100088830`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002446d0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x71002446d8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x71002446e0` | `0x7100026574` |  |
| 3 | `0x71002446e8` | `0x710002657c` |  |
| 4 | `0x71002446f0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x71002446f8` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100245a58` → 槽0 = `0x7100245a68`  (n=6)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245a68` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100245a70` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100245a78` | `0x7100026574` |  |
| 3 | `0x7100245a80` | `0x710002657c` |  |
| 4 | `0x7100245a88` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100245a90` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100245b98` → 槽0 = `0x7100245ba8`  (n=6)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245ba8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100245bb0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100245bb8` | `0x7100026574` |  |
| 3 | `0x7100245bc0` | `0x710002657c` |  |
| 4 | `0x7100245bc8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 5 | `0x7100245bd0` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x71002477e0` → 槽0 = `0x71002477f0`  (n=4)
- 构造/装载者: `fs_obj_destructor_v2 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002477f0` | `0x710011d100` | fs_obj_destructor_v2 |
| 1 | `0x71002477f8` | `0x710011d130` | fs_obj_destructor_v2_logged |
| 2 | `0x7100247800` | `0x710011d158` | fs_locked_file_read_v2 |
| 3 | `0x7100247808` | `0x710011d204` | fs_locked_file_vtable_call_0x18_v2 |

## `0x7100241bf8` → 槽0 = `0x7100241c08`  (n=22)
- 构造/装载者: `FUN_71000601a0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100241c08` | `0x71000601a0` | FUN_71000601a0 |
| 1 | `0x7100241c10` | `0x7100060250` | FUN_7100060250 |
| 2 | `0x7100241c18` | `0x7100060378` | FUN_7100060378 |
| 3 | `0x7100241c20` | `0x71000608a0` | FUN_71000608a0 |
| 4 | `0x7100241c28` | `0x71000603f8` | FUN_71000603f8 |
| 5 | `0x7100241c30` | `0x71000609a4` |  |
| 6 | `0x7100241c38` | `0x7100061a38` |  |
| 7 | `0x7100241c40` | `0x7100061a40` |  |
| 8 | `0x7100241c48` | `0x7100060d10` |  |
| 9 | `0x7100241c50` | `0x7100060fa0` |  |
| 10 | `0x7100241c58` | `0x7100061158` | FUN_7100061158 |
| 11 | `0x7100241c60` | `0x7100061210` | FUN_7100061210 |
| 12 | `0x7100241c68` | `0x7100061280` | FUN_7100061280 |
| 13 | `0x7100241c70` | `0x7100060450` | FUN_7100060450 |
| 14 | `0x7100241c78` | `0x71000606b0` |  |
| 15 | `0x7100241c80` | `0x71000611c8` | FUN_71000611c8 |
| 16 | `0x7100241c88` | `0x71000656f8` | fs_idirectory_get_version |
| 17 | `0x7100241c90` | `0x7100065704` | fs_get_version |
| 18 | `0x7100241c98` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x7100241ca0` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x7100241ca8` | `0x7100065710` | fs_get_version |
| 21 | `0x7100241cb0` | `0x71000612f0` | FUN_71000612f0 |

## `0x71002417e0` → 槽0 = `0x71002417f0`  (n=22)
- 构造/装载者: `FUN_710005390c (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002417f0` | `0x710005390c` | FUN_710005390c |
| 1 | `0x71002417f8` | `0x7100053944` | FUN_7100053944 |
| 2 | `0x7100241800` | `0x7100053b8c` |  |
| 3 | `0x7100241808` | `0x7100053c34` |  |
| 4 | `0x7100241810` | `0x7100053ba8` |  |
| 5 | `0x7100241818` | `0x7100053c40` |  |
| 6 | `0x7100241820` | `0x7100053c4c` |  |
| 7 | `0x7100241828` | `0x7100053c58` |  |
| 8 | `0x7100241830` | `0x7100053c64` |  |
| 9 | `0x7100241838` | `0x7100053c70` |  |
| 10 | `0x7100241840` | `0x7100053c7c` |  |
| 11 | `0x7100241848` | `0x7100053ca4` |  |
| 12 | `0x7100241850` | `0x7100053cc0` |  |
| 13 | `0x7100241858` | `0x7100053bb4` |  |
| 14 | `0x7100241860` | `0x7100053bf4` |  |
| 15 | `0x7100241868` | `0x7100053c98` |  |
| 16 | `0x7100241870` | `0x71000656f8` | fs_idirectory_get_version |
| 17 | `0x7100241878` | `0x7100065704` | fs_get_version |
| 18 | `0x7100241880` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x7100241888` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x7100241890` | `0x7100065710` | fs_get_version |
| 21 | `0x7100241898` | `0x7100053cdc` |  |

## `0x71002418b8` → 槽0 = `0x71002418c8`  (n=26)
- 构造/装载者: `FUN_7100054a00 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002418c8` | `0x7100054a00` | FUN_7100054a00 |
| 1 | `0x71002418d0` | `0x7100054bd0` | FUN_7100054bd0 |
| 2 | `0x71002418d8` | `0x7100055c70` |  |
| 3 | `0x71002418e0` | `0x71000559c0` | FUN_71000559c0 |
| 4 | `0x71002418e8` | `0x7100055fac` |  |
| 5 | `0x71002418f0` | `0x7100055ae0` | FUN_7100055ae0 |
| 6 | `0x71002418f8` | `0x7100058284` |  |
| 7 | `0x7100241900` | `0x7100058290` |  |
| 8 | `0x7100241908` | `0x7100056028` | FUN_7100056028 |
| 9 | `0x7100241910` | `0x7100056368` | FUN_7100056368 |
| 10 | `0x7100241918` | `0x71000557e0` | FUN_71000557e0 |
| 11 | `0x7100241920` | `0x710005829c` | FUN_710005829c |
| 12 | `0x7100241928` | `0x71000582f8` |  |
| 13 | `0x7100241930` | `0x7100055550` |  |
| 14 | `0x7100241938` | `0x7100055744` |  |
| 15 | `0x7100241940` | `0x7100058310` |  |
| 16 | `0x7100241948` | `0x71000656f8` | fs_idirectory_get_version |
| 17 | `0x7100241950` | `0x7100065704` | fs_get_version |
| 18 | `0x7100241958` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x7100241960` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x7100241968` | `0x7100065710` | fs_get_version |
| 21 | `0x7100241970` | `0x7100056954` |  |
| 22 | `0x7100241978` | `0x7100055340` | FUN_7100055340 |
| 23 | `0x7100241980` | `0x71000555ec` | FUN_71000555ec |
| 24 | `0x7100241988` | `0x7100057b48` | FUN_7100057b48 |
| 25 | `0x7100241990` | `0x7100057eb0` |  |

## `0x71002423a0` → 槽0 = `0x71002423b0`  (n=5)
- 构造/装载者: `FUN_7100067248 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002423b0` | `0x7100067248` | FUN_7100067248 |
| 1 | `0x71002423b8` | `0x710006725c` | fs_ifile_nop_destructor_3 |
| 2 | `0x71002423c0` | `0x7100067290` | fs_ifile_indirect_call |
| 3 | `0x71002423c8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002423d0` | `0x710006729c` | FUN_710006729c |

## `0x7100242c20` → 槽0 = `0x7100242c30`  (n=23)
- 构造/装载者: `FUN_710006c020 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242c30` | `0x710006c020` | FUN_710006c020 |
| 1 | `0x7100242c38` | `0x710006cca0` |  |
| 2 | `0x7100242c40` | `0x710006c134` | FUN_710006c134 |
| 3 | `0x7100242c48` | `0x710006c194` | FUN_710006c194 |
| 4 | `0x7100242c50` | `0x710006c1d0` | FUN_710006c1d0 |
| 5 | `0x7100242c58` | `0x710006c20c` | FUN_710006c20c |
| 6 | `0x7100242c60` | `0x710006c248` | FUN_710006c248 |
| 7 | `0x7100242c68` | `0x710006c284` | FUN_710006c284 |
| 8 | `0x7100242c70` | `0x710006c2c0` | FUN_710006c2c0 |
| 9 | `0x7100242c78` | `0x710006c2fc` | FUN_710006c2fc |
| 10 | `0x7100242c80` | `0x710006c338` | FUN_710006c338 |
| 11 | `0x7100242c88` | `0x710006c398` | FUN_710006c398 |
| 12 | `0x7100242c90` | `0x710006c3f8` | FUN_710006c3f8 |
| 13 | `0x7100242c98` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 14 | `0x7100242ca0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 15 | `0x7100242ca8` | `0x710006c690` | FUN_710006c690 |
| 16 | `0x7100242cb0` | `0x710006c6cc` | FUN_710006c6cc |
| 17 | `0x7100242cb8` | `0x710006c708` | FUN_710006c708 |
| 18 | `0x7100242cc0` | `0x710006c744` | FUN_710006c744 |
| 19 | `0x7100242cc8` | `0x710006c780` | FUN_710006c780 |
| 20 | `0x7100242cd0` | `0x710006c7e0` | FUN_710006c7e0 |
| 21 | `0x7100242cd8` | `0x710006c81c` | FUN_710006c81c |
| 22 | `0x7100242ce0` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100246478` → 槽0 = `0x7100246488`  (n=5)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246488` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100246490` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100246498` | `0x7100026574` |  |
| 3 | `0x71002464a0` | `0x710002657c` |  |
| 4 | `0x71002464a8` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100244e00` → 槽0 = `0x7100244e10`  (n=5)
- 构造/装载者: `FUN_7100092c00`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244e10` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100244e18` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100244e20` | `0x7100026574` |  |
| 3 | `0x7100244e28` | `0x710002657c` |  |
| 4 | `0x7100244e30` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100244d58` → 槽0 = `0x7100244d68`  (n=5)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244d68` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100244d70` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100244d78` | `0x7100026574` |  |
| 3 | `0x7100244d80` | `0x710002657c` |  |
| 4 | `0x7100244d88` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100245708` → 槽0 = `0x7100245718`  (n=5)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245718` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100245720` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x7100245728` | `0x7100026574` |  |
| 3 | `0x7100245730` | `0x710002657c` |  |
| 4 | `0x7100245738` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100247810` → 槽0 = `0x7100247820`  (n=8)
- 构造/装载者: `fs_aligned_write_forward (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247820` | `0x7100001ffc` |  |
| 1 | `0x7100247828` | `0x710011d270` |  |
| 2 | `0x7100247830` | `0x710011d278` |  |
| 3 | `0x7100247838` | `0x710011d380` |  |
| 4 | `0x7100247840` | `0x710011d488` |  |
| 5 | `0x7100247848` | `0x710011d498` | fs_aligned_write_forward |
| 6 | `0x7100247850` | `0x710011d4e0` | fs_aligned_read_or_cache |
| 7 | `0x7100247858` | `0x710011d56c` | fs_aligned_read_write_router |

## `0x7100247dc0` → 槽0 = `0x7100247dd0`  (n=8)
- 构造/装载者: `FUN_710012d750`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247dd0` | `0x71000bc878` |  |
| 1 | `0x7100247dd8` | `0x710012f934` | fs_log_trace_message_wrapper |
| 2 | `0x7100247de0` | `0x710012f620` | fs_log_trace_output_ex |
| 3 | `0x7100247de8` | `0x710012f6bc` | FUN_710012f6bc |
| 4 | `0x7100247df0` | `0x710012f748` | FUN_710012f748 |
| 5 | `0x7100247df8` | `0x710012f7bc` | FUN_710012f7bc |
| 6 | `0x7100247e00` | `0x710012f830` | fs_log_trace_output |
| 7 | `0x7100247e08` | `0x710012f8a4` | FUN_710012f8a4 |

## `0x7100249c08` → 槽0 = `0x7100249c18`  (n=22)
- 构造/装载者: `FUN_710016a4cc (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100249c18` | `0x710016a4cc` | FUN_710016a4cc |
| 1 | `0x7100249c20` | `0x710016a4f8` | FUN_710016a4f8 |
| 2 | `0x7100249c28` | `0x710016a8f4` |  |
| 3 | `0x7100249c30` | `0x710016a9b0` |  |
| 4 | `0x7100249c38` | `0x710016aa84` | FUN_710016aa84 |
| 5 | `0x7100249c40` | `0x710016ab60` |  |
| 6 | `0x7100249c48` | `0x710016ac80` |  |
| 7 | `0x7100249c50` | `0x710016ad98` | FUN_710016ad98 |
| 8 | `0x7100249c58` | `0x710016ae44` |  |
| 9 | `0x7100249c60` | `0x710016b010` |  |
| 10 | `0x7100249c68` | `0x710016b1dc` |  |
| 11 | `0x7100249c70` | `0x710016b6e0` | FUN_710016b6e0 |
| 12 | `0x7100249c78` | `0x710016b764` | FUN_710016b764 |
| 13 | `0x7100249c80` | `0x710016b260` |  |
| 14 | `0x7100249c88` | `0x710016b440` |  |
| 15 | `0x7100249c90` | `0x710016b6d8` |  |
| 16 | `0x7100249c98` | `0x71000656f8` | fs_idirectory_get_version |
| 17 | `0x7100249ca0` | `0x7100065704` | fs_get_version |
| 18 | `0x7100249ca8` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x7100249cb0` | `0x710016b604` | FUN_710016b604 |
| 20 | `0x7100249cb8` | `0x7100065710` | fs_get_version |
| 21 | `0x7100249cc0` | `0x710016b7e8` | FUN_710016b7e8 |

## `0x710024b048` → 槽0 = `0x710024b058`  (n=4)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024b058` | `0x71001a1ab0` |  |
| 1 | `0x710024b060` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024b068` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 3 | `0x710024b070` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x710023f880` → 槽0 = `0x710023f890`  (n=8)
- 构造/装载者: `fs_nca_fs_obj_init_full`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710023f890` | `0x7100024ca0` | fs_object_destructor |
| 1 | `0x710023f898` | `0x7100024d10` | FUN_7100024d10 |
| 2 | `0x710023f8a0` | `0x7100024d94` | FUN_7100024d94 |
| 3 | `0x710023f8a8` | `0x7100024e4c` | fs_io_read_data |
| 4 | `0x710023f8b0` | `0x7100024f04` |  |
| 5 | `0x710023f8b8` | `0x7100024f24` | FUN_7100024f24 |
| 6 | `0x710023f8c0` | `0x7100025008` |  |
| 7 | `0x710023f8c8` | `0x7100025030` | FUN_7100025030 |

## `0x7100241510` → 槽0 = `0x7100241520`  (n=23)
- 构造/装载者: `FUN_7100051190 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100241520` | `0x7100051190` | FUN_7100051190 |
| 1 | `0x7100241528` | `0x71000511bc` | FUN_71000511bc |
| 2 | `0x7100241530` | `0x71000511f0` | FUN_71000511f0 |
| 3 | `0x7100241538` | `0x7100051310` | FUN_7100051310 |
| 4 | `0x7100241540` | `0x7100051410` | FUN_7100051410 |
| 5 | `0x7100241548` | `0x7100051510` | FUN_7100051510 |
| 6 | `0x7100241550` | `0x7100051610` | FUN_7100051610 |
| 7 | `0x7100241558` | `0x7100051710` | FUN_7100051710 |
| 8 | `0x7100241560` | `0x7100051810` | FUN_7100051810 |
| 9 | `0x7100241568` | `0x71000519b0` | FUN_71000519b0 |
| 10 | `0x7100241570` | `0x7100051b50` | FUN_7100051b50 |
| 11 | `0x7100241578` | `0x7100051c60` | FUN_7100051c60 |
| 12 | `0x7100241580` | `0x7100051d70` | FUN_7100051d70 |
| 13 | `0x7100241588` | `0x7100051e80` | FUN_7100051e80 |
| 14 | `0x7100241590` | `0x7100052000` | FUN_7100052000 |
| 15 | `0x7100241598` | `0x710005217c` |  |
| 16 | `0x71002415a0` | `0x71000656f8` | fs_idirectory_get_version |
| 17 | `0x71002415a8` | `0x7100065704` | fs_get_version |
| 18 | `0x71002415b0` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x71002415b8` | `0x7100052190` | FUN_7100052190 |
| 20 | `0x71002415c0` | `0x71000522b0` | FUN_71000522b0 |
| 21 | `0x71002415c8` | `0x7100052294` |  |
| 22 | `0x71002415d0` | `0x71000523d8` |  |

## `0x7100241f68` → 槽0 = `0x7100241f78`  (n=5)
- 构造/装载者: `FUN_7100063d84 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100241f78` | `0x7100063d70` |  |
| 1 | `0x7100241f80` | `0x7100063d84` | FUN_7100063d84 |
| 2 | `0x7100241f88` | `0x7100063db8` | fs_call_vtable_method_indirect |
| 3 | `0x7100241f90` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100241f98` | `0x7100063dc4` |  |

## `0x7100242308` → 槽0 = `0x7100242318`  (n=5)
- 构造/装载者: `FUN_7100065bcc (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242318` | `0x7100065bcc` | FUN_7100065bcc |
| 1 | `0x7100242320` | `0x7100065be0` | fs_ifile_nop_destructor |
| 2 | `0x7100242328` | `0x7100065c14` | FUN_7100065c14 |
| 3 | `0x7100242330` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242338` | `0x7100065c20` | FUN_7100065c20 |

## `0x7100242340` → 槽0 = `0x7100242350`  (n=3)
- 构造/装载者: `fs_ifile_reset (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242350` | `0x7100065c44` | fs_ifile_reset |
| 1 | `0x7100242358` | `0x7100065c68` | fs_ifile_reset_destructor |
| 2 | `0x7100242360` | `0x7100065c90` | FUN_7100065c90 |

## `0x7100242368` → 槽0 = `0x7100242378`  (n=5)
- 构造/装载者: `FUN_7100067140 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242378` | `0x7100067140` | FUN_7100067140 |
| 1 | `0x7100242380` | `0x7100067154` | fs_ifile_nop_destructor_2 |
| 2 | `0x7100242388` | `0x7100067188` | FUN_7100067188 |
| 3 | `0x7100242390` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242398` | `0x7100067194` | FUN_7100067194 |

## `0x7100242640` → 槽0 = `0x7100242650`  (n=22)
- 构造/装载者: `FUN_71000689c4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242650` | `0x71000689c4` | FUN_71000689c4 |
| 1 | `0x7100242658` | `0x7100068a18` | FUN_7100068a18 |
| 2 | `0x7100242660` | `0x7100068a6c` | FUN_7100068a6c |
| 3 | `0x7100242668` | `0x7100068aa8` | FUN_7100068aa8 |
| 4 | `0x7100242670` | `0x7100068ad8` | FUN_7100068ad8 |
| 5 | `0x7100242678` | `0x7100068b08` | FUN_7100068b08 |
| 6 | `0x7100242680` | `0x7100068b38` | FUN_7100068b38 |
| 7 | `0x7100242688` | `0x7100068b68` | FUN_7100068b68 |
| 8 | `0x7100242690` | `0x7100068b98` | FUN_7100068b98 |
| 9 | `0x7100242698` | `0x7100068bc8` | FUN_7100068bc8 |
| 10 | `0x71002426a0` | `0x7100068bf8` | FUN_7100068bf8 |
| 11 | `0x71002426a8` | `0x7100068c38` | FUN_7100068c38 |
| 12 | `0x71002426b0` | `0x7100068c44` | FUN_7100068c44 |
| 13 | `0x71002426b8` | `0x7100068c50` | FUN_7100068c50 |
| 14 | `0x71002426c0` | `0x7100068cb0` | FUN_7100068cb0 |
| 15 | `0x71002426c8` | `0x7100068d10` | FUN_7100068d10 |
| 16 | `0x71002426d0` | `0x7100068d3c` | FUN_7100068d3c |
| 17 | `0x71002426d8` | `0x7100065704` | fs_get_version |
| 18 | `0x71002426e0` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x71002426e8` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x71002426f0` | `0x7100065710` | fs_get_version |
| 21 | `0x71002426f8` | `0x7100068d84` | FUN_7100068d84 |

## `0x71002433b0` → 槽0 = `0x71002433c0`  (n=22)
- 构造/装载者: `FUN_7100077270 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002433c0` | `0x7100077270` | FUN_7100077270 |
| 1 | `0x71002433c8` | `0x71000772e0` | FUN_71000772e0 |
| 2 | `0x71002433d0` | `0x7100077364` |  |
| 3 | `0x71002433d8` | `0x7100077370` |  |
| 4 | `0x71002433e0` | `0x710007737c` |  |
| 5 | `0x71002433e8` | `0x7100077388` |  |
| 6 | `0x71002433f0` | `0x7100077394` |  |
| 7 | `0x71002433f8` | `0x71000773a0` |  |
| 8 | `0x7100243400` | `0x71000773ac` |  |
| 9 | `0x7100243408` | `0x71000773b8` |  |
| 10 | `0x7100243410` | `0x71000773c4` |  |
| 11 | `0x7100243418` | `0x71000773e4` |  |
| 12 | `0x7100243420` | `0x7100077404` |  |
| 13 | `0x7100243428` | `0x7100077410` | FUN_7100077410 |
| 14 | `0x7100243430` | `0x7100077500` |  |
| 15 | `0x7100243438` | `0x7100077540` |  |
| 16 | `0x7100243440` | `0x7100077548` |  |
| 17 | `0x7100243448` | `0x7100065704` | fs_get_version |
| 18 | `0x7100243450` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x7100243458` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x7100243460` | `0x7100065710` | fs_get_version |
| 21 | `0x7100243468` | `0x7100077554` |  |

## `0x7100244700` → 槽0 = `0x7100244710`  (n=2)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244710` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x7100244718` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100245bf8` → 槽0 = `0x7100245c08`  (n=4)
- 构造/装载者: `FUN_71000a9bd0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245c08` | `0x71000a9bd0` | FUN_71000a9bd0 |
| 1 | `0x7100245c10` | `0x71000a9be4` |  |
| 2 | `0x7100245c18` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 3 | `0x7100245c20` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100247348` → 槽0 = `0x7100247358`  (n=5)
- 构造/装载者: `fs_empty_function (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247358` | `0x71001c8f2c` | fs_empty_function |
| 1 | `0x7100247360` | `0x71000ce62c` | FUN_71000ce62c |
| 2 | `0x7100247368` | `0x71000ce650` |  |
| 3 | `0x7100247370` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100247378` | `0x71000ce668` |  |

## `0x7100247860` → 槽0 = `0x7100247870`  (n=22)
- 构造/装载者: `fs_nca_fs_obj_destructor_full (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247870` | `0x710011d7e0` | fs_nca_fs_obj_destructor_full |
| 1 | `0x7100247878` | `0x710011d89c` | fs_nca_fs_obj_destructor_full_logged |
| 2 | `0x7100247880` | `0x710011dba4` |  |
| 3 | `0x7100247888` | `0x710011dbc4` |  |
| 4 | `0x7100247890` | `0x710011dbd4` |  |
| 5 | `0x7100247898` | `0x710011dbe4` |  |
| 6 | `0x71002478a0` | `0x710011dbf4` |  |
| 7 | `0x71002478a8` | `0x710011dc04` |  |
| 8 | `0x71002478b0` | `0x710011dc14` |  |
| 9 | `0x71002478b8` | `0x710011dc24` |  |
| 10 | `0x71002478c0` | `0x710011dc34` |  |
| 11 | `0x71002478c8` | `0x710011dc54` |  |
| 12 | `0x71002478d0` | `0x710011dc74` |  |
| 13 | `0x71002478d8` | `0x710011dc94` |  |
| 14 | `0x71002478e0` | `0x710011dcd4` |  |
| 15 | `0x71002478e8` | `0x710011dd14` |  |
| 16 | `0x71002478f0` | `0x710011dd24` |  |
| 17 | `0x71002478f8` | `0x710011dd34` |  |
| 18 | `0x7100247900` | `0x710011dd44` |  |
| 19 | `0x7100247908` | `0x710011dd54` |  |
| 20 | `0x7100247910` | `0x710011dd74` |  |
| 21 | `0x7100247918` | `0x710011dd84` |  |

## `0x7100247a80` → 槽0 = `0x7100247a90`  (n=4)
- 构造/装载者: `fs_nca_obj_destroy (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247a90` | `0x710012b0a4` | fs_nca_obj_destroy |
| 1 | `0x7100247a98` | `0x710012b0d4` | fs_nca_obj_destroy_trace |
| 2 | `0x7100247aa0` | `0x710012b0fc` | FUN_710012b0fc |
| 3 | `0x7100247aa8` | `0x710012b1a8` | FUN_710012b1a8 |

## `0x7100247ab0` → 槽0 = `0x7100247ac0`  (n=27)
- 构造/装载者: `fs_nca_obj_init (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247ac0` | `0x710012b3c0` | fs_nca_obj_init |
| 1 | `0x7100247ac8` | `0x710012b490` | FUN_710012b490 |
| 2 | `0x7100247ad0` | `0x710011dba4` |  |
| 3 | `0x7100247ad8` | `0x710011dbc4` |  |
| 4 | `0x7100247ae0` | `0x710011dbd4` |  |
| 5 | `0x7100247ae8` | `0x710011dbe4` |  |
| 6 | `0x7100247af0` | `0x710011dbf4` |  |
| 7 | `0x7100247af8` | `0x710011dc04` |  |
| 8 | `0x7100247b00` | `0x710011dc14` |  |
| 9 | `0x7100247b08` | `0x710011dc24` |  |
| 10 | `0x7100247b10` | `0x710011dc34` |  |
| 11 | `0x7100247b18` | `0x710011dc54` |  |
| 12 | `0x7100247b20` | `0x710011dc74` |  |
| 13 | `0x7100247b28` | `0x710011dc94` |  |
| 14 | `0x7100247b30` | `0x710011dcd4` |  |
| 15 | `0x7100247b38` | `0x710011dd14` |  |
| 16 | `0x7100247b40` | `0x710011dd24` |  |
| 17 | `0x7100247b48` | `0x710011dd34` |  |
| 18 | `0x7100247b50` | `0x710011dd44` |  |
| 19 | `0x7100247b58` | `0x710011dd54` |  |
| 20 | `0x7100247b60` | `0x710011dd74` |  |
| 21 | `0x7100247b68` | `0x710011dd84` |  |
| 22 | `0x7100247b70` | `0x710012c01c` |  |
| 23 | `0x7100247b78` | `0x710012c02c` | fs_nca_sub_obj_destroy |
| 24 | `0x7100247b80` | `0x710012c0b0` | FUN_710012c0b0 |
| 25 | `0x7100247b88` | `0x710012c168` |  |
| 26 | `0x7100247b90` | `0x710012c150` |  |

## `0x71002491f8` → 槽0 = `0x7100249208`  (n=22)
- 构造/装载者: `FUN_710015d940 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100249208` | `0x710015d940` | FUN_710015d940 |
| 1 | `0x7100249210` | `0x710015d9dc` | FUN_710015d9dc |
| 2 | `0x7100249218` | `0x710015ddb4` |  |
| 3 | `0x7100249220` | `0x710015ddd0` |  |
| 4 | `0x7100249228` | `0x710015ddec` |  |
| 5 | `0x7100249230` | `0x710015de08` |  |
| 6 | `0x7100249238` | `0x710015de24` |  |
| 7 | `0x7100249240` | `0x710015de40` |  |
| 8 | `0x7100249248` | `0x710015de5c` |  |
| 9 | `0x7100249250` | `0x710015de78` |  |
| 10 | `0x7100249258` | `0x710015dca4` | FUN_710015dca4 |
| 11 | `0x7100249260` | `0x7100068c38` | FUN_7100068c38 |
| 12 | `0x7100249268` | `0x7100068c44` | FUN_7100068c44 |
| 13 | `0x7100249270` | `0x710015da88` | FUN_710015da88 |
| 14 | `0x7100249278` | `0x710015dbac` | FUN_710015dbac |
| 15 | `0x7100249280` | `0x710015de94` |  |
| 16 | `0x7100249288` | `0x710015de9c` |  |
| 17 | `0x7100249290` | `0x7100065704` | fs_get_version |
| 18 | `0x7100249298` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x71002492a0` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x71002492a8` | `0x7100065710` | fs_get_version |
| 21 | `0x71002492b0` | `0x7100068d84` | FUN_7100068d84 |

## `0x7100249338` → 槽0 = `0x7100249348`  (n=22)
- 构造/装载者: `FUN_710015e3f0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100249348` | `0x710015e3f0` | FUN_710015e3f0 |
| 1 | `0x7100249350` | `0x710015e48c` | FUN_710015e48c |
| 2 | `0x7100249358` | `0x710015e9dc` |  |
| 3 | `0x7100249360` | `0x710015e9f8` |  |
| 4 | `0x7100249368` | `0x710015ea14` |  |
| 5 | `0x7100249370` | `0x710015ea30` |  |
| 6 | `0x7100249378` | `0x710015ea4c` |  |
| 7 | `0x7100249380` | `0x710015ea68` |  |
| 8 | `0x7100249388` | `0x710015ea84` |  |
| 9 | `0x7100249390` | `0x710015eaa0` |  |
| 10 | `0x7100249398` | `0x710015e8cc` | FUN_710015e8cc |
| 11 | `0x71002493a0` | `0x7100068c38` | FUN_7100068c38 |
| 12 | `0x71002493a8` | `0x7100068c44` | FUN_7100068c44 |
| 13 | `0x71002493b0` | `0x710015e6b0` | FUN_710015e6b0 |
| 14 | `0x71002493b8` | `0x710015e7d4` | FUN_710015e7d4 |
| 15 | `0x71002493c0` | `0x710015eabc` |  |
| 16 | `0x71002493c8` | `0x710015eac4` |  |
| 17 | `0x71002493d0` | `0x7100065704` | fs_get_version |
| 18 | `0x71002493d8` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x71002493e0` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x71002493e8` | `0x7100065710` | fs_get_version |
| 21 | `0x71002493f0` | `0x7100068d84` | FUN_7100068d84 |

## `0x7100249478` → 槽0 = `0x7100249488`  (n=22)
- 构造/装载者: `FUN_710015f140 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100249488` | `0x710015f140` | FUN_710015f140 |
| 1 | `0x7100249490` | `0x710015f1dc` | FUN_710015f1dc |
| 2 | `0x7100249498` | `0x710015f5b4` |  |
| 3 | `0x71002494a0` | `0x710015f5d0` |  |
| 4 | `0x71002494a8` | `0x710015f5ec` |  |
| 5 | `0x71002494b0` | `0x710015f608` |  |
| 6 | `0x71002494b8` | `0x710015f624` |  |
| 7 | `0x71002494c0` | `0x710015f640` |  |
| 8 | `0x71002494c8` | `0x710015f65c` |  |
| 9 | `0x71002494d0` | `0x710015f678` |  |
| 10 | `0x71002494d8` | `0x710015f4a4` | FUN_710015f4a4 |
| 11 | `0x71002494e0` | `0x7100068c38` | FUN_7100068c38 |
| 12 | `0x71002494e8` | `0x7100068c44` | FUN_7100068c44 |
| 13 | `0x71002494f0` | `0x710015f288` | FUN_710015f288 |
| 14 | `0x71002494f8` | `0x710015f3ac` | FUN_710015f3ac |
| 15 | `0x7100249500` | `0x710015f694` |  |
| 16 | `0x7100249508` | `0x710015f69c` |  |
| 17 | `0x7100249510` | `0x7100065704` | fs_get_version |
| 18 | `0x7100249518` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x7100249520` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x7100249528` | `0x7100065710` | fs_get_version |
| 21 | `0x7100249530` | `0x7100068d84` | FUN_7100068d84 |

## `0x71002495f8` → 槽0 = `0x7100249608`  (n=22)
- 构造/装载者: `FUN_7100164640 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100249608` | `0x7100164640` | FUN_7100164640 |
| 1 | `0x7100249610` | `0x7100164870` | FUN_7100164870 |
| 2 | `0x7100249618` | `0x71001656e8` | FUN_71001656e8 |
| 3 | `0x7100249620` | `0x7100165704` | FUN_7100165704 |
| 4 | `0x7100249628` | `0x7100165720` | FUN_7100165720 |
| 5 | `0x7100249630` | `0x710016573c` | FUN_710016573c |
| 6 | `0x7100249638` | `0x7100165758` | FUN_7100165758 |
| 7 | `0x7100249640` | `0x7100165774` | FUN_7100165774 |
| 8 | `0x7100249648` | `0x7100165790` | FUN_7100165790 |
| 9 | `0x7100249650` | `0x71001657ac` | FUN_71001657ac |
| 10 | `0x7100249658` | `0x7100165584` | FUN_7100165584 |
| 11 | `0x7100249660` | `0x71001657ec` | FUN_71001657ec |
| 12 | `0x7100249668` | `0x7100068c44` | FUN_7100068c44 |
| 13 | `0x7100249670` | `0x71001652b8` | FUN_71001652b8 |
| 14 | `0x7100249678` | `0x71001653d8` | FUN_71001653d8 |
| 15 | `0x7100249680` | `0x71001657c8` | FUN_71001657c8 |
| 16 | `0x7100249688` | `0x71001657d0` | FUN_71001657d0 |
| 17 | `0x7100249690` | `0x7100065704` | fs_get_version |
| 18 | `0x7100249698` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x71002496a0` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x71002496a8` | `0x7100065710` | fs_get_version |
| 21 | `0x71002496b0` | `0x71001657f8` | FUN_71001657f8 |

## `0x710024a240` → 槽0 = `0x710024a250`  (n=5)
- 构造/装载者: `FUN_71001845b0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024a250` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024a258` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024a260` | `0x71001845b0` | FUN_71001845b0 |
| 3 | `0x710024a268` | `0x71001845d0` |  |
| 4 | `0x710024a270` | `0x710018480c` |  |

## `0x710024a300` → 槽0 = `0x710024a310`  (n=12)
- 构造/装载者: `FUN_7100184b44 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024a310` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024a318` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024a320` | `0x7100184b44` | FUN_7100184b44 |
| 3 | `0x710024a328` | `0x7100184ba8` |  |
| 4 | `0x710024a330` | `0x7100184d88` | FUN_7100184d88 |
| 5 | `0x710024a338` | `0x7100184ee4` | FUN_7100184ee4 |
| 6 | `0x710024a340` | `0x7100184e70` | FUN_7100184e70 |
| 7 | `0x710024a348` | `0x7100186950` |  |
| 8 | `0x710024a350` | `0x7100186960` | FUN_7100186960 |
| 9 | `0x710024a358` | `0x71001869a8` | FUN_71001869a8 |
| 10 | `0x710024a360` | `0x7100186a78` |  |
| 11 | `0x710024a368` | `0x7100186368` | FUN_7100186368 |

## `0x710024a5b8` → 槽0 = `0x710024a5c8`  (n=13)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024a5c8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024a5d0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024a5d8` | `0x7100026574` |  |
| 3 | `0x710024a5e0` | `0x710002657c` |  |
| 4 | `0x710024a5e8` | `0x7100186f88` |  |
| 5 | `0x710024a5f0` | `0x7100186f90` |  |
| 6 | `0x710024a5f8` | `0x7100186f98` |  |
| 7 | `0x710024a600` | `0x7100186fc4` |  |
| 8 | `0x710024a608` | `0x7100186fd0` |  |
| 9 | `0x710024a610` | `0x7100186fdc` |  |
| 10 | `0x710024a618` | `0x7100186fe8` |  |
| 11 | `0x710024a620` | `0x7100186ff4` |  |
| 12 | `0x710024a628` | `0x7100187000` |  |

## `0x710024b9c0` → 槽0 = `0x710024b9d0`  (n=8)
- 构造/装载者: `FUN_71001aa114 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024b9d0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024b9d8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024b9e0` | `0x71001aa114` | FUN_71001aa114 |
| 3 | `0x710024b9e8` | `0x71001aa148` |  |
| 4 | `0x710024b9f0` | `0x71001aa1b4` | FUN_71001aa1b4 |
| 5 | `0x710024b9f8` | `0x71001aa8e0` |  |
| 6 | `0x710024ba00` | `0x71001aa8e8` |  |
| 7 | `0x710024ba08` | `0x71001aa8f0` |  |

## `0x710024bb48` → 槽0 = `0x710024bb58`  (n=13)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024bb58` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024bb60` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024bb68` | `0x7100026574` |  |
| 3 | `0x710024bb70` | `0x710002657c` |  |
| 4 | `0x710024bb78` | `0x71001aac28` |  |
| 5 | `0x710024bb80` | `0x71001aac30` |  |
| 6 | `0x710024bb88` | `0x71001aac38` |  |
| 7 | `0x710024bb90` | `0x71001aac64` |  |
| 8 | `0x710024bb98` | `0x71001aac70` |  |
| 9 | `0x710024bba0` | `0x71001aac7c` |  |
| 10 | `0x710024bba8` | `0x71001aac88` |  |
| 11 | `0x710024bbb0` | `0x71001aac94` |  |
| 12 | `0x710024bbb8` | `0x71001aaca0` |  |

## `0x710024bd18` → 槽0 = `0x710024bd28`  (n=13)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024bd28` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024bd30` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024bd38` | `0x7100026574` |  |
| 3 | `0x710024bd40` | `0x710002657c` |  |
| 4 | `0x710024bd48` | `0x71001aad90` |  |
| 5 | `0x710024bd50` | `0x71001aad98` |  |
| 6 | `0x710024bd58` | `0x71001aada0` |  |
| 7 | `0x710024bd60` | `0x71001aadcc` |  |
| 8 | `0x710024bd68` | `0x71001aadd8` |  |
| 9 | `0x710024bd70` | `0x71001aade4` |  |
| 10 | `0x710024bd78` | `0x71001aadf0` |  |
| 11 | `0x710024bd80` | `0x71001aadfc` |  |
| 12 | `0x710024bd88` | `0x71001aae08` |  |

## `0x710024bc20` → 槽0 = `0x710024bc30`  (n=2)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024bc30` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024bc38` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x710024bf10` → 槽0 = `0x710024bf20`  (n=8)
- 构造/装载者: `FUN_71001ac3f0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024bf20` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024bf28` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024bf30` | `0x71001ac3f0` | FUN_71001ac3f0 |
| 3 | `0x710024bf38` | `0x71001ac430` |  |
| 4 | `0x710024bf40` | `0x71001ac5a8` | FUN_71001ac5a8 |
| 5 | `0x710024bf48` | `0x71001acbc8` |  |
| 6 | `0x710024bf50` | `0x71001acbd0` |  |
| 7 | `0x710024bf58` | `0x71001acbd8` | FUN_71001acbd8 |

## `0x710024c098` → 槽0 = `0x710024c0a8`  (n=13)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024c0a8` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024c0b0` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024c0b8` | `0x7100026574` |  |
| 3 | `0x710024c0c0` | `0x710002657c` |  |
| 4 | `0x710024c0c8` | `0x71001ace50` |  |
| 5 | `0x710024c0d0` | `0x71001ace58` |  |
| 6 | `0x710024c0d8` | `0x71001ace60` |  |
| 7 | `0x710024c0e0` | `0x71001ace8c` |  |
| 8 | `0x710024c0e8` | `0x71001ace98` |  |
| 9 | `0x710024c0f0` | `0x71001acea4` |  |
| 10 | `0x710024c0f8` | `0x71001aceb0` |  |
| 11 | `0x710024c100` | `0x71001acebc` |  |
| 12 | `0x710024c108` | `0x71001acec8` |  |

## `0x710024c6f0` → 槽0 = `0x710024c700`  (n=4)
- 构造/装载者: `FUN_71001b1c04 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024c700` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 1 | `0x710024c708` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 2 | `0x710024c710` | `0x71001b1c04` | FUN_71001b1c04 |
| 3 | `0x710024c718` | `0x71001b245c` |  |

## `0x710024c310` → 槽0 = `0x710024c320`  (n=8)
- 构造/装载者: `FUN_71001b00d4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024c320` | `0x71001b00d4` | FUN_71001b00d4 |
| 1 | `0x710024c328` | `0x71001b0034` | FUN_71001b0034 |
| 2 | `0x710024c330` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 3 | `0x710024c338` | `0x71001c90e0` | fs_pure_virtual_function_call |
| 4 | `0x710024c340` | `0x71001afe54` |  |
| 5 | `0x710024c348` | `0x71001afe60` |  |
| 6 | `0x710024c350` | `0x71001afe64` |  |
| 7 | `0x710024c358` | `0x71000040ac` |  |

## `0x7100242558` → 槽0 = `0x7100242568`  (n=4)
- 构造/装载者: `FUN_7100063be8 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242568` | `0x7100063be8` | FUN_7100063be8 |
| 1 | `0x7100242570` | `0x7100068300` | fs_safe_release_object |
| 2 | `0x7100242578` | `0x7100067f20` | FUN_7100067f20 |
| 3 | `0x7100242580` | `0x71000682e4` | FUN_71000682e4 |

## `0x710023f378` → 槽0 = `0x710023f388`  (n=5)
- 构造/装载者: `FUN_71000028b4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710023f388` | `0x71000028a0` |  |
| 1 | `0x710023f390` | `0x71000028b4` | FUN_71000028b4 |
| 2 | `0x710023f398` | `0x71000028e8` | FUN_71000028e8 |
| 3 | `0x710023f3a0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x710023f3a8` | `0x71000028f4` |  |

## `0x710023f740` → 槽0 = `0x710023f750`  (n=5)
- 构造/装载者: `FUN_7100024130 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710023f750` | `0x710002411c` |  |
| 1 | `0x710023f758` | `0x7100024130` | FUN_7100024130 |
| 2 | `0x710023f760` | `0x7100024164` |  |
| 3 | `0x710023f768` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x710023f770` | `0x7100024170` |  |

## `0x710023f7a8` → 槽0 = `0x710023f7b8`  (n=5)
- 构造/装载者: `FUN_7100024660 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710023f7b8` | `0x710002464c` |  |
| 1 | `0x710023f7c0` | `0x7100024660` | FUN_7100024660 |
| 2 | `0x710023f7c8` | `0x7100024694` |  |
| 3 | `0x710023f7d0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x710023f7d8` | `0x71000246a0` |  |

## `0x710023f810` → 槽0 = `0x710023f820`  (n=5)
- 构造/装载者: `FUN_7100024ad8 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710023f820` | `0x7100024ac4` |  |
| 1 | `0x710023f828` | `0x7100024ad8` | FUN_7100024ad8 |
| 2 | `0x710023f830` | `0x7100024b0c` |  |
| 3 | `0x710023f838` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x710023f840` | `0x7100024b18` |  |

## `0x710023f848` → 槽0 = `0x710023f858`  (n=5)
- 构造/装载者: `FUN_7100024c58 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710023f858` | `0x7100024c44` |  |
| 1 | `0x710023f860` | `0x7100024c58` | FUN_7100024c58 |
| 2 | `0x710023f868` | `0x7100024c8c` |  |
| 3 | `0x710023f870` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x710023f878` | `0x7100024c98` |  |

## `0x710023f9d0` → 槽0 = `0x710023f9e0`  (n=5)
- 构造/装载者: `FUN_7100025a00 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710023f9e0` | `0x71000259ec` |  |
| 1 | `0x710023f9e8` | `0x7100025a00` | FUN_7100025a00 |
| 2 | `0x710023f9f0` | `0x7100025a40` | FUN_7100025a40 |
| 3 | `0x710023f9f8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x710023fa00` | `0x7100025b20` |  |

## `0x7100250058` → 槽0 = `0x7100250068`  (n=3)
- 构造/装载者: `FUN_710004a3a0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100250068` | `0x710004a3a0` | FUN_710004a3a0 |
| 1 | `0x7100250070` | `0x710004a3b0` | fs_safe_release_object |
| 2 | `0x7100250078` | `0x7100000001` |  |

## `0x7100241eb0` → 槽0 = `0x7100241ec0`  (n=5)
- 构造/装载者: `FUN_7100061a5c (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100241ec0` | `0x7100061a48` |  |
| 1 | `0x7100241ec8` | `0x7100061a5c` | FUN_7100061a5c |
| 2 | `0x7100241ed0` | `0x7100061a90` |  |
| 3 | `0x7100241ed8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100241ee0` | `0x7100061a94` |  |

## `0x7100241f30` → 槽0 = `0x7100241f40`  (n=5)
- 构造/装载者: `FUN_7100063d28 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100241f40` | `0x7100063d14` |  |
| 1 | `0x7100241f48` | `0x7100063d28` | FUN_7100063d28 |
| 2 | `0x7100241f50` | `0x7100063d5c` |  |
| 3 | `0x7100241f58` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100241f60` | `0x7100063d68` |  |

## `0x7100242150` → 槽0 = `0x7100242160`  (n=5)
- 构造/装载者: `FUN_71000644fc (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242160` | `0x71000644e8` |  |
| 1 | `0x7100242168` | `0x71000644fc` | FUN_71000644fc |
| 2 | `0x7100242170` | `0x7100064530` | FUN_7100064530 |
| 3 | `0x7100242178` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242180` | `0x7100064534` |  |

## `0x7100242188` → 槽0 = `0x7100242198`  (n=5)
- 构造/装载者: `FUN_7100064670 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242198` | `0x710006465c` |  |
| 1 | `0x71002421a0` | `0x7100064670` | FUN_7100064670 |
| 2 | `0x71002421a8` | `0x71000646a4` |  |
| 3 | `0x71002421b0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002421b8` | `0x71000646b0` |  |

## `0x7100242460` → 槽0 = `0x7100242470`  (n=5)
- 构造/装载者: `FUN_7100067768 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242470` | `0x7100067768` | FUN_7100067768 |
| 1 | `0x7100242478` | `0x710006777c` | FUN_710006777c |
| 2 | `0x7100242480` | `0x71000677b0` | FUN_71000677b0 |
| 3 | `0x7100242488` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242490` | `0x71000677bc` | FUN_71000677bc |

## `0x71002424e8` → 槽0 = `0x71002424f8`  (n=5)
- 构造/装载者: `FUN_7100067c50 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002424f8` | `0x7100067c50` | FUN_7100067c50 |
| 1 | `0x7100242500` | `0x7100067c64` | FUN_7100067c64 |
| 2 | `0x7100242508` | `0x7100067c98` | FUN_7100067c98 |
| 3 | `0x7100242510` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242518` | `0x7100067ca4` | FUN_7100067ca4 |

## `0x7100242588` → 槽0 = `0x7100242598`  (n=3)
- 构造/装载者: `FUN_7100068350 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242598` | `0x7100068350` | FUN_7100068350 |
| 1 | `0x71002425a0` | `0x7100068354` | fs_safe_release_object |
| 2 | `0x71002425a8` | `0x7100068320` | FUN_7100068320 |

## `0x71002425e0` → 槽0 = `0x71002425f0`  (n=3)
- 构造/装载者: `FUN_7100068760 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002425f0` | `0x7100068760` | FUN_7100068760 |
| 1 | `0x71002425f8` | `0x7100068764` | fs_safe_release_object |
| 2 | `0x7100242600` | `0x7100068590` | FUN_7100068590 |

## `0x7100242608` → 槽0 = `0x7100242618`  (n=5)
- 构造/装载者: `FUN_7100068968 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242618` | `0x7100068968` | FUN_7100068968 |
| 1 | `0x7100242620` | `0x710006897c` | FUN_710006897c |
| 2 | `0x7100242628` | `0x71000689b0` | FUN_71000689b0 |
| 3 | `0x7100242630` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242638` | `0x71000689bc` | FUN_71000689bc |

## `0x7100242700` → 槽0 = `0x7100242710`  (n=3)
- 构造/装载者: `FUN_7100068f10 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242710` | `0x7100068f10` | FUN_7100068f10 |
| 1 | `0x7100242718` | `0x7100068f14` | fs_safe_release_object |
| 2 | `0x7100242720` | `0x7100068db0` | FUN_7100068db0 |

## `0x7100242728` → 槽0 = `0x7100242738`  (n=5)
- 构造/装载者: `FUN_7100068fb0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242738` | `0x7100068fb0` | FUN_7100068fb0 |
| 1 | `0x7100242740` | `0x7100068fc4` | FUN_7100068fc4 |
| 2 | `0x7100242748` | `0x7100068ff8` | FUN_7100068ff8 |
| 3 | `0x7100242750` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242758` | `0x7100069004` | FUN_7100069004 |

## `0x7100242760` → 槽0 = `0x7100242770`  (n=3)
- 构造/装载者: `FUN_71000692d4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242770` | `0x71000692d4` | FUN_71000692d4 |
| 1 | `0x7100242778` | `0x71000692d8` | fs_safe_release_object |
| 2 | `0x7100242780` | `0x7100069030` | FUN_7100069030 |

## `0x7100242a80` → 槽0 = `0x7100242a90`  (n=5)
- 构造/装载者: `FUN_710006bfd8 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242a90` | `0x710006bfc4` |  |
| 1 | `0x7100242a98` | `0x710006bfd8` | FUN_710006bfd8 |
| 2 | `0x7100242aa0` | `0x710006c00c` |  |
| 3 | `0x7100242aa8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242ab0` | `0x710006c018` |  |

## `0x7100242950` → 槽0 = `0x7100242960`  (n=5)
- 构造/装载者: `FUN_710006b8c4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242960` | `0x710006b8b0` |  |
| 1 | `0x7100242968` | `0x710006b8c4` | FUN_710006b8c4 |
| 2 | `0x7100242970` | `0x710006b8f8` |  |
| 3 | `0x7100242978` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242980` | `0x710006b904` |  |

## `0x71002429d8` → 槽0 = `0x71002429e8`  (n=5)
- 构造/装载者: `FUN_710006bcac (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002429e8` | `0x710006bc98` |  |
| 1 | `0x71002429f0` | `0x710006bcac` | FUN_710006bcac |
| 2 | `0x71002429f8` | `0x710006bce0` |  |
| 3 | `0x7100242a00` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242a08` | `0x710006bcec` |  |

## `0x7100242a10` → 槽0 = `0x7100242a20`  (n=5)
- 构造/装载者: `FUN_710006bda4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242a20` | `0x710006bd90` |  |
| 1 | `0x7100242a28` | `0x710006bda4` | FUN_710006bda4 |
| 2 | `0x7100242a30` | `0x710006bdd8` |  |
| 3 | `0x7100242a38` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242a40` | `0x710006bde4` |  |

## `0x7100242a48` → 槽0 = `0x7100242a58`  (n=5)
- 构造/装载者: `FUN_710006be94 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242a58` | `0x710006be80` |  |
| 1 | `0x7100242a60` | `0x710006be94` | FUN_710006be94 |
| 2 | `0x7100242a68` | `0x710006bec8` |  |
| 3 | `0x7100242a70` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100242a78` | `0x710006bed4` |  |

## `0x7100242db0` → 槽0 = `0x7100242dc0`  (n=9)
- 构造/装载者: `FUN_710006ce1c (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242dc0` | `0x710006cda8` |  |
| 1 | `0x7100242dc8` | `0x710006d0f4` |  |
| 2 | `0x7100242dd0` | `0x710006ce1c` | FUN_710006ce1c |
| 3 | `0x7100242dd8` | `0x710006cf04` | FUN_710006cf04 |
| 4 | `0x7100242de0` | `0x710006cfac` | FUN_710006cfac |
| 5 | `0x7100242de8` | `0x710006cfe8` | FUN_710006cfe8 |
| 6 | `0x7100242df0` | `0x710006d048` | FUN_710006d048 |
| 7 | `0x7100242df8` | `0x710006d0a8` | FUN_710006d0a8 |
| 8 | `0x7100242e00` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100242e40` → 槽0 = `0x7100242e50`  (n=5)
- 构造/装载者: `FUN_710006d16c (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100242e50` | `0x710006d0f8` |  |
| 1 | `0x7100242e58` | `0x710006d27c` |  |
| 2 | `0x7100242e60` | `0x710006d16c` | FUN_710006d16c |
| 3 | `0x7100242e68` | `0x710006d20c` | FUN_710006d20c |
| 4 | `0x7100242e70` | `0x71001c90e0` | fs_pure_virtual_function_call |

## `0x7100243078` → 槽0 = `0x7100243088`  (n=5)
- 构造/装载者: `FUN_710006de80 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100243088` | `0x710006de6c` |  |
| 1 | `0x7100243090` | `0x710006de80` | FUN_710006de80 |
| 2 | `0x7100243098` | `0x710006deb4` |  |
| 3 | `0x71002430a0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002430a8` | `0x710006dec0` |  |

## `0x7100243138` → 槽0 = `0x7100243148`  (n=5)
- 构造/装载者: `FUN_710006f120 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100243148` | `0x710006f10c` |  |
| 1 | `0x7100243150` | `0x710006f120` | FUN_710006f120 |
| 2 | `0x7100243158` | `0x710006f154` |  |
| 3 | `0x7100243160` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100243168` | `0x710006f160` |  |

## `0x71002432d8` → 槽0 = `0x71002432e8`  (n=5)
- 构造/装载者: `FUN_7100070b3c (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002432e8` | `0x7100070b28` |  |
| 1 | `0x71002432f0` | `0x7100070b3c` | FUN_7100070b3c |
| 2 | `0x71002432f8` | `0x7100070b70` |  |
| 3 | `0x7100243300` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100243308` | `0x7100070b7c` |  |

## `0x7100243340` → 槽0 = `0x7100243350`  (n=5)
- 构造/装载者: `FUN_7100070e74 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100243350` | `0x7100070e60` |  |
| 1 | `0x7100243358` | `0x7100070e74` | FUN_7100070e74 |
| 2 | `0x7100243360` | `0x7100070ea8` |  |
| 3 | `0x7100243368` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100243370` | `0x7100070eb4` |  |

## `0x7100243378` → 槽0 = `0x7100243388`  (n=5)
- 构造/装载者: `FUN_7100077224 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100243388` | `0x7100077210` |  |
| 1 | `0x7100243390` | `0x7100077224` | FUN_7100077224 |
| 2 | `0x7100243398` | `0x7100077258` | FUN_7100077258 |
| 3 | `0x71002433a0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002433a8` | `0x7100077264` |  |

## `0x71002434c0` → 槽0 = `0x71002434d0`  (n=5)
- 构造/装载者: `FUN_71000777e8 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002434d0` | `0x71000777d4` |  |
| 1 | `0x71002434d8` | `0x71000777e8` | FUN_71000777e8 |
| 2 | `0x71002434e0` | `0x710007781c` |  |
| 3 | `0x71002434e8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002434f0` | `0x7100077828` |  |

## `0x71002451a0` → 槽0 = `0x71002451b0`  (n=5)
- 构造/装载者: `FUN_710009c284 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002451b0` | `0x710009c270` |  |
| 1 | `0x71002451b8` | `0x710009c284` | FUN_710009c284 |
| 2 | `0x71002451c0` | `0x710009c2b8` |  |
| 3 | `0x71002451c8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002451d0` | `0x710009c2c0` |  |

## `0x71002440a0` → 槽0 = `0x71002440b0`  (n=5)
- 构造/装载者: `FUN_710007e994 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002440b0` | `0x710007e980` |  |
| 1 | `0x71002440b8` | `0x710007e994` | FUN_710007e994 |
| 2 | `0x71002440c0` | `0x710007e9c8` | FUN_710007e9c8 |
| 3 | `0x71002440c8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002440d0` | `0x710007e9d4` |  |

## `0x71002440d8` → 槽0 = `0x71002440e8`  (n=22)
- 构造/装载者: `FUN_710007e9e0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002440e8` | `0x710007e9e0` | FUN_710007e9e0 |
| 1 | `0x71002440f0` | `0x710007ea60` | FUN_710007ea60 |
| 2 | `0x71002440f8` | `0x710007eaf4` |  |
| 3 | `0x7100244100` | `0x710007eb14` |  |
| 4 | `0x7100244108` | `0x710007eb24` |  |
| 5 | `0x7100244110` | `0x710007eb34` |  |
| 6 | `0x7100244118` | `0x710007eb44` |  |
| 7 | `0x7100244120` | `0x710007eb54` |  |
| 8 | `0x7100244128` | `0x710007eb64` |  |
| 9 | `0x7100244130` | `0x710007eb74` |  |
| 10 | `0x7100244138` | `0x710007eb84` |  |
| 11 | `0x7100244140` | `0x710007eba4` |  |
| 12 | `0x7100244148` | `0x710007ebc4` |  |
| 13 | `0x7100244150` | `0x710007ebe4` |  |
| 14 | `0x7100244158` | `0x710007ec24` |  |
| 15 | `0x7100244160` | `0x710007ec64` |  |
| 16 | `0x7100244168` | `0x710007ec74` |  |
| 17 | `0x7100244170` | `0x710007ec84` |  |
| 18 | `0x7100244178` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x7100244180` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x7100244188` | `0x7100065710` | fs_get_version |
| 21 | `0x7100244190` | `0x710007ec94` |  |

## `0x7100244198` → 槽0 = `0x71002441a8`  (n=5)
- 构造/装载者: `FUN_710007ed6c (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002441a8` | `0x710007ed58` |  |
| 1 | `0x71002441b0` | `0x710007ed6c` | FUN_710007ed6c |
| 2 | `0x71002441b8` | `0x710007eda0` |  |
| 3 | `0x71002441c0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002441c8` | `0x710007edac` |  |

## `0x71002466b8` → 槽0 = `0x71002466c8`  (n=5)
- 构造/装载者: `FUN_71000bf0e4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002466c8` | `0x71000bf0d0` |  |
| 1 | `0x71002466d0` | `0x71000bf0e4` | FUN_71000bf0e4 |
| 2 | `0x71002466d8` | `0x71000bf118` |  |
| 3 | `0x71002466e0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002466e8` | `0x71000bf124` |  |

## `0x7100246768` → 槽0 = `0x7100246778`  (n=5)
- 构造/装载者: `FUN_71000bf534 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246778` | `0x71000bf520` |  |
| 1 | `0x7100246780` | `0x71000bf534` | FUN_71000bf534 |
| 2 | `0x7100246788` | `0x71000bf568` |  |
| 3 | `0x7100246790` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100246798` | `0x71000bf574` |  |

## `0x71002467d8` → 槽0 = `0x71002467e8`  (n=5)
- 构造/装载者: `FUN_71000bf95c (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002467e8` | `0x71000bf948` |  |
| 1 | `0x71002467f0` | `0x71000bf95c` | FUN_71000bf95c |
| 2 | `0x71002467f8` | `0x71000bf990` |  |
| 3 | `0x7100246800` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100246808` | `0x71000bf99c` |  |

## `0x7100246848` → 槽0 = `0x7100246858`  (n=5)
- 构造/装载者: `FUN_71000bfdb0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246858` | `0x71000bfd9c` |  |
| 1 | `0x7100246860` | `0x71000bfdb0` | FUN_71000bfdb0 |
| 2 | `0x7100246868` | `0x71000bfde4` |  |
| 3 | `0x7100246870` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100246878` | `0x71000bfdf0` |  |

## `0x71002468b0` → 槽0 = `0x71002468c0`  (n=5)
- 构造/装载者: `FUN_71000c0384 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002468c0` | `0x71000c0370` |  |
| 1 | `0x71002468c8` | `0x71000c0384` | FUN_71000c0384 |
| 2 | `0x71002468d0` | `0x71000c03b8` |  |
| 3 | `0x71002468d8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002468e0` | `0x71000c03c4` |  |

## `0x7100246918` → 槽0 = `0x7100246928`  (n=5)
- 构造/装载者: `FUN_71000c07e8 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246928` | `0x71000c07d4` |  |
| 1 | `0x7100246930` | `0x71000c07e8` | FUN_71000c07e8 |
| 2 | `0x7100246938` | `0x71000c081c` |  |
| 3 | `0x7100246940` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100246948` | `0x71000c0828` |  |

## `0x7100246350` → 槽0 = `0x7100246360`  (n=5)
- 构造/装载者: `FUN_71000b8ddc (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246360` | `0x71000b8dc8` |  |
| 1 | `0x7100246368` | `0x71000b8ddc` | FUN_71000b8ddc |
| 2 | `0x7100246370` | `0x71000b8e10` | FUN_71000b8e10 |
| 3 | `0x7100246378` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100246380` | `0x71000b8eb0` |  |

## `0x7100246388` → 槽0 = `0x7100246398`  (n=5)
- 构造/装载者: `FUN_71000b8fb0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246398` | `0x71000b8f9c` |  |
| 1 | `0x71002463a0` | `0x71000b8fb0` | FUN_71000b8fb0 |
| 2 | `0x71002463a8` | `0x71000b8fe4` |  |
| 3 | `0x71002463b0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002463b8` | `0x71000b8fe8` |  |

## `0x7100245d68` → 槽0 = `0x7100245d78`  (n=5)
- 构造/装载者: `FUN_71000ad160 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245d78` | `0x71000ad14c` |  |
| 1 | `0x7100245d80` | `0x71000ad160` | FUN_71000ad160 |
| 2 | `0x7100245d88` | `0x71000ad194` |  |
| 3 | `0x7100245d90` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100245d98` | `0x71000ad1a0` |  |

## `0x7100245df0` → 槽0 = `0x7100245e00`  (n=5)
- 构造/装载者: `FUN_71000ae1d8 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245e00` | `0x71000ae1c4` |  |
| 1 | `0x7100245e08` | `0x71000ae1d8` | FUN_71000ae1d8 |
| 2 | `0x7100245e10` | `0x71000ae20c` |  |
| 3 | `0x7100245e18` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100245e20` | `0x71000ae218` |  |

## `0x7100246680` → 槽0 = `0x7100246690`  (n=5)
- 构造/装载者: `FUN_71000be288 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246690` | `0x71000be274` |  |
| 1 | `0x7100246698` | `0x71000be288` | FUN_71000be288 |
| 2 | `0x71002466a0` | `0x71000be2bc` |  |
| 3 | `0x71002466a8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002466b0` | `0x71000be2c4` |  |

## `0x71002464b0` → 槽0 = `0x71002464c0`  (n=5)
- 构造/装载者: `FUN_71000bc830 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002464c0` | `0x71000bc81c` |  |
| 1 | `0x71002464c8` | `0x71000bc830` | FUN_71000bc830 |
| 2 | `0x71002464d0` | `0x71000bc864` |  |
| 3 | `0x71002464d8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002464e0` | `0x71000bc870` |  |

## `0x7100246538` → 槽0 = `0x7100246548`  (n=5)
- 构造/装载者: `FUN_71000bcc14 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246548` | `0x71000bcc00` |  |
| 1 | `0x7100246550` | `0x71000bcc14` | FUN_71000bcc14 |
| 2 | `0x7100246558` | `0x71000bcc50` | FUN_71000bcc50 |
| 3 | `0x7100246560` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100246568` | `0x71000bccf0` |  |

## `0x7100246570` → 槽0 = `0x7100246580`  (n=5)
- 构造/装载者: `FUN_71000bce08 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246580` | `0x71000bcdf4` |  |
| 1 | `0x7100246588` | `0x71000bce08` | FUN_71000bce08 |
| 2 | `0x7100246590` | `0x71000bce40` | FUN_71000bce40 |
| 3 | `0x7100246598` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002465a0` | `0x71000bcee0` |  |

## `0x71002465a8` → 槽0 = `0x71002465b8`  (n=5)
- 构造/装载者: `FUN_71000bd1e0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002465b8` | `0x71000bd1cc` |  |
| 1 | `0x71002465c0` | `0x71000bd1e0` | FUN_71000bd1e0 |
| 2 | `0x71002465c8` | `0x71000bd214` |  |
| 3 | `0x71002465d0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002465d8` | `0x71000bd220` |  |

## `0x71002442b0` → 槽0 = `0x71002442c0`  (n=5)
- 构造/装载者: `FUN_7100082bc0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002442c0` | `0x7100082bac` |  |
| 1 | `0x71002442c8` | `0x7100082bc0` | FUN_7100082bc0 |
| 2 | `0x71002442d0` | `0x7100082bf4` |  |
| 3 | `0x71002442d8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002442e0` | `0x7100082c00` |  |

## `0x71002441f0` → 槽0 = `0x7100244200`  (n=5)
- 构造/装载者: `FUN_7100082798 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244200` | `0x7100082784` |  |
| 1 | `0x7100244208` | `0x7100082798` | FUN_7100082798 |
| 2 | `0x7100244210` | `0x71000827cc` | FUN_71000827cc |
| 3 | `0x7100244218` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100244220` | `0x71000827d8` |  |

## `0x7100244278` → 槽0 = `0x7100244288`  (n=5)
- 构造/装载者: `FUN_7100082aa0 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244288` | `0x7100082a8c` |  |
| 1 | `0x7100244290` | `0x7100082aa0` | FUN_7100082aa0 |
| 2 | `0x7100244298` | `0x7100082ad4` |  |
| 3 | `0x71002442a0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002442a8` | `0x7100082ae0` |  |

## `0x71002443e8` → 槽0 = `0x71002443f8`  (n=5)
- 构造/装载者: `FUN_7100084828 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002443f8` | `0x7100084814` |  |
| 1 | `0x7100244400` | `0x7100084828` | FUN_7100084828 |
| 2 | `0x7100244408` | `0x710008485c` | FUN_710008485c |
| 3 | `0x7100244410` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100244418` | `0x7100084868` |  |

## `0x7100244470` → 槽0 = `0x7100244480`  (n=5)
- 构造/装载者: `FUN_7100084b1c (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244480` | `0x7100084b08` |  |
| 1 | `0x7100244488` | `0x7100084b1c` | FUN_7100084b1c |
| 2 | `0x7100244490` | `0x7100084b50` |  |
| 3 | `0x7100244498` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002444a0` | `0x7100084b5c` |  |

## `0x7100244870` → 槽0 = `0x7100244880`  (n=5)
- 构造/装载者: `FUN_710008bc78 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244880` | `0x710008bc64` |  |
| 1 | `0x7100244888` | `0x710008bc78` | FUN_710008bc78 |
| 2 | `0x7100244890` | `0x710008bcac` |  |
| 3 | `0x7100244898` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002448a0` | `0x710008bcb8` |  |

## `0x71002448a8` → 槽0 = `0x71002448b8`  (n=5)
- 构造/装载者: `FUN_710008bd88 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002448b8` | `0x710008bd74` |  |
| 1 | `0x71002448c0` | `0x710008bd88` | FUN_710008bd88 |
| 2 | `0x71002448c8` | `0x710008bdbc` |  |
| 3 | `0x71002448d0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002448d8` | `0x710008bdc8` |  |

## `0x7100244d90` → 槽0 = `0x7100244da0`  (n=5)
- 构造/装载者: `FUN_7100092564 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244da0` | `0x7100092550` |  |
| 1 | `0x7100244da8` | `0x7100092564` | FUN_7100092564 |
| 2 | `0x7100244db0` | `0x7100092598` | FUN_7100092598 |
| 3 | `0x7100244db8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100244dc0` | `0x71000925a4` |  |

## `0x71002450f8` → 槽0 = `0x7100245108`  (n=5)
- 构造/装载者: `FUN_710009ae34 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245108` | `0x710009ae20` |  |
| 1 | `0x7100245110` | `0x710009ae34` | FUN_710009ae34 |
| 2 | `0x7100245118` | `0x710009ae68` |  |
| 3 | `0x7100245120` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100245128` | `0x710009ae74` |  |

## `0x7100244ec8` → 槽0 = `0x7100244ed8`  (n=5)
- 构造/装载者: `FUN_71000990e4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100244ed8` | `0x71000990d0` |  |
| 1 | `0x7100244ee0` | `0x71000990e4` | FUN_71000990e4 |
| 2 | `0x7100244ee8` | `0x7100099118` | FUN_7100099118 |
| 3 | `0x7100244ef0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100244ef8` | `0x7100099124` |  |

## `0x7100245070` → 槽0 = `0x7100245080`  (n=5)
- 构造/装载者: `FUN_710009a1d4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245080` | `0x710009a1c0` |  |
| 1 | `0x7100245088` | `0x710009a1d4` | FUN_710009a1d4 |
| 2 | `0x7100245090` | `0x710009a208` |  |
| 3 | `0x7100245098` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002450a0` | `0x710009a214` |  |

## `0x7100245440` → 槽0 = `0x7100245450`  (n=5)
- 构造/装载者: `FUN_71000a7c1c (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100245450` | `0x71000a7c08` |  |
| 1 | `0x7100245458` | `0x71000a7c1c` | FUN_71000a7c1c |
| 2 | `0x7100245460` | `0x71000a7c50` |  |
| 3 | `0x7100245468` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100245470` | `0x71000a7c5c` |  |

## `0x71002454d8` → 槽0 = `0x71002454e8`  (n=5)
- 构造/装载者: `FUN_71000a7ea8 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002454e8` | `0x71000a7e94` |  |
| 1 | `0x71002454f0` | `0x71000a7ea8` | FUN_71000a7ea8 |
| 2 | `0x71002454f8` | `0x71000a7edc` |  |
| 3 | `0x7100245500` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100245508` | `0x71000a7ee8` |  |

## `0x7100246d60` → 槽0 = `0x7100246d70`  (n=5)
- 构造/装载者: `FUN_71000c6da4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246d70` | `0x71000c6d90` |  |
| 1 | `0x7100246d78` | `0x71000c6da4` | FUN_71000c6da4 |
| 2 | `0x7100246d80` | `0x71000c6dd8` |  |
| 3 | `0x7100246d88` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100246d90` | `0x71000c6de4` |  |

## `0x7100246f60` → 槽0 = `0x7100246f70`  (n=5)
- 构造/装载者: `FUN_71000c8048 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100246f70` | `0x71000c8034` |  |
| 1 | `0x7100246f78` | `0x71000c8048` | FUN_71000c8048 |
| 2 | `0x7100246f80` | `0x71000c807c` |  |
| 3 | `0x7100246f88` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100246f90` | `0x71000c8088` |  |

## `0x7100247038` → 槽0 = `0x7100247048`  (n=5)
- 构造/装载者: `FUN_71000c93d4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247048` | `0x71000c93c0` |  |
| 1 | `0x7100247050` | `0x71000c93d4` | FUN_71000c93d4 |
| 2 | `0x7100247058` | `0x71000c9408` |  |
| 3 | `0x7100247060` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100247068` | `0x71000c9414` |  |

## `0x71002470c0` → 槽0 = `0x71002470d0`  (n=5)
- 构造/装载者: `FUN_71000c95e8 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002470d0` | `0x71000c95d4` |  |
| 1 | `0x71002470d8` | `0x71000c95e8` | FUN_71000c95e8 |
| 2 | `0x71002470e0` | `0x71000c961c` |  |
| 3 | `0x71002470e8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002470f0` | `0x71000c9628` |  |

## `0x7100247290` → 槽0 = `0x71002472a0`  (n=5)
- 构造/装载者: `FUN_71000cde70 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x71002472a0` | `0x71000cde5c` |  |
| 1 | `0x71002472a8` | `0x71000cde70` | FUN_71000cde70 |
| 2 | `0x71002472b0` | `0x71000cdea4` |  |
| 3 | `0x71002472b8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x71002472c0` | `0x71000cdeb0` |  |

## `0x7100247920` → 槽0 = `0x7100247930`  (n=8)
- 构造/装载者: `fs_resource_pool_destructor (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100247930` | `0x710011e7c8` |  |
| 1 | `0x7100247938` | `0x710011e7dc` | fs_resource_pool_destructor |
| 2 | `0x7100247940` | `0x710011e810` |  |
| 3 | `0x7100247948` | `0x710011e818` |  |
| 4 | `0x7100247950` | `0x710011e828` |  |
| 5 | `0x7100247958` | `0x710011e830` |  |
| 6 | `0x7100247960` | `0x710011e84c` |  |
| 7 | `0x7100247968` | `0x710011e774` |  |

## `0x7100248348` → 槽0 = `0x7100248358`  (n=28)
- 构造/装载者: `FUN_7100136640 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248358` | `0x7100136640` | FUN_7100136640 |
| 1 | `0x7100248360` | `0x7100136728` | FUN_7100136728 |
| 2 | `0x7100248368` | `0x71001368ec` |  |
| 3 | `0x7100248370` | `0x7100136908` |  |
| 4 | `0x7100248378` | `0x7100136914` |  |
| 5 | `0x7100248380` | `0x7100136920` |  |
| 6 | `0x7100248388` | `0x710013692c` |  |
| 7 | `0x7100248390` | `0x7100136938` |  |
| 8 | `0x7100248398` | `0x7100136944` |  |
| 9 | `0x71002483a0` | `0x7100136950` |  |
| 10 | `0x71002483a8` | `0x710013695c` |  |
| 11 | `0x71002483b0` | `0x7100136ae0` |  |
| 12 | `0x71002483b8` | `0x7100136afc` |  |
| 13 | `0x71002483c0` | `0x7100136978` | FUN_7100136978 |
| 14 | `0x71002483c8` | `0x7100136a70` |  |
| 15 | `0x71002483d0` | `0x7100136ab0` |  |
| 16 | `0x71002483d8` | `0x7100136abc` |  |
| 17 | `0x71002483e0` | `0x7100136ad8` |  |
| 18 | `0x71002483e8` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x71002483f0` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x71002483f8` | `0x7100065710` | fs_get_version |
| 21 | `0x7100248400` | `0x7100136b50` |  |
| 22 | `0x7100248408` | `0x7100136b6c` |  |
| 23 | `0x7100248410` | `0x7100136b7c` |  |
| 24 | `0x7100248418` | `0x7100136b94` | FUN_7100136b94 |
| 25 | `0x7100248420` | `0x7100136bcc` |  |
| 26 | `0x7100248428` | `0x7100136bf4` |  |
| 27 | `0x7100248430` | `0x7100136b18` |  |

## `0x7100248908` → 槽0 = `0x7100248918`  (n=8)
- 构造/装载者: `fs_buffer_queue_reset (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248918` | `0x7100144dd0` | fs_buffer_queue_reset |
| 1 | `0x7100248920` | `0x7100144f9c` | FUN_7100144f9c |
| 2 | `0x7100248928` | `0x7100145114` |  |
| 3 | `0x7100248930` | `0x7100146890` |  |
| 4 | `0x7100248938` | `0x7100146f70` | FUN_7100146f70 |
| 5 | `0x7100248940` | `0x71001450f8` |  |
| 6 | `0x7100248948` | `0x71001450e8` |  |
| 7 | `0x7100248950` | `0x71001470b4` | FUN_71001470b4 |

## `0x7100248618` → 槽0 = `0x7100248628`  (n=8)
- 构造/装载者: `fs_object_list_cleanup (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248628` | `0x7100139390` | fs_object_list_cleanup |
| 1 | `0x7100248630` | `0x71001396b4` | FUN_71001396b4 |
| 2 | `0x7100248638` | `0x71001399fc` |  |
| 3 | `0x7100248640` | `0x7100139f68` |  |
| 4 | `0x7100248648` | `0x710013ac90` | FUN_710013ac90 |
| 5 | `0x7100248650` | `0x710013a5d0` |  |
| 6 | `0x7100248658` | `0x710013a5bc` |  |
| 7 | `0x7100248660` | `0x710013aaa0` |  |

## `0x7100248668` → 槽0 = `0x7100248678`  (n=28)
- 构造/装载者: `FUN_710013c458 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248678` | `0x710013c458` | FUN_710013c458 |
| 1 | `0x7100248680` | `0x710013c4dc` | FUN_710013c4dc |
| 2 | `0x7100248688` | `0x710013c55c` |  |
| 3 | `0x7100248690` | `0x710013c684` |  |
| 4 | `0x7100248698` | `0x710013c7a4` |  |
| 5 | `0x71002486a0` | `0x710013c8c4` |  |
| 6 | `0x71002486a8` | `0x710013c9e4` |  |
| 7 | `0x71002486b0` | `0x710013cb04` |  |
| 8 | `0x71002486b8` | `0x710013cc24` |  |
| 9 | `0x71002486c0` | `0x710013cdc4` | FUN_710013cdc4 |
| 10 | `0x71002486c8` | `0x710013cf64` | FUN_710013cf64 |
| 11 | `0x71002486d0` | `0x710013d808` | FUN_710013d808 |
| 12 | `0x71002486d8` | `0x710013d8c8` |  |
| 13 | `0x71002486e0` | `0x710013d07c` |  |
| 14 | `0x71002486e8` | `0x710013d264` |  |
| 15 | `0x71002486f0` | `0x710013d798` |  |
| 16 | `0x71002486f8` | `0x710013d7a0` |  |
| 17 | `0x7100248700` | `0x710013d7cc` |  |
| 18 | `0x7100248708` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x7100248710` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x7100248718` | `0x7100065710` | fs_get_version |
| 21 | `0x7100248720` | `0x710013d988` | FUN_710013d988 |
| 22 | `0x7100248728` | `0x710013da28` |  |
| 23 | `0x7100248730` | `0x710013db0c` |  |
| 24 | `0x7100248738` | `0x710013db18` |  |
| 25 | `0x7100248740` | `0x710013dc1c` |  |
| 26 | `0x7100248748` | `0x710013dc34` |  |
| 27 | `0x7100248750` | `0x710013d9f0` |  |

## `0x7100248868` → 槽0 = `0x7100248878`  (n=8)
- 构造/装载者: `fs_object_destructor (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248878` | `0x7100024ca0` | fs_object_destructor |
| 1 | `0x7100248880` | `0x7100143a20` | FUN_7100143a20 |
| 2 | `0x7100248888` | `0x7100143aa4` |  |
| 3 | `0x7100248890` | `0x7100143bc4` | FUN_7100143bc4 |
| 4 | `0x7100248898` | `0x7100024f04` |  |
| 5 | `0x71002488a0` | `0x7100024f24` | FUN_7100024f24 |
| 6 | `0x71002488a8` | `0x7100025008` |  |
| 7 | `0x71002488b0` | `0x7100025030` | FUN_7100025030 |

## `0x7100248958` → 槽0 = `0x7100248968`  (n=8)
- 构造/装载者: `fs_resource_pool_destroy (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248968` | `0x7100148530` | fs_resource_pool_destroy |
| 1 | `0x7100248970` | `0x71001486b8` | FUN_71001486b8 |
| 2 | `0x7100248978` | `0x7100148fd0` | FUN_7100148fd0 |
| 3 | `0x7100248980` | `0x7100149018` | FUN_7100149018 |
| 4 | `0x7100248988` | `0x7100149060` | FUN_7100149060 |
| 5 | `0x7100248990` | `0x7100148fb4` |  |
| 6 | `0x7100248998` | `0x7100148fa4` | FUN_7100148fa4 |
| 7 | `0x71002489a0` | `0x7100149068` |  |

## `0x7100248b80` → 槽0 = `0x7100248b90`  (n=5)
- 构造/装载者: `FUN_7100155d34 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248b90` | `0x7100155d20` |  |
| 1 | `0x7100248b98` | `0x7100155d34` | FUN_7100155d34 |
| 2 | `0x7100248ba0` | `0x7100155d68` |  |
| 3 | `0x7100248ba8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248bb0` | `0x7100155d74` |  |

## `0x7100248bb8` → 槽0 = `0x7100248bc8`  (n=5)
- 构造/装载者: `FUN_7100155f64 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248bc8` | `0x7100155f50` |  |
| 1 | `0x7100248bd0` | `0x7100155f64` | FUN_7100155f64 |
| 2 | `0x7100248bd8` | `0x7100155f98` |  |
| 3 | `0x7100248be0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248be8` | `0x7100155fa4` |  |

## `0x7100248bf0` → 槽0 = `0x7100248c00`  (n=5)
- 构造/装载者: `FUN_7100156078 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248c00` | `0x7100156064` |  |
| 1 | `0x7100248c08` | `0x7100156078` | FUN_7100156078 |
| 2 | `0x7100248c10` | `0x71001560ac` |  |
| 3 | `0x7100248c18` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248c20` | `0x71001560b8` |  |

## `0x7100248c28` → 槽0 = `0x7100248c38`  (n=5)
- 构造/装载者: `FUN_71001563c4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248c38` | `0x71001563b0` |  |
| 1 | `0x7100248c40` | `0x71001563c4` | FUN_71001563c4 |
| 2 | `0x7100248c48` | `0x71001563f8` |  |
| 3 | `0x7100248c50` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248c58` | `0x7100156404` |  |

## `0x7100248cb0` → 槽0 = `0x7100248cc0`  (n=5)
- 构造/装载者: `FUN_7100156734 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248cc0` | `0x7100156720` |  |
| 1 | `0x7100248cc8` | `0x7100156734` | FUN_7100156734 |
| 2 | `0x7100248cd0` | `0x7100156768` |  |
| 3 | `0x7100248cd8` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248ce0` | `0x7100156774` |  |

## `0x7100248ce8` → 槽0 = `0x7100248cf8`  (n=5)
- 构造/装载者: `FUN_71001568e4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248cf8` | `0x71001568d0` |  |
| 1 | `0x7100248d00` | `0x71001568e4` | FUN_71001568e4 |
| 2 | `0x7100248d08` | `0x7100156918` |  |
| 3 | `0x7100248d10` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248d18` | `0x7100156924` |  |

## `0x7100248d20` → 槽0 = `0x7100248d30`  (n=5)
- 构造/装载者: `FUN_7100156a88 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248d30` | `0x7100156a74` |  |
| 1 | `0x7100248d38` | `0x7100156a88` | FUN_7100156a88 |
| 2 | `0x7100248d40` | `0x7100156abc` |  |
| 3 | `0x7100248d48` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248d50` | `0x7100156ac8` |  |

## `0x7100248da8` → 槽0 = `0x7100248db8`  (n=5)
- 构造/装载者: `FUN_7100156d14 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248db8` | `0x7100156d00` |  |
| 1 | `0x7100248dc0` | `0x7100156d14` | FUN_7100156d14 |
| 2 | `0x7100248dc8` | `0x7100156d48` |  |
| 3 | `0x7100248dd0` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248dd8` | `0x7100156d54` |  |

## `0x7100248de0` → 槽0 = `0x7100248df0`  (n=5)
- 构造/装载者: `FUN_7100156ed8 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248df0` | `0x7100156ec4` |  |
| 1 | `0x7100248df8` | `0x7100156ed8` | FUN_7100156ed8 |
| 2 | `0x7100248e00` | `0x7100156f0c` |  |
| 3 | `0x7100248e08` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248e10` | `0x7100156f18` |  |

## `0x7100248e68` → 槽0 = `0x7100248e78`  (n=5)
- 构造/装载者: `FUN_710015751c (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248e78` | `0x7100157508` |  |
| 1 | `0x7100248e80` | `0x710015751c` | FUN_710015751c |
| 2 | `0x7100248e88` | `0x7100157550` |  |
| 3 | `0x7100248e90` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248e98` | `0x710015755c` |  |

## `0x7100248ef0` → 槽0 = `0x7100248f00`  (n=5)
- 构造/装载者: `FUN_7100157d74 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248f00` | `0x7100157d60` |  |
| 1 | `0x7100248f08` | `0x7100157d74` | FUN_7100157d74 |
| 2 | `0x7100248f10` | `0x7100157da8` |  |
| 3 | `0x7100248f18` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248f20` | `0x7100157db4` |  |

## `0x7100248f28` → 槽0 = `0x7100248f38`  (n=5)
- 构造/装载者: `FUN_7100157e64 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248f38` | `0x7100157e50` |  |
| 1 | `0x7100248f40` | `0x7100157e64` | FUN_7100157e64 |
| 2 | `0x7100248f48` | `0x7100157e98` |  |
| 3 | `0x7100248f50` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248f58` | `0x7100157ea4` |  |

## `0x7100248f60` → 槽0 = `0x7100248f70`  (n=5)
- 构造/装载者: `FUN_7100157fa4 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100248f70` | `0x7100157f90` |  |
| 1 | `0x7100248f78` | `0x7100157fa4` | FUN_7100157fa4 |
| 2 | `0x7100248f80` | `0x7100157fd8` |  |
| 3 | `0x7100248f88` | `0x71001c8fc0` | fs_stub_return_zero |
| 4 | `0x7100248f90` | `0x7100157fe4` |  |

## `0x7100249738` → 槽0 = `0x7100249748`  (n=29)
- 构造/装载者: `FUN_7100166570 (derived)`

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x7100249748` | `0x7100166570` | FUN_7100166570 |
| 1 | `0x7100249750` | `0x7100166638` | FUN_7100166638 |
| 2 | `0x7100249758` | `0x71001669b8` |  |
| 3 | `0x7100249760` | `0x71001669d4` |  |
| 4 | `0x7100249768` | `0x71001669e0` |  |
| 5 | `0x7100249770` | `0x71001669ec` |  |
| 6 | `0x7100249778` | `0x71001669f8` |  |
| 7 | `0x7100249780` | `0x7100166a04` |  |
| 8 | `0x7100249788` | `0x7100166a10` |  |
| 9 | `0x7100249790` | `0x7100166a1c` |  |
| 10 | `0x7100249798` | `0x7100166a28` |  |
| 11 | `0x71002497a0` | `0x7100166d84` |  |
| 12 | `0x71002497a8` | `0x7100166da0` |  |
| 13 | `0x71002497b0` | `0x7100166a44` | FUN_7100166a44 |
| 14 | `0x71002497b8` | `0x7100166b3c` |  |
| 15 | `0x71002497c0` | `0x7100166ca8` |  |
| 16 | `0x71002497c8` | `0x7100166cb0` | FUN_7100166cb0 |
| 17 | `0x71002497d0` | `0x7100166d38` | FUN_7100166d38 |
| 18 | `0x71002497d8` | `0x7100068d6c` | FUN_7100068d6c |
| 19 | `0x71002497e0` | `0x7100068d78` | FUN_7100068d78 |
| 20 | `0x71002497e8` | `0x7100065710` | fs_get_version |
| 21 | `0x71002497f0` | `0x7100166dbc` |  |
| 22 | `0x71002497f8` | `0x7100166ddc` |  |
| 23 | `0x7100249800` | `0x7100166dec` |  |
| 24 | `0x7100249808` | `0x7100166df8` | FUN_7100166df8 |
| 25 | `0x7100249810` | `0x7100166e30` |  |
| 26 | `0x7100249818` | `0x7100166ee8` |  |
| 27 | `0x7100249820` | `0x7100166e60` | FUN_7100166e60 |
| 28 | `0x7100249828` | `0x7100166ef0` |  |

## `0x710024ad10` → 槽0 = `0x710024ad20`  (n=1)

| # | 槽地址 | 目标 | 名称 |
|---|--------|------|------|
| 0 | `0x710024ad20` | `0x71001c90e0` | fs_pure_virtual_function_call |
