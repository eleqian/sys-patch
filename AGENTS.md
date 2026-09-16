# AGENTS.md

Atmosphère system module that patches other system processes (fs, es, ldr, nifm, nim, erpt, olsc) in memory at boot, plus a Tesla overlay to edit config and view results. C++23 on devkitPro/libnx, aarch64.

Fork of `impeeza/sys-patch` (private remote `eleqian/sys-patch`). Main fork addition is `fs_codepage_patch()` — UTF-8/Chinese filename support — see below.

## Build
- Prereqs: devkitPro with `DEVKITPRO` set, and the libtesla submodule (`git submodule update --init --recursive`).
- Build from the **repo root**: `make` (builds `sysmod` + `overlay`, copies into `out/`); `make dist` also zips; `make clean`.
- After each sysmod build, `make` runs `sysmod/tools/check_patch_sizes.py` (build-time guard): patch function sizes are obtained automatically from `_end` assembly labels placed after each patch function (no manual size macros; sysmod needs `-fno-toplevel-reorder` in CXXFLAGS — without it GCC emits the top-level asm before the deferred function bodies and the computed size is 0). The guard verifies (a) label delta == ELF symbol size, (b) size fits the hole at its fs patch site, and (c) **every hand-written patch instruction decodes to a legal rewrite** (`nop` / `movz` keeping Rd / `add Rd,Rn,w0` with imm6=0 and unchanged Rd,Rn / same-address access-width change) — this class of typo has twice produced undecodable garbage that hung fs at boot. If the fs binary is available (`$FS_KIP1`, else the local RE copy) it also byte-compares every cmp signature. `make check-patch-sizes` runs it standalone. Hole data in the script's `FUNCTIONS` table is derived from Ghidra function boundaries — re-derive when targeting a different fs binary.
- Do **not** run `make -C sysmod` / `make -C overlay` directly. The root Makefile exports `CUSTOM_DEFINES` / `VERSION_WITH_HASH` / build-date defines that the sub-Makefiles require.
- Release version is `export VERSION := 1.5.9` in the root Makefile.
- No tests, lint, or typecheck. Verify by building and checking `/config/sys-patch/log.ini` on device.

## Layout
- `sysmod/` — the system module (title `420000000000000B`). `src/main.cpp` holds the patch table and `fs_codepage_patch()`; runs once at boot, then exits.
- `overlay/` — Tesla overlay GUI (`sys-patch-overlay.ovl`) for config and log. Its Makefile has an `ftp:` target with hardcoded host/credentials — don't run it accidentally.
- `common/minIni/` — INI library shared by both targets.
- Runtime config `/config/sys-patch/config.ini`, log `/config/sys-patch/log.ini`.

## FS codepage patch (fork-specific, high risk)
- `fs_codepage_patch()` replaces fs's CP932 (Shift-JIS)↔UTF-16 routines with UTF-8↔UTF-16 and patches call sites so FAT/exFAT handles 3-byte CJK filenames.
- It targets **hardcoded fs offsets** (`0xd4af4`, `0xfeac0`, `0xfec30`, `0xfee40`, `0xf45d8`, `0xf4d8c`, `0xf77e8`, `0xf7984`, `0xf7a80`, `0xf7bd0`). These are **not FW-version gated** (unlike `patches[]`) and are valid only for the exact firmware they were derived from; re-derive from the fs binary for other versions.
- `fs_patch_function()` byte-compares before writing. On mismatch it returns `-2` and records the failure under `[debug] fs_codepage_patch_result` in the log. `cmp_bytes` must be exact and `func_size` must equal the patch-array length, or patches silently stop applying. A **correct cmp with a wrong patch encoding applies silently** — hence the instruction-level build guard above.
- **ASLR discipline (hard requirement)**: the five replacement functions are copied verbatim into fs's address space, and module load addresses are randomized — Ghidra's/ELF's `0x7100xxxx` values are analysis-time only and mean nothing at runtime. Copied code must therefore be **position-independent and fully self-contained**: no absolute address materialisation, no calls to helpers, no literal pools or external data. Read fs globals through PC-relative access (`adrp` with a *page delta* + `ldr`, exactly like the original code does for the code-page context slot `fs+0x24eb50`). Note that `(uintptr_t)&somefunc` is **not** PC-relative under this `-fPIE` build — GCC routes it through `.data.rel.ro`. The build guard's position-independence scan enforces all of the above (it also rejects `BL`, out-of-function `B`, and `MOVZ/MOVK`-built wide constants).
- Booting/hang triage: `fs_codepage_patch()` writes a progress marker to `[debug] fs_stage` in `log.ini` *before* each patch group (`start → converters → fat_callsites → wildcard_r1 → makeshortname_r2 → h1_unicode2oem → r4_toupper → success`). If fs is broken by a patch it hangs, and sys-patch can no longer write to the SD — so the last recorded `fs_stage` names the culprit group. Escape hatch: `[options] fs_codepage=0` in `config.ini` skips the whole fs codepage patch (all other sys-patch patches still apply), no rebuild required.
- RE notes: `fs_encode_fix/*.md` and `plan.md` (Chinese). The **authoritative scheme + implementation write-up for the UTF-8 Chinese-path patch is `fs_encode_fix/re_utf8_patch_final.md`** (patch inventory, ASLR discipline, per-function notes, guard, triage, limitations) — read it first. Incident post-mortems: `re_boot_hang_2026-09-15.md` (boot hang) and `re_path_not_found_2026-09-15.md` (enumerate-but-cannot-open). Struct offsets: `fs_structs.h` (packed, `_Static_assert`-checked); analysis conclusions: `re_analysis.md`; improvement plan: `re_improve_plan.md`. Dev helper for fs RE: `fs_encode_fix/_fs_dis.py` (`sites` / `range` / `word` / `adrp`) — needs capstone, so run it with the managed venv python; the former one-off `_dis_*` / `_diag_*` scripts were folded into it and into the build guard.
- Ghidra internal types `FsObject` (0x278), `FsDirInfoInternal` (0xAAA), `FsDrvObject` (0x8C8), `FatFileContext` (0xB0), `FatFileContextPart` (0x70), `FsDirInfoObj` (0x690), `FatFileObject` (0x520) and `FatBaseEntry`/`FatClusterCacheNode` are code-derived; the old `/Demangler` `*_demangler` variants and `FsDirInfo`/`FsDirInfoExt` offsets are unreliable. IPC structs (`nn::fs::DirectoryEntry` 0x310, `FspPath` 0x301, `DirectoryEntryType`) follow switchbrew.
- Known issues from RE: `FsDirInfoInternal.lname` is `char[513]` but the patched `PFCODE_Str_Unicode2OEM` has no output bound, so long CJK names overflow into adjacent fields (`aUnicodeName`/state at 0x688); `FAT_MatchWildcardRecursive`/`FAT_MakeShortName`/`FAT_ReplaceShortNameNumber` still treat the `isOEMMBchar` return as a bool (+1 advance).

## Patch-table conventions
- Patterns are byte strings; `.` is the wildcard (`REGEX_SKIP`). `inst_offset`/`patch_offset` are relative to the match; `cond`/`patch`/`applied` are constexpr functions.
- `min_fw_ver`/`max_fw_ver` (and AMS equivalents) gate a pattern; `FW_VER_ANY` disables gating. The `version_skip` config controls whether gating is enforced at runtime.
- Naming/layout rules: comments at `sysmod/src/main.cpp:118`.
- `out/`, `build/`, `*.elf`, `*.nsp`, `*.ovl`, `*.txt` are gitignored build artifacts, not source.

## CI
`.github/workflows/build-jobs.yaml` runs in `devkitpro/devkita64` (`make -C sys-patch -j$(nproc) dist`), uploads `out/`, and publishes a release via `gh` only when the tag differs from the Makefile `VERSION`.
