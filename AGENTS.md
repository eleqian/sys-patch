# AGENTS.md

Atmosphère system module that patches other system processes (fs, es, ldr, nifm, nim, erpt, olsc) in memory at boot, plus a Tesla overlay to edit config and view results. C++23 on devkitPro/libnx, aarch64.

Fork of `impeeza/sys-patch` (private remote `eleqian/sys-patch`). Main fork addition is `fs_codepage_patch()` — UTF-8/Chinese filename support — see below.

## Build
- Prereqs: devkitPro with `DEVKITPRO` set, and the libtesla submodule (`git submodule update --init --recursive`).
- Build from the **repo root**: `make` (builds `sysmod` + `overlay`, copies into `out/`); `make dist` also zips; `make clean`.
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
- `fs_patch_function()` byte-compares before writing. On mismatch it returns `-2` and records the failure under `[debug] fs_codepage_patch_result` in the log. `cmp_bytes` must be exact and `func_size` must equal the patch-array length, or patches silently stop applying.
- RE notes: `fs_encode_fix/*.md` and `plan.md` (Chinese). The current consolidated RE (known-good patches, data flow, root-cause hypotheses) is `fs_encode_fix/re_plan.md` + `fs_encode_fix/re_analysis.md`. All reconstructed structs are exported as a packed C header `fs_encode_fix/fs_structs.h` (offset-checked with `_Static_assert`).
- Ghidra internal types `FsObject` (0x278), `FsDirInfoInternal` (0xAAA), `FsDrvObject` (0x8C8), `FatFileContext` (0xB0), `FatFileContextPart` (0x70), `FsDirInfoObj` (0x690), `FatFileObject` (0x520) and `FatBaseEntry`/`FatClusterCacheNode` are code-derived; the old `/Demangler` `*_demangler` variants and `FsDirInfo`/`FsDirInfoExt` offsets are unreliable. IPC structs (`nn::fs::DirectoryEntry` 0x310, `FspPath` 0x301, `DirectoryEntryType`) follow switchbrew.
- Known issues from RE: `FsDirInfoInternal.lname` is `char[513]` but the patched `PFCODE_Str_Unicode2OEM` has no output bound, so long CJK names overflow into adjacent fields (`aUnicodeName`/state at 0x688); `FAT_MatchWildcardRecursive`/`FAT_MakeShortName`/`FAT_ReplaceShortNameNumber` still treat the `isOEMMBchar` return as a bool (+1 advance).

## Patch-table conventions
- Patterns are byte strings; `.` is the wildcard (`REGEX_SKIP`). `inst_offset`/`patch_offset` are relative to the match; `cond`/`patch`/`applied` are constexpr functions.
- `min_fw_ver`/`max_fw_ver` (and AMS equivalents) gate a pattern; `FW_VER_ANY` disables gating. The `version_skip` config controls whether gating is enforced at runtime.
- Naming/layout rules: comments at `sysmod/src/main.cpp:118`.
- `out/`, `build/`, `*.elf`, `*.nsp`, `*.ovl`, `*.txt` are gitignored build artifacts, not source.

## CI
`.github/workflows/build-jobs.yaml` runs in `devkitpro/devkita64` (`make -C sys-patch -j$(nproc) dist`), uploads `out/`, and publishes a release via `gh` only when the tag differs from the Makefile `VERSION`.
