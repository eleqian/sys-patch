# AGENTS.md

Atmosphère system module that patches other system processes (fs, es, ldr, nifm, nim, erpt, olsc) in
memory at boot, plus a Tesla overlay to edit config and view results. C++23 on devkitPro/libnx, aarch64.

Fork of `impeeza/sys-patch` (private remote `eleqian/sys-patch`). The main fork addition is
`fs_codepage_patch()` — UTF-8 / Chinese filename support.

**Scope of this file: repo rules, build/layout, the hard invariants, and the doc map.** It deliberately
does **not** restate the patch scheme — every topic below points at its authoritative doc. Keep it that
way when editing.

## Documentation map

```
README.md                                   user-facing: features, config, build
AGENTS.md                       ← you are here — agent entry: rules, invariants, map
补丁点合并优化分析.md                        design state-of-record + decision ledger (unnumbered;
                                            a bare §N elsewhere in the docs means 演进史)
fs_encode_fix/README.md                     doc hierarchy index — read this to pick a direction
```

| Topic | Authoritative doc |
|---|---|
| **The fs codepage patch — scheme, per-entry implementation, guard, triage, limits** | **`fs_encode_fix/re_utf8_patch_final.md`** ← read first |
| Design state + decision ledger (what is done, what is not, and why) | `补丁点合并优化分析.md` |
| Functional review of the 7 whole-function replacements (Ghidra) | `fs_encode_fix/re_整函数替换功能评估.md` |
| The **decision history** (§1–§20, section numbers stable for cross-refs) | `fs_encode_fix/补丁点合并优化分析·演进史.md` |
| fs object model / struct offsets (`FsDirInfoInternal`, `FsDrvObject`, …) | `fs_encode_fix/re_analysis.md` + `fs_structs.h` |
| Callback / vtable tables (reference data) | `fs_encode_fix/callback_tables.md` |
| Firmware compat: instruction-level vs whole-function, and the audit tool | `fs_encode_fix/re_fw_compat_design.md`, `re_fw_audit_19.0.1.md` |
| Scheme selection (GBK vs UTF-8 — UTF-8 won) | `fs_encode_fix/cp936_vs_utf8.md` |
| Incident post-mortems | `fs_encode_fix/re_boot_hang_2026-09-15.md`, `re_path_not_found_2026-09-15.md`, `re_homebrew_crash_2026-09-16.md`, `re_bigdir_dir_as_file.md` |
| Retired one-off scripts (**do not reference from new work**) | `fs_encode_fix/_archive/README.md` |

## Build

- Prereqs: devkitPro with `DEVKITPRO` set, and the libtesla submodule (`git submodule update --init --recursive`).
- Build from the **repo root**: `make` (builds `sysmod` + `overlay`, copies into `out/`); `make dist` also zips; `make clean`.
- Do **not** run `make -C sysmod` / `make -C overlay` directly — the root Makefile exports
  `CUSTOM_DEFINES` / `VERSION_WITH_HASH` / build-date defines that the sub-Makefiles require.
  ⚠️ On this host, build from **PowerShell at the repo root** and redirect stdout to a file (it is
  otherwise empty). If `cc1plus: No such file or directory` appears, see 演进史 §15.4 (junction workaround).
- Release version is `export VERSION := 1.5.9` in the root Makefile.
- No tests, lint, or typecheck. Verify by building and checking `/config/sys-patch/log.ini` on device.

### Build-time guard (`sysmod/tools/check_patch_sizes.py`)

Runs automatically on every sysmod build; **any failure breaks the build**. `make check-patch-sizes` runs
it standalone. It verifies:

1. **Replacement sizes** — label delta == ELF symbol size, and size ≤ the hole at its fs patch site. A
   size that *exactly equals* its hole is a **`⚠ ZERO SLACK` warning** (still builds, but the next codegen
   wobble turns it into `HOLE OVERFLOW`).
2. **The fs patch tables** — parsed **out of the source text** of `src/fs_codepage.cpp` (`--main` from the
   Makefile). Anything the regexes cannot parse is **silently skipped, i.e. unverified**, so keep every
   entry in the form `PAT_RE` / `BLOB_RE` / `GROUP_RE` / `PRED_LIST_RE` expect.
3. **ASLR position-independence** of the copied replacement bodies.

- sysmod needs **`-fno-toplevel-reorder`** in CXXFLAGS — without it GCC emits the top-level asm before the
  deferred function bodies and the computed size is 0.
- Set `$FS_KIP1` to an fs binary to also resolve each pattern against the real `.text` (otherwise only the
  structural half runs). Hole data in the script's `FUNCTIONS` table comes from Ghidra function boundaries
  — **re-derive when targeting a different fs binary**.
- The full check list (predicate whitelist, exact-cover group intervals, exactly-one-hit per pattern,
  harvest sentinels, family mutual exclusion, blob lane filters, …) is in
  **`fs_encode_fix/re_utf8_patch_final.md` §4** — that is the authoritative description.

## Layout

- `sysmod/` — the system module (title `420000000000000B`). `src/main.cpp` holds the general patch
  tables, config/logging and the entry point; the fs codepage patch lives in `src/fs_codepage.cpp`
  (API `src/fs_codepage.h`, shared pattern/patch types in `src/patch_types.h`); runs once at boot, then exits.
- `overlay/` — Tesla overlay GUI (`sys-patch-overlay.ovl`) for config and log. Its Makefile has an
  `ftp:` target with hardcoded host/credentials — don't run it accidentally.
- `common/minIni/` — INI library shared by both targets.
- `fs_encode_fix/` — fs RE notes, analysis, offline tools (see the map above).
- Runtime config `/config/sys-patch/config.ini`, log `/config/sys-patch/log.ini`.

## The FS codepage patch, at a glance (scheme detail lives in `re_utf8_patch_final.md`)

- Replaces fs's CP932 (Shift-JIS) ↔ UTF-16 routines with UTF-8 ↔ UTF-16 and patches the call sites, so
  **FAT/exFAT entries whose names contain 3-byte CJK characters can be listed, opened and created**.
- **Pattern-driven — no hardcoded fs offsets.** The tables are two-level in `src/fs_codepage.cpp`:
  - `fs_fn_groups[]` slices ranges of
    `fs_inst_patches[]` (instruction rewrites) and `fs_blob_patches[]` (whole-function replacements).
  - A pattern is a byte template where **`.` is a wildcard**; on a hit the instruction at `i+inst_offset`
    is read, `cond(inst)` decides, `patch(inst)` emits the semantically equivalent instruction.
    **Registers, addresses and widths are inherited from the matched site**, so register reallocation
    between FW versions needs no new offsets.
  - A patch **point** (the `pNN` in a name) may carry several **variant-family** patterns (mutually
    exclusive across firmware generations). A 0-hit sibling is expected, not an error.
  - The old `PATTERNS.json` generator/splicer pipeline is **no longer in the repo** — edit the tables in
    `fs_codepage.cpp` directly.
- **No per-entry gating.** A firmware gets the whole patch or none of it; the only switch is
  `[options] fs_codepage=0`. (`stage_idx` / `[fs_codepage] stage=N` and the per-entry `needs_wide_cmp`
  flag were all removed 2026-09-20 — a half-applied table is unsafe, so gating is all-or-nothing.)
- Scan shortcuts (predicate bit-plane, family retirement, idle exit, blob lane prefilter) are pure
  optimizations with data-derived guards. Cost model + equivalence proofs: `补丁点合并优化分析.md`
  (scan structure) and 演进史 §19.

## Hard invariants (do not violate)

- **ASLR discipline.** The 7 replacement bodies are copied verbatim into fs's address space at a
  randomised base — Ghidra's / the ELF's `0x7100xxxx` values are analysis-time only. Copied code must be
  **position-independent and fully self-contained**: no absolute-address materialisation, no external
  calls, no literal pools, no `&function` (`-fPIE` routes `(uintptr_t)&f` through `.data.rel.ro`). The
  guard enforces this. Full rules: `re_utf8_patch_final.md` §3.1.
- **Never hardcode an fs global — harvest it from the site.** The code-page context slot's data address
  changes on every firmware (**18 distinct values across 26 binaries**). The patcher reads the original
  function, decodes its unique `adrp` + paired `ldr`, and re-encodes the pair relative to the sentinel
  placeholder's real address. Sentinels: `0xDEAD0001/2` (ctx slot) and `0xDEAD0003/4` (the one external
  callee, for M6). **If harvesting fails the whole patch point is skipped** (`FAILED_HARVEST`) — never
  write code that dereferences an unverified pointer.
- **Safety invariant: exactly one pattern hit per patch point per target `.text`.** 0 hits = safe
  no-write; ≥2 = the patch could land in the wrong function. Enforced at build time.
- **`constinit` cannot hold function pointers** (taking a function's address is not a constant
  expression) — `fs_blob_patches[]` stores `FsBlobImpl` **enum** values and `fs_blob_range()` switches to
  the address at runtime. Do not put pointers in these tables.
- **Never hand-write bytes into a patch instruction** — only semantically equivalent rewrites, and the
  differential target is the **original**, bit-for-bit over the supported domain. Watch the short-path
  details: e.g. the original's 1-byte Unicode→OEM path puts the NUL at `[1]`, not `[2]`.
- **Changing the tables has a coupling list** (miss one and it fails *silently*):
  `sysmod/tools/check_patch_sizes.py` **and** `fs_encode_fix/fs_fw_audit.py` (its `FS_PAT_RE` /
  `FS_BLOB_RE`). ⚠️ Any pattern parser must use the **same convention as the C++ `str2hex`: one `.` =
  one wildcard byte, parsed character by character** — the historical `PATTERNS.json` convention
  (`..` = one wildcard) doubles the slot count and turns every template into a silent 0-hit.
- ⚠️ **`FS_OVERLAP` must be a multiple of 4** (`0x50`): the predicate bit-plane is indexed by the
  *chunk's* word grid, so an odd overlap shifts that grid off fs's instruction grid and **every
  multi-word pattern silently stops matching** (guarded by `static_assert`).

## Booting / hang triage

`fs_codepage_patch()` writes a progress marker to `[debug] fs_codepage_patch_result` in `log.ini`
*before* each pending patch group (`start → <function-group label> → success`). If a patch breaks fs it
hangs and sys-patch can no longer write to the SD — so the **last recorded value names the culprit group**.

Log fields (deliberately lean since 2026-09-20):

- `[debug] fs_codepage_patch_result` — last group reached / failure reason / `success`.
- `[fs_codepage]` — **only the entries that located** (`<patch_name> = <result>`; failures such as
  `Failed (fs ctx harvest)` stand out).
- `[debug] fs_codepage_unmatched` — count of entries that did not locate.
- `[fs_codepage_sites] <patch_name> = 0x<offset>` — every hit site (offset relative to module base). A
  patch point (`pNN`) is covered iff one of its variant entries appears here.
- `[debug] tmp_buffer` / `tmp_addr` / `tmp_size` were **removed** on 2026-09-20.

**Escape hatch:** `[options] fs_codepage=0` in `config.ini` skips the whole fs codepage patch (all other
sys-patch patches still apply), no rebuild required. There is no finer knob — the patch is all-or-nothing
by design. Full triage: `re_utf8_patch_final.md` §5.

## Firmware compatibility audit — `fs_encode_fix/fs_fw_audit.py`

One command from a firmware image to "do the fs offsets still work, and what are the new ones":
`all <firmware zip|dir>` (unpack → audit → `report.md`), plus `check` / `audit` / `unpack` / `holes`.
It automates the whole hactool/nstool chain, then relocates every patch point with layered clues and
scoring by **semantic** window match (PC-relative displacements masked out). Statuses: `OK` / `MOVED` /
`FUZZY` / `AMBIGUOUS` / `LOST`, plus a **`cmp 精确命中 N/M`** column where `M` = the number of points that
actually exist on that firmware (**14**, not 31 — variant siblings are skipped).

- Baseline for comparison is `$FS_KIP1`, else `ns_reverse/FS_ghidra_1/bin/19.exfat.FS.kip1`.
- Windows traps it already handles: hactool/nstool path-separator mixing; and a **compressed** KIP1 has a
  byte-identical header to a decompressed one and would make every point read `LOST` (rejected up front).
- Details and the usage/run recipe: `re_fw_compat_design.md` §8, `re_fw_audit_19.0.1.md`.

## Patch-table conventions (general patchers in `src/main.cpp`)

- Patterns are byte strings; `.` is the wildcard (`REGEX_SKIP`). `inst_offset` / `patch_offset` are
  relative to the match; `cond` / `patch` / `applied` are constexpr functions.
- `min_fw_ver` / `max_fw_ver` (and AMS equivalents) gate a pattern; `FW_VER_ANY` disables gating. The
  `version_skip` config controls whether gating is enforced at runtime.
- Naming/layout rules: the naming-convention comment above the `*_cond` helpers in `sysmod/src/main.cpp`.
- `out/`, `build/`, `*.elf`, `*.nsp`, `*.ovl`, `*.txt` are gitignored build artifacts, not source.

## Dev tools for fs RE

- `fs_encode_fix/_fs_dis.py` (`sites` / `range` / `word` / `adrp`) — fs binary disassembly helper.
- `fs_encode_fix/_dump_blobs.py` — disassembles the 7 copied replacement bodies out of
  `sysmod/sys-patch.elf` and prints each size against its hole; use it when the guard reports
  `ZERO SLACK` / `HOLE OVERFLOW` and you need to see where the bytes went.
- `fs_encode_fix/_name_collision_check.py` — reports "same name from fs's point of view".
- `_fs_dis.py` and `_dump_blobs.py` need capstone: run them with the managed venv python.
- The former one-off `_dis_*` / `_diag_*` scripts were folded into these and into the build guard;
  retired scripts are in `fs_encode_fix/_archive/` (**do not reference from new work**).

## CI

`.github/workflows/build-jobs.yaml` runs in `devkitpro/devkita64` (`make -C sys-patch -j$(nproc) dist`),
uploads `out/`, and publishes a release via `gh` only when the tag differs from the Makefile `VERSION`.
