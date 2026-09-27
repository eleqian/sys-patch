# sys-patch

A script-like system module that patches **fs**, **es**, **ldr**, **nifm** and **nim** on boot.

---

## Config

**sys-patch** features a simple config. This can be manually edited or updated using the overlay.

The configuration file can be found in `/config/sys-patch/config.ini`. The file is generated once the module is ran for the first time.

```ini
[options]
patch_sysmmc=1   ; 1=(default) patch sysmmc, 0=don't patch sysmmc
patch_emummc=1   ; 1=(default) patch emummc, 0=don't patch emummc
enable_logging=1 ; 1=(default) output /config/sys-patch/log.ini 0=no log
version_skip=1   ; 1=(default) skips out of date patterns, 0=search all patterns
```

---

## Overlay

The overlay can be used to change the config options and to see what patches are applied.

- Unpatched means the patch wasn't applied (likely not found).
- Patched (green) means it was patched by sys-patch.
- Patched (yellow) means it was already patched, likely by sigpatches or a custom Atmosphere build.

<p float="left">
  <img src="https://i.imgur.com/yDhTdI6.jpg" width="400" />
  <img src="https://i.imgur.com/G6U9wGa.jpg" width="400" />
  <img src="https://i.imgur.com/cSXUIWS.jpg" width="400" />
  <img src="https://i.imgur.com/XNLWLqL.jpg" width="400" />
</p>

---

## Building

### prerequisites
- Install [devkitpro](https://devkitpro.org/wiki/Getting_Started)
- Run the following:
  ```sh
  git clone --recurse-submodules https://github.com/ITotalJustice/sys-patch.git
  cd ./sys-patch
  make
  ```

The output of `out/` can be copied to your SD card.
To activate the sys-module, reboot your switch, or, use [sysmodules overlay](https://github.com/WerWolv/ovl-sysmodules/releases/latest) with the accompanying overlay to activate it.

---

## What is being patched?

Here's a quick run down of what's being patched:

- **fs** and **es** need new patches after every new firmware version.
- **ldr** needs new patches after every new [Atmosphere](https://github.com/Atmosphere-NX/Atmosphere/) release.
- **nifm** ctest patch allows the device to connect to a network without needing to make a connection to a server
- **nim** patches to the ssl function call within nim that queries "https://api.hac.%.ctest.srv.nintendo.net/v1/time", and crashes the console if console ssl certificate is not intact. This patch instead makes the console not crash.

The patches are applied on boot. Once done, the sys-module stops running.
The memory footprint *(16kib)* and the binary size *(~50kib)* are both very small.

---

## Fork addition: UTF-8 (Chinese) file names in **fs**

This fork adds `fs_codepage_patch()`: it replaces fs's CP932 (Shift-JIS) ↔ UTF-16 routines with
UTF-8 ↔ UTF-16 and patches the call sites, so **FAT/exFAT entries whose names contain 3-byte CJK
characters can be listed, opened and created** (Stock firmware shows them as garbage or fails to open them).

It is **pattern-driven** — the tables carry byte templates, not offsets — so one build covers every
fs variant from **14.1.2 to 22.5.0** (26 binaries, 14 patch points each) and a new firmware needs no
new offsets. Every change is verified at build time by `sysmod/tools/check_patch_sizes.py`
(function sizes + holes, unique pattern hits, ASLR/position-independence of the copied code).

Config (`/config/sys-patch/config.ini`, written with defaults on first run):

```ini
[options]
fs_codepage=1     ; 0 = skip the whole fs codepage patch (escape hatch, no rebuild needed)
```

There is no partial / bisect switch — no per-entry flags: the table is applied all-or-nothing
(a half-applied table is dangerous: a replaced converter without its paired width clamp hangs
`FAT_MakeShortName`), so if you need to rule the patch out, turn the whole thing off.

If fs hangs after a patch, it can no longer write to the SD, so the last value of
`[debug] fs_codepage_patch_result` in `log.ini` names the function group that broke it.
The `[fs_codepage]` log section then lists the entries that located (failures stand out as
`Failed (...)`), `[debug] fs_codepage_unmatched` counts the rest, and `[fs_codepage_sites]` gives every
hit offset.
Design + implementation notes (Chinese): `fs_encode_fix/re_utf8_patch_final.md`.
Doc hierarchy / index: `fs_encode_fix/README.md`.

---

## FAQ:

### If I am using sigpatches already, is there any point in using this?

Yes, in 3 situations.

1. A new **ldr** patch needs to be created after every Atmosphere update. Sometimes, a new silent Atmosphere update is released. This tool will always patch **ldr** without having to update patches.

2. Building Atmosphere from src will require you to generate a new **ldr** patch for that custom built Atmosphere. This is easy enough due to the public scripts / tools that exist out there, however this will always be able to patch **ldr**.

3.  If you forget to update your patches when you update your firmware / Atmosphere, this sys-module should be able to patch everything. So it can be used as a fall back.

### Does this mean that I should stop downloading / using sigpatches?

No, I would personally recommend continuing to use sigpatches. Reason being is that should this tool ever break, i likely wont be quick to fix it.

---

## Credits / Thanks

Software is built on the shoulders of giants. This tool wouldn't be possible without these people:

- MrDude
- BornToHonk (farni)
- TeJay
- ArchBox
- Switchbrew (libnx, switch-examples)
- DevkitPro (toolchain)
- [minIni](https://github.com/compuphase/minIni)
- [libtesla](https://github.com/WerWolv/libtesla)
- [Shoutout to the best switch cfw setup guide](https://rentry.org/SwitchHackingIsEasy)
- N
