import json, re, sys

FMAP = r"C:/Users/eleqi/.workbuddy/projects/d-Design-NS-sys-patch/14f8d07c-0adb-4c2c-ba77-5e79d1608e6a/tool-results/mcp-bridge-mcp-ghidra-list_functions-1789304454610-cbf2a0.txt"

m = {}
for line in open(FMAP, encoding="utf-8", errors="replace"):
    line = line.strip()
    if " at " not in line:
        continue
    name, addr = line.rsplit(" at ", 1)
    try:
        a = int(addr, 16)
    except ValueError:
        continue
    m[a] = name

print("functions parsed:", len(m))
json.dump({str(k): v for k, v in m.items()}, open("_fmap.json", "w"))

for t in ["PFCODE_CP932_OEM2Unicode", "PFCODE_CP932_Unicode2OEM", "fs_object_destructor",
          "IDirectory_Func_Table", "fs_stub_return_zero", "fs_pure_virtual"]:
    hits = [(hex(a), n) for a, n in sorted(m.items()) if t.lower() in n.lower()]
    print(f"{t}: {len(hits)} -> {hits[:8]}")
