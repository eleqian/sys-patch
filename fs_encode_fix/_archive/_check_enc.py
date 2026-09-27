# -*- coding: utf-8 -*-
"""Check whether project text files are valid UTF-8 (Write tool may emit GBK for .md)."""
import io, os

ROOT = r"D:\Design\NS\sys-patch"
TARGETS = [
    r".workbuddy\memory\2026-09-15.md",
    r".workbuddy\memory\MEMORY.md",
    r"fs_encode_fix\re_ghidra_round19.md",
    r"fs_encode_fix\re_improve_plan.md",
    r"fs_encode_fix\fs_structs.h",
    r"fs_encode_fix\re_analysis.md",
    r"fs_encode_fix\cp936_vs_utf8.md",
    r"AGENTS.md",
]


def main():
    for rel in TARGETS:
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            print("MISSING ", rel)
            continue
        with open(p, "rb") as f:
            data = f.read()
        try:
            data.decode("utf-8")
            status = "UTF-8 OK"
        except UnicodeDecodeError as e:
            try:
                data.decode("gbk")
                status = "NOT-UTF8 (decodes as GBK) <-- needs conversion: %s" % e
            except UnicodeDecodeError:
                status = "NOT-UTF8 and NOT-GBK (mixed?): %s" % e
        print("%-40s %8d bytes  %s" % (rel, len(data), status))


if __name__ == "__main__":
    main()
