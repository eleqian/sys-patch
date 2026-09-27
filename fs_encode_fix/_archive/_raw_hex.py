"""Dump the full raw 32-byte FAT directory entries for selected names under a path.

Usage: python _raw_hex.py /Roms DC GBA PSP
"""
import sys
import importlib.util
import os

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("rl", os.path.join(here, "_raw_ls.py"))
rl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rl)

FIELDS = ["name[0:8]", "name[8:11]", "attr", "ntres/case", "crtTime10", "crtTime", "crtDate",
          "accDate", "clusHi", "modTime", "modDate", "clusLo", "size"]


def decode_name(raw):
    return (raw[0:8].decode("latin-1").rstrip(" ") + "." + raw[8:11].decode("latin-1").rstrip(" ")).rstrip(".")


def main():
    path = sys.argv[1]
    wants = [w.upper() for w in sys.argv[2:]]
    f = rl.open_vol()
    fs = rl.Fat32(f)
    clus = fs.root_clus
    for p in [x for x in path.split("/") if x]:
        rec = rl.find_subdir(fs, clus, p)
        if not rec:
            print("NOT FOUND", p)
            return
        clus = (rec[6] << 16) | rec[7]
    for rec in rl.parse_dir(fs, clus):
        slot, off, raw, name83, lfn, attr, hi, lo, size = rec
        disp = (lfn or name83)
        if wants and disp.upper() not in wants:
            continue
        print("slot=%-4d lba=0x%x  name=%-18s attr=0x%02x size=%d clus=%d" %
              (slot, off // 512, disp, attr, size, (hi << 16) | lo))
        print("    hex:", raw.hex())
        u16s = rl.struct.unpack_from("<16H", raw)
        print("    u16:", " ".join("%04x" % v for v in u16s))
        print("    raw fields: name=%-11s attr=0x%02x ntres=0x%02x crt10=%d crtTime=0x%04x crtDate=0x%04x "
              "accDate=0x%04x clusHi=0x%04x modTime=0x%04x modDate=0x%04x clusLo=0x%04x size=%d" %
              (raw[0:11].decode("latin-1"), raw[0x0B], raw[0x0C], raw[0x0D],
               u16s[7], u16s[8], u16s[9], u16s[10], u16s[11], u16s[12], u16s[13], u16s[14]))
        print()
    f.close()


if __name__ == "__main__":
    main()
