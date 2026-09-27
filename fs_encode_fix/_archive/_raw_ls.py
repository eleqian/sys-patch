r"""Raw FAT32 directory dumper for the SWITCH SD (F:).

Reads the volume via \\.\F: (read-only) and dumps directory entries with their
8.3 name, LFN, attribute byte, first cluster and size, plus the absolute byte
offset of every raw 32-byte slot. Used to check whether the "subdirectory shown
as file" entries really lost ATTR_DIRECTORY on disk.

Usage: python _raw_ls.py <dir-path>   e.g.  python _raw_ls.py /Roms
"""
import sys
import struct

VOL = r"\\.\F:"
SECTOR = 512


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def open_vol():
    return open(VOL, "rb", buffering=0)


def read_at(f, lba, count):
    return pread(f, lba * SECTOR, count * SECTOR)


def pread(f, offset, length):
    """Raw volume handles need sector-aligned offset and length."""
    start = (offset // SECTOR) * SECTOR
    end = ((offset + length + SECTOR - 1) // SECTOR) * SECTOR
    f.seek(start)
    data = f.read(end - start)
    if len(data) != end - start:
        raise IOError("short read at %d" % start)
    return data[offset - start:offset - start + length]


class Fat32:
    def __init__(self, f):
        self.f = f
        bs = read_at(f, 0, 1)
        assert bs[510:512] == b"\x55\xaa", "no boot signature"
        self.bytes_per_sector = u16(bs, 0x0B) or 512
        assert self.bytes_per_sector == SECTOR, "sector size %d" % self.bytes_per_sector
        self.sec_per_clus = bs[0x0D]
        self.reserved = u16(bs, 0x0E)
        self.num_fats = bs[0x10]
        self.fat_size = u32(bs, 0x24) or u32(bs, 0x30)
        self.root_clus = u32(bs, 0x2C)
        self.fat_lba = self.reserved
        self.data_lba = self.reserved + self.num_fats * self.fat_size
        self.clus_bytes = self.sec_per_clus * self.bytes_per_sector
        # first data cluster is 2
        self.root_clus = u32(bs, 0x2C)

    def clus_to_lba(self, clus):
        return self.data_lba + (clus - 2) * self.sec_per_clus

    def read_fat_entry(self, clus):
        off = clus * 4
        return u32(pread(self.f, self.fat_lba * SECTOR + off, 4), 0) & 0x0FFFFFFF

    def read_bytes(self, offset, length):
        return pread(self.f, offset, length)

    def chain(self, clus, limit=100000):
        out = []
        seen = set()
        while 2 <= clus < 0x0FFFFFF8 and clus not in seen and len(out) < limit:
            out.append(clus)
            seen.add(clus)
            clus = self.read_fat_entry(clus)
        if clus and clus < 0x0FFFFFF8 and clus in seen:
            out.append(("LOOP->%d" % clus))
        return out

    def read_clus(self, clus):
        return read_at(self.f, self.clus_to_lba(clus), self.sec_per_clus)


def parse_dir(fs, clus):
    """Yield (slot_index, absolute_offset, raw32, name83, lfn, attr, hi, lo, size)."""
    lfn_parts = []
    slot = 0
    abs_off = 0
    for c in fs.chain(clus):
        if isinstance(c, str):
            break
        base = fs.clus_to_lba(c) * SECTOR
        data = fs.read_clus(c)
        for i in range(0, len(data), 32):
            raw = data[i:i + 32]
            if raw[0] == 0x00:
                return
            if raw[0] == 0xE5:
                lfn_parts = []
                slot += 1
                continue
            attr = raw[0x0B]
            if attr == 0x0F:
                # LFN entry: gather, sequence number low 5 bits
                seq = raw[0] & 0x1F
                chars = raw[1:11] + raw[14:26] + raw[28:32]
                try:
                    txt = chars.decode("utf-16-le", "replace")
                except Exception:
                    txt = "?"
                lfn_parts.append((seq, txt))
                slot += 1
                continue
            # normal entry
            name83 = raw[0:8].decode("latin-1").rstrip(" ") + "." + \
                     raw[8:11].decode("latin-1").rstrip(" ")
            name83 = name83.rstrip(".")
            lfn = ""
            if lfn_parts:
                lfn_parts.sort(key=lambda x: x[0])
                lfn = "".join(t for _, t in lfn_parts).split("\x00")[0]
            hi = u16(raw, 0x14)
            lo = u16(raw, 0x1A)
            size = u32(raw, 0x1C)
            yield (slot, base + i, raw, name83, lfn, attr, hi, lo, size)
            lfn_parts = []
            slot += 1


def find_subdir(fs, clus, want):
    for rec in parse_dir(fs, clus):
        slot, off, raw, name83, lfn, attr, hi, lo, size = rec
        display = lfn or name83
        if display.upper().rstrip(" ") == want.upper():
            return rec
    return None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/Roms"
    parts = [p for p in path.split("/") if p]
    f = open_vol()
    fs = Fat32(f)
    print("bytes/sector=%d sec/clus=%d clus_bytes=%d reserved=%d fat_lba=%d data_lba=%d root_clus=%d"
          % (fs.bytes_per_sector, fs.sec_per_clus, fs.clus_bytes, fs.reserved, fs.fat_lba, fs.data_lba, fs.root_clus))
    clus = fs.root_clus
    for p in parts:
        rec = find_subdir(fs, clus, p)
        if not rec:
            print("NOT FOUND:", p)
            return
        clus = (rec[6] << 16) | rec[7]
        print("path=%s -> clus=%d" % (p, clus))
    chain = fs.chain(clus)
    print("chain:", chain[:20], "..." if len(chain) > 20 else "")
    print()
    print("%-5s %-22s %-6s %-32s %-10s %s" % ("slot", "8.3", "attr", "LFN", "firstClus", "size"))
    for rec in parse_dir(fs, clus):
        slot, off, raw, name83, lfn, attr, hi, lo, size = rec
        fc = (hi << 16) | lo
        typ = "DIR " if attr & 0x10 else "FILE"
        print("%-5d %-22s 0x%02x %-3s %-32s %-10d %d" % (slot, name83, attr, typ, lfn[:32], fc, size))
    f.close()


if __name__ == "__main__":
    main()
