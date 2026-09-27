import json,struct
fmap=json.load(open("_fmap.json"))
fmap={int(k):v for k,v in fmap.items()}
h=open("_idirvt_hex.txt").read().strip()
raw=bytes.fromhex(h)
base=0x7100247390
for i in range(0,len(raw),8):
    v=struct.unpack_from("<Q",raw,i)[0]
    if v==0:
        print(f"  +{i:#06x}  ---")
        continue
    print(f"  +{i:#06x}  {v:#x}  {fmap.get(v,'??')}")
