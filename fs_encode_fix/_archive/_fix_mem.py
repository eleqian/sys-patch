# -*- coding: utf-8 -*-
"""Repair the workspace memory logs (and any mixed-encoding Chinese text file).

Background
----------
`.workbuddy/memory/YYYY-MM-DD.md` is written by several different tools over a
session. Some wrote UTF-8, some wrote GBK/CP936, and a few wrote *mojibake*
(UTF-8 bytes that were already interpreted as GBK and then re-saved as UTF-8),
so a whole-file decode fails: `data.decode('utf-8')` and `data.decode('gbk')`
both raise on the same file.

Strategy
--------
1. Split on b"\\n" and decode **line by line**, trying utf-8 -> gbk -> gb18030
   -> cp936 -> latin-1 in order (latin-1 can never fail, so it is the safety
   net). A line that decodes cleanly as utf-8 is assumed to be genuine text.
2. For every decoded line also try **undoing baked-in mojibake**: re-encode as
   GBK and decode as UTF-8. This succeeds cleanly only when the line really was
   UTF-8-bytes-as-GBK; a genuine Chinese line almost always fails the round trip
   (and is then kept as-is). ASCII is a fixed point and is unaffected.
3. `--apply` backs the file up to `<name>.bak` first, then rewrites it as clean
   UTF-8 with LF endings. Without `--apply` it only dumps a preview to
   `fs_encode_fix/_mem_decoded.txt` (the historical behaviour).

Usage
-----
    python _fix_mem.py <file.md>            # preview + stats (no write)
    python _fix_mem.py <file.md> --apply    # backup + rewrite in place

Run it with the managed venv python (any python3 works, it is stdlib only).
"""
import argparse
import io
import os
import shutil
import sys

ENCODINGS = ("utf-8", "gbk", "gb18030", "cp936", "latin-1")
DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_mem_decoded.txt")

# Chars that are typical of UTF-8-bytes-read-as-GBK mojibake. Used only for
# reporting, never for a destructive decision.
MOJIBAKE_MARKERS = "锛鈥鈽鐨勪簡杩欎釜鍑虹幇鐩存帴鏂囦欢鐗堟湰"


def _reverse(text, enc):
    """Re-encode `text` with `enc` and decode the bytes as utf-8. None if it fails.

    A line boundary can fall inside a multi-byte UTF-8 character when the
    original text was damaged, leaving 1-3 torn bytes at the front. Those can
    never decode; when only the head is broken we drop up to 3 bytes and retry
    (the torn fragment was already unreadable garbage, nothing is lost).
    """
    try:
        blob = text.encode(enc)
    except UnicodeEncodeError:
        return None
    for drop in range(4):
        try:
            return blob[drop:].decode("utf-8")
        except UnicodeDecodeError:
            continue
    return None


def unmojibake(text):
    """Reverse a double-encoding layer. Returns None when no layer applies.

    Two layers occur in this repo's logs:

    * ``gbk``   -- UTF-8 bytes that were read as GBK, then saved as UTF-8
                   (`第三十一轮` -> `绗笁鍗佷竴杞`).
    * ``latin-1`` -- UTF-8 bytes that were read as latin-1/cp1252
                   (`（emoji）` -> `ï¼emojiï¼`).

    A leftover mojibake layer always leaves a spray of visible U+00A0..U+00FF
    bytes (the C1 range U+0080..U+009F is invisible and must NOT be counted --
    it is exactly what a latin-1 layer leaves behind). The candidate with the
    fewest of those wins; anything still dirty falls back to the original text.
    """
    if text.isascii():
        return None  # ASCII is a fixed point, nothing to undo
    original = text
    for _ in range(3):  # logs have been seen with 1, 2 and 3 stacked layers
        nxt = _undo_once(text)
        if nxt is None or nxt == text:
            break
        text = nxt
    return text if text != original else None


def _undo_once(text):
    """Undo a single double-encoding layer. None when none applies."""
    best = None
    best_bad = None
    for enc in ("gbk", "latin-1"):
        cand = _reverse(text, enc)
        if cand is None:
            continue
        bad = sum(1 for ch in cand if "\u00a0" <= ch <= "\u00ff")
        if bad == 0 and any(ord(ch) > 0x2E80 for ch in cand):
            return cand  # clean decode containing CJK: unambiguous win
        if best_bad is None or bad < best_bad:
            best, best_bad = cand, bad
    return best if best_bad == 0 else None


def decode_line(raw):
    """Decode one raw line (no trailing newline). Returns (text, encoding_tag)."""
    for enc in ENCODINGS:
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:  # pragma: no cover - latin-1 cannot fail
        text = raw.decode("utf-8", errors="replace")
        enc = "replace"

    fixed = unmojibake(text)
    if fixed is not None and fixed != text:
        return fixed, enc + "+unmoji"
    return text, enc


def repair(data):
    lines = data.split(b"\n")
    stats = {}
    out = []
    for raw in lines:
        text, enc = decode_line(raw)
        stats[enc] = stats.get(enc, 0) + 1
        out.append(text)
    return "\n".join(out), stats


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", help="file to inspect/repair (usually a memory log)")
    ap.add_argument("--apply", action="store_true", help="back up and rewrite in place")
    ap.add_argument("--out", default=DEFAULT_OUT, help="preview dump path")
    args = ap.parse_args(argv)

    with open(args.path, "rb") as f:
        data = f.read()

    result, stats = repair(data)

    markers_before = sum(data.count(m.encode("gbk", errors="ignore")) for m in "锛鈥")
    print("=== file:", args.path)
    print("=== bytes:", len(data))
    print("=== per-line decoding stats:", stats)
    print("=== mojibake byte-pairs before:", markers_before)

    try:
        result.encode("utf-8")
        clean = True
    except UnicodeEncodeError as exc:  # pragma: no cover
        clean = False
        print("!!! result still not encodable as utf-8:", exc)

    if args.apply:
        if not clean:
            print("!!! refusing to write: result is not valid utf-8")
            return 1
        backup = args.path + ".bak"
        if not os.path.exists(backup):
            shutil.copy2(args.path, backup)
            print("=== backup:", backup)
        else:
            print("=== backup already exists, kept:", backup)
        with io.open(args.path, "w", encoding="utf-8", newline="\n") as f:
            f.write(result)
        print("=== rewrote in place (utf-8):", args.path)
    else:
        with io.open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(result)
        print("=== preview written:", args.out)
        print("=== head ===")
        for line in result.splitlines()[:12]:
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
