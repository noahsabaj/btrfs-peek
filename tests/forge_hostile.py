"""Forge a hostile btrfs image: rename an entry to a path-traversal name.

The kernel will never create such a name, so the only way to test that a reader
refuses it is to write one into the image by hand. The replacement is the same
length as the original so nothing shifts, and every tree block whose bytes we
touched gets its crc32c recomputed so the reader still accepts the metadata.
"""

import shutil
import sys

try:
    from zlib import crc32 as _unused  # noqa: F401
except ImportError:
    pass

POLY_TABLE = []


def _build_table():
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0x82F63B78 if c & 1 else 0)
        POLY_TABLE.append(c)


_build_table()


def crc32c(data, crc=0xFFFFFFFF):
    for b in data:
        crc = (crc >> 8) ^ POLY_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


NODESIZE = 16384


def main():
    src, dst, old, new = sys.argv[1:5]
    old_b, new_b = old.encode(), new.encode()
    assert len(old_b) == len(new_b), "replacement must be the same length"

    shutil.copyfile(src, dst)
    with open(dst, "r+b") as f:
        data = bytearray(f.read())

        hits = []
        start = 0
        while True:
            i = data.find(old_b, start)
            if i < 0:
                break
            hits.append(i)
            start = i + 1
        if not hits:
            print(f"name {old!r} not found in the image")
            return 1

        touched = set()
        for i in hits:
            data[i : i + len(new_b)] = new_b
            touched.add((i // NODESIZE) * NODESIZE)

        # Every tree block is checksummed over [32, nodesize) with the result in
        # the first 4 bytes, so a block we edited must be re-stamped or the
        # reader will (correctly) reject it before ever seeing the name.
        fixed = 0
        for blk in sorted(touched):
            block = data[blk : blk + NODESIZE]
            if len(block) < NODESIZE:
                continue
            csum = crc32c(bytes(block[32:]))
            data[blk : blk + 4] = csum.to_bytes(4, "little")
            fixed += 1

        f.seek(0)
        f.write(data)
    print(f"rewrote {len(hits)} occurrences of {old!r} -> {new!r}, re-stamped {fixed} blocks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
