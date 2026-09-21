#!/bin/bash
# Build a btrfs test image exercising every read path, plus a sha256 manifest.
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo "usage: $0 <output-dir>   (writes test.img and manifest.txt there; needs root)" >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "$0: must run as root (it makes a loop mount)" >&2
  exit 2
fi
# Resolve to an absolute path: this script cd's around, so a relative one breaks.
mkdir -p "$1"
OUT="$(cd "$1" && pwd)"
export DEBIAN_FRONTEND=noninteractive
command -v mkfs.btrfs >/dev/null || { apt-get update -qq && apt-get install -y -qq btrfs-progs >/dev/null; }
modprobe btrfs || true
W=/root/btrfs-peek-test
M=$W/mnt
umount "$M" 2>/dev/null || true
rm -rf "$W"; mkdir -p "$M"
IMG=$W/test.img
truncate -s 1G "$IMG"
mkfs.btrfs -q -L peektest "$IMG"
mount -o loop "$IMG" "$M"

cd "$M"
# inline + plain
echo "hello inline" > inline.txt
: > empty.txt
head -c 5000000 /dev/urandom > random.bin
# multi-level trees: many files in one dir
mkdir many
for i in $(seq 1 3000); do echo "file $i" > "many/f_$i.txt"; done
# unicode, spaces, windows-hostile names
mkdir names
echo u > "names/ünïcödé – 名前.txt"
echo s > "names/with space.txt"
echo c > "names/colon:name.txt"
echo q > "names/what?.txt"
# symlinks
ln -s inline.txt link_rel
ln -s /etc/hostname link_abs
ln -s many link_dir
# exec bit + hardlink
printf '#!/bin/sh\necho hi\n' > run.sh; chmod 755 run.sh
ln run.sh run_hardlink.sh
# sparse + prealloc
truncate -s 3M sparse.bin
printf 'DATA' | dd of=sparse.bin bs=1 seek=1048576 conv=notrunc status=none
printf 'TAIL' | dd of=sparse.bin bs=1 seek=3145000 conv=notrunc status=none
fallocate -l 2M prealloc.bin
printf 'PRE' | dd of=prealloc.bin bs=1 seek=4096 conv=notrunc status=none
# size not sector aligned
head -c 123457 /dev/urandom > odd.bin
sync

# compressed, one algorithm each (compressible text, >128K so several extents; plus small inline-compressed)
gen() { for i in $(seq 1 40000); do echo "line $i the quick brown fox jumps over the lazy dog $((i*7919))"; done; }
for alg in zlib lzo zstd; do
  mount -o remount,compress-force=$alg "$M"
  mkdir "c_$alg"
  gen > "c_$alg/big.txt"
  for i in $(seq 1 200); do echo "tiny compressible aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; done > "c_$alg/small_inline.txt"
  # mixed: compressible text + random tail, and a partial overwrite to create offset extents
  { gen; head -c 300000 /dev/urandom; gen; } > "c_$alg/mixed.bin"
  sync
  printf 'OVERWRITE-IN-THE-MIDDLE' | dd of="c_$alg/big.txt" bs=1 seek=200000 conv=notrunc status=none
  sync
done
mount -o remount,compress=no "$M"

# subvolumes + snapshot + nested
btrfs -q subvolume create "$M/@home"
mkdir -p "$M/@home/user/proj/.git"
echo "ref: refs/heads/main" > "$M/@home/user/proj/.git/HEAD"
echo "in subvol" > "$M/@home/user/proj/readme.md"
btrfs -q subvolume create "$M/@home/user/nested_sv"
echo nested > "$M/@home/user/nested_sv/n.txt"
btrfs -q subvolume snapshot -r "$M/@home" "$M/snap_home"
echo "after snapshot" > "$M/@home/user/proj/later.txt"
# reflink clone (shared extent with offset)
cp --reflink=always random.bin clone.bin
sync

# manifest: type, mode, size, sha256 (files), target (symlinks); relative paths, sorted
cd "$M"
{
  find . -mindepth 1 \( -type f -printf 'f %m %s ' -exec sh -c 'sha256sum "$1" | cut -d" " -f1 | tr "\n" " "' _ {} \; -printf '%P\n' \) -o \( -type l -printf 'l %l\t%P\n' \) -o \( -type d -printf 'd %m %P\n' \)
} | LC_ALL=C sort > "$W/manifest.txt"
cd /
umount "$M"
cp "$IMG" "$OUT/test.img"
cp "$W/manifest.txt" "$OUT/manifest.txt"
wc -l "$W/manifest.txt"
echo DONE
