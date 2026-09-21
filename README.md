# btrfs-peek

[![CI](https://github.com/noahsabaj/btrfs-peek/actions/workflows/ci.yml/badge.svg)](https://github.com/noahsabaj/btrfs-peek/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

Read a btrfs filesystem from userspace. Read-only, on any OS, with no driver and no mount.

Built for the dual-boot problem: your work is on the Linux partition, you are booted into
Windows, and the only options were a kernel driver that can write to your disk or a reboot.
`btrfs-peek` parses the on-disk format directly from the raw partition (or an image file),
so it cannot modify the filesystem: the device is opened for reading and no code path writes to it.

It is also built to be driven by agents: every command has `--json`, errors go to stderr,
exit codes are distinct, and nothing is interactive.

```
btrfs-peek scan                                   # find btrfs partitions (admin/root)
btrfs-peek -d \\.\Harddisk0Partition6 info
btrfs-peek -d \\.\Harddisk0Partition6 subvols
btrfs-peek -d \\.\Harddisk0Partition6 ls -l /@home/me
btrfs-peek -d \\.\Harddisk0Partition6 find / --name .git -t d --no-snapshots --max-depth 6
btrfs-peek -d \\.\Harddisk0Partition6 cat /@/etc/fstab
btrfs-peek -d \\.\Harddisk0Partition6 cp /@home/me/code/proj C:\tmp\proj -e target -e node_modules
```

Set `BTRFS_PEEK_DEVICE` to skip `-d`. On Linux or macOS the device is `/dev/nvme0n1p6` or an image file.

## Install

```
cargo install --git https://github.com/noahsabaj/btrfs-peek
```

Pure Rust, no C toolchain needed, and it builds on Windows, Linux and macOS.
Raw disks need privileges: an elevated (Administrator) terminal on Windows,
root on Linux.

## Paths and subvolumes

Paths are absolute from the top-level subvolume (id 5), where every other subvolume is a
directory. A distro that mounts `@home` at `/home` has its files under `/@home` here;
Fedora uses `/home` and `/root`. `subvols` and `ls /` show the layout.

Symlinks are reported, never followed: their targets refer to the Linux mount layout,
which the tool cannot know.

## Commands

| Command | What it does |
|---|---|
| `scan` | Probe every disk and partition for a btrfs superblock. |
| `info` | Label, UUID, size, features, RAID profiles, default subvolume, clean-unmount state. |
| `subvols` | Subvolumes and snapshots with full paths. |
| `ls [-l] PATH` | List a directory. |
| `stat PATH` | Metadata, extent count, compression in use. |
| `cat PATH [--offset N --length N]` | File contents to stdout. |
| `find PATH [--name GLOB] [-t f\|d\|l] [--max-depth N] [-x] [--no-snapshots]` | Search by name. |
| `cp SRC DEST [-e GLOB]... [--force] [-x] [--no-snapshots] [--manifest FILE]` | Copy a file or tree out. |

`cp` keeps sparse files sparse, sets mtimes, and keeps going past an unreadable file
(reported as a warning). What the host cannot represent is handled rather than dropped:

- Names Windows rejects (`a:b`, `what?`, `nul.txt`, trailing dots, case collisions) are
  rewritten and reported.
- Symlinks are created when the host allows it; otherwise they are reported.
- `--manifest` writes JSON lines with each entry's mode, uid, gid, mtime, and symlink
  target, so permissions and links can be reapplied later.

Exit codes: `0` ok, `1` error, `2` usage, `3` path not found, `4` device access
denied, `5` the copy finished but some entries failed. A partial copy never exits
`0`, and a file that could not be read is removed rather than left looking whole.

## Reading an image you did not make

The filesystem is treated as untrusted input. A crafted image cannot make `cp`
write outside the destination you named: entry names are reduced to a single
path component on every platform, and the result is re-checked before use.
Corrupt metadata is reported rather than guessed at, and a corrupt compressed
extent fails that file instead of silently producing a file full of zeros.

This is enforced by a test, not just by intent: CI forges an entry named
`../../evil` into a real image (re-stamping the checksums so the reader still
accepts it) and fails the build if anything lands outside the destination.

## What is supported

- zlib, lzo, and zstd compression; inline, regular, preallocated, and sparse extents; reflinks.
- Subvolumes, snapshots, nested subvolumes.
- `single`, `dup`, and `raid1*` profiles, including multi-device (repeat `-d`).
- Metadata checksums are verified (crc32c) with fallback to the DUP/RAID1 mirror,
  and data reads fall back to the other mirror too.

Not supported: RAID0/10/5/6 striped across devices, `extent-tree-v2`, `raid-stripe-tree`,
encryption (LUKS sits below btrfs; unlock it first). These are refused with an error rather
than read wrongly. Data checksums are not verified, and metadata checksums other than
crc32c are not checked -- the tool warns loudly when it cannot verify them. The log
tree is not replayed: after an unclean shutdown, writes fsynced in the last seconds
before it are not visible (the tool warns).

Git Bash on Windows rewrites arguments that look like Unix paths. Use PowerShell, or
`export MSYS_NO_PATHCONV=1`.

## Testing

`tests/mkimg.sh` builds an image on Linux (WSL works) that exercises every read path and
writes a sha256 manifest from the kernel's view of it. `tests/verify.py` compares a
`btrfs-peek cp --manifest` run against that manifest: every path, type, mode, size, hash,
and symlink target must match.

```
sudo bash tests/mkimg.sh /some/dir
btrfs-peek -d /some/dir/test.img cp / out --manifest peek.jsonl
python tests/verify.py /some/dir/manifest.txt peek.jsonl /
```

## Contributing

Issues and pull requests are welcome. The one hard rule: nothing may ever write
to the source device. A change that opens it for anything but reading will be
rejected.

If you hit a filesystem this tool reads wrongly, the most useful bug report is
the output of `btrfs-peek info` plus, if you can make one, a small image that
reproduces it.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
