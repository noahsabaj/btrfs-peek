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
btrfs-peek helper install                         # Windows, elevated, once: then no admin needed
btrfs-peek scan                                   # find btrfs partitions
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
root on Linux. On Windows the helper (below) asks for that once instead of every time.

## Without an elevated terminal (Windows)

Windows lets only administrators open a raw disk, so every command fails with
exit code `4` in an ordinary terminal. The helper is a small Windows service
that reads btrfs partitions for you. Install it once, from an elevated terminal:

```
btrfs-peek helper install          # elevated, once
btrfs-peek helper status           # any terminal: exit 0 if it is installed and answering
btrfs-peek helper update           # any terminal: update the service to the latest signed release now
btrfs-peek helper uninstall        # elevated
```

After that, every command works unchanged from any terminal of the account
that installed it. When opening a disk is denied, btrfs-peek asks the helper
instead.

What the helper can and cannot do:

- It opens only btrfs partitions (`\\.\HarddiskNPartitionM`, checked for a btrfs
  superblock). Whole disks, other filesystems, files and other paths are refused.
- It only reads. It opens the partition for reading, as btrfs-peek itself does.
- It answers only the account that installed it (or the one named with `--sid`),
  and only on this machine: its named pipe refuses network clients.
- It runs the copy installed in `C:\Program Files\btrfs-peek`, which only
  administrators can change, never the exe you installed it from. It keeps no
  privileges beyond the ones every process has.
- btrfs-peek checks that the pipe is served by the installed service (by its
  process id) before trusting it.

### Updates

The service updates itself, so a fix to it never needs another elevated
install. Ten minutes after it starts and then daily (or at once with
`btrfs-peek helper update`, from any terminal), it fetches the latest
[release](https://github.com/noahsabaj/btrfs-peek/releases) with Windows' own
`curl.exe` and installs it only if all of these hold:

- its minisign signature verifies against the release key built into the
  service ([update-key.pub](update-key.pub));
- the signature's trusted comment is exactly `btrfs-peek X.Y.Z windows-x86_64`,
  so a build for another target is refused;
- X.Y.Z is newer than the running version, so neither the same build nor an
  older signed one (with a bug since fixed) is taken.

Releases are built and signed in GitHub Actions; the secret key lives in the
repository's secrets and never touches this machine, so nothing running here
can make the service run its code. It swaps the new exe in, waits until no
client is reading through it, and exits so that the service manager starts it
again on the new build. Each check's time, outcome and error are written to
`C:\Program Files\btrfs-peek\update-status.txt`, which `helper status` shows.

A local build (`cargo install`, `cargo build`) updates the btrfs-peek you run
freely, but the service moves only through signed releases. Helpers installed
before 0.3.0 cannot update themselves: run `btrfs-peek helper install` from an
elevated terminal once more.

On Linux, the `disk` group does the same job: `sudo usermod -aG disk $USER`,
then log in again.

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
| `helper install [--sid SID]` / `uninstall` / `status` / `update` | Windows: read without an elevated terminal (above). |

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

## Releases

Push a tag `vX.Y.Z` matching the version in Cargo.toml: `.github/workflows/release.yml`
builds the Windows exe, signs it with the release key, checks the signature against
`update-key.pub`, and publishes both as a GitHub release, which installed helpers then
update to.

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
