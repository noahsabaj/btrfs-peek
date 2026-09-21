//! btrfs-peek: read a btrfs filesystem from userspace, read-only, on any OS.

mod copy;
mod decompress;
mod dev;
mod disk;
mod fs;
mod scan;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use fs::{Fs, Loc, NotFound, Piece};
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;

const AFTER_HELP: &str = "\
PATHS are absolute from the top-level subvolume (id 5). Other subvolumes appear
as directories, so a distro that mounts `@home` at /home keeps its files under
/@home here. Run `subvols` or `ls /` to see the layout.

EXIT CODES: 0 ok, 1 error, 2 usage, 3 path not found, 4 device access denied,
5 copy finished but some entries failed (see the warnings).

The device is only ever opened for reading. Nothing is mounted, no driver is
installed, and no code path writes to it.";

#[derive(Parser)]
#[command(version, about, after_help = AFTER_HELP)]
struct Cli {
    /// Image file or block device (\\.\Harddisk0Partition6, /dev/nvme0n1p6). Repeat for multi-device filesystems.
    #[arg(short, long, global = true, env = "BTRFS_PEEK_DEVICE")]
    device: Vec<String>,
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Find btrfs filesystems on this machine's disks (needs admin/root).
    Scan,
    /// Filesystem summary: label, uuid, size, features, profiles.
    Info,
    /// List subvolumes and snapshots with their paths.
    Subvols,
    /// List a directory.
    Ls {
        #[arg(default_value = "/")]
        path: String,
        /// Include mode, owner, size, mtime, and symlink targets.
        #[arg(short, long)]
        long: bool,
    },
    /// Show one path's metadata and extent layout.
    Stat { path: String },
    /// Write a file's contents to stdout.
    Cat {
        path: String,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long)]
        length: Option<u64>,
    },
    /// Search a directory tree by name.
    Find {
        #[arg(default_value = "/")]
        path: String,
        /// Glob matched against the file name, e.g. '*.rs' or '.git'.
        #[arg(short, long)]
        name: Option<String>,
        /// f, d, or l.
        #[arg(short = 't', long = "type")]
        ty: Option<char>,
        #[arg(long)]
        max_depth: Option<usize>,
        /// Do not descend into other subvolumes (skips snapshots).
        #[arg(short = 'x', long)]
        one_subvolume: bool,
        /// Do not descend into snapshots; other subvolumes (like @home) are still searched.
        #[arg(long)]
        no_snapshots: bool,
    },
    /// Copy a file or a whole tree onto this machine.
    Cp {
        src: String,
        dest: PathBuf,
        /// Glob matched against the file name and the path relative to SRC. Repeatable.
        #[arg(short, long)]
        exclude: Vec<String>,
        /// Overwrite files that already exist.
        #[arg(short, long)]
        force: bool,
        /// Do not descend into other subvolumes (skips snapshots).
        #[arg(short = 'x', long)]
        one_subvolume: bool,
        /// Do not descend into snapshots; other subvolumes are still copied.
        #[arg(long)]
        no_snapshots: bool,
        /// Write JSON lines recording mode, owner, mtime, and symlink targets.
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
}

pub fn open_error(path: &str, e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        let how = if cfg!(windows) {
            "run from an elevated (Administrator) terminal"
        } else {
            "run as root, or add yourself to the `disk` group"
        };
        return anyhow::Error::new(AccessDenied).context(format!(
            "{path}: access denied; raw disks need privileges: {how}"
        ));
    }
    anyhow::Error::new(e).context(format!("opening {path}"))
}

/// Some entries could not be copied, so the copy is not a faithful one.
#[derive(Debug)]
struct Incomplete(u64);
impl std::fmt::Display for Incomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} entries could not be copied; the copy is incomplete",
            self.0
        )
    }
}
impl std::error::Error for Incomplete {}

#[derive(Debug)]
struct AccessDenied;
impl std::fmt::Display for AccessDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("access denied")
    }
}
impl std::error::Error for AccessDenied {}

pub fn uuid(b: &[u8; 16]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn iso_time(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Civil-from-days, Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (d, m) = (
        doy - (153 * mp + 2) / 5 + 1,
        if mp < 10 { mp + 3 } else { mp - 9 },
    );
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn mode_string(mode: u32) -> String {
    let kind = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o020000 => 'c',
        0o060000 => 'b',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '-',
    };
    let mut s = String::from(kind);
    for shift in [6, 3, 0] {
        let bits = mode >> shift & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}

fn join(dir: &str, name: &str) -> String {
    format!("{}/{name}", dir.trim_end_matches('/'))
}

fn describe(fs: &Fs, loc: Loc, path: &str, subvol: bool) -> Result<serde_json::Value> {
    let inode = fs.inode(loc)?;
    let mut v = json!({
        "path": path,
        "type": if subvol { "subvolume" } else { inode.type_name() },
        "mode": format!("{:o}", inode.mode & 0o7777),
        "uid": inode.uid,
        "gid": inode.gid,
        "size": inode.size,
        "nlink": inode.nlink,
        "mtime": iso_time(inode.mtime_sec),
        "inode": loc.ino,
        "subvolume_id": loc.tree,
    });
    if inode.is_symlink() {
        v["target"] = json!(String::from_utf8_lossy(&fs.read_symlink_target(loc)?));
    }
    Ok(v)
}

fn print_long(v: &serde_json::Value, name: &str) {
    let mode = u32::from_str_radix(v["mode"].as_str().unwrap_or("0"), 8).unwrap_or(0);
    let kind = match v["type"].as_str().unwrap_or("") {
        "dir" | "subvolume" => 0o040000,
        "symlink" => 0o120000,
        _ => 0o100000,
    };
    let target = v
        .get("target")
        .and_then(|t| t.as_str())
        .map(|t| format!(" -> {t}"))
        .unwrap_or_default();
    let tag = if v["type"] == "subvolume" {
        "  [subvolume]"
    } else {
        ""
    };
    let n = |k: &str| v[k].as_u64().unwrap_or(0);
    println!(
        "{} {:>5} {:>5} {:>12} {} {name}{target}{tag}",
        mode_string(mode | kind),
        n("uid"),
        n("gid"),
        n("size"),
        v["mtime"].as_str().unwrap_or("")
    );
}

/// Nesting past this is corruption, not a real tree; it also bounds the recursion.
const MAX_FIND_DEPTH: usize = 256;

fn find(
    fs: &Fs,
    dir: Loc,
    path: &str,
    depth: usize,
    q: &FindQuery,
    seen: &mut std::collections::HashSet<Loc>,
    out: &mut Vec<String>,
) -> Result<()> {
    if q.max_depth.is_some_and(|m| depth >= m) || depth >= MAX_FIND_DEPTH {
        return Ok(());
    }
    // A directory that contains one of its own ancestors would otherwise be
    // walked until the stack ran out.
    if !seen.insert(dir) {
        bail!("{path}: directory loops back to one of its own parents");
    }
    for e in fs.readdir(dir)? {
        let name = e.name_lossy();
        let child = join(path, &name);
        let is_dir = e.ftype == disk::FT_DIR;
        let kind = if is_dir {
            'd'
        } else if e.ftype == disk::FT_SYMLINK {
            'l'
        } else {
            'f'
        };
        if q.ty.is_none_or(|t| t == kind) && q.name.as_ref().is_none_or(|g| g.is_match(&name)) {
            if q.stream {
                println!("{child}");
            }
            out.push(child.clone());
        }
        let skip = e.subvol
            && !Fs::is_placeholder(e.loc)
            && (q.one_subvolume || q.no_snapshots && fs.is_snapshot(e.loc.tree)?);
        if is_dir && !skip {
            if let Err(err) = find(fs, e.loc, &child, depth + 1, q, seen, out) {
                eprintln!("btrfs-peek: {child}: {err:#}");
            }
        }
    }
    seen.remove(&dir);
    Ok(())
}

struct FindQuery {
    name: Option<globset::GlobMatcher>,
    ty: Option<char>,
    max_depth: Option<usize>,
    one_subvolume: bool,
    no_snapshots: bool,
    stream: bool,
}

fn run(cli: Cli) -> Result<()> {
    if let Cmd::Scan = cli.cmd {
        let r = scan::scan();
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&r)?);
        } else {
            for f in &r.filesystems {
                println!(
                    "{}  label={:?} uuid={} size={} used={} devices={}",
                    f.device, f.label, f.uuid, f.total_bytes, f.bytes_used, f.num_devices
                );
            }
            if r.filesystems.is_empty() {
                println!("no btrfs filesystems found");
            }
        }
        if !r.access_denied.is_empty() {
            eprintln!("btrfs-peek: {} devices could not be opened; rerun with admin/root privileges to scan them", r.access_denied.len());
            if r.filesystems.is_empty() {
                return Err(anyhow::Error::new(AccessDenied));
            }
        }
        return Ok(());
    }

    let fs = Fs::open(&cli.device)?;
    if fs.sb.csum_type != 0 {
        eprintln!(
            "btrfs-peek: warning: this filesystem uses {} checksums, which this tool cannot verify; corruption will not be detected",
            fs.sb.csum_name()
        );
    }
    if fs.sb.log_root != 0 {
        eprintln!("btrfs-peek: warning: the filesystem was not cleanly unmounted; writes fsynced just before the crash are not visible");
    }
    match cli.cmd {
        Cmd::Scan => unreachable!(),
        Cmd::Info => {
            let sb = &fs.sb;
            let features: Vec<_> = disk::INCOMPAT_FLAGS
                .iter()
                .filter(|(bit, _)| sb.incompat_flags & bit != 0)
                .map(|(_, n)| *n)
                .collect();
            let mut profiles: Vec<String> = fs
                .chunks()
                .map(|c| format!("{}:{}", c.kind(), c.profile()))
                .collect();
            profiles.sort();
            profiles.dedup();
            let v = json!({
                "devices": fs.device_paths(),
                "label": sb.label,
                "uuid": uuid(&sb.fsid),
                "generation": sb.generation,
                "total_bytes": sb.total_bytes,
                "bytes_used": sb.bytes_used,
                "num_devices": sb.num_devices,
                "sectorsize": sb.sectorsize,
                "nodesize": sb.nodesize,
                "checksum": sb.csum_name(),
                "metadata_checksums_verified": sb.csum_type == 0,
                "features": features,
                "profiles": profiles,
                "default_subvolume_id": fs.default_subvol()?,
                "clean_unmount": sb.log_root == 0,
            });
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                for (k, val) in v.as_object().unwrap() {
                    println!("{k:<28} {}", val.to_string().trim_matches('"'));
                }
            }
        }
        Cmd::Subvols => {
            let subvols = fs.subvols()?;
            let default = fs.default_subvol()?;
            if cli.json {
                let v: Vec<_> = subvols
                    .iter()
                    .map(|s| json!({"id": s.id, "parent": s.parent, "path": s.path, "readonly": s.readonly, "snapshot": s.snapshot, "generation": s.generation, "default": s.id == default}))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                for s in subvols {
                    let mut tags = Vec::new();
                    if s.snapshot {
                        tags.push("snapshot");
                    }
                    if s.readonly {
                        tags.push("readonly");
                    }
                    if s.id == default {
                        tags.push("default");
                    }
                    println!("{:>6}  {}  {}", s.id, s.path, tags.join(","));
                }
            }
        }
        Cmd::Ls { path, long } => {
            let loc = fs.resolve(&path)?;
            if !fs.inode(loc)?.is_dir() {
                let v = describe(&fs, loc, &path, false)?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&json!([v]))?);
                } else {
                    print_long(&v, &path);
                }
                return Ok(());
            }
            let mut rows = Vec::new();
            for e in fs.readdir(loc)? {
                let name = e.name_lossy();
                if long || cli.json {
                    let mut v = describe(&fs, e.loc, &join(&path, &name), e.subvol)?;
                    v["name"] = json!(name);
                    rows.push(v);
                } else {
                    let suffix = if e.ftype == disk::FT_DIR {
                        "/"
                    } else if e.ftype == disk::FT_SYMLINK {
                        "@"
                    } else {
                        ""
                    };
                    println!("{name}{suffix}");
                }
            }
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for v in &rows {
                    print_long(v, v["name"].as_str().unwrap_or(""));
                }
            }
        }
        Cmd::Stat { path } => {
            let loc = fs.resolve(&path)?;
            let mut v = describe(&fs, loc, &path, false)?;
            let extents = fs.extents(loc)?;
            let mut kinds: Vec<&str> = extents.iter().map(|e| e.compression_name()).collect();
            kinds.sort_unstable();
            kinds.dedup();
            v["extents"] = json!(extents.len());
            v["compression"] = json!(kinds);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                for (k, val) in v.as_object().unwrap() {
                    println!("{k:<14} {}", val.to_string().trim_matches('"'));
                }
            }
        }
        Cmd::Cat {
            path,
            offset,
            length,
        } => {
            let loc = fs.resolve(&path)?;
            let inode = fs.inode(loc)?;
            if inode.is_dir() {
                bail!("{path} is a directory");
            }
            let end = length.map_or(u64::MAX, |l| offset.saturating_add(l));
            let mut out = std::io::stdout().lock();
            let zeros = [0u8; 65536];
            fs.read_range(loc, offset, end, &mut |p| {
                match p {
                    Piece::Data(d) => out.write_all(d)?,
                    Piece::Zeros(mut n) => {
                        while n > 0 {
                            let k = n.min(zeros.len() as u64);
                            out.write_all(&zeros[..k as usize])?;
                            n -= k;
                        }
                    }
                }
                Ok(())
            })?;
            out.flush()?;
        }
        Cmd::Find {
            path,
            name,
            ty,
            max_depth,
            one_subvolume,
            no_snapshots,
        } => {
            if let Some(t) = ty {
                if !matches!(t, 'f' | 'd' | 'l') {
                    bail!("--type must be f, d, or l");
                }
            }
            let name = name
                .map(|n| globset::Glob::new(&n).map(|g| g.compile_matcher()))
                .transpose()
                .context("--name")?;
            let q = FindQuery {
                name,
                ty,
                max_depth,
                one_subvolume,
                no_snapshots,
                stream: !cli.json,
            };
            let mut out = Vec::new();
            let mut seen = std::collections::HashSet::new();
            find(&fs, fs.resolve(&path)?, &path, 0, &q, &mut seen, &mut out)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        }
        Cmd::Cp {
            src,
            dest,
            exclude,
            force,
            one_subvolume,
            no_snapshots,
            manifest,
        } => {
            let mut set = globset::GlobSetBuilder::new();
            for e in &exclude {
                set.add(globset::Glob::new(e).with_context(|| format!("--exclude {e}"))?);
            }
            let manifest = manifest
                .map(|p| {
                    std::fs::File::create(&p).with_context(|| format!("creating {}", p.display()))
                })
                .transpose()?;
            let loc = fs.resolve(&src)?;
            let mut c = copy::Copier::new(
                &fs,
                copy::Options {
                    exclude: set.build()?,
                    force,
                    one_subvolume,
                    no_snapshots,
                    manifest,
                },
            );
            c.copy(loc, &src, &dest)?;
            let r = c.report;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                for w in &r.warnings {
                    eprintln!("btrfs-peek: warning: {w}");
                }
                println!(
                    "copied {} files, {} dirs, {} symlinks, {} bytes; {} excluded, {} failed",
                    r.files, r.dirs, r.symlinks, r.bytes, r.excluded, r.failures
                );
            }
            // An incomplete copy must not look like a successful one to a script.
            if r.failures > 0 {
                return Err(anyhow::Error::new(Incomplete(r.failures)));
            }
        }
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        // A closed pipe (`| head`) is not a failure.
        if e.chain().any(|c| {
            c.downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
        }) {
            return;
        }
        eprintln!("btrfs-peek: {e:#}");
        let code = if e.chain().any(|c| c.is::<NotFound>()) {
            3
        } else if e.chain().any(|c| c.is::<AccessDenied>()) {
            4
        } else if e.chain().any(|c| c.is::<Incomplete>()) {
            5
        } else {
            1
        };
        std::process::exit(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_time_handles_epoch_leap_days_and_negatives() {
        assert_eq!(iso_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_time(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso_time(1_789_824_609), "2026-09-19T13:30:09Z");
        assert_eq!(iso_time(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn name_hash_matches_the_kernel() {
        // The root tree's `default` entry: `(ROOT_TREE_DIR DIR_ITEM 2378154706)` in any dump-tree.
        assert_eq!(disk::name_hash(b"default"), 2_378_154_706);
    }

    #[test]
    fn mode_string_renders_like_ls() {
        assert_eq!(mode_string(0o100755), "-rwxr-xr-x");
        assert_eq!(mode_string(0o040700), "drwx------");
        assert_eq!(mode_string(0o120777), "lrwxrwxrwx");
    }

    #[cfg(windows)]
    #[test]
    fn host_name_makes_linux_names_legal_on_windows() {
        assert_eq!(copy::host_name("a:b?.txt"), "a_b_.txt");
        assert_eq!(copy::host_name("trailing."), "trailing._");
        assert_eq!(copy::host_name("nul.txt"), "_nul.txt");
        assert_eq!(copy::host_name("COM1"), "_COM1");
        assert_eq!(copy::host_name("common.rs"), "common.rs");
    }
}
