//! Recursive copy out of the filesystem onto the host.
//!
//! Everything here treats the source filesystem as hostile. A directory entry
//! name is raw bytes chosen by whoever made the image, so it is sanitized into
//! a single path component before it is ever joined onto the destination, and
//! the result is checked to still be a direct child of where the user pointed.

use crate::disk::Inode;
use crate::fs::{Entry, Fs, Loc, Piece};
use anyhow::{bail, Context, Result};
use globset::GlobSet;
use serde::Serialize;
use std::collections::HashSet;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Directory nesting past this is corruption, not a real tree.
const MAX_DEPTH: usize = 256;

pub struct Options {
    pub exclude: GlobSet,
    pub force: bool,
    pub one_subvolume: bool,
    pub no_snapshots: bool,
    pub manifest: Option<std::fs::File>,
}

#[derive(Default, Serialize)]
pub struct Report {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub bytes: u64,
    pub excluded: u64,
    /// Entries that could not be copied. Non-zero means the copy is incomplete,
    /// and the process exits non-zero so a script never reads it as success.
    pub failures: u64,
    pub warnings: Vec<String>,
}

/// One line of the `--manifest` file: what the host filesystem cannot hold.
#[derive(Serialize)]
struct ManifestLine<'a> {
    path: &'a str,
    dest: &'a Path,
    #[serde(rename = "type")]
    ty: &'a str,
    mode: String,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
}

pub struct Copier<'a> {
    pub fs: &'a Fs,
    pub opts: Options,
    pub report: Report,
    /// Directories on the current recursion path, so a cycle cannot run forever.
    ancestors: HashSet<Loc>,
}

/// Turns a name from the filesystem into exactly one safe path component.
///
/// This runs on every platform. The traversal characters are not a Windows
/// representability problem: on Unix a name of `..` or `/etc/cron.d/evil` would
/// otherwise escape the destination entirely, because `Path::join` with an
/// absolute component throws the base away.
pub fn host_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            // A separator or a control byte is unusable as a single component
            // on any host; the rest are illegal only on Windows.
            let illegal = c == '/' || c == '\\' || c < ' ';
            let windows_illegal =
                cfg!(windows) && matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*');
            if illegal || windows_illegal {
                '_'
            } else {
                c
            }
        })
        .collect();
    // A run of only dots is navigation, not a name.
    if out.is_empty() || out.chars().all(|c| c == '.') {
        out.insert(0, '_');
    }
    if cfg!(windows) {
        if out.ends_with(['.', ' ']) {
            out.push('_');
        }
        let stem = out.split('.').next().unwrap_or("").to_ascii_uppercase();
        let reserved = matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
        if reserved {
            out.insert(0, '_');
        }
    }
    out
}

impl<'a> Copier<'a> {
    pub fn new(fs: &'a Fs, opts: Options) -> Copier<'a> {
        Copier {
            fs,
            opts,
            report: Report::default(),
            ancestors: HashSet::new(),
        }
    }

    pub fn copy(&mut self, src: Loc, src_path: &str, dest: &Path) -> Result<()> {
        let inode = self.fs.inode(src)?;
        if inode.is_dir() {
            self.copy_dir(src, src_path.trim_end_matches('/'), "", dest, 0)
        } else {
            let dest = if dest.is_dir() {
                dest.join(host_name(src_path.rsplit('/').next().unwrap_or("file")))
            } else {
                dest.to_path_buf()
            };
            self.copy_leaf(src, src_path, &dest)
        }
    }

    fn copy_dir(
        &mut self,
        dir: Loc,
        src_path: &str,
        rel: &str,
        dest: &Path,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            bail!("directory nesting deeper than {MAX_DEPTH}; the filesystem is corrupt");
        }
        // A directory that contains itself would otherwise recurse forever,
        // burying the destination in nested copies until the disk filled.
        if !self.ancestors.insert(dir) {
            bail!("directory loops back to one of its own parents; skipped");
        }
        let result = self.copy_dir_inner(dir, src_path, rel, dest, depth);
        self.ancestors.remove(&dir);
        result
    }

    fn copy_dir_inner(
        &mut self,
        dir: Loc,
        src_path: &str,
        rel: &str,
        dest: &Path,
        depth: usize,
    ) -> Result<()> {
        // Refuse to descend through a symlink already sitting in the destination:
        // create_dir_all would happily follow it out of the destination tree.
        if let Ok(meta) = dest.symlink_metadata() {
            if meta.file_type().is_symlink() {
                bail!(
                    "{} is a symlink; refusing to write through it",
                    dest.display()
                );
            }
        }
        std::fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
        self.report.dirs += 1;
        self.manifest(dir, src_path, dest, None)?;

        // The host may fold case or reject characters; keep every entry, renamed if it must be.
        let mut taken = HashSet::new();
        for entry in self.fs.readdir(dir)? {
            let name = entry.name_lossy();
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let child_src = format!("{src_path}/{name}");
            if self.opts.exclude.is_match(&child_rel) || self.opts.exclude.is_match(&name) {
                self.report.excluded += 1;
                continue;
            }
            let mut host = host_name(&name);
            let fold = |s: &str| {
                if cfg!(windows) {
                    s.to_lowercase()
                } else {
                    s.to_string()
                }
            };
            // Compare the raw bytes, not the lossy string: a name that is not
            // valid UTF-8 is also one the host is not receiving faithfully.
            let renamed = host.as_bytes() != entry.name.as_slice();
            if renamed || taken.contains(&fold(&host)) {
                let base = host.clone();
                let mut n = 1;
                while taken.contains(&fold(&host)) {
                    host = format!("{base}~{n}");
                    n += 1;
                }
                self.report.warnings.push(format!(
                    "{child_src}: written as {host:?} (the original name is not representable here)"
                ));
            }
            taken.insert(fold(&host));
            let child_dest = dest.join(&host);

            // Belt and braces: host_name should make this impossible, so if a
            // join still escaped, stop rather than write outside the destination.
            if child_dest.parent() != Some(dest) {
                self.report.failures += 1;
                self.report.warnings.push(format!(
                    "{child_src}: refusing to write outside {}",
                    dest.display()
                ));
                continue;
            }

            if let Err(e) = self.copy_entry(&entry, dir, &child_src, &child_rel, &child_dest, depth)
            {
                // One unreadable file must not cost the rest of the tree.
                self.report.failures += 1;
                self.report.warnings.push(format!("{child_src}: {e:#}"));
            }
        }
        self.set_mtime(dir, dest);
        Ok(())
    }

    fn copy_entry(
        &mut self,
        entry: &Entry,
        parent: Loc,
        src: &str,
        rel: &str,
        dest: &Path,
        depth: usize,
    ) -> Result<()> {
        let skip = entry.subvol
            && !Fs::is_placeholder(entry.loc)
            && (self.opts.one_subvolume && entry.loc.tree != parent.tree
                || self.opts.no_snapshots && self.fs.is_snapshot(entry.loc.tree)?);
        if skip {
            self.report.excluded += 1;
            return Ok(());
        }
        if self.fs.inode(entry.loc)?.is_dir() {
            self.copy_dir(entry.loc, src, rel, dest, depth + 1)
        } else {
            self.copy_leaf(entry.loc, src, dest)
        }
    }

    fn copy_leaf(&mut self, loc: Loc, src: &str, dest: &Path) -> Result<()> {
        let inode = self.fs.inode(loc)?;
        if dest.symlink_metadata().is_ok() {
            if !self.opts.force {
                bail!(
                    "{} already exists (use --force to overwrite)",
                    dest.display()
                );
            }
            std::fs::remove_file(dest).with_context(|| format!("replacing {}", dest.display()))?;
        }
        if inode.is_symlink() {
            let target = String::from_utf8_lossy(&self.fs.read_symlink_target(loc)?).into_owned();
            self.manifest(loc, src, dest, Some(target.clone()))?;
            if let Err(e) = self.symlink(&target, dest, src) {
                self.report.warnings.push(format!(
                    "{src}: symlink to {target:?} not created ({e}); it is recorded in the manifest"
                ));
                return Ok(());
            }
            self.report.symlinks += 1;
            return Ok(());
        }
        if !inode.is_file() {
            self.report
                .warnings
                .push(format!("{src}: skipped {}", inode.type_name()));
            return Ok(());
        }

        // Write to a sibling temp name and rename into place, so a read error
        // partway through never leaves a short file that looks complete.
        let tmp = dest.with_file_name(format!(
            "{}.btrfs-peek-partial",
            dest.file_name().unwrap_or_default().to_string_lossy()
        ));
        if let Err(e) = self.write_file(loc, &inode, &tmp) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        std::fs::rename(&tmp, dest)
            .with_context(|| format!("moving the finished file into {}", dest.display()))?;
        self.set_mtime(loc, dest);
        self.report.files += 1;
        self.report.bytes += inode.size;
        self.manifest(loc, src, dest, None)
    }

    fn write_file(&self, loc: Loc, inode: &Inode, tmp: &Path) -> Result<()> {
        let mut file =
            std::fs::File::create(tmp).with_context(|| format!("creating {}", tmp.display()))?;
        self.fs.read_range(loc, 0, u64::MAX, &mut |piece| {
            match piece {
                Piece::Data(d) => file.write_all(d)?,
                // Seek past a hole so the destination stays sparse, in steps
                // because the seek offset is signed and a hole need not be.
                Piece::Zeros(n) => {
                    let mut left = n;
                    while left > 0 {
                        let step = left.min(i64::MAX as u64);
                        file.seek(SeekFrom::Current(step as i64))?;
                        left -= step;
                    }
                }
            }
            Ok(())
        })?;
        file.set_len(inode.size)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(inode.mode & 0o7777))?;
        }
        // An error here means bytes never reached the disk; it must not be dropped.
        file.sync_all()
            .with_context(|| format!("flushing {}", tmp.display()))?;
        Ok(())
    }

    fn set_mtime(&self, loc: Loc, dest: &Path) {
        if let Ok(inode) = self.fs.inode(loc) {
            let t = filetime::FileTime::from_unix_time(inode.mtime_sec, inode.mtime_nsec);
            let _ = filetime::set_file_mtime(dest, t);
        }
    }

    fn manifest(&mut self, loc: Loc, src: &str, dest: &Path, target: Option<String>) -> Result<()> {
        let Some(out) = self.opts.manifest.as_mut() else {
            return Ok(());
        };
        let inode = self.fs.inode(loc)?;
        let line = ManifestLine {
            path: src,
            dest,
            ty: inode.type_name(),
            mode: format!("{:o}", inode.mode & 0o7777),
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            mtime: inode.mtime_sec,
            target,
        };
        serde_json::to_writer(&mut *out, &line)?;
        out.write_all(b"\n")?;
        Ok(())
    }

    #[cfg(unix)]
    fn symlink(&self, target: &str, dest: &Path, _src: &str) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, dest)
    }

    /// Windows needs the target's kind up front, and a privilege most users lack.
    /// The kind comes from the *source* filesystem: asking the host would consult
    /// whatever happens to sit at that path on this machine, which is unrelated.
    #[cfg(windows)]
    fn symlink(&self, target: &str, dest: &Path, src: &str) -> std::io::Result<()> {
        let src_dir = src.rsplit_once('/').map_or("/", |(d, _)| d);
        let resolved = if target.starts_with('/') {
            target.to_string()
        } else {
            format!("{src_dir}/{target}")
        };
        let is_dir = self
            .fs
            .resolve(&resolved)
            .ok()
            .and_then(|loc| self.fs.inode(loc).ok())
            .is_some_and(|i| i.is_dir());
        let win_target = target.replace('/', "\\");
        if is_dir {
            std::os::windows::fs::symlink_dir(&win_target, dest)
        } else {
            std::os::windows::fs::symlink_file(&win_target, dest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::host_name;
    use std::path::Path;

    /// The traversal cases: these are what let a crafted image escape.
    #[test]
    fn traversal_names_become_one_harmless_component() {
        for bad in [
            "..",
            ".",
            "/etc/passwd",
            "../../root",
            "a/b",
            "a\\b",
            "",
            "...",
        ] {
            let got = host_name(bad);
            assert!(!got.contains('/'), "{bad:?} -> {got:?} kept a slash");
            assert!(!got.contains('\\'), "{bad:?} -> {got:?} kept a backslash");
            assert!(
                got != "." && got != "..",
                "{bad:?} -> {got:?} is navigation"
            );
            let joined = Path::new("/base/out").join(&got);
            assert_eq!(
                joined.parent(),
                Some(Path::new("/base/out")),
                "{bad:?} -> {got:?} escaped the destination"
            );
        }
    }

    #[test]
    fn ordinary_names_are_untouched() {
        for ok in [
            "common.rs",
            "file.tar.gz",
            "ünïcödé",
            ".gitignore",
            "..hidden",
        ] {
            assert_eq!(host_name(ok), ok);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_only_rules_still_apply() {
        assert_eq!(host_name("a:b?.txt"), "a_b_.txt");
        assert_eq!(host_name("trailing."), "trailing._");
        assert_eq!(host_name("nul.txt"), "_nul.txt");
        assert_eq!(host_name("COM1"), "_COM1");
        assert_eq!(host_name("CONIN$"), "_CONIN$");
    }
}
