//! The service updates itself: it fetches the latest release with Windows'
//! own curl, accepts it only as `update::verify_update` says, swaps it in for
//! the exe it runs, and exits once no client is reading so that the service
//! manager's failure actions start it again on the new exe.

use super::super::update::{announced, release_key, verify_update, Update, Version};
use super::install_dir;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

/// Fixed, like everything else the service trusts: nothing configures it.
const RELEASES: &str = "https://github.com/noahsabaj/btrfs-peek/releases/latest/download/";
const ASSET: &str = "btrfs-peek-windows-x86_64.exe";
/// A minisign signature is about 300 bytes.
const MAX_SIG: u64 = 16 << 10;
/// The release exe is a few MB.
const MAX_EXE: u64 = 64 << 20;

const EXE: &str = "btrfs-peek.exe";
const NEW: &str = "btrfs-peek.exe.new";
const OLD: &str = "btrfs-peek.exe.old";
pub const STATUS_FILE: &str = "update-status.txt";

/// Late enough not to slow a boot; then daily.
const FIRST_CHECK: Duration = Duration::from_secs(10 * 60);
const EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// How often, and at most how long, a restart waits for clients to finish.
const IDLE_POLL: Duration = Duration::from_secs(2);
const IDLE_LIMIT: Duration = Duration::from_secs(60 * 60);

/// Client sessions in progress; a restart waits for none.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// Counts a client session while it lives.
pub struct Busy(());

impl Busy {
    pub fn enter() -> Busy {
        ACTIVE.fetch_add(1, Ordering::SeqCst);
        Busy(())
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The version swapped in and waiting for the restart. Also the lock that
/// keeps two checks (the daily one and a client's) from swapping at once.
static INSTALLED: Mutex<Option<Version>> = Mutex::new(None);

/// What the service runs at start: an update leaves the old exe behind, and a
/// check that failed midway may leave a new one. Best effort: the old one is
/// still locked if this somehow is not the new image.
pub fn clean_up() {
    let dir = install_dir();
    let _ = fs::remove_file(dir.join(OLD));
    let _ = fs::remove_file(dir.join(NEW));
}

/// Checks 10 minutes after start, then daily, recording each result; restarts
/// onto an update it installed. Errors are only recorded.
pub fn spawn_checks() {
    std::thread::spawn(|| {
        let mut wait = FIRST_CHECK;
        loop {
            std::thread::sleep(wait);
            wait = EVERY;
            if let Ok(Update::Installed(_)) = check_and_record() {
                restart_when_idle();
            }
        }
    });
}

/// One check, recorded in the status file: what UPDATE runs.
pub fn check_and_record() -> io::Result<Update> {
    let r = check_for_update();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    // The folder is the service's; a failure to write here changes nothing else.
    let _ = fs::write(install_dir().join(STATUS_FILE), status_text(now, &r));
    r
}

fn status_text(now: i64, r: &io::Result<Update>) -> String {
    let mut text = format!("checked: {}\n", crate::iso_time(now));
    match r {
        Ok(u) => text += &format!("outcome: {u}\n"),
        Err(e) => {
            // One line per field: curl's errors can span several.
            let e = e
                .to_string()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            text += &format!("outcome: failed\nerror: {e}\n");
        }
    }
    text
}

/// Steps 1-4: fetch the signature, and if it announces a newer release, the
/// exe; verify exactly those bytes; swap them in. The restart is the caller's.
pub fn check_for_update() -> io::Result<Update> {
    let mut installed = INSTALLED.lock().unwrap_or_else(|e| e.into_inner());
    // One update per run: a second swap would have to delete the running image.
    if let Some(v) = *installed {
        return Ok(Update::Installed(v));
    }
    let running = Version::running();
    let sig = fetch(&format!("{RELEASES}{ASSET}.minisig"), 120, MAX_SIG)?;
    let sig = String::from_utf8(sig)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the signature is not UTF-8"))?;
    if announced(&sig)? <= running {
        return Ok(Update::UpToDate(running));
    }
    let exe = fetch(&format!("{RELEASES}{ASSET}"), 900, MAX_EXE)?;
    let v = verify_update(release_key(), &exe, &sig, running)?;
    install(&install_dir(), &exe)?;
    *installed = Some(v);
    Ok(Update::Installed(v))
}

/// curl.exe from the system directory, never from PATH: PATH is the user's to change.
fn curl() -> io::Result<PathBuf> {
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buf[..n])).join("curl.exe"))
}

/// The body at `url`, at most `max_size` bytes, in memory.
fn fetch(url: &str, max_time: u32, max_size: u64) -> io::Result<Vec<u8>> {
    let curl = curl()?;
    let out = Command::new(&curl)
        // -q first: no .curlrc. HTTPS only, redirects included (the release
        // assets redirect to GitHub's object store).
        .args([
            "-q",
            "-fsSL",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
        ])
        .args(["--tlsv1.2", "--max-time", &max_time.to_string()])
        .args(["--max-filesize", &max_size.to_string(), url])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("running {}: {e}", curl.display())))?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::other(format!(
            "fetching {url} failed ({}): {}",
            out.status,
            why.trim()
        )));
    }
    // --max-filesize cannot stop a body whose size is not announced up front.
    if out.stdout.len() as u64 > max_size {
        return Err(io::Error::other(format!(
            "{url} is larger than {max_size} bytes"
        )));
    }
    Ok(out.stdout)
}

/// Writes the verified bytes themselves (never a re-read file, which could
/// have changed since) next to the exe, then swaps them in.
fn install(dir: &Path, exe: &[u8]) -> io::Result<()> {
    let new = dir.join(NEW);
    let mut f = File::create(&new)?;
    f.write_all(exe)?;
    f.sync_all()?;
    drop(f);
    swap(&dir.join(EXE), &new, &dir.join(OLD))
}

/// `new` becomes `exe`, and `exe` becomes `old`. Windows lets a running image
/// be renamed but not deleted or overwritten, hence the detour through `old`.
/// If `new` cannot take its place, `exe` goes back.
fn swap(exe: &Path, new: &Path, old: &Path) -> io::Result<()> {
    match fs::remove_file(old) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    fs::rename(exe, old)?;
    if let Err(e) = fs::rename(new, exe) {
        let _ = fs::rename(old, exe);
        return Err(e);
    }
    Ok(())
}

/// Ends the process once no client session is active (or after an hour),
/// without reporting SERVICE_STOPPED: the service manager counts that as a
/// failure, and its failure actions (set at install) start the service again,
/// now on the new exe. Only the first caller waits; the others return.
pub fn restart_when_idle() {
    static WAITING: AtomicBool = AtomicBool::new(false);
    if WAITING.swap(true, Ordering::SeqCst) {
        return;
    }
    let deadline = Instant::now() + IDLE_LIMIT;
    while ACTIVE.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
        std::thread::sleep(IDLE_POLL);
    }
    std::process::exit(1);
}

/// The status file's `key: value` lines, for `helper status --json`.
pub fn parse_status(text: &str) -> serde_json::Map<String, serde_json::Value> {
    text.lines()
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_string(), serde_json::Value::from(v)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("btrfs-peek-updater-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn curl_is_the_systems() {
        let c = curl().unwrap();
        assert!(c.is_absolute(), "{}", c.display());
        let lower = c.to_string_lossy().to_ascii_lowercase();
        assert!(lower.ends_with(r"\system32\curl.exe"), "{}", c.display());
        assert!(c.exists(), "{}", c.display());
    }

    /// The swap works on a running image, which is the one case that matters:
    /// the service swaps the exe it is running.
    #[test]
    fn the_swap_renames_a_running_exe_aside() {
        let dir = temp_dir("running");
        let exe = dir.join(EXE);
        fs::copy(curl().unwrap().with_file_name("ping.exe"), &exe).unwrap();
        let mut child = Command::new(&exe)
            .args(["-n", "30", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        fs::write(dir.join(OLD), b"an older leftover").unwrap();
        install(&dir, b"the new build").unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"the new build");
        assert!(!dir.join(NEW).exists());
        // The old image is still running, under its new name, so it cannot be deleted yet.
        assert!(fs::remove_file(dir.join(OLD)).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
        // What `clean_up` does once the new service runs.
        super::super::retry(|| fs::remove_file(dir.join(OLD))).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_swap_puts_the_exe_back() {
        let dir = temp_dir("failed");
        let (exe, new, old) = (dir.join(EXE), dir.join(NEW), dir.join(OLD));
        fs::write(&exe, b"current").unwrap();
        // No `new`: the second rename fails.
        assert!(swap(&exe, &new, &old).is_err());
        assert_eq!(fs::read(&exe).unwrap(), b"current");
        assert!(!old.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn status_text_records_time_outcome_and_error() {
        let v = Version::parse("0.4.0").unwrap();
        let t = status_text(0, &Ok(Update::Installed(v)));
        assert_eq!(
            t,
            "checked: 1970-01-01T00:00:00Z\noutcome: updated to 0.4.0; restarting when idle\n"
        );
        let t = status_text(0, &Err(io::Error::other("curl: (6)\n  no host")));
        assert_eq!(
            t,
            "checked: 1970-01-01T00:00:00Z\noutcome: failed\nerror: curl: (6) no host\n"
        );
        let m = parse_status(&t);
        assert_eq!(m["checked"], "1970-01-01T00:00:00Z");
        assert_eq!(m["error"], "curl: (6) no host");
    }
}
