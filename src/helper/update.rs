//! What the helper service accepts as an update of itself.
//!
//! Releases are signed in CI with a minisign key that never leaves GitHub
//! Actions, so nothing on this machine can make the SYSTEM service run its
//! code. A build is accepted only if its signature verifies against the key
//! embedded here, its trusted comment names exactly this program and target,
//! and its version is newer than the one running. This part is pure, so every
//! OS tests it; fetching and swapping are in `windows/updater.rs`.

use minisign_verify::{PublicKey, Signature};
use std::fmt;
use std::io;

/// The release key's public half, as `rsign generate` wrote it.
const RELEASE_KEY_FILE: &str = include_str!("../../update-key.pub");

/// The only target the service updates to.
pub const TARGET: &str = "windows-x86_64";

/// The release key in base64: the key file's last non-empty line.
pub fn release_key() -> &'static str {
    RELEASE_KEY_FILE
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

impl Version {
    /// `X.Y.Z`, decimal, nothing else: no `v`, no pre-release, no leading
    /// zeros, so one version has one spelling in a trusted comment.
    pub fn parse(s: &str) -> Option<Version> {
        let mut parts = s.split('.');
        let mut next = || -> Option<u64> {
            let p = parts.next()?;
            let canonical = !p.is_empty()
                && p.len() <= 19
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p == "0" || !p.starts_with('0'));
            canonical.then(|| p.parse().ok()).flatten()
        };
        let v = Version {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        parts.next().is_none().then_some(v)
    }

    /// This build's version.
    pub fn running() -> Version {
        Version::parse(super::VERSION).expect("Cargo.toml's version is X.Y.Z")
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// What a check for an update did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Update {
    /// Nothing newer is signed; the version running.
    UpToDate(Version),
    /// This version is in place and runs once the service restarts.
    Installed(Version),
}

/// The text the service replies with and records; the client reads the
/// installed version back out of it (`installed_version`).
impl fmt::Display for Update {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Update::UpToDate(v) => write!(f, "up to date ({v})"),
            Update::Installed(v) => write!(f, "{UPDATED_TO}{v}; restarting when idle"),
        }
    }
}

const UPDATED_TO: &str = "updated to ";

/// The version an `Update::Installed` reply names; None for any other reply.
pub fn installed_version(reply: &str) -> Option<Version> {
    let (v, _) = reply.strip_prefix(UPDATED_TO)?.split_once(';')?;
    Version::parse(v)
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// The version a trusted comment names, if it is exactly
/// `btrfs-peek X.Y.Z windows-x86_64`.
fn comment_version(comment: &str) -> Option<Version> {
    let (v, target) = comment.strip_prefix("btrfs-peek ")?.split_once(' ')?;
    if target != TARGET {
        return None;
    }
    Version::parse(v)
}

fn decode(sig: &str) -> io::Result<Signature> {
    Signature::decode(sig).map_err(|e| invalid(format!("the update's signature is malformed: {e}")))
}

/// The version a signature's trusted comment announces, before the exe is
/// fetched, so an up-to-date check downloads only the signature. Not yet
/// trusted: `verify_update` checks it again against the exe.
pub fn announced(sig: &str) -> io::Result<Version> {
    let sig = decode(sig)?;
    comment_version(sig.trusted_comment()).ok_or_else(|| wrong_comment(&sig))
}

fn wrong_comment(sig: &Signature) -> io::Error {
    invalid(format!(
        "the update is signed as {:?}, not as `btrfs-peek X.Y.Z {TARGET}`",
        sig.trusted_comment()
    ))
}

/// Checks that `exe` is a signed release of this program for this target,
/// newer than `running`; its version.
pub fn verify_update(
    public_key_b64: &str,
    exe: &[u8],
    sig: &str,
    running: Version,
) -> io::Result<Version> {
    let key = PublicKey::from_base64(public_key_b64)
        .map_err(|e| invalid(format!("the release key is malformed: {e}")))?;
    let sig = decode(sig)?;
    // Covers the trusted comment too: the global signature signs it.
    key.verify(exe, &sig, false)
        .map_err(|e| invalid(format!("the update's signature does not verify: {e}")))?;
    let v = comment_version(sig.trusted_comment()).ok_or_else(|| wrong_comment(&sig))?;
    // Strictly newer: neither the same build again nor an older signed one
    // with a bug since fixed.
    if v <= running {
        return Err(invalid(format!(
            "the signed release {v} is not newer than the running {running}"
        )));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/update/");

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}{name}")).unwrap()
    }

    fn test_key() -> String {
        let pub_file = fixture("test-key.pub");
        pub_file.lines().last().unwrap().trim().to_string()
    }

    fn payload() -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}payload.bin")).unwrap()
    }

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn verify(sig: &str, exe: &[u8], running: &str) -> io::Result<Version> {
        verify_update(&test_key(), exe, sig, v(running))
    }

    #[test]
    fn versions_parse_only_in_canonical_form() {
        assert_eq!(v("0.3.0").to_string(), "0.3.0");
        assert_eq!(v("10.20.30").to_string(), "10.20.30");
        for bad in [
            "",
            "0.3",
            "0.3.0.1",
            "v0.3.0",
            "0.3.0-rc1",
            "0.03.0",
            "0..0",
            " 0.3.0",
            "0.3.0 ",
            "+1.0.0",
            "-1.0.0",
            "1.0.x",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad:?} parsed");
        }
        assert_eq!(Version::parse(&format!("{}.0.0", "9".repeat(25))), None);
    }

    #[test]
    fn versions_order_numerically() {
        assert!(v("0.3.0") < v("0.3.1"));
        assert!(v("0.3.9") < v("0.10.0"));
        assert!(v("0.99.99") < v("1.0.0"));
        assert!(v("1.2.3") == v("1.2.3"));
    }

    #[test]
    fn the_running_version_parses() {
        assert_eq!(Version::running().to_string(), super::super::VERSION);
    }

    #[test]
    fn the_embedded_release_key_parses() {
        assert_eq!(
            release_key(),
            "RWQ5rvRzRSb/Zgq2f/7NOM1j81uGcUPUoNSNxl1HUnqWFafv1xuhkRV5"
        );
        PublicKey::from_base64(release_key()).unwrap();
    }

    #[test]
    fn a_newer_signed_release_passes() {
        let sig = fixture("signed-0.4.0.minisig");
        assert_eq!(verify(&sig, &payload(), "0.3.0").unwrap(), v("0.4.0"));
        assert_eq!(verify(&sig, &payload(), "0.3.99").unwrap(), v("0.4.0"));
        assert_eq!(announced(&sig).unwrap(), v("0.4.0"));
    }

    #[test]
    fn the_same_or_an_older_release_fails() {
        let sig = fixture("signed-0.4.0.minisig");
        for running in ["0.4.0", "0.4.1", "1.0.0"] {
            let e = verify(&sig, &payload(), running).unwrap_err();
            assert!(e.to_string().contains("not newer"), "{running}: {e}");
        }
    }

    #[test]
    fn a_tampered_payload_fails() {
        let sig = fixture("signed-0.4.0.minisig");
        let mut exe = payload();
        exe[300] ^= 1;
        let e = verify(&sig, &exe, "0.3.0").unwrap_err();
        assert!(e.to_string().contains("does not verify"), "{e}");
        exe.truncate(10);
        assert!(verify(&sig, &exe, "0.3.0").is_err());
    }

    /// The trusted comment is covered by the signature: raising the version
    /// in it breaks the signature.
    #[test]
    fn a_tampered_comment_fails() {
        let sig = fixture("signed-0.4.0.minisig").replace("0.4.0", "9.9.9");
        assert_eq!(announced(&sig).unwrap(), v("9.9.9"));
        let e = verify(&sig, &payload(), "0.3.0").unwrap_err();
        assert!(e.to_string().contains("does not verify"), "{e}");
    }

    #[test]
    fn a_signature_from_another_key_fails() {
        let sig = fixture("other-key.minisig");
        let e = verify(&sig, &payload(), "0.3.0").unwrap_err();
        assert!(e.to_string().contains("does not verify"), "{e}");
        // Nor does the release key accept a test signature.
        let sig = fixture("signed-0.4.0.minisig");
        assert!(verify_update(release_key(), &payload(), &sig, v("0.3.0")).is_err());
    }

    #[test]
    fn another_target_fails() {
        let sig = fixture("linux.minisig");
        let e = verify(&sig, &payload(), "0.3.0").unwrap_err();
        assert!(e.to_string().contains("linux-x86_64"), "{e}");
        assert!(announced(&sig).is_err());
    }

    #[test]
    fn a_malformed_comment_fails() {
        for name in ["malformed-short", "malformed-v", "malformed-extra"] {
            let sig = fixture(&format!("{name}.minisig"));
            let e = verify(&sig, &payload(), "0.3.0").unwrap_err();
            assert!(e.to_string().contains("signed as"), "{name}: {e}");
            assert!(announced(&sig).is_err(), "{name}");
        }
    }

    #[test]
    fn a_malformed_signature_fails() {
        for sig in ["", "not a signature", "untrusted comment: x\nRWQ\n"] {
            assert!(verify(sig, &payload(), "0.3.0").is_err());
            assert!(announced(sig).is_err());
        }
    }

    #[test]
    fn replies_round_trip() {
        let up = Update::UpToDate(v("0.3.0")).to_string();
        assert_eq!(up, "up to date (0.3.0)");
        assert_eq!(installed_version(&up), None);
        let done = Update::Installed(v("0.4.0")).to_string();
        assert_eq!(done, "updated to 0.4.0; restarting when idle");
        assert_eq!(installed_version(&done), Some(v("0.4.0")));
    }
}
