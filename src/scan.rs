//! Find btrfs filesystems on the machine's block devices.

use crate::dev::Device;
use crate::disk::{Superblock, SUPER_OFFSET, SUPER_SIZE};
use serde::Serialize;
use std::io::ErrorKind;

#[derive(Serialize)]
pub struct Found {
    pub device: String,
    pub label: String,
    pub uuid: String,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub num_devices: u64,
}

#[derive(Default, Serialize)]
pub struct ScanResult {
    pub filesystems: Vec<Found>,
    /// Devices that exist but could not be opened; on Windows this means "run elevated".
    pub access_denied: Vec<String>,
}

fn candidates() -> Vec<String> {
    if cfg!(windows) {
        // Partition 0 is the whole disk, which covers a filesystem made without a partition table.
        return (0..32)
            .flat_map(|d| (0..=64).map(move |p| format!(r"\\.\Harddisk{d}Partition{p}")))
            .collect();
    }
    let Ok(text) = std::fs::read_to_string("/proc/partitions") else {
        return Vec::new();
    };
    text.lines()
        .skip(2)
        .filter_map(|l| l.split_whitespace().nth(3))
        .map(|n| format!("/dev/{n}"))
        .collect()
}

pub fn scan() -> ScanResult {
    let mut out = ScanResult::default();
    for path in candidates() {
        let dev = match Device::open(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                out.access_denied.push(path);
                continue;
            }
            Err(_) => continue,
        };
        let Ok(raw) = dev.read(SUPER_OFFSET, SUPER_SIZE) else {
            continue;
        };
        let Ok(sb) = Superblock::parse(&raw) else {
            continue;
        };
        out.filesystems.push(Found {
            device: path,
            label: sb.label.clone(),
            uuid: crate::uuid(&sb.fsid),
            total_bytes: sb.total_bytes,
            bytes_used: sb.bytes_used,
            num_devices: sb.num_devices,
        });
    }
    out
}
