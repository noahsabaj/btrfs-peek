//! On-disk btrfs structures. Everything is little-endian and parsed by offset,
//! with bounds checks: a corrupt filesystem must produce an error, never a panic.

use anyhow::{bail, Result};

pub const SUPER_OFFSET: u64 = 0x1_0000;
pub const SUPER_SIZE: usize = 4096;
pub const MAGIC: &[u8; 8] = b"_BHRfS_M";
pub const HEADER_SIZE: usize = 101;
pub const KEY_SIZE: usize = 17;
pub const INODE_ITEM_SIZE: usize = 160;

pub const FS_TREE_OBJECTID: u64 = 5;
pub const FIRST_FREE_OBJECTID: u64 = 256;
pub const LAST_FREE_OBJECTID: u64 = u64::MAX - 256;

pub const INODE_ITEM_KEY: u8 = 1;
pub const INODE_REF_KEY: u8 = 12;
pub const DIR_ITEM_KEY: u8 = 84;
pub const DIR_INDEX_KEY: u8 = 96;
pub const EXTENT_DATA_KEY: u8 = 108;
pub const ROOT_ITEM_KEY: u8 = 132;
pub const ROOT_BACKREF_KEY: u8 = 144;
pub const ROOT_REF_KEY: u8 = 156;
pub const CHUNK_ITEM_KEY: u8 = 228;

pub const FT_DIR: u8 = 2;
pub const FT_SYMLINK: u8 = 7;

pub const BLOCK_GROUP_RAID0: u64 = 1 << 3;
pub const BLOCK_GROUP_RAID10: u64 = 1 << 6;
pub const BLOCK_GROUP_RAID5: u64 = 1 << 7;
pub const BLOCK_GROUP_RAID6: u64 = 1 << 8;

pub const INCOMPAT_FLAGS: &[(u64, &str)] = &[
    (1 << 0, "mixed-backref"),
    (1 << 1, "default-subvol"),
    (1 << 2, "mixed-groups"),
    (1 << 3, "compress-lzo"),
    (1 << 4, "compress-zstd"),
    (1 << 5, "big-metadata"),
    (1 << 6, "extended-iref"),
    (1 << 7, "raid56"),
    (1 << 8, "skinny-metadata"),
    (1 << 9, "no-holes"),
    (1 << 10, "metadata-uuid"),
    (1 << 11, "raid1c34"),
    (1 << 12, "zoned"),
    (1 << 13, "extent-tree-v2"),
    (1 << 14, "raid-stripe-tree"),
    (1 << 16, "simple-quota"),
];
/// Features that change how file data is located; reading without understanding
/// them would return wrong bytes, so they are refused.
pub const INCOMPAT_REFUSED: u64 = (1 << 13) | (1 << 14);

pub fn bytes(b: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    match off.checked_add(len).and_then(|end| b.get(off..end)) {
        Some(s) => Ok(s),
        None => bail!(
            "corrupt structure: wanted {len} bytes at offset {off}, have {}",
            b.len()
        ),
    }
}
pub fn u8_at(b: &[u8], off: usize) -> Result<u8> {
    Ok(bytes(b, off, 1)?[0])
}
pub fn u16_at(b: &[u8], off: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(bytes(b, off, 2)?.try_into().unwrap()))
}
pub fn u32_at(b: &[u8], off: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(b, off, 4)?.try_into().unwrap()))
}
pub fn u64_at(b: &[u8], off: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes(b, off, 8)?.try_into().unwrap()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub objectid: u64,
    pub ty: u8,
    pub offset: u64,
}

impl Key {
    pub fn new(objectid: u64, ty: u8, offset: u64) -> Self {
        Key {
            objectid,
            ty,
            offset,
        }
    }
    pub fn parse(b: &[u8], off: usize) -> Result<Key> {
        Ok(Key {
            objectid: u64_at(b, off)?,
            ty: u8_at(b, off + 8)?,
            offset: u64_at(b, off + 9)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Superblock {
    pub fsid: [u8; 16],
    pub generation: u64,
    pub root: u64,
    pub chunk_root: u64,
    pub log_root: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub incompat_flags: u64,
    pub csum_type: u16,
    pub devid: u64,
    pub label: String,
    pub sys_chunk_array: Vec<u8>,
}

impl Superblock {
    pub fn parse(b: &[u8]) -> Result<Superblock> {
        if bytes(b, 0x40, 8)? != MAGIC {
            bail!("no btrfs magic");
        }
        let csum_type = u16_at(b, 0xc4)?;
        if csum_type == 0 {
            let want = u32_at(b, 0)?;
            let got = crc32c::crc32c(bytes(b, 32, SUPER_SIZE - 32)?);
            if want != got {
                bail!("superblock checksum mismatch");
            }
        }
        let sys_len = u32_at(b, 0xa0)? as usize;
        if sys_len > 2048 {
            bail!("corrupt superblock: sys_chunk_array_size {sys_len}");
        }
        let label_raw = bytes(b, 0x12b, 256)?;
        let label_end = label_raw.iter().position(|&c| c == 0).unwrap_or(256);
        let sb = Superblock {
            fsid: bytes(b, 0x20, 16)?.try_into().unwrap(),
            generation: u64_at(b, 0x48)?,
            root: u64_at(b, 0x50)?,
            chunk_root: u64_at(b, 0x58)?,
            log_root: u64_at(b, 0x60)?,
            total_bytes: u64_at(b, 0x70)?,
            bytes_used: u64_at(b, 0x78)?,
            root_dir_objectid: u64_at(b, 0x80)?,
            num_devices: u64_at(b, 0x88)?,
            sectorsize: u32_at(b, 0x90)?,
            nodesize: u32_at(b, 0x94)?,
            incompat_flags: u64_at(b, 0xbc)?,
            csum_type,
            devid: u64_at(b, 0xc9)?,
            label: String::from_utf8_lossy(&label_raw[..label_end]).into_owned(),
            sys_chunk_array: bytes(b, 0x32b, sys_len)?.to_vec(),
        };
        if !sb.sectorsize.is_power_of_two() || !(512..=65536).contains(&sb.sectorsize) {
            bail!("corrupt superblock: sectorsize {}", sb.sectorsize);
        }
        if !sb.nodesize.is_power_of_two() || !(4096..=65536).contains(&sb.nodesize) {
            bail!("corrupt superblock: nodesize {}", sb.nodesize);
        }
        Ok(sb)
    }

    pub fn csum_name(&self) -> &'static str {
        match self.csum_type {
            0 => "crc32c",
            1 => "xxhash64",
            2 => "sha256",
            3 => "blake2b",
            _ => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Chunk {
    pub start: u64,
    pub length: u64,
    pub ty: u64,
    /// (devid, physical offset)
    pub stripes: Vec<(u64, u64)>,
}

impl Chunk {
    /// Parses a chunk item; returns it with the number of bytes it occupied.
    pub fn parse(start: u64, b: &[u8]) -> Result<(Chunk, usize)> {
        let num_stripes = u16_at(b, 44)? as usize;
        if num_stripes == 0 {
            bail!("corrupt chunk at {start}: zero stripes");
        }
        let mut stripes = Vec::with_capacity(num_stripes);
        for i in 0..num_stripes {
            let o = 48 + i * 32;
            stripes.push((u64_at(b, o)?, u64_at(b, o + 8)?));
        }
        let chunk = Chunk {
            start,
            length: u64_at(b, 0)?,
            ty: u64_at(b, 24)?,
            stripes,
        };
        Ok((chunk, 48 + num_stripes * 32))
    }

    pub fn profile(&self) -> &'static str {
        let t = self.ty;
        if t & BLOCK_GROUP_RAID0 != 0 {
            "raid0"
        } else if t & (1 << 4) != 0 {
            "raid1"
        } else if t & (1 << 5) != 0 {
            "dup"
        } else if t & BLOCK_GROUP_RAID10 != 0 {
            "raid10"
        } else if t & BLOCK_GROUP_RAID5 != 0 {
            "raid5"
        } else if t & BLOCK_GROUP_RAID6 != 0 {
            "raid6"
        } else if t & (1 << 9) != 0 {
            "raid1c3"
        } else if t & (1 << 10) != 0 {
            "raid1c4"
        } else {
            "single"
        }
    }

    pub fn kind(&self) -> &'static str {
        match self.ty & 7 {
            1 => "data",
            2 => "system",
            4 => "metadata",
            5 => "data+metadata",
            _ => "mixed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Inode {
    pub size: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
}

impl Inode {
    pub fn parse(b: &[u8]) -> Result<Inode> {
        bytes(b, 0, INODE_ITEM_SIZE)?;
        Ok(Inode {
            size: u64_at(b, 16)?,
            nlink: u32_at(b, 40)?,
            uid: u32_at(b, 44)?,
            gid: u32_at(b, 48)?,
            mode: u32_at(b, 52)?,
            mtime_sec: u64_at(b, 136)? as i64,
            mtime_nsec: u32_at(b, 144)?,
        })
    }
    pub fn is_dir(&self) -> bool {
        self.mode & 0o170000 == 0o040000
    }
    pub fn is_file(&self) -> bool {
        self.mode & 0o170000 == 0o100000
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & 0o170000 == 0o120000
    }
    pub fn type_name(&self) -> &'static str {
        match self.mode & 0o170000 {
            0o040000 => "dir",
            0o100000 => "file",
            0o120000 => "symlink",
            0o020000 => "chardev",
            0o060000 => "blockdev",
            0o010000 => "fifo",
            0o140000 => "socket",
            _ => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: Vec<u8>,
    pub location: Key,
    pub ftype: u8,
}

/// A DIR_ITEM holds one entry per name that hashes to its key; a DIR_INDEX holds one.
pub fn parse_dir_entries(b: &[u8]) -> Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < b.len() {
        let location = Key::parse(b, off)?;
        let data_len = u16_at(b, off + 25)? as usize;
        let name_len = u16_at(b, off + 27)? as usize;
        let ftype = u8_at(b, off + 29)?;
        let name = bytes(b, off + 30, name_len)?.to_vec();
        out.push(DirEntry {
            name,
            location,
            ftype,
        });
        off += 30 + name_len + data_len;
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub enum ExtentKind {
    Inline(Vec<u8>),
    /// A real extent; `disk_bytenr == 0` is a hole.
    Regular {
        disk_bytenr: u64,
        disk_num_bytes: u64,
        offset: u64,
    },
    Prealloc,
}

#[derive(Clone, Debug)]
pub struct Extent {
    pub file_off: u64,
    /// Bytes this extent contributes to the file.
    pub len: u64,
    pub ram_bytes: u64,
    pub compression: u8,
    pub kind: ExtentKind,
}

impl Extent {
    pub fn parse(file_off: u64, b: &[u8]) -> Result<Extent> {
        let ram_bytes = u64_at(b, 8)?;
        let compression = u8_at(b, 16)?;
        if u8_at(b, 17)? != 0 {
            bail!("encrypted extents are not supported");
        }
        let (kind, len) = match u8_at(b, 20)? {
            0 => (
                ExtentKind::Inline(bytes(b, 21, b.len().saturating_sub(21))?.to_vec()),
                ram_bytes,
            ),
            t @ (1 | 2) => {
                let num_bytes = u64_at(b, 45)?;
                if t == 2 {
                    (ExtentKind::Prealloc, num_bytes)
                } else {
                    let kind = ExtentKind::Regular {
                        disk_bytenr: u64_at(b, 21)?,
                        disk_num_bytes: u64_at(b, 29)?,
                        offset: u64_at(b, 37)?,
                    };
                    (kind, num_bytes)
                }
            }
            t => bail!("unknown file extent type {t}"),
        };
        Ok(Extent {
            file_off,
            len,
            ram_bytes,
            compression,
            kind,
        })
    }

    pub fn compression_name(&self) -> &'static str {
        match self.compression {
            0 => "none",
            1 => "zlib",
            2 => "lzo",
            3 => "zstd",
            _ => "unknown",
        }
    }
}

/// `btrfs_name_hash`: raw crc32c seeded with `~1`, no final inversion.
pub fn name_hash(name: &[u8]) -> u64 {
    u64::from(!crc32c::crc32c_append(1, name))
}
