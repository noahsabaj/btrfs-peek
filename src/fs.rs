//! The filesystem proper: chunk mapping, tree walks, lookups, and file reads.

use crate::decompress::decompress;
use crate::dev::Device;
use crate::disk::*;
use anyhow::{anyhow, bail, Context, Result};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

/// Raised when a path does not exist, so the CLI can exit with its own code.
#[derive(Debug)]
pub struct NotFound(pub String);
impl std::fmt::Display for NotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not found: {}", self.0)
    }
}
impl std::error::Error for NotFound {}

/// An inode is only unique within its subvolume tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Loc {
    pub tree: u64,
    pub ino: u64,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: Vec<u8>,
    pub loc: Loc,
    pub ftype: u8,
    /// The entry is the root of another subvolume.
    pub subvol: bool,
}

impl Entry {
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

#[derive(Clone, Debug)]
pub struct Subvol {
    pub id: u64,
    pub parent: u64,
    pub path: String,
    pub readonly: bool,
    pub snapshot: bool,
    pub generation: u64,
}

struct Node(Vec<u8>);

impl Node {
    fn level(&self) -> u8 {
        self.0[100]
    }
    fn nritems(&self) -> usize {
        u32::from_le_bytes(self.0[96..100].try_into().unwrap()) as usize
    }
    fn item(&self, i: usize) -> Result<(Key, &[u8])> {
        let o = HEADER_SIZE + i * 25;
        let key = Key::parse(&self.0, o)?;
        let off = u32_at(&self.0, o + 17)? as usize;
        let size = u32_at(&self.0, o + 21)? as usize;
        Ok((key, bytes(&self.0, HEADER_SIZE + off, size)?))
    }
    fn ptr(&self, i: usize) -> Result<(Key, u64)> {
        let o = HEADER_SIZE + i * 33;
        Ok((Key::parse(&self.0, o)?, u64_at(&self.0, o + KEY_SIZE)?))
    }
}

struct TreeRoot {
    bytenr: u64,
    root_dirid: u64,
}

pub struct Fs {
    devs: HashMap<u64, Device>,
    pub sb: Superblock,
    chunks: BTreeMap<u64, Chunk>,
    nodes: RefCell<HashMap<u64, Rc<Node>>>,
    roots: RefCell<HashMap<u64, Rc<TreeRoot>>>,
    /// The last decompressed extent; reflinks and overwrites reference one extent many times.
    last_extent: RefCell<Option<(u64, Rc<Vec<u8>>)>>,
}

type Visit<'a> = &'a mut dyn FnMut(&Key, &[u8]) -> Result<bool>;

impl Fs {
    pub fn open(paths: &[String]) -> Result<Fs> {
        if paths.is_empty() {
            bail!("no device given: pass --device or set BTRFS_PEEK_DEVICE (run `btrfs-peek scan` to find one)");
        }
        let mut devs = HashMap::new();
        let mut best: Option<Superblock> = None;
        for path in paths {
            let dev = Device::open(path).map_err(|e| crate::open_error(path, e))?;
            let raw = dev
                .read(SUPER_OFFSET, SUPER_SIZE)
                .with_context(|| format!("{path}: reading superblock"))?;
            let sb = Superblock::parse(&raw)
                .with_context(|| format!("{path}: not a btrfs filesystem"))?;
            if let Some(b) = &best {
                if b.fsid != sb.fsid {
                    bail!("{path} belongs to a different filesystem than the other devices");
                }
            }
            devs.insert(sb.devid, dev);
            if best.as_ref().is_none_or(|b| sb.generation > b.generation) {
                best = Some(sb);
            }
        }
        let sb = best.unwrap();
        if sb.incompat_flags & INCOMPAT_REFUSED != 0 {
            bail!("filesystem uses extent-tree-v2 or raid-stripe-tree, which this tool cannot read correctly");
        }

        let mut fs = Fs {
            devs,
            sb,
            chunks: BTreeMap::new(),
            nodes: RefCell::new(HashMap::new()),
            roots: RefCell::new(HashMap::new()),
            last_extent: RefCell::new(None),
        };

        // Bootstrap: the superblock carries the SYSTEM chunks, enough to read the chunk tree.
        let arr = fs.sb.sys_chunk_array.clone();
        let mut off = 0;
        while off < arr.len() {
            let key = Key::parse(&arr, off)?;
            if key.ty != CHUNK_ITEM_KEY {
                bail!("corrupt sys_chunk_array: key type {}", key.ty);
            }
            let (chunk, used) = Chunk::parse(
                key.offset,
                bytes(&arr, off + KEY_SIZE, arr.len() - off - KEY_SIZE)?,
            )?;
            fs.chunks.insert(chunk.start, chunk);
            off += KEY_SIZE + used;
        }
        let mut found = Vec::new();
        fs.walk(
            fs.sb.chunk_root,
            Key::new(0, 0, 0),
            Key::new(u64::MAX, 255, u64::MAX),
            &mut |k, d| {
                if k.ty == CHUNK_ITEM_KEY {
                    found.push(Chunk::parse(k.offset, d)?.0);
                }
                Ok(true)
            },
        )
        .context("reading chunk tree")?;
        for c in found {
            fs.chunks.insert(c.start, c);
        }
        Ok(fs)
    }

    pub fn chunks(&self) -> impl Iterator<Item = &Chunk> {
        self.chunks.values()
    }

    pub fn device_paths(&self) -> Vec<String> {
        let mut v: Vec<_> = self
            .devs
            .iter()
            .map(|(id, d)| (*id, d.path.clone()))
            .collect();
        v.sort();
        v.into_iter().map(|(_, p)| p).collect()
    }

    fn mirrors(&self, logical: u64, len: u64) -> Result<Vec<(&Device, u64)>> {
        let chunk = self
            .chunks
            .range(..=logical)
            .next_back()
            .map(|(_, c)| c)
            .filter(|c| logical + len <= c.start + c.length)
            .ok_or_else(|| {
                anyhow!("logical address {logical} (+{len}) is not mapped by any chunk")
            })?;
        let striped =
            BLOCK_GROUP_RAID0 | BLOCK_GROUP_RAID10 | BLOCK_GROUP_RAID5 | BLOCK_GROUP_RAID6;
        if chunk.ty & striped != 0 && chunk.stripes.len() > 1 {
            bail!(
                "{} chunks striped across devices are not supported",
                chunk.profile()
            );
        }
        let out: Vec<_> = chunk
            .stripes
            .iter()
            .filter_map(|(devid, phys)| {
                self.devs
                    .get(devid)
                    .map(|d| (d, phys + (logical - chunk.start)))
            })
            .collect();
        if out.is_empty() {
            bail!(
                "the device holding logical address {logical} was not given (filesystem has {} devices; pass each with --device)",
                self.sb.num_devices
            );
        }
        Ok(out)
    }

    /// Reads file data, trying each mirror in turn. On DUP and RAID1 a bad
    /// sector in one copy is exactly what the other copy is there for.
    fn read_logical(&self, logical: u64, len: usize) -> Result<Vec<u8>> {
        let mut last_err = None;
        for (dev, phys) in self.mirrors(logical, len as u64)? {
            match dev.read(phys, len) {
                Ok(b) => return Ok(b),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.map_or_else(
            || anyhow!("logical address {logical} has no readable mirror"),
            Into::into,
        ))
    }

    fn read_node(&self, logical: u64) -> Result<Rc<Node>> {
        if let Some(n) = self.nodes.borrow().get(&logical) {
            return Ok(n.clone());
        }
        let size = self.sb.nodesize as usize;
        let mut last_err = anyhow!("unreadable");
        for (dev, phys) in self.mirrors(logical, size as u64)? {
            let buf = match dev.read(phys, size) {
                Ok(b) => b,
                Err(e) => {
                    last_err = e.into();
                    continue;
                }
            };
            if u64_at(&buf, 48)? != logical {
                last_err = anyhow!("tree block at {logical} has the wrong address in its header");
                continue;
            }
            if self.sb.csum_type == 0 && u32_at(&buf, 0)? != crc32c::crc32c(&buf[32..]) {
                last_err = anyhow!("tree block at {logical} failed its checksum");
                continue;
            }
            let node = Rc::new(Node(buf));
            let max_items = (size - HEADER_SIZE) / 25;
            if node.nritems() > max_items {
                bail!("tree block at {logical} claims {} items", node.nritems());
            }
            let mut cache = self.nodes.borrow_mut();
            if cache.len() >= 8192 {
                cache.clear();
            }
            cache.insert(logical, node.clone());
            return Ok(node);
        }
        Err(last_err)
    }

    /// Visits every item with `min <= key <= max` in order. The visitor returns `false` to stop.
    pub fn walk(&self, root: u64, min: Key, max: Key, visit: Visit) -> Result<bool> {
        self.walk_node(root, &min, &max, visit, 0, None)
    }

    fn walk_node(
        &self,
        logical: u64,
        min: &Key,
        max: &Key,
        visit: Visit,
        depth: u8,
        expect_level: Option<u8>,
    ) -> Result<bool> {
        if depth > 8 {
            bail!("tree deeper than btrfs allows; corrupt or cyclic");
        }
        let node = self.read_node(logical)?;
        let n = node.nritems();
        // A node must sit lower than its parent. Without this a node pointing at
        // itself (or at an ancestor) would be walked until the depth cap, doing
        // 8 levels of pointless work per visit instead of being named as corrupt.
        if let Some(expected) = expect_level {
            if node.level() != expected {
                bail!(
                    "tree block at {logical} is level {} where its parent expects {expected}",
                    node.level()
                );
            }
        }
        if node.level() == 0 {
            for i in 0..n {
                let (key, data) = node.item(i)?;
                if key < *min {
                    continue;
                }
                if key > *max || !visit(&key, data)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        for i in 0..n {
            let (key, child) = node.ptr(i)?;
            if key > *max {
                return Ok(false);
            }
            // A child holds keys below its right sibling's first key.
            if i + 1 < n && node.ptr(i + 1)?.0 <= *min {
                continue;
            }
            if !self.walk_node(child, min, max, visit, depth + 1, Some(node.level() - 1))? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn get(&self, root: u64, key: Key) -> Result<Option<Vec<u8>>> {
        let mut out = None;
        self.walk(root, key, key, &mut |_, d| {
            out = Some(d.to_vec());
            Ok(false)
        })?;
        Ok(out)
    }

    fn tree(&self, id: u64) -> Result<Rc<TreeRoot>> {
        if let Some(r) = self.roots.borrow().get(&id) {
            return Ok(r.clone());
        }
        // A snapshot's ROOT_ITEM is keyed by its creation transid; take the newest.
        let mut item = None;
        self.walk(
            self.sb.root,
            Key::new(id, ROOT_ITEM_KEY, 0),
            Key::new(id, ROOT_ITEM_KEY, u64::MAX),
            &mut |_, d| {
                item = Some(d.to_vec());
                Ok(true)
            },
        )?;
        let item = item.ok_or_else(|| anyhow!("subvolume tree {id} does not exist"))?;
        let root = Rc::new(TreeRoot {
            bytenr: u64_at(&item, 176)?,
            root_dirid: u64_at(&item, 168)?,
        });
        self.roots.borrow_mut().insert(id, root.clone());
        Ok(root)
    }

    pub fn root(&self) -> Result<Loc> {
        Ok(Loc {
            tree: FS_TREE_OBJECTID,
            ino: self.tree(FS_TREE_OBJECTID)?.root_dirid,
        })
    }

    pub fn inode(&self, loc: Loc) -> Result<Inode> {
        if Self::is_placeholder(loc) {
            return Ok(Inode {
                size: 0,
                nlink: 1,
                uid: 0,
                gid: 0,
                mode: 0o040755,
                mtime_sec: 0,
                mtime_nsec: 0,
            });
        }
        let item = self
            .get(
                self.tree(loc.tree)?.bytenr,
                Key::new(loc.ino, INODE_ITEM_KEY, 0),
            )?
            .ok_or_else(|| anyhow!("inode {} missing from tree {}", loc.ino, loc.tree))?;
        Inode::parse(&item)
    }

    fn entry(&self, dir: Loc, e: DirEntry) -> Result<Entry> {
        if e.location.ty != ROOT_ITEM_KEY {
            return Ok(Entry {
                name: e.name,
                loc: Loc {
                    tree: dir.tree,
                    ino: e.location.objectid,
                },
                ftype: e.ftype,
                subvol: false,
            });
        }
        // Inside a snapshot, a nested subvolume is only a placeholder: the kernel shows an
        // empty directory unless a ROOT_REF ties the child to this exact tree.
        let child = e.location.objectid;
        let linked = self
            .get(self.sb.root, Key::new(dir.tree, ROOT_REF_KEY, child))?
            .is_some();
        let loc = if linked {
            Loc {
                tree: child,
                ino: self.tree(child)?.root_dirid,
            }
        } else {
            Loc { tree: 0, ino: 0 }
        };
        Ok(Entry {
            name: e.name,
            loc,
            ftype: FT_DIR,
            subvol: true,
        })
    }

    /// Whether subvolume tree `id` was created as a snapshot of another.
    pub fn is_snapshot(&self, id: u64) -> Result<bool> {
        let mut snap = false;
        self.walk(
            self.sb.root,
            Key::new(id, ROOT_ITEM_KEY, 0),
            Key::new(id, ROOT_ITEM_KEY, u64::MAX),
            &mut |_, d| {
                snap = d.len() >= 279 && bytes(d, 263, 16)?.iter().any(|&b| b != 0);
                Ok(true)
            },
        )?;
        Ok(snap)
    }

    /// True for the empty-directory stand-in described in [`Fs::entry`].
    pub fn is_placeholder(loc: Loc) -> bool {
        loc.tree == 0
    }

    pub fn lookup(&self, dir: Loc, name: &[u8]) -> Result<Option<Entry>> {
        if Self::is_placeholder(dir) {
            return Ok(None);
        }
        let root = self.tree(dir.tree)?.bytenr;
        let Some(item) = self.get(root, Key::new(dir.ino, DIR_ITEM_KEY, name_hash(name)))? else {
            return Ok(None);
        };
        match parse_dir_entries(&item)?
            .into_iter()
            .find(|e| e.name == name)
        {
            Some(e) => Ok(Some(self.entry(dir, e)?)),
            None => Ok(None),
        }
    }

    pub fn readdir(&self, dir: Loc) -> Result<Vec<Entry>> {
        if Self::is_placeholder(dir) {
            return Ok(Vec::new());
        }
        let root = self.tree(dir.tree)?.bytenr;
        let mut raw = Vec::new();
        self.walk(
            root,
            Key::new(dir.ino, DIR_INDEX_KEY, 0),
            Key::new(dir.ino, DIR_INDEX_KEY, u64::MAX),
            &mut |_, d| {
                raw.extend(parse_dir_entries(d)?);
                Ok(true)
            },
        )?;
        let mut out = raw
            .into_iter()
            .map(|e| self.entry(dir, e))
            .collect::<Result<Vec<_>>>()?;
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Resolves an absolute path from the top-level subvolume (id 5), where every other
    /// subvolume appears as a directory. Symlinks are not followed: their targets refer
    /// to the Linux mount layout, which this tool cannot know.
    pub fn resolve(&self, path: &str) -> Result<Loc> {
        let mut stack = vec![self.root()?];
        let mut walked = String::new();
        for part in path
            .split(['/', '\\'])
            .filter(|p| !p.is_empty() && *p != ".")
        {
            if part == ".." {
                if stack.len() > 1 {
                    stack.pop();
                }
                continue;
            }
            let dir = *stack.last().unwrap();
            if !Self::is_placeholder(dir) {
                let inode = self.inode(dir)?;
                if inode.is_symlink() {
                    let target =
                        String::from_utf8_lossy(&self.read_symlink_target(dir)?).into_owned();
                    bail!("{walked} is a symlink to {target:?}; symlinks are not followed, resolve it yourself");
                }
                if !inode.is_dir() {
                    bail!("{walked} is not a directory");
                }
            }
            walked.push('/');
            walked.push_str(part);
            match self.lookup(dir, part.as_bytes())? {
                Some(e) => stack.push(e.loc),
                None => return Err(NotFound(walked).into()),
            }
        }
        Ok(*stack.last().unwrap())
    }

    pub fn extents(&self, loc: Loc) -> Result<Vec<Extent>> {
        let root = self.tree(loc.tree)?.bytenr;
        let mut out = Vec::new();
        self.walk(
            root,
            Key::new(loc.ino, EXTENT_DATA_KEY, 0),
            Key::new(loc.ino, EXTENT_DATA_KEY, u64::MAX),
            &mut |k, d| {
                out.push(Extent::parse(k.offset, d)?);
                Ok(true)
            },
        )?;
        Ok(out)
    }

    fn compressed_extent(
        &self,
        disk_bytenr: u64,
        disk_num_bytes: u64,
        algo: u8,
        ram_bytes: u64,
    ) -> Result<Rc<Vec<u8>>> {
        if let Some((addr, data)) = &*self.last_extent.borrow() {
            if *addr == disk_bytenr {
                return Ok(data.clone());
            }
        }
        if ram_bytes > 1 << 30 || disk_num_bytes > 1 << 30 {
            bail!("implausible compressed extent ({disk_num_bytes} -> {ram_bytes} bytes)");
        }
        let raw = self.read_logical(disk_bytenr, disk_num_bytes as usize)?;
        let plain = Rc::new(decompress(
            algo,
            &raw,
            ram_bytes as usize,
            self.sb.sectorsize as usize,
        )?);
        *self.last_extent.borrow_mut() = Some((disk_bytenr, plain.clone()));
        Ok(plain)
    }

    /// Streams `[start, end)` of a file to `sink`, clamped to the file size. Holes and
    /// preallocated ranges arrive as `Piece::Zeros`, so a file sink can stay sparse.
    pub fn read_range(
        &self,
        loc: Loc,
        start: u64,
        end: u64,
        sink: &mut dyn FnMut(Piece) -> Result<()>,
    ) -> Result<()> {
        let size = self.inode(loc)?.size;
        let end = end.min(size);
        let mut pos = start;
        let mut emit = |from: u64,
                        to: u64,
                        pos: &mut u64,
                        data: Option<&dyn Fn(u64, u64) -> Result<Vec<u8>>>|
         -> Result<()> {
            // Clip [from, to) to what is still wanted, fill any gap before it with zeros.
            let (from, to) = (from.max(*pos), to.min(end));
            if from >= to {
                return Ok(());
            }
            if from > *pos {
                sink(Piece::Zeros(from - *pos))?;
            }
            match data {
                None => sink(Piece::Zeros(to - from))?,
                Some(read) => {
                    let mut at = from;
                    while at < to {
                        let n = (to - at).min(1 << 20);
                        sink(Piece::Data(&read(at, n)?))?;
                        at += n;
                    }
                }
            }
            *pos = to;
            Ok(())
        };

        for ext in self.extents(loc)? {
            if pos >= end || ext.file_off >= end {
                break;
            }
            let (from, to) = (ext.file_off, ext.file_off.saturating_add(ext.len));
            if to <= pos {
                continue;
            }
            match &ext.kind {
                ExtentKind::Prealloc | ExtentKind::Regular { disk_bytenr: 0, .. } => {
                    emit(from, to, &mut pos, None)?
                }
                ExtentKind::Inline(raw) => {
                    // An inline extent lives inside a leaf, so it cannot be
                    // larger than one. Checking here keeps a corrupt ram_bytes
                    // away from the allocation inside decompress().
                    if ext.ram_bytes > u64::from(self.sb.nodesize) {
                        bail!(
                            "inline extent claims {} bytes, more than the {}-byte leaf holding it",
                            ext.ram_bytes,
                            self.sb.nodesize
                        );
                    }
                    let plain = if ext.compression == 0 {
                        raw.clone()
                    } else {
                        decompress(
                            ext.compression,
                            raw,
                            ext.ram_bytes as usize,
                            self.sb.sectorsize as usize,
                        )?
                    };
                    let to = from + plain.len() as u64;
                    emit(
                        from,
                        to,
                        &mut pos,
                        Some(&|at, n| {
                            Ok(plain[(at - from) as usize..(at - from + n) as usize].to_vec())
                        }),
                    )?;
                }
                ExtentKind::Regular {
                    disk_bytenr,
                    offset,
                    ..
                } if ext.compression == 0 => {
                    let base = disk_bytenr.checked_add(*offset).ok_or_else(|| {
                        anyhow!("extent address {disk_bytenr}+{offset} overflows")
                    })?;
                    emit(
                        from,
                        to,
                        &mut pos,
                        Some(&|at, n| {
                            let addr = base
                                .checked_add(at - from)
                                .ok_or_else(|| anyhow!("extent address overflows"))?;
                            self.read_logical(addr, n as usize)
                        }),
                    )?;
                }
                ExtentKind::Regular {
                    disk_bytenr,
                    disk_num_bytes,
                    offset,
                } => {
                    let plain = self.compressed_extent(
                        *disk_bytenr,
                        *disk_num_bytes,
                        ext.compression,
                        ext.ram_bytes,
                    )?;
                    let offset = *offset;
                    emit(
                        from,
                        to,
                        &mut pos,
                        Some(&|at, n| {
                            let s = (offset + (at - from)) as usize;
                            plain
                                .get(s..s + n as usize)
                                .map(<[u8]>::to_vec)
                                .ok_or_else(|| {
                                    anyhow!("extent reference outside its decompressed data")
                                })
                        }),
                    )?;
                }
            }
        }
        // Trailing hole (or a whole-file hole with the no-holes feature).
        emit(pos, end, &mut pos, None)
    }

    /// A symlink target, which the kernel caps at PATH_MAX. Reading it through
    /// the general path would honour whatever size a corrupt inode claimed.
    pub fn read_symlink_target(&self, loc: Loc) -> Result<Vec<u8>> {
        const MAX: u64 = 4096;
        let size = self.inode(loc)?.size;
        if size > MAX {
            bail!("symlink claims a {size}-byte target, past the {MAX}-byte maximum");
        }
        self.read_to_vec(loc, size)
    }

    fn read_to_vec(&self, loc: Loc, cap: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.read_range(loc, 0, cap, &mut |p| {
            match p {
                Piece::Data(d) => out.extend_from_slice(d),
                Piece::Zeros(n) => out.resize(out.len() + n as usize, 0),
            }
            Ok(())
        })?;
        Ok(out)
    }

    pub fn default_subvol(&self) -> Result<u64> {
        let key = Key::new(
            self.sb.root_dir_objectid,
            DIR_ITEM_KEY,
            name_hash(b"default"),
        );
        let Some(item) = self.get(self.sb.root, key)? else {
            return Ok(FS_TREE_OBJECTID);
        };
        Ok(parse_dir_entries(&item)?
            .first()
            .map_or(FS_TREE_OBJECTID, |e| e.location.objectid))
    }

    /// Path of inode `ino` inside its own tree, built by climbing INODE_REFs.
    fn path_in_tree(&self, tree: u64, mut ino: u64) -> Result<String> {
        let root = self.tree(tree)?;
        let mut parts = Vec::new();
        while ino != root.root_dirid {
            if parts.len() >= 4096 {
                bail!(
                    "inode {ino} in tree {tree}: the parent chain never reaches the subvolume root"
                );
            }
            let mut found = None;
            self.walk(
                root.bytenr,
                Key::new(ino, INODE_REF_KEY, 0),
                Key::new(ino, INODE_REF_KEY, u64::MAX),
                &mut |k, d| {
                    let len = u16_at(d, 8)? as usize;
                    found = Some((
                        k.offset,
                        String::from_utf8_lossy(bytes(d, 10, len)?).into_owned(),
                    ));
                    Ok(false)
                },
            )?;
            let (parent, name) = found
                .ok_or_else(|| anyhow!("inode {ino} in tree {tree} has no parent reference"))?;
            parts.push(name);
            ino = parent;
        }
        parts.reverse();
        Ok(parts.join("/"))
    }

    pub fn subvols(&self) -> Result<Vec<Subvol>> {
        let mut items = Vec::new();
        let mut backrefs = HashMap::new();
        self.walk(
            self.sb.root,
            Key::new(FIRST_FREE_OBJECTID, 0, 0),
            Key::new(LAST_FREE_OBJECTID, 255, u64::MAX),
            &mut |k, d| {
                match k.ty {
                    ROOT_ITEM_KEY => {
                        let snapshot = d.len() >= 279 && bytes(d, 263, 16)?.iter().any(|&b| b != 0);
                        items.push((
                            k.objectid,
                            u64_at(d, 160)?,
                            u64_at(d, 208)? & 1 != 0,
                            snapshot,
                        ));
                    }
                    ROOT_BACKREF_KEY => {
                        let len = u16_at(d, 16)? as usize;
                        let name = String::from_utf8_lossy(bytes(d, 18, len)?).into_owned();
                        backrefs.insert(k.objectid, (k.offset, u64_at(d, 0)?, name));
                    }
                    _ => {}
                }
                Ok(true)
            },
        )?;
        items.dedup_by_key(|i| i.0);

        let mut paths: HashMap<u64, String> = HashMap::from([(FS_TREE_OBJECTID, String::new())]);
        let mut out = Vec::new();
        // Parents always have lower ids than the subvolumes created inside them... except
        // after a move, so resolve iteratively until nothing new resolves.
        let mut pending: Vec<_> = items.iter().collect();
        while !pending.is_empty() {
            let before = pending.len();
            let mut next = Vec::new();
            for it in pending {
                let Some((parent, dirid, name)) = backrefs.get(&it.0) else {
                    continue;
                };
                let Some(parent_path) = paths.get(parent) else {
                    next.push(it);
                    continue;
                };
                let dir = self.path_in_tree(*parent, *dirid)?;
                let path = [parent_path.as_str(), dir.as_str(), name.as_str()]
                    .iter()
                    .filter(|s| !s.is_empty())
                    .copied()
                    .collect::<Vec<_>>()
                    .join("/");
                paths.insert(it.0, path.clone());
                out.push(Subvol {
                    id: it.0,
                    parent: *parent,
                    path: format!("/{path}"),
                    generation: it.1,
                    readonly: it.2,
                    snapshot: it.3,
                });
            }
            if next.len() == before {
                break;
            }
            pending = next;
        }
        out.sort_by_key(|s| s.id);
        Ok(out)
    }
}

pub enum Piece<'a> {
    Data(&'a [u8]),
    Zeros(u64),
}
