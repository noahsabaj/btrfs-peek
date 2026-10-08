//! Read-only access to an image file or a raw block device.
//!
//! The device is opened for reading only; there is no code path in this crate
//! that can write to it. Raw devices on Windows reject reads that are not
//! sector-aligned, so every read is widened to 4 KiB boundaries.
//!
//! On Windows an unelevated process may not open a raw disk; if the helper
//! service is installed, the device is read through it instead.

use std::fs::File;
use std::io;

const ALIGN: u64 = 4096;
const MAX_IO: usize = 4 << 20;

pub struct Device {
    backing: Backing,
    pub path: String,
}

enum Backing {
    File(File),
    #[cfg(windows)]
    Helper(crate::helper::Remote),
}

impl Backing {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        match self {
            Backing::File(f) => read_at(f, buf, off),
            #[cfg(windows)]
            Backing::Helper(h) => h.read_at(buf, off),
        }
    }
}

#[cfg(windows)]
pub(crate) fn read_at(file: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, off)
}
#[cfg(unix)]
pub(crate) fn read_at(file: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, off)
}

impl Device {
    pub fn open(path: &str) -> io::Result<Device> {
        let backing = match File::open(path) {
            Ok(f) => Backing::File(f),
            #[cfg(windows)]
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                match crate::helper::Remote::open(path)? {
                    Some(h) => Backing::Helper(h),
                    // No helper installed: the original error says what to do.
                    None => return Err(e),
                }
            }
            Err(e) => return Err(e),
        };
        Ok(Device {
            backing,
            path: path.to_string(),
        })
    }

    pub fn read(&self, off: u64, len: usize) -> io::Result<Vec<u8>> {
        let start = off - off % ALIGN;
        let end = (off + len as u64).div_ceil(ALIGN) * ALIGN;
        let mut buf = vec![0u8; (end - start) as usize];
        let mut done = 0;
        while done < buf.len() {
            let want = (buf.len() - done).min(MAX_IO);
            match self
                .backing
                .read_at(&mut buf[done..done + want], start + done as u64)
            {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        let skip = (off - start) as usize;
        // An image file need not end on an aligned boundary; only the requested bytes must exist.
        if done < skip + len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "{}: read of {len} bytes at offset {off} ran past the end of the device",
                    self.path
                ),
            ));
        }
        buf.truncate(skip + len);
        buf.drain(..skip);
        Ok(buf)
    }
}
