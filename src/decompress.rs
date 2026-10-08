//! The three btrfs compression formats.
//!
//! A compressed extent decodes to exactly `ram_bytes`, give or take sector
//! padding (`finish`). Anything else means the extent is corrupt, and this
//! module reports that rather than papering over it:
//! returning a plausible-looking buffer of zeros is worse than failing, because
//! the caller would write it to disk and call the copy a success.

use anyhow::{bail, Context, Result};
use std::io::Read;

/// Refuse a declared size no btrfs extent can legitimately have, before it
/// reaches an allocation. The kernel caps an uncompressed extent at 128 MiB.
pub const MAX_RAM_BYTES: usize = 1 << 30;

pub fn decompress(algo: u8, src: &[u8], ram_bytes: usize, sectorsize: usize) -> Result<Vec<u8>> {
    decode(algo, src, ram_bytes, sectorsize, false)
}

/// An inline extent: the kernel may compress the file's whole last sector,
/// the zeros past its end included, while `ram_bytes` declares only the
/// file's bytes. It reads one sector back and keeps `ram_bytes` of it, so a
/// stream may decode up to the sector boundary; the rest is dropped. (Most
/// small files on a Fedora install with `compress=zstd:1`, 2026, decode to
/// a whole 4096-byte sector this way.)
pub fn decompress_inline(
    algo: u8,
    src: &[u8],
    ram_bytes: usize,
    sectorsize: usize,
) -> Result<Vec<u8>> {
    decode(algo, src, ram_bytes, sectorsize, true)
}

fn decode(
    algo: u8,
    src: &[u8],
    ram_bytes: usize,
    sectorsize: usize,
    inline: bool,
) -> Result<Vec<u8>> {
    if ram_bytes > MAX_RAM_BYTES {
        bail!("extent claims {ram_bytes} bytes decompressed, which no btrfs extent can be");
    }
    if sectorsize == 0 {
        bail!("sectorsize is zero");
    }
    let size = Size {
        ram_bytes,
        most: if inline {
            ram_bytes.next_multiple_of(sectorsize)
        } else {
            ram_bytes
        },
        sectorsize,
    };
    let out = match algo {
        1 => stream(flate2::read::ZlibDecoder::new(src), src, size, "zlib")?,
        2 => lzo(src, size)?,
        3 => {
            let dec = ruzstd::decoding::StreamingDecoder::new(src)
                .map_err(|e| anyhow::anyhow!("zstd extent: {e}"))?;
            stream(dec, src, size, "zstd")?
        }
        n => bail!("unknown compression type {n}"),
    };
    debug_assert_eq!(out.len(), ram_bytes);
    Ok(out)
}

/// What an extent may decode to.
#[derive(Clone, Copy)]
struct Size {
    /// What it declares.
    ram_bytes: usize,
    /// The most it may decode to: `ram_bytes`, or for an inline extent the
    /// end of its sector (`decompress_inline`).
    most: usize,
    sectorsize: usize,
}

fn stream(reader: impl Read, src: &[u8], size: Size, what: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // Read one byte past what it may decode to: if it arrives, the data does
    // not match the metadata describing it.
    reader
        .take(size.most as u64 + 1)
        .read_to_end(&mut out)
        .with_context(|| format!("{what} extent ({} compressed bytes)", src.len()))?;
    finish(out, size, what)
}

/// Settles up between what the stream produced and what the extent declared.
///
/// `ram_bytes` is rounded up to a whole number of sectors, so a file's last
/// extent legitimately decodes short by up to one sector and the kernel treats
/// the remainder as zeros (the inode size hides it). Any larger shortfall is a
/// truncated or corrupt extent, and must not be quietly filled in: a buffer of
/// zeros that looks like data is worse than an error, because the caller would
/// write it out and report the copy a success.
///
/// An inline extent may also decode past `ram_bytes` up to its sector's end
/// (`decompress_inline`); those bytes are not the file's and are dropped.
fn finish(mut out: Vec<u8>, size: Size, what: &str) -> Result<Vec<u8>> {
    let Size {
        ram_bytes,
        most,
        sectorsize,
    } = size;
    if out.len() > most {
        let past = if most > ram_bytes {
            format!(", past the end of its {sectorsize}-byte sector")
        } else {
            String::new()
        };
        bail!(
            "{what} extent decodes to more than the {ram_bytes} bytes it declares{past}; it is corrupt"
        );
    }
    out.truncate(ram_bytes);
    let short_by = ram_bytes - out.len();
    if short_by >= sectorsize {
        bail!(
            "{what} extent decodes to {} bytes but declares {ram_bytes}, short by {short_by} \
             which is more than the {sectorsize}-byte sector padding; it is truncated or corrupt",
            out.len()
        );
    }
    out.resize(ram_bytes, 0);
    Ok(out)
}

/// btrfs frames LZO1X itself: a 4-byte total length, then segments of
/// `[4-byte length][data]`, each holding one sector of plaintext. A segment
/// header never straddles a sector boundary; the writer pads to the next one.
fn lzo(src: &[u8], size: Size) -> Result<Vec<u8>> {
    let Size {
        ram_bytes,
        sectorsize,
        ..
    } = size;
    let le32 = |off: usize| -> Result<usize> {
        match src.get(off..off + 4) {
            Some(b) => Ok(u32::from_le_bytes(b.try_into().unwrap()) as usize),
            None => bail!("lzo extent: truncated header at offset {off}"),
        }
    };
    // Validate the frame length rather than clamping it. Clamping turned a
    // corrupt header into a short read, which then zero-filled silently.
    let total = le32(0)?;
    if total < 4 || total > src.len() {
        bail!(
            "lzo extent: frame declares {total} bytes but the extent holds {}",
            src.len()
        );
    }

    let mut out = Vec::new();
    let mut pos = 4;
    while pos < total && out.len() < ram_bytes {
        let left_in_sector = sectorsize - pos % sectorsize;
        if left_in_sector < 4 {
            pos += left_in_sector;
            if pos >= total {
                break;
            }
        }
        let seg_len = le32(pos)?;
        pos += 4;
        if seg_len == 0 || pos + seg_len > total {
            bail!("lzo extent: segment of {seg_len} bytes at offset {pos} overruns the frame");
        }
        let seg = &src[pos..pos + seg_len];
        // lzokay can panic on malformed input; one bad extent must fail this
        // file, not abort the whole copy.
        let plain =
            std::panic::catch_unwind(|| lzokay_native::decompress_all(seg, Some(sectorsize)))
                .map_err(|_| anyhow::anyhow!("lzo extent: segment at offset {pos} is malformed"))?
                .map_err(|e| anyhow::anyhow!("lzo extent at offset {pos}: {e:?}"))?;
        if plain.len() > sectorsize {
            bail!(
                "lzo extent: segment at offset {pos} expands to {} bytes, past the {sectorsize}-byte sector",
                plain.len()
            );
        }
        out.extend_from_slice(&plain);
        pos += seg_len;
    }
    finish(out, size, "lzo")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zlib_of(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn a_good_stream_round_trips() {
        let plain = b"the quick brown fox".repeat(100);
        let got = decompress(1, &zlib_of(&plain), plain.len(), 4096).unwrap();
        assert_eq!(got, plain);
    }

    #[test]
    fn a_short_decode_within_one_sector_is_padded_as_the_kernel_intends() {
        // A file's last extent declares a sector-rounded ram_bytes and decodes
        // short by the padding; this is the common case, not corruption.
        let plain = b"x".repeat(5000);
        let got = decompress(1, &zlib_of(&plain), 8192, 4096).unwrap();
        assert_eq!(got.len(), 8192);
        assert_eq!(&got[..5000], &plain[..]);
        assert!(got[5000..].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_shortfall_bigger_than_the_sector_padding_is_an_error() {
        let plain = b"the quick brown fox".repeat(100);
        let comp = zlib_of(&plain);
        let err = decompress(1, &comp, plain.len() + 4096, 4096).unwrap_err();
        assert!(
            format!("{err:#}").contains("truncated or corrupt"),
            "got: {err:#}"
        );
    }

    /// What the kernel wrote for most small files on a Fedora install: the
    /// file's last sector compressed whole, zeros past its end included.
    fn sector_of(data: &[u8]) -> Vec<u8> {
        let mut sector = data.to_vec();
        sector.resize(4096, 0);
        zlib_of(&sector)
    }

    #[test]
    fn an_inline_extent_that_decodes_to_its_whole_sector_keeps_its_declared_bytes() {
        for plain in [b"abcd".to_vec(), b"export default 1;\n".repeat(50)] {
            let got = decompress_inline(1, &sector_of(&plain), plain.len(), 4096).unwrap();
            assert_eq!(got, plain);
        }
        // And one that decodes to exactly what it declares, as before.
        let plain = b"the quick brown fox".repeat(10);
        let got = decompress_inline(1, &zlib_of(&plain), plain.len(), 4096).unwrap();
        assert_eq!(got, plain);
    }

    #[test]
    fn an_inline_extent_that_decodes_past_its_sector_is_an_error() {
        let plain = b"x".repeat(4097);
        let err = decompress_inline(1, &zlib_of(&plain), 100, 4096).unwrap_err();
        assert!(
            format!("{err:#}").contains("past the end of its 4096-byte sector"),
            "got: {err:#}"
        );
    }

    #[test]
    fn a_regular_extent_that_decodes_to_more_than_it_declares_is_an_error() {
        let err = decompress(1, &sector_of(b"abcd"), 4, 4096).unwrap_err();
        assert!(
            format!("{err:#}").contains("more than the 4 bytes it declares; it is corrupt"),
            "got: {err:#}"
        );
    }

    #[test]
    fn a_corrupt_lzo_frame_length_is_rejected() {
        // Frame header declares far more than the extent holds.
        let mut src = vec![0u8; 64];
        src[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = decompress(2, &src, 4096, 4096).unwrap_err();
        assert!(
            format!("{err:#}").contains("frame declares"),
            "got: {err:#}"
        );
    }

    #[test]
    fn an_implausible_ram_bytes_is_refused_before_allocating() {
        let err = decompress(1, &[], usize::MAX / 2, 4096).unwrap_err();
        assert!(
            format!("{err:#}").contains("no btrfs extent can be"),
            "got: {err:#}"
        );
    }

    #[test]
    fn garbage_lzo_input_errors_rather_than_panicking() {
        let mut src = vec![0xAAu8; 256];
        src[..4].copy_from_slice(&256u32.to_le_bytes());
        src[4..8].copy_from_slice(&200u32.to_le_bytes());
        assert!(decompress(2, &src, 4096, 4096).is_err());
    }
}
