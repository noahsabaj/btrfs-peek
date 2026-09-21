//! The three btrfs compression formats.
//!
//! A compressed extent decodes to exactly `ram_bytes`. Anything else means the
//! extent is corrupt, and this module reports that rather than papering over it:
//! returning a plausible-looking buffer of zeros is worse than failing, because
//! the caller would write it to disk and call the copy a success.

use anyhow::{bail, Context, Result};
use std::io::Read;

/// Refuse a declared size no btrfs extent can legitimately have, before it
/// reaches an allocation. The kernel caps an uncompressed extent at 128 MiB.
pub const MAX_RAM_BYTES: usize = 1 << 30;

pub fn decompress(algo: u8, src: &[u8], ram_bytes: usize, sectorsize: usize) -> Result<Vec<u8>> {
    if ram_bytes > MAX_RAM_BYTES {
        bail!("extent claims {ram_bytes} bytes decompressed, which no btrfs extent can be");
    }
    if sectorsize == 0 {
        bail!("sectorsize is zero");
    }
    let out = match algo {
        1 => stream(
            flate2::read::ZlibDecoder::new(src),
            src,
            ram_bytes,
            sectorsize,
            "zlib",
        )?,
        2 => lzo(src, ram_bytes, sectorsize)?,
        3 => {
            let dec = ruzstd::decoding::StreamingDecoder::new(src)
                .map_err(|e| anyhow::anyhow!("zstd extent: {e}"))?;
            stream(dec, src, ram_bytes, sectorsize, "zstd")?
        }
        n => bail!("unknown compression type {n}"),
    };
    debug_assert_eq!(out.len(), ram_bytes);
    Ok(out)
}

fn stream(
    reader: impl Read,
    src: &[u8],
    ram_bytes: usize,
    sectorsize: usize,
    what: &str,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // Read one byte past what we want: if it arrives, the extent decodes to more
    // than it declared, so the data does not match the metadata describing it.
    reader
        .take(ram_bytes as u64 + 1)
        .read_to_end(&mut out)
        .with_context(|| format!("{what} extent ({} compressed bytes)", src.len()))?;
    finish(out, ram_bytes, sectorsize, what)
}

/// Settles up between what the stream produced and what the extent declared.
///
/// `ram_bytes` is rounded up to a whole number of sectors, so a file's last
/// extent legitimately decodes short by up to one sector and the kernel treats
/// the remainder as zeros (the inode size hides it). Any larger shortfall is a
/// truncated or corrupt extent, and must not be quietly filled in: a buffer of
/// zeros that looks like data is worse than an error, because the caller would
/// write it out and report the copy a success.
fn finish(mut out: Vec<u8>, ram_bytes: usize, sectorsize: usize, what: &str) -> Result<Vec<u8>> {
    if out.len() > ram_bytes {
        bail!(
            "{what} extent decodes to more than the {ram_bytes} bytes it declares; it is corrupt"
        );
    }
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
fn lzo(src: &[u8], ram_bytes: usize, sectorsize: usize) -> Result<Vec<u8>> {
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
    finish(out, ram_bytes, sectorsize, "lzo")
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
