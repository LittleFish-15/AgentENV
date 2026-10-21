//! Bounded sequential sparse output for a reconstructed logical image.
use std::io::{self, Seek, SeekFrom, Write};

/// The data limit counts bytes written from nonzero 4 KiB pages. Filesystem
/// allocation and metadata can differ; this is not a filesystem quota.
pub struct SparseOutput<W> {
    output: W,
    logical_limit: u64,
    data_limit: u64,
    logical: u64,
    written: u64,
    gap: u64,
}

impl<W: Write + Seek> SparseOutput<W> {
    pub fn new(output: W, logical_limit: u64, data_limit: u64) -> Self {
        Self {
            output,
            logical_limit,
            data_limit,
            logical: 0,
            written: 0,
            gap: 0,
        }
    }

    pub fn append(&mut self, data: &[u8]) -> io::Result<()> {
        let invalid = || io::Error::other("raw export byte budget exceeded");
        if !data.len().is_multiple_of(4096) {
            return Err(io::Error::other("raw export chunks must be page aligned"));
        }
        let end = self
            .logical
            .checked_add(data.len() as u64)
            .ok_or_else(invalid)?;
        let charge = data
            .chunks(4096)
            .filter(|page| page.iter().any(|b| *b != 0))
            .count() as u64
            * 4096;
        let written = self.written.checked_add(charge).ok_or_else(invalid)?;
        if end > self.logical_limit || written > self.data_limit {
            return Err(invalid());
        }
        // Validate the entire chunk before writing any part of it.
        for page in data.chunks(4096) {
            if page.iter().all(|b| *b == 0) {
                self.gap += page.len() as u64;
            } else {
                if self.gap != 0 {
                    let distance = i64::try_from(self.gap).map_err(|_| invalid())?;
                    self.output.seek(SeekFrom::Current(distance))?;
                    self.gap = 0;
                }
                self.output.write_all(page)?;
            }
        }
        self.logical = end;
        self.written = written;
        Ok(())
    }

    pub fn logical_bytes(&self) -> u64 {
        self.logical
    }
    pub fn written_bytes(&self) -> u64 {
        self.written
    }
    pub fn into_inner(self) -> W {
        self.output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn holes_across_chunks_keep_logical_offsets() {
        let mut out = SparseOutput::new(Cursor::new(Vec::new()), 6 * 4096, 2 * 4096);
        out.append(&vec![0; 8192]).unwrap();
        out.append(&vec![7; 4096]).unwrap();
        out.append(&vec![0; 4096]).unwrap();
        out.append(&vec![9; 4096]).unwrap();
        out.append(&vec![0; 4096]).unwrap();
        assert_eq!(out.logical_bytes(), 6 * 4096);
        assert_eq!(out.written_bytes(), 2 * 4096);
        let bytes = out.into_inner().into_inner();
        assert_eq!(&bytes[..8192], &vec![0; 8192]);
        assert_eq!(&bytes[8192..12288], &vec![7; 4096]);
        assert_eq!(&bytes[12288..16384], &vec![0; 4096]);
        assert_eq!(&bytes[16384..], &vec![9; 4096]);
        // The caller sets the final logical length, including the trailing hole.
        assert_eq!(bytes.len(), 5 * 4096);
    }

    #[test]
    fn rejected_chunk_does_not_partially_write() {
        let mut out = SparseOutput::new(Cursor::new(Vec::new()), 3 * 4096, 4096);
        out.append(&vec![1; 4096]).unwrap();
        assert!(out.append(&vec![2; 8192]).is_err());
        assert_eq!(out.logical_bytes(), 4096);
        assert_eq!(out.written_bytes(), 4096);
        assert_eq!(out.into_inner().into_inner(), vec![1; 4096]);
    }

    #[test]
    fn zeros_still_count_against_logical_budget() {
        let mut out = SparseOutput::new(Cursor::new(Vec::new()), 4096, 0);
        out.append(&vec![0; 4096]).unwrap();
        assert!(out.append(&vec![0; 4096]).is_err());
        assert_eq!(out.written_bytes(), 0);
        assert!(out.into_inner().into_inner().is_empty());
    }

    #[test]
    fn unaligned_chunks_are_rejected_without_changes() {
        let mut out = SparseOutput::new(Cursor::new(Vec::new()), 8192, 8192);
        assert!(out.append(&[1]).is_err());
        assert_eq!(out.logical_bytes(), 0);
    }
}
