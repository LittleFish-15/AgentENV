//! Immutable file-to-device translation for the stable Host pmem protocol.
//! This describes logical addresses, never a UB allocation or physical PFN.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

pub const DEVICE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const LOAD_BYTES: u64 = 256 * 1024;
const MAX_EXTENTS: usize = 16_384;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FileExtent {
    pub file_offset: u64,
    pub device_offset: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StablePmemLayout {
    pub image_sha256: String,
    pub logical_bytes: u64,
    pub image_bytes: u64,
    pub load_bytes: u64,
    pub extents: Vec<FileExtent>,
}

/// One requested slice and the device load unit containing it. Loading the
/// unit is the service's responsibility; the client returns only requested data.
#[derive(Debug, PartialEq, Eq)]
pub struct ReadSlice {
    pub file_offset: u64,
    pub device_offset: u64,
    pub bytes: usize,
    pub unit_offset: u64,
    pub unit_bytes: u64,
}

impl StablePmemLayout {
    pub fn validate(&self, file_bytes: u64) -> Result<()> {
        let hash = self.image_sha256.strip_prefix("sha256:").unwrap_or("");
        ensure!(
            hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()),
            "stable pmem image requires a SHA256 identity"
        );
        ensure!(
            self.logical_bytes == DEVICE_BYTES && self.load_bytes == LOAD_BYTES,
            "stable pmem v1 requires 4 GiB logical capacity and 256 KiB load units"
        );
        ensure!(
            self.image_bytes > 0 && self.image_bytes <= self.logical_bytes,
            "image exceeds stable pmem logical capacity"
        );
        ensure!(
            file_bytes > 0 && !self.extents.is_empty() && self.extents.len() <= MAX_EXTENTS,
            "invalid stable pmem file extent count"
        );
        let mut end = 0u64;
        let mut physical_ranges = Vec::with_capacity(self.extents.len());
        for extent in &self.extents {
            ensure!(
                extent.file_offset == end && extent.bytes > 0,
                "file extents must cover the immutable file without holes or overlap"
            );
            end = end
                .checked_add(extent.bytes)
                .ok_or_else(|| anyhow::anyhow!("file extent overflow"))?;
            let device_end = extent
                .device_offset
                .checked_add(extent.bytes)
                .ok_or_else(|| anyhow::anyhow!("device extent overflow"))?;
            ensure!(
                device_end <= self.image_bytes,
                "file extent exceeds valid image bytes"
            );
            physical_ranges.push((extent.device_offset, device_end));
        }
        ensure!(
            end == file_bytes,
            "extent coverage differs from immutable lower length"
        );
        physical_ranges.sort_unstable();
        ensure!(
            physical_ranges.windows(2).all(|p| p[0].1 <= p[1].0),
            "stable image file extents overlap in device space"
        );
        Ok(())
    }

    /// Caller validates once at open. No payload read or device allocation.
    pub fn plan(&self, file_bytes: u64, offset: u64, count: usize) -> Result<Vec<ReadSlice>> {
        let bytes = file_bytes.saturating_sub(offset).min(count as u64);
        if bytes == 0 {
            return Ok(Vec::new());
        }
        let end = offset
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("read overflow"))?;
        let mut at = offset;
        let mut plan = Vec::new();
        let first = self
            .extents
            .partition_point(|e| e.file_offset <= at)
            .saturating_sub(1);
        for extent in &self.extents[first..] {
            while at < end && at < extent.file_offset + extent.bytes {
                ensure!(at >= extent.file_offset, "unmapped lower range");
                let device = extent.device_offset + (at - extent.file_offset);
                let unit = device / self.load_bytes * self.load_bytes;
                let unit_end = (unit + self.load_bytes).min(self.image_bytes);
                let n = (end - at)
                    .min(extent.file_offset + extent.bytes - at)
                    .min(unit_end - device);
                ensure!(n > 0, "empty stable pmem read slice");
                plan.push(ReadSlice {
                    file_offset: at,
                    device_offset: device,
                    bytes: n as usize,
                    unit_offset: unit,
                    unit_bytes: unit_end - unit,
                });
                at += n;
            }
            if at == end {
                break;
            }
        }
        ensure!(at == end, "incomplete stable pmem read plan");
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn layout() -> StablePmemLayout {
        StablePmemLayout {
            image_sha256: format!("sha256:{}", "a".repeat(64)),
            logical_bytes: DEVICE_BYTES,
            image_bytes: LOAD_BYTES * 8,
            load_bytes: LOAD_BYTES,
            extents: vec![
                FileExtent {
                    file_offset: 0,
                    device_offset: LOAD_BYTES - 4096,
                    bytes: 8192,
                },
                FileExtent {
                    file_offset: 8192,
                    device_offset: LOAD_BYTES * 5,
                    bytes: 4096,
                },
            ],
        }
    }
    #[test]
    fn fragmented_file_crosses_device_units_without_reading_gaps() {
        let l = layout();
        l.validate(12288).unwrap();
        let p = l.plan(12288, 2048, 10240).unwrap();
        assert_eq!(
            p.iter().map(|s| s.bytes).collect::<Vec<_>>(),
            vec![2048, 4096, 4096]
        );
        assert_eq!(
            p.iter().map(|s| s.unit_offset).collect::<Vec<_>>(),
            vec![0, LOAD_BYTES, 5 * LOAD_BYTES]
        );
        assert_eq!(p.iter().map(|s| s.bytes).sum::<usize>(), 10240);
    }
    #[test]
    fn eof_and_out_of_range_have_no_load_plan() {
        let l = layout();
        l.validate(12288).unwrap();
        assert!(l.plan(12288, u64::MAX, 4096).unwrap().is_empty());
        assert_eq!(l.plan(12288, 12286, 4096).unwrap()[0].bytes, 2);
    }
    #[test]
    fn rejects_holes_overlap_capacity_and_integer_wrap() {
        let base = layout();
        let mut l = base.clone();
        l.extents[1].file_offset += 1;
        assert!(l.validate(12288).is_err());
        let mut l = base.clone();
        l.extents[1].device_offset = LOAD_BYTES;
        assert!(l.validate(12288).is_err());
        let mut l = base.clone();
        l.image_bytes = DEVICE_BYTES + 1;
        assert!(l.validate(12288).is_err());
        let mut l = base.clone();
        l.extents[0].device_offset = u64::MAX;
        assert!(l.validate(12288).is_err());
        let mut l = base;
        l.load_bytes = 128 * 1024 * 1024;
        assert!(l.validate(12288).is_err());
    }
    #[test]
    fn last_unit_never_loads_past_image_end() {
        let mut l = layout();
        l.image_bytes = LOAD_BYTES * 5 + 4096;
        l.validate(12288).unwrap();
        let p = l.plan(12288, 8192, 4096).unwrap();
        assert_eq!(p[0].unit_bytes, 4096);
    }
}
