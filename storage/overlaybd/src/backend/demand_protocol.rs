//! Metadata-only open and bounded demand reads. No fallback or reconnect.
use super::demand_layout::StablePmemLayout;
use super::ub_protocol::{hex_bytes, MAX_CHUNK, MAX_READ};
use std::io::{self, Read, Write};

pub const MAGIC: &[u8; 8] = b"AENVDM1\0";
pub const STABLE_MAGIC: &[u8; 8] = b"AENVDM2\0";

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub struct Session<T> {
    stream: T,
    file_bytes: u64,
    next_request: u64,
    healthy: bool,
    magic: &'static [u8; 8],
    layout: Option<StablePmemLayout>,
}

impl<T: Read + Write> Session<T> {
    pub fn open(
        stream: T,
        object: &str,
        generation: &str,
        digest: &str,
        file_bytes: u64,
        wire_bytes: u64,
        manifest: &str,
    ) -> io::Result<Self> {
        Self::open_with_layout(
            stream, object, generation, digest, file_bytes, wire_bytes, manifest, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_with_layout(
        mut stream: T,
        object: &str,
        generation: &str,
        digest: &str,
        file_bytes: u64,
        wire_bytes: u64,
        manifest: &str,
        layout: Option<&StablePmemLayout>,
    ) -> io::Result<Self> {
        let magic = if layout.is_some() {
            STABLE_MAGIC
        } else {
            MAGIC
        };
        let layout_bytes = if let Some(layout) = layout {
            layout
                .validate(file_bytes)
                .map_err(|e| invalid(&e.to_string()))?;
            let bytes = serde_json::to_vec(layout).map_err(|e| invalid(&e.to_string()))?;
            if bytes.len() > 1024 * 1024 {
                return Err(invalid("stable layout too large"));
            }
            Some(bytes)
        } else {
            None
        };
        if object.len() != 37 || !object.starts_with("aenv_") {
            return Err(invalid("invalid demand layer namespace"));
        }
        hex_bytes::<16>(&object[5..])?;
        let generation = hex_bytes::<16>(generation)?;
        let digest = hex_bytes::<32>(digest.strip_prefix("sha256:").unwrap_or(digest))?;
        let manifest = hex_bytes::<32>(manifest.strip_prefix("sha256:").unwrap_or(manifest))?;
        if file_bytes == 0
            || !wire_bytes.is_multiple_of(4 * 1024 * 1024)
            || file_bytes
                .checked_add(4096)
                .is_none_or(|end| end > wire_bytes)
        {
            return Err(invalid("invalid demand logical wire range"));
        }
        let mut request = Vec::with_capacity(180);
        request.extend_from_slice(magic);
        request.extend_from_slice(&(object.len() as u16).to_be_bytes());
        request.extend_from_slice(object.as_bytes());
        request.extend_from_slice(&generation);
        request.extend_from_slice(&file_bytes.to_be_bytes());
        request.extend_from_slice(&wire_bytes.to_be_bytes());
        request.extend_from_slice(&digest);
        request.extend_from_slice(&manifest);
        if let Some(bytes) = layout_bytes {
            request.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            request.extend_from_slice(&bytes);
        }
        stream.write_all(&request)?;
        stream.flush()?;
        Self::response(&mut stream, magic, 0, 0)?;
        Ok(Self {
            stream,
            file_bytes,
            next_request: 1,
            healthy: true,
            magic,
            layout: layout.cloned(),
        })
    }

    fn response(
        stream: &mut T,
        magic: &[u8; 8],
        request_id: u64,
        expected: usize,
    ) -> io::Result<()> {
        let mut response = [0_u8; 24];
        stream.read_exact(&mut response)?;
        let status = u32::from_be_bytes(response[8..12].try_into().unwrap());
        let count = u32::from_be_bytes(response[12..16].try_into().unwrap());
        let received_id = u64::from_be_bytes(response[16..24].try_into().unwrap());
        if &response[..8] != magic
            || received_id != request_id
            || status != 0
            || count as usize != expected
        {
            return Err(invalid(&format!(
                "demand response refused or mismatched: status={status}, request={received_id}, bytes={count}"
            )));
        }
        Ok(())
    }

    pub fn read_at(&mut self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if !self.healthy {
            return Err(invalid(
                "demand session failed; no implicit reconnect or source fallback",
            ));
        }
        let count = self.file_bytes.saturating_sub(offset).min(len as u64) as usize;
        if count > MAX_READ {
            return Err(invalid("demand read exceeds bounded allocation"));
        }
        let mut result = vec![0_u8; count];
        if let Err(error) = self.read_into(offset, &mut result) {
            self.healthy = false;
            return Err(error);
        }
        Ok(result)
    }

    fn read_into(&mut self, offset: u64, result: &mut [u8]) -> io::Result<()> {
        let plan = self
            .layout
            .as_ref()
            .map(|layout| layout.plan(self.file_bytes, offset, result.len()))
            .transpose()
            .map_err(|e| invalid(&e.to_string()))?;
        let mut done = 0;
        let mut slice_index = 0;
        while done < result.len() {
            let count = if let Some(plan) = &plan {
                plan[slice_index].bytes
            } else {
                (result.len() - done).min(MAX_CHUNK)
            };
            let request = self.next_request;
            self.next_request = self
                .next_request
                .checked_add(1)
                .ok_or_else(|| invalid("request ID exhausted"))?;
            let at = offset
                .checked_add(done as u64)
                .ok_or_else(|| invalid("demand offset overflow"))?;
            self.stream.write_all(&request.to_be_bytes())?;
            self.stream.write_all(&at.to_be_bytes())?;
            self.stream.write_all(&(count as u32).to_be_bytes())?;
            if let Some(plan) = &plan {
                // Server must validate against its trusted layout, never accept
                // client addresses as authorization to publish or read memory.
                self.stream
                    .write_all(&plan[slice_index].device_offset.to_be_bytes())?;
                slice_index += 1;
            }
            self.stream.flush()?;
            Self::response(&mut self.stream, self.magic, request, count)?;
            self.stream.read_exact(&mut result[done..done + count])?;
            done += count;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Default)]
    struct Wire {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Wire {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Wire {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn response(id: u64, status: u32, bytes: &[u8]) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&status.to_be_bytes());
        b.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(bytes);
        b
    }
    fn open(input: Vec<u8>) -> io::Result<Session<Wire>> {
        Session::open(
            Wire {
                input: Cursor::new(input),
                output: vec![],
            },
            "aenv_0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
            &"a".repeat(64),
            2 * MAX_CHUNK as u64,
            4 * 1024 * 1024,
            &"b".repeat(64),
        )
    }
    #[test]
    fn open_has_no_read_request() {
        let s = open(response(0, 0, &[])).unwrap();
        assert_eq!(s.stream.output.len(), 8 + 2 + 37 + 16 + 8 + 8 + 32 + 32);
        assert_eq!(s.next_request, 1);
    }
    #[test]
    fn exact_read_and_request_id() {
        let mut input = response(0, 0, &[]);
        input.extend(response(1, 0, b"data"));
        assert_eq!(open(input).unwrap().read_at(9, 4).unwrap(), b"data");
    }
    #[test]
    fn wrong_id_or_error_is_terminal() {
        for (id, status) in [(2, 0), (1, 2)] {
            let mut input = response(0, 0, &[]);
            input.extend(response(id, status, b"data"));
            let mut s = open(input).unwrap();
            assert!(s.read_at(0, 4).is_err());
            let written = s.stream.output.len();
            assert!(s.read_at(0, 4).is_err());
            assert_eq!(written, s.stream.output.len());
        }
    }
    #[test]
    fn full_protocol_cannot_impersonate_demand() {
        let mut input = response(0, 0, &[]);
        input[..8].copy_from_slice(b"AENVUB1\0");
        assert!(open(input).is_err());
    }

    fn stable_response(id: u64, bytes: &[u8]) -> Vec<u8> {
        let mut r = response(id, 0, bytes);
        r[..8].copy_from_slice(STABLE_MAGIC);
        r
    }

    fn stable_open(input: Vec<u8>) -> io::Result<Session<Wire>> {
        use super::super::demand_layout::{FileExtent, DEVICE_BYTES, LOAD_BYTES};
        let layout = StablePmemLayout {
            image_sha256: format!("sha256:{}", "e".repeat(64)),
            logical_bytes: DEVICE_BYTES,
            image_bytes: LOAD_BYTES * 4,
            load_bytes: LOAD_BYTES,
            extents: vec![FileExtent {
                file_offset: 0,
                device_offset: LOAD_BYTES - 2,
                bytes: 8,
            }],
        };
        Session::open_with_layout(
            Wire {
                input: Cursor::new(input),
                output: vec![],
            },
            "aenv_0123456789abcdef0123456789abcdef",
            &"a".repeat(32),
            &"b".repeat(64),
            8,
            4 * 1024 * 1024,
            &"c".repeat(64),
            Some(&layout),
        )
    }

    #[test]
    fn stable_reads_split_at_device_boundary_not_file_boundary() {
        use super::super::demand_layout::LOAD_BYTES;
        let mut input = stable_response(0, &[]);
        input.extend(stable_response(1, b"ab"));
        input.extend(stable_response(2, b"cdefgh"));
        let mut s = stable_open(input).unwrap();
        let start = s.stream.output.len();
        assert_eq!(s.read_at(0, 8).unwrap(), b"abcdefgh");
        let requests = &s.stream.output[start..];
        assert_eq!(requests.len(), 56);
        assert_eq!(
            u64::from_be_bytes(requests[20..28].try_into().unwrap()),
            LOAD_BYTES - 2
        );
        assert_eq!(
            u64::from_be_bytes(requests[48..56].try_into().unwrap()),
            LOAD_BYTES
        );
        assert_eq!(u32::from_be_bytes(requests[16..20].try_into().unwrap()), 2);
        assert_eq!(u64::from_be_bytes(requests[36..44].try_into().unwrap()), 2);
    }

    #[test]
    fn stable_open_rejects_old_chunk_device_broker() {
        assert!(stable_open(response(0, 0, &[])).is_err());
    }

    #[test]
    fn stable_partial_read_failure_poisons_connection_without_returning_partial_data() {
        let mut input = stable_response(0, &[]);
        input.extend(stable_response(1, b"ab"));
        let mut s = stable_open(input).unwrap();
        assert!(s.read_at(0, 8).is_err());
        let n = s.stream.output.len();
        assert!(s.read_at(0, 1).is_err());
        assert_eq!(s.stream.output.len(), n);
    }
}
