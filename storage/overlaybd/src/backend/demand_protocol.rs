//! Metadata-only open and bounded demand reads. No fallback or reconnect.
use super::ub_protocol::{hex_bytes, MAX_CHUNK, MAX_READ};
use std::io::{self, Read, Write};

pub const MAGIC: &[u8; 8] = b"AENVDM1\0";

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub struct Session<T> {
    stream: T,
    file_bytes: u64,
    next_request: u64,
    healthy: bool,
}

impl<T: Read + Write> Session<T> {
    pub fn open(
        mut stream: T,
        object: &str,
        generation: &str,
        digest: &str,
        file_bytes: u64,
        wire_bytes: u64,
        manifest: &str,
    ) -> io::Result<Self> {
        if object.len() != 37 || !object.starts_with("aenv_") {
            return Err(invalid("invalid demand layer namespace"));
        }
        hex_bytes::<16>(&object[5..])?;
        let generation = hex_bytes::<16>(generation)?;
        let digest = hex_bytes::<32>(digest.strip_prefix("sha256:").unwrap_or(digest))?;
        let manifest = hex_bytes::<32>(manifest.strip_prefix("sha256:").unwrap_or(manifest))?;
        if file_bytes == 0
            || !wire_bytes.is_multiple_of(4 * 1024 * 1024)
            || file_bytes.checked_add(4096).is_none_or(|end| end > wire_bytes)
        {
            return Err(invalid("invalid demand logical wire range"));
        }
        let mut request = Vec::with_capacity(180);
        request.extend_from_slice(MAGIC);
        request.extend_from_slice(&(object.len() as u16).to_be_bytes());
        request.extend_from_slice(object.as_bytes());
        request.extend_from_slice(&generation);
        request.extend_from_slice(&file_bytes.to_be_bytes());
        request.extend_from_slice(&wire_bytes.to_be_bytes());
        request.extend_from_slice(&digest);
        request.extend_from_slice(&manifest);
        stream.write_all(&request)?;
        stream.flush()?;
        Self::response(&mut stream, 0, 0)?;
        Ok(Self {
            stream,
            file_bytes,
            next_request: 1,
            healthy: true,
        })
    }

    fn response(stream: &mut T, request_id: u64, expected: usize) -> io::Result<()> {
        let mut response = [0_u8; 24];
        stream.read_exact(&mut response)?;
        let status = u32::from_be_bytes(response[8..12].try_into().unwrap());
        let count = u32::from_be_bytes(response[12..16].try_into().unwrap());
        let received_id = u64::from_be_bytes(response[16..24].try_into().unwrap());
        if &response[..8] != MAGIC || received_id != request_id || status != 0 || count as usize != expected {
            return Err(invalid(&format!(
                "demand response refused or mismatched: status={status}, request={received_id}, bytes={count}"
            )));
        }
        Ok(())
    }

    pub fn read_at(&mut self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if !self.healthy {
            return Err(invalid("demand session failed; no implicit reconnect or source fallback"));
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
        let mut done = 0;
        while done < result.len() {
            let count = (result.len() - done).min(MAX_CHUNK);
            let request = self.next_request;
            self.next_request = self.next_request.checked_add(1).ok_or_else(|| invalid("request ID exhausted"))?;
            let at = offset.checked_add(done as u64).ok_or_else(|| invalid("demand offset overflow"))?;
            self.stream.write_all(&request.to_be_bytes())?;
            self.stream.write_all(&at.to_be_bytes())?;
            self.stream.write_all(&(count as u32).to_be_bytes())?;
            self.stream.flush()?;
            Self::response(&mut self.stream, request, count)?;
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
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> { self.input.read(b) }
    }
    impl Write for Wire {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> { self.output.extend_from_slice(b); Ok(b.len()) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    fn response(id: u64, status: u32, bytes: &[u8]) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&status.to_be_bytes()); b.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        b.extend_from_slice(&id.to_be_bytes()); b.extend_from_slice(bytes); b
    }
    fn open(input: Vec<u8>) -> io::Result<Session<Wire>> {
        Session::open(Wire { input: Cursor::new(input), output: vec![] },
            "aenv_0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef",
            &"a".repeat(64), 2 * MAX_CHUNK as u64, 4 * 1024 * 1024, &"b".repeat(64))
    }
    #[test]
    fn open_has_no_read_request() {
        let s = open(response(0, 0, &[])).unwrap();
        assert_eq!(s.stream.output.len(), 8 + 2 + 37 + 16 + 8 + 8 + 32 + 32);
        assert_eq!(s.next_request, 1);
    }
    #[test]
    fn exact_read_and_request_id() {
        let mut input = response(0, 0, &[]); input.extend(response(1, 0, b"data"));
        assert_eq!(open(input).unwrap().read_at(9, 4).unwrap(), b"data");
    }
    #[test]
    fn wrong_id_or_error_is_terminal() {
        for (id, status) in [(2, 0), (1, 2)] {
            let mut input = response(0, 0, &[]); input.extend(response(id, status, b"data"));
            let mut s = open(input).unwrap(); assert!(s.read_at(0, 4).is_err());
            let written = s.stream.output.len(); assert!(s.read_at(0, 4).is_err());
            assert_eq!(written, s.stream.output.len());
        }
    }
    #[test]
    fn full_protocol_cannot_impersonate_demand() {
        let mut input = response(0, 0, &[]); input[..8].copy_from_slice(b"AENVUB1\0");
        assert!(open(input).is_err());
    }
}
