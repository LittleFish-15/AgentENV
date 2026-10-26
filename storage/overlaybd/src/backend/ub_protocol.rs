//! Read-only, generation-bound connection to the node's UB layer broker.
//! This module intentionally uses only std so its wire contract can be tested
//! independently of Linux, ublk, the SDK and the async runtime.
use std::io::{self, Read, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub const MAGIC: &[u8; 8] = b"AENVUB1\0";
pub const MAX_CHUNK: usize = 1024 * 1024;
pub const MAX_READ: usize = 64 * 1024 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn hex_bytes<const N: usize>(text: &str) -> io::Result<[u8; N]> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(invalid("UB identity must be fixed-length lowercase hex"));
    }
    let mut result = [0; N];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| invalid("invalid UB hex identity"))?;
    }
    Ok(result)
}

pub struct Session<T> {
    stream: T,
    file_bytes: u64,
    health: SessionHealth,
}

#[derive(Clone)]
pub(super) struct SessionHealth(Arc<AtomicBool>);

impl SessionHealth {
    pub(super) fn is_healthy(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl<T: Read + Write> Session<T> {
    pub fn is_healthy(&self) -> bool {
        self.health.is_healthy()
    }
    pub(super) fn health_token(&self) -> SessionHealth {
        self.health.clone()
    }
    pub fn open(
        mut stream: T,
        object: &str,
        generation: &str,
        digest: &str,
        file_bytes: u64,
        mapping_bytes: u64,
    ) -> io::Result<Self> {
        if object.len() != 37 || !object.starts_with("aenv_") {
            return Err(invalid("invalid UB layer object namespace"));
        }
        hex_bytes::<16>(&object[5..])?;
        let generation = hex_bytes::<16>(generation)?;
        let digest = hex_bytes::<32>(digest.strip_prefix("sha256:").unwrap_or(digest))?;
        if file_bytes == 0
            || !mapping_bytes.is_multiple_of(4 * 1024 * 1024)
            || file_bytes
                .checked_add(4096)
                .is_none_or(|n| n > mapping_bytes)
        {
            return Err(invalid("invalid UB layer lengths"));
        }
        let mut request = Vec::with_capacity(128);
        request.extend_from_slice(MAGIC);
        request.extend_from_slice(&(object.len() as u16).to_be_bytes());
        request.extend_from_slice(object.as_bytes());
        request.extend_from_slice(&generation);
        request.extend_from_slice(&file_bytes.to_be_bytes());
        request.extend_from_slice(&mapping_bytes.to_be_bytes());
        request.extend_from_slice(&digest);
        stream.write_all(&request)?;
        stream.flush()?;
        Self::response(&mut stream, 0)?;
        Ok(Self {
            stream,
            file_bytes,
            health: SessionHealth(Arc::new(AtomicBool::new(true))),
        })
    }

    fn response(stream: &mut T, expected: usize) -> io::Result<()> {
        let mut header = [0; 16];
        stream.read_exact(&mut header)?;
        if &header[..8] != MAGIC {
            return Err(invalid("UB broker protocol mismatch"));
        }
        let status = u32::from_be_bytes(header[8..12].try_into().unwrap());
        let length = u32::from_be_bytes(header[12..16].try_into().unwrap()) as usize;
        if status != 0 || length != expected {
            return Err(invalid(
                "UB broker refused request or returned a short/oversized response",
            ));
        }
        Ok(())
    }

    pub fn read_at(&mut self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if !self.is_healthy() {
            return Err(invalid(
                "UB session failed; refusing implicit reconnect or local fallback",
            ));
        }
        let wanted = (self.file_bytes.saturating_sub(offset)).min(len as u64);
        if wanted > MAX_READ as u64 {
            return Err(invalid("UB read exceeds bounded allocation limit"));
        }
        let mut data = vec![0; wanted as usize];
        let result = self.read_into(offset, &mut data);
        if result.is_err() {
            self.health.0.store(false, Ordering::Release);
        }
        result.map(|()| data)
    }

    fn read_into(&mut self, offset: u64, data: &mut [u8]) -> io::Result<()> {
        let mut done = 0;
        while done < data.len() {
            let count = (data.len() - done).min(MAX_CHUNK);
            let at = offset
                .checked_add(done as u64)
                .ok_or_else(|| invalid("UB offset overflow"))?;
            self.stream.write_all(&at.to_be_bytes())?;
            self.stream.write_all(&(count as u32).to_be_bytes())?;
            self.stream.flush()?;
            Self::response(&mut self.stream, count)?;
            self.stream.read_exact(&mut data[done..done + count])?;
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
        incoming: Cursor<Vec<u8>>,
        outgoing: Vec<u8>,
    }
    impl Read for Wire {
        fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
            self.incoming.read(dst)
        }
    }
    impl Write for Wire {
        fn write(&mut self, src: &[u8]) -> io::Result<usize> {
            self.outgoing.extend_from_slice(src);
            Ok(src.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    const OBJECT: &str = "aenv_0123456789abcdef0123456789abcdef";
    const GENERATION: &str = "0123456789abcdef0123456789abcdef";
    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fn reply(status: u32, length: u32) -> Vec<u8> {
        [
            MAGIC.as_slice(),
            &status.to_be_bytes(),
            &length.to_be_bytes(),
        ]
        .concat()
    }
    fn session(tail: &[u8], size: u64) -> Session<Wire> {
        let wire = Wire {
            incoming: Cursor::new([reply(0, 0), tail.to_vec()].concat()),
            outgoing: vec![],
        };
        Session::open(wire, OBJECT, GENERATION, DIGEST, size, 4 * 1024 * 1024).unwrap()
    }
    #[test]
    fn open_frame_has_exact_v1_layout_without_trailing_bytes() {
        let s = session(&[], 10);
        let frame = &s.stream.outgoing;
        assert_eq!(frame.len(), 111);
        assert_eq!(&frame[..8], MAGIC);
        assert_eq!(&frame[8..10], &37u16.to_be_bytes());
        assert_eq!(&frame[10..47], OBJECT.as_bytes());
        assert_eq!(&frame[47..63], &hex_bytes::<16>(GENERATION).unwrap());
        assert_eq!(&frame[63..71], &10u64.to_be_bytes());
        assert_eq!(&frame[71..79], &(4 * 1024 * 1024u64).to_be_bytes());
        assert_eq!(&frame[79..111], &hex_bytes::<32>(DIGEST).unwrap());
    }
    #[test]
    fn reads_exact_bytes_and_encodes_offset() {
        let mut s = session(&[reply(0, 3), b"abc".to_vec()].concat(), 10);
        assert!(s.is_healthy());
        assert_eq!(s.read_at(2, 3).unwrap(), b"abc");
        assert!(s
            .stream
            .outgoing
            .ends_with(&[2_u64.to_be_bytes().as_slice(), &3_u32.to_be_bytes()].concat()));
    }
    #[test]
    fn eof_and_zero_reads_do_not_send_requests() {
        let mut s = session(&[], 10);
        let sent = s.stream.outgoing.len();
        assert!(s.read_at(10, 5).unwrap().is_empty());
        assert!(s.read_at(u64::MAX, 5).unwrap().is_empty());
        assert!(s.read_at(0, 0).unwrap().is_empty());
        assert_eq!(sent, s.stream.outgoing.len());
    }
    #[test]
    fn clamps_at_eof() {
        let mut s = session(&[reply(0, 2), b"xy".to_vec()].concat(), 10);
        assert_eq!(s.read_at(8, usize::MAX).unwrap(), b"xy");
    }
    #[test]
    fn rejects_short_oversized_and_error_responses_and_poisons_session() {
        for (status, length) in [(0, 2), (0, 4), (1, 3)] {
            let mut s = session(&reply(status, length), 10);
            assert!(s.read_at(0, 3).is_err());
            let sent = s.stream.outgoing.len();
            assert!(s.read_at(0, 3).is_err());
            assert_eq!(sent, s.stream.outgoing.len());
        }
    }
    #[test]
    fn truncated_payload_is_error() {
        let mut s = session(&[reply(0, 3), b"ab".to_vec()].concat(), 10);
        assert!(s.read_at(0, 3).is_err());
    }
    #[test]
    fn failure_marker_survives_last_session_drop() {
        let mut s = session(&[reply(0, 3), b"ab".to_vec()].concat(), 10);
        let health = s.health_token();
        assert!(health.is_healthy());
        assert!(s.read_at(0, 3).is_err());
        drop(s);
        assert!(!health.is_healthy());
    }
    #[test]
    fn splits_large_reads() {
        let tail = [
            reply(0, MAX_CHUNK as u32),
            vec![7; MAX_CHUNK],
            reply(0, 1),
            vec![8],
        ]
        .concat();
        let mut s = session(&tail, (MAX_CHUNK + 1) as u64);
        let result = s.read_at(0, MAX_CHUNK + 1).unwrap();
        assert_eq!(result.len(), MAX_CHUNK + 1);
        assert_eq!(result[MAX_CHUNK], 8);
    }
    #[test]
    fn rejects_wrong_handshake_and_identity() {
        assert!(Session::open(Wire::default(), OBJECT, "bad", DIGEST, 1, 4194304).is_err());
        assert!(Session::open(
            Wire::default(),
            "other_object",
            GENERATION,
            DIGEST,
            1,
            4194304
        )
        .is_err());
        assert!(Session::open(
            Wire::default(),
            OBJECT,
            GENERATION,
            DIGEST,
            4194304,
            4194304
        )
        .is_err());
        assert!(Session::open(Wire::default(), OBJECT, GENERATION, DIGEST, 0, 4194304).is_err());
        let wire = Wire {
            incoming: Cursor::new(reply(1, 0)),
            outgoing: vec![],
        };
        assert!(Session::open(wire, OBJECT, GENERATION, DIGEST, 1, 4194304).is_err());
    }
    #[test]
    fn bad_magic_and_hex_are_rejected() {
        let mut s = session(&[0; 16], 10);
        assert!(s.read_at(0, 1).is_err());
        assert!(hex_bytes::<1>("AA").is_err());
        assert!(hex_bytes::<1>("gg").is_err());
        assert_eq!(hex_bytes::<1>("af").unwrap(), [175]);
    }
}
