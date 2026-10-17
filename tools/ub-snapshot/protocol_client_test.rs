//! Test-only client: exercises the actual Rust wire client against the Python broker.
#[path = "../../storage/overlaybd/src/backend/ub_protocol.rs"]
mod wire;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().collect();
    assert_eq!(arguments.len(), 8);
    #[cfg(unix)]
    let stream = std::os::unix::net::UnixStream::connect(&arguments[1])?;
    #[cfg(windows)]
    let stream = std::net::TcpStream::connect(&arguments[1])?;
    let size: u64 = arguments[5].parse()?;
    let mut session = wire::Session::open(
        stream,
        &arguments[2],
        &arguments[3],
        &arguments[4],
        size,
        arguments[6].parse()?,
    )?;
    assert!(session.is_healthy());
    if arguments[7] == "reject" {
        assert!(session.read_at(0, 10).is_err());
        assert!(session.read_at(0, 10).is_err());
    } else {
        let bytes = session.read_at(0, size as usize)?;
        for (index, byte) in bytes.iter().enumerate() {
            assert_eq!(*byte, (index % 256) as u8);
        }
        assert!(session.read_at(size, 1)?.is_empty());
        assert!(session.read_at(0, 0)?.is_empty());
        assert_eq!(session.read_at(size - 1, 20)?.len(), 1);
    }
    println!("RUST_PYTHON_WIRE_TEST_PASSED");
    Ok(())
}
