fn main() {
    let result = run();
    if let Err(error) = result {
        eprintln!("native FD verification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> std::io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected DESCRIPTOR SHA256",
        ));
    }
    aenv_native_fd_verify::validate(&args[1], &args[2])?;
    #[cfg(target_os = "linux")]
    return aenv_native_fd_verify::verify(&args[1], &args[2]);
    #[cfg(not(target_os = "linux"))]
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "device verifier requires Linux",
    ))
}
