fn main() {
    let result = run();
    if let Err(error) = result {
        eprintln!("native FD verification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> std::io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 && !(args.len() == 4 && args[3] == "--private-cow") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected DESCRIPTOR SHA256 [--private-cow]",
        ));
    }
    aenv_native_fd_verify::validate(&args[1], &args[2])?;
    #[cfg(target_os = "linux")]
    return aenv_native_fd_verify::verify_mode(&args[1], &args[2], args.len() == 4);
    #[cfg(not(target_os = "linux"))]
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "device verifier requires Linux",
    ))
}
