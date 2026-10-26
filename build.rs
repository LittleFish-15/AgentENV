use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=AENV_BUILD_GIT_COMMIT");
    println!("cargo:rerun-if-changed=services/api/proto/scheduler.proto");
    println!("cargo:rerun-if-changed=src/image/content.proto");
    println!("cargo:rerun-if-changed=src/image/build_history.proto");
    emit_git_rerun_inputs();

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &["services/api/proto/scheduler.proto"],
            &["services/api/proto"],
        )
        .expect("failed to compile scheduler proto for Rust gRPC client");

    tonic_prost_build::configure()
        .build_server(true)
        .compile_protos(
            &["src/image/content.proto", "src/image/build_history.proto"],
            &["src/image"],
        )
        .expect("failed to compile content store client");

    let commit = resolve_git_commit().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=AENV_GIT_COMMIT={commit}");
}

fn emit_git_rerun_inputs() {
    if let Some(path) = git_path("HEAD") {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let Some(head_ref) = git_stdout(["symbolic-ref", "-q", "HEAD"]) else {
        return;
    };
    let head_ref = head_ref.trim();
    if head_ref.is_empty() {
        return;
    }

    if let Some(path) = git_path(head_ref) {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // Track packed refs as well as the loose branch ref so changes after
    // repacking or worktree-local HEAD updates still refresh the embedded SHA.
    if let Some(path) = git_path("packed-refs").filter(|path| path.exists()) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn git_path(path: &str) -> Option<PathBuf> {
    git_stdout(["rev-parse", "--git-path", path]).map(|path| PathBuf::from(path.trim()))
}

fn resolve_git_commit() -> Option<String> {
    // Offline source packets have no .git directory. The packet builder binds
    // this explicit provenance value to its verified tracked-source inventory.
    if let Ok(commit) = std::env::var("AENV_BUILD_GIT_COMMIT") {
        assert!(
            commit.len() == 40
                && commit
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "AENV_BUILD_GIT_COMMIT must be a full lowercase Git SHA"
        );
        return Some(commit);
    }
    let commit = git_stdout(["rev-parse", "--short", "HEAD"])?;
    let commit = commit.trim();
    (!commit.is_empty()).then(|| commit.to_string())
}

fn git_stdout<const N: usize>(args: [&str; N]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout).ok()
}
