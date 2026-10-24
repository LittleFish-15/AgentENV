#![allow(dead_code)]
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct State {
    initialized: bool,
    reject_init: bool,
    reject_dax: bool,
    reject_exec: bool,
    calls: Vec<&'static str>,
}
#[derive(Clone)]
struct EnvdInstance(Arc<Mutex<State>>);
impl EnvdInstance {
    async fn wait_for_ready(&self, _: Duration, _: Duration) -> Result<()> {
        self.0.lock().unwrap().calls.push("health");
        Ok(())
    }
    async fn init(&self, _: Option<String>, _: Option<String>, _: Option<String>) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        state.calls.push("init");
        anyhow::ensure!(!state.reject_init, "init authentication failed");
        state.initialized = true;
        Ok(())
    }
}
struct Binding { version: u32 }
struct Common {
    direct_rootfs: Option<Binding>,
    env_vars: Option<String>,
    default_workdir: Option<String>,
    default_user: Option<String>,
}
struct Launch(Common);
impl Launch { fn common(&self) -> &Common { &self.0 } }
struct Policy { envd_timeout: Duration, envd_poll_interval: Duration }
struct Tools;
impl Tools { fn image_config_path(&self) -> &Path { Path::new("unused") } }
struct UblkDeviceManager;
impl UblkDeviceManager {
    fn global() -> Self { Self }
    async fn notify_sandbox_ready(&self, _: &Path) -> Result<()> { Ok(()) }
}
struct Output { exit_code: i32, stdout: String, stderr: String }
struct FirecrackerSandbox {
    envd_instance: Option<EnvdInstance>, launch: Launch, runtime_policy: Policy,
    tools_ublk_device: Option<Tools>, mem_snapshot_image_config_path: Option<PathBuf>,
    rootfs_image_config_path: Option<PathBuf>, initial_guest_drive_mounts: Vec<()>,
}
impl FirecrackerSandbox {
    async fn run_native_readiness_command(envd: EnvdInstance, command: String, _: Vec<String>) -> Result<Output> {
        let mut state = envd.0.lock().unwrap();
        anyhow::ensure!(state.initialized, "401 Unauthorized: restored source auth has not been initialized");
        let dax = command == "/agentenv/dax-check";
        state.calls.push(if dax { "dax" } else { "exec" });
        Ok(Output {
            exit_code: if dax { if state.reject_dax { 1 } else { 0 } }
                       else if state.reject_exec { 1 } else { 73 },
            stdout: if dax { "DAX_ACTIVE fixture".into() } else { String::new() },
            stderr: String::new(),
        })
    }
    async fn mount_initial_guest_drives(envd: EnvdInstance, _: Vec<()>) -> Result<()> {
        envd.0.lock().unwrap().calls.push("mount");
        Ok(())
    }
    // ACTUAL_WAIT_FOR_READY
}

fn fixture(native: bool) -> (FirecrackerSandbox, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State::default()));
    (FirecrackerSandbox {
        envd_instance: Some(EnvdInstance(state.clone())),
        launch: Launch(Common { direct_rootfs: native.then_some(Binding { version: 5 }),
            env_vars: None, default_workdir: Some("/".into()), default_user: Some("root".into()) }),
        runtime_policy: Policy { envd_timeout: Duration::from_secs(10), envd_poll_interval: Duration::from_millis(1) },
        tools_ublk_device: None, mem_snapshot_image_config_path: None, rootfs_image_config_path: None,
        initial_guest_drive_mounts: vec![],
    }, state)
}
#[tokio::test]
async fn restored_native_auth_is_initialized_before_any_dax_or_exec() {
    let (sandbox, state) = fixture(true);
    sandbox.wait_for_ready().await.unwrap();
    assert_eq!(state.lock().unwrap().calls, ["health", "init", "dax", "dax", "exec"]);
}
#[tokio::test]
async fn failed_init_never_runs_guest_probe() {
    let (sandbox, state) = fixture(true);
    state.lock().unwrap().reject_init = true;
    assert!(sandbox.wait_for_ready().await.is_err());
    assert_eq!(state.lock().unwrap().calls, ["health", "init"]);
}
#[tokio::test]
async fn failed_dax_remains_a_readiness_failure() {
    let (sandbox, state) = fixture(true);
    state.lock().unwrap().reject_dax = true;
    assert!(sandbox.wait_for_ready().await.is_err());
    assert_eq!(state.lock().unwrap().calls, ["health", "init", "dax"]);
}
#[tokio::test]
async fn failed_execution_remains_a_readiness_failure() {
    let (sandbox, state) = fixture(true);
    state.lock().unwrap().reject_exec = true;
    assert!(sandbox.wait_for_ready().await.is_err());
    assert_eq!(state.lock().unwrap().calls, ["health", "init", "dax", "dax", "exec"]);
}
#[tokio::test]
async fn ordinary_rootfs_still_initializes_once_without_native_checks() {
    let (mut sandbox, state) = fixture(false);
    sandbox.initial_guest_drive_mounts.push(());
    sandbox.wait_for_ready().await.unwrap();
    assert_eq!(state.lock().unwrap().calls, ["health", "init", "mount"]);
}
