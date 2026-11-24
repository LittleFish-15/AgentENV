"""Preview M/N SP3 prerequisite transactions. No package or service changes."""

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile


KERNEL = "6.6.0-145.3.34.165.oe2403sp3.aarch64"
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
BUILD_PACKAGES = ["gcc", "gcc-c++", "binutils", "make", "git", "clang-libs", "cmake",
                  "openssl-devel", "protobuf-compiler", "elfutils-libelf-devel"]
UB_PACKAGES = [
    "ubs-mem-shmem-1.0.0-14.oe2403sp3.aarch64",
    "ubs-engine-1.0.1-1.oe2403sp3.aarch64",
    "ubs-engine-client-libs-1.0.1-1.oe2403sp3.aarch64",
    "ubs-comm-lib-1.0.0-27.oe2403sp3.aarch64",
    "obmm-1.0-3.oe2403sp3.aarch64",
    "obmm-devel-1.0-3.oe2403sp3.aarch64",
]


def run(cmd, timeout, **kwargs):
    try:
        result = subprocess.run(cmd, stdin=subprocess.DEVNULL, timeout=timeout, check=False,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", **kwargs)
        lines = result.stdout.splitlines()
        # Keep diagnostics and transaction rows while excluding URLs/credentials.
        clean = [line[:300] for line in lines if "://" not in line
                 and not re.search(r"(?i)authorization|password|token|bearer", line)]
        return {"exitCode": result.returncode, "lines": clean[-100:]}
    except subprocess.TimeoutExpired:
        return {"exitCode": None, "reason": "deadline exceeded"}


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--machine-id", required=True)
    cli.add_argument("--boot-id", required=True)
    args = cli.parse_args()
    if not (os.getuid() == os.geteuid() == 0
            and os.uname().machine == "aarch64" and os.uname().release == KERNEL
            and pathlib.Path("/etc/machine-id").read_text().strip() == args.machine_id
            and pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == args.boot_id):
        raise SystemExit("unexpected host identity; no prerequisite operations run")
    candidates = ("dnf", "rpm", "gcc", "ld", "make", "git", "rustc", "cargo", "curl", "ubsectl")
    tools = {name: shutil.which(name, path=PATH) for name in candidates}
    env = {key: os.environ[key] for key in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy",
                                           "http_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR")
           if key in os.environ}
    env.update(PATH=PATH, LC_ALL="C", HOME="/root")
    report = {"status": "MN_SP3_PACKAGE_PREVIEW", "packagesInstalled": False, "servicesChanged": False,
              "modulesChanged": False, "tools": tools, "release": KERNEL}
    if tools["rpm"]:
        report["existingKernel"] = run([tools["rpm"], "-q", "kernel", "kernel-devel"], 10, env=env)
    # Keep DNF metadata and logs private to this job instead of changing system repositories.
    if tools["dnf"]:
        with tempfile.TemporaryDirectory(prefix="dnf-preview-", dir=pathlib.Path.cwd()) as tmp:
            base = [tools["dnf"], "--assumeno", "--noplugins", f"--setopt=cachedir={tmp}/cache",
                    f"--setopt=persistdir={tmp}/state", f"--setopt=logdir={tmp}/log",
                    "--setopt=history_record=false", "--setopt=exit_on_lock=true",
                    "--setopt=timeout=8", "--setopt=retries=1"]
            report["buildPreview"] = run(base + ["install", *BUILD_PACKAGES], 95, env=env)
            report["ubPreview"] = run(base + ["install", *UB_PACKAGES], 95, env=env)
            report["rustVersions"] = run(base + ["--cacheonly", "repoquery", "--latest-limit", "2",
                                                 "rust", "cargo"], 15, env=env)
    else:
        report["dnf"] = "not present"
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
