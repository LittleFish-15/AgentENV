"""Install only the two-node reviewed SP3 compiler dependency transaction."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


KERNEL = "6.6.0-145.3.34.165.oe2403sp3.aarch64"
REQUEST = ["gcc", "gcc-c++", "binutils", "make", "git", "clang-libs", "cmake",
           "openssl-devel", "protobuf-compiler", "elfutils-libelf-devel"]
ENV = {key: os.environ[key] for key in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                                       "http_proxy", "https_proxy", "no_proxy",
                                       "SSL_CERT_FILE", "SSL_CERT_DIR") if key in os.environ}
ENV.update(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL="C", HOME="/root")


EXPECTED_RPMS = (
    'binutils 0:2.41-28.oe2403sp3 aarch64',
    'clang-libs 0:17.0.6-63.oe2403sp3 aarch64',
    'cmake 0:3.27.9-8.oe2403sp3 aarch64',
    'elfutils-libelf-devel 0:0.190-10.oe2403sp3 aarch64',
    'gcc 0:12.3.1-111.oe2403sp3 aarch64',
    'gcc-c++ 0:12.3.1-111.oe2403sp3 aarch64',
    'git 0:2.43.0-14.oe2403sp3 aarch64',
    'make 1:4.4.1-2.oe2403sp3 aarch64',
    'openssl-devel 1:3.0.12-55.oe2403sp3 aarch64',
    'protobuf-compiler 0:25.1-13.oe2403sp3 aarch64',
    'libgcc 0:12.3.1-111.oe2403sp3 aarch64',
    'libgomp 0:12.3.1-111.oe2403sp3 aarch64',
    'libstdc++ 0:12.3.1-111.oe2403sp3 aarch64',
    'openssl 1:3.0.12-55.oe2403sp3 aarch64',
    'openssl-libs 1:3.0.12-55.oe2403sp3 aarch64',
    'abseil-cpp 0:20230802.1-6.oe2403sp3 aarch64',
    'clang-resource-filesystem 0:17.0.6-63.oe2403sp3 aarch64',
    'cmake-data 0:3.27.9-8.oe2403sp3 noarch',
    'cmake-filesystem 0:3.27.9-8.oe2403sp3 aarch64',
    'cmake-rpm-macros 0:3.27.9-8.oe2403sp3 noarch',
    'cpp 0:12.3.1-111.oe2403sp3 aarch64',
    'emacs-filesystem 1:29.1-11.oe2403sp3 noarch',
    'gc 0:8.2.4-1.oe2403sp3 aarch64',
    'git-core 0:2.43.0-14.oe2403sp3 aarch64',
    'glibc-devel 0:2.38-84.oe2403sp3 aarch64',
    'guile 5:2.2.7-6.oe2403sp3 aarch64',
    'jsoncpp 0:1.9.5-5.oe2403sp3 aarch64',
    'kernel-headers 0:6.6.0-145.3.39.170.oe2403sp3 aarch64',
    'libmpc 0:1.3.1-2.oe2403sp3 aarch64',
    'libstdc++-devel 0:12.3.1-111.oe2403sp3 aarch64',
    'libtool-ltdl 0:2.4.7-4.oe2403sp3 aarch64',
    'libxcrypt-devel 0:4.4.36-3.oe2403sp3 aarch64',
    'llvm-libs 0:17.0.6-63.oe2403sp3 aarch64',
    'perl-Error 1:0.17029-4.oe2403sp3 noarch',
    'perl-Git 0:2.43.0-14.oe2403sp3 noarch',
    'perl-TermReadKey 0:2.38-2.oe2403sp3 aarch64',
    'protobuf 0:25.1-13.oe2403sp3 aarch64',
    'zlib-devel 0:1.2.13-4.oe2403sp3 aarch64',
    'zstd-devel 0:1.5.5-3.oe2403sp3 aarch64',
    'compiler-rt 0:17.0.6-63.oe2403sp3 aarch64',
    'libatomic 0:12.3.1-111.oe2403sp3 aarch64',
    'openmp 0:17.0.6-63.oe2403sp3 aarch64',
    'openmp-devel 0:17.0.6-63.oe2403sp3 aarch64',
)

def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def run(args, seconds):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors="replace",
                            timeout=seconds, check=False, env=ENV)
    safe = [line[:280] for line in result.stdout.splitlines()
            if "://" not in line and not re.search(r"(?i)token|authorization|password", line)]
    print("\n".join(safe[-70:]), flush=True)
    return result.returncode, result.stdout


def main():
    require(os.getuid() == os.geteuid() == 0 and os.uname().release == KERNEL
            and os.uname().machine == "aarch64", "wrong host or running kernel")
    require(all(Path(path).is_file() for path in ("/usr/bin/dnf", "/usr/bin/rpm")), "missing RPM tools")
    before = subprocess.check_output(["/usr/bin/rpm", "-q", "kernel", "kernel-devel"], env=ENV)
    require(("kernel-" + KERNEL).encode() in before and ("kernel-devel-" + KERNEL).encode() in before,
            "running kernel or matching development package absent")
    expected = set(EXPECTED_RPMS)
    require(len(expected) == 43 and shutil.disk_usage(Path.cwd()).free >= 1024**3,
            "reviewed RPM manifest or private free space differs")
    with tempfile.TemporaryDirectory(prefix="sp3-build-rpms-", dir=Path.cwd()) as temp:
        staging = Path(temp)
        command = ["/usr/bin/dnf", "--noplugins", "--setopt=exit_on_lock=true",
                   "--setopt=timeout=15", "--setopt=retries=1"]
        code, _ = run(command + ["--assumeyes", "--downloadonly", f"--downloaddir={staging}",
                                 "install", *REQUEST], 700)
        require(code == 0, "download phase failed; no transaction started")
        packages = sorted(staging.glob("*.rpm"))
        require(len(packages) == len(expected), "downloaded RPM count differs; no transaction started")
        headers = set()
        for package in packages:
            info = subprocess.check_output(["/usr/bin/rpm", "-qp", "--qf",
                                           "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}", str(package)],
                                           text=True, env=ENV).strip()
            headers.add(info)
        require(headers == expected, "downloaded RPM identities differ; no transaction started")
        local = command + ["--disablerepo=*", "--setopt=localpkg_gpgcheck=1",
                           "--setopt=install_weak_deps=false"]
        files = [str(package) for package in packages]
        preview_code, log = run(local + ["--assumeno", "install", *files], 140)
        require(preview_code == 1 and "Dependencies resolved." in log
                and "Operation aborted." in log
                and re.search(r"(?m)^Install\s+38 Packages$", log)
                and re.search(r"(?m)^Upgrade\s+5 Packages$", log)
                and not re.search(r"(?mi)^\s*(remov|eras|downgrad|reinstall)", log),
                "offline transaction differs from reviewed install/upgrade counts")
        code, _ = run(local + ["--assumeyes", "install", *files], 400)
        require(code == 0, "package installation failed; reconcile installed package state")
    after = subprocess.check_output(["/usr/bin/rpm", "-q", "kernel", "kernel-devel"], env=ENV)
    require(after == before, "kernel package set changed")
    observed = {name: shutil.which(name, path=ENV["PATH"]) for name in ("gcc", "g++", "ld", "make", "git", "protoc")}
    require(all(observed.values()), "native tool set not ready")
    print(json.dumps({"status": "SP3_BUILD_DEPS_INSTALLED", "tools": observed,
                      "kernelPackagesUnchanged": True, "ubPackagesInstalled": False}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "SP3_BUILD_DEPS_STOPPED", "reason": str(error)[:350]}), flush=True)
        raise SystemExit(1)
