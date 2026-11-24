#!/usr/bin/env python3
"""Inspect Linux prerequisites for the M/N Rust demand run, without host changes."""

import argparse
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


MIB = 1024 * 1024
SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin"
ENGINE_BYTES = 9_704_056
ENGINE_SHA = "22ce7d2f4309765d18e4df41a8a2941aacd023cac46d8f135aee0cd4a2e19d45"
TOOLS = (
    "git", "cargo", "rustc", "cc", "c++", "gcc", "ld", "make", "cmake",
    "pkg-config", "clang", "protoc", "openssl", "perl", "modinfo", "rpm",
    "mke2fs", "debugfs", "systemctl", "ip", "scp", "runuser", "stat", "ldconfig", "readelf",
    "rpm2cpio", "cpio", "ubsectl",
)
UNITS = (
    "ubse.service", "ubsmd.service", "aenv.service", "agentenv.service",
    "agentenv-ub-sdk.service", "agentenv-ub-device.service",
)
KCONFIG = (
    "CONFIG_KVM", "CONFIG_BLK_DEV_UBLK", "CONFIG_DAX", "CONFIG_FS_DAX",
    "CONFIG_EXT4_FS", "CONFIG_OBMM", "CONFIG_MODULES", "CONFIG_MODVERSIONS",
    "CONFIG_MODULE_SIG_FORCE", "CONFIG_USER_NS",
    "CONFIG_UB", "CONFIG_UB_UBUS", "CONFIG_UB_HISI_UBUS", "CONFIG_UB_UMMU_CORE",
    "CONFIG_UB_URMA", "CONFIG_IO_URING",
)


def read_text(path, limit=4096):
    try:
        with open(path, "rb") as source:
            data = source.read(limit + 1)
        return data.decode("utf-8", "replace").strip() if len(data) <= limit else None
    except OSError:
        return None


def file_facts(path, limit=None, process_executable=False):
    try:
        path = Path(path)
        # Read the running process's actual executable even if its package path was replaced.
        resolved = path if process_executable else path.resolve(strict=True)
        result = {"path": os.readlink(path) if process_executable else str(resolved)}
        info = resolved.stat()
        result.update(bytes=info.st_size, uid=info.st_uid, gid=info.st_gid,
                      mode=f"{stat.S_IMODE(info.st_mode):04o}")
        if stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
            result.update(major=os.major(info.st_rdev), minor=os.minor(info.st_rdev),
                          characterDevice=stat.S_ISCHR(info.st_mode))
        if limit is not None and stat.S_ISREG(info.st_mode) and info.st_size <= limit:
            flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
            fd = os.open(resolved, flags if process_executable else flags | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as source:
                current = os.fstat(source.fileno())
                identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                if not stat.S_ISREG(current.st_mode) or identity != (
                        current.st_dev, current.st_ino, current.st_size,
                        current.st_mtime_ns, current.st_ctime_ns):
                    return None
                digest = hashlib.sha256()
                remaining = info.st_size
                while remaining:
                    chunk = source.read(min(MIB, remaining))
                    if not chunk:
                        return None
                    digest.update(chunk)
                    remaining -= len(chunk)
                after = os.fstat(source.fileno())
                if identity != (after.st_dev, after.st_ino, after.st_size,
                                after.st_mtime_ns, after.st_ctime_ns):
                    return None
                result["sha256"] = digest.hexdigest()
        return result
    except (OSError, RuntimeError):
        return None


def trusted_tool(name):
    # Inspect only system tools. A PATH entry controlled by jwk is never run as root.
    candidate = shutil.which(name, path=SYSTEM_PATH)
    if not candidate:
        return None
    try:
        selected = Path(candidate)
        resolved = selected.resolve(strict=True)
        for path in set((resolved, *resolved.parents, *selected.parents)):
            info = path.stat()
            if info.st_uid or info.st_mode & 0o022:
                return None
        return candidate
    except (OSError, RuntimeError):
        return None


def command(name, *arguments, limit=32768):
    tool = trusted_tool(name)
    if not tool:
        return None
    try:
        result = subprocess.run(
            [tool, *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=4, check=False,
            env={"PATH": SYSTEM_PATH, "LANG": "C", "LC_ALL": "C", "HOME": "/root"},
        )
        return result.stdout.decode("utf-8", "replace") if len(result.stdout) <= limit else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def selected_version(program):
    candidate = trusted_tool(program)
    # Executing a rustup shim may fetch a missing default toolchain. Only report its path.
    if not candidate or Path(candidate).resolve().name == "rustup":
        return None
    output = command(program, "--version", limit=8192)
    return output.splitlines()[0][:160] if output and output.splitlines() else None


def parse_array(data):
    try:
        values = json.loads(data)
        return values if isinstance(values, list) else []
    except (TypeError, ValueError):
        return []


def network(expected, peer):
    links = parse_array(command("ip", "-j", "address", "show", limit=128 * 1024))
    local = {a.get("local") for link in links for a in link.get("addr_info", [])}
    routes = parse_array(command("ip", "-j", "route", "get", str(peer))) if peer else []
    route = routes[0] if routes else {}
    return {
        "expectedAddress": str(expected) if expected else None,
        "localAddressMatches": (str(expected) in local) if expected else None,
        "addressInventoryAvailable": bool(links), "peerAddress": str(peer) if peer else None,
        "peerRoute": {"device": route.get("dev"), "source": route.get("prefsrc", route.get("src")),
                      "type": route.get("type"), "hasGateway": "gateway" in route} if route else None,
        "tcpConnectivityTested": False,
    }


def local_account():
    accounts = (read_text("/etc/passwd", MIB) or "").splitlines()
    groups = (read_text("/etc/group", MIB) or "").splitlines()
    jwk = next((row.split(":") for row in accounts if row.startswith("jwk:")), None)
    group = next((row.split(":") for row in groups if row.startswith("jwk:")), None)
    return {
        "present": bool(jwk), "uid": jwk[2] if jwk and len(jwk) >= 7 else None,
        "gid": jwk[3] if jwk and len(jwk) >= 7 else None,
        "home": jwk[5] if jwk and len(jwk) >= 7 else None,
        "shell": jwk[6] if jwk and len(jwk) >= 7 else None,
        "groupGid": group[2] if group and len(group) >= 3 else None,
        "uid1204OccupiedByOther": any(row[0] != "jwk" and row[2] == "1204"
                                      for row in map(lambda value: value.split(":"), accounts) if len(row) >= 3),
        "gid1205OccupiedByOther": any(row[0] != "jwk" and row[2] == "1205"
                                      for row in map(lambda value: value.split(":"), groups) if len(row) >= 3),
        "ordinaryCargo": (file_facts("/home/jwk/.cargo/bin/cargo") if jwk else None),
    }


def os_release():
    keys = ("ID", "VERSION_ID", "PRETTY_NAME")
    lines = (read_text("/etc/os-release", 8192) or "").splitlines()
    result = {}
    for line in lines:
        key, _, value = line.partition("=")
        if key in keys:
            result[key] = value.strip('"\'')[:160]
    return result


def kernel_config(release, build):
    candidates = (Path("/proc/config.gz"), Path("/boot") / ("config-" + release), build / ".config")
    for path in candidates:
        try:
            if path.suffix == ".gz":
                with gzip.open(path, "rt", encoding="utf-8", errors="replace") as source:
                    text = source.read(MIB + 1)
                if len(text) > MIB:
                    continue
            else:
                text = read_text(path, MIB)
            if not text:
                continue
        except (OSError, EOFError):
            continue
        flags = {}
        for name in KCONFIG:
            match = re.search(rf"(?m)^(?:{name}=([ymn])|# {name} is not set)$", text)
            flags[name] = (match[1] or "n") if match else None
        return {"source": str(path), "flags": flags}
    return {"source": None, "flags": {}}


def module_info(name):
    fields = {}
    for line in (command("modinfo", name, limit=16384) or "").splitlines():
        key, _, value = line.partition(":")
        if key in ("filename", "vermagic", "srcversion", "signer", "depends", "sig_hashalgo"):
            fields[key] = value.strip()[:300]
    return fields


def kernel_facts(release):
    modules = Path("/lib/modules") / release
    build = modules / "build"
    module = Path("/sys/module/obmm")
    return {
        "release": release, "pageBytes": os.sysconf("SC_PAGE_SIZE"),
        "build": file_facts(build), "moduleSymvers": file_facts(build / "Module.symvers", 24 * MIB),
        "buildRelease": read_text(build / "include/config/kernel.release"),
        "generatedAutoconf": (build / "include/generated/autoconf.h").is_file(),
        "config": kernel_config(release, build),
        "ublk": {"loaded": Path("/sys/module/ublk_drv").is_dir(),
                 "installedModule": module_info("ublk_drv")},
        "ubFirmwareHints": directory_inventory("/sys/bus/acpi/devices", "HISI0581:", 16),
        "obmm": {
            "loaded": module.is_dir(), "srcversion": read_text(module / "srcversion"),
            "refcount": read_text(module / "refcnt"),
            "holders": directory_inventory(module / "holders", None, 16, include_names=True),
            "pmemReadonly": read_text(module / "parameters/pmem_ro_enable"),
            "pmemDemandWrite": read_text(module / "parameters/pmem_demand_write_enable"),
            "installedModule": module_info("obmm"), "modulesDisabled": read_text("/proc/sys/kernel/modules_disabled"),
            "signatureEnforced": read_text("/sys/module/module/parameters/sig_enforce"),
            "lockdown": read_text("/sys/kernel/security/lockdown"),
        },
    }


def directory_inventory(path, prefix, limit=256, include_names=False):
    try:
        found = []
        with os.scandir(path) as entries:
            for entry in entries:
                if prefix is None or entry.name.startswith(prefix):
                    found.append(entry.name)
                    if len(found) > limit:
                        break
        result = {"present": True, "count": min(len(found), limit), "truncated": len(found) > limit}
        if include_names:
            result["names"] = sorted(found[:limit])
        return result
    except OSError:
        return {"present": False, "count": 0, "truncated": False}


def service_facts():
    result = {name: {} for name in UNITS}
    allowed = {"Id", "LoadState", "ActiveState", "SubState", "MainPID", "User", "Group", "FragmentPath"}
    output = command("systemctl", "show", "--no-pager", "--property=" + ",".join(sorted(allowed)), *UNITS)
    for stanza in (output or "").strip().split("\n\n"):
        facts = dict(line.split("=", 1) for line in stanza.splitlines() if "=" in line)
        if facts.get("Id") in result:
            result[facts["Id"]] = {name: value[:250] for name, value in facts.items() if name in allowed}
    return result


def process_facts():
    names = ("ubse", "ubs-engine", "ubsmd", "uvm-ublk-daemon", "agentenv-ub-pro", "agentenv", "server")
    result = {name: [] for name in names}
    scanned = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            scanned += 1
            if scanned > 16384:
                break
            name = read_text(Path(entry.path) / "comm", 64)
            if name in result and len(result[name]) < 12:
                result[name].append(int(entry.name))
    return {name: sorted(pids) for name, pids in result.items() if pids}


def start_ticks(pid):
    value = read_text(f"/proc/{pid}/stat") or ""
    fields = value.rpartition(")")[2].split()
    return fields[19] if len(fields) > 19 else None


def engine_facts(services, processes):
    main = services["ubse.service"].get("MainPID", "0")
    candidates = [int(main)] if main.isdecimal() and int(main) else []
    candidates.extend(processes.get("ubse", []))
    candidates.extend(processes.get("ubs-engine", []))
    result = []
    for pid in dict.fromkeys(candidates[:5]):
        ticks = start_ticks(pid)
        if not ticks:
            continue
        facts = file_facts(f"/proc/{pid}/exe", 32 * MIB, process_executable=True)
        if not facts or start_ticks(pid) != ticks:
            continue
        supported = (facts.get("sha256") == ENGINE_SHA and facts["bytes"] == ENGINE_BYTES
                     and facts["uid"] == 0 and int(facts["mode"], 8) & 0o022 == 0)
        result.append({"pid": pid, "startTicks": ticks, "supportedByPinnedProvider": supported, **facts})
    return result


def sdk_facts():
    headers = {}
    for include in (Path("/usr/include"), Path("/usr/include/ub"), Path("/usr/local/include")):
        for name in ("ubs_mem.h", "ubs_mem_def.h", "ubs_engine_mem.h", "libobmm.h", "clang-c/Index.h", "openssl/ssl.h"):
            path = include / name
            facts = file_facts(path, MIB)
            if facts:
                headers[str(path)] = facts
    resolved = {}
    cached = command("ldconfig", "-p", limit=512 * 1024) or ""
    for line in cached.splitlines():
        if "=>" not in line:
            continue
        left, right = line.split("=>", 1)
        name = left.strip().partition(" ")[0]
        path = right.strip()
        if path.startswith("/") and name.startswith(("libubsm_sdk.so", "libclang", "libssl.so", "libcrypto.so")):
            resolved.setdefault(name, path)
    for directory in (Path("/usr/lib64"), Path("/usr/lib/aarch64-linux-gnu"), Path("/usr/local/lib")):
        for name in ("libubsm_sdk.so", "libssl.so", "libcrypto.so", "libclang.so"):
            if (directory / name).is_file():
                resolved.setdefault(name, str(directory / name))
    libraries = {name: file_facts(path, 32 * MIB if name.startswith("libubsm_sdk.so") else None)
                 for name, path in sorted(resolved.items())[:22]}
    names = ("ubsmem_initialize", "ubsmem_finalize", "ubsmem_shmem_allocate", "ubsmem_shmem_map",
             "ubsmem_shmem_lookup", "ubsmem_shmem_unmap", "ubsmem_shmem_deallocate")
    sdk = next((value for name, value in libraries.items() if name.startswith("libubsm_sdk.so") and value), None)
    symbols = command("readelf", "--dyn-syms", "--wide", sdk["path"], limit=256 * 1024) if sdk else None
    exports = set()
    for line in (symbols or "").splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].endswith(":") and fields[6] != "UND":
            exports.add(fields[7].split("@", 1)[0])
    feature = (read_text("/sys/bus/ub/ub_feature", 128) or "").splitlines()
    try:
        bits = hex(int(feature[0], 0)) if feature else None
    except ValueError:
        bits = None
    return {"headers": headers, "libraries": libraries, "opensslPkgConfig":
            (command("pkg-config", "--modversion", "openssl", limit=128) or "").strip() or None,
            "sdkSymbolsFound": [name for name in names if name in exports]
                               if symbols is not None else None,
            "ubFeatureBits": bits,
            "ubBusDevices": directory_inventory("/sys/bus/ub/devices", None),
            "regionDevices": directory_inventory("/sys/devices/obmm", "obmm_shmdev"),
            "uburmaDevices": directory_inventory("/dev", "uburma"),
            "knownBinarySha256": ENGINE_SHA, "knownBinaryBytes": ENGINE_BYTES,
            "SDKCalled": False, "FabricExercised": False}


def disk_facts():
    result = {}
    for raw in ("/", "/home", "/home/jwk", "/tmp"):
        path = Path(raw)
        if not path.exists():
            continue
        try:
            info = os.statvfs(path)
            filesystem = command("stat", "-f", "-c", "%T", "--", raw, limit=256)
            result[raw] = {"availableBytes": info.f_bavail * info.f_frsize, "freeInodes": info.f_favail,
                           "filesystem": filesystem.strip() if filesystem else None}
        except OSError:
            continue
    return result



def deployed_runtime_facts(processes):
    # Follow the running executable only for already observed named processes.
    running = {}
    for name in ("server", "agentenv", "uvm-ublk-daemon", "agentenv-ub-pro"):
        entries = []
        for pid in processes.get(name, [])[:3]:
            ticks = start_ticks(pid)
            facts = file_facts(f"/proc/{pid}/exe", 192 * MIB, process_executable=True)
            if facts and ticks and start_ticks(pid) == ticks:
                entries.append({"pid": pid, "startTicks": ticks, **facts})
        if entries:
            running[name] = entries
    locations = {}
    home = Path("/home/jwk")
    candidates = [Path("/usr/local/bin") / name for name in
                  ("aenv", "server", "uvm-ublk-daemon", "agentenv-ub-provider")]
    candidates.append(home / "agent" / "bin" / "libaenv-ub.so")
    builds = home / "agent" / "builds" / "rust-demand-207462625ee2"
    inventory = directory_inventory(builds, "attempt-", 24, include_names=True)
    names = [name for name in inventory.get("names", []) if re.fullmatch(r"attempt-\d+", name)]
    for name in sorted(names, reverse=True)[:2]:
        candidates.extend(builds / name / "stage" / file for file in
                          ("server", "uvm-ublk-daemon", "agentenv-ub-provider", "libaenv-ub.so"))
    for candidate in candidates:
        facts = file_facts(candidate, 192 * MIB)
        if facts:
            locations[str(candidate)] = facts
    return {"runningExecutables": running, "knownArtifactPaths": locations,
            "configInstalled": {path: Path(path).is_file() for path in
                                ("/etc/aenv/ub/sdk.json", "/etc/aenv/ub/device.json")},
            "newSdkOrGuestTestExecuted": False}


def probe(args):
    host = {"hostname": os.uname().nodename, "architecture": os.uname().machine,
            "machineId": read_text("/etc/machine-id", 64),
            "bootId": read_text("/proc/sys/kernel/random/boot_id", 64), "osRelease": os_release()}
    release = os.uname().release
    addresses = network(args.expected_address, args.peer_address)
    wrong_host = ((args.machine_id and host["machineId"] != args.machine_id)
                  or (args.boot_id and host["bootId"] != args.boot_id)
                  or (args.expected_address and addresses["localAddressMatches"] is not True))
    if wrong_host:
        return {"status": "EXPECTED_NODE_NOT_CONFIRMED", "node": args.node_label,
                "host": host, "network": addresses}, 2
    services = service_facts()
    processes = process_facts()
    engines = engine_facts(services, processes)
    kernel = kernel_facts(release)
    devices = {path: file_facts(path) for path in ("/dev/kvm", "/dev/ublk-control", "/dev/net/tun",
                                                  "/dev/obmm", "/dev/obmm_pmem")}
    tools = {name: trusted_tool(name) for name in TOOLS}
    account = local_account()
    sdk = sdk_facts()
    package_names = ("kernel", "kernel-devel", "ubs-engine", "ubs-engine-client-libs",
                     "ubs-mem-shmem", "ubs-comm-lib", "obmm", "obmm-devel", "rust", "cargo",
                     "libgcc", "libgomp", "libstdc++", "openssl", "openssl-libs")
    packages = (command("rpm", "-q", "--qf", "%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n",
                        *package_names) or "").splitlines()
    issues = []
    if host["architecture"] != "aarch64":
        issues.append("native Linux ARM64 required by the pinned Provider")
    if not kernel["moduleSymvers"] or not kernel["moduleSymvers"].get("sha256") or kernel["buildRelease"] != release:
        issues.append("kernel-devel tree and Module.symvers matching this running kernel not confirmed")
    if not any(path.endswith("/ubs_mem.h") for path in sdk["headers"]):
        issues.append("UB SDK public header not found in inspected system include paths")
    if not any(name.startswith("libubsm_sdk.so") and value for name, value in sdk["libraries"].items()):
        issues.append("UB SDK library not found in inspected system library paths")
    if not any(engine["supportedByPinnedProvider"] for engine in engines):
        issues.append("matching running UBSE executable not confirmed")
    if not devices["/dev/kvm"] or not devices["/dev/kvm"].get("characterDevice"):
        issues.append("no KVM character device was observed at /dev/kvm")
    if not tools["cargo"] and not account["ordinaryCargo"]:
        issues.append("Cargo not found in the inspected system paths or jwk Rustup directory")
    missing_tools = [name for name in ("git", "gcc", "c++", "ld", "make", "pkg-config", "protoc") if not tools[name]]
    if missing_tools:
        issues.append("build tools missing from inspected system PATH: " + ", ".join(missing_tools))
    if args.peer_address and not addresses["peerRoute"]:
        issues.append("peer route could not be observed locally")
    return {"status": "READ_ONLY_POST_DEPLOY_INVENTORY", "node": args.node_label,
            "host": host, "network": addresses, "account": account, "kernel": kernel,
            "devices": devices, "tools": tools,
            "versions": {name: selected_version(name) for name in ("cargo", "rustc", "cc", "c++", "protoc")},
            "services": services, "processes": processes, "engines": engines, "sdk": sdk,
            "deployment": deployed_runtime_facts(processes),
            "packages": [line for line in packages if line.partition(" ")[0] in package_names],
            "filesystems": disk_facts(), "issues": issues, "guestCreated": False,
            "SDKCalled": False, "servicesChanged": False, "kernelChanged": False}, 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-label", choices=("node-m", "node-n"))
    parser.add_argument("--expected-address", type=ipaddress.ip_address)
    parser.add_argument("--peer-address", type=ipaddress.ip_address)
    parser.add_argument("--machine-id")
    parser.add_argument("--boot-id")
    args = parser.parse_args()
    try:
        if sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0:
            result, exit_code = {"status": "ROOT_LINUX_REQUIRED"}, 2
        else:
            result, exit_code = probe(args)
    except (OSError, RuntimeError, ValueError) as error:
        result, exit_code = {"status": "READ_ONLY_INSPECTION_FAILED", "errorType": type(error).__name__,
                             "errno": getattr(error, "errno", None)}, 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
