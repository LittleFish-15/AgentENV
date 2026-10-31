"""Build a private native overlaybd-apply source fix, test, and convert selected Titanic only.

Runs after dropping to jwk; never installs system packages, creates units or
mounts. All dependency install prefixes are inside this experiment directory.
"""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import resource
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import urllib.request
import zlib

ROOT = Path('/home/jwk/agent/dsbench-20261031')
WORK = ROOT / 'apply-sourcefix-v1'
PREFIX = WORK / 'prefix'
CURRENT = None


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    need(path.resolve() == path and path.is_file(), 'Redirected or missing file')
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024**2), b''):
            h.update(data)
    return h.hexdigest()


def directory(path):
    need(path.is_relative_to(ROOT) and path.resolve() == path, 'Build path outside experiment')
    if not path.exists():
        directory(path.parent)
        path.mkdir(mode=0o700)
    s = path.stat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 1204 and not s.st_mode & 0o022,
         'Unexpected build directory owner/type')


def save(path, value):
    raw = json.dumps(value, sort_keys=True, indent=2).encode() + b'\n'
    if path.exists():
        need(path.resolve() == path and path.read_bytes() == raw, 'Existing different build record preserved')
    else:
        with path.open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def run(label, args, cwd, env, timeout=1800):
    global CURRENT
    record = WORK / 'steps' / (label + '.json')
    definition = {'argv': list(map(str, args)), 'cwd': str(cwd)}
    if record.exists():
        old = json.loads(record.read_bytes())
        need(old['definition'] == definition and old['exitCode'] == 0, 'Different prior build phase preserved')
        print('BUILD_PHASE_REUSED=' + label, flush=True)
        return
    log = WORK / 'logs' / (label + '.log')
    need(not log.exists(), 'Incomplete native build phase preserved: ' + label)
    print('BUILD_PHASE=' + label, flush=True)
    with log.open('xb') as output:
        build_env = dict(env)
        build_env.pop('LD_LIBRARY_PATH', None)
        CURRENT = subprocess.Popen(definition['argv'], cwd=cwd, env=build_env,
                                   stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = CURRENT.wait(timeout=timeout)
        finally:
            if CURRENT.poll() is None:
                os.killpg(CURRENT.pid, signal.SIGKILL)
                CURRENT.wait(timeout=10)
            CURRENT = None
    save(record, {'definition': definition, 'exitCode': code})
    if code:
        print('BUILD_LOG_FAILURE=' + json.dumps({'phase': label, 'exitCode': code,
              'log': str(log), 'tail': log.read_bytes()[-16000:].decode(errors='replace')}), flush=True)
    need(code == 0, 'Native build failed; log and sources preserved: ' + label)


def source(name):
    spec = next(row for row in SOURCE_LOCK if row['name'] == name)
    archive = WORK / 'archives' / (name + '.tar.gz')
    if not archive.exists():
        for attempt in range(2):
            try:
                with urllib.request.urlopen(urllib.request.Request(spec['url'], headers={
                        'User-Agent': 'AgentENV-private-native-build'}), timeout=45) as response:
                    raw = response.read(spec['bytes'] + 1)
                need(len(raw) == spec['bytes'] and sha(raw) == spec['sha256'], 'Source archive identity differs')
                with archive.open('xb') as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                break
            except Exception as error:
                print('SOURCE_FETCH=' + json.dumps({'source': name, 'attempt': attempt + 1,
                      'errorType': type(error).__name__}), flush=True)
                if attempt:
                    raise
    need(file_sha(archive) == spec['sha256'], 'Cached source archive differs')
    target = WORK / 'src' / name
    stamp = target / '.source-record.json'
    if stamp.exists():
        need(json.loads(stamp.read_bytes())['sha256'] == spec['sha256'], 'Prior source differs')
        return target
    directory(target)
    need(not any(target.iterdir()), 'Partial source extraction preserved: ' + name)
    with tarfile.open(archive, 'r:gz') as tar:
        entries = tar.getmembers()
        need(len(entries) < 100000 and sum(x.size for x in entries) < 2 * 1024**3,
             'Source extraction exceeds limits')
        roots = {PurePosixPath(x.name).parts[0] for x in entries}
        need(len(roots) == 1, 'Unexpected source archive layout')
        selected = []
        for member in entries:
            path = PurePosixPath(member.name)
            need(not path.is_absolute() and '..' not in path.parts, 'Unsafe source archive path')
            if len(path.parts) == 1:
                continue
            member.name = str(PurePosixPath(*path.parts[1:]))
            destination = target / member.name
            need(destination.resolve().is_relative_to(target), 'Source path escaped')
            need(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                 'Special source archive object refused')
            if member.islnk():
                link = PurePosixPath(member.linkname)
                need(link.parts[0] in roots and '..' not in link.parts and not link.is_absolute(), 'Hardlink escaped')
                member.linkname = str(PurePosixPath(*link.parts[1:]))
            if member.issym():
                need(not Path(member.linkname).is_absolute() and
                     (destination.parent / member.linkname).resolve().is_relative_to(target), 'Symlink escaped')
            member.mode &= 0o755
            selected.append(member)
        tar.extractall(target, members=selected)
    save(stamp, {'sha256': spec['sha256'], 'url': spec['url']})
    return target


def cmake_package(name, src, env, options=()):
    build = WORK / 'build' / name
    directory(build)
    run(name + '-configure', ['cmake', '-S', src, '-B', build, '-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_INSTALL_PREFIX=' + str(PREFIX), '-DCMAKE_INSTALL_LIBDIR=lib',
        '-DCMAKE_PREFIX_PATH=' + str(PREFIX), *options], WORK, env)
    run(name + '-build', ['cmake', '--build', build, '--parallel', '4'], WORK, env)
    run(name + '-private-install', ['cmake', '--install', build], WORK, env)


def resume_loader_failure():
    marker = WORK / 'resume-loader-env-v2.json'
    record = WORK / 'steps/curl-configure.json'
    log = WORK / 'logs/curl-configure.log'
    if marker.exists():
        need(json.loads(marker.read_bytes())['state'] == 'KNOWN_LOADER_FAILURE_ARCHIVED', 'Different resume record preserved')
        return
    need(record.resolve() == record and log.resolve() == log, 'Prior phase path redirected')
    need(record.is_file() and log.is_file(), 'Expected 005 curl loader failure records missing')
    old = json.loads(record.read_bytes()); raw = log.read_bytes()
    argv = old.get('definition', {}).get('argv', [])
    need(old.get('exitCode') == 127 and old.get('definition', {}).get('cwd') == str(WORK)
         and argv[:3] == ['cmake', '-S', str(WORK / 'src/curl')]
         and b'/usr/lib64/libldap.so.2: undefined symbol: EVP_md2, version OPENSSL_3.0.0' in raw,
         'Failure differs from the confirmed host cmake loader error; preserve it')
    archived = []
    for path in (record, log):
        info = path.stat(); target = path.with_name(path.stem + '.loader-failure-005' + path.suffix)
        need(info.st_uid == 1204 and stat.S_ISREG(info.st_mode) and not target.exists()
             and not target.is_symlink(), 'Unexpected prior failure archive metadata')
        os.link(path, target)  # Preserve exact prior bytes/inode before retiring its old filename.
        path.unlink()
        archived.append({'path': str(target), 'sha256': file_sha(target)})
    save(marker, {'state': 'KNOWN_LOADER_FAILURE_ARCHIVED', 'archived': archived,
                  'change': 'Host build commands run without LD_LIBRARY_PATH; candidate runtime uses private path'})
    print('KNOWN_CMAKE_LOADER_FAILURE_ARCHIVED', flush=True)


def repair_private_e2fs_sdk(e2fs, env):
    sdk = e2fs / 'build/libext2fs/include'
    installed = e2fs / 'build/v1.47.0-opt/include'
    directory(sdk)
    need(installed.is_dir() and installed.resolve() == installed, 'Private ext2fs install headers missing')
    copied = []
    total = 0
    for src in sorted(installed.rglob('*')):
        if not src.is_file():
            continue
        resolved = src.resolve()
        need(resolved.is_relative_to(installed) and resolved.stat().st_uid == 1204,
             'Installed SDK header escaped or owner differs')
        raw = resolved.read_bytes(); total += len(raw)
        need(total < 8 * 1024**2 and len(copied) < 512, 'Private SDK header bounds exceeded')
        dest = sdk / src.relative_to(installed)
        directory(dest.parent)
        need(dest.resolve() == dest, 'SDK target redirected')
        if dest.exists():
            need(dest.read_bytes() == raw, 'Existing different SDK header preserved')
        else:
            with dest.open('xb') as f:
                f.write(raw)
        copied.append({'file': str(dest.relative_to(sdk)), 'sha256': sha(raw)})
    # This public header is also present in the exact pinned source tree.
    header = e2fs / 'lib/et/com_err.h'
    need(file_sha(header) == COM_ERR_HEADER_SHA, 'Pinned error-library header differs')
    target = sdk / 'et/com_err.h'; directory(target.parent)
    if target.exists():
        need(target.read_bytes() == header.read_bytes(), 'Installed error-library header differs')
    else:
        with target.open('xb') as f:
            f.write(header.read_bytes())
    # No system ldconfig is needed for an unprivileged private prefix.
    script = e2fs / 'build.sh'
    body = script.read_text()
    if 'make install-libs LDCONFIG=:' not in body:
        need(body.count('make install-libs') == 1, 'Unknown private dependency install script')
        body = body.replace('make install-libs', 'make install-libs LDCONFIG=:')
    legacy_copy = 'cp -r ${VERSION}/include/ext2fs libext2fs/include'
    complete_copy = 'cp -r ${VERSION}/include/. libext2fs/include/'
    if legacy_copy in body:
        need(body.count(legacy_copy) == 1, 'Unknown SDK packaging rule')
        body = body.replace(legacy_copy, complete_copy)
    need(complete_copy in body, 'Private SDK packaging rule incomplete')
    script.write_text(body)
    config = e2fs / 'build/MCONFIG'
    need(config.resolve() == config and config.is_file(), 'Private e2fs build configuration missing')
    lines = config.read_text().splitlines(True)
    indices = [i for i, line in enumerate(lines) if line.startswith('LDCONFIG =')]
    need(len(indices) == 1, 'Unknown private ldconfig rule')
    lines[indices[0]] = 'LDCONFIG = :\n'
    config.write_text(''.join(lines))
    need('LDCONFIG = :\n' in config.read_text(), 'Private cache-refresh hook not disabled')
    probe = WORK / 'e2fs-header-probe-v3.cpp'
    raw = b'#include <sys/types.h>\n#include <stdint.h>\n#include <ext2fs/ext2fs.h>\n'
    if probe.exists():
        need(probe.read_bytes() == raw, 'Different SDK probe preserved')
    else:
        probe.write_bytes(raw)
    run('e2fs-sdk-header-probe-v3', ['g++', '-E', '-x', 'c++', '-I' + str(sdk),
        '-I' + str(PREFIX / 'include'), str(probe), '-o', str(WORK / 'e2fs-header-probe-v3.i')], WORK, env, 60)
    record = {'state': 'PRIVATE_E2FS_SDK_COMPLETE_SYSTEM_LDCONFIG_DISABLED',
              'headers': copied, 'comErrSha256': file_sha(target), 'preprocessProbePassed': True,
              'systemPackagesChanged': False}
    save(WORK / 'e2fs-sdk-repair-v3.json', record)
    print('PRIVATE_E2FS_SDK_REPAIRED', flush=True)


def resume_header_failure():
    marker = WORK / 'resume-e2fs-header-v3.json'
    if marker.exists():
        need(json.loads(marker.read_bytes())['state'] == 'KNOWN_HEADER_FAILURE_ARCHIVED', 'Different native resume state')
        return
    record = WORK / 'steps/overlaybd-apply-build.json'
    log = WORK / 'logs/overlaybd-apply-build.log'
    need(record.resolve() == record and log.resolve() == log and record.is_file() and log.is_file(),
         'Expected 006 build failure missing')
    old = json.loads(record.read_bytes()); raw = log.read_bytes()
    argv = old.get('definition', {}).get('argv', [])
    need(old.get('exitCode') == 2 and old.get('definition', {}).get('cwd') == str(WORK)
         and argv == ['cmake', '--build', str(WORK / 'build/overlaybd'), '--parallel', '4', '--target', 'overlaybd-apply']
         and b'fatal error: et/com_err.h: No such file or directory' in raw,
         'Native failure differs; original evidence preserved')
    archived = []
    for path in (record, log):
        info = path.stat(); target = path.with_name(path.stem + '.header-failure-006' + path.suffix)
        need(info.st_uid == 1204 and stat.S_ISREG(info.st_mode) and not target.exists() and not target.is_symlink(),
             'Unexpected native failure archive metadata')
        os.link(path, target); path.unlink()
        archived.append({'file': str(target), 'sha256': file_sha(target)})
    save(marker, {'state': 'KNOWN_HEADER_FAILURE_ARCHIVED', 'archived': archived})
    print('KNOWN_E2FS_HEADER_FAILURE_ARCHIVED', flush=True)


def main():
    need(platform.node() == 'server1', 'Build is A only')
    if os.geteuid() == 0:
        os.setgroups([]); os.setgid(1205); os.setuid(1204)
    need(os.getuid() == os.geteuid() == 1204 and os.getgid() == 1205, 'Build must run as jwk')
    for line in Path('/proc/self/status').read_text().splitlines():
        if line.startswith(('CapEff:', 'CapPrm:', 'CapAmb:', 'CapInh:')):
            need(int(line.split()[1], 16) == 0, 'Build must have zero capabilities')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SystemExit(143)))
    os.umask(0o077)
    directory(WORK)
    for name in ('archives', 'src', 'build', 'steps', 'logs', 'tmp', 'cache', 'prefix'):
        directory(WORK / name)
    required = ('gcc', 'g++', 'make', 'cmake', 'perl', 'pkg-config', 'sh', 'bash')
    missing = [name for name in required if not shutil.which(name)]
    need(not missing, 'Missing native build tools (no system install): ' + ','.join(missing))
    need(shutil.disk_usage(WORK).free > 20 * 1024**3, 'Need 20GiB private workspace')
    env = dict(os.environ)
    env.update(HOME='/home/jwk', USER='jwk', LOGNAME='jwk',
        PATH=str(PREFIX / 'bin') + ':/usr/sbin:/usr/bin:/sbin:/bin',
        TMPDIR=str(WORK / 'tmp'), XDG_CACHE_HOME=str(WORK / 'cache'),
        PKG_CONFIG_PATH=str(PREFIX / 'lib/pkgconfig') + ':' + str(PREFIX / 'lib64/pkgconfig'),
        CMAKE_BUILD_PARALLEL_LEVEL='4', MAKEFLAGS='-j4',
        CFLAGS='-O2 -fPIC -I' + str(PREFIX / 'include'),
        CXXFLAGS='-O2 -fPIC -I' + str(PREFIX / 'include'),
        LDFLAGS='-L' + str(PREFIX / 'lib') + ' -Wl,-rpath,' + str(PREFIX / 'lib'))
    env.pop('LD_LIBRARY_PATH', None)  # Host cmake/make must use their system ABI.
    resume_loader_failure()
    # Bootstrap only missing autotools, always under the private prefix.
    for name, program in [('m4', 'm4'), ('autoconf', 'autoreconf'), ('automake', 'automake'), ('libtool', 'libtoolize')]:
        if not shutil.which(program, path=env['PATH']):
            src = source(name)
            run(name + '-configure', [src / 'configure', '--prefix=' + str(PREFIX)], src, env)
            run(name + '-build', ['make', '-j4'], src, env)
            run(name + '-private-install', ['make', 'install'], src, env)
    src = source('zlib')
    run('zlib-configure', [src / 'configure', '--prefix=' + str(PREFIX)], src, env)
    run('zlib-build', ['make', '-j4'], src, env)
    run('zlib-private-install', ['make', 'install'], src, env)
    src = source('aio')
    run('aio-build', ['make', '-j4'], src, env)
    run('aio-private-install', ['make', 'prefix=' + str(PREFIX), 'install'], src, env)
    cmake_package('zstd', source('zstd') / 'build/cmake', env,
        ['-DZSTD_BUILD_PROGRAMS=OFF', '-DZSTD_BUILD_TESTS=OFF', '-DZSTD_BUILD_SHARED=ON'])
    src = source('lz4')
    run('lz4-build', ['make', '-j4'], src, env)
    run('lz4-private-install', ['make', 'PREFIX=' + str(PREFIX), 'install'], src, env)
    src = source('openssl')
    run('openssl-configure', ['perl', src / 'Configure', 'linux-aarch64', '--prefix=' + str(PREFIX),
        '--openssldir=' + str(PREFIX / 'ssl'), '--libdir=lib', 'shared', 'no-tests'], src, env)
    run('openssl-build', ['make', '-j4'], src, env)
    run('openssl-private-install', ['make', 'install_sw'], src, env)
    cmake_package('curl', source('curl'), env, ['-DBUILD_CURL_EXE=OFF', '-DBUILD_TESTING=OFF',
        '-DBUILD_SHARED_LIBS=ON', '-DCURL_USE_OPENSSL=ON', '-DOPENSSL_ROOT_DIR=' + str(PREFIX),
        '-DCURL_USE_LIBPSL=OFF', '-DCURL_USE_LIBSSH2=OFF', '-DUSE_NGHTTP2=OFF',
        '-DCURL_DISABLE_LDAP=ON', '-DCURL_DISABLE_LDAPS=ON'])
    src = source('overlaybd')
    file = src / 'src/tools/overlaybd-apply.cpp'
    old = file.read_bytes()
    need(sha(old) in (APPLY_BEFORE_SHA, APPLY_AFTER_SHA), 'Native source does not match reviewed baseline')
    if sha(old) == APPLY_BEFORE_SHA:
        patched = old.replace(BEFORE_BYTES, AFTER_BYTES)
        need(sha(patched) == APPLY_AFTER_SHA, 'Native patch differs')
        file.write_bytes(patched)
    photon = source('photon'); e2fs = source('e2fsprogs'); erofs = source('erofs-utils'); rapid = source('rapidjson')
    ocf = source('ocf'); ocf_target = src / 'src/overlaybd/cache/ocf_cache/ocf'
    need(not ocf_target.is_symlink(), 'OCF source redirected')
    if not (ocf_target / '.source-record.json').exists():
        need(not ocf_target.exists() or not any(ocf_target.iterdir()), 'Unexpected OCF files')
        shutil.copytree(ocf, ocf_target, dirs_exist_ok=True, symlinks=True)
    # Only resource tuning in a fresh private dependency checkout.
    script = e2fs / 'build.sh'
    body = script.read_text().replace('make -j8', 'make -j4')
    script.write_text(body)
    build = WORK / 'build/overlaybd'; directory(build)
    options = ['-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_INSTALL_PREFIX=' + str(PREFIX),
        '-DCMAKE_PREFIX_PATH=' + str(PREFIX), '-DBUILD_CURL_FROM_SOURCE=OFF',
        '-DBUILD_STREAM_CONVERTOR=OFF', '-DBUILD_TCMU=OFF', '-DBUILD_TESTING=OFF',
        '-DBUILD_STATIC_TOOLS=OFF', '-DENABLE_DSA=OFF', '-DENABLE_ISAL=OFF', '-DENABLE_QAT=OFF',
        '-DFETCHCONTENT_FULLY_DISCONNECTED=ON', '-DFETCHCONTENT_SOURCE_DIR_PHOTON=' + str(photon),
        '-DFETCHCONTENT_SOURCE_DIR_E2FSPROGS=' + str(e2fs),
        '-DFETCHCONTENT_SOURCE_DIR_EROFS-UTILS=' + str(erofs),
        '-DFETCHCONTENT_SOURCE_DIR_RAPIDJSON=' + str(rapid)]
    repair_private_e2fs_sdk(e2fs, env)
    for library in ('libcurl.so', 'libssl.so', 'libcrypto.so', 'libzstd.a', 'libaio.a'):
        path = PREFIX / 'lib' / library
        need(path.is_file() and path.resolve().is_relative_to(PREFIX), 'Private link input missing or escaped: ' + library)
    options.extend(['-DCURL_LIBRARY=' + str(PREFIX / 'lib/libcurl.so'),
        '-DCURL_LIBRARY_RELEASE=' + str(PREFIX / 'lib/libcurl.so'),
        '-DCURL_INCLUDE_DIR=' + str(PREFIX / 'include'), '-DOPENSSL_ROOT_DIR=' + str(PREFIX),
        '-DOPENSSL_SSL_LIBRARY=' + str(PREFIX / 'lib/libssl.so'),
        '-DOPENSSL_CRYPTO_LIBRARY=' + str(PREFIX / 'lib/libcrypto.so'),
        '-DLIBZSTD=' + str(PREFIX / 'lib/libzstd.a'), '-DAIO_LIBRARIES=' + str(PREFIX / 'lib/libaio.a'),
        '-DAIO_INCLUDE_DIR=' + str(PREFIX / 'include')])
    run('overlaybd-private-link-configure-v3', ['cmake', '-S', src, '-B', build, *options], WORK, env)
    resume_header_failure()
    run('overlaybd-apply-build', ['cmake', '--build', build, '--parallel', '4', '--target', 'overlaybd-apply'], WORK, env)
    candidate = src / 'build/output/overlaybd-apply'
    need(candidate.is_file() and os.access(candidate, os.X_OK), 'Native candidate missing')
    libpath = str(PREFIX / 'lib') + ':' + str(PREFIX / 'lib64') + ':' + str(e2fs / 'build/libext2fs/lib') + ':' + str(e2fs / 'build/v1.47.0-opt/lib') + ':' + str(src / 'build/output')
    env['LD_LIBRARY_PATH'] = libpath
    help_result = subprocess.run([str(candidate), '--help'], capture_output=True, env=env, cwd=WORK, timeout=15)
    need(help_result.returncode == 0, 'Private apply --help failed before conversion')
    missing_config = str(WORK / 'explicit-missing-config.json')
    negative = subprocess.run([str(candidate), '--service_config_path=' + missing_config,
        str(ROOT / 'prepared-inputs.json'), str(ROOT / 'prepared-inputs.json')],
        capture_output=True, env=env, cwd=WORK, timeout=15)
    need(negative.returncode > 0 and missing_config.encode() in negative.stderr
         and b'terminate called' not in negative.stderr, 'Final explicit path validation not confirmed')
    result = {'state': 'PRIVATE_NATIVE_APPLY_BUILT_AND_PARSER_TESTED', 'candidate': str(candidate),
              'sha256': file_sha(candidate), 'sourceBefore': APPLY_BEFORE_SHA, 'sourceAfter': APPLY_AFTER_SHA,
              'privateLibraryPath': libpath, 'hostDefaultConfigPresent': Path('/etc/overlaybd/overlaybd.json').exists(),
              'explicitMissingConfigRejected': True, 'SDKCalled': False, 'GuestCreated': False,
              'buildLinkage': 'native glibc/private dependency prefix; original tools remain musl static',
              'sourceLockSha256': sha(json.dumps(SOURCE_LOCK, sort_keys=True).encode())}
    save(WORK / 'candidate.json', result)
    print('PRIVATE_NATIVE_APPLY_READY=' + json.dumps(result), flush=True)
    worker = zlib.decompress(base64.b64decode(CONVERT_WORKER_Z64))
    need(sha(worker) == CONVERT_WORKER_SHA, 'Conversion worker differs')
    scope = {'__name__': '__main__', 'PRIVATE_APPLY': str(candidate), 'PRIVATE_LIBRARY_PATH': libpath}
    exec(compile(worker, '<dsbench-convert-sourcefix>', 'exec'), scope)


# The exact source lock, patch and existing native conversion worker are appended
# by the local preparation step. They contain no credentials.

SOURCE_LOCK = [{'name': 'aio', 'url': 'https://sources.buildroot.net/libaio/libaio-0.3.113.tar.gz', 'expected': '2c44d1c5fd0d43752287c9ae1eb9c023f04ef848ea8d4aafa46e9aedb678200b', 'sha256': '2c44d1c5fd0d43752287c9ae1eb9c023f04ef848ea8d4aafa46e9aedb678200b', 'bytes': 49980}, {'name': 'curl', 'repo': 'curl/curl', 'commit': '57495c64871d18905a0941db9196ef90bafe9a29', 'url': 'https://codeload.github.com/curl/curl/tar.gz/57495c64871d18905a0941db9196ef90bafe9a29', 'sha256': '0c7df3d2730de54d3e8eaa557c04ba60c5b68dab7a3904afd45b8de2bb72dc47', 'bytes': 3464188}, {'name': 'e2fsprogs', 'repo': 'data-accelerator/e2fsprogs', 'commit': '404deb95e6b0ed0ceb0148d289977e65bee7f8d0', 'expected': '2c3efbc3f98c6db52425fe4f5d04194c3f4abbb2676388617c57127c3d30a5a1', 'url': 'https://codeload.github.com/data-accelerator/e2fsprogs/tar.gz/404deb95e6b0ed0ceb0148d289977e65bee7f8d0', 'sha256': '2c3efbc3f98c6db52425fe4f5d04194c3f4abbb2676388617c57127c3d30a5a1', 'bytes': 9686901}, {'name': 'erofs-utils', 'repo': 'erofs/erofs-utils', 'commit': 'eec6f7a2755dfccc8f655aa37cf6f26db9164e60', 'expected': '4cccdb0932dd3c2ca0595451463e0819be8e14d99961c896f91f6f6a90082158', 'url': 'https://codeload.github.com/erofs/erofs-utils/tar.gz/eec6f7a2755dfccc8f655aa37cf6f26db9164e60', 'sha256': '4cccdb0932dd3c2ca0595451463e0819be8e14d99961c896f91f6f6a90082158', 'bytes': 186465}, {'name': 'lz4', 'repo': 'lz4/lz4', 'commit': 'ebb370ca83af193212df4dcbadcc5d87bc0de2f0', 'url': 'https://codeload.github.com/lz4/lz4/tar.gz/ebb370ca83af193212df4dcbadcc5d87bc0de2f0', 'sha256': 'eb1a93e934d4fd29df6e2061ba0bf447568561764d758f4a5662c0e29370ffa9', 'bytes': 387536}, {'name': 'ocf', 'repo': 'Open-CAS/ocf', 'commit': 'c2dd2259e47c2e5e72dc77f99d0150a5d05496d7', 'expected': 'b67a4cda8e940ab68b3f67995c04d1d6da1e3a8299dfef7136cd1a4626c61cf8', 'url': 'https://codeload.github.com/Open-CAS/ocf/tar.gz/c2dd2259e47c2e5e72dc77f99d0150a5d05496d7', 'sha256': 'b67a4cda8e940ab68b3f67995c04d1d6da1e3a8299dfef7136cd1a4626c61cf8', 'bytes': 364310}, {'name': 'openssl', 'repo': 'openssl/openssl', 'commit': 'c3cc0f1386b0544383a61244a4beeb762b67498f', 'url': 'https://codeload.github.com/openssl/openssl/tar.gz/c3cc0f1386b0544383a61244a4beeb762b67498f', 'sha256': '2a0d6d2469d33c1f8c2e1f7de712602d2bd9892d9aeadb2b7618ee947923333e', 'bytes': 15355875}, {'name': 'overlaybd', 'repo': 'kvcache-ai/overlaybd', 'commit': 'df60cf3ae062f28563ee4a14687af27e9d17c20a', 'url': 'https://codeload.github.com/kvcache-ai/overlaybd/tar.gz/df60cf3ae062f28563ee4a14687af27e9d17c20a', 'sha256': '7417c4d0f3abb0ac6b0f991508d06f3e95edddbc5b3b8021554f2d17c2764cfd', 'bytes': 1509677}, {'name': 'photon', 'repo': 'alibaba/PhotonLibOS', 'commit': '0178d14499d8639759a81e32ad58da5226df5e9b', 'expected': 'b5d4a1fad757df6808e83108b2b311d310807e54c06ab9eef7896a2ece2647b0', 'url': 'https://codeload.github.com/alibaba/PhotonLibOS/tar.gz/0178d14499d8639759a81e32ad58da5226df5e9b', 'sha256': 'b5d4a1fad757df6808e83108b2b311d310807e54c06ab9eef7896a2ece2647b0', 'bytes': 1058675}, {'name': 'rapidjson', 'repo': 'Tencent/rapidjson', 'commit': '80b6d1c83402a5785c486603c5611923159d0894', 'url': 'https://codeload.github.com/Tencent/rapidjson/tar.gz/80b6d1c83402a5785c486603c5611923159d0894', 'sha256': '458dba865f6df41fd0c2150a1bbf1897b92b3e750e7aae2f9481b6f05a423699', 'bytes': 1110569}, {'name': 'zlib', 'repo': 'madler/zlib', 'commit': '51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf', 'url': 'https://codeload.github.com/madler/zlib/tar.gz/51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf', 'sha256': 'd9e270d46252734aa49770fbc544125391617956266f220bd63216c834f3a522', 'bytes': 1572004}, {'name': 'zstd', 'repo': 'facebook/zstd', 'commit': 'f8745da6ff1ad1e7bab384bd1f9d742439278e99', 'url': 'https://codeload.github.com/facebook/zstd/tar.gz/f8745da6ff1ad1e7bab384bd1f9d742439278e99', 'sha256': '4b0bd1f0cfb25e61b9103c35f27395530ff5b4c0d2513a00fd745849e85ea52c', 'bytes': 2453329}, {'name': 'm4', 'url': 'https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.gz', 'sha256': '3be4a26d825ffdfda52a56fc43246456989a3630093cced3fbddf4771ee58a70', 'bytes': 2953876, 'optionalBootstrap': True}, {'name': 'autoconf', 'url': 'https://ftp.gnu.org/gnu/autoconf/autoconf-2.72.tar.gz', 'sha256': 'afb181a76e1ee72832f6581c0eddf8df032b83e2e0239ef79ebedc4467d92d6e', 'bytes': 2143794, 'optionalBootstrap': True}, {'name': 'automake', 'url': 'https://ftp.gnu.org/gnu/automake/automake-1.17.tar.gz', 'sha256': '397767d4db3018dd4440825b60c64258b636eaf6bf99ac8b0897f06c89310acd', 'bytes': 2451070, 'optionalBootstrap': True}, {'name': 'libtool', 'url': 'https://ftp.gnu.org/gnu/libtool/libtool-2.5.4.tar.gz', 'sha256': 'da8ebb2ce4dcf46b90098daf962cffa68f4b4f62ea60f798d0ef12929ede6adf', 'bytes': 2016535, 'optionalBootstrap': True}]
APPLY_BEFORE_SHA = 'f908c59df6340b3146db266f2d382364fe8507fd7042c79a9a0ad6c917cc7a71'
APPLY_AFTER_SHA = '152474b43b0e58903e66d7c7f08960c3776cb1bb39483635c20aa500497fe8d9'
BEFORE_BYTES = b'->check(CLI::ExistingFile)->default_val("/etc/overlaybd/overlaybd.json")'
AFTER_BYTES = b'->default_val("/etc/overlaybd/overlaybd.json")->check(CLI::ExistingFile)'
CONVERT_WORKER_SHA = 'ce810604deaf6b7b8656144b1560d6eab075bdaa825ae4294432e3a32b44e122'
CONVERT_WORKER_Z64 = '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'

COM_ERR_HEADER_SHA = 'dd3888db3ee874593eb2aba59985514fa68c6190fdc43aef2d339855114f5bbc'

if __name__ == '__main__':
    main()
