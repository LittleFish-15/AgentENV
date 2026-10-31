"""Build a private native overlaybd-apply source fix, test, and convert D03/D10.

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
        CURRENT = subprocess.Popen(definition['argv'], cwd=cwd, env=env,
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
        LD_LIBRARY_PATH=str(PREFIX / 'lib') + ':' + str(PREFIX / 'lib64'),
        CMAKE_BUILD_PARALLEL_LEVEL='4', MAKEFLAGS='-j4',
        CFLAGS='-O2 -fPIC -I' + str(PREFIX / 'include'),
        CXXFLAGS='-O2 -fPIC -I' + str(PREFIX / 'include'),
        LDFLAGS='-L' + str(PREFIX / 'lib') + ' -Wl,-rpath,' + str(PREFIX / 'lib'))
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
    run('overlaybd-configure', ['cmake', '-S', src, '-B', build, *options], WORK, env)
    run('overlaybd-apply-build', ['cmake', '--build', build, '--parallel', '4', '--target', 'overlaybd-apply'], WORK, env)
    candidate = src / 'build/output/overlaybd-apply'
    need(candidate.is_file() and os.access(candidate, os.X_OK), 'Native candidate missing')
    libpath = env['LD_LIBRARY_PATH'] + ':' + str(e2fs / 'build/libext2fs/lib') + ':' + str(src / 'build/output')
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
CONVERT_WORKER_SHA = 'b00fc56e01968455fafd0ffdba3e00eadf9bc55a2f39a6f0bba8a930d23085f3'
CONVERT_WORKER_Z64 = 'eNqdWn1v47jR/9+fgtgClXz1iyy/e5ECjuPNBZeNg9hZXOEaAiVRsWpZMkQpibtPvvszQ1JvtnPXNsDdihQ5nDfO/GbkL1++PJoTEqchSbaMsHefJ374QkKa+K+MLF5ZHNDj9Q1xohCeExaTCJa+ReQQswONmUsWszvi7+kL461abUn3jDgxowlr08MhOLadaL/3E9yfxNRJCOWEJ1EM69uRpG67bR477SSKAt6OHL8VA6VFGBzhDP8VKJGYvaQBjYnnB4x/JWFE9lEaJg2yvPmtQW5TxuGZs/jVdxiJYnKgzg4OIH7IExoEIEsUtmpfvnyp+ftDFCdkS/k28O1s+C8ehdlzxGteHO2BRoJLiJp+hGG25AAUvSjeZ2O+TRM/yEcJTfLn1D7EkcM4z2YSf8+y5zT13VrtabFYkStxgK61t9Getf/1tmsD/2HSdrnNQmfbNA1z0DG6Ha1eu54u55+vZ4cgOu7hkcsZFr42KRs7A3PQtClngR8yIFKrucwjIWOuHu0aoGAKKqhPagT+fHgRgSJ2coh/MfU5I0+gc2B/HsdRrKstipLrg/0THZWmqAjaOG7FjEfBK9Pr5OpKqJXQ0BUPLZ9baFO93iDaXXhIE2FiYMf1Y+Yk4F1gzb3POfgkcI10tyC7Ml+Lb6nZH+jyxZsPlAXV6MBCXYttrS69DVjdF7LYDGzHgErEWx4aS5crWnh0GOn1er4UFhJnm4Y78CTig/PrAd3bLp0ooiAadfWOYfbILwT/ATlsTasXhwmOW+nBBTfWBamCOvXwOv0ZH0KPkucWTyxwGVRjxzR6qMbioNIal702SDH0w6g85P6/WXm8R5taIUfzlMgJ7nJq+UgQy0eSVj7MSeXmdLY0fJFmjN5CENf1PY/FXBkzZkkah6ChLXtXLpR5lBcFLij8okeB28QsECHKSiIdb1C9cKozfwNuHlUkkWGMQzyQnlh4muJIOb8gJKIh10vmLDHVwugXJoU5xeR+B/T0feSyKyMaGoZ8zRMiOWkJO5cMy5MLRhUhpLW07pY3d09qCZKUMiJ7xRz5KzEiwzQbhelyYaVoUXyUum8nxwMrGUDqGaykSyW90iBlStiYvgHLGBdbbro/cF28hCALccvasSO/WsU4ZiFPY2ZR7vj+1TcacJjzQxcUc2XWWxC6gEUwxN/gWvwz1P4sMIChFmmCfnPJLp/YpEyPupZ9TBiXJEEIoDjPcpqUHFgjkTwEUhgmjfyMwiMvBpT3TwKKurZvMUQIHc6sf82mvCDlWx3G4oofQ+f8iksjQBZksYX5QC9bAaIGBTOgSDSO6VE/CXxiba7leiu7QutJZ7CRMv1FZJnJ5Dr10XUnE0xulpNCDt5LXUHiTDj5IW/FZDITr4j+Oqq3cibWgw3woWeP4HPvhlcn/wf/joxi1ahYNZKrutVV6r6DFnRkq/X8fHejCy6upN1wbz1XC8ASC2GBTuMX3ij8uQEKs1mA7veqVBVEL3B24fFtoos14HpaC14qEwOiCBNde5iu7n7Mrdni4cf8aXm3eLCWq/njlQarcxKtELAMaNLcII0JvlOnCrOKC1DKPHDGiZ9ILyslUcbTACNBgQpaIKEegH/qe3pA54BgCqLWIYA6b+5VIXAloVz644nrh1clyjfzHw/P9/cNfAOcXElu/iNCLI7LlJarm8XzSij7Cv5rCAyDJAdZfIPLKYVrSQOjPxZyV3W+WizurW/Tu/vnp7lQeCnI/NR4wg7aJFO0Brc9mQExmDo74FQUDa0sMrMOT5iCEuoHSAwsUw4N6yYEWsOYbFouEzeHIaDhVxog2oA6AI8+6udGFmHmjAkMMwYc9SDxMjor8eBY5n7N0StIz+I9BDQcCAhbiTzS1ffUD/VKolMgsxXKEAoHaWJP3NHgwGmabCOIOPLcUlrzOZkCRg+OReCE6PPCEobRRdAxCtvAK7j+L3GUgvrXGxmqcAbWgpb6+UQqJ3olZUiyOdXTU/JsJl+8lOb7IACAyTLbcF8AxSqeEXchUEXYpXAuOmMb4KvXxuSYQv6SNk3YOwS8Fj8EfoJbKqkBZMc5zLpxwvGa6ro2o4e5501QifD4GO+zx+nezh7vwu1Eq5/gOCE0urKkiSeCM3U2DdIZ1E8coSTZHgIqIFaY/DeLI+LQA7V92OuzDAWBgtI95TsdMvlwCCpXMEPgGhW2ZLFlCdByRUTN0CZaNt/0EW3xFt4lmWUzQF7eWKWV5fcgoi6vLqxcl5LFs0VrDY3AtI3wytni++PTfLmc31hQC1p3D4/Pq6UFU4/TJ5h7WKys+e/z2fNqfqNJlJaTAWeRRNBZqhBGMSkqSyLFE9AHNOv5eJ2U8t6ieFfSiCxcm4X+mzxKY4d5/nvztaPlusVthbNhqEdn07Vkf0AfcKizZfjgRs6OxfgkcjTXztGg4KAtaEiKopIFnkSlBjxBUcZLxa7tKxtlJzfIAeuLkIjY+Hj3sGwBlNifoxxlVElfnSiwE+xVN406GLMrSxo4/7u1+K1e+GdR2IuQpUDhhGBALgSB+yarsCuyfhfsviObJTcQuv1OQ98DxjjYEq7c+1oTVsNRSO6+T2/nQqhN4UiAfvSMuJDAFEDtIE97TOMDVIEzPzkKsVYQ5kLfKTxXukMpWMTRG56VkTxRG7xdazTeD3oZpzdCkdL1CgbXYqHifYM1jHQ+hLPIiypmtDJ+F6U/AC++s1IOq6VjtbyYMfJ3YhqqMPzlly7QuwfTkASowItb/5rQV0gV1A6Y6GmUYoYIWPlJL0Fk0yC7+8rdtNyhSrcewXxpdYP8xKw4wyuDuVGM7tkrw7TYaYiUifFVpc1zygI4fRQXU96LEj0xXkFdASMNc1t+eW78+ISsvFP1bMESasfba8HIp6AEUjIQDXApLDQHZqfXg/12ALdSTQ76/e6gwiJ4CBqMBt+AHyWeJvjK3xQSfMC8H83DF+yLTCCEF4QO5qEkKQvRUPAoqhzcJmemqesn2XQDOX4BPBcfv3EFqfH0V1P7kLYEAAU2/Kn9uvg+xzd5AwcZfF7On3BSDe8Xtw9TuSybmT7c4nDWel59a460iua0x+nqV6XzLPTIcChCTl3A2HbK4zaHsXwSD3KIa6r07m+s+7vrp+nTP6zPSUM5okhj7LiwwKNBYFNnJ1dWT1h9f4QS98RPMASjl/x+c2vNprNf55ZS1iVnqpC7Wcx+mz8hrP92d3uyQQXy+kdmhvWZfFi9PD7d/Ziu5pUXuXSXd9UKcI9Rf73Jw1KWvC4EpiB6A/cQywEpilaCqP9g5iEKWT4nQ76arTSmsMx+b8jSEc9gYbpnMfaZxLHrLGFtTmCMjNmllBk5fhNulM01GIlNa81VAXI9nGzOQZAkoZoZWR8IY6na7UR7RLicudeIIUCxlVZVbi9Zxk5k2SVSm6RcL9HKOGmUQEFBX4lf7SrlOhZVtdBpqcA+oVvdsmNHcT0lH/e4VOWKyQWGpI1mosOdL6sY7mJo0179OEmpCGuQBjCIYVTb7zwOz8KuGZwUZz4jTJrk4lymiXn80Q+RQg4jPk5ls7CBcN5ALZVgsOi0y1MvdRjKfboy7aLwLhKU8j94zE7O0Ve+vEoF7RpADXFSyWvZvMx0X4n6pnCySpzXku+0Cl0AJTmJ8wZSLgPcsCoozjed4+GzO4G71xpIKlEFOhJiFzntlvDGBa+XPNc/yYPYz8NGdAEPlLt/vdjBEuENctHkMp+IoWl4LEyAWDPGrmVdtm1zI5R7pdk5XyHQwbyDXXr8ugJ6IRFUmLAQ+19Fm778h6ikYimsiMNEWrOBqjrfkx4Oojle2ScmW9gjAicQA0vdlkvrxCvtjLIoIE6bRRL1lZBU+S9vQ60zWF1ApKb82AViiEMbZbZAnYMeBopS40rL12Pv6qKqJIMSu2GSgBu9/inB1QTBtXjafBR4XC7b/ElvR2pFYBmhQZkexSQaXmqrNCllKKO/zyAaZr5vkj3cXdGr6pgk7wm2Vc5IiW+EmAVFmZ8l3+nj4/0/kKlmU33Vs6RSBKq9yoBGCenWN2ek4dIXoXRyUQhxegv+z0JXh8NEBP6ESQgcCS5by9TQUH60qX/uLmJf1fpi6jPjc0YD1MUlL5NRTagEs5jWyNPBRclLiOKy6HhWLhIQlRsy2qXtm8t85nsvub3k9o9UgyRO7kUm4UXVqNj8UwTYCRFZKouqk/8+pKLfeoXHZouBkCwq5MQJwIHXaTUTf3xyf2UAbQiuTyCJuKqZy/3cTWSC2G3Ebd7JHkRWRyn5Mray80/vURU9ZrydI8hqKjppSxc8qQJ4QhSMVPVwQ8XIkxI6X3axvv6jyi6KEo/fZxFOKgZFBX9grpiX4BFMlO51iHtCCZvTsPdHJlY46waq84zWoFepyBO2x0YrW4b0wLdRMqOHJIXz8zqvXqu07n+qzhf4nOpnI4r+tix/SsB+2P18pVpfU2s1hzGENWFA4T+lzulZF1v+lCJveKNKLkE7mBa/e5iJdOKWCtDlzW8zKLlKc6dHyMIMYSsgFKSq5b/7OM1rlR9xfCUYIEU49BknSZS3uJWiVXdbdJ/PTkVVRzGNj+JTFOYL/sQSCnU3cio/J2ohhBVR4Eo7EOoIulP8KcP84QfJ7CWw1SsNfFd86GTouoBSkS3wDKEZ7SNvieRFo/oRi9uU3pchEKnqyhei6/nt3YN1s7yeP8x+LVv3af64eFpp5x8I5MYSlJZU/+Qb6Wd0tPnDzX98fK32F4IOQiiqzHWhLrIZXA9iH8XPeoLIASUeUjvw+RZglfiBC74AXPfqRymHHCx/OcJcIBV5nu/4sEMmIho7W+wZospxE+5hb3lvdq/uvECGsduq1XInFRfmDCqBeQcjZ2B2jJ5jDIZu3xgxuzsejjud4bhrOp2e3R+6TscdDFnHGBl9OnaHlJn22Bz3mGcPTQevUkFXJlUgOxo7pmtQ1+kahm2Pu+7I7VPWH9Lu2DC6/dHQ7ZgedTzWsQejvjP2xh2v2+safXjbGbj9KlmVkYCuMbaHzB0MHGPYc0Zdx/XcDvN6FDd5cIbhsHF/2B8YvY7ZGxhdk477HW/U6RlD13DcDrhi0WWUUeQNKpWwGUKhtW32WvvjNqVvzHeCKHWxhGnv0hB8+qVJ/fw3QDSkwZH7vGmIv06naRqdHrhyGrpNs3kQXdOm4yfHCV6RSmb0nJHtsZFL2ZCNbXNEx2aXmf2hbY4H4+6wx3qDoecajI6Mrm1Sw+mNTLs7HPS8vttzx12RhP4HnvEnCgEElmYie7jnnLnmaOiZ3b4LejU7Xdq3meuapjdkpueN+3YfVD10+h4b0v7QcOnIpP1uzxj3euAd4CSg2xoAHsvCtrVliQrLsvBzmmVpEvvIb2u1/wdIf+K7'

if __name__ == '__main__':
    main()
