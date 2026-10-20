"""Generate an experimental FC patch from exact reviewed source files; never edit them."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('Reviewed source anchor differs')
    return text.replace(before, after, 1)


def generate(source):
    manifest = json.loads((HERE / 'baseline.json').read_text())
    files = {}
    for name, expected in manifest['files'].items():
        raw = (source / name).read_bytes().replace(b'\r\n', b'\n')
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Reviewed FC file differs: ' + name)
        files[name] = raw.decode()
    changed = dict(files)
    base = 'src/vmm/src/devices/virtio/pmem/'
    changed[base + 'mod.rs'] = replace_once(files[base + 'mod.rs'], 'pub mod metrics;\n',
                                           'pub mod metrics;\npub mod native_fd;\n')
    device = files[base + 'device.rs']
    device = replace_once(device, '    BackingFileZeroSize,\n',
        '    BackingFileZeroSize,\n    /// Invalid inherited pmem backing: {0}\n    NativeBacking(std::io::Error),\n')
    device = replace_once(device,
        '        let (file, file_len, mmap_ptr, mmap_len) =\n            Self::mmap_backing_file(&config.path_on_host, config.read_only)?;',
        '''        let activate_event = EventFd::new(libc::EFD_NONBLOCK).map_err(PmemError::EventFd)?;
        let queue_events = vec![EventFd::new(libc::EFD_NONBLOCK).map_err(PmemError::EventFd)?];
        let (file, file_len, mmap_ptr, mmap_len) =
            match super::native_fd::NativePmemFd::parse(&config.path_on_host)
                .map_err(PmemError::NativeBacking)?
            {
                Some(backing) => backing
                    .map(config.read_only)
                    .map_err(PmemError::NativeBacking)?,
                None => Self::mmap_backing_file(&config.path_on_host, config.read_only)?,
            };''')
    device = replace_once(device,
        '            activate_event: EventFd::new(libc::EFD_NONBLOCK).map_err(PmemError::EventFd)?,',
        '            activate_event,')
    device = replace_once(device,
        '            queue_events: vec![EventFd::new(libc::EFD_NONBLOCK).map_err(PmemError::EventFd)?],',
        '            queue_events,')
    changed[base + 'device.rs'] = device
    changed[base + 'persist.rs'] = replace_once(files[base + 'persist.rs'],
        '        let queues = state.virtio_state.build_queues_checked(',
        '''        if super::native_fd::is_native_pmem_path(&state.config.path_on_host) {
            return Err(PmemPersistError::Pmem(PmemError::NativeBacking(
                std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "inherited native pmem needs durable backing reconstruction; raw FD restore refused",
                ),
            )));
        }
        let queues = state.virtio_state.build_queues_checked(''')
    changed['src/vmm/src/lib.rs'] = replace_once(files['src/vmm/src/lib.rs'],
        '        use self::MicrovmStateError::SaveVmState;\n',
        '''        use self::MicrovmStateError::SaveVmState;
        if self.full_config().pmem_devices.iter().any(|config| {
            crate::devices::virtio::pmem::native_fd::is_native_pmem_path(&config.path_on_host)
        }) {
            return Err(MicrovmStateError::NotAllowed(
                "inherited native pmem cannot be saved without durable backing references".into(),
            ));
        }
''')
    native_name = base + 'native_fd.rs'
    changed[native_name] = (HERE / 'native_fd.rs').read_text().replace('\r\n', '\n')
    result = []
    for name in sorted(changed):
        before = files.get(name, '')
        result.extend(difflib.unified_diff(before.splitlines(True), changed[name].splitlines(True),
            fromfile='a/' + name if name in files else '/dev/null', tofile='b/' + name))
    return ''.join(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='A matching, complete FC source checkout')
    parser.add_argument('output', type=Path, help='New patch file; existing files are preserved')
    args = parser.parse_args()
    patch = generate(args.source)
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(patch)


if __name__ == '__main__':
    main()
