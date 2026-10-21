"""Public-header SDK adapter; no private SDK descriptor tables."""
import ctypes
from pathlib import Path

CHUNK = 1024 * 1024

class SdkError(RuntimeError):
    def __init__(self, operation, rc):
        super().__init__(f'SDK {operation} failed: rc={rc}')
        self.operation, self.rc = operation, rc



class NativeBackend:
    def __init__(self, library, inspection_limit=256 * CHUNK):
        self.lib = ctypes.CDLL(str(library))
        self.lib.aenv_ub_abi_version.argtypes = []
        self.lib.aenv_ub_abi_version.restype = ctypes.c_int
        if self.lib.aenv_ub_abi_version() != 3:
            raise ValueError('UB adapter ABI mismatch')
        self.lib.aenv_ub_configure_region.argtypes = [ctypes.c_char_p]
        self.lib.aenv_ub_configure_region.restype = ctypes.c_int
        self.mappings = []
        self.inspection_limit = inspection_limit
        self.coverage_by_object = {}
        self.allocation_calls = 0
        i, q, p = ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p
        declarations = {
            'allocate': [ctypes.c_char_p, q],
            'map': [ctypes.c_char_p, q, i, ctypes.POINTER(i), ctypes.POINTER(q)],
            'read': [i, q, p, q], 'write': [i, q, p, q],
            'unmap': [i], 'deallocate': [ctypes.c_char_p], 'finalize': [],
            'initialize': [],
        }
        for name, args in declarations.items():
            fn = getattr(self.lib, 'aenv_ub_' + name)
            fn.argtypes, fn.restype = args, i

    def call(self, operation, *args):
        rc = getattr(self.lib, 'aenv_ub_' + operation)(*args)
        if operation not in ('read', 'write'):
            print(f'SDK_PHASE={operation} rc={rc}', flush=True)
        if rc:
            raise SdkError(operation, rc)

    def allocate(self, replica):
        self.allocation_calls += 1
        self.call('allocate', replica.objectName.encode(), replica.mappingBytes)

    def initialize(self):
        self.call('initialize')

    def configure_region(self, region):
        self.call('configure_region', region.encode())

    def map(self, replica, writable=False):
        handle, coverage = ctypes.c_int(), ctypes.c_uint64()
        rc = self.lib.aenv_ub_map(replica.objectName.encode(), replica.mappingBytes,
                                int(writable), ctypes.byref(handle), ctypes.byref(coverage))
        print(f'SDK_PHASE=map rc={rc} backing_coverage_bytes={coverage.value}', flush=True)
        mapped = None
        if handle.value:
            mapped = NativeMapping(self, handle.value)
            self.mappings.append(mapped)
        if rc:
            raise SdkError('map', rc)
        if mapped is None or not replica.mappingBytes <= coverage.value <= self.inspection_limit:
            raise ValueError('Invalid/post-creation backing coverage exceeds inspection limit')
        mapped.backing_coverage = coverage.value
        self.coverage_by_object[replica.objectName] = coverage.value
        if sum(self.coverage_by_object.values()) > self.inspection_limit:
            raise ValueError('Unique object coverage exceeds post-map inspection budget; not a hard physical quota')
        return mapped

    def deallocate(self, replica):
        self.call('deallocate', replica.objectName.encode())

    def close_maps(self):
        failures = []
        for mapped in self.mappings:
            try:
                mapped.close()
            except Exception as error:
                failures.append(str(error))
        if failures:
            raise RuntimeError('; '.join(failures))

    def finalize(self):
        self.call('finalize')



class NativeMapping:
    def __init__(self, backend, handle):
        self.backend, self.handle, self.closed = backend, handle, False

    def read(self, offset, count):
        if self.closed or not 0 < count <= CHUNK:
            raise ValueError('Invalid/closed bounded read')
        out = ctypes.create_string_buffer(count)
        self.backend.call('read', self.handle, offset, out, count)
        return out.raw

    def write(self, offset, data):
        if self.closed or not 0 < len(data) <= CHUNK:
            raise ValueError('Invalid/closed bounded write')
        self.backend.call('write', self.handle, offset, ctypes.create_string_buffer(data), len(data))

    def close(self):
        if not self.closed:
            self.backend.call('unmap', self.handle)
            self.closed = True
