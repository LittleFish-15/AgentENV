#!/usr/bin/env python3
"""Read-only native-backing prerequisites; no SDK calls, Guest or allocation."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys


def main():
    result = {'status': 'READONLY_NATIVE_PREREQUISITES_NOT_A_CAPABILITY_PASS',
              'platform': platform.system(), 'architecture': platform.machine(),
              'SDK_called': False, 'allocated': False, 'Guest_created': False,
              'KVM_registration_tested': False, 'UB_FD_mapping_tested': False,
              'CC_readonly_tested': False, 'private_CoW_tested': False,
              'headers': {}}
    if sys.platform != 'linux':
        result['blocker'] = 'Native mappings require Linux'
        print(json.dumps(result, indent=2))
        return
    result['uid'] = os.geteuid()
    result['page_bytes'] = os.sysconf('SC_PAGE_SIZE')
    result['kvm_rw_access'] = os.access('/dev/kvm', os.R_OK | os.W_OK)
    feature = Path('/sys/bus/ub/ub_feature')
    try:
        first = feature.read_text().splitlines()[0].strip()
        value = int(first, 0)
        result['ub_feature_first_line'] = hex(value)
        result['NC_advertised_reference_bit2'] = bool(value & 4)
        result['CC_advertised_reference_bit3'] = bool(value & 8)
    except (OSError, ValueError, IndexError) as error:
        result['ub_feature_error'] = type(error).__name__
    # Fixed public include files only; no configuration, credentials or proc dump.
    for name in ('ubs_mem.h', 'ubs_mem_def.h', 'ubs_engine_mem.h', 'libobmm.h'):
        path = Path('/usr/include') / name
        try:
            raw = path.read_bytes()
            if len(raw) > 1024 * 1024:
                raise ValueError('Header exceeds read limit')
            text = raw.decode(errors='replace')
            signatures = re.findall(r'[^;{}\n]*\b(?:ubsmem_shmem_[a-z_]+|ubs_mem_fd_[a-z_]+)\s*\([^;{}]*\)\s*;', text)
            result['headers'][name] = {'sha256': hashlib.sha256(raw).hexdigest(),
                'selected_signatures': [re.sub(r'\s+', ' ', item).strip()[:1000] for item in signatures[:50]]}
        except (OSError, ValueError) as error:
            result['headers'][name] = {'error': type(error).__name__}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
