import hashlib
from pathlib import Path


_NAMES = ('recovery.py', 'recovery_reports.py', 'recovery_bootargs.py', 'recovery_bootplist.py',
          'recovery_nvram_panic.py', 'recovery_panic_control.py', 'panic-source-preflight.py',
          'recovery_arrival.py', 'kdp_registry.py', 'recovery_netdump_settings.py', 'recovery_sources.py',
          'recovery_netdump.py', 'kdp_udp_preflight.py', 'kdp_crashdump.py', 'recovery_netdump_capture.py',
          'udp_observer.py')


def source_files(main_path):
    main_path = Path(main_path)
    return tuple((name, main_path if name == 'recovery.py' else main_path.with_name(name)) for name in _NAMES)


def identity(main_path):
    return hashlib.sha256(b'\0'.join(path.read_bytes() for _, path in source_files(main_path))).hexdigest()
