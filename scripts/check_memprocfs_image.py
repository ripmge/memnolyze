"""Offline MemProcFS image initialization check with native diagnostics enabled."""
import argparse
import json
import os
import struct
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--memprocfs-path', type=Path,
                        help='Directory containing memprocfs.py and matching native libraries')
    args = parser.parse_args()
    image = args.image.resolve(strict=True)
    if not image.is_file() or image.stat().st_size == 0:
        parser.error('Image must be a nonempty regular file')
    if struct.calcsize('P') != 8:
        parser.error('This diagnostic requires 64-bit Python')
    dll_directory = None
    vmm = None
    try:
        if args.memprocfs_path:
            directory = args.memprocfs_path.resolve(strict=True)
            if not (directory / 'memprocfs.py').is_file():
                raise ValueError('Configured directory must contain memprocfs.py')
            sys.path.insert(0, str(directory))
            if os.name == 'nt':
                dll_directory = os.add_dll_directory(str(directory))
        import memprocfs as m
        command = ['-device', str(image), '-printf', '-v', '-disable-python',
                   '-disable-symbolserver', '-disable-symbols', '-disable-yara']
        print(json.dumps({'python': sys.executable, 'python_version': sys.version,
                          'module_file': m.__file__, 'image_size': image.stat().st_size,
                          'arguments': command, 'scope': 'offline initialization only; no forensic scan'}, indent=2), flush=True)
        vmm = m.Vmm(command)
        system = vmm.get_config(m.OPT_CORE_SYSTEM)
        build = vmm.get_config(m.OPT_WIN_VERSION_BUILD)
        if system not in (m.SYSTEM_WINDOWS_X64, m.SYSTEM_WINDOWS_X86) or not 2600 <= build <= 100000:
            raise ValueError('Initialization did not provide plausible Windows metadata')
        print(json.dumps({'status': 'initialized', 'system': system, 'windows_build': build}), flush=True)
        return 0
    except Exception as exc:
        print(f'Initialization failed: {type(exc).__name__}: {exc}', file=sys.stderr, flush=True)
        return 2
    finally:
        try:
            if vmm is not None:
                vmm.close()
        finally:
            if dll_directory is not None:
                dll_directory.close()


if __name__ == '__main__':
    raise SystemExit(main())
