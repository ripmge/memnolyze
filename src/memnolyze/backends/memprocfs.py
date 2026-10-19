"""Isolated native API worker. No drive mount or Dokany required."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from ..io import child_env, write_json, utcnow

IMPORT_PROBE = r'''
import json, os, sys
from pathlib import Path
location = sys.argv[1]
dll_directory = None
if location:
    sys.path.insert(0, location)
    if os.name == 'nt':
        dll_directory = os.add_dll_directory(location)
import memprocfs
if not callable(getattr(memprocfs, 'Vmm', None)):
    raise ImportError('The imported memprocfs module does not expose the Vmm API')
module_file = str(Path(memprocfs.__file__).resolve())
native = sys.modules.get(memprocfs.Vmm.__module__)
native_file = getattr(native, '__file__', None)
print('MEMNOLYZE_PROBE=' + json.dumps({'module_file': module_file,
      'native_module_file': str(Path(native_file).resolve()) if native_file else None}))
'''

def discover(config: dict) -> dict:
    supplied = config['memprocfs_path']
    path = Path(supplied).resolve() if supplied else None
    result = {'available': False, 'path': str(path) if path else None,
              'configured_path': str(path) if path else None,
              'source': 'configured_directory' if path else 'python_import',
              'python_executable': sys.executable, 'check': 'native_api_import',
              'image_validated': False,
              'integration': 'Python API in isolated subprocess; image support checked during analysis'}
    if path and not (path / 'memprocfs.py').is_file():
        return {**result, 'error': 'memprocfs.py missing from configured directory'}
    try:
        probe = subprocess.run([sys.executable, '-c', IMPORT_PROBE, str(path) if path else ''],
                               capture_output=True, text=True, encoding='utf-8', errors='replace',
                               timeout=30, env=child_env(Path(config['state_dir'])))
        result['exit_code'] = probe.returncode
        if probe.returncode:
            diagnostic = (probe.stderr.strip() or probe.stdout.strip())[-1500:]
            return {**result, 'error': 'MemProcFS API import failed: ' +
                    (diagnostic or f'process exited with code {probe.returncode} without diagnostic output')}
        line = next((line for line in reversed(probe.stdout.splitlines())
                     if line.startswith('MEMNOLYZE_PROBE=')), None)
        if line is None:
            return {**result, 'error': 'MemProcFS import probe returned no module metadata'}
        metadata = json.loads(line.split('=', 1)[1])
        return {**result, **metadata, 'available': True,
                'path': str(Path(metadata['module_file']).parent), 'error': None}
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return {**result, 'error': str(exc)}

def worker(job_path: Path) -> int:
    job = json.loads(job_path.read_text(encoding='utf-8'))
    config = job['config']
    target = Path(job['target'])
    dll_directory = None
    if config['memprocfs_path']:
        location = str(Path(config['memprocfs_path']).resolve())
        sys.path.insert(0, location)
        if os.name == 'nt':
            dll_directory = os.add_dll_directory(location)
    import memprocfs as m
    args = ['-device', job['image'], '-disable-python', '-disable-yara']
    # Only the Microsoft symbol service is permitted when explicitly enabled.
    if job['offline'] or not config['memprocfs_symbols']:
        args += ['-disable-symbolserver', '-disable-symbols']
    if config['memprocfs_forensic']:
        args += ['-forensic', '2']
    write_json(target / 'invocation.json', {'arguments': args, 'started_at': utcnow()})
    vmm = m.Vmm(args)
    errors = []
    def export(name: str, value: Any) -> None:
        write_json(target / f'{name}.json', value)
    try:
        system = vmm.get_config(m.OPT_CORE_SYSTEM)
        build = vmm.get_config(m.OPT_WIN_VERSION_BUILD)
        if system not in (m.SYSTEM_WINDOWS_X64, m.SYSTEM_WINDOWS_X86) or not 2600 <= build <= 100000:
            raise ValueError('No plausible Windows OS metadata')
        version = '.'.join(str(vmm.get_config(getattr(m, 'OPT_CONFIG_VMM_VERSION_' + part)))
                           for part in ('MAJOR', 'MINOR', 'REVISION'))
        export('info', {'system': system, 'windows_build': build, 'version': version})
        processes, modules, regions, threads = [], [], [], []
        for process in vmm.process_list():
            if job['pid'] is not None and process.pid != job['pid']:
                continue
            record = {'pid': process.pid, 'ppid': process.ppid, 'name': process.name}
            for attr in ('eprocess', 'dtb', 'state', 'pathkernel', 'pathuser', 'cmdline'):
                try:
                    record[attr] = getattr(process, attr)
                except Exception as exc:
                    errors.append({'pid': process.pid, 'operation': attr, 'error': str(exc)})
            processes.append(record)
            try:
                for module in process.module_list():
                    modules.append({'pid': process.pid, 'name': module.name,
                                    'base': module.base, 'size': module.image_size})
            except Exception as exc:
                errors.append({'pid': process.pid, 'operation': 'modules', 'error': str(exc)})
            if job['profile'] != 'quick' or job['pid'] is not None:
                for name, destination in [('vad', regions), ('thread', threads)]:
                    try:
                        for row in getattr(process.maps, name)():
                            destination.append({'pid': process.pid, **row})
                    except Exception as exc:
                        errors.append({'pid': process.pid, 'operation': name, 'error': str(exc)})
        export('processes', processes)
        export('modules', modules)
        export('regions', regions)
        export('threads', threads)
        try:
            export('networks', vmm.maps.net())
        except Exception as exc:
            errors.append({'operation': 'networks', 'error': str(exc)})
        # Persist baseline before awaiting forensic processing.
        export('errors', errors)
        if config['memprocfs_forensic']:
            deadline = time.monotonic() + config['forensic_timeout_seconds']
            while True:
                progress = vmm.vfs.read('/forensic/progress_percent.txt', 64).decode().strip()
                if int(progress) == 100:
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError(f'Forensic processing incomplete ({progress}%)')
                time.sleep(1)
            listing = vmm.vfs.list('/forensic/findevil')
            export('findevil_listing', listing)
            if 'findevil.txt' not in listing:
                raise ValueError('Forensic complete but FindEvil artifact is unavailable')
            size = listing['findevil.txt']['size']
            if size > config['max_vfs_bytes']:
                raise ValueError('FindEvil artifact exceeds configured export limit')
            # Access can trigger asynchronous rendering. Read twice and require stable bytes.
            previous = None
            for _ in range(30):
                data = vmm.vfs.read('/forensic/findevil/findevil.txt', config['max_vfs_bytes'])
                if data == previous and data.strip():
                    break
                previous = data
                time.sleep(1)
            else:
                raise ValueError('FindEvil results did not become stable and nonempty')
            (target / 'findevil.txt').write_bytes(data)
            export('forensic', {'status': 'complete', 'progress': 100,
                                'source': '/forensic/findevil/findevil.txt'})
    finally:
        try:
            vmm.close()
        finally:
            if dll_directory is not None:
                dll_directory.close()
    return 0

if __name__ == '__main__':
    raise SystemExit(worker(Path(sys.argv[1])))
