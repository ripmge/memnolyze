"""Isolated native API worker. No drive mount or Dokany required."""
import importlib.util
import json
import sys
import time
from pathlib import Path
from typing import Any
from ..io import write_json, utcnow

def discover(config: dict) -> dict:
    supplied = config['memprocfs_path']
    path = Path(supplied).resolve() if supplied else None
    if path and not (path / 'memprocfs.py').is_file():
        return {'available': False, 'error': 'memprocfs.py missing from configured directory'}
    return {'available': bool(path or importlib.util.find_spec('memprocfs')),
            'path': str(path) if path else None,
            'integration': 'Python API in isolated subprocess; version queried after initialization'}

def worker(job_path: Path) -> int:
    job = json.loads(job_path.read_text(encoding='utf-8'))
    config = job['config']
    target = Path(job['target'])
    if config['memprocfs_path']:
        sys.path.insert(0, str(Path(config['memprocfs_path']).resolve()))
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
        vmm.close()
    return 0

if __name__ == '__main__':
    raise SystemExit(worker(Path(sys.argv[1])))
