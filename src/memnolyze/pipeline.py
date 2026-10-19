"""Sequential, restartable case orchestration with immutable raw attempts."""
import hashlib
import logging
import subprocess
import sys
import time
import uuid
from pathlib import Path
from .backends import volatility, memprocfs
from .config import PROFILES
from .detectors import detect
from .io import fingerprint, write_json, read_json, execute, child_env, rows, utcnow
from .normalizers import normalize
from .reporting import render

def analyze(image: Path, case: Path, config: dict, profile: str, backend: str,
            offline: bool, resume: bool, pid: int | None, only: list[str] | None,
            rerun: list[str] | None = None) -> int:
    image, case = image.resolve(strict=True), case.resolve()
    if not image.is_file():
        raise ValueError('Image path must point to a regular file')
    if case == image or image.is_relative_to(case):
        raise ValueError('Case directory must not contain the input image')
    manifest_path = case / 'manifest.json'
    if case.exists() and any(case.iterdir()) and not (resume and manifest_path.is_file()):
        raise ValueError('Output must be empty; use --resume for an existing case')
    previous = read_json(manifest_path) if resume and manifest_path.exists() else None
    if previous and (previous['pid'] != pid or previous['offline'] != offline or previous['config'] != config):
        raise ValueError('Resume requires the same configuration, offline policy and PID scope')
    logging.info('Hashing input image (streaming SHA-256)')
    metadata = fingerprint(image)
    if previous and previous['image']['sha256'] != metadata['sha256']:
        raise ValueError('Resume refused: input hash differs from existing case')
    for directory in ('logs', 'raw', 'normalized', 'exports'):
        (case / directory).mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(case / 'logs/analyzer.log', encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logging.getLogger().addHandler(handler)
    lock = case / '.analysis.lock'
    # Exclusive create protects raw attempts and manifest against concurrent resumes.
    try:
        lock_stream = lock.open('x')
    except FileExistsError:
        raise ValueError('Case is locked. Verify no analyzer is running before removing .analysis.lock')
    lock_stream.write(str(__import__('os').getpid()))
    lock_stream.close()
    started = time.monotonic()
    manifest = previous or {'schema_version': 1, 'created_at': utcnow(), 'image': metadata,
                            'pid': pid, 'offline': offline, 'config': config, 'executions': [],
                            'backend_info': {}, 'capabilities': {}}
    manifest.update(status='running', updated_at=utcnow(), profile=profile)
    write_json(case / 'config.json', config)
    write_json(manifest_path, manifest)
    def checkpoint() -> None:
        manifest['updated_at'] = utcnow()
        write_json(manifest_path, manifest)
        write_json(case / 'logs/plugin_execution.json', manifest['executions'])
    def latest(engine: str, plugin: str) -> dict | None:
        records = [e for e in manifest['executions'] if e['backend'] == engine and e['plugin'] == plugin]
        return records[-1] if records else None
    def reusable(engine: str, plugin: str) -> bool:
        record = latest(engine, plugin)
        if not record or record['status'] not in ('success', 'empty'):
            return False
        if engine == 'memprocfs' and profile != 'quick' and pid is None:
            cached_profile = record.get('profile')
            if cached_profile is None:
                job_path = (case / record['source_file']).parent / 'job.json'
                cached_profile = read_json(job_path).get('profile') if job_path.is_file() else None
            if cached_profile not in ('standard', 'deep'):
                return False
        for source, digest in record.get('artifact_hashes', {}).items():
            path = case / source
            if not path.is_file() or file_hash(path) != digest:
                raise ValueError(f'Cached artifact integrity check failed: {source}')
        return bool(record.get('artifact_hashes'))
    try:
        engines = ['volatility', 'memprocfs'] if backend == 'all' else [backend]
        for engine in engines:
            capability = (volatility if engine == 'volatility' else memprocfs).discover(config)
            manifest['capabilities'][engine] = capability
            checkpoint()
            if not capability['available']:
                manifest['executions'].append({'backend': engine, 'plugin': 'discovery',
                    'status': 'unavailable', 'error': capability.get('error', 'Backend not installed')})
                checkpoint()
                continue
            plugins = (only or config['plugins'] or PROFILES[profile]) if engine == 'volatility' else ['triage']
            # Always establish OS metadata, including in targeted reruns.
            if engine == 'volatility':
                plugins = list(dict.fromkeys(['info', *plugins]))
            for plugin in plugins:
                if not plugin.replace('_', '').isalnum():
                    raise ValueError('Plugin selection must use logical names from the profile registry')
                if plugin not in (rerun or []) and reusable(engine, plugin):
                    logging.info('Reusing %s/%s', engine, plugin)
                    continue
                token = uuid.uuid4().hex[:12]
                target = case / 'raw' / engine / f'{plugin}-{token}'
                target.mkdir(parents=True)
                record = {'backend': engine, 'plugin': plugin, 'profile': profile, 'status': 'running', 'started_at': utcnow(),
                          'source_file': (target / 'output.jsonl').relative_to(case).as_posix()}
                manifest['executions'].append(record)
                checkpoint()
                logging.info('Running %s/%s', engine, plugin)
                try:
                    if engine == 'volatility':
                        cmd = volatility.build_command(config, capability, image, plugin, offline, pid)
                        if cmd is None:
                            record.update(status='unsupported', error='Plugin not advertised by installed backend')
                            checkpoint()
                            continue
                    else:
                        job = target / 'job.json'
                        write_json(job, {'image': str(image), 'target': str(target), 'config': config,
                                         'offline': offline, 'profile': profile, 'pid': pid})
                        cmd = [sys.executable, '-m', 'memnolyze.backends.memprocfs', str(job)]
                    result = execute(cmd, target / 'output.jsonl', target / 'stderr.txt',
                                     config['timeout_seconds'] + (config['forensic_timeout_seconds'] if engine == 'memprocfs' else 0),
                                     child_env(Path(config['state_dir'])))
                    record.update(result)
                    record['stderr_file'] = (target / 'stderr.txt').relative_to(case).as_posix()
                    if engine == 'volatility' and record['status'] == 'success':
                        count, info = 0, []
                        for row in rows(target / 'output.jsonl'):
                            count += 1
                            if plugin == 'info':
                                info.append(row)
                        record['record_count'] = count
                        if plugin == 'info':
                            if not volatility.plausible_info(info):
                                raise ValueError('Plugin did not provide plausible OS metadata')
                            manifest['backend_info']['volatility'] = {'version': capability['version'], 'os': info}
                        if count == 0:
                            # Completed empty output is distinct from a successful positive extraction.
                            record['status'] = 'empty'
                            if plugin in ('info', 'pslist'):
                                raise ValueError('Required baseline plugin produced no records')
                    elif engine == 'memprocfs':
                        artifacts = {p.stem: p.relative_to(case).as_posix() for p in target.glob('*.json')
                                     if p.stem not in ('job', 'invocation')}
                        if (target / 'findevil.txt').exists():
                            artifacts['findevil'] = (target / 'findevil.txt').relative_to(case).as_posix()
                        record['artifacts'] = artifacts
                        if 'info' in artifacts:
                            manifest['backend_info']['memprocfs'] = read_json(case / artifacts['info'])
                            if record['status'] != 'success' and 'processes' in artifacts:
                                record['status'] = 'partial'
                            if 'errors' in artifacts:
                                errors = read_json(case / artifacts['errors'])
                                record['extraction_errors'] = len(errors)
                                if any(e.get('operation') in ('modules', 'networks', 'vad', 'thread') for e in errors):
                                    record['status'] = 'partial'
                        elif record['status'] == 'success':
                            raise ValueError('MemProcFS returned without OS metadata')
                    sources = list(record.get('artifacts', {}).values()) if engine == 'memprocfs' else [record['source_file']]
                    record['artifact_hashes'] = {s: file_hash(case / s) for s in sources if (case / s).is_file()}
                except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    record.update(status='failed', error=str(exc))
                checkpoint()
                if record['status'] == 'interrupted':
                    raise KeyboardInterrupt
        current = {}
        for entry in manifest['executions']:
            current[(entry['backend'], entry['plugin'])] = entry
        for entry in current.values():
            if entry['status'] in ('success', 'empty', 'partial'):
                for source, digest in entry.get('artifact_hashes', {}).items():
                    if file_hash(case / source) != digest:
                        raise ValueError(f'Artifact integrity check failed before normalization: {source}')
        data = normalize(case, list(current.values()))
        data['findings'] = detect(data)
        for name, content in data.items():
            write_json(case / 'normalized' / f'{name}.json', content)
        manifest['counts'] = {k: len(v) for k, v in data.items()}
        # Every requested backend must initialize for a full success.
        initialized = all(e in manifest['backend_info'] for e in engines)
        failures = any(e['status'] not in ('success', 'empty', 'unsupported') for e in current.values())
        manifest['status'] = 'complete' if initialized and not failures else 'partial' if manifest['backend_info'] else 'failed'
        manifest['last_run_duration_seconds'] = round(time.monotonic() - started, 3)
        manifest['duration_seconds'] = round(sum(e.get('duration_seconds', 0) for e in manifest['executions']), 3)
        checkpoint()
        render(case)
        logging.info('Case %s: %s processes, %s findings', manifest['status'], len(data['processes']), len(data['findings']))
        return 0 if manifest['status'] == 'complete' else 2
    except KeyboardInterrupt:
        for entry in manifest['executions']:
            if entry['status'] == 'running':
                entry['status'] = 'interrupted'
        manifest['status'] = 'interrupted'
        checkpoint()
        logging.warning('Interrupted: completed artifacts retained; rerun with --resume')
        return 130
    except Exception as exc:
        manifest.update(status='failed', error=str(exc))
        checkpoint()
        raise
    finally:
        lock.unlink(missing_ok=True)
        logging.getLogger().removeHandler(handler)
        handler.close()

def file_hash(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
