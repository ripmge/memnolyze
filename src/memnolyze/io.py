"""Case IO, read-only image fingerprinting and bounded subprocess execution."""
import hashlib
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=True), encoding='utf-8')
    temporary.replace(path)

def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8-sig'))

def text_tail(path: Path, limit: int = 8192) -> str:
    if not path.is_file():
        return ''
    with path.open('rb') as stream:
        stream.seek(0, 2)
        stream.seek(max(0, stream.tell() - limit))
        return stream.read(limit).decode('utf-8', errors='replace')

def fingerprint(path: Path, skip_hash: bool = False) -> dict:
    path = path.resolve(strict=True)
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError('Image must be a nonempty regular file')
    before = path.stat()
    digest = None
    if not skip_hash:
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
                digest.update(block)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('Image changed while hashing')
    sidecars = []
    if path.suffix.lower() == '.vmem':
        sidecars = [str(p.resolve()) for p in path.parent.iterdir()
                    if p.is_file() and p.suffix.lower() in ('.vmsn', '.vmss')]
    return {'path': str(path), 'size': before.st_size, 'mtime_ns': before.st_mtime_ns,
            'sha256': digest.hexdigest() if digest else None,
            'format_hint': path.suffix.lower(), 'sidecars': sidecars}

def child_env(state: Path) -> dict[str, str]:
    env = os.environ.copy()
    state.mkdir(parents=True, exist_ok=True)
    # Volatility creates its default cache during import, before parsing --cache-path.
    env.update(APPDATA=str(state.resolve()), XDG_CACHE_HOME=str(state.resolve()),
               TEMP=str(state.resolve()), TMP=str(state.resolve()),
               PYTHONUTF8='1', PYTHONIOENCODING='utf-8')
    return env

def execute(command: list[str], stdout: Path, stderr: Path, timeout: int,
            env: dict[str, str] | None = None, cwd: Path | None = None) -> dict:
    start = time.monotonic()
    result = {'command': command, 'started_at': utcnow(), 'status': 'failed'}
    stdout.parent.mkdir(parents=True, exist_ok=True)
    with stdout.open('xb') as out, stderr.open('xb') as err:
        try:
            process = subprocess.Popen(command, stdout=out, stderr=err, env=env,
                                       cwd=cwd, shell=False)
            try:
                deadline = time.monotonic() + timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    try:
                        code = process.wait(timeout=min(30, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        if time.monotonic() >= deadline:
                            raise
                        logging.info('Still running: %s (%.0fs)', command[0], time.monotonic() - start)
                result.update(exit_code=code, status='success' if code == 0 else 'failed')
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                result.update(exit_code=process.returncode,
                              status='interrupted' if isinstance(exc, KeyboardInterrupt) else 'timeout')
        except OSError as exc:
            result['error'] = str(exc)
    result['duration_seconds'] = round(time.monotonic() - start, 3)
    logging.info('Execution %s: %s (%.1fs)', command[0], result['status'], result['duration_seconds'])
    return result

def rows(path: Path) -> Iterator[dict]:
    """Stream JSONL; flatten the children used by Volatility tree renderers."""
    def flatten(row: dict) -> Iterator[dict]:
        yield {k: v for k, v in row.items() if k != '__children'}
        for child in row.get('__children', []):
            yield from flatten(child)
    if path.name == 'yara-result.txt':
        from .yara import matches
        yield from matches(path)
    elif path.suffix == '.jsonl':
        with path.open(encoding='utf-8-sig') as stream:
            for line in stream:
                if line.strip():
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError('Expected a JSON object per line')
                    yield from flatten(value)
    else:
        data = read_json(path)
        if not isinstance(data, list):
            raise ValueError('Expected a JSON array')
        for row in data:
            if not isinstance(row, dict):
                raise ValueError('Expected object records')
            yield from flatten(row)
