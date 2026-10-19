"""Discover installed plugin classes and run the supported CLI."""
import re
import shutil
import subprocess
import sys
from pathlib import Path
from ..io import child_env

def command(config: dict) -> list[str]:
    if config['volatility_command']:
        return config['volatility_command']
    found = shutil.which('vol') or shutil.which('volatility')
    return [found] if found else [sys.executable, '-c', 'from volatility3.cli import main; main()']

def discover(config: dict) -> dict:
    cmd = command(config)
    try:
        result = subprocess.run(cmd + ['--help'], capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=90,
                                env=child_env(Path(config['state_dir'])))
        output = result.stdout + result.stderr
        plugins = sorted(set(re.findall(r'\bwindows\.[A-Za-z0-9_.]+\.[A-Z][A-Za-z0-9_]*', output)))
        version = re.search(r'Framework\s+(\S+)', output)
        return {'available': result.returncode == 0 and bool(plugins), 'command': cmd,
                'version': version.group(1) if version else None, 'plugins': plugins,
                'error': None if plugins else output[-1500:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'available': False, 'command': cmd, 'plugins': [], 'error': str(exc)}

def resolve(logical: str, plugins: list[str]) -> str | None:
    # Prefer current malware namespace; match the module preceding the class.
    matches = [p for p in plugins if p.split('.')[-2] == logical]
    matches.sort(key=lambda p: ('.malware.' not in p, p))
    return matches[0] if matches else None

def build_command(config: dict, capability: dict, image: Path, logical: str,
                  offline: bool, pid: int | None) -> list[str] | None:
    plugin = resolve(logical, capability['plugins'])
    if not plugin:
        return None
    cmd = capability['command'] + ['-q', '-r', 'jsonl', '--cache-path',
                                  str(Path(config['state_dir']).resolve() / 'volatility3')]
    if offline:
        cmd += ['--offline']
    if config['symbol_dirs']:
        cmd += ['-s', ';'.join(str(Path(p).resolve()) for p in config['symbol_dirs'])]
    cmd += ['-f', str(image), plugin]
    cmd += config['plugin_args'].get(logical, [])
    # Only inject --pid if the actual installed plugin advertises it.
    if pid is not None and logical != 'info':
        help_result = subprocess.run(capability['command'] + [plugin, '--help'],
                                     capture_output=True, text=True, timeout=60,
                                     env=child_env(Path(config['state_dir'])))
        if '--pid' in help_result.stdout and '--pid' not in cmd:
            cmd += ['--pid', str(pid)]
    return cmd

def plausible_info(records: list[dict]) -> bool:
    values = {str(r.get('Variable')): r.get('Value') for r in records}
    build = values.get('NTBuildLab') or values.get('Major/Minor')
    return bool(values.get('Kernel Base') and build and values.get('Is64Bit') is not None)
