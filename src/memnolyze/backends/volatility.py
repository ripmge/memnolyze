"""Discover installed plugin classes and run the supported CLI."""
import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path
from ..io import child_env

# Volatility's initial parser inspects sys.argv including argv[0]. Python -c
# leaves '-c' there, which Volatility interprets as its own config argument.
# Set it before importing the CLI (which also captures it as CLI_NAME).
PYTHON_ENTRYPOINT = "import sys; sys.argv[0] = 'vol'; from volatility3.cli import main; main()"

def command(config: dict) -> list[str]:
    if config['volatility_command']:
        return config['volatility_command']
    # Use the same interpreter/dependencies as memnolyze when the package is
    # installed there, even if PATH points at another environment's vol.exe.
    if importlib.util.find_spec('volatility3') is not None:
        return [sys.executable, '-c', PYTHON_ENTRYPOINT]
    found = shutil.which('vol') or shutil.which('volatility')
    return [found] if found else [sys.executable, '-c', PYTHON_ENTRYPOINT]

def discover(config: dict) -> dict:
    cmd = command(config)
    try:
        result = subprocess.run(cmd + ['--help'], capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=90,
                                env=child_env(Path(config['state_dir'])))
        output = result.stdout + result.stderr
        plugins = sorted(set(re.findall(r'\bwindows\.[A-Za-z0-9_.]+\.[A-Z][A-Za-z0-9_]*', output)))
        version = re.search(r'Framework\s+(\S+)', output)
        available = result.returncode == 0 and bool(plugins)
        error = None
        if not available:
            diagnostic = (result.stderr.strip() or result.stdout.strip())[-1500:]
            error = (f'Volatility exited with code {result.returncode}: {diagnostic}'
                     if result.returncode else f'No Windows plugins advertised. {diagnostic}')
        return {'available': available, 'command': cmd, 'exit_code': result.returncode,
                'check': 'cli_help_and_plugins', 'image_validated': False,
                'version': version.group(1) if version else None, 'plugins': plugins,
                'error': error}
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
