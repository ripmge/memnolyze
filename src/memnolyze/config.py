"""Central configuration and logical plugin profiles."""
import json
import re
from pathlib import Path
from typing import Any

QUICK = ['info', 'pslist', 'psscan', 'pstree', 'cmdline', 'netscan', 'svcscan', 'malfind']
STANDARD = QUICK + ['dlllist', 'ldrmodules', 'suspicious_threads', 'hollowprocesses',
                    'processghosting', 'pebmasquerade', 'callbacks', 'modules', 'driverirp']
PROFILES = {'quick': QUICK, 'standard': STANDARD,
            'deep': STANDARD + ['vadinfo', 'handles', 'threads', 'privileges']}
DEFAULTS: dict[str, Any] = {
    'volatility_command': None, 'memprocfs_path': None,
    'state_dir': '.state', 'timeout_seconds': 1800, 'forensic_timeout_seconds': 1800,
    'symbol_dirs': [], 'plugins': None, 'plugin_args': {},
    'memprocfs_forensic': True, 'memprocfs_symbols': False,
    'max_vfs_bytes': 64 * 1024 * 1024,
}

def load_config(path: Path | None) -> dict[str, Any]:
    config = DEFAULTS.copy()
    if path:
        supplied = json.loads(path.read_text(encoding='utf-8-sig'))
        if not isinstance(supplied, dict) or set(supplied) - set(DEFAULTS):
            raise ValueError('Configuration must be an object with known keys only')
        config.update(supplied)
    for key in ('timeout_seconds', 'forensic_timeout_seconds', 'max_vfs_bytes'):
        if not isinstance(config[key], int) or isinstance(config[key], bool) or config[key] <= 0:
            raise ValueError(f'{key} must be a positive integer')
    command = config['volatility_command']
    if command is not None and (not isinstance(command, list) or not command or
                                not all(isinstance(x, str) for x in command)):
        raise ValueError('volatility_command must be a nonempty array of arguments')
    if not isinstance(config['state_dir'], str) or not config['state_dir']:
        raise ValueError('state_dir must be a nonempty path string')
    if config['memprocfs_path'] is not None and not isinstance(config['memprocfs_path'], str):
        raise ValueError('memprocfs_path must be a path string or null')
    for key in ('memprocfs_forensic', 'memprocfs_symbols'):
        if not isinstance(config[key], bool):
            raise ValueError(f'{key} must be boolean')
    if not isinstance(config['symbol_dirs'], list) or not all(isinstance(p, str) for p in config['symbol_dirs']):
        raise ValueError('symbol_dirs must be an array of path strings')
    plugins = config['plugins']
    if plugins is not None and (not isinstance(plugins, list) or not plugins or
                               not all(isinstance(p, str) and re.fullmatch(r'[a-z][a-z0-9_]*', p) for p in plugins)):
        raise ValueError('plugins must be a nonempty array of logical plugin names or null')
    if not isinstance(config['plugin_args'], dict):
        raise ValueError('plugin_args must be an object')
    for args in config['plugin_args'].values():
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ValueError('plugin_args values must be arrays of strings')
        # No extraction or arbitrary Volatility configuration through this interface.
        allowed = {'--pid', '--offset', '--address', '--maxsize', '--size'}
        if any(a.startswith('-') and a not in allowed for a in args):
            raise ValueError('Unsupported plugin argument; dumping is outside this MVP')
    return config
