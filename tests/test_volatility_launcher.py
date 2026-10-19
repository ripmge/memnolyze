"""Regression coverage for Python -c argument handling and venv selection."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from memnolyze.backends import volatility
from memnolyze.config import load_config
from memnolyze.io import child_env


class LauncherTests(unittest.TestCase):
    def test_entrypoint_resets_argv_before_import_without_changing_arguments(self):
        with tempfile.TemporaryDirectory(prefix='vol launcher ') as directory:
            root = Path(directory)
            package = root / 'volatility3'
            package.mkdir()
            (package / '__init__.py').write_text('')
            # This synthetic CLI models Volatility's early full-argv parse.
            (package / 'cli.py').write_text(
                'import argparse,json,sys\n'
                'assert sys.argv[0] == "vol", sys.argv\n'
                'def main():\n'
                '    parser=argparse.ArgumentParser(add_help=False)\n'
                '    parser.add_argument("-c","--config")\n'
                '    parser.parse_known_args([a for a in sys.argv if a != "--help"])\n'
                '    print(json.dumps(sys.argv))\n')
            args = ['--help', '-c', str(root / 'legitimate config.json'),
                    '-f', str(root / 'image with spaces & chars.dmp')]
            env = child_env(root / 'state')
            env['PYTHONPATH'] = str(root)
            result = subprocess.run([sys.executable, '-c', volatility.PYTHON_ENTRYPOINT, *args],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), ['vol', *args])

    def test_current_interpreter_package_wins_over_unrelated_path_executable(self):
        with patch.object(volatility.importlib.util, 'find_spec', return_value=object()), \
             patch.object(volatility.shutil, 'which') as which:
            cmd = volatility.command(load_config(None))
        self.assertEqual(cmd, [sys.executable, '-c', volatility.PYTHON_ENTRYPOINT])
        which.assert_not_called()

    def test_explicit_command_is_preserved(self):
        config = load_config(None)
        config['volatility_command'] = ['D:/Custom Tools/vol.exe']
        with patch.object(volatility.importlib.util, 'find_spec') as find:
            self.assertEqual(volatility.command(config), config['volatility_command'])
        find.assert_not_called()

    def test_path_is_available_for_separate_engine_installation(self):
        with patch.object(volatility.importlib.util, 'find_spec', return_value=None), \
             patch.object(volatility.shutil, 'which', return_value='D:/Tools/vol.exe'):
            self.assertEqual(volatility.command(load_config(None)), ['D:/Tools/vol.exe'])

    def test_no_package_or_executable_uses_corrected_fallback(self):
        with patch.object(volatility.importlib.util, 'find_spec', return_value=None), \
             patch.object(volatility.shutil, 'which', return_value=None):
            self.assertEqual(volatility.command(load_config(None)),
                             [sys.executable, '-c', volatility.PYTHON_ENTRYPOINT])

    def test_failed_help_keeps_error_even_when_plugin_names_are_printed(self):
        with tempfile.TemporaryDirectory() as directory:
            config = load_config(None)
            config['state_dir'] = directory
            result = subprocess.CompletedProcess([], 2, 'windows.info.Info', 'argument -c: expected one argument')
            with patch.object(volatility, 'command', return_value=['vol']), \
                 patch.object(volatility.subprocess, 'run', return_value=result):
                capability = volatility.discover(config)
            self.assertFalse(capability['available'])
            self.assertEqual(capability['exit_code'], 2)
            self.assertIn('expected one argument', capability['error'])
