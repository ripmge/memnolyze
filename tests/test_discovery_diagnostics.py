"""Discovery must identify the selected module without claiming image support."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from memnolyze.backends import memprocfs
from memnolyze.config import load_config
from memnolyze.diagnostics import failure_hint, error_excerpt, log_execution
from memnolyze.io import child_env


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='engine directory ')
        self.root = Path(self.temp.name).resolve()
        self.config = load_config(None)
        self.config['state_dir'] = str(self.root / 'state')

    def tearDown(self):
        self.temp.cleanup()

    def module(self, text):
        (self.root / 'memprocfs.py').write_text(text, encoding='utf-8')

    def test_configured_directory_reports_actual_file_without_initializing(self):
        self.module('class Vmm:\n    def __init__(self, args):\n        raise RuntimeError("Must not initialize during discovery")\n')
        self.config['memprocfs_path'] = str(self.root)
        result = memprocfs.discover(self.config)
        self.assertTrue(result['available'], result.get('error'))
        self.assertEqual(Path(result['module_file']), self.root / 'memprocfs.py')
        self.assertEqual(result['source'], 'configured_directory')
        self.assertFalse(result['image_validated'])
        self.assertEqual(result['check'], 'native_api_import')

    def test_importable_module_with_null_config_still_reports_resolved_path(self):
        self.module('class Vmm: pass\n')
        env = child_env(self.root / 'state')
        env['PYTHONPATH'] = str(self.root)
        with patch.object(memprocfs, 'child_env', return_value=env):
            result = memprocfs.discover(self.config)
        self.assertTrue(result['available'], result.get('error'))
        self.assertEqual(result['configured_path'], None)
        self.assertEqual(result['path'], str(self.root))
        self.assertEqual(result['source'], 'python_import')

    def test_native_import_failure_is_unavailable(self):
        self.module('raise ImportError("DLL load failed: test dependency unavailable")\n')
        self.config['memprocfs_path'] = str(self.root)
        result = memprocfs.discover(self.config)
        self.assertFalse(result['available'])
        self.assertIn('DLL load failed', result['error'])

    def test_module_without_api_is_unavailable(self):
        self.module('message = "not the API"\n')
        self.config['memprocfs_path'] = str(self.root)
        result = memprocfs.discover(self.config)
        self.assertFalse(result['available'])
        self.assertIn('does not expose the Vmm API', result['error'])

    def test_missing_explicit_directory_does_not_fall_back_to_another_installation(self):
        self.config['memprocfs_path'] = str(self.root / 'missing')
        result = memprocfs.discover(self.config)
        self.assertFalse(result['available'])
        self.assertEqual(result['source'], 'configured_directory')


class FailureHintsTests(unittest.TestCase):
    def test_excerpt_is_bounded_and_preserves_engine_error(self):
        excerpt = error_excerpt('context\n' * 100 + 'TypeError: Vmm initialization failed', '')
        self.assertIn('TypeError: Vmm initialization failed', excerpt)
        self.assertLessEqual(len(excerpt.splitlines()), 8)
        self.assertLessEqual(len(error_excerpt('x' * 10000, '')), 1600)

    def test_stdout_diagnostics_do_not_echo_json_records(self):
        excerpt = error_excerpt('', '{"error": "private evidence"}\n[CORE] initialization failed\n')
        self.assertIn('[CORE] initialization failed', excerpt)
        self.assertNotIn('private evidence', excerpt)

    def test_failure_is_logged_with_original_error_and_full_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            (case / 'stderr.txt').write_text('RuntimeError: arbitrary backend error', encoding='utf-8')
            record = {'backend': 'test', 'plugin': 'example', 'status': 'failed',
                      'exit_code': 7, 'stderr_file': 'stderr.txt', 'error': 'Execution failed'}
            with self.assertLogs(level='ERROR') as captured:
                log_execution(record, case)
            output = '\n'.join(captured.output)
            self.assertIn('test/example: failed (exit 7)', output)
            self.assertIn('RuntimeError: arbitrary backend error', output)
            self.assertIn(str(case.resolve() / 'stderr.txt'), output)

    def test_symbol_failure_explains_offline_policy(self):
        hint = failure_hint('volatility', 'Unsatisfied requirement plugins.Info.kernel.symbol_table_name', True)
        self.assertIn('symbols', hint)
        self.assertIn('Offline mode blocks', hint)

    def test_layer_failure_is_not_misreported_as_only_symbols(self):
        hint = failure_hint('volatility', 'Unable to validate plugins.Info.kernel.layer_name and kernel.symbol_table_name', True)
        self.assertIn('image translation', hint)
        self.assertNotIn('kernel symbols could not', hint)

    def test_unknown_failure_does_not_copy_sensitive_output(self):
        hint = failure_hint('volatility', 'private memory contents: secret', True)
        self.assertNotIn('secret', hint)
        self.assertIn('stderr', hint)
