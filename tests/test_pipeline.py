"""Synthetic orchestration tests, explicitly separate from real-image validation."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from memnolyze.config import load_config
from memnolyze.io import read_json, write_json
from memnolyze.pipeline import analyze

class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.image = self.root / 'memory image with spaces.bin'
        self.image.write_bytes(b'unit-test-fixture-not-a-real-memory-image')
        self.case = self.root / 'case with spaces'
        self.config = load_config(None)
        self.config['state_dir'] = str(self.root / 'state')
        self.capability = {'available': True, 'version': 'unit-test', 'plugins': []}

    def tearDown(self):
        self.temp.cleanup()

    def command(self, config, capability, image, logical, offline, pid):
        records = {
            'info': [{'Variable': 'Kernel Base', 'Value': '0x1000'},
                     {'Variable': 'NTBuildLab', 'Value': 'test'},
                     {'Variable': 'Is64Bit', 'Value': 'True'}],
            'pslist': [{'PID': 4, 'Offset(V)': 4096, 'ImageFileName': 'System'}],
        }
        if logical == 'broken':
            return [sys.executable, '-c', 'print("invalid JSON")']
        if logical == 'missing':
            return None
        import json
        return [sys.executable, '-c', 'print(' + repr('\n'.join(json.dumps(r) for r in records.get(logical, []))) + ')']

    def run_case(self, resume=False, plugins=None):
        with patch('memnolyze.pipeline.volatility.discover', return_value=self.capability), \
             patch('memnolyze.pipeline.volatility.build_command', side_effect=self.command):
            return analyze(self.image, self.case, self.config, 'quick', 'volatility', True,
                           resume, None, plugins or ['pslist', 'broken', 'missing', 'malfind'])

    def test_failure_isolation_report_and_immutable_resume(self):
        self.assertEqual(self.run_case(), 2)
        manifest = read_json(self.case / 'manifest.json')
        statuses = {e['plugin']: e['status'] for e in manifest['executions']}
        self.assertEqual(statuses['broken'], 'failed')
        self.assertEqual(statuses['missing'], 'unsupported')
        self.assertEqual(statuses['malfind'], 'empty')
        self.assertTrue((self.case / 'report.html').exists())
        self.assertEqual(len(read_json(self.case / 'normalized/processes.json')), 1)
        before = {str(p): p.read_bytes() for p in (self.case / 'raw').rglob('*') if p.is_file()}
        self.assertEqual(self.run_case(True), 2)
        for path, content in before.items():
            self.assertEqual(Path(path).read_bytes(), content)
        executions = read_json(self.case / 'manifest.json')['executions']
        self.assertEqual(len([e for e in executions if e['plugin'] == 'pslist']), 1)
        self.assertEqual(len([e for e in executions if e['plugin'] == 'broken']), 2)

    def test_resume_rejects_changed_image(self):
        self.assertEqual(self.run_case(plugins=['pslist']), 0)
        self.image.write_bytes(b'different')
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            self.run_case(True, ['pslist'])

    def test_resume_rejects_tampered_artifact(self):
        self.run_case(plugins=['pslist'])
        record = read_json(self.case / 'manifest.json')['executions'][0]
        (self.case / record['source_file']).write_text('[]')
        with self.assertRaisesRegex(ValueError, 'integrity'):
            self.run_case(True, ['pslist'])
        self.assertFalse((self.case / '.analysis.lock').exists())

    def test_existing_output_is_not_overwritten(self):
        self.run_case(plugins=['pslist'])
        with self.assertRaisesRegex(ValueError, 'Output must be empty'):
            self.run_case()

    def test_interrupted_attempt_can_resume(self):
        with patch('memnolyze.pipeline.volatility.discover', return_value=self.capability), \
             patch('memnolyze.pipeline.volatility.build_command', side_effect=KeyboardInterrupt):
            self.assertEqual(analyze(self.image, self.case, self.config, 'quick', 'volatility',
                                     True, False, None, ['pslist']), 130)
        self.assertEqual(read_json(self.case / 'manifest.json')['status'], 'interrupted')
        self.assertEqual(self.run_case(True, ['pslist']), 0)

    def test_profile_upgrade_refreshes_memprocfs_scope_and_retains_raw(self):
        def execute_worker(command, stdout, stderr, *args):
            job = read_json(Path(command[-1]))
            target = Path(job['target'])
            stdout.write_bytes(b'')
            stderr.write_bytes(b'')
            write_json(target / 'info.json', {'windows_build': 17134, 'version': 'unit-test'})
            write_json(target / 'processes.json', [{'pid': 4, 'eprocess': 4096, 'name': 'System'}])
            write_json(target / 'regions.json', [] if job['profile'] == 'quick' else [{'pid': 4, 'start': 8192}])
            return {'status': 'success', 'exit_code': 0}
        def run(profile, resume):
            with patch('memnolyze.pipeline.memprocfs.discover', return_value={'available': True}), \
                 patch('memnolyze.pipeline.execute', side_effect=execute_worker):
                return analyze(self.image, self.case, self.config, profile, 'memprocfs',
                               True, resume, None, None)
        self.assertEqual(run('quick', False), 0)
        original = read_json(self.case / 'manifest.json')['executions'][0]
        self.assertEqual(run('standard', True), 0)
        records = read_json(self.case / 'manifest.json')['executions']
        self.assertEqual([r['profile'] for r in records], ['quick', 'standard'])
        self.assertTrue((self.case / original['source_file']).is_file())
        self.assertEqual(len(read_json(self.case / 'normalized/regions.json')), 1)
        self.assertEqual(run('deep', True), 0)
        self.assertEqual(len(read_json(self.case / 'manifest.json')['executions']), 2)

if __name__ == '__main__':
    unittest.main()
