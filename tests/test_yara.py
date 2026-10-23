"""YARA policy, provenance, parsing and worker tests; fixtures are synthetic."""
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from memnolyze.backends.memprocfs import worker, yara_settings
from memnolyze.config import load_config
from memnolyze.io import read_json, write_json, rows
from memnolyze.normalizers import normalize
from memnolyze.evidence import resolve_records
from memnolyze.cli import main

RECORD = ('Match Index:  0\nRule:         TestRule\nType:         Virtual Memory\n'
          'Base Address: 0x1000\nPID:          42\nProcess Name: example.exe\n\n'
          'Matches:\n[$a]: 1001\n')


class YaraTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='yara rules ')
        self.root = Path(self.temp.name)
        self.rule = self.root / 'custom rule.yar'
        self.rule.write_text('rule TestRule { condition: false }', encoding='utf-8')
        self.config = load_config(None)

    def tearDown(self):
        self.temp.cleanup()

    def test_config_validation(self):
        path = self.root / 'config.json'
        for bad in ({'memprocfs_yara_rules': []}, {'memprocfs_accept_elastic_license': 'true'},
                    {'memprocfs_forensic': False, 'memprocfs_yara_rules': str(self.rule)}):
            write_json(path, bad)
            with self.assertRaises(ValueError):
                load_config(path)

    def test_rules_and_include_changes_affect_fingerprint(self):
        dependency = self.root / 'included.yar'
        dependency.write_text('rule Included { condition: false }')
        self.rule.write_text('include "included.yar"\n')
        self.config['memprocfs_yara_rules'] = str(self.rule)
        before = yara_settings(self.config)
        dependency.write_text('rule Included { condition: true }')
        self.assertNotEqual(before, yara_settings(self.config))
        self.assertEqual(len(before['custom_rules']['dependencies']), 1)
        dependency.unlink()
        with self.assertRaises(OSError):
            yara_settings(self.config)

    def test_cli_passes_explicit_options_and_rejects_volatility_only(self):
        args = ['analyze', '--image', str(self.rule), '--output', str(self.root / 'case'),
                '--backend', 'memprocfs', '--yara-rules', str(self.rule), '--accept-elastic-license']
        with patch('memnolyze.pipeline.analyze', return_value=0) as run:
            self.assertEqual(main(args), 0)
            config = run.call_args.args[2]
            self.assertTrue(config['memprocfs_accept_elastic_license'])
            self.assertEqual(config['memprocfs_yara_rules'], str(self.rule.resolve()))
        args[args.index('memprocfs')] = 'volatility'
        with patch('memnolyze.pipeline.analyze') as run:
            self.assertEqual(main(args), 1)
            run.assert_not_called()

    def test_parsing_normalization_and_inline_original_evidence(self):
        target = self.root / 'raw/memprocfs/test'
        target.mkdir(parents=True)
        source = target / 'yara-result.txt'
        source.write_text(RECORD, encoding='utf-8')
        write_json(target / 'processes.json', [{'pid': 42, 'name': 'example.exe', 'eprocess': 4096}])
        execution = {'backend': 'memprocfs', 'plugin': 'triage', 'status': 'success', 'artifacts': {
            'processes': 'raw/memprocfs/test/processes.json', 'yara-result': 'raw/memprocfs/test/yara-result.txt'}}
        data = normalize(self.root, [execution])
        indicator = data['indicators'][0]
        self.assertEqual(indicator['category'], 'yara_match')
        self.assertEqual(indicator['title'], 'YARA: TestRule')
        self.assertEqual(indicator['process_id'], data['processes'][0]['process_id'])
        evidence = indicator['evidence'][0]
        resolved = resolve_records(self.root, [evidence])
        self.assertEqual(resolved[evidence['source_file'], '0']['record']['original_record'], RECORD.rstrip())
        source.write_text('unknown output')
        with self.assertRaises(ValueError):
            list(rows(source))

    def run_worker(self, custom=False, elastic=False, count=1, omit=None):
        self.config['memprocfs_yara_rules'] = str(self.rule) if custom else None
        self.config['memprocfs_accept_elastic_license'] = elastic
        target = self.root / 'run'
        target.mkdir()
        job = target / 'job.json'
        write_json(job, {'config': self.config, 'target': str(target), 'image': 'synthetic.raw',
                         'offline': True, 'pid': None, 'profile': 'quick'})
        files = {'/forensic/progress_percent.txt': b'100',
                 '/forensic/findevil/findevil.txt': b'# PID Process Type Address\n',
                 '/forensic/findevil/yara.txt': b'', '/forensic/findevil/yara_rules.txt': b'',
                 '/forensic/yara/match-count.txt': str(count).encode(),
                 '/forensic/yara/result.txt': RECORD.encode() if count else b'',
                 '/forensic/yara/rules.txt': str(self.rule).encode()}
        if omit:
            files.pop(omit)
        closed, arguments = [], []
        class Vmm:
            def __init__(self, args):
                arguments.extend(args)
                self.maps = types.SimpleNamespace(net=lambda: [])
                self.vfs = types.SimpleNamespace(
                    read=lambda path, limit: files[path][:limit],
                    list=lambda folder: {path.rsplit('/', 1)[-1]: {'size': len(content)}
                                         for path, content in files.items() if path.rsplit('/', 1)[0] == folder})
            def process_list(self):
                return []
            def get_config(self, key):
                return {'system': 2, 'build': 17134, 'MAJOR': 5, 'MINOR': 19, 'REVISION': 0}[key]
            def close(self):
                closed.append(True)
        module = types.SimpleNamespace(Vmm=Vmm, OPT_CORE_SYSTEM='system', OPT_WIN_VERSION_BUILD='build',
            SYSTEM_WINDOWS_X64=2, SYSTEM_WINDOWS_X86=4, OPT_CONFIG_VMM_VERSION_MAJOR='MAJOR',
            OPT_CONFIG_VMM_VERSION_MINOR='MINOR', OPT_CONFIG_VMM_VERSION_REVISION='REVISION')
        with patch.dict(sys.modules, memprocfs=module), patch('memnolyze.backends.memprocfs.time.sleep'):
            try:
                worker(job)
            finally:
                self.assertEqual(closed, [True])
        return arguments, target

    def test_custom_rules_disable_builtin_and_export_matches(self):
        args, target = self.run_worker(custom=True)
        self.assertIn('-disable-yara-builtin', args)
        self.assertNotIn('-disable-yara', args)
        self.assertNotIn('-license-accept-elastic-license-2-0', args)
        self.assertEqual(read_json(target / 'yara_status.json')['match_count'], 1)
        self.assertEqual((target / 'yara-input.rules').read_bytes(), self.rule.read_bytes())

    def test_elastic_requires_explicit_acceptance(self):
        args, target = self.run_worker(elastic=True)
        self.assertIn('-license-accept-elastic-license-2-0', args)
        self.assertNotIn('-disable-yara-builtin', args)
        self.assertTrue((target / 'findevil-yara.txt').exists())

    def test_zero_matches_are_valid(self):
        args, target = self.run_worker(custom=True, count=0)
        self.assertEqual(read_json(target / 'yara_status.json')['match_count'], 0)

    def test_missing_yara_output_does_not_claim_success(self):
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            self.run_worker(custom=True, omit='/forensic/yara/result.txt')

    def test_match_count_mismatch_is_failure(self):
        with self.assertRaisesRegex(ValueError, 'count mismatch'):
            self.run_worker(custom=True, count=2)

    def test_native_compile_error_is_not_reported_as_zero_matches(self):
        original = self.run_worker
        # The worker reads its captured native output to detect failed YARA initialization.
        with patch('memnolyze.backends.memprocfs.text_tail', return_value='[yara] yr_initialize() failed with error code 1'):
            with self.assertRaisesRegex(ValueError, 'YARA engine initialization failed'):
                original(custom=True, count=0)

    def test_resume_refreshes_changed_rules_and_requires_explicit_policy_change(self):
        from memnolyze.pipeline import analyze
        image, case = self.root / 'image.bin', self.root / 'case'
        image.write_bytes(b'synthetic image')
        self.config['state_dir'] = str(self.root / 'state')
        self.config['memprocfs_yara_rules'] = str(self.rule)
        runs = []
        def execute(command, stdout, stderr, *args):
            job = read_json(Path(command[-1]))
            target = Path(job['target'])
            runs.append(target)
            stdout.write_bytes(b'')
            stderr.write_bytes(b'')
            write_json(target / 'info.json', {'windows_build': 17134, 'version': 'synthetic'})
            write_json(target / 'processes.json', [])
            write_json(target / 'yara_config.json', yara_settings(job['config']))
            return {'status': 'success', 'exit_code': 0}
        def run(resume=False, rerun=None):
            return analyze(image, case, self.config, 'quick', 'memprocfs', True, resume, None, None,
                           rerun=rerun, skip_hash=True)
        with patch('memnolyze.pipeline.memprocfs.discover', return_value={'available': True}), \
             patch('memnolyze.pipeline.execute', side_effect=execute):
            self.assertEqual(run(), 0)
            self.assertEqual(run(True), 0)
            self.assertEqual(len(runs), 1)
            self.rule.write_text('rule Changed { condition: false }')
            self.assertEqual(run(True), 0)
            self.assertEqual(len(runs), 2)
            self.config['memprocfs_yara_rules'] = None
            with self.assertRaisesRegex(ValueError, '--rerun triage'):
                run(True)
            self.assertEqual(run(True, ['triage']), 0)
            self.assertEqual(len(runs), 3)
            self.assertEqual(len(read_json(case / 'manifest.json')['configuration_history']), 1)
            self.assertTrue(all(p.is_dir() for p in runs))
