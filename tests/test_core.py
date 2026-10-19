"""Runs with unittest offline and pytest when installed."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from memnolyze.config import load_config
from memnolyze.detectors import detect
from memnolyze.io import fingerprint, rows, write_json, execute
from memnolyze.normalizers import normalize, process_address
from memnolyze.reporting import escape, evidence_links
from memnolyze.backends.volatility import resolve, plausible_info

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def artifact(self, kind, records, backend='volatility'):
        path = self.root / 'raw' / backend / f'{kind}.json'
        write_json(path, records)
        return {'backend': backend, 'plugin': kind, 'status': 'success',
                'source_file': path.relative_to(self.root).as_posix()}

    def test_streaming_image_hash_and_sidecar(self):
        image = self.root / 'image with spaces.vmem'
        image.write_bytes(b'abc')
        (self.root / 'snapshot.vmsn').write_bytes(b'companion')
        meta = fingerprint(image)
        self.assertEqual(meta['sha256'], 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        self.assertEqual(len(meta['sidecars']), 1)
        self.assertEqual(image.read_bytes(), b'abc')

    def test_jsonl_nested_and_malformed(self):
        path = self.root / 'out.jsonl'
        path.write_text('\n' + json.dumps({'PID': 1, '__children': [{'PID': 2}]}) + '\n')
        self.assertEqual([r['PID'] for r in rows(path)], [1, 2])
        path.write_text('{bad')
        with self.assertRaises(ValueError):
            list(rows(path))

    def test_plugin_alias_namespace(self):
        names = ['windows.malfind.Malfind', 'windows.malware.malfind.Malfind']
        self.assertEqual(resolve('malfind', names), names[1])
        self.assertIsNone(resolve('unavailable', names))
        self.assertFalse(plausible_info([]))

    def test_pid_reuse_is_not_merged_and_network_stays_unassigned(self):
        entries = [self.artifact('pslist', [
            {'PID': 10, 'ImageFileName': 'x', 'Offset(V)': 0x1000, 'CreateTime': '2020'},
            {'PID': 10, 'ImageFileName': 'x', 'Offset(V)': 0x2000, 'CreateTime': '2021'}]),
            self.artifact('netscan', [{'PID': 10, 'Owner': 'x'}])]
        data = normalize(self.root, entries)
        self.assertEqual(len(data['processes']), 2)
        self.assertIsNone(data['networks'][0]['process_id'])

    def test_cross_engine_eprocess_and_cmdline(self):
        entries = [self.artifact('pslist', [{'PID': 10, 'Offset(V)': 0x800000001000}])]
        raw = self.artifact('processes', [{'pid': 10, 'eprocess': 0xffff800000001000, 'cmdline': 'hello'}], 'memprocfs')
        entries.append({'backend': 'memprocfs', 'plugin': 'triage', 'status': 'success',
                        'artifacts': {'processes': raw['source_file']}})
        data = normalize(self.root, entries)
        self.assertEqual(len(data['processes']), 1)
        self.assertEqual(data['processes'][0]['command_line'], 'hello')
        self.assertEqual(process_address(0x800000001000), '0xffff800000001000')

    def test_scan_only_needs_active_list_and_excludes_terminated(self):
        scan = self.artifact('psscan', [{'PID': 1, 'Offset(V)': 1},
                            {'PID': 2, 'Offset(V)': 2, 'ExitTime': '2023'}])
        self.assertEqual(normalize(self.root, [scan])['indicators'], [])
        active = self.artifact('pslist', [{'PID': 4, 'Offset(V)': 4}])
        data = normalize(self.root, [scan, active])
        self.assertEqual([i['pid'] for i in data['indicators']], [1])
        active['status'] = 'failed'
        self.assertEqual(normalize(self.root, [scan, active])['indicators'], [])

    def test_findevil_real_layout_parser(self):
        path = self.root / 'raw/memprocfs/findevil.txt'
        path.parent.mkdir(parents=True)
        path.write_text('# PID Process Type Address Description\n000a 10 explorer.exe THREAD 00007ff91304f320 TID:5240 SYSTEM_IMPERSONATION\n')
        data = normalize(self.root, [{'backend': 'memprocfs', 'plugin': 'triage', 'status': 'success',
                                     'artifacts': {'findevil': 'raw/memprocfs/findevil.txt'}}])
        self.assertEqual(data['indicators'][0]['category'], 'thread_anomaly')
        self.assertEqual(data['indicators'][0]['evidence'][0]['record_id'], 'line:2')

    def test_correlations_require_identity_and_independent_categories(self):
        base = {'processes': [{'process_id': '10:x', 'pid': 10}], 'networks': [], 'indicators': []}
        for category, engine in [('memory_injection', 'volatility'), ('memory_injection', 'memprocfs'), ('thread_anomaly', 'memprocfs')]:
            base['indicators'].append({'category': category, 'process_id': '10:x', 'pid': 10,
                'title': category, 'address': None, 'evidence': [{'backend': engine}]})
        findings = detect(base)
        self.assertEqual(len([f for f in findings if f['category'] == 'correlation']), 2)
        self.assertTrue(all(f['confidence'] != 'high' for f in findings))
        for i in base['indicators']:
            i['process_id'] = None
        self.assertEqual(len(detect(base)), 3)

    def test_html_escaping_and_link_validation(self):
        self.assertEqual(escape('<script>'), '&lt;script&gt;')
        self.assertEqual(evidence_links([{'source_file': 'javascript:alert(1)'}]), '')
        self.assertEqual(evidence_links([{'source_file': 'raw/../../evil'}]), '')
        self.assertIn('%22', evidence_links([{'source_file': 'raw/a"b.json'}]))

    def test_standard_loader_pid_and_thread_address_fields(self):
        entries = [self.artifact('pslist', [{'PID': 20, 'Offset(V)': 4096, 'ImageFileName': 'test.exe'}]),
                   self.artifact('ldrmodules', [{'Pid': 20, 'Process': 'test.exe', 'Base': 8192,
                       'InLoad': False, 'InInit': True, 'InMem': True, 'MappedPath': 'module.dll'}]),
                   self.artifact('suspicious_threads', [{'PID': 20, 'Process': 'test.exe',
                       'TID': 21, 'Address': 12288, 'Note': 'unexpected region'}])]
        data = normalize(self.root, entries)
        identity = data['processes'][0]['process_id']
        self.assertTrue(all(i['process_id'] == identity for i in data['indicators']))
        self.assertEqual(data['modules'][0]['attributes']['base'], '0x2000')
        self.assertEqual(data['modules'][0]['attributes']['path'], 'module.dll')
        self.assertEqual(data['threads'][0]['attributes']['start'], '0x3000')
        self.assertEqual([i['address'] for i in data['indicators']], ['0x2000', '0x3000'])

    def test_pebmasquerade_baseline_rows_are_not_all_findings(self):
        entry = self.artifact('pebmasquerade', [
            {'PID': 20, 'PEB_ImageFilePath_Spoofed': False, 'PEB_CommandLine_Spoofed': False},
            {'PID': 30, 'PEB_ImageFilePath_Spoofed': True, 'PEB_CommandLine_Spoofed': False}])
        self.assertEqual([i['pid'] for i in normalize(self.root, [entry])['indicators']], [30])

    def test_loader_init_only_difference_stays_metadata(self):
        entry = self.artifact('ldrmodules', [
            {'Pid': 20, 'Base': 8192, 'MappedPath': 'test.exe',
             'InLoad': True, 'InInit': False, 'InMem': True}])
        data = normalize(self.root, [entry])
        self.assertEqual(data['indicators'], [])
        self.assertFalse(data['modules'][0]['attributes']['loader_lists']['InInit'])

    def test_command_timeout_and_missing_executable(self):
        result = execute([sys.executable, '-c', 'import time;time.sleep(30)'],
                         self.root / 'out', self.root / 'err', 1)
        self.assertEqual(result['status'], 'timeout')
        result = execute([str(self.root / 'missing.exe')], self.root / 'out2', self.root / 'err2', 1)
        self.assertEqual(result['status'], 'failed')

    def test_subprocess_preserves_spaces_and_shell_metacharacters(self):
        script = self.root / 'script with spaces.py'
        script.write_text('import sys,json; print(json.dumps(sys.argv[1:]))')
        argument = 'D:\\Image Folder\\sample & echo unsafe.dmp'
        result = execute([sys.executable, str(script), argument], self.root / 'stdout', self.root / 'stderr', 5)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(json.loads((self.root / 'stdout').read_text()), [argument])

    def test_config_rejects_uncontrolled_dump_args(self):
        path = self.root / 'config.json'
        write_json(path, {'plugin_args': {'malfind': ['--dump']}})
        with self.assertRaises(ValueError):
            load_config(path)

if __name__ == '__main__':
    unittest.main()
