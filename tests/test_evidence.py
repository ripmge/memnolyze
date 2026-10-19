import tempfile
import unittest
from pathlib import Path
from memnolyze.evidence import resolve_records
from memnolyze.io import write_json
from memnolyze.reporting import render

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.case = Path(self.temp.name)
        (self.case / 'raw').mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def evidence(self, source, identifier):
        return {'backend': 'test', 'plugin': 'test', 'source_file': source, 'record_id': identifier}

    def test_numeric_ids_follow_flattened_records_not_physical_lines(self):
        path = self.case / 'raw/tree.jsonl'
        path.write_text('\n{"PID":1,"__children":[{"PID":2}]}\n{"PID":3}\n')
        refs = [self.evidence('raw/tree.jsonl', str(i)) for i in range(4)]
        result = resolve_records(self.case, refs)
        self.assertEqual([result['raw/tree.jsonl', str(i)]['record']['PID'] for i in range(3)], [1, 2, 3])
        self.assertIn('error', result['raw/tree.jsonl', '3'])

    def test_findevil_line_ids_keep_header_and_blank_line_positions(self):
        (self.case / 'raw/findevil.txt').write_text('header\n\n000a 10 test.exe THREAD 12345678 detail\n')
        result = resolve_records(self.case, [self.evidence('raw/findevil.txt', 'line:3')])
        self.assertEqual(result['raw/findevil.txt', 'line:3']['record'], '000a 10 test.exe THREAD 12345678 detail')

    def test_invalid_missing_and_absence_references_are_explicit(self):
        refs = [self.evidence('../outside.json', '0'), self.evidence('raw/missing.json', '0'),
                self.evidence('raw/missing.json', 'absence')]
        result = resolve_records(self.case, refs)
        self.assertIn('Invalid', result['../outside.json', '0']['error'])
        self.assertIn('Cannot read', result['raw/missing.json', '0']['error'])
        self.assertIn('Absence reference', result['raw/missing.json', 'absence']['error'])

    def test_report_embeds_exact_record_escapes_html_and_keeps_source_link(self):
        reference = self.evidence('raw/loader.json', '1')
        write_json(self.case / 'raw/loader.json', [{'Pid': 1}, {'Pid': 9100, 'MappedPath': '<script>payload</script>'}])
        write_json(self.case / 'manifest.json', {'schema_version': 1, 'status': 'complete',
            'created_at': 'test', 'image': {'path': 'image.dmp'}, 'offline': True,
            'backend_info': {}, 'executions': []})
        for name in ('processes', 'networks', 'modules', 'regions', 'threads'):
            write_json(self.case / f'normalized/{name}.json', [])
        write_json(self.case / 'normalized/findings.json', [{'finding_id': 'F-0128',
            'severity': 'medium', 'confidence': 'low', 'process_id': None, 'pid': 9100,
            'category': 'loader_anomaly', 'title': 'Test finding', 'evidence': [reference, reference]}])
        report = render(self.case).read_text(encoding='utf-8')
        self.assertIn('&quot;Pid&quot;: 9100', report)
        self.assertIn('&lt;script&gt;payload&lt;/script&gt;', report)
        self.assertNotIn('<script>payload</script>', report)
        self.assertIn('href="raw/loader.json"', report)
        self.assertIn('test/test [1]', report)
        self.assertEqual(report.count('class="evidence-record"'), 1)
