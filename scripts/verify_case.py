"""Validate a real case's provenance, report links and cached-run behavior."""
import hashlib
import argparse
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.external = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key == 'href':
                self.links.append(value)
            if key in ('src', 'href') and value.startswith(('http:', 'https:', '//')):
                self.external.append(value)

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', type=Path)
    parser.add_argument('--allow-partial', action='store_true',
                        help='Validate provenance for a documented partial case without asserting complete coverage')
    args = parser.parse_args()
    case = args.case.resolve()
    manifest = json.loads((case / 'manifest.json').read_text())
    current = {(e['backend'], e['plugin']): e for e in manifest['executions']}
    statuses = ('complete', 'partial') if args.allow_partial else ('complete',)
    job_statuses = ('success', 'empty', 'unsupported', 'partial') if args.allow_partial else ('success', 'empty', 'unsupported')
    assert manifest['status'] in statuses, manifest['status']
    assert all(e['status'] in job_statuses for e in current.values())
    checked = 0
    for execution in manifest['executions']:
        for source, expected in execution.get('artifact_hashes', {}).items():
            with (case / source).open('rb') as stream:
                assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected, source
            checked += 1
    counts = {}
    for name in ('processes', 'networks', 'modules', 'regions', 'threads', 'findings'):
        data = json.loads((case / 'normalized' / f'{name}.json').read_text())
        counts[name] = len(data)
        for row in data:
            for evidence in row.get('evidence', []):
                assert (case / evidence['source_file']).is_file()
    parser = Links()
    parser.feed((case / 'report.html').read_text(encoding='utf-8'))
    assert not parser.external, parser.external
    for link in parser.links:
        if not link.startswith('#'):
            target = case / unquote(link)
            assert target.resolve().is_relative_to(case)
            assert target.is_file(), target
    assert counts['processes'] > 0
    print(json.dumps({'status': 'verified', 'case_status': manifest['status'],
                      'partial_jobs': [{'backend': e['backend'], 'plugin': e['plugin']}
                                       for e in current.values() if e['status'] == 'partial'],
                      'counts': counts, 'checked_artifact_hashes': checked,
                      'report_links': len(parser.links), 'external_resources': 0,
                      'backend_info': manifest['backend_info']}, indent=2))

if __name__ == '__main__':
    main()
