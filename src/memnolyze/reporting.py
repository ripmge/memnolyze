"""Self-contained local HTML. All evidence strings are escaped before rendering."""
import html
import json
from collections import Counter
from pathlib import Path
from urllib.parse import quote
from .io import read_json
from .evidence import resolve_records
from .report_controls import SCRIPT

def escape(value: object) -> str:
    return html.escape('' if value is None else str(value), quote=True)

def evidence_links(evidence: list[dict]) -> str:
    links = []
    for item in evidence:
        source = item.get('source_file', '')
        path = Path(source)
        if not source.startswith('raw/') or path.is_absolute() or '..' in path.parts or '\\' in source:
            continue
        links.append(f'<a href="{quote(source, safe="/")}">{escape(item.get("backend"))}/'
                     f'{escape(item.get("plugin"))} [{escape(item.get("record_id"))}]</a>')
    return '<br>'.join(links)

def render(case: Path) -> Path:
    manifest = read_json(case / 'manifest.json')
    data = {name: read_json(case / 'normalized' / f'{name}.json') for name in
            ('processes', 'networks', 'modules', 'regions', 'threads', 'findings')}
    processes = {p['process_id']: p for p in data['processes']}
    evidence_records = resolve_records(case, [e for f in data['findings'] for e in f['evidence']])
    def finding_evidence(evidence: list[dict]) -> str:
        snippets = []
        seen = set()
        for item in evidence:
            key = (item['source_file'], str(item['record_id']))
            if key in seen:
                continue
            seen.add(key)
            entry = evidence_records[key]
            if 'record' in entry:
                record = entry['record']
                content = record if isinstance(record, str) else json.dumps(record, indent=2, ensure_ascii=False)
                body = f'<pre class="original-record">{escape(content)}</pre>'
            else:
                body = f'<p>{escape(entry["error"])}</p>'
            snippets.append('<section class="evidence-record"><p>' + evidence_links([item]) + '</p>' + body + '</section>')
        return '<h3>Referenced original records</h3>' + ''.join(snippets)
    findings = []
    ranks = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
    for f in sorted(data['findings'], key=lambda f: (ranks.get(f['severity'], 9), f['finding_id'])):
        process = processes.get(f['process_id'], {})
        detail = json.dumps({k: v for k, v in f.items() if k != 'evidence'}, indent=2)
        sources = sorted({e['backend'] + '/' + e['plugin'] for e in f['evidence']})
        findings.append('<tr>' + ''.join(f'<td>{escape(v)}</td>' for v in
            (f['finding_id'], f['severity'], f['confidence'], process.get('name'), f['pid'], f['category'])) +
            f'<td data-column-values="{escape(json.dumps(sources))}">{"<br>".join(escape(s) for s in sources)}</td>'
            f'<td data-column-values="{escape(json.dumps([f["title"]]))}"><details id="{escape(f["finding_id"])}"><summary>{escape(f["title"])}</summary>'
            f'<pre>{escape(detail)}</pre>{finding_evidence(f["evidence"])}</details></td></tr>')
    process_html = []
    for process in sorted(data['processes'], key=lambda p: (p['pid'], p['process_id'])):
        identity = process['process_id']
        linked = [f for f in data['findings'] if f['process_id'] == identity]
        artifacts = []
        for kind in ('networks', 'modules', 'regions', 'threads'):
            records = [a for a in data[kind] if a['process_id'] == identity]
            items = ''.join('<li><pre>' + escape(json.dumps(a['attributes'], indent=2)) +
                            '</pre>' + evidence_links(a['evidence']) + '</li>' for a in records)
            artifacts.append(f'<details><summary>{escape(kind)} ({len(records)})</summary><ul>{items}</ul></details>')
        parent = [p for p in data['processes'] if p['pid'] == process['ppid']]
        parent_label = parent[0]['name'] if len(parent) == 1 else 'unresolved / ambiguous'
        linked_html = ' '.join(f'<a href="#{escape(f["finding_id"])}">{escape(f["finding_id"])}</a>' for f in linked)
        process_html.append('<tr>' + ''.join(f'<td>{escape(v)}</td>' for v in
            (process['pid'], process['name'], f'{process["ppid"]} ({parent_label})', process['creation_time'])) +
            f'<td data-column-values="{escape(json.dumps([process["command_line"] or ""]))}"><details><summary>{escape(process["command_line"] or "Process details")}</summary>'
            f'<pre>{escape(json.dumps(process, indent=2))}</pre>{evidence_links(process["evidence"])}'
            f'{linked_html}{"".join(artifacts)}</details></td></tr>')
    execution_rows = []
    for execution in manifest['executions']:
        sources = [execution.get('source_file'), execution.get('stderr_file'),
                   *execution.get('artifacts', {}).values()]
        links = evidence_links([{'source_file': s, 'backend': execution['backend'],
                                 'plugin': execution['plugin'], 'record_id': Path(s).name}
                                for s in sources if s and (case / s).is_file()])
        execution_rows.append('<tr>' + ''.join(f'<td>{escape(execution.get(k))}</td>' for k in
            ('backend', 'plugin', 'status', 'duration_seconds', 'record_count', 'error')) +
            '<td><details><summary>Invocation / original artifacts</summary><pre>' +
            escape(json.dumps(execution, indent=2)) + '</pre>' + links + '</details></td></tr>')
    execution_html = ''.join(execution_rows)
    def table(identity: str, headers: list[str], body: str) -> str:
        head = []
        for index, header in enumerate(headers):
            menu = ''
            if not (identity == 'executions' and index == len(headers) - 1):
                menu = ('<details class="column-filter"><summary>Filter</summary><div class="filter-panel">'
                        f'<input type="search" aria-label="Search values in {escape(header)}" placeholder="Search values">'
                        '<p>No selection = all values. Counts include all rows.</p>'
                        '<button type="button" data-clear-column>Clear selection</button>'
                        '<div class="filter-options"></div></div></details>')
            head.append(f'<th scope="col"><button type="button" data-sort aria-label="Sort by {escape(header)}">{escape(header)} ↕</button>{menu}</th>')
        return (f'<p><button type="button" data-clear-filters="{identity}">Clear filters</button> '
                f'<span data-row-count="{identity}" aria-live="polite"></span></p>'
                f'<table id="{identity}"><thead><tr>' + ''.join(head)
                + '</tr></thead><tbody>' + body + '</tbody></table>')
    def expand_controls(identity: str) -> str:
        return (f'<p class="detail-controls"><button type="button" data-details-target="{identity}" '
                f'data-expand="true" aria-controls="{identity}">Expand all</button> '
                f'<button type="button" data-details-target="{identity}" data-expand="false" '
                f'aria-controls="{identity}">Collapse all</button> '
                '<span>Applies to currently visible entries.</span></p>')
    severity = dict(Counter(f['severity'] for f in data['findings']))
    windows_build = manifest['backend_info'].get('memprocfs', {}).get('windows_build')
    versions = {k: v.get('version') for k, v in manifest['backend_info'].items()}
    latest = {(e['backend'], e['plugin']): e for e in manifest['executions']}
    coverage = Counter(e['status'] for e in latest.values())
    completed = coverage['success'] + coverage['empty']
    coverage_parts = [f'{completed} completed']
    for status in ('partial', 'failed', 'timeout', 'interrupted', 'unsupported', 'unavailable', 'running'):
        if coverage[status]:
            coverage_parts.append(f'{coverage[status]} {status}')
    stats = ''.join(f'<div class="metric"><strong>{len(data[key]):,}</strong><span>{label}</span></div>'
                    for key, label in [('findings', 'Findings'), ('processes', 'Processes'),
                                       ('networks', 'Network records'), ('modules', 'Module records'),
                                       ('regions', 'Region records'), ('threads', 'Thread records')])
    severity_html = ' '.join(f'<span class="severity {level}">{severity.get(level, 0)} {level}</span>'
                             for level in ('high', 'medium', 'low', 'info'))
    duration = manifest.get('duration_seconds')
    runtime = f'{duration:.0f}s' if isinstance(duration, (float, int)) else 'not recorded'
    version_label = ' · '.join(f'{name} {version}' for name, version in versions.items())
    status_class = manifest['status'] if manifest['status'] in ('complete', 'partial', 'failed') else 'other'
    warning = ('No findings detected by executed checks' if not data['findings'] else
               'Findings are investigation hypotheses. Validate against the linked source artifacts.')
    verification = manifest.get('image_verification', {})
    hash_notice = ''
    if verification.get('sha256_skipped'):
        hash_notice = 'Image SHA-256 skipped; identity checked using file metadata only.'
    elif verification.get('resume_identity') == 'metadata_only':
        hash_notice = 'Image SHA-256 recorded this run; original case identity matched using file metadata only.'
    content = f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Memnolyze — local case report</title><style>
body{{font:15px system-ui;margin:2rem;background:#101820;color:#e1e9ef}} a{{color:#74c7ff}} h1,h2{{color:#bde5ff}}
table{{border-collapse:collapse;width:100%;margin:1rem 0;background:#172632}}td,th{{padding:.6rem;border-bottom:1px solid #344653;text-align:left;vertical-align:top}}
th{{cursor:pointer}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;max-height:24rem;overflow:auto}}summary{{cursor:pointer}}
th{{position:relative;vertical-align:top}}th [data-sort]{{background:transparent;border:0;padding:0;font-weight:bold;text-align:left}}.column-filter{{font-weight:normal;font-size:12px;margin-top:.6rem}}.filter-panel{{position:absolute;z-index:10;left:0;top:100%;min-width:270px;max-width:380px;padding:.8rem;background:#203442;border:1px solid #74c7ff;box-shadow:0 4px 16px #0008}}.filter-panel input[type="search"]{{width:230px}}.filter-panel p{{font-size:11px}}.filter-options{{max-height:260px;overflow:auto;margin-top:.6rem}}.filter-options label{{display:flex;gap:.5rem;align-items:start;padding:.3rem;overflow-wrap:anywhere}}.filter-options input[type="checkbox"]{{width:auto;margin-top:.2rem}}[hidden]{{display:none!important}}
.evidence-record{{border-left:3px solid #74c7ff;padding:0 .8rem;margin:1rem 0}}.original-record{{background:#101820;padding:.8rem}}
button{{padding:.5rem .8rem;cursor:pointer;background:#24485e;color:#e1e9ef;border:1px solid #74c7ff;border-radius:.25rem}}button:focus-visible{{outline:2px solid #f6bf63;outline-offset:2px}}.detail-controls span{{font-size:.85rem;color:#b5c7d3}}
input{{padding:.6rem;width:28rem;max-width:90%;background:#fff;color:#111}} .notice{{padding:1rem;border-left:4px solid #f6bf63;background:#29313a}}
.case-header{{padding:1.2rem 1.4rem;background:linear-gradient(120deg,#1c3345,#172632);border:1px solid #344f62;border-radius:12px}}.header-top{{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}}.header-top h1{{margin:0;font-size:1.7rem}}.badges{{display:flex;gap:.5rem;flex-wrap:wrap}}.badge{{border:1px solid #456276;border-radius:20px;padding:.3rem .7rem;font-size:.82rem;background:#172632}}.badge.complete{{color:#9ce3bf;border-color:#38876a}}.badge.partial{{color:#ffd28a;border-color:#9a7338}}.badge.failed{{color:#ffb0b0;border-color:#ae5555}}.case-meta{{font-size:.85rem;color:#b5c7d3;margin:.8rem 0;overflow-wrap:anywhere}}.metrics{{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:.6rem}}.metric{{background:#10182088;border:1px solid #344f62;border-radius:8px;padding:.65rem .8rem}}.metric strong{{display:block;font-size:1.5rem;color:#e8f4ff}}.metric span{{font-size:.78rem;color:#b5c7d3}}.header-bottom{{display:flex;gap:.6rem 1rem;align-items:center;justify-content:space-between;flex-wrap:wrap;margin-top:.8rem;font-size:.8rem;color:#b5c7d3}}.severity{{display:inline-block;margin-right:.25rem;padding:.2rem .45rem;border-radius:4px;background:#101820}}.severity.high{{color:#ffaaa7}}.severity.medium{{color:#ffd28a}}.severity.low{{color:#96d5fb}}.case-note{{font-size:.8rem;color:#b5c7d3;margin:.7rem 0 0}}.case-metadata{{margin:.6rem 0 1rem;font-size:.85rem;color:#b5c7d3}}@media(max-width:850px){{.metrics{{grid-template-columns:repeat(3,minmax(0,1fr))}}}}@media(max-width:480px){{body{{margin:1rem}}.metrics{{grid-template-columns:repeat(2,minmax(0,1fr))}}}}
</style></head><body><header class="case-header" aria-label="Case overview">
<div class="header-top"><h1>Memnolyze</h1><div class="badges"><span class="badge">Profile: <strong>{escape(manifest.get('profile', 'not recorded'))}</strong></span><span class="badge {status_class}">{escape(manifest['status']).upper()}</span><span class="badge">{'Offline' if manifest['offline'] else 'Symbol downloads allowed'}</span></div></div>
<p class="case-meta">{escape(Path(manifest['image']['path']).name)} · Windows build {escape(windows_build or 'see metadata')} · {escape(version_label)} · Plugin time {escape(runtime)}</p>
<div class="metrics">{stats}</div><div class="header-bottom"><div aria-label="Findings by severity">{severity_html}</div><span>Checks: {escape(' · '.join(coverage_parts))}</span></div>
<p class="case-note">{escape('No findings detected by executed checks' if not data['findings'] else 'Investigation hypotheses; findings require analyst validation.')} {escape(hash_notice)}</p></header>
<details class="case-metadata"><summary>Case metadata · image hash · OS details</summary><p>{escape(warning)} FindEvil is experimental; absent detections on Windows Server do not provide assurance. Counts represent source observations, not deduplicated objects. Plugin time includes all attempts.</p><pre>{escape(json.dumps({'image': manifest['image'], 'created_at': manifest['created_at'], 'schema_version': manifest['schema_version'], 'offline': manifest['offline'], 'backends': manifest['backend_info']}, indent=2))}</pre></details>
<h2>Findings</h2><label>Filter findings <input data-filter="findings" placeholder="Severity, PID, category or title"></label>
{expand_controls('findings')}
{table('findings', ['ID', 'Severity', 'Confidence', 'Process', 'PID', 'Category', 'Evidence sources', 'Finding / evidence'], ''.join(findings))}
<h2>Process Explorer</h2><label>Filter processes <input data-filter="processes" placeholder="Process, PID or command line"></label>
{expand_controls('processes')}
<p>Parent labels use an unambiguous PID match only; generation and acquisition artifacts may prevent definitive parent attribution.</p>
{table('processes', ['PID', 'Name', 'Parent PID', 'Created', 'Command line / artifacts'], ''.join(process_html))}
<h2>Plugin execution history</h2>{expand_controls('executions')}{table('executions', ['Backend', 'Plugin', 'Status', 'Seconds', 'Records', 'Error', 'Original artifacts'], execution_html)}
<script>
{SCRIPT}
</script></body></html>'''
    output = case / 'report.html'
    output.write_text(content, encoding='utf-8')
    return output
