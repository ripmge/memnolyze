"""Deterministic hypotheses, deliberately separate from extraction/parsing."""
from dataclasses import asdict
from .models import Finding

def detect(data: dict) -> list[dict]:
    findings = []
    def add(category: str, title: str, pid: int | None, identity: str | None,
            evidence: list[dict], address: str | None = None,
            severity: str = 'medium', confidence: str = 'low') -> None:
        findings.append(asdict(Finding(f'F-{len(findings)+1:04d}', category, severity, confidence,
            title, identity, pid, address, evidence,
            title + '. This is an investigation hypothesis, not a malware confirmation.')))
    for indicator in data['indicators']:
        add(indicator['category'], indicator['title'], indicator['pid'], indicator['process_id'],
            indicator['evidence'], indicator['address'])
    for process in data['processes']:
        identity, pid = process['process_id'], process['pid']
        signals = [i for i in data['indicators'] if i['process_id'] == identity]
        categories = {i['category'] for i in signals}
        evidence = [e for signal in signals for e in signal['evidence']]
        if {'memory_injection', 'thread_anomaly'} <= categories:
            add('correlation', 'Memory and thread anomalies in the same process', pid, identity,
                evidence, severity='high', confidence='medium')
        injection = [i for i in signals if i['category'] == 'memory_injection']
        engines = {e['backend'] for i in injection for e in i['evidence']}
        if len(engines) > 1:
            add('correlation', 'Injection indicators reported by both engines', pid, identity,
                [e for i in injection for e in i['evidence']], severity='high', confidence='medium')
        networks = [n for n in data['networks'] if n['process_id'] == identity]
        if 'loader_anomaly' in categories and networks:
            add('correlation', 'Loader anomaly with network activity', pid, identity,
                evidence + [e for n in networks for e in n['evidence']], confidence='medium')
        if len(categories) >= 3:
            add('correlation', 'Multiple independent indicator categories', pid, identity,
                evidence, severity='high', confidence='medium')
    return findings
