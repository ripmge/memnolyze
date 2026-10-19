"""Resolve referenced records for offline report embedding, once per source."""
from collections import defaultdict
from pathlib import Path
from .io import rows

def resolve_records(case: Path, evidence: list[dict]) -> dict[tuple[str, str], dict]:
    """Numeric IDs follow io.rows' zero-based flattening; line:N is one-based."""
    requested: dict[str, set[str]] = defaultdict(set)
    for item in evidence:
        requested[item['source_file']].add(str(item['record_id']))
    resolved = {}
    root = case.resolve()
    for source, identifiers in requested.items():
        for identifier in identifiers:
            resolved[source, identifier] = {'error': 'Referenced record unavailable.'}
        path = Path(source)
        if (not source.startswith('raw/') or path.is_absolute() or '..' in path.parts or
                '\\' in source or not (root / path).resolve().is_relative_to(root / 'raw')):
            for identifier in identifiers:
                resolved[source, identifier] = {'error': 'Invalid evidence path.'}
            continue
        numeric = {int(i): i for i in identifiers if i.isascii() and i.isdecimal()}
        lines = {int(i[5:]): i for i in identifiers
                 if i.startswith('line:') and i[5:].isascii() and i[5:].isdecimal() and int(i[5:]) > 0}
        if 'absence' in identifiers:
            resolved[source, 'absence'] = {'error':
                'Absence reference: this finding compares against the completed source list; '
                'there is no individual record to display.'}
        try:
            if numeric:
                remaining = set(numeric)
                for index, record in enumerate(rows(root / path)):
                    if index in remaining:
                        resolved[source, numeric[index]] = {'record': record}
                        remaining.remove(index)
                    if not remaining:
                        break
            if lines:
                remaining = set(lines)
                with (root / path).open(encoding='utf-8-sig', errors='replace') as stream:
                    for index, line in enumerate(stream, 1):
                        if index in remaining:
                            resolved[source, lines[index]] = {'record': line.rstrip('\r\n')}
                            remaining.remove(index)
                        if not remaining:
                            break
        except (OSError, ValueError) as exc:
            for identifier in identifiers:
                if 'record' not in resolved[source, identifier] and identifier != 'absence':
                    resolved[source, identifier] = {'error': f'Cannot read referenced record: {exc}'}
    return resolved
