"""Parse MemProcFS forensic YARA records while preserving their original text."""
import re
from collections.abc import Iterator
from pathlib import Path


def matches(path: Path) -> Iterator[dict]:
    block: list[str] = []
    start = 0
    def record() -> dict:
        original = ''.join(block).rstrip()
        fields = {}
        for line in original.splitlines():
            if line.strip() == 'Matches:':
                break
            key, separator, value = line.partition(':')
            if separator:
                fields[key.strip()] = value.strip()
        if not fields.get('Rule'):
            raise ValueError(f'YARA record at line {start} has no rule identifier')
        return {'rule': fields['Rule'], 'pid': fields.get('PID'),
                'name': fields.get('Process Name'), 'address': fields.get('Base Address'),
                'memory_type': fields.get('Type'), 'line_start': start, 'original_record': original}
    with path.open(encoding='utf-8-sig', errors='replace') as stream:
        for line_number, line in enumerate(stream, 1):
            if re.match(r'^Match Index:\s*\d+\s*$', line):
                if block:
                    yield record()
                block, start = [line], line_number
            elif block:
                block.append(line)
            elif line.strip():
                raise ValueError('Unrecognized MemProcFS YARA output format')
    if block:
        yield record()
