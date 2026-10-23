"""Normalize successful artifacts and correlate conservatively across engines."""
import re
from dataclasses import asdict
from pathlib import Path
from .io import rows, read_json
from .models import Process, Artifact

def number(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value), 16 if str(value).lower().startswith('0x') else 10)
    except (TypeError, ValueError):
        return None

def address(value: object) -> str | None:
    n = number(value)
    return hex(n) if n is not None else None

def clean(value: object) -> str | None:
    return None if value in (None, '', '-', 'N/A', 'NotApplicable', 'Unreadable') else str(value)

def process_address(value: object) -> str | None:
    """Volatility can render x64 virtual addresses without sign extension."""
    n = number(value)
    if n is not None and (1 << 47) <= n < (1 << 48):
        n |= 0xffff000000000000
    return hex(n) if n is not None else None

def normalize(case: Path, executions: list[dict]) -> dict[str, list]:
    result: dict[str, list] = {k: [] for k in ('processes', 'networks', 'modules', 'regions', 'threads', 'indicators')}
    process_rows, other_rows = [], []
    successful = {(e['backend'], e['plugin']): e for e in executions
                  if e['status'] in ('success', 'empty', 'partial')}
    for (backend, plugin), execution in successful.items():
        files = {plugin: execution['source_file']} if backend == 'volatility' else execution.get('artifacts', {})
        for kind, source in files.items():
            if kind in ('info', 'errors', 'forensic', 'findevil_listing', 'invocation') or (
                    kind.startswith(('yara', 'findevil-')) and kind != 'yara-result'):
                continue
            if kind == 'findevil':
                for line_number, line in enumerate((case / source).read_text(encoding='utf-8', errors='replace').splitlines(), 1):
                    match = re.match(r'^\s*([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]{8,16})(?:\s+(.*))?$', line)
                    if match:
                        _, pid, name, indicator, va, description = match.groups()
                        other_rows.append(('findevil', {'pid': int(pid), 'name': name, 'type': indicator,
                                           'address': '0x' + va, 'description': description},
                                           {'backend': backend, 'plugin': 'findevil', 'source_file': source,
                                            'record_id': f'line:{line_number}'}))
                continue
            for index, row in enumerate(rows(case / source)):
                evidence = {'backend': backend, 'plugin': kind, 'source_file': source,
                            'record_id': str(index)}
                if kind in ('pslist', 'psscan', 'pstree', 'processes'):
                    process_rows.append((kind, row, evidence))
                else:
                    other_rows.append((kind, row, evidence))
    # Build strongest identities first. A PID alone never merges two process objects.
    process_rows.sort(key=lambda x: ('pslist', 'processes', 'psscan', 'pstree').index(x[0]))
    processes: list[dict] = result['processes']
    for kind, row, evidence in process_rows:
        pid = number(row.get('PID', row.get('Pid', row.get('pid'))))
        if pid is None:
            continue
        offset = process_address(row.get('Offset(V)', row.get('eprocess')))
        created = clean(row.get('CreateTime'))
        name = clean(row.get('ImageFileName', row.get('name')))
        matches = [p for p in processes if p['pid'] == pid and
                   not (created and p['creation_time'] and created != p['creation_time']) and
                   ((offset and p['eprocess'] == offset) or
                    (created and p['creation_time'] == created and not (offset and p['eprocess'] and offset != p['eprocess'])))]
        process = matches[0] if len(matches) == 1 else None
        if process is None:
            identity = f'{pid}:{offset or "unknown-offset"}:{created or evidence["backend"] + ":" + kind + ":" + evidence["record_id"]}'
            process = asdict(Process(identity, pid, name,
                                     number(row.get('PPID', row.get('ppid'))), created, offset,
                                     clean(row.get('cmdline')), clean(row.get('ExitTime'))))
            processes.append(process)
        else:
            for key, value in [('creation_time', created), ('name', name), ('exit_time', clean(row.get('ExitTime')))]:
                if process[key] is None:
                    process[key] = value
            if process['command_line'] is None:
                process['command_line'] = clean(row.get('cmdline'))
        process['evidence'].append(evidence)
    def assign(pid: int | None, row: dict) -> str | None:
        candidates = [p for p in processes if p['pid'] == pid]
        name = clean(row.get('Process', row.get('Owner', row.get('name'))))
        if name:
            narrowed = [p for p in candidates if p['name'] and p['name'].casefold() == name.casefold()]
            if narrowed:
                candidates = narrowed
        # Source lacks generation metadata: only attach to an unambiguous candidate.
        return candidates[0]['process_id'] if len(candidates) == 1 else None
    for kind, row, evidence in other_rows:
        pid = number(row.get('PID', row.get('Pid', row.get('pid'))))
        process_id = assign(pid, row)
        if kind == 'cmdline':
            for process in processes:
                if process['process_id'] == process_id:
                    process['command_line'] = clean(row.get('Args'))
                    process['evidence'].append(evidence)
            continue
        destination, attrs = None, {}
        if kind in ('netscan', 'networks'):
            destination = 'networks'
            attrs = {'local_address': row.get('LocalAddr', row.get('src-ip')),
                     'local_port': row.get('LocalPort', row.get('src-port')),
                     'remote_address': row.get('ForeignAddr', row.get('dst-ip')),
                     'remote_port': row.get('ForeignPort', row.get('dst-port')),
                     'state': row.get('State', row.get('state')),
                     'protocol': row.get('Proto'), 'ip_version': row.get('ver')}
        elif kind in ('dlllist', 'modules', 'ldrmodules'):
            destination = 'modules'
            attrs = {'name': row.get('Name', row.get('name')), 'path': row.get('Path', row.get('MappedPath')),
                     'base': address(row.get('Base', row.get('base'))), 'size': row.get('Size', row.get('size'))}
            if kind == 'ldrmodules':
                attrs['loader_lists'] = {k: row.get(k) for k in ('InLoad', 'InInit', 'InMem')}
        elif kind in ('malfind', 'vadinfo', 'regions'):
            destination = 'regions'
            attrs = {'start': address(row.get('Start VPN', row.get('Start', row.get('start')))),
                     'end': address(row.get('End VPN', row.get('End', row.get('end')))),
                     'protection': row.get('Protection', row.get('protection')),
                     'private': row.get('PrivateMemory')}
        elif kind in ('threads', 'suspicious_threads'):
            destination = 'threads'
            attrs = {'tid': row.get('TID', row.get('tid')), 'start': address(row.get('StartAddress', row.get('Address', row.get('va-start')))),
                     'indicator': row.get('Note', row.get('Notes'))}
        if destination:
            result[destination].append(asdict(Artifact(process_id, pid, attrs, [evidence])))
        category = None
        title = None
        if kind == 'malfind':
            category, title = 'memory_injection', 'Executable private memory region (malfind)'
        elif kind == 'suspicious_threads':
            category, title = 'thread_anomaly', 'Suspicious thread reported by Volatility'
        elif kind in ('hollowprocesses', 'processghosting'):
            category, title = 'loader_anomaly', f'Process image anomaly ({kind})'
        elif kind == 'pebmasquerade' and any(row.get(k) is True for k in
                ('PEB_ImageFilePath_Spoofed', 'PEB_CommandLine_Spoofed')):
            category, title = 'loader_anomaly', 'PEB masquerading indicator'
        # InInit-only differences remain metadata; require a load/memory-list discrepancy.
        elif kind == 'ldrmodules' and any(row.get(k) is False for k in ('InLoad', 'InMem')):
            category, title = 'loader_anomaly', 'Module absent from a loader list'
        elif kind == 'yara-result':
            category, title = 'yara_match', f'YARA: {row["rule"]}'
        elif kind == 'findevil':
            indicator = row['type']
            category = ('yara_match' if indicator.startswith('YR_')
                        else 'memory_injection' if indicator in ('PE_INJECT', 'PRIVATE_RWX', 'PRIVATE_RX', 'NOIMAGE_RX')
                        else 'thread_anomaly' if indicator == 'THREAD'
                        else 'loader_anomaly' if indicator.startswith(('PE_', 'PEB_')) else 'backend_indicator')
            title = f'FindEvil: {indicator}'
        if category:
            result['indicators'].append({'process_id': process_id, 'pid': pid, 'category': category,
                                        'title': title, 'address': row.get('address', attrs.get('start') or attrs.get('base') or address(row.get('Base'))),
                                        'evidence': [evidence]})
    # Scan-only requires a completed active list, and excludes known terminated processes.
    if ('volatility', 'pslist') in successful:
        for process in processes:
            plugins = {e['plugin'] for e in process['evidence'] if e['backend'] == 'volatility'}
            if 'psscan' in plugins and 'pslist' not in plugins and not process['exit_time']:
                result['indicators'].append({'process_id': process['process_id'], 'pid': process['pid'],
                    'category': 'scan_only', 'title': 'Scan process absent from completed active list',
                    'address': process['eprocess'], 'evidence': process['evidence'] + [
                        {'backend': 'volatility', 'plugin': 'pslist',
                         'source_file': successful[('volatility', 'pslist')]['source_file'], 'record_id': 'absence'}]})
    return result
