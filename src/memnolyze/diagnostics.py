"""Concise backend failure explanations without copying memory records into logs."""
import logging
from pathlib import Path
from .io import text_tail, read_json


def error_excerpt(stderr: str, stdout: str) -> str:
    """Bound diagnostic text; stdout may also contain forensic records."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    # Some engines write errors to stdout. Do not echo JSON evidence records.
    markers = ('error', 'failed', 'unable to', 'unsatisfied requirement', 'exception', 'typeerror')
    lines += [line.strip() for line in stdout.splitlines()
              if line.strip() and not line.lstrip().startswith(('{', '[{', '"'))
              and any(marker in line.lower() for marker in markers)]
    excerpt = '\n'.join(dict.fromkeys(lines[-8:]))[-1600:]
    return ''.join(char for char in excerpt if char in '\n\t' or char.isprintable())


def log_execution(record: dict, case: object) -> None:
    """Expose terminal failures immediately without echoing arbitrary engine output."""
    status = record['status']
    if status in ('success', 'empty'):
        logging.info('%s/%s: %s%s', record['backend'], record['plugin'], status,
                     f" ({record['record_count']} records)" if 'record_count' in record else '')
        return
    level = logging.WARNING if status in ('partial', 'unsupported', 'interrupted') else logging.ERROR
    logging.log(level, '%s/%s: %s%s. %s', record['backend'], record['plugin'], status,
                f" (exit {record['exit_code']})" if record.get('exit_code') is not None else '',
                record.get('error', 'Check did not complete.'))
    if record.get('extraction_error_summary'):
        logging.log(level, 'Extraction errors: %s', record['extraction_error_summary'])
        source = record.get('artifacts', {}).get('errors')
        if source:
            for error in read_json(Path(case) / source)[:3]:
                detail = error_excerpt(str(error.get('error', '')), '')
                logging.log(level, '%s%s: %s', error.get('operation', 'Extraction'),
                            f" (PID {error['pid']})" if 'pid' in error else '', detail)
    stderr = text_tail(Path(case) / record['stderr_file']) if record.get('stderr_file') else ''
    stdout = text_tail(Path(case) / record['source_file']) if record.get('source_file') else ''
    excerpt = error_excerpt(stderr, stdout)
    if excerpt:
        logging.log(level, 'Engine error excerpt:\n%s', excerpt)
    for key, label in (('stderr_file', 'Engine stderr'), ('source_file', 'Engine output')):
        if record.get(key) and (Path(case) / record[key]).is_file():
            logging.log(level, '%s: %s', label, Path(case).resolve() / record[key])

def failure_hint(backend: str, output: str, offline: bool) -> str:
    text = output.lower()
    if backend == 'volatility':
        if 'layer_name' in text and ('unsatisfied' in text or 'unable to validate' in text):
            return 'Memory image translation requirements were not met. Check the image format, completeness and any VMware sidecars.'
        if 'symbol_table_name' in text or 'offlineexception' in text:
            policy = ('Offline mode blocks symbol downloads; provide matching local symbols or explicitly allow symbol downloads.'
                      if offline else 'Check access to the symbol server and provide matching local symbols if necessary.')
            return 'Windows kernel symbols could not be resolved. ' + policy
        if 'argument -c/--config: expected one argument' in text:
            return 'Volatility launcher argument error. Update the launcher and check any explicit volatility_command override.'
    if 'modulenotfounderror' in text:
        return 'A required Python module could not be imported. Check the selected interpreter and engine installation.'
    if 'dll load failed' in text or 'not a valid win32 application' in text:
        return 'A native engine library could not be loaded. Check architecture, Python compatibility and DLL dependencies.'
    if backend == 'memprocfs' and ('vmm' in text or 'initializ' in text):
        return 'MemProcFS initialization or processing failed. Inspect the original stderr and confirm image support and engine dependencies.'
    return 'Backend execution failed. Inspect the original stdout/stderr artifacts for details.'
