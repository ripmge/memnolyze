"""Stable normalized schema; backend-specific fields remain in raw artifacts."""
from dataclasses import dataclass, field
from typing import Any

@dataclass
class Evidence:
    backend: str
    plugin: str
    source_file: str
    record_id: str

@dataclass
class Process:
    process_id: str
    pid: int
    name: str | None = None
    ppid: int | None = None
    creation_time: str | None = None
    eprocess: str | None = None
    command_line: str | None = None
    exit_time: str | None = None
    evidence: list[dict] = field(default_factory=list)

@dataclass
class Artifact:
    """Network/module/region/thread share provenance and nullable identity."""
    process_id: str | None
    pid: int | None
    attributes: dict[str, Any]
    evidence: list[dict]

@dataclass
class Finding:
    finding_id: str
    category: str
    severity: str
    confidence: str
    title: str
    process_id: str | None
    pid: int | None
    address: str | None
    evidence: list[dict]
    description: str
    limitations: list[str] = field(default_factory=lambda: [
        'Indicator requiring analyst validation; legitimate software or acquisition artifacts may explain it.'
    ])
