# Quick validation: October 18, 2026

## Environment

- Windows x64, NT 10.0.26100; Python 3.12.10 x64.
- Volatility 3 **2.28.2**, an existing global installation accessible from the project virtual environment.
- MemProcFS **5.19.0**, the native runtime version reported by `Vmm.get_config`; local binaries selected through `config.example.json`.
- Package downloads from the agent environment failed with `WinError 10013`. pytest/setuptools were not preinstalled. The offline source bootstrap and standard-library unittest runner were used; the pytest-compatible suite was not run with pytest itself.
- Volatility initially failed because its default cache was outside the writable project directory. Child processes now use a project state path.

## Actual image

File: `ransomcare-case1.dmp/ransomcare5.dmp`; this is not a synthetic memory image.

```text
Size:   8,588,951,552 bytes
SHA256: 078a7fa5dd01c8af4401c3e9d98b63ca0edd3dccd92f5bba80ecf3515494c0e1
Layer:  WindowsCrashDump64Layer, reported by Volatility
OS:     Windows, kernel build 17134, x64
```

Volatility initially lacked matching kernel symbols in offline mode. The user downloaded symbols with Volatility outside the agent sandbox; afterwards `windows.info` succeeded **with `--offline`**. The matching ISF was available under the installed Volatility directory at `symbols/windows/ntkrnlmp.pdb/5B396742883C48D0AB74C7374DEEE916-1.json.xz`. Reproduction on another host requires those symbols or equivalent local symbol setup.

MemProcFS identified plausible OS metadata and 115 processes without symbol downloads. An initial forensic startup without a writable project TEMP produced no usable output. Redirecting TEMP/TMP allowed forensic processing and FindEvil to complete. The native Python API was actually tested; an EXE `-pythonexec` comparison was not performed.

## Complete Quick run

```powershell
.\scripts\bootstrap.ps1 -Config config.example.json
.\.venv\Scripts\python.exe -m memnolyze analyze `
  --image ransomcare-case1.dmp/ransomcare5.dmp `
  --output cases/ransomcase-quick --profile quick --backend all `
  --offline --config config.example.json
```

The original local case preserves earlier integration attempts. Two version differences were corrected: `windows.info` provided `Major/Minor` rather than `NTBuildLab` on this image, and MemProcFS module size was exposed as `image_size`, not `size`. The case was then resumed:

```powershell
.\.venv\Scripts\python.exe -m memnolyze analyze `
  --image ransomcare-case1.dmp/ransomcare5.dmp --output cases/ransomcase-quick `
  --profile quick --backend all --offline --config config.example.json `
  --resume --rerun triage
```

| Check | Actual result |
|---|---|
| info | Plausible kernel/OS metadata; final attempt successful |
| pslist | 120 records |
| psscan | 134 records |
| pstree | 120 flattened records |
| cmdline | 120 records |
| netscan | 62 records |
| svcscan | 1,330 records |
| malfind | 11 records |
| MemProcFS | 115 processes, 6,660 modules, 43 network records |
| Forensic | 100 percent; FindEvil artifact checked and exported |
| FindEvil | 12 normalized indicators |
| Normalized | 134 processes, 105 network records, 6,660 modules, 11 regions |
| Findings | 23; severity medium, confidence low |
| Case | `complete`; final selected jobs successful |

Network/module counts preserve source observations rather than deduplicating every object across engines. Real output confirmed that Volatility may omit upper x64 EPROCESS sign bits while MemProcFS provides canonical addresses. Normalization reconciles these representations using the address and PID, without PID-only merging.

The findings consist of 11 malfind regions, six FindEvil `PROC_DEBUG` indicators, five thread indicators, and one loader indicator. They are **not malware confirmations**. Correlation rules were tested with synthetic unit fixtures; this real Quick run produced no extra combined findings. Known terminated processes are excluded from scan-only indicators.

MemProcFS could not retrieve user paths/command lines for PID 4, 104, and 1708: six individual missing fields recorded in the original `errors.json`. Process/module/network extraction and forensic processing succeeded. No missing field values were invented.

The original Quick run remains under local `cases/ransomcase-quick`. Its distributable copy, with the current report UI and unchanged raw evidence, is the [RansomCase1 example](../examples/README.md) under `examples/ransomcase1`.

## Independent backends

```powershell
.\.venv\Scripts\python.exe -m memnolyze analyze --image ransomcare-case1.dmp/ransomcare5.dmp --output cases/volatility-independent --backend volatility --plugin pslist --config config.example.json --offline
.\.venv\Scripts\python.exe -m memnolyze analyze --image ransomcare-case1.dmp/ransomcare5.dmp --output cases/memprocfs-independent --backend memprocfs --config config.example.json --offline
```

- Volatility alone: `complete`; successful info/pslist, 120 processes, no findings from these baseline checks.
- MemProcFS alone: `complete`; 115 processes and 12 FindEvil findings.

## Resume, report, and tests

A subsequent full resume reused all eight Volatility jobs and the MemProcFS job without new engine execution or raw-file replacement. The image and cached artifact hashes were verified.

```powershell
.\.venv\Scripts\python.exe -m memnolyze report --case cases/ransomcase-quick
.\.venv\Scripts\python.exe scripts/verify_case.py cases/ransomcase-quick
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

At the Quick milestone, **18 tests passed**, compilation succeeded, **28 artifact hashes** and **7,473 report links** were checked, and there were **zero external HTML resources**. These counts describe that historical report version. Later report/evidence work increased the suite to **26 passing tests**. Initially no browser automation was used; subsequent controls/filtering were tested with headless Edge as described in the Deep notes.

Coverage includes paths with spaces, missing executables, aliases/unavailable plugins, empty/malformed output, PID reuse and ambiguous attribution, canonical addresses, scan-only rules, FindEvil parsing, correlation rules, HTML escaping, rejected dump arguments, timeouts/cleanup, plugin failure isolation, interrupted cases, immutable resume, changed image hashes, and tampered artifacts. Explicitly synthetic API fixtures test incomplete forensic readiness and offline/license switches; these are never presented as real analysis results.

## Follow-up validation and remaining limits

[Standard](VALIDATION-STANDARD.md) and [Deep](VALIDATION-DEEP.md) were subsequently run on the same actual image. Both are partial because of one missing MemProcFS VAD table. Quick results above remain unchanged.

- Other Windows builds, VMware sidecars, RAW images, and positive Volatility suspicious-thread cases need additional real-image testing.
- Custom YARA, binary dumps, and comprehensive forensic CSV/JSON exports are not implemented.
- Standard/Deep or PID scope exports VAD/thread metadata; Quick can still contain FindEvil thread indicators.
- Network switches were used, but traffic was not measured with packet capture. OS-enforced isolation and modified-engine behavior are outside the orchestrator.
- Normalized tables and HTML are built in memory, while images and JSONL are streamed.
- Ctrl+C terminates the direct backend child. General Windows Job Object management of arbitrary third-party process trees is not implemented.
- Case access and retention remain the analyst's responsibility; the analyzer does not upload evidence.
