# Architecture decisions

## Vertical slice

`CLI -> image validation/hash -> capability discovery -> sequential backend jobs -> raw artifacts -> normalization -> rules -> HTML`

Python 3.12.10 x64 was compatible with the available native MemProcFS binaries. The application uses argparse, JSON configuration, dataclasses, and a static HTML report without additional runtime packages. `pyproject.toml` exposes optional engine and test dependencies. The offline bootstrap registers source through a `.pth` file and can create a virtual environment with existing system packages.

## Engines and process isolation

Volatility runs through its CLI, using plugin classes discovered from `--help`, the JSONL renderer, and argument arrays without a shell. Logical names prefer the current `windows.malware` namespace. Each plugin has a separate subprocess, timeout, stdout, and stderr artifact.

MemProcFS uses its official native Python API in an isolated worker. A separate distribution can be selected with `memprocfs_path`. The API was tested against the actual image, including `-forensic 2`, without a drive mount or Dokany. The documented `-pythonexec` approach was reviewed using official documentation and the bundled example. It also provides a Vmm object, but introduces EXE/Python-plugin startup. Since the API path worked, no practical comparison of both startup methods was performed.

Native forensic processing requires writable temporary storage. APPDATA, XDG_CACHE_HOME, TEMP, and TMP are redirected only for child processes to the configured project state directory. The worker waits for `/forensic/progress_percent.txt == 100`, discovers the FindEvil directory, and exports only stable, nonempty results. Original output remains available. Missing symbols and native initialization failures remain visible; no synthetic results replace failed extraction.

## Data and integrity

The image is opened read-only and hashed in 8 MiB blocks. Raw artifacts are stored in immutable attempt directories with random identifiers. An atomically replaced manifest records job status before and after execution. Resume rehashes the image and verifies cached artifact SHA-256 values. Configuration, PID scope, and network policy must match. A case lock prevents concurrent analysis of the same case; a stale lock after a hard kill requires manual removal after checking that no analyzer is running.

Normalization and rules consume successful, valid-empty, or explicitly partial extractions. Each record carries a backend, logical plugin, relative raw path, and record index. JSONL indices follow recursive flattening, excluding blank lines and `__children`; `io.rows` reproduces this order. FindEvil references use original text line numbers. Process identity uses PID with EPROCESS or creation time. Canonical x64 sign extension reconciles Volatility and MemProcFS EPROCESS addresses. Ambiguous PID matches remain unresolved. Network timestamps are not yet checked against process lifetimes.

Rules generate explainable hypotheses with separate severity and confidence. Empty results never imply malware clearance. The UI uses the normalized schema; finding details may embed the exact referenced evidence record for verification. Foreign strings are HTML-escaped, and raw links are restricted to relative paths under `raw/`. There are no external scripts, CDNs, or fetch requests.

## Deliberate limits

Sequential execution limits IO pressure. Images and JSONL are streamed, while normalized tables and report HTML are held in memory. Very large cases will need pagination or a local database. MemProcFS Quick exports processes, modules, networks, and FindEvil; Standard/Deep or PID scope adds VADs and threads. Deep enables selected metadata plugins without dumping process memory. YARA is disabled by default. Explicit custom-rule scanning and independent Elastic License 2.0 opt-in enable the corresponding forensic engine options. Custom-only runs explicitly disable bundled rules even when the engine has cached earlier license acceptance. Entry rules and recognized source includes are hashed and copied per attempt; changed inputs invalidate MemProcFS reuse. Original match blocks become evidence-backed YARA findings. Binary extraction remains future work.

Offline mode uses the documented offline/symbol-server switches and disables MemProcFS Python plugins. Explicit YARA scans use local supplied or bundled rules in either network policy; no rule downloads are added. The orchestrator makes no network connections itself. Enforce a strict network boundary using an isolated VM or firewall; the wrapper cannot sandbox arbitrary or locally modified engines. Direct child processes are terminated on interruption; general Windows Job Object management for arbitrary subprocess trees is not implemented.

## Official references

- [Volatility CLI](https://volatility3.readthedocs.io/en/stable/vol-cli.html)
- [MemProcFS Python API](https://github.com/ufrisk/MemProcFS/wiki/API_Python)
- [MemProcFS CLI and offline switches](https://github.com/ufrisk/MemProcFS/wiki/_CommandLine)
- [Forensic readiness](https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic)
- [FindEvil formats and limitations](https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil)
