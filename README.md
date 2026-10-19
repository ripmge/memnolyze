# Memnolyze

A local Windows memory triage tool for DFIR analysts. Memnolyze orchestrates Volatility 3 and MemProcFS, preserves raw evidence, correlates processes, and produces traceable findings and a standalone HTML report. It does not acquire live memory, upload evidence, run extracted binaries, or provide malware clearance.

## Requirements and dependencies

Windows x64 and Python 3.11 or 3.12 x64 are the initial target platform. Development validation used Python 3.12.10, Volatility 3 2.28.2, and MemProcFS 5.19.0.

| Component | Purpose | Installation |
|---|---|---|
| Python 3.11/3.12 x64 | Runtime | Install on the destination computer |
| Python standard library | Application runtime | No additional application dependencies |
| setuptools >= 68 | Regular package installation | Provided by the pip build environment |
| volatility3 >= 2.28.0 | Volatility backend | `engines` extra or an existing CLI installation |
| memprocfs >= 5 | MemProcFS backend, native x64 extension | `engines` extra or a separate binary directory |
| pytest >= 8 | Optional test runner | `test` extra; unittest also works without additional packages |

The source archive does not include Python, a virtual environment, engine binaries, symbols, or a memory image. Dokany is not required for the Python API integration. Backends can run independently.

## Install and run

Extract the archive, open PowerShell, and install the project:

```powershell
cd .\memnolyze
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[engines,test]"
.\.venv\Scripts\python.exe -m memnolyze doctor --config config.portable.json
.\.venv\Scripts\python.exe -m memnolyze analyze `
  --image "D:\Images\server.dmp" `
  --output ".\cases\my-case" `
  --profile quick --backend all --offline --config config.portable.json
Start-Process .\cases\my-case\report.html
```

Offline analysis requires the correct symbols to be available already; see **Symbols and network access** below. Use `--backend volatility` to run only Volatility.

`config.portable.json` discovers regularly installed engines. `config.example.json` demonstrates using a separately extracted MemProcFS directory containing `memprocfs.py`, `vmmpyc.pyd`, and the native DLLs. Relative paths are resolved against the current working directory.

For an offline source setup with existing engines, run `scripts/bootstrap.ps1`. It creates a virtual environment with system packages if needed and registers `src` using a `.pth` file. It does not download packages. An existing isolated virtual environment must have its engines installed separately. Use `scripts/bootstrap.ps1 -Config config.example.json` for the separate MemProcFS directory configuration. Activating the environment is optional; use its Python executable explicitly.

Supported input hints include RAW (`.raw`, `.mem`, `.bin`), VMware (`.vmem`), and Windows dumps (`.dmp`). Files are passed to the engines without custom conversion. Directories and compressed archives are not accepted as images. VMware sidecars in the same directory are recorded, including their absence. Successful backend OS identification determines whether the image was initialized, not the filename extension.

The original development image was `ransomcare-case1.dmp/ransomcare5.dmp`: a file inside a directory whose name also ends in `.dmp`. This image is not included in the archive.

## Included example and source archive

Open the actual [Deep example report](examples/deep-case/report.html) locally. The example comes from the publicly obtained demonstration memory image used during development, and includes raw records, normalized data, its manifest, and execution logs so relative evidence links remain usable. It is not a synthetic analysis. Its status remains `partial` because of the documented MemProcFS VAD limitation.

```powershell
# View the example without a memory image or running engines:
Start-Process .\examples\deep-case\report.html
# Regenerate it after changing the renderer:
.\.venv\Scripts\python.exe -m memnolyze report --case examples/deep-case
```

Historical absolute image/tool paths in the example document the original analysis environment. They are not needed to view or regenerate the report. Use your own image and output directory for new analyses. Paths under `cases/` in validation notes describe the original local runs; only the Deep case is included in the archive, under `examples/deep-case/`.

`python scripts/package_project.py` builds `dist/memnolyze-source.zip` and a SHA-256 sidecar from an explicit list of project directories. It excludes virtual environments, caches, images, downloaded engine binaries, other cases, local validation outputs, and Git metadata. The explicitly selected Deep example is the exception. After extracting the archive, the project directory can be initialized as a new Git repository. The archive itself is ignored by Git.

Project documentation, source comments, CLI messages, and report controls use **English**. Original forensic records are retained in their source language; translating them would change evidence.

The project, Python package, and command are named **memnolyze**. Historical commands in the included case logs/manifest retain the original tool name as recorded during analysis; they are evidence history, not current setup instructions.

## Symbols and network access

Offline is the default. Existing symbols are reused. Symbol downloads must be enabled explicitly for initial setup:

```powershell
.\.venv\Scripts\python.exe -m memnolyze analyze --image "D:\Images\server.dmp" `
  --output "D:\Results\symbol-setup" --backend volatility --plugin info `
  --allow-symbol-downloads --config config.portable.json
```

Volatility requires matching Windows ISF symbols. A `kernel.symbol_table_name` requirement failure is not a successful analysis. Child processes use the configured state directory, `.state` by default, for APPDATA and their cache. Depending on the Volatility version, downloaded ISFs may also reside in its installed symbol directories. `symbol_dirs` adds local search paths. Copy the required symbol files or provide a local symbol directory when moving to another computer.

MemProcFS uses its local `info.db` by default; its additional debug-symbol subsystem is disabled. `memprocfs_symbols: true` enables that subsystem only outside offline mode. YARA is disabled, and no Elastic or other rule-set license is accepted automatically. FindEvil is experimental, particularly on Windows Server: absent detections are not evidence of a clean system.

The orchestrator makes no network connections itself. Offline control relies on documented engine switches. Use a disconnected VM or firewall for OS-enforced network isolation; arbitrary modified engines cannot be sandboxed by this wrapper.

## CLI examples

```powershell
# Run either backend independently:
.\.venv\Scripts\python.exe -m memnolyze analyze --image "D:\Images\server.vmem" --output "D:\Results\vol" --backend volatility
.\.venv\Scripts\python.exe -m memnolyze analyze --image "D:\Images\server.vmem" --output "D:\Results\mpfs" --backend memprocfs --config config.portable.json

# Resume an incomplete case; verify and reuse successful artifacts:
.\.venv\Scripts\python.exe -m memnolyze analyze --image "D:\Images\server.dmp" --output "D:\Results\case" --resume --config config.portable.json

# Retry one failed plugin; info is always included:
.\.venv\Scripts\python.exe -m memnolyze analyze --image "D:\Images\server.dmp" --output "D:\Results\case" --backend volatility --plugin netscan --resume --config config.portable.json

# Explicitly rerun a completed extraction, retaining previous raw attempts:
.\.venv\Scripts\python.exe -m memnolyze analyze --image "D:\Images\server.dmp" --output "D:\Results\case" --backend memprocfs --resume --rerun triage --config config.portable.json

# Investigate one PID in a separate case:
.\.venv\Scripts\python.exe -m memnolyze analyze --image "D:\Images\server.dmp" --output "D:\Results\pid1234" --pid 1234 --profile standard --config config.portable.json

# Rebuild HTML from normalized case data:
.\.venv\Scripts\python.exe -m memnolyze report --case "D:\Results\case"
```

Options: `--profile quick|standard|deep`, `--backend volatility|memprocfs|all`, `--pid`, `--config`, `--resume`, `--offline`, `--allow-symbol-downloads`, `--verbose`, repeatable `--plugin LOGICAL_NAME`, and repeatable `--rerun LOGICAL_NAME|triage`.

Volatility PID arguments are added only when the installed plugin advertises `--pid`; global checks remain global. MemProcFS PID scope limits process/module/VAD/thread exports, while forensic processing and network extraction remain global. Ambiguous artifact attribution remains unresolved rather than being guessed.

Exit codes: `0` completed requested checks; `2` partial results/backend failure; `1` invalid arguments or IO failure; `130` interrupted. `empty` means valid empty output, not a positive extraction; empty OS/pslist baselines are failures. `unsupported` plugins are visibly skipped and do not count as executed checks. Historical failures remain visible after successful retries.

Resume requires the same configuration, PID scope, offline policy, and image hash. Profile/backend/plugin selection can change, and existing case artifacts remain available. Upgrading Quick to Standard/Deep refreshes MemProcFS extraction to obtain VADs and threads. Ctrl+C retains completed results. After a hard kill, `.analysis.lock` may remain: verify that no analyzer is running before removing that individual lock.

## Configuration and profiles

Configuration is JSON; unknown keys are rejected. `volatility_command` is an argument array such as `["D:\\Tools\\venv\\Scripts\\vol.exe"]`, with no shell interpolation. `memprocfs_path` can be `null` for a regular pip installation or point to the directory containing its Python module and native binaries.

| Setting | Behavior |
|---|---|
| `state_dir` | Child-process cache and temporary directory |
| `symbol_dirs` | Additional local Volatility symbol directories |
| `timeout_seconds` | Per-plugin process timeout |
| `forensic_timeout_seconds` | Additional MemProcFS allowance and forensic wait limit after baseline extraction |
| `memprocfs_forensic` | Set to `false` to disable forensic processing and FindEvil |
| `memprocfs_symbols` | Additional debug symbols; disabled in offline mode |
| `max_vfs_bytes` | Maximum FindEvil export size |
| `plugins` | Optional logical plugin list replacing the selected Volatility profile |
| `plugin_args` | Metadata arguments: `--pid`, `--offset`, `--address`, `--maxsize`, `--size`; no dump switches |

| Profile | Volatility checks, when advertised by the installed version |
|---|---|
| quick | info, pslist, psscan, pstree, cmdline, netscan, svcscan, malfind |
| standard | quick + dlllist, ldrmodules, suspicious_threads, hollowprocesses, processghosting, pebmasquerade, callbacks, modules, driverirp |
| deep | standard + vadinfo, handles, threads, privileges |

Plugin classes are discovered from the installed CLI, including current malware namespaces. MemProcFS Quick exports OS information, processes, modules, network records, and forensic/FindEvil results. Standard/Deep or PID scope adds VADs and threads. Deep handles and privileges are currently raw exports; VADs and threads are normalized.

All three profiles were run on the actual test image. Standard and Deep remain partial because MemProcFS could not read the VAD table of MemCompression. See [Standard validation](docs/VALIDATION-STANDARD.md) and [Deep validation](docs/VALIDATION-DEEP.md).

## Output and report

```text
case/
  manifest.json                  # Image hash, versions, status, execution history
  config.json
  logs/analyzer.log
  logs/plugin_execution.json
  raw/volatility/<plugin>-<id>/   # Original stdout/stderr for each attempt
  raw/memprocfs/triage-<id>/      # API records, FindEvil, errors, invocation
  normalized/                    # Processes, networks, modules, regions, threads,
                                 # indicators and findings as JSON
  exports/                       # Reserved for future explicit exports
  report.html
```

The standalone report works through `file://` without external CDNs or services. Its compact header shows the profile, status, result counts, severity distribution, and check coverage. Process details include parent relationships, command lines, modules, networks, and linked findings. Severity and confidence are separate. PIDs are correlated with EPROCESS/creation time where available; ambiguous matches remain `null`.

Header **Filter (N)** menus list unique column values and their frequencies across all rows. Multiple values within a column use OR; different columns and free-text search use AND. No selection means no restriction. **Clear filters** resets the table. **Evidence sources** filters individual backend/plugin origins; the **Finding / evidence** menu uses finding titles rather than full embedded JSON. Click a column title to sort.

**Expand all** and **Collapse all** operate on currently visible rows in Findings, Process Explorer, and execution history. These controls and filtering were exercised with headless Edge.

Opening a finding shows its **Referenced original records** inline, alongside backend/plugin identifiers, record IDs, and raw file links. Numeric IDs are zero-based indices after flattening nested `__children`; `line:N` is an original one-based FindEvil text line. Only requested records are loaded once per source. Missing records and absence references are explained explicitly. HTML strings are escaped. Rebuilding the report does not rerun analysis.

Initial rules cover scan-only processes, combined memory/thread anomalies, injection indicators from both engines, loader anomalies with network activity, and multiple independent categories. Findings are investigation hypotheses requiring analyst validation.

## Tests, validation, and limitations

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
# Optional, when pytest is installed:
.\.venv\Scripts\python.exe -m pytest
```

The suite supports both runners. **26 tests passed** in development; the unittest runner was used because package downloads were restricted. See [Quick validation](docs/VALIDATION.md), [Standard validation](docs/VALIDATION-STANDARD.md), [Deep validation](docs/VALIDATION-DEEP.md), and [architecture](docs/ARCHITECTURE.md).

| Actual test-image run | Processes | Regions | Thread observations | Findings | Status |
|---|---:|---:|---:|---:|---|
| Quick | 134 | 11 | 0 | 23 | complete |
| Standard | 134 | 13,025 | 1,468 | 147 | partial |
| Deep | 134 | 26,041 | 2,947 | 147 | partial |

Counts preserve observations from multiple sources rather than deduplicating every module, region, thread, or network object. A missing MemProcFS VAD table for PID 1708 explains the partial Standard/Deep status. Additional Windows builds, VMware/RAW inputs, and positive Volatility suspicious-thread cases need more real-image validation. The image and JSONL are streamed, but normalized tables and report HTML are currently built in RAM.

Useful next steps are manual finding prioritization, process-lifetime-aware network attribution, selective forensic CSV/JSON exports, and report pagination. Custom YARA rules and binary dumps are not implemented.
