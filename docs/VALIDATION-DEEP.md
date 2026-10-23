# Deep profile: actual image validation

On October 18, 2026, the third profile ran against the unchanged `ransomcare-case1.dmp/ransomcare5.dmp`, SHA-256 `078a7fa5dd01c8af4401c3e9d98b63ca0edd3dccd92f5bba80ecf3515494c0e1`.

## Invocation and scope

```powershell
.\.venv\Scripts\python.exe -m memnolyze analyze `
  --image ransomcare-case1.dmp/ransomcare5.dmp `
  --output cases/ransomcase-deep --profile deep `
  --backend all --offline --config config.example.json
```

Volatility 3 **2.28.2** and MemProcFS **5.19.0** ran sequentially without symbol downloads or binary dumps. Quick/Standard raw data was retained; Deep used a separate case. Total backend runtime was **515.688 seconds**, approximately 8 minutes 36 seconds, excluding hashing, discovery, and report generation.

## Results

All **21 Volatility plugins** actually executed: 18 with records and three with valid empty output (`suspicious_threads`, `hollowprocesses`, `processghosting`). None failed or was unavailable.

| Additional Deep check | Resolved plugin class | Records |
|---|---|---:|
| vadinfo | windows.vadinfo.VadInfo | 13,016 |
| handles | windows.handles.Handles | 39,449 |
| threads | windows.threads.Threads | 1,479 |
| privileges | windows.privileges.Privs | 4,200 |

All four returned nonempty, valid JSONL. VADs and threads were normalized and assigned to processes. Handles/privileges remain complete raw exports with counts and links in execution history; separate normalized handle/token views and additional detection rules for them are not implemented.

MemProcFS returned 13,014 VADs and 1,468 threads. Forensic reached 100 percent and FindEvil was exported. As in Standard, VAD retrieval failed for **PID 1708 (`MemCompression`)**. User paths/command lines were also missing for PID 4, 104, and 1708. All seven failed individual operations are recorded in `errors.json`. The case correctly has status **`partial`**, and the analyze command returned exit code **2**. The native VAD failure's cause remains unconfirmed; missing records are not fabricated.

| Normalized artifact | Count |
|---|---:|
| Processes | 134 |
| Network observations | 105 |
| Module observations | 18,211 |
| Regions | 26,041 |
| Threads | 2,947 |
| Findings | 147 |

Region/thread counts preserve observations from both engines rather than deduplicating them. Regions also include 11 malfind observations. Finding counts match Standard: the four Deep checks add investigation context without classifying every VAD, handle, thread, or privilege as suspicious. Four loader/network correlations remain included. Referenced original finding records are embedded directly, alongside record IDs and raw links.

The original Deep report (approximately 14.7 MB) remains in the local validation case `cases/ransomcase-deep` and is excluded from the source archive. The distributed [RansomCase1 example](../examples/README.md) now uses the completed Quick run to keep the report smaller. Reports now also have compact overview metrics, English expand/collapse controls, and unique-value column filters. These UI changes do not alter evidence.

## Verification

```powershell
.\.venv\Scripts\python.exe scripts/verify_case.py cases/ransomcase-deep --allow-partial
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m memnolyze report --case cases/ransomcase-deep
```

- **26 tests passed**. No corrections to Deep extraction or normalization were required.
- **31 artifact hashes**, **48,116 report links**, and **zero external HTML resources** were verified for the Deep report at the validation milestone. Later UI revisions can change the report's exact size or link presentation.
- The local `validation/deep_checks.py` checked 21 actual plugin runs and offline switches. Every Volatility VAD/thread and MemProcFS VAD/thread was compared against the original PID, evidence index, and normalized fields. Handle/privilege counts were verified against raw output.
- Every concrete finding evidence record was checked against its embedded representation. Original raw artifacts were not overwritten.
- Headless Edge exercised expand/collapse, filtered selection, unchanged hidden rows, and filter reset on Standard/Deep. Subsequent tests also covered unique values, finding-type choices, category multi-selection, cross-column AND, individual evidence sources, option search, free-text combination, clearing filters, and sorting.
- The first headless browser launch failed because of the environment's GPU process. The local test worked with in-process GPU and `--no-sandbox`; these flags apply only to the test invocation and are not required by the report. This was not a full visual or cross-platform browser test.

Local console, test, artifact-check, and browser logs under `validation/` are excluded from the archive. Quick, Standard, and Deep have all run against this actual image. This does not validate other images, Windows builds, or engine versions. The known MemProcFS VAD gap remains visible in Standard and Deep.
