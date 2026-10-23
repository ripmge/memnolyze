# Standard profile: actual image validation

On October 18, 2026, the Standard profile ran with **Volatility 3 2.28.2** and **MemProcFS 5.19.0** against the unchanged `ransomcare-case1.dmp/ransomcare5.dmp`. SHA-256: `078a7fa5dd01c8af4401c3e9d98b63ca0edd3dccd92f5bba80ecf3515494c0e1`.

## Reproduction

```powershell
.\.venv\Scripts\python.exe -m memnolyze analyze `
  --image ransomcare-case1.dmp/ransomcare5.dmp `
  --output cases/ransomcase-standard --profile standard `
  --backend all --offline --config config.example.json
```

Execution was sequential without symbol downloads. Quick raw artifacts were not modified. Total backend runtime was **349.466 seconds**, excluding image hashing, discovery, and report generation.

## Actual coverage

**Case status: `partial`; CLI exit code: `2`.** All 17 Volatility plugins ran successfully. MemProcFS exported VAD/thread metadata and completed forensic/FindEvil results, but could not read one VAD table.

| Additional Volatility check | Status | Records |
|---|---|---:|
| dlllist | success | 5,717 |
| ldrmodules | success | 5,663 |
| suspicious_threads | empty | 0 |
| hollowprocesses | empty | 0 |
| processghosting | empty | 0 |
| pebmasquerade | success | 120 |
| callbacks | success | 235 |
| modules | success | 171 |
| driverirp | success | 3,922 |

`empty` denotes valid empty output, not proof of malware absence. All eight Quick checks also succeeded, with the same record counts as the earlier Quick run.

MemProcFS exported **13,014 VAD records**, **1,468 threads**, 6,660 modules, 43 network records, and 115 processes. Forensic reached 100 percent and FindEvil yielded 12 indicators. `ProcessMaps.vad()` failed for **PID 1708 (`MemCompression`)**. No VAD records were invented. The underlying native API failure was not established; no conclusion about manipulation or system health follows from it.

User paths and command lines were also missing for PID 4, 104, and 1708, as in Quick. All seven failed individual operations are preserved in `errors.json`. The VAD gap correctly results in partial status.

## Normalized output

| Artifact | Count |
|---|---:|
| Correlated processes | 134 |
| Network observations | 105 |
| Module observations, including loader/kernel records | 18,211 |
| Regions: MemProcFS VADs plus malfind | 13,025 |
| Threads | 1,468 |
| Individual indicators | 143 |
| Findings including correlations | 147 |

Module/network counts preserve observations from multiple sources; they are not deduplicated object counts. Kernel modules have no invented process association. Callback/IRP raw data remains accessible through execution history.

Findings comprise 11 memory-injection indicators, 121 loader indicators, six other backend indicators, five thread indicators, and **four "Loader anomaly with network activity" correlations**. Loader indicators comprise 118 ldrmodules records, two positive PEB flags, and one FindEvil loader indicator. All 147 findings are associated with a process and have medium severity. Correlations have medium confidence; individual indicators have low confidence. These are investigation hypotheses, not malware confirmations.

The original local Standard report was approximately 10.4 MB, without external resources. That case is not included in the archive; see the [included Quick example](../examples/README.md). Full browser performance was not benchmarked.

## Integration corrections

- This ldrmodules version uses **`Pid`**. Normalization now handles it, enabling process correlation.
- Loader records also become normalized modules with base address, path, and original loader flags.
- `suspicious_threads` uses **`Address`**. The mapping was corrected against the installed official plugin source and regression-tested. This actual image returned no records from that plugin; all 1,468 native MemProcFS thread records were checked against their originals.
- Loader/ghosting indicators retain their base address as the finding address.
- An isolated missing `InInit` entry remains metadata. A loader finding requires `InLoad` or `InMem` to be explicitly false. All original flags are retained. This excludes 111 InInit-only observations from prioritization while retaining 118 load/memory-list discrepancies. It is an analyzer prioritization decision, not proof of legitimacy.
- Upgrading Quick to Standard/Deep refreshes a previously successful MemProcFS Quick job to obtain additional VAD/thread data. Equivalent Standard/Deep metadata can be reused. Profile upgrades have a separate regression test.

After normalization corrections, existing artifacts were re-evaluated through targeted resume without repeating completed plugins:

```powershell
.\.venv\Scripts\python.exe -m memnolyze analyze `
  --image ransomcare-case1.dmp/ransomcare5.dmp `
  --output cases/ransomcase-standard --profile standard `
  --backend volatility --offline --config config.example.json --resume
```

The partial MemProcFS job remains visible in the case and results. Selecting Volatility prevents another attempt at that failed VAD extraction; case status remains partial.

## Checks

```powershell
.\.venv\Scripts\python.exe scripts/verify_case.py cases/ransomcase-standard --allow-partial
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q src tests scripts
```

At this milestone, **22 tests passed**, **27 artifact hashes** and **33,613 report links** were verified, and no external HTML resources were present. Later report changes increased the suite to 26 passing tests.

The local `validation/standard_checks.py` compared all 13,014 VADs and 1,468 threads to their original records, including PID, evidence index, and addresses. It also verified all 5,663 loader records, process attribution, base addresses, findings, and the known VAD gap. Local console/test/verification artifacts remain excluded from Git and the source archive.

The verifier requires a complete case by default. `--allow-partial` explicitly permits integrity checks for a documented partial case and reports partial jobs; it does not declare coverage complete.
