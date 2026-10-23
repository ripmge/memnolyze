# RansomCase1 example

This is the actual **Quick** analysis of the public RansomCase1 demonstration image used during development. The folder is named for the case; the profile is recorded in its manifest and report. Quick is the smallest of the three profiles (`quick`, `standard`, `deep`).

| Recorded result | Value |
|---|---|
| Status | Complete |
| Windows kernel build | 17134, x64 |
| Engines | Volatility 3 2.28.2 and MemProcFS 5.19.0 |
| Completed checks | 8 Volatility plugins and MemProcFS triage |
| Processes | 134 |
| Network observations | 105 |
| Module observations | 6,660 |
| Findings | 23, all medium severity / low confidence |

The findings are 11 executable private memory regions from malfind, six FindEvil PROC_DEBUG indicators, five FindEvil THREAD indicators, and one FindEvil PEB_BAD_LDR indicator. These are investigation leads, not malware confirmations. Counts preserve source observations. See the [actual findings](ransomcase1/normalized/findings.json), [manifest](ransomcase1/manifest.json), and [validation notes](../docs/VALIDATION.md).

The [interactive HTML report](ransomcase1/report.html) is approximately 2.2 MB, compared with approximately 14.7 MB for the previous Deep example. It retains the current report controls and original referenced evidence. Raw outputs, normalized data, and logs are included; the memory image, engines, and symbols are excluded. Original evidence and historical development-machine paths are preserved.

Regenerate the report after installing the project:

```powershell
python -m memnolyze report --case examples/ransomcase1
```
