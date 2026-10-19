# Deep example case

Open [deep-case/report.html](deep-case/report.html) locally in a browser.

This is the actual Deep analysis of the public demonstration memory image used during development. It includes raw plugin/API outputs, normalized records, execution logs and the report so evidence links remain usable. The memory image, backend binaries and symbol files are not included.

The report is `partial`: MemProcFS could not retrieve the VAD table of MemCompression (PID 1708). See [the validation notes](../docs/VALIDATION-DEEP.md). Original acquisition/demo process metadata and historical development-machine paths remain as recorded; this is not an analysis of the receiving computer.

Regenerate the report after installing the project:

```powershell
python -m memnolyze report --case examples/deep-case
```
