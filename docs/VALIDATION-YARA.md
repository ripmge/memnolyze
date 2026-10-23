# YARA integration validation

The custom-rule path was tested with MemProcFS 5.19.0 and Python 3.12.10 x64 on the same real 8,588,951,552-byte RansomCase1 image documented in [Quick validation](VALIDATION.md). All runs were offline, used the Quick profile and MemProcFS backend, and explicitly skipped image hashing. The input image was not modified. The shipped example remains the earlier Quick analysis with YARA disabled.

## Positive custom-rule scan

A local source rule matched the ASCII/wide string `DumpIt.exe`. Its metadata explicitly described it as a validation marker, not a malware detection. The rule path contained spaces. No Elastic license was accepted; `-disable-yara-builtin` enforced that policy.

The scan returned **83 custom YARA matches**. The original detailed results were exported, the reported count matched the parsed records, and **83 YARA findings** were generated alongside the 12 existing FindEvil indicators. Object-memory matches without process metadata remained unattributed. Process-memory matches used the existing conservative process attribution. Raw result text remained unchanged and was embedded with each evidence reference.

The local case is `cases/yara-custom-validation`, excluded from the source archive. A resume reused completed output. Rule fingerprint changes caused a fresh attempt without overwriting earlier raw artifacts.

## Zero-match and invalid-rule scans

A source index with a local quoted include loaded a rule with an always-false condition. The local case `cases/yara-zero-validation` completed with **zero custom YARA matches** and retained the 12 non-YARA FindEvil indicators. Empty result files were handled successfully.

A deliberately invalid source rule produced MemProcFS's `yr_initialize() failed with error code 1` diagnostic. The case was marked **partial**, baseline metadata and FindEvil results were retained, and the engine error appeared in the console. It was not interpreted as a successful zero-detection scan. The local case is `cases/yara-invalid-validation`.

## Elastic rule scan

After explicit user authorization, a fresh Quick run with both backends used `--accept-elastic-license`. The recorded MemProcFS invocation contains `-license-accept-elastic-license-2-0` and no YARA-disable flags. Forensic processing completed at 100 percent and all nine selected backend checks succeeded. The FindEvil YARA result and triggered-rule exports were present but empty: there were no additional Elastic `YR_*` indicators. The report contains the same 23 findings (11 malfind and 12 non-YARA FindEvil indicators), with 134 processes. This does not establish that the image is free of malware.

The separate local case is `cases/ransomcase-elastic`; the existing shipped example was not replaced. Its 21 artifact hashes and 7,462 report links were verified, with no external report resources. The HTML is approximately 2.2 MB.

## Controlled tests and limitations

Unit tests cover default-off policy, explicit Elastic acceptance, custom-only disabling of bundled rules, input/include fingerprints, copied rules, CLI validation, original match evidence, malformed output, count mismatches, missing artifacts, zero matches, engine initialization errors, Vmm cleanup, cached result reuse, changed-rule reruns, and explicit policy changes during resume.

Elastic activation and exports were covered by synthetic API tests and subsequently by the explicitly authorized real-image run described above. Compiled rules are passed through and preserved, but a real compiled-rule scan was not performed. Source include provenance recognizes local quoted include directives; custom include resolvers and remotely fetched rules are unsupported. YARA scanning uses MemProcFS's engine-defined scope and limits, including its own skipped processes and maximum match count; completion does not imply exhaustive detection coverage.

References: [forensic YARA](https://github.com/ufrisk/MemProcFS/wiki/FS_Forensic_Yara), [command-line options](https://github.com/ufrisk/MemProcFS/wiki/_CommandLine), [FindEvil](https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil).
