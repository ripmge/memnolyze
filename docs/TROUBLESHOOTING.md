# Troubleshooting

## `TypeError: Vmm.init(): Initialization of vmm failed`

This is the Python API's generic initialization exception. It does not identify whether the cause is file access, image interpretation, Windows detection, or another native initialization requirement. A successful import check does not rule these out. Read the native messages before the exception.

Use the standalone initialization diagnostic with the active 64-bit Python environment:

```powershell
python scripts/check_memprocfs_image.py `
  --image "D:\Images\image.vmem" `
  --memprocfs-path "D:\Tools\MemProcFS" *> memprocfs-init.log
```

Omit `--memprocfs-path` for a pip-installed API. The script reports the selected interpreter/module, enables native `-printf` and `-v`, disables symbols/network symbol downloads, Python plugins and YARA, and opens only the specified image. It does not start forensic processing or mount a drive. It requires plausible Windows metadata before reporting successful initialization, and closes a successfully created Vmm object. The flags follow the native API header and [documented verbosity controls](https://github.com/ufrisk/MemProcFS/wiki/_CommandLine). It deliberately does not use `-vvv`, which can log memory contents.

The diagnostic was tested with the actual development image (Windows build 17134 recognized) and a deliberately invalid input (failed status with the native file/device error visible before the generic exception). It does not reconstruct missing VMware metadata or prove that a failing image is corrupt. For a `.vmem` without its matching `.vmss`/`.vmsn`, record how the file was acquired and whether the VM was running when it was copied; do not substitute unrelated metadata.

## Doctor succeeds but all image checks fail

Doctor does not analyze the image. Volatility's check runs help/plugin discovery; MemProcFS's check imports the API in a child process without creating a Vmm object. Both report `image_validated: false`. A tool being available does not establish compatible image format, complete memory, symbols, or successful forensic processing.

Memnolyze's baseline profile is `quick`; the supported names are `quick`, `standard`, and `deep`. These are plugin selections, not Windows OS profiles. Volatility 3 resolves its OS information using the image and symbols rather than a Volatility 2-style manually selected OS profile.

Inspect one failed `windows.info` run first instead of repeating the entire profile. Its original stdout, stderr, command, and exit code are under `raw/volatility/info-*/` and `manifest.json`. Version 0.1.2 adds concise failure hints to execution records and the report without copying memory data into logs.

| Failure output | Next check |
|---|---|
| `kernel.symbol_table_name` / `OfflineException` | Matching local symbols; offline mode prevents downloads |
| `kernel.layer_name` | Image format/completeness and VMware sidecars; symbol errors may be secondary |
| `ModuleNotFoundError` | Selected Python interpreter and engine dependencies |
| DLL load failure | Native library dependencies, architecture, and interpreter compatibility |
| Other failure | Original stdout/stderr; a generic status cannot establish the cause |

For an isolated check, use a new output directory:

```powershell
python -m memnolyze analyze --image "D:\Images\server.dmp" `
  --output "D:\Results\info-check" --backend volatility --plugin info `
  --offline --config config.local.json
```

If the actual error confirms missing symbols, either supply matching local `symbol_dirs`, or deliberately repeat the info check with `--allow-symbol-downloads` in a separate output directory where network use is permitted. Downloads are never enabled automatically. Changing the offline policy/configuration requires a new case because resume preserves the original settings.

## MemProcFS installed in a neighboring directory

`memprocfs_path: null` means Python's import search, normally a pip-installed package in the selected interpreter. It does not mean that a neighboring folder has been discovered. Earlier versions could show `available: true, path: null` after merely finding a module spec; they did not verify the native API import.

Version 0.1.2 reports the resolved `path`, `module_file`, `native_module_file`, import `source`, interpreter, and API-import error. A successful import still does not guarantee that initialization with a particular image will work. The runtime version is read after image initialization, not guessed from a different installed distribution.

For this layout:

```text
D:\Tools\
  memnolyze\
  MemProcFS\
    memprocfs.py
    vmmpyc.pyd
    vmm.dll
    ...
```

Copy the portable configuration and edit `memprocfs_path`:

```powershell
Copy-Item config.portable.json config.local.json
```

```json
{
  "memprocfs_path": "D:/Tools/MemProcFS"
}
```

The minimal JSON object above is also a valid standalone configuration; unspecified settings use defaults. An absolute path avoids working-directory ambiguity. Alternatively, `../MemProcFS` is valid when commands are run from `D:\Tools\memnolyze`. Paths are relative to the working directory, not the configuration file. The directory must contain the Python API and matching native binaries, not only `MemProcFS.exe`.

```powershell
python -m memnolyze doctor --config config.local.json
```

Use that same `--config` for analysis. Both the import probe and analysis worker register the explicitly configured DLL directory on Windows. No neighboring directories are imported automatically.

The 0.1.2 changes passed 40 tests on Python 3.12 x64. The actual configured MemProcFS directory passed the native API import probe and a Quick image analysis, returning 115 processes and 12 findings with complete status. A deliberately invalid input was also tested: it produced failed status with an image-translation explanation, not a successful empty analysis. These checks validate the diagnostic behavior; they do not establish the cause of an uninspected failure on another image or interpreter.

## Volatility discovery fails with `argument -c/--config: expected one argument`

Fixed in memnolyze **0.1.1**. This is a memnolyze launcher bug, not evidence that a Volatility configuration file is required.

The previous fallback invoked Python with:

```python
[sys.executable, '-c', 'from volatility3.cli import main; main()']
```

Python sets `sys.argv[0]` to `-c` for that invocation. Volatility's initial argument parser inspects the full `sys.argv`, including the first element, and interprets it as Volatility's own `-c/--config` switch. Its next argument is missing or is another option, so discovery fails before help/plugin enumeration. See the [official CLI source](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/cli/__init__.py), particularly the initial `known_args` construction.

The corrected bootstrap sets a normal program name **before importing the CLI**, which also captures that name during import:

```python
[sys.executable, '-c', "import sys; sys.argv[0] = 'vol'; from volatility3.cli import main; main()"]
```

The fixed discovery order is: explicit `volatility_command`, the Volatility package importable by memnolyze's current Python, then an external executable on PATH. If none is found, the corrected bootstrap returns the actual import error. This avoids selecting another environment's `vol.exe` when the package is installed in the active environment. Doctor now includes `python_executable`, the launch command, `exit_code`, and a useful error even when failing output also contains plugin names.

### Manual hotfix on another computer

Activate the existing virtual environment and locate the installed file:

```powershell
python -c "import sys; import memnolyze.backends.volatility as v; print(sys.executable); print(v.__file__)"
```

Back up the printed `volatility.py` file and either replace it with the corrected `src/memnolyze/backends/volatility.py` from this release, or make the minimal edit below. No change to the Volatility installation is required.

In the old `command()` function, replace this source-code string:

```python
'from volatility3.cli import main; main()'
```

with this string, retaining the surrounding argument list:

```python
"import sys; sys.argv[0] = 'vol'; from volatility3.cli import main; main()"
```

The one-string edit fixes the fallback error. Replacing the complete backend file additionally provides interpreter preference and improved diagnostics. The full 0.1.1 release also updates the doctor output and version metadata. Restart any long-running memnolyze process after changing installed Python code.

If `volatility_command` in your configuration explicitly contains the old Python bootstrap, update it too. Alternatively, after updating the backend, set it to `null` to use automatic discovery. An explicit command always takes precedence.

Verify without scanning an image:

```powershell
python -m pip show volatility3
python -m memnolyze doctor --config config.portable.json
```

Expected: `volatility.available` is `true`, its `error` is `null`, plugin classes are listed, and the selected command points to the intended environment. Version 0.1.1 also reports `exit_code: 0` and the interpreter path. If discovery is still false, inspect that command/error first. A later missing-symbol failure during analysis is a separate issue; do not solve this launcher failure by adding a dummy Volatility config file.

### Python 3.13 and validation limits

The same failure was reproduced on Python **3.12.10** with Volatility **2.28.2**, so it is not specific to Python 3.13. Volatility's [published metadata](https://pypi.org/project/volatility3/) declares Python >=3.8. This does not independently establish compatibility of every plugin or native dependency with every newer Python release.

Python 3.13 was not available in the development VM. Full image/backend validation remains on Python 3.12 x64; 3.11/3.12 are the documented initial target. There is no need to downgrade solely to resolve this particular `-c` parsing error. Validate native MemProcFS separately on the destination environment.

On October 19, 2026, the fix passed **32 unit tests**, including six launcher regressions. With the actual Volatility installation, the corrected interpreter-based launcher discovered **90 Windows plugins** and ran `windows.info` plus `windows.pslist` offline against the actual development image, yielding **120 active process records** and a complete baseline case. This was a targeted launcher test, not a repeat of all profile integrations.
