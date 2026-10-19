param([string]$Config = 'config.portable.json')
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path .venv/Scripts/python.exe)) {
    python -m venv --system-site-packages .venv
    if ($LASTEXITCODE -ne 0) { throw 'venv creation failed' }
}
# Offline source installation without setuptools or network access.
$sourcePath = (Resolve-Path src).Path
$sitePath = & .venv/Scripts/python.exe -c "import sysconfig; print(sysconfig.get_path('purelib'))"
[System.IO.File]::WriteAllText((Join-Path $sitePath 'memnolyze-source.pth'), $sourcePath + [Environment]::NewLine)
& .venv/Scripts/python.exe -m memnolyze doctor --config $Config
exit $LASTEXITCODE
