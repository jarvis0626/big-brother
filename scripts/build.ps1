param([switch]$SkipInstall, [switch]$DirectoryOnly)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$taskCache = Join-Path $projectRoot '.cache'
$env:ELECTRON_CACHE = Join-Path $taskCache 'electron'
$env:ELECTRON_BUILDER_CACHE = Join-Path $taskCache 'electron-builder'
$env:PIP_CACHE_DIR = Join-Path $taskCache 'pip'
$env:PYINSTALLER_CONFIG_DIR = Join-Path $taskCache 'pyinstaller'
$env:TEMP = Join-Path $taskCache 'temp'
$env:TMP = $env:TEMP
$env:CSC_IDENTITY_AUTO_DISCOVERY = 'false'
New-Item -ItemType Directory -Path $env:TEMP -Force | Out-Null
if (-not $SkipInstall) {
  if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Python environment setup failed' }
  }
  & '.venv\Scripts\python.exe' -m pip install -r requirements.txt --cache-dir $env:PIP_CACHE_DIR
  if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed' }
  npm.cmd ci
  if ($LASTEXITCODE -ne 0) { throw 'Node dependency installation failed' }
}
if ($DirectoryOnly) { npm.cmd run package:dir } else { npm.cmd run package }
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
Write-Output 'Big Brother build complete. See release/ for unsigned Windows packages.'
