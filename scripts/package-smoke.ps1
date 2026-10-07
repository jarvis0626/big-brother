param([ValidateSet('installer','portable')][string]$Target = 'portable')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$testRoot = Join-Path $projectRoot ('.cache\package-test-' + $Target + '-' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
$resolvedRoot = [IO.Path]::GetFullPath($testRoot)
if (-not $resolvedRoot.StartsWith([IO.Path]::GetFullPath($projectRoot) + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Test path escapes workspace' }
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
$env:TEMP = Join-Path $projectRoot '.cache\temp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Path $env:TEMP -Force | Out-Null
$oldData = $env:BB_DATA_DIR
$oldPath = $env:PATH
$oldElectronMode = $env:ELECTRON_RUN_AS_NODE
$appProcess = $null
try {
  Remove-Item Env:\ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue
  # Prove packaged startup with ordinary Windows PATH, without Python/Node discovery.
  $env:PATH = "$env:WINDIR\System32;$env:WINDIR"
  if ($Target -eq 'portable') {
    Remove-Item Env:\BB_DATA_DIR -ErrorAction SilentlyContinue
    $executable = Join-Path $testRoot 'Big-Brother-portable.exe'
    Copy-Item -LiteralPath (Join-Path $projectRoot 'release\Big-Brother-0.1.0-x64-portable.exe') -Destination $executable
    $dataDir = Join-Path $testRoot 'BigBrother-data'
    $appProcess = Start-Process -FilePath $executable -ArgumentList '--smoke-test' -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $testRoot 'startup-errors.txt')
  } else {
    $installDir = Join-Path $testRoot 'installed'
    $installer = Join-Path $projectRoot 'release\Big-Brother-0.1.0-x64-nsis.exe'
    $setup = Start-Process -FilePath $installer -ArgumentList ('/S /D=' + $installDir) -WindowStyle Hidden -PassThru -Wait
    if ($setup.ExitCode -ne 0) { throw ('Installer failed: ' + $setup.ExitCode) }
    $executable = Join-Path $installDir 'Big Brother.exe'
    if (-not (Test-Path -LiteralPath $executable)) { throw 'Installer did not create the application' }
    $dataDir = Join-Path $testRoot 'data'
    $env:BB_DATA_DIR = $dataDir
    $appProcess = Start-Process -FilePath $executable -ArgumentList '--smoke-test' -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $testRoot 'startup-errors.txt')
  }
  $reportPath = Join-Path $dataDir 'package-smoke.json'
  $deadline = [DateTime]::UtcNow.AddSeconds(90)
  while (-not (Test-Path -LiteralPath $reportPath)) {
    if ($appProcess.HasExited) { throw ('Packaged launcher exited before the smoke report; exit ' + $appProcess.ExitCode + '. See the test-owned startup-errors.txt.') }
    if ([DateTime]::UtcNow -gt $deadline) { throw 'Packaged startup timed out' }
    Start-Sleep -Milliseconds 250
  }
  $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
  $appProcess.WaitForExit(15000) | Out-Null
  if (-not $report.passed -or -not $report.packaged -or -not $report.resources_present) { throw ('Package smoke failed: ' + ($report | ConvertTo-Json -Depth 5)) }
  if ($Target -eq 'portable' -and -not $report.portable) { throw 'Portable data routing was not active' }
  $signature = Get-AuthenticodeSignature -LiteralPath $executable
  $metadata = (Get-Item -LiteralPath $executable).VersionInfo
  $result = [ordered]@{target=$Target;passed=$true;no_python_node_path=$true;signature=$signature.Status.ToString();product_name=$metadata.ProductName;file_description=$metadata.FileDescription;smoke=$report;tested_at=[DateTime]::UtcNow.ToString('o')}
  if ($Target -eq 'installer') {
    $uninstaller = Get-ChildItem -LiteralPath $installDir -Filter '*Uninstall*.exe' -File | Select-Object -First 1
    if ($uninstaller) {
      $uninstall = Start-Process -FilePath $uninstaller.FullName -ArgumentList '/S' -WindowStyle Hidden -PassThru -Wait
      $result.uninstaller_exit = $uninstall.ExitCode
      $cleanupDeadline = [DateTime]::UtcNow.AddSeconds(15)
      while ((Test-Path -LiteralPath $executable) -and [DateTime]::UtcNow -lt $cleanupDeadline) { Start-Sleep -Milliseconds 250 }
      $result.application_removed = -not (Test-Path -LiteralPath $executable)
      if (-not $result.application_removed) { throw 'Silent uninstaller did not remove application' }
    } else { throw 'Installer did not create an uninstaller' }
  }
  $artifact = Join-Path $projectRoot ('artifacts\' + $Target + '-smoke.json')
  $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $artifact -Encoding UTF8
  $result | ConvertTo-Json -Depth 8
} finally {
  if ($appProcess -and -not $appProcess.HasExited) { Stop-Process -Id $appProcess.Id -ErrorAction SilentlyContinue }
  $env:PATH = $oldPath
  if ($null -eq $oldElectronMode) { Remove-Item Env:\ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue } else { $env:ELECTRON_RUN_AS_NODE = $oldElectronMode }
  if ($null -eq $oldData) { Remove-Item Env:\BB_DATA_DIR -ErrorAction SilentlyContinue } else { $env:BB_DATA_DIR = $oldData }
}
