param([switch]$PurgeState)
$ErrorActionPreference = "Stop"
$base = Join-Path $env:ProgramFiles "Private Network Node"
$data = Join-Path $env:ProgramData "Private Network Node"
$wrapper = Join-Path $base "RealityNodeAgent.exe"
if (Test-Path $wrapper) {
  & $wrapper stop 2>$null
  & $wrapper uninstall 2>$null
}
Remove-Item $base -Recurse -Force -ErrorAction SilentlyContinue
if ($PurgeState) { Remove-Item $data -Recurse -Force -ErrorAction SilentlyContinue }
