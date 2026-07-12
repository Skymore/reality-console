param(
  [Parameter(Mandatory = $true)][string]$Payload,
  [Parameter(Mandatory = $true)][string]$Version,
  [switch]$NoStart
)
$ErrorActionPreference = "Stop"
$base = Join-Path $env:ProgramFiles "Private Network Node"
$data = Join-Path $env:ProgramData "Private Network Node"
$release = Join-Path $base "releases\$Version"
$wrapper = Join-Path $base "RealityNodeAgent.exe"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Administrator privileges are required"
}
New-Item -ItemType Directory -Force -Path $release, "$data\state", "$data\logs" | Out-Null
Copy-Item "$Payload\node-host.exe", "$Payload\xray.exe" -Destination $release -Force
Copy-Item "$Payload\RealityNodeAgent.exe" -Destination $wrapper -Force
Copy-Item "$PSScriptRoot\RealityNodeAgent.xml" -Destination "$base\RealityNodeAgent.xml" -Force

$current = Join-Path $base "current"
if (Test-Path $current) {
  $old = (Get-Item $current).Target
  if ($old) { Set-Content -NoNewline -Path "$base\previous-release.txt" -Value $old }
  Remove-Item $current -Force
}
New-Item -ItemType Junction -Path $current -Target $release | Out-Null
& $wrapper stop 2>$null
& $wrapper uninstall 2>$null
& $wrapper install
if (-not $NoStart) { & $wrapper start }
