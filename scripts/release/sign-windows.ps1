param(
  [Parameter(Mandatory = $true)][string]$ArtifactDirectory,
  [Parameter(Mandatory = $true)][string]$StatusFile
)
$ErrorActionPreference = "Stop"
$pfx = $env:WINDOWS_SIGNING_PFX_BASE64
$password = $env:WINDOWS_SIGNING_PFX_PASSWORD
if ([bool]$pfx -xor [bool]$password) { throw "Windows signing credentials are partial" }
if (-not $pfx) {
  if ($env:REQUIRE_SIGNING -eq "1") { throw "Windows signing credentials are required" }
  @{ schemaVersion = 1; status = "unsigned-validation" } | ConvertTo-Json | Set-Content $StatusFile
  exit 0
}

$temporary = Join-Path $env:RUNNER_TEMP "private-network-signing.pfx"
try {
  [IO.File]::WriteAllBytes($temporary, [Convert]::FromBase64String($pfx))
  $files = Get-ChildItem $ArtifactDirectory -Recurse -File | Where-Object { $_.Extension -in ".exe", ".msi" }
  if (-not $files) { throw "No Windows executable or installer artifacts were found" }
  foreach ($file in $files) {
    & signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /f $temporary /p $password $file.FullName
    & signtool verify /pa $file.FullName
  }
  @{ schemaVersion = 1; status = "signed-and-verified" } | ConvertTo-Json | Set-Content $StatusFile
} finally {
  Remove-Item $temporary -Force -ErrorAction SilentlyContinue
}
