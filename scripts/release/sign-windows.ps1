param(
  [string]$ArtifactDirectory,
  [string[]]$Files,
  [Parameter(Mandatory = $true)][string]$StatusFile
)
$ErrorActionPreference = "Stop"
$targets = @()
if ($ArtifactDirectory) {
  if (-not (Test-Path -LiteralPath $ArtifactDirectory -PathType Container)) { throw "Windows signing directory is missing: $ArtifactDirectory" }
  $targets += Get-ChildItem $ArtifactDirectory -Recurse -File | Where-Object { $_.Extension -in ".exe", ".msi" }
}
foreach ($path in $Files) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Windows signing input is missing: $path" }
  $targets += Get-Item -LiteralPath $path
}
$targets = $targets | Sort-Object FullName -Unique
if (-not $targets) { throw "No Windows executable or installer artifacts were found" }

$pfx = $env:WINDOWS_SIGNING_PFX_BASE64
$password = $env:WINDOWS_SIGNING_PFX_PASSWORD
if ([bool]$pfx -xor [bool]$password) { throw "Windows signing credentials are partial" }
if (-not $pfx) {
  if ($env:REQUIRE_SIGNING -eq "1") { throw "Windows signing credentials are required" }
  @{ schemaVersion = 1; status = "unsigned-validation"; files = @($targets.Name) } | ConvertTo-Json | Set-Content $StatusFile
  exit 0
}

$temporary = Join-Path $env:RUNNER_TEMP "private-network-signing.pfx"
try {
  [IO.File]::WriteAllBytes($temporary, [Convert]::FromBase64String($pfx))
  $identity = $null
  foreach ($file in $targets) {
    & signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /f $temporary /p $password $file.FullName
    if ($LASTEXITCODE -ne 0) { throw "signtool failed to sign $($file.FullName)" }
    & signtool verify /pa $file.FullName
    if ($LASTEXITCODE -ne 0) { throw "signtool failed to verify $($file.FullName)" }
    $signature = Get-AuthenticodeSignature -FilePath $file.FullName
    if ($signature.Status -ne "Valid" -or -not $signature.SignerCertificate) { throw "Authenticode verification failed: $($file.FullName)" }
    if (-not $identity) { $identity = $signature.SignerCertificate.Subject }
    if ($signature.SignerCertificate.Subject -ne $identity) { throw "Windows signing identities differ within one candidate" }
  }
  @{ schemaVersion = 1; status = "signed-and-verified"; signingIdentity = $identity; files = @($targets.Name) } | ConvertTo-Json | Set-Content $StatusFile
} finally {
  Remove-Item $temporary -Force -ErrorAction SilentlyContinue
}
