param(
  [Parameter(Mandatory = $true)][string]$Artifact,
  [Parameter(Mandatory = $true)][string]$Target,
  [Parameter(Mandatory = $true)][ValidateSet("release", "validation")][string]$Mode,
  [Parameter(Mandatory = $true)][string]$SignatureOutput,
  [Parameter(Mandatory = $true)][string]$LifecycleOutput
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf)) { throw "Actual Windows installer is missing" }
$bytes = [IO.File]::ReadAllBytes((Resolve-Path $Artifact))
if ($bytes.Length -lt 512 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
  throw "Lifecycle evidence requires a real PE installer, not a synthetic file"
}

$status = "unsigned-validation"
$artifactSigner = $null
$installerSigner = $null
$cleanResult = "incomplete"
$installLocation = $null
$uninstaller = $null
$installedDuringRun = $false
$artifactHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Artifact).Hash.ToLowerInvariant()
$connectBinaryHash = $null
$networkProofArguments = @()
if ($Target.StartsWith("connect-") -and $env:CONNECT_NETWORK_PROOF_DIR) {
  foreach ($proofMode in @("online", "offline", "direct-failed", "relay-failed", "logout")) {
    $proof = Join-Path $env:CONNECT_NETWORK_PROOF_DIR "$Target.$proofMode.network.json"
    if (-not (Test-Path -LiteralPath $proof -PathType Leaf)) { throw "Connect network proof is missing: $proof" }
    $copiedProof = Join-Path (Split-Path -Parent $LifecycleOutput) ([IO.Path]::GetFileName($proof))
    Copy-Item -LiteralPath $proof -Destination $copiedProof
    $networkProofArguments += @("--network-proof", $copiedProof)
  }
}
try {
  $outer = Get-AuthenticodeSignature -FilePath $Artifact
  if ($Mode -eq "release") {
    if ($outer.Status -ne "Valid" -or -not $outer.SignerCertificate) { throw "Installer Authenticode signature is not valid" }
    $installerSigner = $outer.SignerCertificate.Subject
  }

  $process = Start-Process -FilePath $Artifact -ArgumentList "/S" -Wait -PassThru
  if ($process.ExitCode -ne 0) { throw "Installer exited with code $($process.ExitCode)" }
  $uninstallRegistryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )
  $uninstall = Get-ItemProperty -Path $uninstallRegistryPaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -in "Reality Client", "Private Network Connect" } |
    Select-Object -First 1
  if (-not $uninstall -or -not $uninstall.InstallLocation) { throw "Installed application was not registered with an install location" }
  $installLocation = $uninstall.InstallLocation
  $installedDuringRun = $true
  $executables = Get-ChildItem -LiteralPath $installLocation -Recurse -Filter *.exe |
    Where-Object { -not $_.PSIsContainer }
  if (-not $executables) { throw "Installed package contains no executable binaries" }
  $connectBinary = Join-Path $installLocation "reality-client.exe"
  if (-not (Test-Path -LiteralPath $connectBinary -PathType Leaf)) {
    throw "Installed Connect executable is unavailable"
  }
  & scripts/smoke/run-connect-headless.ps1 -Binary $connectBinary
  $connectBinaryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $connectBinary).Hash.ToLowerInvariant()
  if ($Mode -eq "release") {
    foreach ($file in $executables) {
      $inner = Get-AuthenticodeSignature -FilePath $file.FullName
      if ($inner.Status -ne "Valid" -or -not $inner.SignerCertificate) { throw "Installed binary signature is not valid: $($file.FullName)" }
      if (-not $artifactSigner) { $artifactSigner = $inner.SignerCertificate.Subject }
      if ($inner.SignerCertificate.Subject -ne $artifactSigner) { throw "Installed binaries have different signing identities" }
    }
    $status = "verified"
    $cleanResult = "passed"
  }
} finally {
  if ($installedDuringRun -and $installLocation -and (Test-Path -LiteralPath $installLocation)) {
    $uninstaller = Get-ChildItem -LiteralPath $installLocation -Filter "uninstall*.exe" |
      Where-Object { -not $_.PSIsContainer } |
      Select-Object -First 1
    if (-not $uninstaller) { throw "Installed package has no uninstaller; refusing to leave test state behind" }
    $uninstallProcess = Start-Process -FilePath $uninstaller.FullName -ArgumentList "/S" -Wait -PassThru
    if ($uninstallProcess.ExitCode -ne 0 -or (Test-Path -LiteralPath $installLocation)) {
      throw "Installer lifecycle cleanup failed; refusing to claim a clean test machine"
    }
  }
}

@{
  schemaVersion = 1
  kind = "signature-verification"
  target = $Target
  artifact = @{ name = [IO.Path]::GetFileName($Artifact); sha256 = $artifactHash }
  artifactSigner = $artifactSigner
  installerSigner = $installerSigner
  status = $status
} | ConvertTo-Json | Set-Content -LiteralPath $SignatureOutput -Encoding utf8

$writerArguments = @(
  "scripts/release/write-lifecycle-evidence.py",
  "--artifact", $Artifact,
  "--target", $Target,
  "--source-commit", $env:GITHUB_SHA,
  "--result", "clean-install-signature=$cleanResult"
)
if ($connectBinaryHash) {
  $writerArguments += @("--connect-binary-sha256", $connectBinaryHash)
}
$writerArguments += $networkProofArguments + @(
  "--repository", $env:GITHUB_REPOSITORY,
  "--workflow", $env:GITHUB_WORKFLOW_REF,
  "--run-id", $env:GITHUB_RUN_ID,
  "--run-attempt", $env:GITHUB_RUN_ATTEMPT,
  "--job", "artifact-lifecycle ($Target)",
  "--output", $LifecycleOutput
)
& python @writerArguments
if ($LASTEXITCODE -ne 0) { throw "Lifecycle evidence writer failed" }
