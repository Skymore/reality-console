$ErrorActionPreference = "Stop"
$work = Join-Path ([IO.Path]::GetTempPath()) ("private-network-smoke-" + [guid]::NewGuid())
$releases = Join-Path $work "releases"
$state = Join-Path $work "state"
try {
  New-Item -ItemType Directory -Force -Path $releases, $state | Out-Null
  Set-Content (Join-Path $state "identity") "durable-node-identity"
  foreach ($version in "1.0.0", "1.1.0") {
    $release = Join-Path $releases $version
    New-Item -ItemType Directory -Path $release | Out-Null
    Set-Content (Join-Path $release "node-host.exe") "node-host-$version"
    Set-Content (Join-Path $release "xray.exe") "xray-$version"
  }
  $current = Join-Path $work "current"
  New-Item -ItemType Junction -Path $current -Target (Join-Path $releases "1.0.0") | Out-Null
  $previous = (Get-Item $current).Target
  Remove-Item $current
  New-Item -ItemType Junction -Path $current -Target (Join-Path $releases "1.1.0") | Out-Null
  if ((Get-Content (Join-Path $state "identity")) -ne "durable-node-identity") { throw "upgrade removed state" }
  Remove-Item $current
  New-Item -ItemType Junction -Path $current -Target $previous | Out-Null
  if ((Get-Item $current).Target -notmatch "1.0.0") { throw "rollback selected the wrong release" }
  Remove-Item $current
  Remove-Item $releases -Recurse
  if (-not (Test-Path (Join-Path $state "identity"))) { throw "uninstall removed state without purge" }
  Remove-Item $state -Recurse
  Write-Output "windows lifecycle smoke: passed"
} finally {
  Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
