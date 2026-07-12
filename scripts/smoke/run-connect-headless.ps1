param(
  [Parameter(Mandatory = $true)][string]$Binary
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { throw "Connect binary is unavailable" }
$work = Join-Path ([IO.Path]::GetTempPath()) ("connect-headless-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null

function Invoke-Headless([string]$Request, [string]$Output, [int]$ExpectedExit) {
  $start = [Diagnostics.ProcessStartInfo]::new()
  $start.FileName = $Binary
  $start.ArgumentList.Add("headless")
  $start.ArgumentList.Add("--output")
  $start.ArgumentList.Add($Output)
  $start.UseShellExecute = $false
  $start.RedirectStandardInput = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $process = [Diagnostics.Process]::Start($start)
  $process.StandardInput.WriteLine($Request)
  $process.StandardInput.Close()
  if (-not $process.WaitForExit(60000)) {
    $process.Kill($true)
    throw "Connect headless process timed out"
  }
  if ($process.ExitCode -ne $ExpectedExit) {
    throw "Connect headless process exited with $($process.ExitCode), expected $ExpectedExit"
  }
}

try {
  $output = Join-Path $work "status.json"
  Invoke-Headless '{"schemaVersion":1,"operation":{"method":"status"}}' $output 0
  $value = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
  if (
    $value.schemaVersion -ne 1 -or
    $value.complete -ne $true -or
    $value.outcome.status -ne "success" -or
    @($value.PSObject.Properties.Name).Count -ne 3
  ) { throw "Connect headless status response is invalid" }

  $invalid = Join-Path $work "invalid.json"
  Invoke-Headless '{"schemaVersion":1,"operation":{"method":"status","extra":true}}' $invalid 65
  $failure = Get-Content -LiteralPath $invalid -Raw | ConvertFrom-Json
  if (
    $failure.complete -ne $true -or
    $failure.outcome.status -ne "error" -or
    $failure.outcome.code -ne "headless_request_invalid"
  ) { throw "Connect accepted an extended headless request" }

  Write-Host "Connect installed-binary headless smoke passed"
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
