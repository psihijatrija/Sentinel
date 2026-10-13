# Sentinel - local code-coverage run.
#
# Runs the full xUnit suite with coverlet.msbuild instrumentation and prints the
# Sentinel.Core line/branch/method summary. Writes a cobertura report to
# tests/Sentinel.Tests/TestResults/coverage.cobertura.xml (gitignored).
#
# Usage:
#   .\coverage.ps1                 # run coverage, print summary
#   .\coverage.ps1 -OpenReport     # also open the raw cobertura XML
#
# Notes:
# - Uses coverlet.msbuild (MSBuild integration), NOT the VSTest --collect collector,
#   because the collector does not support .NET Framework (net48) targets.
# - This does not use --no-build: coverlet instruments at test-build time.

[CmdletBinding()]
param(
    [switch]$OpenReport
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$testProj = Join-Path $repoRoot 'tests\Sentinel.Tests\Sentinel.Tests.csproj'
$reportPath = Join-Path $repoRoot 'tests\Sentinel.Tests\TestResults\coverage.cobertura.xml'

Write-Host '==> Running test suite with coverage instrumentation...' -ForegroundColor Cyan
dotnet test $testProj -c Release /p:CollectCoverage=true /p:CoverletOutputFormat=cobertura
if ($LASTEXITCODE -ne 0) {
    throw "Test run failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path $reportPath)) {
    throw "Coverage report not found at $reportPath"
}

# Parse the cobertura <coverage> root attributes for the headline numbers.
[xml]$cov = Get-Content $reportPath -Raw
$lineRate   = [double]$cov.coverage.'line-rate'
$branchRate = [double]$cov.coverage.'branch-rate'

Write-Host ''
Write-Host '==============================================' -ForegroundColor Green
Write-Host '   Sentinel.Core coverage' -ForegroundColor Green
Write-Host '==============================================' -ForegroundColor Green
Write-Host ("   Line coverage:   {0,6:P2}" -f $lineRate)
Write-Host ("   Branch coverage: {0,6:P2}" -f $branchRate)
Write-Host ("   Report:          {0}" -f $reportPath)
Write-Host '==============================================' -ForegroundColor Green

if ($OpenReport) {
    Start-Process $reportPath
}
