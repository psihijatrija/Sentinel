param([string]$ResultsPath = 'TestResults')
$ErrorActionPreference = 'Stop'
function Write-Summary([string]$message) {
    Write-Host $message
    if ($env:GITHUB_STEP_SUMMARY) { $message | Out-File $env:GITHUB_STEP_SUMMARY -Append }
}
function Write-Failure([string]$message) {
    Write-Summary $message
    $encoded = $message.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
    Write-Host ('::error::' + $encoded)
}
$files = @(Get-ChildItem $ResultsPath -Filter '*.trx' -Recurse -ErrorAction SilentlyContinue)
if ($files.Count -eq 0) { Write-Summary 'Windows test results unavailable: the host may have stalled or exited early.' }
foreach ($file in $files) {
    [xml]$trx = Get-Content $file.FullName -Raw
    $c = $trx.TestRun.ResultSummary.Counters
    Write-Summary "Windows Framework tests ($($file.Name)): executed=$($c.executed), passed=$($c.passed), failed=$($c.failed), notExecuted=$($c.notExecuted)"
    foreach ($result in $trx.SelectNodes("//*[local-name()='UnitTestResult'][@outcome='Failed']")) {
        $message = $result.SelectSingleNode(".//*[local-name()='Message']")
        Write-Failure "Failed: $($result.testName) $($message.InnerText)"
        $stack = $result.SelectSingleNode(".//*[local-name()='StackTrace']")
        if ($stack) { Write-Summary $stack.InnerText }
    }
}
Get-ChildItem $ResultsPath -Filter '*Sequence*.xml' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    [xml]$sequence = Get-Content $_.FullName -Raw
    foreach ($test in $sequence.SelectNodes("//*[local-name()='Test'][@Completed='False' or @Completed='false']")) {
        Write-Failure "Incomplete test at host termination: $($test.Name)"
    }
}
