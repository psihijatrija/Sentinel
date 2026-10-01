param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$SrcDir,
    [Parameter(Mandatory)][string]$SetupIss
)

# Stamp all csproj files (skip tools/)
Get-ChildItem $SrcDir -Recurse -Filter '*.csproj' |
    Where-Object { $_.FullName -notmatch '\\tools\\' } |
    ForEach-Object {
        $c = [IO.File]::ReadAllText($_.FullName)
        $c = $c -replace '<Version>[^<]+</Version>', "<Version>$Version</Version>"
        [IO.File]::WriteAllText($_.FullName, $c)
    }

# Stamp setup.iss
$c = [IO.File]::ReadAllText($SetupIss)
$c = $c -replace 'AppVersion=.*',                    "AppVersion=$Version"
$c = $c -replace 'VersionInfoVersion=.*',             "VersionInfoVersion=$Version.0"
$c = $c -replace 'VersionInfoProductVersion=.*',      "VersionInfoProductVersion=$Version.0"
$c = $c -replace 'VersionInfoOriginalFileName=.*',    "VersionInfoOriginalFileName=SentinelSetup-$Version.exe"
$c = $c -replace 'OutputBaseFilename=SentinelSetup-\S+', "OutputBaseFilename=SentinelSetup-$Version"
[IO.File]::WriteAllText($SetupIss, $c)

Write-Host "Stamped all versions to $Version"
