<#
.SYNOPSIS
    Sentinel end-of-work release: bump version, build installer, commit, push, publish.

.DESCRIPTION
    One-command release pipeline. Reads the current version from ../version.txt, computes the
    NEXT version using Sentinel's strict "increment-by-one, carry on 9" policy, updates
    version.txt, builds the installer via build.ps1 (which stamps every csproj + setup.iss and
    copies the installer to releases\<version>\), commits all changes, pushes to origin, and
    (unless -NoPublish) creates a GitHub release with the installer attached.

    VERSIONING POLICY (never make big jumps):
      - Always increment by exactly one patch: 2.5.3 -> 2.5.4.
      - A component may never exceed 9. When the patch is 9 it carries into the minor:
        2.5.9 -> 2.6.0. When both minor and patch are 9 it carries into the major:
        2.9.9 -> 3.0.0. The user's shorthand "2.9 -> 3.0" is this same rule.
      - This holds even if enough work for a larger release was done. The size of the
        changeset never changes the increment.

.PARAMETER Version
    Explicit version to release (must still obey the policy: exactly one step above current).
    Omit to auto-compute the next version.

.PARAMETER NoPublish
    Build, commit, and push, but do not create a GitHub release.

.PARAMETER DryRun
    Print every action without changing files, committing, pushing, or publishing.
#>
[CmdletBinding()]
param(
    [string]$Version,
    [switch]$NoPublish,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$RepoRoot   = Resolve-Path (Join-Path $PSScriptRoot "..")
$VersionFile = Join-Path $RepoRoot "version.txt"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

#  Version policy: increment by one with carry on 9 
function Get-NextVersion([string]$current) {
    $parts = $current.Trim().Split('.')
    if ($parts.Count -ne 3) {
        throw "version.txt must be MAJOR.MINOR.PATCH (got '$current')."
    }
    [int]$major = $parts[0]; [int]$minor = $parts[1]; [int]$patch = $parts[2]
    if ($major -lt 0 -or $minor -lt 0 -or $patch -lt 0 -or $minor -gt 9 -or $patch -gt 9) {
        throw "Version components out of range in '$current' (minor/patch must be 0-9)."
    }

    $patch++
    if ($patch -gt 9) {           # patch rolled past 9 -> carry into minor
        $patch = 0
        $minor++
        if ($minor -gt 9) {       # minor rolled past 9 -> carry into major
            $minor = 0
            $major++
        }
    }
    return "$major.$minor.$patch"
}

#  Extract the CHANGELOG section for a version as GitHub release notes 
function Get-ChangelogNotes([string]$Version) {
    $fallback = "Sentinel $Version. See docs/CHANGELOG.md for details."
    $changelog = Join-Path $RepoRoot "docs\CHANGELOG.md"
    if (-not (Test-Path $changelog)) { return $fallback }

    $lines = Get-Content $changelog
    # Match the heading for this version, e.g. "## [2.5.9] - 2026-09-09". The version dots are
    # escaped so "2.5.9" cannot accidentally match "2x5x9".
    $escaped = [regex]::Escape($Version)
    $headingRe = "^##\s*\[$escaped\]"
    $anyHeadingRe = '^##\s*\['

    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match $headingRe) { $start = $i; break }
    }
    if ($start -lt 0) { return $fallback }

    # Collect lines after the heading until the next "## [" heading.
    $body = New-Object System.Collections.Generic.List[string]
    for ($j = $start + 1; $j -lt $lines.Count; $j++) {
        if ($lines[$j] -match $anyHeadingRe) { break }
        $body.Add($lines[$j])
    }

    $text = ($body -join "`n").Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $fallback }
    return "## Sentinel $Version`n`n$text"
}

#  Read current + compute next 
if (-not (Test-Path $VersionFile)) { throw "version.txt not found at $VersionFile" }
$Current = (Get-Content $VersionFile -Raw).Trim()
Write-Step "Current version: $Current"

if ($Version) {
    $expected = Get-NextVersion $Current
    if ($Version -ne $expected) {
        throw "Requested version '$Version' violates the increment-by-one policy. Next allowed is '$expected'."
    }
    $Next = $Version
} else {
    $Next = Get-NextVersion $Current
}
Write-Step "Next version:    $Next"

if ($DryRun) {
    Write-Host "[DryRun] Would set version.txt -> $Next" -ForegroundColor Yellow
    Write-Host "[DryRun] Would run build.ps1, commit, push$(if (-not $NoPublish) {', and publish GitHub release'})." -ForegroundColor Yellow
    return
}

#  1. Bump version.txt (single source of truth; build.ps1 stamps everything else) 
Write-Step "Writing version.txt"
Set-Content -Path $VersionFile -Value $Next -NoNewline

#  2. Build installer (publishes, stamps, compiles Inno Setup, copies to releases\) 
Write-Step "Building installer via build.ps1"
& (Join-Path $PSScriptRoot "build.ps1")
if ($LASTEXITCODE -ne 0) { throw "build.ps1 failed" }

$InstallerPath = Join-Path $RepoRoot "releases\$Next\SentinelSetup-$Next.exe"
if (-not (Test-Path $InstallerPath)) { throw "Installer not found at $InstallerPath" }
Write-Step "Installer ready: $InstallerPath"

# Git and gh write informational messages (CRLF/LF warnings, progress) to stderr. Under
# $ErrorActionPreference = "Stop" those stderr lines would be treated as terminating errors, so
# invoke external commands through a helper that only fails on a non-zero exit code.
function Invoke-External {
    param([Parameter(Mandatory)][string]$File, [Parameter(Mandatory)][string[]]$Args, [switch]$AllowNonZero)
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $File @Args 2>&1 | ForEach-Object { Write-Host $_ }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
    if (-not $AllowNonZero -and $code -ne 0) {
        throw "$File $($Args -join ' ') exited with code $code"
    }
    return $code
}

#  3. Commit 
Write-Step "Committing release $Next"
# Stage all tracked modifications + the intended new/version files. Build artifacts under
# publish/ are gitignored; releases/<ver> is added explicitly.
# Note: releases/ is gitignored - the installer ships as a GitHub release artifact (step 5),
# not as a committed binary. So it is intentionally not staged here.
Invoke-External git @('-C', $RepoRoot, 'add', '-A', '--', 'src', 'tests', 'docs', 'version.txt', 'installer/setup.iss', 'installer/release.ps1')
Invoke-External git @('-C', $RepoRoot, 'commit', '-m', "Release $Next")

#  4. Push to origin/main 
Write-Step "Pushing to origin"
Invoke-External git @('-C', $RepoRoot, 'push', 'origin', 'HEAD')

#  5. Publish GitHub release with installer attached 
if ($NoPublish) {
    Write-Step "Skipping GitHub release (-NoPublish)."
} else {
    Write-Step "Publishing GitHub release v$Next"
    $notes = Get-ChangelogNotes -Version $Next
    # Write notes to a temp file and use --notes-file. Passing multi-line release notes
    # inline via --notes breaks the gh invocation (the newlines split the argument), which
    # previously left the commit pushed but no GitHub release created. --notes-file is
    # newline-safe.
    $notesFile = New-TemporaryFile
    try {
        Set-Content -Path $notesFile -Value $notes -Encoding UTF8
        Invoke-External gh @('release', 'create', "v$Next", $InstallerPath, '--title', "Sentinel $Next", '--notes-file', $notesFile.FullName)
    }
    finally {
        Remove-Item $notesFile -ErrorAction SilentlyContinue
    }
}

Write-Host "==============================================" -ForegroundColor Green
Write-Host "Release $Next complete." -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
