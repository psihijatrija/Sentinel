# Sentinel Installer Build Script
# Minimum framework-dependent installer for net48-windows.
# Requires .NET Framework 4.8 on the target machine (installer offers download if missing).
# Usage: .\build.ps1
# Upgrade ACLs / stop / rename live in setup.iss (ResetInstallDirAcls + --prepare-upgrade).

$ErrorActionPreference = "Stop"

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "   Sentinel - Building Minimum Installer      " -ForegroundColor Cyan
Write-Host "   (net48-windows, framework-dependent)       " -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# 0. Read version from single source of truth
$VersionFile = Join-Path $PSScriptRoot "..\version.txt"
$Version = (Get-Content $VersionFile -Raw).Trim()
Write-Host "Version: $Version" -ForegroundColor Green

# 0.1 Stamp all .csproj files with the version
$CsprojFiles = Get-ChildItem (Join-Path $PSScriptRoot "..") -Recurse -Filter "*.csproj" |
    Where-Object { $_.FullName -notmatch '\\tools\\' }
foreach ($csproj in $CsprojFiles) {
    $content = Get-Content $csproj.FullName -Raw
    if ($content -match '<Version>') {
        $content = $content -replace '<Version>[^<]+</Version>', "<Version>$Version</Version>"
        Set-Content $csproj.FullName -Value $content -NoNewline
    }
}
Write-Host "Stamped project versions to $Version" -ForegroundColor Yellow

# 0.2 Stamp Inno Setup script
$SetupScript = Join-Path $PSScriptRoot "setup.iss"
$issContent = [System.IO.File]::ReadAllText($SetupScript)
$issContent = $issContent -replace 'AppVersion=.*', "AppVersion=$Version"
$issContent = $issContent -replace 'VersionInfoVersion=.*', "VersionInfoVersion=$Version.0"
$issContent = $issContent -replace 'VersionInfoProductVersion=.*', "VersionInfoProductVersion=$Version.0"
$issContent = $issContent -replace 'VersionInfoOriginalFileName=.*', "VersionInfoOriginalFileName=SentinelSetup-$Version.exe"
$issContent = $issContent -replace 'OutputBaseFilename=SentinelSetup-.*', "OutputBaseFilename=SentinelSetup-$Version"
[System.IO.File]::WriteAllText($SetupScript, $issContent)

# 1. Clean previous publish folder + leftover Setup EXEs from older versions
$PublishDir = Join-Path $PSScriptRoot "..\publish"
$SrcDir = Join-Path $PSScriptRoot "..\src"
Write-Host "Cleaning publish outputs..." -ForegroundColor Yellow
if (Test-Path $PublishDir) {
    Remove-Item -Path $PublishDir -Recurse -Force -ErrorAction SilentlyContinue
}
Get-ChildItem $PSScriptRoot -Filter "SentinelSetup-*.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne "SentinelSetup-$Version.exe" } |
    ForEach-Object {
        Write-Host "Removing old installer $($_.Name)" -ForegroundColor Yellow
        Remove-Item $_.FullName -Force
    }
Get-ChildItem $PSScriptRoot -Filter "*.old" -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item $_.FullName -Force }

$Dotnet = "C:\Program Files\dotnet\dotnet.exe"
if (-not (Test-Path $Dotnet)) { $Dotnet = "dotnet" }

# 2. Publish Service - framework-dependent net48 (small; uses installed .NET 4.8)
Write-Host "Publishing Sentinel Service (net48-windows, framework-dependent)..." -ForegroundColor Yellow
$ServiceProj = Join-Path $PSScriptRoot "..\src\Sentinel.Service\Sentinel.Service.csproj"
$ServiceOut = Join-Path $PublishDir "service"
& $Dotnet publish $ServiceProj -c Release -f net48-windows -o $ServiceOut
if ($LASTEXITCODE -ne 0) { throw "Service publish failed" }

# 3. Publish Agent - framework-dependent net48
Write-Host "Publishing Sentinel Agent (net48-windows, framework-dependent)..." -ForegroundColor Yellow
$AgentProj = Join-Path $PSScriptRoot "..\src\Sentinel.Agent\Sentinel.Agent.csproj"
$AgentOut = Join-Path $PublishDir "agent"
& $Dotnet publish $AgentProj -c Release -f net48-windows -o $AgentOut
if ($LASTEXITCODE -ne 0) { throw "Agent publish failed" }

# 3a. Icon + version.txt
Write-Host "Deploying Sentinel.ico and version.txt..." -ForegroundColor Yellow
$IconSource = Join-Path $PSScriptRoot "assets\Sentinel.ico"
if (-not (Test-Path $IconSource)) {
    $IconSource = Join-Path $PSScriptRoot "..\assets\Sentinel.ico"
}
if (Test-Path $IconSource) {
    Copy-Item $IconSource -Destination (Join-Path $AgentOut "Sentinel.ico") -Force
    Copy-Item $IconSource -Destination (Join-Path $ServiceOut "Sentinel.ico") -Force
}
Copy-Item $VersionFile -Destination (Join-Path $AgentOut "version.txt") -Force
Copy-Item $VersionFile -Destination (Join-Path $ServiceOut "version.txt") -Force

# 3b. Offline PE/URL ML models
$MlModelsSrc = Join-Path $PSScriptRoot "..\src\Sentinel.Core\MlModels"
foreach ($target in @("service", "agent")) {
    $dest = Join-Path $PublishDir "$target\MlModels"
    if (Test-Path $MlModelsSrc) {
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Get-ChildItem $MlModelsSrc -Filter "*.zip" -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item $_.FullName -Destination $dest -Force
            Write-Host "Copied ML model $($_.Name) -> $target\MlModels" -ForegroundColor Yellow
        }
    }
}

# 3c. LGPO.exe and GSecurity.inf - shipped as plain files, NOT embedded in the assembly.
#     Embedding a PE inside a DLL triggers AV dropper heuristics. These files are
#     placed beside the service/agent EXE and loaded at runtime from the install directory.
$HardeningResourcesSrc = Join-Path $PSScriptRoot "..\src\Sentinel.Core\HardeningResources"
foreach ($target in @("service", "agent")) {
    $dest = Join-Path $PublishDir $target
    foreach ($hardeningFile in @("LGPO.exe", "GSecurity.inf")) {
        $src = Join-Path $HardeningResourcesSrc $hardeningFile
        if (Test-Path $src) {
            Copy-Item $src -Destination $dest -Force
            Write-Host "Copied $hardeningFile -> $target\" -ForegroundColor Yellow
        }
    }
}

# 3d. Trim shipped bloat from each publish tree (~2 MB off the installer).
#     Two things leaked into the published payload over time:
#       * A duplicate HardeningResources\ subfolder (LGPO.exe + GSecurity.inf again) that
#         dotnet publish emits as content. The runtime loads LGPO/GSecurity from the install
#         ROOT (AppContext.BaseDirectory, see HardeningModule.ApplyLgpoSecurityPolicy), never
#         from HardeningResources\, so that whole subfolder is dead weight (~0.9 MB x2 trees).
#       * *.pdb debug symbols, which framework-dependent publish includes by default and which
#         have no place in an end-user release installer (~1 MB).
#     Removing them is loss-free: the root LGPO.exe/GSecurity.inf the code actually reads are
#     kept by the copy step above.
foreach ($target in @("service", "agent")) {
    $dest = Join-Path $PublishDir $target

    $hrDir = Join-Path $dest "HardeningResources"
    if (Test-Path $hrDir) {
        Remove-Item -Path $hrDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Pruned unused HardeningResources\ from $target\" -ForegroundColor Yellow
    }

    Get-ChildItem $dest -Filter "*.pdb" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Pruned *.pdb from $target\" -ForegroundColor Yellow
}

# 3e. Sign published binaries with Authenticode
Write-Host "Signing published binaries..." -ForegroundColor Yellow
$SignScript = Join-Path $PSScriptRoot "..\tools\sign-binaries.ps1"
if (Test-Path $SignScript) {
    try {
        & $SignScript -TargetDirectory $PublishDir
    }
    catch {
        Write-Warning "Binary signing encountered an issue: $_"
    }
}

# 4. Locate Inno Setup Compiler
Write-Host "Locating Inno Setup compiler..." -ForegroundColor Yellow
$DefaultIsccPaths = @(
    # Prefer Inno 6 stub (often quieter on ML AV than Inno 7); user-local install first
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 7\ISCC.exe",
    "C:\Program Files\Inno Setup 7\ISCC.exe"
)

$IsccPath = $null
foreach ($Path in $DefaultIsccPaths) {
    if (Test-Path $Path) {
        $IsccPath = $Path
        break
    }
}
if (-not $IsccPath) {
    $IsccPath = Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
}
if (-not $IsccPath) {
    Write-Host "ERROR: Inno Setup compiler (ISCC.exe) was not found." -ForegroundColor Red
    Write-Host "Install Inno Setup 6: https://jrsoftware.org/isdl.php" -ForegroundColor Red
    Exit 1
}
Write-Host "Found Inno Setup at: $IsccPath" -ForegroundColor Green

# 5. Compile installer
Write-Host "Compiling installer with Inno Setup..." -ForegroundColor Yellow
# Inno Setup 7 quirk: if the output exe already exists, icon embedding may be skipped.
# Always delete the previous output before compiling.
$PreviousInstaller = Join-Path $PSScriptRoot "SentinelSetup-$Version.exe"
if (Test-Path $PreviousInstaller) { Remove-Item $PreviousInstaller -Force }
& $IsccPath $SetupScript
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }

$InstallerPath = Join-Path $PSScriptRoot "SentinelSetup-$Version.exe"
if (-not (Test-Path $InstallerPath)) {
    throw "Installer not produced at $InstallerPath"
}

# 5a. Sign produced installer
if ((Test-Path $SignScript) -and (Test-Path $InstallerPath)) {
    try {
        & $SignScript -TargetDirectory $PSScriptRoot
    }
    catch {
        Write-Warning "Installer signing encountered an issue: $_"
    }
}

$sizeMb = [math]::Round((Get-Item $InstallerPath).Length / 1MB, 2)
Write-Host "==============================================" -ForegroundColor Green
Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "Installer: installer\SentinelSetup-$Version.exe ($sizeMb MB)" -ForegroundColor Green
Write-Host "Runtime:   .NET Framework 4.8 (framework-dependent)" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

# 6. Copy to releases/ for GitHub upload
$ReleasesDir = Join-Path $PSScriptRoot "..\releases\$Version"
if (-not (Test-Path $ReleasesDir)) { New-Item -ItemType Directory -Path $ReleasesDir -Force | Out-Null }
Copy-Item $InstallerPath -Destination $ReleasesDir -Force
Write-Host "Copied installer to releases\$Version\" -ForegroundColor Green
