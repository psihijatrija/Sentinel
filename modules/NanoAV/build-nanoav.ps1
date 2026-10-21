# build.ps1 - compile NanoAV COM server DLL using csc.exe
# Produces: bin\NanoAV.dll (COM server that persists via Run key)
# Also produces: bin\NanoAV.exe (bootstrap installer)

$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$srcDir = Join-Path $root 'src'
$binDir = Join-Path $root 'bin'

New-Item -ItemType Directory -Path $binDir -Force | Out-Null

# Locate csc.exe (64-bit framework compiler).
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    $csc = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}
if (-not (Test-Path $csc)) { throw "csc.exe not found for .NET Framework v4.0.30319" }

$fwDir = Split-Path $csc -Parent

# Framework assemblies to reference (resolved from the framework dir / GAC).
$refs = @(
    'System.dll',
    'System.Core.dll',
    'System.Management.dll',
    'System.Security.dll',
    'System.ServiceProcess.dll'
) | ForEach-Object { "/reference:`"$(Join-Path $fwDir $_)`"" }

$manifest = Join-Path $srcDir 'NanoApp.manifest'

Write-Host "Compiling COM Server DLL with: $csc" -ForegroundColor Cyan

# Get all source files for DLL (all .cs files)
$dllSources = Get-ChildItem -Path $srcDir -Filter *.cs -Recurse | ForEach-Object { "`"$($_.FullName)`"" }

# Compile the DLL (target library for COM server)
$dllArgs = @(
    '/nologo',
    '/target:library',
    '/platform:x64',
    '/optimize+',
    '/debug-',
    '/langversion:5',
    '/warn:0',
    "/out:`"$binDir\NanoAV.dll`""
) + $refs + $dllSources

& $csc @dllArgs
if ($LASTEXITCODE -ne 0) { throw "DLL compilation failed (exit $LASTEXITCODE)" }

$size = [math]::Round((Get-Item "$binDir\NanoAV.dll").Length / 1KB, 1)
Write-Host "Built DLL: $binDir\NanoAV.dll  ($size KB)" -ForegroundColor Green

# Compile the bootstrap EXE installer
Write-Host "Compiling Bootstrap EXE installer..." -ForegroundColor Cyan

# For EXE, include all sources (RundllLoader.cs needed for ComServerRegistrar reference)
$exeSources = Get-ChildItem -Path $srcDir -Filter *.cs -Recurse | ForEach-Object { "`"$($_.FullName)`"" }

$exeArgs = @(
    '/nologo',
    '/target:exe',
    '/platform:x64',
    '/optimize+',
    '/debug-',
    '/langversion:5',
    '/warn:0',
    "/win32manifest:`"$manifest`"",
    "/out:`"$binDir\NanoAV.exe`""
) + $refs + $exeSources

& $csc @exeArgs
if ($LASTEXITCODE -ne 0) { throw "EXE compilation failed (exit $LASTEXITCODE)" }

$size = [math]::Round((Get-Item "$binDir\NanoAV.exe").Length / 1KB, 1)
Write-Host "Built EXE: $binDir\NanoAV.exe  ($size KB)" -ForegroundColor Green

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "Files: $binDir\NanoAV.dll, $binDir\NanoAV.exe" -ForegroundColor Cyan
