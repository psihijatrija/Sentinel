# Independent NanoAV module (3.3.8)

NanoAV is packaged as its own `NanoAV.exe` and COM `NanoAV.dll`, built from the supplied NanoAV-main.zip. It does not reference Sentinel.Core or call Sentinel's tier, scoring or response-policy pipeline. The installer launches its original bootstrap after installing Sentinel. Its original COM registration, per-user Run key, online requests, caches, heuristics, quarantine, deletion and response decisions remain its own.

On installation/upgrade, remove only NanoAV's `.installed` bootstrap marker so the unchanged bootstrap refreshes its ProgramData DLL copy and current-user startup registration from the co-installed, coexistence-patched EXE. Preserve its configuration, database, logs, backups and quarantine. An already running older copy is not retroactively patched; the upgrade must complete and its startup path must point to the integrated copy.

## Exact source scope

Archive SHA-256: `232f33f15dba196eb462b047c843266c9506aba25e59c19cb74191b35b102ed8`.

Of 22 supplied files, 17 are byte-identical. Five have only coexistence call-site edits: `NanoC2Engine.cs`, `NanoFileScanner.cs`, `NanoMemoryScanner.cs`, `NanoPidRegistry.cs` and `NanoThreatAnalysis.cs` (21 inserted / 6 removed lines). The added `SentinelCoexistence.cs` helper (with shared `SentinelCoexistencePaths.cs` path logic) protects the resolved Sentinel installation and ProgramData/Sentinel files, checks the pinned Process object before individual kills, and skips a module-name-wide taskkill fallback that could include Sentinel. Unresolvable target identity is protected because it cannot safely be distinguished from Sentinel. Other NanoAV rules/settings are not rewritten. The original build script, README, config, entry point and assembly metadata are unchanged. `modules/NanoAV/UPSTREAM.json` records original and integrated per-file hashes.

Build/installer wiring, tests and Sentinel-side exclusions are outside the supplied source. Sentinel recognizes NanoAV in its own installation directory; a copied name elsewhere is not exempt. The original bootstrap's `%ProgramData%\NanoAV\NanoAV.dll` copy is exempt from Sentinel file scanning/quarantine only when its SHA-256 equals the co-installed EXE. Memory inspection and DLL remediation skip the co-installed NanoAV image. NanoAV is not included in Sentinel's own offline executable firewall blocks.

## Online and privacy boundary

This is an explicit exception to the offline product boundary: NanoAV retains CIRCL/Cymru/MalwareBazaar calls, reverse DNS, optional webhook code and its own firewall actions as supplied. These can disclose hashes, public IP/name lookups and, if separately configured, alert details. Sentinel Core/Service/Agent transports remain offline. No credentials are invented or embedded by this integration. The supplied MalwareBazaar key is empty; provider authentication, endpoints and availability are not certified. NanoAV logs/cache/quarantine remain under `%ProgramData%\NanoAV` and are not Sentinel's verified response receipts.

## Validation and retained limitations

Build from Command Prompt with `installer\build.bat` (or `build` inside the installer directory), or from PowerShell with `installer/build.ps1`. The batch entry point delegates to the same PowerShell implementation; both publish NanoAV before invoking Inno Setup. `build -StampOnly` prepares metadata without publishing or compiling an installer.

The full solution cross-build and separate EXE/COM DLL publication are checked without executing the scanner. Eighteen portable coexistence boundary cases pass; the installed-path Windows case is explicitly skipped on Linux and remains in the Windows test suite. Desktop-monitor behavior is unchanged; see [privacy review](PRIVACY_REVIEW_2026-10-21.md).

Preserving the supplied program also preserves its defects. Its process-start callback can request termination without first proving a threat; the unsigned-file cache can later drive a known-bad deletion. Its Main returns after starting monitoring, and the inspected startup does not schedule the C2/reverse-shell polling methods. These paths were not repaired because the requested source changes were limited to coexistence. Packaging does not establish that NanoAV remains resident, that every advertised engine runs, or that its live providers work. Validate startup/autorun, actual lifetime, feed responses, mutual process/file protection, upgrade and uninstall on a disposable Windows machine before relying on it. No detection-quality or mutual-protection guarantee against races or administrator tampering is claimed.

The supplied README attributes NanoAV to Gorstak and declares MIT licensing; that README and original notices are preserved. NanoAV keeps its original 1.0.0.0 assembly metadata inside the Sentinel 3.3.8 package.
