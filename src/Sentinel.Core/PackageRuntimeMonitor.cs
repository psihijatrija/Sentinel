using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v1.8.2: Supply-chain runtime - package managers spawning LOLBins / writing
    /// executables under package trees (postinstall, slopsquatting, TrapDoor-class).
    /// </summary>
    public sealed class PackageRuntimeMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<PackageRuntimeMonitor> _logger;
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertCooldown = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<int, DateTimeOffset> _pkgSessions = new();
        private readonly List<FileSystemWatcher> _devConfigWatchers = new();
        private readonly ConcurrentQueue<string> _configPoisonEvents = new();

        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);

        private static readonly HashSet<string> PackageManagers = new(StringComparer.OrdinalIgnoreCase)
        {
            "npm", "npm.cmd", "npx", "npx.cmd", "pnpm", "pnpm.cmd", "yarn", "yarn.cmd",
            "pip", "pip3", "pip.exe", "python", "python3", "uv", "uv.exe",
            "cargo", "cargo.exe", "dotnet", "dotnet.exe", "gem", "gem.cmd",
            "go", "go.exe", "nuget", "nuget.exe", "choco", "choco.exe",
            "winget", "winget.exe"
        };

        private static readonly HashSet<string> DangerousChildren = new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell", "pwsh", "cmd", "mshta", "certutil", "bitsadmin",
            "wscript", "cscript", "regsvr32", "rundll32", "curl", "wget",
            "bash", "sh", "wsl"
        };

        private static readonly string[] PackageTreeFragments =
        {
            @"\node_modules\", @"\site-packages\", @"\.cargo\", @"\packages\",
            @"\.nuget\packages\", @"\bower_components\"
        };

        private static readonly string[] DevConfigNames =
        {
            "CLAUDE.md", ".cursorrules", "AGENTS.md", "mcp.json",
            ".mcp.json", "gemini.md"
        };

        public PackageRuntimeMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<PackageRuntimeMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PackageRuntimeMonitor] Started - package/dev-config supply-chain runtime");
            StartDevConfigWatchers();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    ScanProcesses(ct);
                    DrainConfigPoison();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[PackageRuntimeMonitor] scan error");
                }

                try { await Task.Delay(PollInterval, ct); }
                catch (OperationCanceledException) { break; }
            }

            foreach (var w in _devConfigWatchers)
                w.Dispose();
            _devConfigWatchers.Clear();
        }

        private void StartDevConfigWatchers()
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var roots = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            };
            if (!string.IsNullOrEmpty(home))
            {
                roots.Add(Path.Combine(home, "source"));
                roots.Add(Path.Combine(home, "repos"));
                roots.Add(Path.Combine(home, "dev"));
            }

            foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;
                    var w = new FileSystemWatcher(root)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                        Filter = "*.*",
                        InternalBufferSize = 64 * 1024
                    };
                    w.Created += OnDevConfigEvent;
                    w.Changed += OnDevConfigEvent;
                    w.EnableRaisingEvents = true;
                    _devConfigWatchers.Add(w);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[PackageRuntimeMonitor] Dev config watcher not started for {Root}", root);
                }
            }
        }

        private void OnDevConfigEvent(object sender, FileSystemEventArgs e)
        {
            try
            {
                var name = Path.GetFileName(e.FullPath);
                if (string.IsNullOrEmpty(name)) return;
                if (!DevConfigNames.Any(n => name.Equals(n) ||
                                            name.Equals(".cursorrules")))
                    return;
                // Ignore huge trees noise: only shallow-ish paths (<=6 segments under profile)
                var parts = e.FullPath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (parts.Length > 12) return;
                _configPoisonEvents.Enqueue(e.FullPath);
            }
            catch { /* ignore watcher errors */ }
        }

        private void DrainConfigPoison()
        {
            while (_configPoisonEvents.TryDequeue(out var path))
            {
                var key = "cfg:" + path;
                var now = DateTimeOffset.UtcNow;
                if (_alertCooldown.TryGetValue(key, out var last) && now - last < AlertCooldown)
                    continue;
                _alertCooldown[key] = now;

                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Dev Config Poison: AI Agent Instruction File Write",
                    Evidence = $"AI/dev agent config file written or modified: {path}",
                    Reasoning =
                        "Malicious packages (TrapDoor-class) rewrite CLAUDE.md / Cursor / MCP configs " +
                        "so coding agents execute attacker instructions without a model vulnerability.",
                    Confidence = 0.55,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "filesystem",
                    ProcessId = 0,
                    SignalType = SignalType.SuspiciousProcess,
                    Metadata = new Dictionary<string, string> { ["Path"] = path }
                });
            }
        }

        private void ScanProcesses(CancellationToken ct)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var kv in _pkgSessions.Where(k => now - k.Value > TimeSpan.FromMinutes(15)).ToList())
                _pkgSessions.TryRemove(kv.Key, out _);

            Process[] procs;
            try { procs = Process.GetProcesses(); }
            catch { return; }

            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                string name;
                int pid;
                try
                {
                    name = p.ProcessName;
                    pid = p.Id;
                }
                catch { continue; }

                var bare = name.EndsWith(".exe") ? name[..^4] : name;
                if (PackageManagers.Contains(name) || PackageManagers.Contains(bare))
                    _pkgSessions[pid] = now;
            }

            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                int pid, ppid;
                string childName, parentName;
                string? path = null;
                try
                {
                    pid = p.Id;
                    childName = p.ProcessName;
                    var parent = _ancestryCache.GetParent(pid);
                    parentName = parent.name ?? "";
                    ppid = parent.parentId;
                    try { path = SecurityValidation.GetProcessImagePath(p.Id); } catch { /* deny */ }
                }
                catch { continue; }

                var parentIsPkg = _pkgSessions.ContainsKey(ppid) ||
                    PackageManagers.Contains(parentName) ||
                    PackageManagers.Contains(Sentinel.Core.StringNet48.ReplaceIgnoreCase(parentName, ".exe", ""));

                if (!parentIsPkg) continue;

                var childBare = childName.EndsWith(".exe")
                    ? childName[..^4]
                    : childName;

                var dangerousChild = DangerousChildren.Contains(childName) || DangerousChildren.Contains(childBare);
                var inPackageTree = path != null && PackageTreeFragments.Any(f =>
                    path.Contains(f));
                var isExeDrop = path != null &&
                    (path.EndsWith(".exe") ||
                     path.EndsWith(".dll") ||
                     path.EndsWith(".scr")) &&
                    inPackageTree;

                if (!dangerousChild && !isExeDrop) continue;

                var key = $"{ppid}:{childBare}:{dangerousChild}:{isExeDrop}";
                if (_alertCooldown.TryGetValue(key, out var last) && now - last < AlertCooldown)
                    continue;
                _alertCooldown[key] = now;

                var high = dangerousChild && (
                    childBare.Equals("mshta") ||
                    childBare.Equals("certutil") ||
                    childBare.Equals("powershell") ||
                    childBare.Equals("pwsh"));

                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = high
                        ? "Package Runtime: LOLBin from Package Manager"
                        : isExeDrop
                            ? "Package Runtime: Executable under Package Tree"
                            : "Package Runtime: Suspicious Child of Package Manager",
                    Evidence =
                        $"Package manager parent '{parentName}' (PID {ppid}) spawned '{childName}' (PID {pid}). " +
                        $"Path: {path ?? "(unknown)"}",
                    Reasoning =
                        "Supply-chain attacks abuse postinstall scripts and malicious packages to run shells, " +
                        "download payloads, or plant binaries under node_modules/site-packages without user intent.",
                    Confidence = high ? 0.85 : isExeDrop ? 0.70 : 0.60,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = high ? ResponseAction.KillProcessTree : ResponseAction.LogOnly,
                    ProcessName = childName,
                    ProcessId = pid,
                    SignalType = SignalType.SuspiciousProcess,
                    Metadata = new Dictionary<string, string>
                    {
                        ["ParentProcess"] = parentName,
                        ["ParentPid"] = ppid.ToString(),
                        ["ChildPath"] = path ?? "",
                        ["PackageTree"] = inPackageTree.ToString()
                    }
                });
            }

            foreach (var p in procs)
            {
                try { p.Dispose(); } catch { /* ignore */ }
            }
        }
    }
}
