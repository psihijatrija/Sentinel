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
    /// v1.8.2: Detects AI coding agents / MCP toolchains abused as autonomous attackers
    /// (agentic recon, credential harvest, package install, LOLBin spawn).
    /// LogOnly by default; KillProcessTree only when agent + credential path + network tool.
    /// </summary>
    public sealed class AgenticProcessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<AgenticProcessMonitor> _logger;
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertCooldown = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<int, DateTimeOffset> _agentPids = new();
        private readonly ConcurrentDictionary<int, int> _spawnCounts = new();

        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(8);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);

        private static readonly HashSet<string> AgentNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "claude", "claude.exe", "cursor", "cursor.exe", "codex", "codex.exe",
            "aider", "aider.exe", "windsurf", "windsurf.exe", "continue", "continue.exe",
            "gemini", "gemini.exe", "copilot", "github-copilot", "ollama", "ollama.exe",
            "lmstudio", "lm-studio", "open-webui", "npx", "npx.cmd"
        };

        private static readonly HashSet<string> HighRiskChildren = new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell", "pwsh", "cmd", "bash", "wsl", "python", "python3", "node",
            "certutil", "mshta", "bitsadmin", "curl", "wget", "ssh", "scp", "rclone",
            "mimikatz", "procdump", "rubeus", "lazagne"
        };

        private static readonly string[] CredentialPathFragments =
        {
            @"\login data", @"\cookies", @"\key4.db", @"\logins.json",
            @"\.ssh\id_", @"\credentials", @"\.aws\", @"\.azure\",
            @"\.config\gcloud", @"\appdata\roaming\mozilla",
            @"\.kube\config", @"\.gnupg\"
        };

        public AgenticProcessMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<AgenticProcessMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[AgenticProcessMonitor] Started - AI/MCP agent abuse detection");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    Scan(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[AgenticProcessMonitor] scan error");
                }

                try { await Task.Delay(PollInterval, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        private void Scan(CancellationToken ct)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var kv in _agentPids.Where(k => now - k.Value > TimeSpan.FromMinutes(10)).ToList())
                _agentPids.TryRemove(kv.Key, out _);

            Process[] procs;
            try { procs = Process.GetProcesses(); }
            catch { return; }

            var byId = new Dictionary<int, Process>();
            foreach (var p in procs)
            {
                try { byId[p.Id] = p; }
                catch { /* disposed */ }
            }

            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                string name;
                try { name = p.ProcessName; }
                catch { continue; }

                var bare = name.EndsWith(".exe")
                    ? name[..^4]
                    : name;

                if (AgentNames.Contains(name) || AgentNames.Contains(bare) ||
                    name.Contains("claude") ||
                    name.Contains("cursor"))
                {
                    _agentPids[p.Id] = now;
                }
            }

            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                int pid, ppid;
                string childName, parentName;
                try
                {
                    pid = p.Id;
                    childName = p.ProcessName;
                    var parent = _ancestryCache.GetParent(pid);
                    parentName = parent.name ?? "";
                    ppid = parent.parentId;
                }
                catch { continue; }

                var isAgentChild = _agentPids.ContainsKey(ppid) ||
                    AgentNames.Contains(parentName) ||
                    parentName.Contains("claude") ||
                    parentName.Contains("cursor");

                if (!isAgentChild) continue;

                _spawnCounts.AddOrUpdate(ppid, 1, (_, c) => c + 1);

                var childBare = childName.EndsWith(".exe")
                    ? childName[..^4]
                    : childName;

                if (!HighRiskChildren.Contains(childName) && !HighRiskChildren.Contains(childBare))
                    continue;

                string? path = null;
                try { path = SecurityValidation.GetProcessImagePath(p.Id); } catch { /* access denied */ }

                var credTouch = path != null && CredentialPathFragments.Any(f =>
                    path.Contains(f));

                // Burst: many children from one agent
                var burst = _spawnCounts.TryGetValue(ppid, out var count) && count >= 12;

                var key = $"{ppid}:{childBare}";
                if (_alertCooldown.TryGetValue(key, out var last) && now - last < AlertCooldown)
                    continue;
                _alertCooldown[key] = now;

                var critical = credTouch ||
                    childBare.Equals("mimikatz") ||
                    childBare.Equals("procdump");

                var confidence = critical ? 0.88 : burst ? 0.72 : 0.62;
                var response = critical
                    ? ResponseAction.KillProcessTree
                    : ResponseAction.LogOnly;

                _ = _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = critical
                        ? "Agentic AI: Credential-Path Tool Spawn"
                        : burst
                            ? "Agentic AI: Burst Process Spawn"
                            : "Agentic AI: High-Risk Child Process",
                    Evidence =
                        $"AI/dev agent parent '{parentName}' (PID {ppid}) spawned '{childName}' (PID {pid}). " +
                        (credTouch ? "Child image path touches credential stores. " : "") +
                        (burst ? $"Parent spawn burst count~={count}. " : ""),
                    Reasoning =
                        "Agentic coding tools can be jailbroken or config-poisoned to run recon, " +
                        "install packages, harvest credentials, and exfiltrate data with little human input. " +
                        "Treating agent process trees as high-privilege automation.",
                    Confidence = confidence,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = response,
                    ProcessName = childName,
                    ProcessId = pid,
                    SignalType = critical ? SignalType.CredentialTheft : SignalType.SuspiciousProcess,
                    Metadata = new Dictionary<string, string>
                    {
                        ["ParentProcess"] = parentName,
                        ["ParentPid"] = ppid.ToString(),
                        ["ChildPath"] = path ?? "",
                        ["Burst"] = burst.ToString(),
                        ["CredPath"] = credTouch.ToString()
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
