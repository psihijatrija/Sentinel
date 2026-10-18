using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public partial class AdvancedResponseEngine
    {
        private readonly SentinelConfig _config;
        private readonly SentinelMetrics _metrics;
        private readonly JsonlEventLogger _eventLogger;
        private readonly QuarantineManager _quarantineManager;
        private readonly AllowlistService? _allowlist;
        private readonly SentinelEventLogWriter? _windowsEventLog;
        private IncidentResponseService? _incidentResponse;
        private DllUnloadEngine? _dllUnloadEngine;
        private ChainTracer? _chainTracer;
        private ReinfectionCorrelator? _reinfectionCorrelator;
        private VpnShieldEngine? _vpnShieldEngine;
        private readonly IsolationResponseEngine? _isolationResponse;

        // v1.6.0: Rolling kill budget to prevent response weaponization (FP kill storms)
        private readonly ConcurrentQueue<long> _killTimestampsMs = new();
        private long _lastRateLimitLogMs;
        // v1.6.1: NetworkIsolate budget + Tier1 alert hook
        private readonly ConcurrentQueue<long> _isolateTimestampsMs = new();
        private long _lastIsolateRateLimitLogMs;
        private DetectionEngine? _detectionEngine;

        // v1.8.1 RT-LOW-1: hard cap on timestamp queues (limit * 2) under pathological load
        private static int BudgetQueueCap(int limit) => Math.Max(limit * 2, 32);

        /// <summary>Set after DI construction to avoid circular dependency.</summary>
        public void SetReinfectionCorrelator(ReinfectionCorrelator correlator) => _reinfectionCorrelator = correlator;

        public AdvancedResponseEngine(
            SentinelConfig config,
            SentinelMetrics metrics,
            JsonlEventLogger eventLogger,
            QuarantineManager quarantineManager,
            AllowlistService? allowlist = null,
            SentinelEventLogWriter? windowsEventLog = null,
            IsolationResponseEngine? isolationResponse = null)
        {
            _config = config;
            _metrics = metrics;
            _eventLogger = eventLogger;
            _quarantineManager = quarantineManager;
            _allowlist = allowlist;
            _windowsEventLog = windowsEventLog;
            _isolationResponse = isolationResponse;
        }

        private void TryWriteWindowsEventLog(DetectionEvent detection, string actionTaken, string reason)
        {
            try
            {
                if (_windowsEventLog == null || !_windowsEventLog.IsAvailable)
                    return;
                // Durable trail for real actions / chain confirms only (not observe LogOnly spam)
                if (string.IsNullOrEmpty(actionTaken) ||
                    actionTaken.StartsWith("LOG", StringComparison.OrdinalIgnoreCase))
                    return;
                if (reason != null &&
                    !actionTaken.StartsWith("RESPONSE_", StringComparison.OrdinalIgnoreCase) &&
                    reason.IndexOf("ChainConfirmed", StringComparison.OrdinalIgnoreCase) < 0 &&
                    actionTaken.IndexOf("KILL", StringComparison.OrdinalIgnoreCase) < 0 &&
                    actionTaken.IndexOf("QUARANTINE", StringComparison.OrdinalIgnoreCase) < 0 &&
                    actionTaken.IndexOf("ISOLATE", StringComparison.OrdinalIgnoreCase) < 0 &&
                    actionTaken.IndexOf("NETWORK", StringComparison.OrdinalIgnoreCase) < 0)
                    return;

                _windowsEventLog.WriteChainResponse(detection, actionTaken, reason ?? "");
            }
            catch
            {
                // Absolute fail-soft - response path must never throw on Event Log
            }
        }

        /// <summary>
        /// v1.6.0: Returns false when MaxKillsPerMinute budget is exhausted.
        /// NetworkIsolate is gated separately via TryConsumeIsolateBudget.
        /// </summary>
        private bool TryConsumeKillBudget()
        {
            int limit = _config.MaxKillsPerMinute;
            if (limit <= 0) return true;

            long now = System.Net48Environment.TickCount64;
            long windowStart = now - 60_000;
            while (_killTimestampsMs.TryPeek(out long ts) && ts < windowStart)
                _killTimestampsMs.TryDequeue(out _);

            if (_killTimestampsMs.Count >= limit)
            {
                // Log at most once per 30s to avoid log floods
                long lastLog = Interlocked.Read(ref _lastRateLimitLogMs);
                if (now - lastLog > 30_000 &&
                    Interlocked.CompareExchange(ref _lastRateLimitLogMs, now, lastLog) == lastLog)
                {
                    _ = _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = 0,
                        ProcessName = "SYSTEM",
                        ActionTaken = "RATE_LIMITED",
                        Reason = $"Kill budget exhausted ({limit}/min). Subsequent kills demoted to LogOnly until window slides.",
                        ExecutionTimeMs = 0
                    });
                    // v1.6.1: Loud Tier1 so operators see weaponized FP / ransomware wave
                    EmitBudgetExhaustedAlert("KillBudget", limit);
                }
                return false;
            }

            _killTimestampsMs.Enqueue(now);
            TrimBudgetQueue(_killTimestampsMs, BudgetQueueCap(limit));
            return true;
        }

        /// <summary>
        /// v1.6.1: Cap new NetworkIsolate targets per minute.
        /// </summary>
        private bool TryConsumeIsolateBudget()
        {
            int limit = _config.MaxNetworkIsolatesPerMinute;
            if (limit <= 0) return true;

            long now = System.Net48Environment.TickCount64;
            long windowStart = now - 60_000;
            while (_isolateTimestampsMs.TryPeek(out long ts) && ts < windowStart)
                _isolateTimestampsMs.TryDequeue(out _);

            if (_isolateTimestampsMs.Count >= limit)
            {
                long lastLog = Interlocked.Read(ref _lastIsolateRateLimitLogMs);
                if (now - lastLog > 30_000 &&
                    Interlocked.CompareExchange(ref _lastIsolateRateLimitLogMs, now, lastLog) == lastLog)
                {
                    _ = _eventLogger.LogEventAsync("response", new ResponseEvent
                    {
                        ProcessId = 0,
                        ProcessName = "SYSTEM",
                        ActionTaken = "ISOLATE_RATE_LIMITED",
                        Reason = $"NetworkIsolate budget exhausted ({limit}/min). Further isolates skipped until window slides.",
                        ExecutionTimeMs = 0
                    });
                    EmitBudgetExhaustedAlert("NetworkIsolateBudget", limit);
                }
                return false;
            }

            _isolateTimestampsMs.Enqueue(now);
            TrimBudgetQueue(_isolateTimestampsMs, BudgetQueueCap(limit));
            return true;
        }

        private static void TrimBudgetQueue(ConcurrentQueue<long> queue, int maxCount)
        {
            while (queue.Count > maxCount && queue.TryDequeue(out _)) { }
        }

        private void EmitBudgetExhaustedAlert(string budgetType, int limit)
        {
            var de = _detectionEngine;
            if (de == null) return;
            _ = de.EmitAsync(new DetectionEvent
            {
                RuleName = "Anti-Tamper: Response Budget Exhausted",
                Evidence = $"{budgetType} hit limit of {limit} actions per minute. " +
                           "Further destructive responses are demoted/skipped until the window slides.",
                Reasoning = "Exhausting the automated response budget can indicate either a true mass-infection " +
                            "event (ransomware) or an attacker weaponizing false positives / decoy beacons. " +
                            "Operators must review immediately; detection logging continues.",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.AntiTamper,
                Metadata = new Dictionary<string, string>
                {
                    ["BudgetType"] = budgetType,
                    ["LimitPerMinute"] = limit.ToString()
                }
            });
        }

        public void SetDllUnloadEngine(DllUnloadEngine engine) => _dllUnloadEngine = engine;

        public void SetChainTracer(ChainTracer tracer) => _chainTracer = tracer;

        public void SetIncidentResponseService(IncidentResponseService irs) => _incidentResponse = irs;

        /// <summary>v2.6.0: Wire the VPN-shield engine after DI to avoid circular construction.</summary>
        public void SetVpnShieldEngine(VpnShieldEngine engine) => _vpnShieldEngine = engine;

        /// <summary>v1.6.1: Wire DetectionEngine after DI to avoid circular construction.</summary>
        public void SetDetectionEngine(DetectionEngine engine) => _detectionEngine = engine;

        private static readonly HashSet<string> PresidentsLawKeywords = new(StringComparer.OrdinalIgnoreCase)
        {
            "lsass", "amsi", "etw", "ransomware", "shadow copy",
            "self-protection", "selfprotection", "honeypot", "chain-nuke",
            "composite", "verdictgate", "verdict gate",
            "webcamhijack", "webcam hijack", "audiohijack", "audio hijack",
            "antitamper", "anti-tamper", "tampering",
            "hollowing", "reverseshell", "reverse shell",
            "threatintel", "badusb", "canary",
            "tls:", "certificate"
        };

        private bool IsPresidentsLawRule(DetectionEvent detection)
        {
            // Delegate to ScoringEngine's authoritative enum-based categorization
            // to avoid divergence between the two parallel President's Law checks.
            return ScoringEngine.IsPresidentsLawRule(detection.RuleName);
        }

        /// <summary>
        /// v1.8.3: Single-signal heuristics that fire during normal user work (SSH, torrents,
        /// portable tools in Downloads, rclone backups, shell networking). These must never
        /// kill/quarantine alone. Confirmed attacks and multi-signal composites are excluded.
        /// </summary>
        internal static bool IsObserveOnlyUserActivityHeuristic(string? ruleName)
        {
            if (string.IsNullOrWhiteSpace(ruleName)) return false;
            var r = ruleName!;

            // Composites / confirmed campaigns always act
            if (r.Contains("Composite") ||
                r.Contains("Fileless Attack") ||
                r.Contains("Covert RAT") ||
                r.Contains("Dropped Payload") ||
                r.Contains("Confirmed C2") ||
                r.Contains("SYSTEM Token") ||
                r.Contains("Non-Service Process with SYSTEM"))
                return false;

            return r.Contains("Reverse Shell: Suspicious Outbound") ||
                   r.Contains("Connection on Blocked Port") ||
                   r.Contains("Network UDP: Classic Malware Port") ||
                   r.Contains("Attack Tool: Connection from Suspicious Path") ||
                   r.Contains("Network Policy: Unusual Destination") ||
                   r.Contains("SeImpersonatePrivilege from Suspicious Path") ||
                   r.Contains("Cloud Sync Tool Running") ||
                   r.Contains("Data Exfiltration: Cloud Sync");
        }

        public async Task<ResponseExecutionResult> HandleAsync(DetectionEvent detection)
        {
            if (detection == null) throw new ArgumentNullException(nameof(detection));
            if (detection.RecordedExecution != null)
            {
                _metrics.RecordResponseOutcome(detection.RecordedExecution);
                // Report a trusted inline executor's receipt without executing its action again.
                // External telemetry cannot populate this internal, non-serialized field.
                await _eventLogger.LogEventAsync("response_result", detection.RecordedExecution).ConfigureAwait(false);
                return detection.RecordedExecution;
            }
            ResponsePolicy.EnforceDispatchPolicy(detection);
            var execution = new ResponseExecutionResult
            {
                ProcessId = detection.ProcessId, ProcessName = detection.ProcessName,
                RequestedAction = detection.AuthorizedResponse.ToString(),
                EffectiveAction = detection.AuthorizedResponse.ToString()
            };
            try { await HandleCoreAsync(detection, execution).ConfigureAwait(false); }
            catch (Exception ex)
            {
                execution.Add("Executor", detection.ProcessId.ToString(), ResponseExecutionStatus.Failed, ex.Message);
                execution.Reason = "Response executor failed: " + ex.Message;
            }
            execution.CompletedAt = DateTimeOffset.UtcNow;
            _metrics.RecordResponseOutcome(execution);
            await _eventLogger.LogEventAsync("response_result", execution).ConfigureAwait(false);
            return execution;
        }

        private Task LogResponseAsync(ResponseExecutionResult execution, ResponseEvent response)
        {
            execution.Reason = response.Reason;
            execution.CompletedAt = DateTimeOffset.UtcNow;
            if (response.ActionTaken == "LOG" && execution.Effects.Count == 0)
                execution.EffectiveAction = nameof(ResponseAction.LogOnly);
            response.Execution = execution;
            if (response.ActionTaken != "LOG" && execution.Status != ResponseExecutionStatus.Verified)
                response.ActionTaken = "RESPONSE_" + execution.Status.ToString().ToUpperInvariant();
            return _eventLogger.LogEventAsync("response", response);
        }

        private async Task HandleCoreAsync(DetectionEvent detection, ResponseExecutionResult execution)
        {
            var stopwatch = Stopwatch.StartNew();

            bool shouldKill = false;
            bool shouldIsolateNetwork = false;
            bool shouldQuarantineAndKill = false;
            bool shouldRemoveCertAndKillAdder = false;
            bool shouldRemoveCert = false;
            bool shouldRemoveRegistryEntry = false;
            bool shouldRaiseVpnShield = false;
            bool shouldDismountVolume = false;
            bool shouldContainDocker = false;
            bool shouldContainVm = false;
            string reason = "LogOnly";

            // HARDENING v1.3.8: Absolute self-exclusion - never take action against our own processes.
            // The FileReputationEngine flags our unsigned dev builds as "Suspicious" (score ~43-48),
            // and the correlation engine can escalate these to kill responses. Force LogOnly.
            //
            // SECURITY: Path-verified, not name-based. An attacker naming their binary
            // "Sentinel.Agent.exe" in a user-writable directory is NOT excluded.
            // We resolve the actual image path and verify it resides in our installation directory.
            if (detection.ProcessId > 0)
            {
                try
                {
                    var detectedImagePath = SecurityValidation.GetProcessImagePath(detection.ProcessId);
                    // SECURITY v1.4.4: Normalize both paths with Path.GetFullPath() to resolve
                    // symlinks, junctions, and relative segments (../) before comparison.
                    // Also use trailing separator to prevent prefix collision attacks
                    // (e.g., C:\Program Files\Sentinel2\evil.exe matching our dir).
                    // v2.0 RT-HIGH-2: hardlink-aware self path (not string-prefix alone)
                    if (detectedImagePath != null &&
                        (SelfPathGuard.IsSentinelSelfBinary(detectedImagePath) ||
                         SelfPathGuard.IsUnderInstallDirectory(detectedImagePath)))
                    {
                        // Only skip response for our own binaries under install - not arbitrary hardlinks
                        if (SelfPathGuard.IsSentinelSelfBinary(detectedImagePath))
                        {
                            reason = "LogOnly (Self-exclusion: verified Sentinel install path)";
                            stopwatch.Stop();
                            _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                            var selfLog = new ResponseEvent
                            {
                                ProcessId = detection.ProcessId,
                                ProcessName = detection.ProcessName,
                                ActionTaken = "LOG",
                                Reason = reason,
                                ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                            };
                            await LogResponseAsync(execution, selfLog);
                            return;
                        }
                    }
                }
                catch { /* process may have exited - continue with normal handling */ }
            }

            // Live DetectionEngine classifies tier authority before dispatch.
            var isPresidentsLaw = IsPresidentsLawRule(detection);
            var effectiveTier = detection.Tier;
            var effectiveResponse = detection.AuthorizedResponse;
            var effectiveKillAuthorized = detection.KillAuthorized;

            string? imagePath = null;
            try
            {
                if (detection.ProcessId > 0)
                {
                    imagePath = SecurityValidation.GetProcessImagePath(detection.ProcessId);
                }
            }
            catch { }

            // v1.6.9: IDE / development tool protection - Electron/V8 apps generate JIT code
            // that matches syscall-stub patterns, RWX memory patterns, and other heuristics.
            // Killing an IDE is an irreversible false positive that destroys the developer's
            // session. Demote to LogOnly unless this is a President's Law rule (actual confirmed
            // malicious activity like process injection INTO the IDE).
            if (!isPresidentsLaw && detection.ProcessId > 0 &&
                ChainTracer.IsLegitimateIdeHost(imagePath, detection.ProcessName))
            {
                reason = $"LogOnly (IDE host protection: {detection.ProcessName} at '{imagePath}')";
                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                var ideLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "LOG",
                    Reason = reason,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await LogResponseAsync(execution, ideLog);
                return;
            }

            if (!isPresidentsLaw && detection.ProcessId > 0 &&
                AlwaysOnPolicies.ApplyGameProtection(detection, imagePath))
            {
                reason = $"LogOnly (AlwaysOn: Game Protection - {detection.ProcessName} at '{imagePath}')";
                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                var gameLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "LOG",
                    Reason = reason,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await LogResponseAsync(execution, gameLog);
                return;
            }

            if (_allowlist != null && _allowlist.ShouldSuppress(detection.ProcessName, imagePath, detection.RuleName))
            {
                effectiveTier = DetectionTier.Tier2Indicator;
                effectiveResponse = ResponseAction.LogOnly;
                effectiveKillAuthorized = false;
                reason = "LogOnly (Suppressed by allowlist)";
            }

            if (IsObserveOnlyUserActivityHeuristic(detection.RuleName) &&
                     effectiveResponse is ResponseAction.KillProcess or ResponseAction.KillProcessTree
                         or ResponseAction.Quarantine or ResponseAction.QuarantineAndKill
                         or ResponseAction.NetworkIsolate)
            {
                // Weak user-activity heuristics never authorize destructive response.
                effectiveTier = DetectionTier.Tier2Indicator;
                effectiveResponse = ResponseAction.LogOnly;
                effectiveKillAuthorized = false;
                reason = "LogOnly (observe-first: weak user-activity heuristic - no confirmed attack)";
            }

            bool ar = _config.ActiveResponse;
            execution.EffectiveAction = effectiveTier == DetectionTier.Tier2Indicator
                ? nameof(ResponseAction.LogOnly) : effectiveResponse.ToString();

            // v2.8.4: Isolation-environment upgrade. When a Tier1 kill/quarantine action is already
            // authorized AND the offending process runs from a mounted ISO/disk image, upgrade the
            // action to DismountVolume so containment also kills+dismounts+deletes the backing .iso
            // (via the wired IsolationResponseEngine). This is deliberately gated on an ALREADY
            // authorized destructive action - it never lowers the bar. It uses non-attacker-
            // controllable anchors only (the OS-recorded process image path + mounted image path),
            // never a filename. If the ISO origin can't be confirmed, we leave the action untouched.
            if (ar && effectiveTier == DetectionTier.Tier1Behavioral &&
                (effectiveKillAuthorized ||
                 effectiveResponse is ResponseAction.KillProcess or ResponseAction.KillProcessTree
                     or ResponseAction.Quarantine or ResponseAction.QuarantineAndKill) &&
                detection.ProcessId > 4 &&
                IsoOriginResolver.IsImagePathOnMountedIso(imagePath))
            {
                effectiveResponse = ResponseAction.DismountVolume;
                reason = $"ISO-hosted terminal (upgraded to DismountVolume) - {reason}";
            }

            // v2.8.4: Isolation-environment containment for Docker containers and VMs. Mirrors the
            // ISO branch above and closes the same dead-code gap: IsolationResponseEngine's Docker
            // and VM handlers previously had zero runtime callers. A chain-confirmed terminal that
            // carries a container/VM origin (via non-attacker-controllable metadata the detecting
            // monitor recorded, or a resolvable VM host PID) is contained by stopping/removing the
            // container or terminating the VM host IN ADDITION to the normal kill. Gated on an
            // already-authorized destructive action (ar + Tier1); never fires on a bare
            // container-config observation. These run alongside the kill branch below (they do not
            // replace the process kill), so the offending process is still terminated.
            bool killGradeAuthorizedNow =
                ar && _isolationResponse != null && effectiveTier == DetectionTier.Tier1Behavioral &&
                (effectiveKillAuthorized ||
                 effectiveResponse is ResponseAction.KillProcess or ResponseAction.KillProcessTree
                     or ResponseAction.Quarantine or ResponseAction.QuarantineAndKill);
            if (killGradeAuthorizedNow &&
                detection.Metadata != null &&
                detection.Metadata.TryGetValue("ContainerId", out var containerId) &&
                !string.IsNullOrWhiteSpace(containerId))
            {
                shouldContainDocker = true;
                reason = $"Docker containment (container={containerId}) - {reason}";
            }
            else if (killGradeAuthorizedNow &&
                     detection.Metadata != null &&
                     detection.Metadata.TryGetValue("VmHostPid", out var vmPidStr) &&
                     int.TryParse(vmPidStr, out var vmHostPid) && vmHostPid > 4)
            {
                shouldContainVm = true;
                reason = $"VM containment (vmHostPid={vmHostPid}) - {reason}";
            }

            if (effectiveResponse == ResponseAction.QuarantineAndKill && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldQuarantineAndKill = true;
                    if (!reason.StartsWith("ChainConfirmed"))
                        reason = $"QuarantineAndKill (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (active response unavailable)";
                }
            }
            else if (effectiveResponse == ResponseAction.RemoveCertAndKillAdder && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldRemoveCertAndKillAdder = true;
                    reason = $"RemoveCertAndKillAdder (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (active response unavailable)";
                }
            }
            else if (effectiveResponse == ResponseAction.RemoveRegistryEntry && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldRemoveRegistryEntry = true;
                    reason = $"RemoveRegistryEntry (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (active response unavailable)";
                }
            }
            else if (effectiveResponse == ResponseAction.RemoveCert && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldRemoveCert = true;
                    reason = $"RemoveCert (AuthorizedResponse={effectiveResponse}, no process terminated)";
                }
                else
                {
                    reason = "LogOnly (active response unavailable)";
                }
            }
            else if (effectiveResponse == ResponseAction.NetworkIsolate && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldIsolateNetwork = true;
                    reason = $"NetworkIsolate (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (active response unavailable)";
                }
            }
            else if (effectiveResponse == ResponseAction.VpnShieldUp && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                // v2.6.0: Protective VPN-shield remediation for a confirmed network-tamper
                // incident. Tier1-guarded like every other action (Tier2 can never reach here).
                // Additionally gated on the operator opt-in ProductPosture.AllowsVpnShield -
                // default-deny: with VpnShield disabled this stays LogOnly and no tunnel is raised.
                if (ar && ProductPosture.AllowsVpnShield(_config))
                {
                    shouldRaiseVpnShield = true;
                    reason = $"VpnShieldUp (AuthorizedResponse={effectiveResponse}, network-tamper remediation)";
                }
                else if (!ProductPosture.AllowsVpnShield(_config))
                {
                    reason = "LogOnly (VpnShield disabled - opt-in via VpnShield.Enabled)";
                }
                else
                {
                    reason = "LogOnly (active response unavailable)";
                }
            }
            else if (effectiveResponse == ResponseAction.DismountVolume && effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldDismountVolume = true;
                    reason = $"DismountVolume (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (active response unavailable)";
                }
            }
            else if ((effectiveKillAuthorized ||
                      effectiveResponse is ResponseAction.KillProcess or ResponseAction.KillProcessTree) &&
                     effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (ar)
                {
                    shouldKill = true;
                    if (!reason.StartsWith("MitmDefense") && !reason.StartsWith("ChainConfirmed"))
                        reason = $"Kill requested (AuthorizedResponse={effectiveResponse})";
                }
                else
                {
                    reason = "LogOnly (active response unavailable)";
                }
            }
            else if (effectiveTier == DetectionTier.Tier1Behavioral)
            {
                if (reason == "LogOnly")
                    reason = "LogOnly (Tier1 without kill authorization)";
            }
            else
            {
                if (reason == "LogOnly")
                {
                    reason = "LogOnly (Tier2 Indicator)";
                }
            }

            // MANDATORY pre-action audit (constraints: the tamper-resistant audit trail MUST be
            // written BEFORE any kill/block/quarantine/isolate/cert-removal fires). All should*
            // flags are finalized above; a destructive branch runs immediately below. Writing here
            // once - rather than in each branch - guarantees no destructive path can execute
            // without a preceding PRE_ACTION record. LogOnly outcomes are intentionally NOT
            // audited here (they cause no host mutation); they remain in events.jsonl only.
            bool willActDestructively =
                shouldKill || shouldQuarantineAndKill || shouldIsolateNetwork ||
                shouldRemoveCertAndKillAdder || shouldRemoveCert || shouldRemoveRegistryEntry ||
                shouldRaiseVpnShield || shouldDismountVolume || shouldContainDocker || shouldContainVm;

            if (willActDestructively)
            {
                // Copy into locals so the null-coalescing here does not alter the compiler's
                // null-state flow for detection.RuleName / detection.ProcessName in the
                // destructive branches below (which read them directly, as they always have).
                var auditRuleName = detection.RuleName is { } rn ? rn : "unknown";
                var auditRuleId = detection.RuleId is { } rid ? rid : auditRuleName;
                var auditProcessName = detection.ProcessName is { } pn ? pn : "unknown";
                await _eventLogger.LogAuditBeforeActionAsync(
                    detectionId: detection.Timestamp.ToString("O") + ":" + detection.ProcessId,
                    ruleId: auditRuleId,
                    ruleName: auditRuleName,
                    proposedAction: effectiveResponse,
                    confidence: detection.Confidence,
                    processName: auditProcessName,
                    processId: detection.ProcessId,
                    justification: reason);
            }

            if (shouldRemoveCertAndKillAdder)
            {
                var certThumb = detection.Metadata!.GetValueOrDefault("CertThumbprint", "Unknown");
                var adderPidStr = detection.Metadata!.GetValueOrDefault("AdderProcessId", "0");

                // Only remove certs that are MITM-related (planted for interception).
                // Non-MITM cert detections are logged but not actioned.
                bool isMitmCert = ResponsePolicy.IsMitmDefenseAction(detection, _config);

                if (!string.IsNullOrEmpty(certThumb) && certThumb != "Unknown" && isMitmCert)
                {
                    execution.Effects.AddRange(RemoveCertificateFromStore(certThumb));
                }
                else if (!isMitmCert)
                {
                    stopwatch.Stop();
                    _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                    await LogResponseAsync(execution, new ResponseEvent
                    {
                        ProcessId = detection.ProcessId,
                        ProcessName = detection.ProcessName,
                        ActionTaken = "LOG",
                        Reason = $"Triggered by rule: {detection.RuleName}. Cert removal skipped - not MITM-related. CertThumbprint={certThumb}",
                        ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                    });
                    return;
                }

                if (int.TryParse(adderPidStr, out int adderPid) && adderPid > 4 && isMitmCert)
                {
                    if (TryConsumeKillBudget())
                        execution.AddProcessTree(HardeningModule.SafeKillProcessTree(adderPid));
                    else
                        execution.Add("ProcessTree", adderPidStr, ResponseExecutionStatus.Refused, "Kill budget exhausted.");
                }

                if (!int.TryParse(adderPidStr, out int verifiedAdder) || verifiedAdder <= 4)
                    execution.Add("ProcessTree", adderPidStr, ResponseExecutionStatus.Refused, "Valid certificate-adder PID was not supplied.");
                if (string.IsNullOrEmpty(certThumb) || certThumb == "Unknown")
                    execution.Add("CertificateRemoval", certThumb, ResponseExecutionStatus.Refused, "Certificate thumbprint missing.");

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = isMitmCert ? "REMOVE_CERT_AND_KILL_ADDER" : "LOG",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. CertThumbprint={certThumb}. AdderPID={adderPidStr}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await LogResponseAsync(execution, responseLog);
            }
            else if (shouldRemoveCert)
            {
                var certThumb = detection.Metadata!.GetValueOrDefault("CertThumbprint", "Unknown");

                // Only remove certs that are MITM-related (planted for interception).
                bool isMitmCert = ResponsePolicy.IsMitmDefenseAction(detection, _config);

                if (!string.IsNullOrEmpty(certThumb) && certThumb != "Unknown" && isMitmCert)
                {
                    execution.Effects.AddRange(RemoveCertificateFromStore(certThumb));
                }

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = isMitmCert ? "REMOVE_CERT" : "LOG",
                    Reason = isMitmCert
                        ? $"Triggered by rule: {detection.RuleName}. {reason}. CertThumbprint={certThumb}"
                        : $"Triggered by rule: {detection.RuleName}. Cert removal skipped - not MITM-related. CertThumbprint={certThumb}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await LogResponseAsync(execution, responseLog);
            }
            else if (shouldQuarantineAndKill)
            {
                // v1.6.0: rate-limit destructive responses
                if (!TryConsumeKillBudget())
                {
                    stopwatch.Stop();
                    _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                    await LogResponseAsync(execution, new ResponseEvent
                    {
                        ProcessId = detection.ProcessId,
                        ProcessName = detection.ProcessName,
                        ActionTaken = "LOG",
                        Reason = $"Triggered by rule: {detection.RuleName}. QuarantineAndKill rate-limited (MaxKillsPerMinute).",
                        ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                    });
                    return;
                }

                // DLL sideloading/injection: quarantine the malicious DLL, kill the host process
                var targetPidStr = detection.Metadata!.GetValueOrDefault("TargetProcessId", "0");
                int.TryParse(targetPidStr, out int targetPid);
                
                string quarantinedInfo = "None";
                string dllContainmentInfo = "Not attempted";
                if (targetPid > 0 && _dllUnloadEngine != null)
                {
                    var remediateResult = await _dllUnloadEngine.UnloadInjectedDllAsync(targetPid);
                    dllContainmentInfo = remediateResult.ContainmentSummary;
                    if (remediateResult.Containment != null) execution.AddProcessTree(remediateResult.Containment);
                    foreach (var file in remediateResult.FileOutcomes)
                        execution.Add("DllQuarantine", file.Key,
                            file.Value == DllFileOutcome.Quarantined || file.Value == DllFileOutcome.AlreadyAbsent
                                ? ResponseExecutionStatus.Verified : file.Value == DllFileOutcome.Deferred
                                    ? ResponseExecutionStatus.Attempted : ResponseExecutionStatus.Failed, file.Value.ToString());
                    if (remediateResult.Containment == null)
                        execution.Add("DllContainment", targetPid.ToString(), ResponseExecutionStatus.Refused, "No eligible mapped-module containment was performed.");
                    if (remediateResult.QuarantinedDlls.Count > 0)
                    {
                        quarantinedInfo = string.Join(", ", remediateResult.QuarantinedDlls);
                    }
                }

                // HARDENING v1.5.9: Verify Authenticode before quarantining the injector binary.
                // Legitimate debugging/profiling tools (e.g., x64dbg, Process Hacker, AV hooking
                // engines) use injection APIs but are validly signed. Quarantining them is an
                // irreversible false positive that destroys the user's tool from disk.
                // Fix: signed injectors are still killed (stop the action) but NOT quarantined.
                // Unsigned/invalid-signature injectors are quarantined as before.
                bool injectorQuarantined = false;
                try
                {
                    using var proc = Process.GetProcessById(detection.ProcessId);
                    // QUERY_LIMITED only - MainModule uses PROCESS_VM_READ (breaks anti-cheat)
                    var quarantinePath = SecurityValidation.GetProcessImagePath(detection.ProcessId)
                                        ?? proc.MainModule?.FileName;
                    if (SecurityValidation.IsGameOrAntiCheatPath(quarantinePath))
                        quarantinePath = null; // never quarantine game binaries from path lookup races
                    if (!string.IsNullOrEmpty(quarantinePath) && File.Exists(quarantinePath))
                    {
                        // QuarantineManager refuses signed binaries by default (returns null).
                        var qPath = await _quarantineManager.QuarantineFileAtomicAsync(quarantinePath!);
                        var quarantineEffect = ResponseVerification.Quarantine(quarantinePath!, qPath);
                        execution.Effects.Add(quarantineEffect);
                        injectorQuarantined = quarantineEffect.Status == ResponseExecutionStatus.Verified;
                        // signed binary - kill process tree but preserve the file on disk
                    }
                }
                catch (Exception ex)
                {
                    execution.Add("Quarantine", detection.ProcessId.ToString(), ResponseExecutionStatus.Failed, ex.Message);
                }
                if (!execution.Effects.Any(e => e.Action == "Quarantine"))
                    execution.Add("Quarantine", detection.ProcessId.ToString(), ResponseExecutionStatus.Refused, "Injector file was not eligible or could not be resolved.");

                // Report the injector tree separately from the process hosting the DLL.
                var injectorContainment = HardeningModule.SafeKillProcessTree(detection.ProcessId);
                execution.AddProcessTree(injectorContainment);

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = injectorContainment.Success
                        ? (injectorQuarantined ? "QUARANTINE_AND_KILL" : "KILL_ONLY (injector file preserved)")
                        : "CONTAINMENT_INCOMPLETE",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. Quarantined={quarantinedInfo}. InjectorQuarantined={injectorQuarantined}. TargetPID={targetPid}. DllContainment={dllContainmentInfo}. InjectorContainment={JsonSerializer.Serialize(injectorContainment)}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await LogResponseAsync(execution, responseLog);
                TryWriteWindowsEventLog(detection, responseLog.ActionTaken, responseLog.Reason);
                NotifyReinfectionCorrelator(detection, execution);
            }
            else if (shouldRaiseVpnShield)
            {
                // v2.6.0: Confirmed network tamper -> raise a protective userland VPN tunnel,
                // clean the network, and drop the tunnel once verified clean (fail-safe: the
                // tunnel stays up if the path cannot be verified clean). Fire-and-forget: the
                // engine runs its own clean-and-verify loop and never throws to this path.
                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                if (_vpnShieldEngine != null)
                {
                    var shieldDetection = detection;
                    _ = _vpnShieldEngine.RaiseShieldAsync(shieldDetection, CancellationToken.None);
                    execution.Add("VpnShield", "network", ResponseExecutionStatus.Attempted,
                        "Shield remediation scheduled; final tunnel/network state is not verified by this response.");
                }

                if (_vpnShieldEngine == null)
                    execution.Add("VpnShield", "network", ResponseExecutionStatus.Refused, "VPN shield executor is unavailable.");
                var shieldLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "VPN_SHIELD",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await LogResponseAsync(execution, shieldLog);
                TryWriteWindowsEventLog(detection, shieldLog.ActionTaken, shieldLog.Reason);
            }
            else if (shouldIsolateNetwork)
            {
                // v1.6.1: rate-limit isolate storms (decoy C2 / domain-fronting noise)
                if (!TryConsumeIsolateBudget())
                {
                    stopwatch.Stop();
                    _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                    await LogResponseAsync(execution, new ResponseEvent
                    {
                        ProcessId = detection.ProcessId,
                        ProcessName = detection.ProcessName,
                        ActionTaken = "LOG",
                        Reason = $"Triggered by rule: {detection.RuleName}. NetworkIsolate rate-limited (MaxNetworkIsolatesPerMinute).",
                        ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                    });
                    return;
                }

                // Network-level threat: block suspicious IPs extracted from evidence metadata
                var targetIp = detection.Metadata!.GetValueOrDefault("TargetIP", "");
                if (!string.IsNullOrEmpty(targetIp))
                {
                    // Validate IP before creating firewall rules
                    // v1.8.1 RT-NEW-3: never firewall-block private/LAN/gateway (decoy beaconing)
                    if (!System.Net.IPAddress.TryParse(targetIp, out var parsedIp) ||
                        System.Net.IPAddress.IsLoopback(parsedIp) ||
                        targetIp == "0.0.0.0" || targetIp == "255.255.255.255" ||
                        SecurityValidation.IsPrivateIpAddress(targetIp) ||
                        IsMulticastOrUnspecified(parsedIp) ||
                        IsLikelyCdnOrPublicResolver(parsedIp))
                    {
                        // Skip invalid/loopback/private/broadcast/CDN-or-resolver IPs (collateral)
                    }
                    else
                    {
                        execution.Effects.Add(IsolateNetworkTarget(targetIp, detection.RuleName));
                        // v1.8.1: restore ARP entry purge (lost in LOLBin-free rewrite).
                        // Was `arp -d` shell-out (v5.9.0); now DeleteIpNetEntry P/Invoke only.
                        execution.Effects.Add(FlushArpEntry(targetIp));
                        execution.Effects.Add(FlushDnsCache());
                    }
                }

                if (!execution.Effects.Any(e => e.Action == "FirewallRules"))
                    execution.Add("FirewallRules", targetIp, ResponseExecutionStatus.Refused, "Target is absent, invalid or protected from isolation.");

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "NETWORK_ISOLATE",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. Target={targetIp}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await LogResponseAsync(execution, responseLog);
                TryWriteWindowsEventLog(detection, responseLog.ActionTaken, responseLog.Reason);
            }
            else if (shouldRemoveRegistryEntry)
            {
                var hive = detection.Metadata!.GetValueOrDefault("Hive", "HKLM");
                var keyPath = detection.Metadata!.GetValueOrDefault("KeyPath", "");
                var valueName = detection.Metadata!.GetValueOrDefault("ValueName", "");
                var subKey = detection.Metadata!.GetValueOrDefault("SubKey", "");
                var removed = false;
                var removalLog = "";

                try
                {
                    if (!string.IsNullOrEmpty(valueName) && !string.IsNullOrEmpty(keyPath))
                    {
                        // Remove a specific value from a key
                        var regHive = hive switch
                        {
                            "HKCU" => Microsoft.Win32.Registry.CurrentUser,
                            "HKCR" => Microsoft.Win32.Registry.ClassesRoot,
                            "HKLM" => Microsoft.Win32.Registry.LocalMachine,
                            _ => throw new ArgumentException("Unsupported registry hive.")
                        };
                        using var key = regHive.OpenSubKey(keyPath, writable: true);
                        if (key != null)
                        {
                            key.DeleteValue(valueName, throwOnMissingValue: false);
                            removed = !key.GetValueNames().Contains(valueName, StringComparer.OrdinalIgnoreCase);
                            removalLog = $"Verified absent value '{valueName}' from {hive}\\{keyPath}";
                        }
                    }
                    else if (!string.IsNullOrEmpty(subKey) && keyPath.Contains("Services"))
                    {
                        // Remove a service subkey
                        using var servicesKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath, writable: true);
                        if (servicesKey != null)
                        {
                            servicesKey.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
                            using var remaining = servicesKey.OpenSubKey(subKey);
                            removed = remaining == null;
                            removalLog = $"Verified absent service subkey '{subKey}' from {hive}\\{keyPath}";
                        }
                    }
                    else if (!string.IsNullOrEmpty(keyPath) && keyPath.Contains("CLSID"))
                    {
                        // Remove a CLSID subkey tree
                        using var clsidKey = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(keyPath, writable: true);
                        if (clsidKey != null)
                        {
                            using var parent = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey("CLSID", writable: true);
                            if (parent != null)
                            {
                                var clsid = detection.Metadata!.GetValueOrDefault("CLSID", "");
                                if (!string.IsNullOrEmpty(clsid))
                                {
                                    parent.DeleteSubKeyTree(clsid, throwOnMissingSubKey: false);
                                    using var remaining = parent.OpenSubKey(clsid);
                                    removed = remaining == null;
                                    removalLog = $"Verified absent CLSID '{clsid}' from HKCR\\CLSID";
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    removalLog = $"Failed to remove registry entry: {ex.Message}";
                }

                execution.Add("RegistryRemoval", hive + "\\" + keyPath,
                    removed ? ResponseExecutionStatus.Verified : ResponseExecutionStatus.Failed,
                    string.IsNullOrEmpty(removalLog) ? "Registry target was not removed or could not be verified." : removalLog);

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = removed ? "REMOVE_REGISTRY_ENTRY" : "REMOVE_REGISTRY_ENTRY_FAILED",
                    Reason = $"Triggered by rule: {detection.RuleName}. {reason}. {removalLog}",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await LogResponseAsync(execution, responseLog);
                TryWriteWindowsEventLog(detection, responseLog.ActionTaken, responseLog.Reason);
            }
            else if (shouldKill && detection.ProcessId > 4)
            {
                // v2.8.4: Isolation-environment containment runs alongside the process kill when a
                // chain-confirmed terminal carries a Docker/VM origin. Fire-and-forget delegation to
                // the (now wired) IsolationResponseEngine - the offending process is still killed
                // below. This closes the dead-code gap for HandleDockerThreatAsync/HandleVmThreatAsync.
                string isolationContainmentNote = "";
                if (shouldContainDocker && _isolationResponse != null &&
                    detection.Metadata != null &&
                    detection.Metadata.TryGetValue("ContainerId", out var cid))
                {
                    try
                    {
                        await _isolationResponse.HandleDockerThreatAsync(cid);
                        execution.Add("DockerContainment", cid, ResponseExecutionStatus.Attempted, "Legacy executor returned without a verifiable container-state receipt.");
                    }
                    catch (Exception ex) { execution.Add("DockerContainment", cid, ResponseExecutionStatus.Failed, ex.Message); }
                    isolationContainmentNote = $". Docker containment (container={cid})";
                }
                else if (shouldContainVm && _isolationResponse != null &&
                         detection.Metadata != null &&
                         detection.Metadata.TryGetValue("VmHostPid", out var vp) &&
                         int.TryParse(vp, out var vmPid) && vmPid > 4)
                {
                    var vmName = detection.Metadata.TryGetValue("VmName", out var vn) ? vn : "";
                    try
                    {
                        await _isolationResponse.HandleVmThreatAsync(vmPid, vmName);
                        execution.Add("VmContainment", vmPid.ToString(), ResponseExecutionStatus.Attempted, "Legacy executor returned without a verifiable VM-state receipt.");
                    }
                    catch (Exception ex) { execution.Add("VmContainment", vmPid.ToString(), ResponseExecutionStatus.Failed, ex.Message); }
                    isolationContainmentNote = $". VM containment (vmHostPid={vmPid})";
                }

                if ((shouldContainDocker || shouldContainVm) && _isolationResponse == null)
                    execution.Add("EnvironmentContainment", "isolation", ResponseExecutionStatus.Refused, "Isolation executor unavailable.");

                // v1.6.0: rate-limit kill storms
                if (!TryConsumeKillBudget())
                {
                    stopwatch.Stop();
                    _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                    await LogResponseAsync(execution, new ResponseEvent
                    {
                        ProcessId = detection.ProcessId,
                        ProcessName = detection.ProcessName,
                        ActionTaken = "LOG",
                        Reason = $"Triggered by rule: {detection.RuleName}. Kill rate-limited (MaxKillsPerMinute).",
                        ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                    });
                    return;
                }

                // Collect forensic evidence before killing
                try { if (_incidentResponse != null) _ = _incidentResponse.CollectEvidenceAsync(detection); } catch { }

                var reasonText = $"Triggered by rule: {detection.RuleName}. {reason}{isolationContainmentNote}";
                if (_chainTracer != null)
                {
                    var traceResult = await _chainTracer.TraceAndRespondAsync(detection);
                    foreach (var tree in traceResult.ProcessContainments) execution.AddProcessTree(tree);
                    execution.Effects.AddRange(traceResult.AdditionalEffects);
                    if (!traceResult.Success)
                        execution.Add("ChainTrace", detection.ProcessId.ToString(), ResponseExecutionStatus.Failed,
                            traceResult.ErrorMessage ?? "Chain tracing did not complete.");
                    if (traceResult.ProcessContainments.Count == 0)
                        execution.Add("ProcessTree", detection.ProcessId.ToString(), ResponseExecutionStatus.Refused, "Chain tracing did not verify process containment.");
                    if (traceResult.Success)
                    {
                        if (traceResult.AttackRoot != null)
                        {
                            reasonText += $". Root source of attack: {traceResult.AttackRoot.ProcessName} (PID {traceResult.AttackRoot.ProcessId}, Path: '{traceResult.AttackRoot.ImagePath ?? "unknown"}')";
                        }
                        if (traceResult.QuarantinedFiles.Count > 0)
                        {
                            var files = string.Join(", ", traceResult.QuarantinedFiles.Select(f => $"{f.ProcessName} ('{f.OriginalPath}')"));
                            reasonText += $". Quarantined source files: {files}";
                        }
                    }
                }
                else
                {
                    execution.AddProcessTree(HardeningModule.SafeKillProcessTree(detection.ProcessId));
                }

                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "KILL",
                    Reason = reasonText,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await LogResponseAsync(execution, responseLog);
                TryWriteWindowsEventLog(detection, responseLog.ActionTaken, responseLog.Reason);
                NotifyReinfectionCorrelator(detection, execution);
            }
            else if (shouldDismountVolume)
            {
                // v2.8.4: Isolation-environment containment. A chain-confirmed terminal whose
                // originating process runs from a mounted ISO/disk image: kill the process tree,
                // dismount the image, and delete the backing .iso. Delegated to the (now wired)
                // IsolationResponseEngine so the injection-safe Dismount-DiskImage path is reused.
                // Rate-limited on the same kill budget as any other kill (chain-confirmed bypasses).
                await HandleIsoDismountAsync(detection, reason, stopwatch, execution);
                NotifyReinfectionCorrelator(detection, execution);
            }
            else
            {
                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                var responseLog = new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "LOG",
                    Reason = reason,
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                };
                await LogResponseAsync(execution, responseLog);
                // LogOnly never writes Windows Event Log (CriticalOnly trail)
            }
        }

        /// <summary>
        /// v2.8.4: Executes isolation-environment (mounted ISO) containment for a chain-confirmed
        /// terminal. Resolves the backing .iso for the offending PID and delegates to the wired
        /// <see cref="IsolationResponseEngine"/>. If the origin cannot be confirmed as a mounted
        /// ISO, degrades to a plain process-tree kill (never dismounts/deletes an unrelated volume).
        /// A missing IsolationResponseEngine (e.g. Agent-side) also degrades to kill-only.
        /// </summary>
        private async Task HandleIsoDismountAsync(
            DetectionEvent detection, string reason, Stopwatch stopwatch, ResponseExecutionResult execution)
        {
            if (!TryConsumeKillBudget())
            {
                stopwatch.Stop();
                _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);
                await LogResponseAsync(execution, new ResponseEvent
                {
                    ProcessId = detection.ProcessId,
                    ProcessName = detection.ProcessName,
                    ActionTaken = "LOG",
                    Reason = $"Triggered by rule: {detection.RuleName}. DismountVolume rate-limited (MaxKillsPerMinute).",
                    ExecutionTimeMs = stopwatch.ElapsedMilliseconds
                });
                return;
            }

            // Prefer an explicit backing-image path supplied by the emitting monitor; else resolve
            // it from the offending PID. Both are non-attacker-controllable anchors (the OS records
            // the mounted image path and the process image path at creation).
            string? isoPath = detection.Metadata != null &&
                              detection.Metadata.TryGetValue("IsoPath", out var mp) && !string.IsNullOrEmpty(mp)
                ? mp
                : IsoOriginResolver.ResolveBackingImageForProcess(detection.ProcessId);

            string actionTaken;
            if (_isolationResponse != null && !string.IsNullOrEmpty(isoPath) && detection.ProcessId > 4)
            {
                await _isolationResponse.HandleIsoThreatAsync(detection.ProcessId, isoPath!);
                actionTaken = "ISO_KILL_DISMOUNT_DELETE";
                execution.Add("IsoContainment", isoPath!, ResponseExecutionStatus.Attempted,
                    "Legacy executor returned; dismount and complete process-tree exit were not independently verified.");
                reason += ". ISO containment attempted; verification remains outstanding";
            }
            else
            {
                // Could not confirm an ISO origin - do NOT dismount/delete anything. Fall back to
                // a plain process-tree kill so the confirmed terminal is still contained.
                if (detection.ProcessId > 4)
                    execution.AddProcessTree(HardeningModule.SafeKillProcessTree(detection.ProcessId));
                execution.Add("IsoContainment", isoPath ?? "unresolved", ResponseExecutionStatus.Refused,
                    "ISO origin or executor unavailable; only process containment was attempted.");
                actionTaken = "KILL";
                reason += string.IsNullOrEmpty(isoPath)
                    ? ". ISO origin unresolved; process containment attempted, no volume mutation"
                    : ". IsolationResponseEngine unavailable; process containment attempted";
            }

            stopwatch.Stop();
            _metrics.RecordResponse(stopwatch.ElapsedMilliseconds);

            var responseLog = new ResponseEvent
            {
                ProcessId = detection.ProcessId,
                ProcessName = detection.ProcessName,
                ActionTaken = actionTaken,
                Reason = $"Triggered by rule: {detection.RuleName}. {reason}",
                ExecutionTimeMs = stopwatch.ElapsedMilliseconds
            };
            await LogResponseAsync(execution, responseLog);
            TryWriteWindowsEventLog(detection, responseLog.ActionTaken, responseLog.Reason);
        }

        private void NotifyReinfectionCorrelator(DetectionEvent detection, ResponseExecutionResult execution)
        {
            try
            {
                if (_reinfectionCorrelator == null || !execution.HasVerifiedProcessExit(detection.ProcessId)) return;
                var hash = detection.Metadata?.GetValueOrDefault("SHA256", "");
                if (string.IsNullOrEmpty(hash))
                {
                    // Try to compute hash from process image
                    try
                    {
                        using var proc = Process.GetProcessById(detection.ProcessId);
                        var path = SecurityValidation.GetProcessImagePath(detection.ProcessId);
                        if (!string.IsNullOrEmpty(path) && File.Exists(path))
                        {
                            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                FileShare.ReadWrite | FileShare.Delete);
                            hash = ConvertHex.ToHexString(System.Security.Cryptography.Sha256Net48.HashData(fs)).ToLowerInvariant();
                        }
                    }
                    catch { }
                }
                if (!string.IsNullOrEmpty(hash))
                {
                    _reinfectionCorrelator.RegisterKilledHash(hash!, detection.ProcessName ?? "unknown", detection.ProcessName ?? "unknown");
                }
            }
            catch { }
        }

    }
}
