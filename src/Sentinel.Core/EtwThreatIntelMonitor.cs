using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Thread-start and private executable PE inspection.
    /// Uses <see cref="NativeProcessMemory"/> (dynamic APIs). Skips game/anti-cheat paths only.
    ///
    /// KNOWN LIMITATION (v2.0.4 LOW-4): Process hollowing where an attacker overwrites the
    /// .text section of a legitimate signed binary without changing memory type (remains MEM_IMAGE)
    /// will NOT be detected by unbacked-RWX scanning. The Authenticode check on-disk will pass
    /// since the file is genuine. Detection relies on behavioral signals from other monitors
    /// (credential access, C2 beaconing, etc.) that feed into the correlation engine.
    /// Partial mitigation: memory-mapped section hash comparison (future work).
    /// </summary>
    public sealed class EtwThreatIntelMonitor : IMonitor, IDisposable, ISensorProgressSource, IMonitorWorker
    {
        public string Name => "EtwThreatIntelMonitor";
        public SensorProgress Progress { get; } = new(TimeSpan.FromSeconds(30))
            { Scope = "Bounded recent-candidate scan cycles; gates and budgets can leave regions uninspected. An empty board does not prove protected Threat-Intelligence provider availability. See EtwSessionGuard." };
        public bool IsWorkerRunning => _monitorTask is { IsCompleted: false };

        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ILogger<EtwThreatIntelMonitor> _logger;
        private readonly ContextBus? _contextBus;
        private CancellationTokenSource? _cts;
        private Task? _monitorTask;

        private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();
        private readonly ConcurrentDictionary<(int Pid, long Created), DateTimeOffset> _payloadAlertedPids = new();
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan PayloadEvidenceCooldown = TimeSpan.FromSeconds(8);
        private int _candidateCursor;

        public EtwThreatIntelMonitor(
            DetectionEngine detectionEngine,
            TelemetryFusionEngine fusionEngine,
            ILogger<EtwThreatIntelMonitor> logger,
            ContextBus? contextBus = null,
            DllUnloadEngine? dllUnloadEngine = null)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _logger = logger;
            _contextBus = contextBus;
        }

        public Task StartAsync(CancellationToken ct)
        {
            _logger.LogInformation(
                "[EtwThreatIntelMonitor] Started - thread/private-PE injection scan (game paths skipped, APIs dynamic)");
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _monitorTask = Task.Run(() => RunScanLoopAsync(_cts.Token));
            return Task.CompletedTask;
        }

        public async Task StopAsync()
        {
            _logger.LogInformation("[EtwThreatIntelMonitor] Stopping...");
            _cts?.Cancel();
            if (_monitorTask != null)
            {
                try { await _monitorTask; } catch { /* cancelled */ }
            }
        }

        public void Dispose() => _cts?.Dispose();

        private async Task RunScanLoopAsync(CancellationToken ct)
        {
            // Only PIDs that just did remote TI - not a full-system 5s walk
            // (that was the LatencyMon hard-fault source).
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanSuspectPidsAsync(ct).ConfigureAwait(false);
                    Progress.Succeeded();
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex)
                {
                    Progress.Failed(ex.Message);
                    _logger.LogWarning(ex, "Local injection scan cycle failed");
                }
                try { await Task.Delay(TimeSpan.FromSeconds(8), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        private async Task ScanSuspectPidsAsync(CancellationToken ct)
        {
            var candidates = InjectionSuspectBoard.Snapshot();
            var budget = Stopwatch.StartNew();
            for (int inspected = 0; inspected < Math.Min(candidates.Length, 16) && budget.ElapsedMilliseconds < 1000; inspected++)
            {
                var pid = candidates[_candidateCursor % candidates.Length];
                _candidateCursor = (_candidateCursor + 1) % candidates.Length;
                if (ct.IsCancellationRequested) break;
                if (pid <= 4) continue;
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    // A suppressed browser/API event supplies PE inspection only, not
                    // new authority for legacy compact-page/thread heuristics.
                    if (!InjectionSuspectBoard.IsPayloadOnly(pid))
                    {
                        ScanOneProcessStack(proc);
                        await ScanOneProcessThreadsAsync(proc, ct).ConfigureAwait(false);
                    }
                    await ScanOneProcessPayloadAsync(proc, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex) { _logger.LogDebug(ex, "Injection candidate PID {Pid} could not be inspected", pid); }
            }
        }

        private void ScanOneProcessStack(Process proc)
        {
            int pid = proc.Id;
            var frames = InjectionSuspectBoard.TakeStack(pid);
            if (frames == null || frames.Length == 0) return;

            var name = proc.ProcessName;
            var imagePath = SecurityValidation.GetProcessImagePath(pid);
            if (!NativeProcessMemory.CanInspect(pid, imagePath))
                return;
            if (_alertedPids.TryGetValue(pid, out var last) &&
                DateTimeOffset.UtcNow - last < AlertCooldown)
                return;

            var ranges = MappedModuleCache.Get(pid);
            if (ranges.Count == 0)
            {
                NativeProcessMemory.EnumModules(pid);
                ranges = MappedModuleCache.Get(pid);
            }
            if (ranges.Count == 0) return;

            IntPtr h = NativeProcessMemory.OpenRemoteHandle(
                NativeProcessMemory.PROCESS_QUERY_INFORMATION | NativeProcessMemory.PROCESS_VM_READ, pid);
            if (h == IntPtr.Zero) return;

            ulong unbackedAddr = 0;
            try
            {
                foreach (ulong frame in frames)
                {
                    if (frame == 0) continue;
                    bool inModule = false;
                    foreach (var r in ranges)
                    {
                        if (frame >= r.Base && frame < r.End) { inModule = true; break; }
                    }
                    if (inModule) continue;

                    if (NativeProcessMemory.QueryRemoteRegion(h, new IntPtr(unchecked((long)frame)), out var mbi) == 0)
                        continue;
                    if (mbi.State != NativeProcessMemory.MEM_COMMIT) continue;
                    if (mbi.Type == NativeProcessMemory.MEM_IMAGE) continue;
                    if (!NativeProcessMemory.IsExecutableProtection(mbi.Protect)) continue;

                    unbackedAddr = frame;
                    break;
                }
            }
            finally
            {
                NativeProcessMemory.CloseHandle(h);
            }

            if (unbackedAddr == 0) return;

            _alertedPids[pid] = DateTimeOffset.UtcNow;
            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Evasion: Unbacked Return Frame at Sensitive Syscall",
                Evidence = $"Process '{name}' (PID {pid}) issued a Threat-Intelligence API with a " +
                           $"call-stack return frame at 0x{unbackedAddr:X} in committed, executable, " +
                           $"non-image memory ({frames.Length} frame(s) captured).",
                Reasoning = "A return address outside every loaded module, in unbacked executable memory, " +
                            "indicates injected/manually-mapped code or call-stack spoofing (T1055). " +
                            "response authorization: correlation decides terminal action.",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = name,
                ProcessId = pid,
                SignalType = SignalType.ProcessInjection,
                Family = TerminalFamily.Injection,
                Metadata = new Dictionary<string, string>
                {
                    ["UnbackedReturnAddress"] = $"0x{unbackedAddr:X}",
                    ["StackFrameCount"] = frames.Length.ToString(),
                    ["ImagePath"] = imagePath ?? ""
                }
            });

            _contextBus?.Publish(new InjectionSignal
            {
                ProcessId = pid,
                ProcessName = name,
                SourceMonitor = "EtwThreatIntelMonitor.StackWalk",
                ThreadId = 0,
                StartAddress = $"0x{unbackedAddr:X}",
                ImagePath = imagePath ?? ""
            });
        }

        private async Task ScanOneProcessThreadsAsync(Process proc, CancellationToken ct)
        {
            var name = proc.ProcessName;
            var imagePath = SecurityValidation.GetProcessImagePath(proc.Id);
            if (!NativeProcessMemory.CanInspect(proc.Id, imagePath))
                return;
            if (_alertedPids.TryGetValue(proc.Id, out var last) &&
                DateTimeOffset.UtcNow - last < AlertCooldown)
                return;

            var ranges = MappedModuleCache.Get(proc.Id);
            if (ranges.Count == 0)
            {
                NativeProcessMemory.EnumModules(proc.Id);
                ranges = MappedModuleCache.Get(proc.Id);
            }
            if (ranges.Count == 0) return;

            foreach (ProcessThread thread in proc.Threads)
            {
                if (ct.IsCancellationRequested) break;
                IntPtr start;
                try { start = thread.StartAddress; }
                catch { continue; }
                if (start == IntPtr.Zero) continue;

                ulong sa = (ulong)start;
                bool inside = ranges.Any(r => sa >= r.Base && sa < r.End);
                if (inside) continue;
                if (!LooksLikeUnbackedShellcode(proc.Id, start))
                    continue;

                _alertedPids[proc.Id] = DateTimeOffset.UtcNow;
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Evasion: Unmapped Thread Start Address",
                    Evidence = $"Thread {thread.Id} in '{name}' (PID {proc.Id}) started at unmapped 0x{start:X}.",
                    Reasoning = "Thread entrypoint outside any loaded module indicates shellcode injection / thread hijacking.",
                    Confidence = 0.90,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    ProcessName = name,
                    ProcessId = proc.Id,
                    SignalType = SignalType.AntiTamper,
                    Family = TerminalFamily.Evasion,
                    Metadata = new Dictionary<string, string>
                    {
                        ["ThreadId"] = thread.Id.ToString(),
                        ["StartAddress"] = $"0x{start:X}",
                        ["ImagePath"] = imagePath ?? ""
                    }
                });

                _contextBus?.Publish(new InjectionSignal
                {
                    ProcessId = proc.Id,
                    ProcessName = name,
                    SourceMonitor = "EtwThreatIntelMonitor",
                    ThreadId = thread.Id,
                    StartAddress = $"0x{start:X}",
                    ImagePath = imagePath ?? ""
                });
                break;
            }
        }

        private async Task ScanOneProcessPayloadAsync(Process proc, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var imagePath = SecurityValidation.GetProcessImagePath(proc.Id);
            if (!NativeProcessMemory.CanInspect(proc.Id, imagePath)) return;
            uint access = NativeProcessMemory.PROCESS_QUERY_INFORMATION | NativeProcessMemory.PROCESS_VM_READ;
            IntPtr handle = NativeProcessMemory.OpenRemoteHandle(access, proc.Id);
            if (handle == IntPtr.Zero) return;
            try
            {
                // Pin evidence to the handle being read, not just a recycled PID.
                if (!NativeProcessMemory.TryGetCreationTime(handle, out long created) ||
                    created != proc.StartTime.ToUniversalTime().ToFileTimeUtc()) return;
                var key = (proc.Id, created);
                if (_payloadAlertedPids.TryGetValue(key, out var last) &&
                    DateTimeOffset.UtcNow - last < PayloadEvidenceCooldown) return;

                var payloads = UnbackedPeScanner.Scan(address =>
                {
                    var pointer = new IntPtr(unchecked((long)address));
                    return NativeProcessMemory.QueryRemoteRegion(handle, pointer, out var region) == 0
                        ? (NativeProcessMemory.MEMORY_BASIC_INFORMATION?)null : region;
                }, address =>
                {
                    var header = new byte[4096];
                    if (!NativeProcessMemory.CopyRemote(handle, new IntPtr(unchecked((long)address)), header, out int count)) return null;
                    if (count != header.Length) Array.Resize(ref header, count);
                    return header;
                }, ct);
                if (payloads.Count == 0) return;
                if (_payloadAlertedPids.Count >= 4096) _payloadAlertedPids.Clear();
                _payloadAlertedPids[key] = DateTimeOffset.UtcNow;
                await _detectionEngine.EmitAsync(CreatePayloadObservation(proc.Id, proc.ProcessName,
                    imagePath ?? "", created, payloads, DateTime.UtcNow)).ConfigureAwait(false);
            }
            finally { NativeProcessMemory.CloseHandle(handle); }
        }

        internal static DetectionEvent CreatePayloadObservation(int pid, string name, string imagePath,
            long created, IReadOnlyList<UnbackedPeScanner.Payload> payloads, DateTime timestamp) => new()
        {
            RuleName = "Memory Payload: Unbacked Executable PE",
            ProcessId = pid, ProcessName = name, Timestamp = timestamp,
            Tier = DetectionTier.Tier2Indicator, AuthorizedResponse = ResponseAction.LogOnly,
            SignalType = SignalType.Generic, Confidence = 0.95,
            Evidence = $"Read-only inspection found {payloads.Count} private executable PE allocation(s) in PID {pid}; allocation addresses are in metadata.",
            Reasoning = "PE structure was found at the allocation base of private executable code, including RX pages. " +
                "This alone does not prove a malicious loader or authorize response. An independent, lifetime-matched credential-store read is required by the dedicated theft chain.",
            Metadata = new Dictionary<string, string>
            {
                ["UnbackedPePayload"] = "true", ["PayloadEvidenceSource"] = "PrivateExecutableAllocation",
                ["ProcessCreationTime"] = created.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["ImagePath"] = imagePath,
                ["PayloadAllocations"] = string.Join(",", payloads.Select(p => $"0x{p.Allocation:X}")),
                ["ExecutablePages"] = string.Join(",", payloads.Select(p => $"0x{p.ExecutablePage:X}:0x{p.Protection:X}"))
            }
        };

        /// <summary>
        /// True for a compact private executable page (classic shellcode).
        /// Large JIT / Chromium / OBS regions are not a hit.
        /// </summary>
        internal static bool IsCompactPrivateExecutable(uint state, uint type, uint protect, long regionSize)
        {
            if (state != NativeProcessMemory.MEM_COMMIT) return false;
            if (type == NativeProcessMemory.MEM_IMAGE) return false;
            if (!NativeProcessMemory.IsExecutableProtection(protect)) return false;
            return regionSize > 0 && regionSize <= 16 * 1024;
        }

        internal static bool LooksLikeUnbackedShellcode(int pid, IntPtr start)
        {
            if (start == IntPtr.Zero || pid <= 4) return false;
            uint access = NativeProcessMemory.PROCESS_QUERY_INFORMATION | NativeProcessMemory.PROCESS_VM_READ;
            IntPtr h = NativeProcessMemory.OpenRemoteHandle(access, pid);
            if (h == IntPtr.Zero) return false;
            try
            {
                if (NativeProcessMemory.QueryRemoteRegion(h, start, out var mbi) == 0)
                    return false;
                return IsCompactPrivateExecutable(mbi.State, mbi.Type, mbi.Protect, (long)mbi.RegionSize);
            }
            finally
            {
                NativeProcessMemory.CloseHandle(h);
            }
        }

    }
}
