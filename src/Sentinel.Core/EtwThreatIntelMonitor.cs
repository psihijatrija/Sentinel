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
    /// Thread-start and unbacked RWX injection scanner.
    /// Uses <see cref="NativeProcessMemory"/> (dynamic APIs). Skips game/anti-cheat paths only.
    ///
    /// KNOWN LIMITATION (v2.0.4 LOW-4): Process hollowing where an attacker overwrites the
    /// .text section of a legitimate signed binary without changing memory type (remains MEM_IMAGE)
    /// will NOT be detected by unbacked-RWX scanning. The Authenticode check on-disk will pass
    /// since the file is genuine. Detection relies on behavioral signals from other monitors
    /// (credential access, C2 beaconing, etc.) that feed into the correlation engine.
    /// Partial mitigation: memory-mapped section hash comparison (future work).
    /// </summary>
    public sealed class EtwThreatIntelMonitor : IMonitor, IDisposable
    {
        public string Name => "EtwThreatIntelMonitor";

        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ILogger<EtwThreatIntelMonitor> _logger;
        private readonly ContextBus? _contextBus;
        private readonly DllUnloadEngine? _dllUnload;
        private CancellationTokenSource? _cts;
        private Task? _monitorTask;

        private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);

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
            _dllUnload = dllUnloadEngine;
        }

        public Task StartAsync(CancellationToken ct)
        {
            _logger.LogInformation(
                "[EtwThreatIntelMonitor] Started - thread/RWX injection scan (game paths skipped, APIs dynamic)");
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
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch { }
                try { await Task.Delay(TimeSpan.FromSeconds(8), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        private async Task ScanSuspectPidsAsync(CancellationToken ct)
        {
            foreach (var pid in InjectionSuspectBoard.Snapshot())
            {
                if (ct.IsCancellationRequested) break;
                if (pid <= 4) continue;
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    ScanOneProcessStack(proc);
                    await ScanOneProcessThreadsAsync(proc, ct).ConfigureAwait(false);
                    if (IsHighValueTarget(proc.ProcessName))
                        await ScanOneProcessRwxAsync(proc, ct).ConfigureAwait(false);
                }
                catch { }
            }
        }

        /// <summary>
        /// Off-thread call-stack analysis. Consumes the frames stashed by the ETW dispatcher
        /// (captured via ETW-TI STACKWALK) and flags a return frame that resolves to committed,
        /// executable, non-image (unbacked) memory outside every loaded module. Emits a
        /// Tier1Behavioral observe-until-chain signal; correlation decides any terminal action.
        /// Fail-closed: any inspection failure yields no signal. Runs on the scan loop thread,
        /// never on the ETW callback thread.
        /// </summary>
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
                            "Observe-until-chain: correlation decides terminal action.",
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

        private async Task ScanOneProcessRwxAsync(Process proc, CancellationToken ct)
        {
            if (ct.IsCancellationRequested) return;
            var name = proc.ProcessName;
            var imagePath = SecurityValidation.GetProcessImagePath(proc.Id);
            if (!NativeProcessMemory.CanInspect(proc.Id, imagePath))
                return;
            if (_alertedPids.TryGetValue(proc.Id, out var last) &&
                DateTimeOffset.UtcNow - last < AlertCooldown)
                return;

            uint access = NativeProcessMemory.PROCESS_QUERY_INFORMATION | NativeProcessMemory.PROCESS_VM_READ;
            IntPtr h = NativeProcessMemory.OpenRemoteHandle(access, proc.Id);
            if (h == IntPtr.Zero) return;

            try
            {
                var rwx = FindUnbackedRwx(h, proc.Id);
                if (rwx.Count == 0) return;

                var mzRegions = new List<(long Address, long Size)>();
                foreach (var region in rwx)
                {
                    if (NativeProcessMemory.LooksLikeMzPe(proc.Id, new IntPtr(region.Address)))
                        mzRegions.Add(region);
                }
                if (mzRegions.Count == 0)
                    return;

                if (_dllUnload != null)
                    await _dllUnload.CheckAndUnloadAsync(proc.Id, name);

                _alertedPids[proc.Id] = DateTimeOffset.UtcNow;
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Threat Intel: Remote Memory Injection (ALLOCVM_REMOTE + PROTECTVM_REMOTE)",
                    Evidence = $"Process '{name}' (PID {proc.Id}) has {rwx.Count} unbacked RWX region(s) with injected MZ header, " +
                               $"total {rwx.Sum(r => r.Size):N0} bytes.",
                    Reasoning = "Unbacked RWX with MZ header indicates remote memory injection / hollowed payload (T1055).",
                    Confidence = 0.95,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    ProcessName = name,
                    ProcessId = proc.Id,
                    SignalType = SignalType.ProcessInjection,
                    Family = TerminalFamily.Injection,
                    Metadata = new Dictionary<string, string>
                    {
                        ["RwxRegionCount"] = rwx.Count.ToString(),
                        ["TotalRwxSize"] = rwx.Sum(r => r.Size).ToString(),
                        ["ImagePath"] = imagePath ?? ""
                    }
                });
            }
            finally
            {
                NativeProcessMemory.CloseHandle(h);
            }
        }

        private static List<(long Address, long Size)> FindUnbackedRwx(IntPtr hProcess, int pid)
        {
            var results = new List<(long, long)>();
            var ranges = MappedModuleCache.Get(pid);
            if (ranges.Count == 0)
            {
                NativeProcessMemory.EnumModules(pid);
                ranges = MappedModuleCache.Get(pid);
            }

            IntPtr address = IntPtr.Zero;
            int scanned = 0;
            while (scanned < 10000)
            {
                scanned++;
                if (NativeProcessMemory.QueryRemoteRegion(hProcess, address, out var mbi) == 0) break;

                if (mbi.State == NativeProcessMemory.MEM_COMMIT &&
                    mbi.Type != NativeProcessMemory.MEM_IMAGE &&
                    (mbi.Protect == NativeProcessMemory.PAGE_EXECUTE_READWRITE ||
                     mbi.Protect == NativeProcessMemory.PAGE_EXECUTE_WRITECOPY))
                {
                    ulong baseAddr = (ulong)mbi.BaseAddress;
                    long size = (long)mbi.RegionSize;
                    bool inside = ranges.Any(r => baseAddr >= r.Base && baseAddr < r.End);
                    if (!inside && size > 0 && size < 100_000_000)
                        results.Add(((long)baseAddr, size));
                }

                ulong next = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
                if (next <= (ulong)address) break;
                address = (IntPtr)next;
            }

            return results;
        }

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

        private static bool IsHighValueTarget(string processName)
        {
            var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "svchost", "explorer", "RuntimeBroker", "dllhost",
                "spoolsv", "searchindexer", "taskhostw", "sihost",
                "lsass", "csrss", "winlogon", "wininit", "services",
                "conhost", "wmiprvse", "smartscreen", "backgroundTaskHost",
                "ceprkac", "msedgewebview2", "msedge", "chrome", "firefox",
                "brave", "discord"
            };
            return targets.Contains(processName);
        }
    }
}
