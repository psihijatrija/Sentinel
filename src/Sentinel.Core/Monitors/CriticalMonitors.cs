// Critical Monitor Group - self-protection monitors that restart indefinitely

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// On-disk ntdll integrity + remote Hell's Gate / indirect-syscall scan.
    /// Memory APIs resolved via <see cref="NativeProcessMemory"/> (not PE imports).
    /// Skips game/anti-cheat paths only - defenses stay armed for everything else.
    /// Hell's Gate requires a well-formed stub table (compact syscall+ret or a copied
    /// ntdll prologue) with 3+ distinct SSNs. Loose <c>0F 05</c> bytes in V8/Chromium
    /// JIT regions are not a hit - process-name skips are not used as a trust grant.
    /// </summary>
    public sealed class SyscallStubMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<SyscallStubMonitor> _logger;
        private byte[]? _baselineNtdllHash;
        private DateTime _ntdllStamp = DateTime.MinValue;
        private long _ntdllLength = -1;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<int, DateTimeOffset> _syscallAlertedPids = new();
        private static readonly TimeSpan SyscallAlertCooldown = TimeSpan.FromMinutes(5);

        public SyscallStubMonitor(DetectionEngine de, ILogger<SyscallStubMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SyscallStubMonitor] Started - ntdll integrity + Hell's Gate scan (game paths skipped)");
            var ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
            if (File.Exists(ntdllPath))
            {
                try
                {
                    var info = new FileInfo(ntdllPath);
                    _ntdllStamp = info.LastWriteTimeUtc;
                    _ntdllLength = info.Length;
                    using var fs = new FileStream(ntdllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    _baselineNtdllHash = System.Security.Cryptography.Sha256Net48.HashData(fs);
                }
                catch { /* access race */ }
            }

            int cycleCount = 0;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);

                    if (_baselineNtdllHash != null && File.Exists(ntdllPath))
                    {
                        // Re-hash only when the file stamp changes. Reading ntdll.dll from disk
                        // every 30s is a burst of hard pagefaults when the standby list dropped it.
                        var info = new FileInfo(ntdllPath);
                        if (info.LastWriteTimeUtc == _ntdllStamp && info.Length == _ntdllLength)
                        {
                            cycleCount++;
                            if (cycleCount % 2 == 0)
                                await ScanForIndirectSyscallPatternsAsync(ct);
                            continue;
                        }

                        byte[] currentHash;
                        using (var fs = new FileStream(ntdllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                        {
                            currentHash = System.Security.Cryptography.Sha256Net48.HashData(fs);
                        }
                        _ntdllStamp = info.LastWriteTimeUtc;
                        _ntdllLength = info.Length;
                        if (!currentHash.SequenceEqual(_baselineNtdllHash))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "ETW Tampering: ntdll.dll On-Disk Hash Changed",
                                Evidence = $"ntdll.dll hash changed from {ConvertHex.ToHexString(_baselineNtdllHash)} to {ConvertHex.ToHexString(currentHash)}",
                                Reasoning = "The on-disk ntdll.dll hash changed, which should never happen during normal operation.",
                                Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                            _baselineNtdllHash = currentHash;
                        }
                    }

                    cycleCount++;
                    if (cycleCount % 2 == 0)
                        await ScanForIndirectSyscallPatternsAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[SyscallStubMonitor] Error"); }
            }
        }

        private async Task ScanForIndirectSyscallPatternsAsync(CancellationToken ct)
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                if (proc.Id <= 4) { proc.Dispose(); continue; }

                try
                {
                    var name = proc.ProcessName;
                    var imagePath = SecurityValidation.GetProcessImagePath(proc.Id);
                    if (!NativeProcessMemory.CanInspect(proc.Id, imagePath))
                    {
                        proc.Dispose();
                        continue;
                    }

                    if (_syscallAlertedPids.TryGetValue(proc.Id, out var lastAlert) &&
                        DateTimeOffset.UtcNow - lastAlert < SyscallAlertCooldown)
                    {
                        proc.Dispose();
                        continue;
                    }

                    uint access = NativeProcessMemory.PROCESS_QUERY_INFORMATION | NativeProcessMemory.PROCESS_VM_READ;
                    IntPtr hProcess = NativeProcessMemory.OpenRemoteHandle(access, proc.Id);
                    if (hProcess == IntPtr.Zero) { proc.Dispose(); continue; }

                    try
                    {
                        var scan = ScanProcessForSyscallStubs(hProcess);
                        if (scan.IsHit)
                        {
                            _syscallAlertedPids[proc.Id] = DateTimeOffset.UtcNow;
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Evasion: Indirect Syscall / Hell's Gate Pattern Detected",
                                Evidence = $"Process '{name}' (PID {proc.Id}) contains {scan.WellFormedStubs} well-formed " +
                                           $"syscall stub(s) ({scan.DistinctSsns} distinct SSNs) in a small private executable " +
                                           "memory region. Pattern: mov r10,rcx; mov eax,SSN; syscall; ret - densely packed, " +
                                           "valid SSN range (0x0001-0x01FF), single private allocation.",
                                Reasoning = "A densely-packed table of compact syscall stubs with 3+ distinct valid SSNs in a " +
                                            "small private (VirtualAlloc'd) executable region indicates Hell's Gate / " +
                                            "SysWhispers-style EDR bypass (MITRE T1106, T1562.001). " +
                                            "JIT engines (V8, CLR) are excluded by region-size cap (64 KB), MEM_PRIVATE " +
                                            "requirement, stub density check, and SSN range validation.",
                                Confidence = 0.92,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                ProcessName = name,
                                ProcessId = proc.Id,
                                SignalType = SignalType.SecurityEvasion,
                                // Terminal Evasion: rule name matches "Indirect Syscall" / "Hell's Gate"
                                // Evasion fragments (kill-grade). Preserves current substring classification.
                                Family = TerminalFamily.Evasion,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["SyscallStubCount"] = scan.WellFormedStubs.ToString(),
                                    ["DistinctSsnCount"] = scan.DistinctSsns.ToString(),
                                    ["ImagePath"] = imagePath ?? "",
                                    ["Technique"] = "IndirectSyscall/HellsGate"
                                }
                            });
                        }
                    }
                    finally
                    {
                        NativeProcessMemory.CloseHandle(hProcess);
                        proc.Dispose();
                    }
                }
                catch
                {
                    try { proc.Dispose(); } catch { }
                }
            }
        }

        //  Hell's Gate structural constraints 
        // A real Hell's Gate / SysWhispers stub TABLE has all of these properties:
        //
        //   1. PRIVATE memory (MEM_PRIVATE = 0x20000): allocated with VirtualAlloc.
        //      Never MEM_IMAGE (DLL sections) or MEM_MAPPED (file-backed views).
        //      V8 JIT regions on some Chrome builds are MEM_MAPPED - this rejects them.
        //
        //   2. SMALL region: a full SysWhispers table for all ~500 syscalls is ~5 KB.
        //      Cap at 64 KB. V8/CLR/JVM JIT regions are 256 KB-4 MB - this rejects them.
        //
        //   3. DENSE packing: consecutive stubs are 11 or 21 bytes each. In a real table
        //      they are back-to-back with at most an alignment NOP between them (<= 48 bytes
        //      between stub starts). V8 JIT prologues are hundreds of bytes apart.
        //
        //   4. VALID SSN range: Windows syscall numbers are 0x0001-0x01FF (fewer than 512
        //      syscalls exist on all Windows versions). An immediate outside that range is
        //      a compiler constant or attacker garbage, not a real syscall number.
        //
        //   5. ALL stubs in ONE region: a deployed table is a single contiguous allocation.
        //      Counting stubs across separate regions allows 3 unrelated JIT prologues in
        //      3 different regions to combine into a false positive.
        private const long MaxHellsGateRegionBytes = 64 * 1024;  // 64 KB
        private const int  MaxStubSpacingBytes      = 48;         // packed: 11-byte stub + <=37 bytes padding
        private const int  MinValidSsn              = 0x0001;
        private const int  MaxValidSsn              = 0x01FF;
        private const uint MemPrivate               = 0x20000;

        private static HellsGateScanResult ScanProcessForSyscallStubs(IntPtr hProcess)
        {
            IntPtr address = IntPtr.Zero;
            int regionsScanned = 0;

            while (regionsScanned < 5000)
            {
                regionsScanned++;
                int bytesReturned = NativeProcessMemory.QueryRemoteRegion(hProcess, address, out var mbi);
                if (bytesReturned == 0) break;

                long regionSize = (long)mbi.RegionSize;

                // Constraint 1 + 2: committed, private, executable, small.
                if (mbi.State == NativeProcessMemory.MEM_COMMIT &&
                    mbi.Type  == MemPrivate &&
                    NativeProcessMemory.IsExecutableProtection(mbi.Protect) &&
                    regionSize > 0 && regionSize <= MaxHellsGateRegionBytes)
                {
                    int readSize = (int)regionSize;
                    var buffer   = new byte[readSize];
                    if (NativeProcessMemory.CopyRemote(hProcess, mbi.BaseAddress, buffer, out int bytesRead) &&
                        bytesRead > 16)
                    {
                        // Constraint 3 + 4: dense packing + valid SSN range, within ONE region.
                        var hits      = FindSyscallStubs(buffer, bytesRead);
                        var denseHits = FilterByDensity(hits, MaxStubSpacingBytes);
                        if (IsHellsGateEvidence(denseHits))
                            return new HellsGateScanResult(denseHits.Count, CountDistinctSsns(denseHits));
                    }
                }

                ulong nextAddr = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
                if (nextAddr <= (ulong)address) break;
                address = (IntPtr)nextAddr;
            }

            return new HellsGateScanResult(0, 0);
        }

        /// <summary>
        /// Returns the largest dense cluster of stubs where each consecutive pair of stub
        /// start offsets is within <paramref name="maxSpacing"/> bytes.
        /// Requires >= 3 stubs in the cluster. Eliminates scattered JIT prologues.
        /// </summary>
        /// <summary>Test hook - exposes FilterByDensity for unit tests.</summary>
        internal static List<SyscallStubHit> FilterByDensityPublic(List<SyscallStubHit> hits, int maxSpacing)
            => FilterByDensity(hits, maxSpacing);

        private static List<SyscallStubHit> FilterByDensity(List<SyscallStubHit> hits, int maxSpacing)
        {
            if (hits.Count < 3) return new List<SyscallStubHit>();

            int bestStart = 0, bestLen = 1;
            int curStart  = 0, curLen  = 1;

            for (int i = 1; i < hits.Count; i++)
            {
                if (hits[i].Offset - hits[i - 1].Offset <= maxSpacing)
                {
                    curLen++;
                    if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
                }
                else
                {
                    curStart = i;
                    curLen   = 1;
                }
            }

            return bestLen >= 3 ? hits.GetRange(bestStart, bestLen) : new List<SyscallStubHit>();
        }

        private static int CountDistinctSsns(List<SyscallStubHit> hits)
        {
            var s = new HashSet<int>();
            foreach (var h in hits) s.Add(h.Ssn);
            return s.Count;
        }

        /// <summary>
        /// Finds well-formed Hell's Gate / SysWhispers syscall stubs in a memory buffer.
        ///
        /// Two patterns matched:
        ///   1. Compact stub (11 bytes):  mov r10,rcx; mov eax,SSN; syscall; ret
        ///      4C 8B D1  B8 lo hi 00 00  0F 05  C3
        ///
        ///   2. Copied ntdll prologue (21 bytes): mov r10,rcx; mov eax,SSN;
        ///      test byte ptr [SharedUserData+0x308],1; jne +3; syscall; ret
        ///      4C 8B D1  B8 lo hi 00 00  F6 04 25 08 03 FE 7F 01  75 03  0F 05  C3
        ///
        /// SSNs outside 0x0001-0x01FF are rejected: they are compiler-generated immediates
        /// or attacker garbage, not real Windows syscall numbers.
        /// </summary>
        internal static List<SyscallStubHit> FindSyscallStubs(byte[] buffer, int length)
        {
            var hits = new List<SyscallStubHit>();
            if (buffer == null || length < 11) return hits;
            int lim = Math.Min(length, buffer.Length);

            for (int i = 0; i <= lim - 11; i++)
            {
                // mov r10,rcx (4C 8B D1) + mov eax,imm32 (B8 lo hi 00 00)
                if (buffer[i]     != 0x4C || buffer[i + 1] != 0x8B ||
                    buffer[i + 2] != 0xD1 || buffer[i + 3] != 0xB8)
                    continue;

                // High word of imm32 must be zero - SSN fits in 16 bits
                if (buffer[i + 6] != 0x00 || buffer[i + 7] != 0x00)
                    continue;

                int ssn = buffer[i + 4] | (buffer[i + 5] << 8);

                // Valid Windows syscall range: 0x0001-0x01FF.
                // Rejects SSN=0 (no real stub), compiler constants, and out-of-range values.
                if (ssn < MinValidSsn || ssn > MaxValidSsn)
                    continue;

                // Pattern 1: compact - syscall (0F 05) immediately followed by ret (C3)
                if (i + 10 < lim &&
                    buffer[i + 8] == 0x0F && buffer[i + 9] == 0x05 && buffer[i + 10] == 0xC3)
                {
                    hits.Add(new SyscallStubHit(i, ssn));
                    i += 10;
                    continue;
                }

                // Pattern 2: copied ntdll prologue with SharedUserData hypervisor check
                if (i + 20 < lim &&
                    buffer[i +  8] == 0xF6 && buffer[i +  9] == 0x04 && buffer[i + 10] == 0x25 &&
                    buffer[i + 11] == 0x08 && buffer[i + 12] == 0x03 && buffer[i + 13] == 0xFE &&
                    buffer[i + 14] == 0x7F && buffer[i + 15] == 0x01 &&
                    buffer[i + 16] == 0x75 && buffer[i + 17] == 0x03 &&
                    buffer[i + 18] == 0x0F && buffer[i + 19] == 0x05 &&
                    buffer[i + 20] == 0xC3)
                {
                    hits.Add(new SyscallStubHit(i, ssn));
                    i += 20;
                }
            }

            return hits;
        }

        internal static int CountSyscallStubs(byte[] buffer, int length) =>
            FindSyscallStubs(buffer, length).Count;

        internal static bool IsHellsGateEvidence(IReadOnlyList<SyscallStubHit> hits)
        {
            if (hits == null || hits.Count < 3) return false;
            var ssns = new HashSet<int>();
            foreach (var hit in hits)
                ssns.Add(hit.Ssn);
            return ssns.Count >= 3;
        }

        internal readonly struct SyscallStubHit
        {
            public readonly int Offset;
            public readonly int Ssn;
            public SyscallStubHit(int offset, int ssn) { Offset = offset; Ssn = ssn; }
        }

        internal readonly struct HellsGateScanResult
        {
            public readonly int WellFormedStubs;
            public readonly int DistinctSsns;
            public bool IsHit => WellFormedStubs >= 3 && DistinctSsns >= 3;
            public HellsGateScanResult(int stubs, int ssns)
            {
                WellFormedStubs = stubs;
                DistinctSsns = ssns;
            }
        }
    }

    public sealed class IPSecIntegrityGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<IPSecIntegrityGuard> _logger;
        private int _consecutiveFailures;
        private bool _cleanedObserveMode;
        private DateTimeOffset _nextAttemptUtc = DateTimeOffset.MinValue;
        private DateTimeOffset _lastEmitUtc = DateTimeOffset.MinValue;

        // After repeated re-apply failures, back off aggressively so we do not
        // burn CPU/disk and flood events.jsonl (was every 30s forever).
        private const int SoftFailThreshold = 3;
        private const int HardFailThreshold = 8;
        private static readonly TimeSpan MinEmitInterval = TimeSpan.FromMinutes(15);

        public IPSecIntegrityGuard(DetectionEngine de, SentinelConfig config, ILogger<IPSecIntegrityGuard> l)
        {
            _detectionEngine = de;
            _config = config;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            // v2.5.5: Hardening is always-on - no config sync needed.
            _logger.LogInformation("[IPSecIntegrityGuard] Started - IPSec profile=always-on hardening (v2.5.5+)");

            // Rebuild GSecurity on startup.
            if (!_cleanedObserveMode)
            {
                HardeningModule.ReapplyIPSecPolicy();
                _cleanedObserveMode = true;
            }

            await Task.Delay(15000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (HardeningModule.IsIPSecPolicyActive())
                    {
                        if (_consecutiveFailures > 0)
                            _logger.LogInformation(
                                "[IPSecIntegrityGuard] IPSec policy GSecurity active again after {Count} failure(s)",
                                _consecutiveFailures);
                        _consecutiveFailures = 0;
                        _nextAttemptUtc = DateTimeOffset.MinValue;
                    }
                    else if (DateTimeOffset.UtcNow >= _nextAttemptUtc)
                    {
                        _consecutiveFailures++;
                        _logger.LogWarning(
                            "[IPSecIntegrityGuard] Restrictive IPSec GSecurity missing - re-applying (failure #{Count})",
                            _consecutiveFailures);

                        bool skipReapply = _consecutiveFailures > HardFailThreshold;
                        bool reapplied = false;
                        if (!skipReapply)
                        {
                            HardeningModule.ReapplyIPSecPolicy();
                            await Task.Delay(2000, ct);
                            reapplied = HardeningModule.IsIPSecPolicyActive();
                        }
                        else
                        {
                            reapplied = HardeningModule.IsIPSecPolicyActive();
                        }

                        bool shouldEmit = !reapplied
                            ? (_consecutiveFailures == 1
                               || DateTimeOffset.UtcNow - _lastEmitUtc >= MinEmitInterval)
                            : true;

                        if (shouldEmit)
                        {
                            _lastEmitUtc = DateTimeOffset.UtcNow;
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Anti-Tamper: IPSec Policy Deleted and Re-Applied",
                                Evidence = $"Restrictive GSecurity IPSec was missing/unassigned. " +
                                           $"Re-application {(skipReapply ? "SKIPPED (backoff)" : reapplied ? "SUCCEEDED" : "FAILED")}. " +
                                           $"Consecutive failures: {_consecutiveFailures}.",
                                Reasoning = "Sentinel maintains the GSecurity IPSec profile - hardening is always-on as of v2.5.5.",
                                Confidence = 0.95,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM",
                                ProcessId = 0,
                                SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["Reapplied"] = reapplied.ToString(),
                                    ["ConsecutiveFailures"] = _consecutiveFailures.ToString(),
                                    ["Restrictive"] = "true",
                                    ["BackedOff"] = skipReapply.ToString()
                                }
                            });
                        }

                        if (reapplied)
                        {
                            _consecutiveFailures = 0;
                            _nextAttemptUtc = DateTimeOffset.MinValue;
                        }
                        else
                        {
                            _nextAttemptUtc = DateTimeOffset.UtcNow + ComputeBackoff(_consecutiveFailures);
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[IPSecIntegrityGuard] Error"); }

                await Task.Delay(30000, ct);
            }
        }

        /// <summary>
        /// Exponential-ish backoff: 30s -> 2m -> 5m -> 15m -> 1h (capped).
        /// </summary>
        private static TimeSpan ComputeBackoff(int consecutiveFailures)
        {
            if (consecutiveFailures <= SoftFailThreshold)
                return TimeSpan.FromSeconds(30);
            if (consecutiveFailures <= 5)
                return TimeSpan.FromMinutes(2);
            if (consecutiveFailures <= HardFailThreshold)
                return TimeSpan.FromMinutes(5);
            if (consecutiveFailures <= 15)
                return TimeSpan.FromMinutes(15);
            return TimeSpan.FromHours(1);
        }
    }

    /// <summary>
    /// Always-on: self-heals Defender ASR Block rules every 60s (v2.5.5+).
    /// </summary>
    public sealed class AsrPolicyGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<AsrPolicyGuard> _logger;
        private int _consecutiveFailures;

        public AsrPolicyGuard(DetectionEngine de, SentinelConfig config, ILogger<AsrPolicyGuard> l)
        {
            _detectionEngine = de;
            _config = config;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            // v2.5.5: Hardening is always-on - always self-heal ASR Block every 60s.
            _logger.LogInformation("[AsrPolicyGuard] Started - mode=always-on ASR Block self-heal (v2.5.5+)");

            try { await Task.Delay(20000, ct); } catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (!HardeningModule.IsAsrPolicyIntact())
                    {
                        _consecutiveFailures++;
                        _logger.LogWarning(
                            "[AsrPolicyGuard] Restrictive ASR incomplete - re-applying (failure #{Count})",
                            _consecutiveFailures);

                        HardeningModule.ReapplyAsrRules();
                        await Task.Delay(1500, ct);
                        bool ok = HardeningModule.IsAsrPolicyIntact();

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: ASR Policy Drift Re-Applied",
                            Evidence = $"Restrictive ASR Block rules missing/demoted. " +
                                       $"Re-application {(ok ? "SUCCEEDED" : "FAILED")}. " +
                                       $"Consecutive failures: {_consecutiveFailures}",
                            Reasoning = "Sentinel maintains ASR Block policy - hardening is always-on as of v2.5.5.",
                            Confidence = 0.90,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.AntiTamper,
                            Metadata = new Dictionary<string, string>
                            {
                                ["Reapplied"] = ok.ToString(),
                                ["ConsecutiveFailures"] = _consecutiveFailures.ToString(),
                                ["RuleCount"] = HardeningModule.AsrRules.Length.ToString(),
                                ["Restrictive"] = "true"
                            }
                        });

                        if (ok) _consecutiveFailures = 0;
                    }
                    else
                    {
                        _consecutiveFailures = 0;
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[AsrPolicyGuard] Error"); }

                try { await Task.Delay(60000, ct); }
                catch (OperationCanceledException) { break; }
            }
        }
    }
}
