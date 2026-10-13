using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// System-wide process integrity (permanent product law - do not disable):
    /// 1. Every mapped module is identity-checked (path + Microsoft signature).
    ///    Foreign modules are unloaded immediately via <see cref="DllUnloadEngine"/>
    ///    (constraint: DLL unloaders may remediate without a chain; Tier1, never demoted).
    /// 2. Missing image path -> Tier2 LogOnly.
    /// Games skipped for handle safety only (Denuvo). Module *count* is not a signal.
    /// </summary>
    public sealed class MemoryBehaviorAnalyzer : IDisposable
    {
        private readonly DllUnloadEngine _dllUnloadEngine;
        private readonly ILogger<MemoryBehaviorAnalyzer> _logger;
        private readonly System.Threading.Timer _timer;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);
        private int _baselineEnumDone;

        public MemoryBehaviorAnalyzer(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            DllUnloadEngine dllUnloadEngine,
            ILogger<MemoryBehaviorAnalyzer> logger)
        {
            _ = fusionEngine;
            _ = detectionEngine;
            _ = signerTrust;
            _dllUnloadEngine = dllUnloadEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanMemory, null, ScanInterval, ScanInterval);
        }

        private void ScanMemory(object? state)
        {
            try
            {
                bool baseline = Interlocked.Exchange(ref _baselineEnumDone, 1) == 0;
                if (baseline)
                {
                    foreach (var proc in Process.GetProcesses())
                    {
                        try
                        {
                            if (proc.Id <= 4) continue;
                            var name = proc.ProcessName;
                            var path = SecurityValidation.GetProcessImagePath(proc.Id);
                            if (SecurityValidation.IsGameOrAntiCheatProcess(proc.Id, path) ||
                                !NativeProcessMemory.CanInspect(proc.Id, path))
                                continue;
                            _ = _dllUnloadEngine
                                .CheckAndUnloadAsync(proc.Id, name)
                                .GetAwaiter().GetResult();
                        }
                        catch (System.ComponentModel.Win32Exception) { }
                        catch (InvalidOperationException) { }
                        catch { }
                        finally
                        {
                            proc.Dispose();
                        }
                    }
                }

                _dllUnloadEngine.PruneStalePidCaches();

            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[MemoryBehaviorAnalyzer] Scan error");
            }
        }

        public void Dispose() => _timer.Dispose();
    }
}
