using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// ComHijackMonitor (v2.7.3) - drives the previously-unwired <see cref="ComHijackEvaluator"/>.
    ///
    /// Enumerates COM CLSID server registrations under HKCU and HKLM (incl. Wow6432Node) -
    /// InprocServer32 / InprocHandler32 / LocalServer32 / TreatAs - and runs each through
    /// <see cref="ComHijackEvaluator.Evaluate"/>. This catches COM hijack persistence
    /// (T1546.015): a CLSID whose server points at a user-writable drop, a Component Based
    /// Servicing DLL name outside the store (the cbsapi.dll plant class), a script-host LOLBin,
    /// or an HKCU entry that SHADOWS an HKLM class with a different path (HKCU wins at activation
    /// with no admin - exactly the shadow we hunted during the CbsApi investigation).
    ///
    /// CONSTRAINT COMPLIANCE: verdicts are emitted Tier2 / LogOnly - a registry-state signal is
    /// "what it IS", not "what it DOES", so it never authorizes a response on its own. It is a
    /// local staged-payload seed (Provenance=com-hijack) that feeds the correlation engine; a
    /// COM-hijack payload that then acts harmfully escalates via a composite to graceful
    /// containment. The CLSID key is NEVER deleted (deleting a shell class bricks logon/explorer);
    /// only the payload FILE is quarantined to the .senq vault, and only when
    /// <see cref="ComHijackEvaluator.Verdict.ShouldQuarantinePayload"/> is set (drop-path /
    /// servicing-impersonation payload, never a signed OS LOLBin).
    /// </summary>
    public sealed class ComHijackMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly DllUnloadEngine _dllUnloadEngine;
        private readonly ILogger<ComHijackMonitor> _logger;

        // Dedup per (clsid|kind|serverpath) so a persistent hijack is surfaced at most once/window.
        private readonly ConcurrentDictionary<string, DateTime> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ReAlertWindow = TimeSpan.FromHours(6);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(5);

        private const int MaxClsidsPerHive = 20000; // safety bound on enumeration cost

        public ComHijackMonitor(
            DetectionEngine de,
            DllUnloadEngine dllUnloadEngine,
            ILogger<ComHijackMonitor> l)
        {
            _detectionEngine = de;
            _dllUnloadEngine = dllUnloadEngine;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ComHijackMonitor] Started");

            // Small delay so first scan does not pile onto boot.
            try { await Task.Delay(TimeSpan.FromSeconds(90), ct); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    ScanAllHives(ct);

                    var cutoff = DateTime.UtcNow - ReAlertWindow;
                    foreach (var kv in _alerted)
                        if (kv.Value < cutoff) _alerted.TryRemove(kv.Key, out _);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ComHijackMonitor] scan error"); }

                try { await Task.Delay(ScanInterval, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        private void ScanAllHives(CancellationToken ct)
        {
            // HKCU CLSID entries can shadow HKLM - pass the HKLM base so the evaluator can compare.
            ScanClsidRoot(Registry.CurrentUser, "HKCU", @"Software\Classes\CLSID",
                Registry.LocalMachine, @"Software\Classes\CLSID", ct);
            ScanClsidRoot(Registry.CurrentUser, "HKCU", @"Software\Classes\Wow6432Node\CLSID",
                Registry.LocalMachine, @"Software\Classes\Wow6432Node\CLSID", ct);
            ScanClsidRoot(Registry.LocalMachine, "HKLM", @"Software\Classes\CLSID", null, null, ct);
            ScanClsidRoot(Registry.LocalMachine, "HKLM", @"Software\Classes\Wow6432Node\CLSID", null, null, ct);
        }

        private void ScanClsidRoot(
            RegistryKey hive, string hiveLabel, string clsidPath,
            RegistryKey? hklmHive, string? hklmClsidPath, CancellationToken ct)
        {
            using var root = hive.OpenSubKey(clsidPath);
            if (root == null) return;

            int count = 0;
            foreach (var clsid in root.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                if (++count > MaxClsidsPerHive) break;

                try
                {
                    using var clsidKey = root.OpenSubKey(clsid);
                    if (clsidKey == null) continue;

                    EvaluateServer(clsidKey, clsid, hiveLabel,
                        ComHijackEvaluator.ServerKind.InprocServer32, "InprocServer32",
                        hklmHive, hklmClsidPath);
                    EvaluateServer(clsidKey, clsid, hiveLabel,
                        ComHijackEvaluator.ServerKind.InprocHandler32, "InprocHandler32",
                        hklmHive, hklmClsidPath);
                    EvaluateServer(clsidKey, clsid, hiveLabel,
                        ComHijackEvaluator.ServerKind.LocalServer32, "LocalServer32",
                        hklmHive, hklmClsidPath);
                    EvaluateServer(clsidKey, clsid, hiveLabel,
                        ComHijackEvaluator.ServerKind.TreatAs, "TreatAs",
                        hklmHive, hklmClsidPath);
                }
                catch { /* per-CLSID best effort */ }
            }
        }

        private void EvaluateServer(
            RegistryKey clsidKey, string clsid, string hiveLabel,
            ComHijackEvaluator.ServerKind kind, string subKeyName,
            RegistryKey? hklmHive, string? hklmClsidPath)
        {
            using var sub = clsidKey.OpenSubKey(subKeyName);
            if (sub == null) return;

            var serverValue = sub.GetValue(null) as string; // (default) value
            if (string.IsNullOrWhiteSpace(serverValue)) return;

            // For HKCU entries, look up the matching HKLM server path (shadow detection).
            string? hklmValue = null;
            bool hkcuShadowsHklm = false;
            if (hiveLabel == "HKCU" && hklmHive != null && hklmClsidPath != null
                && kind != ComHijackEvaluator.ServerKind.TreatAs)
            {
                try
                {
                    using var hklmSub = hklmHive.OpenSubKey($@"{hklmClsidPath}\{clsid}\{subKeyName}");
                    hklmValue = hklmSub?.GetValue(null) as string;
                    hkcuShadowsHklm = !string.IsNullOrWhiteSpace(hklmValue);
                }
                catch { }
            }

            var registration = new ComHijackEvaluator.Registration(
                clsid: clsid,
                hive: hiveLabel,
                kind: kind,
                serverValue: serverValue!,
                baselineValue: null,   // no persisted baseline yet; new/changed handled by path-trust
                hkcuShadowsHklm: hkcuShadowsHklm,
                hklmValue: hklmValue);

            var verdict = ComHijackEvaluator.Evaluate(in registration);
            if (!verdict.IsHijack) return;

            var serverPath = ComHijackEvaluator.ExtractServerPath(serverValue);
            var dedupKey = $"{clsid}|{kind}|{serverPath}";
            if (_alerted.TryGetValue(dedupKey, out var last) &&
                (DateTime.UtcNow - last) < ReAlertWindow)
                return;
            _alerted[dedupKey] = DateTime.UtcNow;

            _ = EmitAndMaybeQuarantineAsync(verdict, clsid, hiveLabel, kind, serverValue!, serverPath);
        }

        private async Task EmitAndMaybeQuarantineAsync(
            ComHijackEvaluator.Verdict verdict, string clsid, string hiveLabel,
            ComHijackEvaluator.ServerKind kind, string serverValue, string serverPath)
        {
            try
            {
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = verdict.RuleName,
                    Evidence = $"CLSID {clsid} ({hiveLabel}\\...\\{kind}) server '{serverValue}'"
                               + (string.IsNullOrEmpty(serverPath) ? "" : $" -> '{serverPath}'"),
                    Reasoning = verdict.Reasoning,
                    Confidence = verdict.Confidence,
                    Tier = verdict.Tier,                        // Tier2Indicator from the evaluator
                    AuthorizedResponse = verdict.AuthorizedResponse, // LogOnly from the evaluator
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.SuspiciousProcess,
                    Metadata = new Dictionary<string, string>
                    {
                        ["CLSID"] = clsid,
                        ["Hive"] = hiveLabel,
                        ["ServerKind"] = kind.ToString(),
                        ["ServerPath"] = serverPath,
                        ["Provenance"] = "com-hijack"
                    }
                }).ConfigureAwait(false);

                // Payload-file quarantine (never the CLSID key). Only when the evaluator says the
                // payload is a drop-path / servicing-impersonation file (not a signed OS LOLBin).
                if (verdict.ShouldQuarantinePayload && serverPath.Length > 0)
                {
                    await _dllUnloadEngine.OnComServerPlantAsync(serverPath).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ComHijackMonitor] emit/quarantine failed for CLSID {Clsid}", clsid);
            }
        }
    }
}
