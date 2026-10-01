using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.AntiTamper)]
    public class VerdictGateRule : IDetectionRule
    {
        public string Name => "VerdictGateRule";

        private readonly FileVerdictAds _verdictAds;
        private readonly SafeProcessExemptionRegistry _exemptionRegistry;

        public VerdictGateRule(FileVerdictAds verdictAds, SafeProcessExemptionRegistry exemptionRegistry)
        {
            _verdictAds = verdictAds;
            _exemptionRegistry = exemptionRegistry;
        }

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var imagePath = pt.ImagePath;
                if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
                {
                    return null;
                }

                // Compute file hash
                string hash = string.Empty;
                try
                {
                    using var sha = System.Security.Cryptography.SHA256.Create();
                    using var fs = File.OpenRead(imagePath);
                    var hashBytes = sha.ComputeHash(fs);
                    hash = ConvertHex.ToHexString(hashBytes).ToLowerInvariant();
                }
                catch
                {
                    return null;
                }

                // Check Alternate Data Stream verdict
                var verdict = _verdictAds.GetVerdict(imagePath, hash);

                if (verdict == HashVerdict.Unsafe)
                {
                    return new DetectionEvent
                    {
                        RuleName = Name,
                        ProcessName = pt.ProcessName,
                        ProcessId = pt.ProcessId,
                        SignalType = SignalType.SuspiciousProcess,
                        Confidence = 0.99,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        Evidence = $"Process '{pt.ProcessName}' (PID {pt.ProcessId}) has signed 'unsafe' ADS reputation consensus verdict.",
                        Reasoning = "Process image was marked as malicious/unsafe by reputation consensus check and signed locally. Execution prevented.",
                        Metadata = new Dictionary<string, string> { { "SHA256", hash }, { "Verdict", "Unsafe" } }
                    };
                }
                else if (verdict == HashVerdict.Safe)
                {
                    _exemptionRegistry.RegisterSafeProcess(pt.ProcessId);
                }
            }

            return null;
        }
    }

    /// <summary>
    /// Detects ClickFix / FakeCAPTCHA paste-and-run tradecraft.
    /// Intel 2025-2026 (Microsoft, ESET +500%, Malwarebytes, Krebs): fake reCAPTCHA/Turnstile
    /// pages instruct users to Win+R -> paste PowerShell/cmd that downloads stealers/RATs.
    /// </summary>
}
