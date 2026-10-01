using System;
using System.Collections.Generic;

namespace Sentinel.Core
{
    /// <summary>
    /// Base class for all enrichment signals that flow through the ContextBus.
    /// These are NOT detections - they are context signals that help monitors
    /// make better decisions by sharing findings with each other.
    /// </summary>
    public abstract class EnrichmentSignal
    {
        public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
        public TimeSpan Ttl { get; set; } = TimeSpan.FromMinutes(5);
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string SourceMonitor { get; set; } = string.Empty;

        public bool IsExpired => DateTimeOffset.UtcNow - Timestamp > Ttl;
    }

    // 
    // Network Signals
    // 

    /// <summary>
    /// Published by BeaconingDetector when C2 beaconing is confirmed.
    /// Consumed by: GhostProcessMonitor (cross-validate ghost PIDs),
    ///              ChainTracer (enrich chain evidence with C2 endpoints).
    /// </summary>
    public sealed class NetworkC2Signal : EnrichmentSignal
    {
        public string RemoteAddress { get; set; } = string.Empty;
        public int RemotePort { get; set; }
        public double CoefficientOfVariation { get; set; }
        public double MeanIntervalSeconds { get; set; }
        public double Confidence { get; set; }
        public int ObservationCount { get; set; }
    }

    /// <summary>
    /// Published by GhostProcessMonitor when a ghost (unresolvable) PID is found.
    /// Consumed by: BeaconingDetector (flag ghost PIDs for priority analysis),
    ///              AppNetworkPolicyMonitor (treat unknown PIDs as high-risk).
    /// </summary>
    public sealed class GhostProcessSignal : EnrichmentSignal
    {
        public List<string> Destinations { get; set; } = new();
        public int ScansSeen { get; set; }
        public bool ConnectsToBlockedDevice { get; set; }
        public bool HasSuspiciousPort { get; set; }
    }

    /// <summary>
    /// Published by AppDnsExfilMonitor and DnsQueryMonitor for DNS anomalies.
    /// Consumed by: GhostProcessMonitor (correlate ghost PIDs with DGA domains),
    ///              BeaconingDetector (correlate beaconing with DNS patterns).
    /// </summary>
    public sealed class DnsAnomalySignal : EnrichmentSignal
    {
        public string Domain { get; set; } = string.Empty;
        public DnsAnomalyType AnomalyType { get; set; }
        public double Entropy { get; set; }
        public int QueryCount { get; set; }
        public string? ResolverIp { get; set; }
    }

    public enum DnsAnomalyType
    {
        HighEntropySubdomain,  // DGA indicator
        RapidQueryVolume,      // Tunneling/beaconing
        DoHBypass,             // Application-level DNS bypass
    }

    // 
    // File & Process Signals
    // 

    /// <summary>
    /// Published by FileReputationEngine after scoring a file.
    /// Consumed by: AppNetworkPolicyMonitor (demote alerts for known-good),
    ///              BeaconingDetector (adjust trust for scored binaries),
    ///              DetectionEngine (annotate telemetry with reputation).
    /// </summary>
    public sealed class FileVerdictSignal : EnrichmentSignal
    {
        public string FilePath { get; set; } = string.Empty;
        public string Sha256 { get; set; } = string.Empty;
        public int CompositeScore { get; set; }
        public FileVerdict Verdict { get; set; }
        public bool IsSigned { get; set; }
        public string? SignerName { get; set; }
    }

    /// <summary>
    /// Published by EtwThreatIntelMonitor when injection indicators are found.
    /// Consumed by: ChainTracer (enrich chain with injection evidence),
    ///              BehavioralCorrelationEngine (correlate with other signals).
    /// </summary>
    public sealed class InjectionSignal : EnrichmentSignal
    {
        public int ThreadId { get; set; }
        public string StartAddress { get; set; } = string.Empty;
        public string? ImagePath { get; set; }
    }

    /// <summary>
    /// Published by EphemeralProcessMonitor when a flash process is detected.
    /// Consumed by: ChainTracer (add to chain evidence if PID appears later),
    ///              FileReputationEngine (priority-scan ephemeral binaries).
    /// </summary>
    public sealed class EphemeralProcessSignal : EnrichmentSignal
    {
        public string ExecutableName { get; set; } = string.Empty;
        public string? ExecutablePath { get; set; }
        public bool SelfDeleted { get; set; }
        public bool SuspiciousPath { get; set; }
        public string PrefetchFile { get; set; } = string.Empty;
    }

    // 
    // Volume / Exfiltration Signals
    // 

    /// <summary>
    /// Published by DataExfiltrationMonitor when volume spikes are detected.
    /// Consumed by: BeaconingDetector (correlate spike timing with beacon PID),
    ///              AppNetworkPolicyMonitor (flag processes active during spike).
    /// </summary>
    public sealed class ExfiltrationSpikeSignal : EnrichmentSignal
    {
        public long BytesDelta { get; set; }
        public long BaselineRate { get; set; }
        public double SpikeMultiplier { get; set; }
        public TimeSpan Interval { get; set; }
    }

    /// <summary>
    /// Published by CredentialCanaryMonitor when canary credentials are accessed.
    /// Consumed by: BehavioralCorrelationEngine (combine with other theft signals),
    ///              ChainTracer (flag PIDs that accessed credentials).
    /// </summary>
    public sealed class CredentialAccessSignal : EnrichmentSignal
    {
        public string TargetName { get; set; } = string.Empty;
        public CredentialAccessType AccessType { get; set; }
    }

    public enum CredentialAccessType
    {
        CanaryDeleted,
        CanaryRead,
        CanaryModified
    }

    /// <summary>
    /// Published by AppNetworkPolicyMonitor when a process contacts a new subnet.
    /// Consumed by: BeaconingDetector (correlate new subnet with beaconing),
    ///              GhostProcessMonitor (identify processes breaking policy).
    /// </summary>
    public sealed class NetworkPolicyViolationSignal : EnrichmentSignal
    {
        public string RemoteAddress { get; set; } = string.Empty;
        public string Subnet { get; set; } = string.Empty;
        public bool IsEnforcementPhase { get; set; }
    }

    // 
    // Named Pipe Signals (v1.6.8)
    // 

    /// <summary>
    /// Published by NamedPipeMonitor when a suspicious named pipe is detected.
    /// Consumed by: BehavioralCorrelationEngine (composite pipe + beacon detection),
    ///              ChainTracer (enrich chain evidence with IPC indicators).
    /// </summary>
    public sealed class NamedPipeSignal : EnrichmentSignal
    {
        public string PipeName { get; set; } = string.Empty;
        public string MatchedPattern { get; set; } = string.Empty;
        public uint OwnerPid { get; set; }
        public bool IsKnownBadPattern { get; set; }
        public double Entropy { get; set; }
    }

    // 
    // Token Theft Signals (v1.6.8)
    // 

    /// <summary>
    /// Published by TokenTheftMonitor when token manipulation is detected.
    /// Consumed by: BehavioralCorrelationEngine (composite token theft + lateral movement),
    ///              ChainTracer (enrich chain evidence with privilege escalation indicators).
    /// </summary>
    public sealed class TokenTheftSignal : EnrichmentSignal
    {
        public string TokenUserName { get; set; } = string.Empty;
        public TokenTheftType TheftType { get; set; }
        public string ImagePath { get; set; } = string.Empty;
        public bool HasImpersonatePrivilege { get; set; }
    }

    public enum TokenTheftType
    {
        SystemTokenFromUserProcess,
        ImpersonatePrivilegeFromSuspiciousPath,
        CrossSessionTokenDuplication,
    }

    // 
    // Command-Line Obfuscation Signals (v2.7.8)
    // 

    /// <summary>
    /// Published by any monitor that holds a process command line and scores it via
    /// <c>MlThreatScorer.ScoreCommandLine</c>. Captures the *shape* of command-line obfuscation
    /// (encoded PowerShell, base64/hex blobs, escape-char stuffing, download+IEX combos) that
    /// defeats signature / regex matching - the dominant modern LOLBin tradecraft.
    ///
    /// Consumed by: WeightedCorrelationEngine / BehavioralCorrelationEngine (composite fuel),
    ///              ChainTracer (enrich chain evidence with the obfuscated launch string).
    ///
    /// SOFT SIGNAL ONLY. A high score is observe-fuel; it never authorises a kill on its own -
    /// only a chain-confirmed terminal does. Consistent with the observe-until-chain constraint.
    /// </summary>
    public sealed class CommandLineObfuscationSignal : EnrichmentSignal
    {
        /// <summary>Obfuscation risk in [0,100] from the ML model or heuristic fallback.</summary>
        public int RiskScore { get; set; }

        /// <summary>True when a trained model produced the score; false when the heuristic did.</summary>
        public bool FromModel { get; set; }

        /// <summary>Shannon entropy of the command line (bits/byte) - high = likely encoded payload.</summary>
        public double Entropy { get; set; }

        /// <summary>True when an encoded-command flag (e.g. PowerShell -enc) was present.</summary>
        public bool HasEncodedCommandFlag { get; set; }

        /// <summary>True when a download primitive and in-memory exec token co-occur (dropper shape).</summary>
        public bool DownloadAndExecCombo { get; set; }
    }
}
