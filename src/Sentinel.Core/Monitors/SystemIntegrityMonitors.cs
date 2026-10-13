// System Integrity Monitor Group - firewall, secure boot, scheduled tasks, TLS certificates, UAC, WMI persistence, and boot integrity

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    // 
    // Firewall Integrity Monitor - detects firewall rule tampering
    // 
    public sealed class FirewallIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<FirewallIntegrityMonitor> _logger;
        private int _baselineRuleCount;

        public FirewallIntegrityMonitor(DetectionEngine de, ILogger<FirewallIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[FirewallIntegrityMonitor] Started");
            _baselineRuleCount = CountFirewallRules();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    var current = CountFirewallRules();
                    if (_baselineRuleCount > 0 && current > _baselineRuleCount + 5)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Firewall Integrity: Bulk Rule Addition",
                            Evidence = $"Firewall rules increased from {_baselineRuleCount} to {current}",
                            Reasoning = "A significant number of firewall rules were added since baseline, indicating possible malware creating exceptions.",
                            Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                    }
                    _baselineRuleCount = current;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[FirewallIntegrityMonitor] Error"); }
            }
        }

        private static int CountFirewallRules()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
                return key?.ValueCount ?? 0;
            }
            catch { return 0; }
        }
    }


    // 
    // Secure Boot Integrity Monitor - checks Secure Boot state
    // 
    public sealed class SecureBootIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<SecureBootIntegrityMonitor> _logger;

        public SecureBootIntegrityMonitor(DetectionEngine de, ILogger<SecureBootIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SecureBootIntegrityMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(300000, ct);
                    try
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
                        var val = key?.GetValue("UEFISecureBootEnabled");
                        if (val is int enabled && enabled == 0)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Secure Boot: Disabled",
                                Evidence = "UEFI Secure Boot is disabled on this system",
                                Reasoning = "Secure Boot being disabled allows unsigned bootloaders and rootkits to load before the OS.",
                                Confidence = 0.50, Tier = DetectionTier.Tier2Indicator,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                        }
                    }
                    catch { }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[SecureBootIntegrityMonitor] Error"); }
            }
        }
    }


    // 
    // Scheduled Task Monitor - detects new/modified scheduled tasks
    // 
    public sealed class ScheduledTaskMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ScheduledTaskMonitor> _logger;
        private readonly HashSet<string> _baselineTasks = new(StringComparer.OrdinalIgnoreCase);

        public ScheduledTaskMonitor(DetectionEngine de, ILogger<ScheduledTaskMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ScheduledTaskMonitor] Started");
            SnapshotTasks(_baselineTasks);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    SnapshotTasks(current);
                    foreach (var task in current.Except(_baselineTasks))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Persistence: New Scheduled Task",
                            Evidence = $"New scheduled task: {task}",
                            Reasoning = "A new scheduled task was created, which is a common persistence mechanism for malware.",
                            Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                        _baselineTasks.Add(task);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ScheduledTaskMonitor] Error"); }
            }
        }

        private static void SnapshotTasks(HashSet<string> target)
        {
            var taskDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks");
            if (!Directory.Exists(taskDir)) return;
            try
            {
                foreach (var f in Directory.EnumerateFiles(taskDir, "*", SearchOption.AllDirectories))
                    target.Add(f);
            }
            catch { }
        }
    }


    // 
    // TLS Certificate Monitor - detects NEW root certificates added after baseline.
    // Startup: silently baselines all existing certs. Never alerts or removes.
    // Runtime: detects new certs not in baseline. Emits Tier2 log-only alerts.
    // Never auto-removes any certificate - alerts only for admin review.
    // 
    public sealed class TlsCertificateMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<TlsCertificateMonitor> _logger;
        private readonly HashSet<string> _baselineThumbprints = new(StringComparer.OrdinalIgnoreCase);

        // Known enterprise TLS inspection CA subject patterns - these are legitimate
        // but still logged as Tier2 indicators for visibility
        private static readonly string[] KnownEnterpriseCAs =
        {
            "Zscaler", "Blue Coat", "BlueCoat", "Palo Alto", "Fortinet", "FortiGate",
            "Symantec WSS", "Cisco Umbrella", "McAfee", "Sophos", "Barracuda",
            "WatchGuard", "Check Point", "SonicWall", "Trend Micro", "iboss",
            "Websense", "Forcepoint", "Netskope", "Clearswift"
        };

        // Known developer/debugging tool CA patterns - Tier2 only, no removal
        private static readonly string[] KnownDevToolCAs =
        {
            "Fiddler", "DO_NOT_TRUST_FiddlerRoot", "Charles", "mitmproxy",
            "Burp", "BurpSuite", "OWASP ZAP", "Telerik"
        };

        public TlsCertificateMonitor(
            DetectionEngine de, SentinelConfig config, JsonlEventLogger logger,
            ILogger<TlsCertificateMonitor> l)
        {
            _detectionEngine = de; _config = config; _eventLogger = logger; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[TlsCertificateMonitor] Started - performing startup full-store audit");

            // Phase 1: Startup scan - audit every existing cert, flag unknowns
            try
            {
                await AuditAndBaselineStoreAsync(ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[TlsCertificateMonitor] Startup audit failed");
            }

            _logger.LogInformation("[TlsCertificateMonitor] Audit complete: {Count} certs baselined", _baselineThumbprints.Count);

            // Phase 2: Runtime polling - detect new certs
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    await PollForNewCertsAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[TlsCertificateMonitor] Poll error"); }
            }
        }

        /// <summary>
        /// Startup audit: score every existing cert. Known public CAs are silently baselined.
        /// Unknown/suspicious certs that were present before Sentinel started get flagged as
        /// Tier2 indicators (can't auto-remove because we don't know if user installed them).
        /// This prevents the "race the baseline" attack from going completely unnoticed.
        /// </summary>
        private async Task AuditAndBaselineStoreAsync(CancellationToken ct)
        {
            var storesToAudit = new (System.Security.Cryptography.X509Certificates.StoreName Name, System.Security.Cryptography.X509Certificates.StoreLocation Location, string Label)[]
            {
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine, "Root"),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine, "TrustedPublisher"),
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser, "UserRoot"),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser, "UserTrustedPublisher")
            };

            foreach (var (storeName, storeLocation, storeLabel) in storesToAudit)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    using var store = new System.Security.Cryptography.X509Certificates.X509Store(storeName, storeLocation);
                    store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

                    foreach (var cert in store.Certificates)
                    {
                        if (ct.IsCancellationRequested) break;

                        var key = $"{storeLabel}:{cert.Thumbprint}";
                        _baselineThumbprints.Add(key);

                        var analysis = AnalyzeCert(cert);

                        // Known public root CAs: fully trusted, no alert
                        if (analysis.IsPublicRootCa) continue;

                        // Known enterprise/dev tool CAs: log as Tier2 for visibility but no action
                        if (analysis.IsEnterpriseCa || analysis.IsDevTool)
                        {
                            await EmitCertDetectionAsync(cert, analysis, null, isStartupScan: true);
                            continue;
                        }

                        // Unknown cert with suspicious signals: flag it even though it was pre-existing
                        // This catches the "install cert before Sentinel starts" attack
                        if (analysis.Confidence >= 0.70)
                        {
                            _logger.LogWarning("[TlsCertificateMonitor] Startup: suspicious pre-existing cert in {Store}: {Subject} (confidence {Conf:F2})",
                                storeLabel, cert.Subject, analysis.Confidence);

                            // Very high confidence at startup (>=0.90): actively remove only
                            // when ActiveResponse is on AND not a public/enterprise/dev CA.
                            // Pre-existing store pollution from Microsoft root updates must not
                            // brick TLS by deleting real trust anchors.
                            ResponseAction? startupResponse = null;
                            if (analysis.Confidence >= 0.90
                                && ResponsePolicy.MayPerformInlineHostMutation(_config)
                                && !analysis.IsPublicRootCa
                                && !analysis.IsEnterpriseCa
                                && !analysis.IsDevTool)
                            {
                                startupResponse = ResponseAction.RemoveCert;
                                _logger.LogWarning("[TlsCertificateMonitor] REMOVING malicious pre-existing cert: {Subject}", cert.Subject);
                            }

                            await EmitCertDetectionAsync(cert, analysis, null, isStartupScan: false, startupResponse);
                            // Note: isStartupScan=false here so the response engine actually processes the removal
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[TlsCertificateMonitor] Audit of {Store} failed", storeLabel);
                }
            }
        }

        /// <summary>
        /// Runtime polling: detect new certs added after baseline.
        /// New unknown certs with high confidence -> remove + notify.
        /// New known public CAs -> baseline silently.
        /// Monitors Root AND TrustedPublisher stores (BYOVD attack vector).
        /// </summary>
        private async Task PollForNewCertsAsync(CancellationToken ct)
        {
            await PollStoreAsync(
                System.Security.Cryptography.X509Certificates.StoreName.Root,
                System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine,
                "Root", ct);
            await PollStoreAsync(
                System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher,
                System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine,
                "TrustedPublisher", ct);
            await PollStoreAsync(
                System.Security.Cryptography.X509Certificates.StoreName.Root,
                System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser,
                "UserRoot", ct);
            await PollStoreAsync(
                System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher,
                System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser,
                "UserTrustedPublisher", ct);
        }

        private async Task PollStoreAsync(
            System.Security.Cryptography.X509Certificates.StoreName storeName,
            System.Security.Cryptography.X509Certificates.StoreLocation storeLocation,
            string storeLabel,
            CancellationToken ct)
        {
            try
            {
                using var store = new System.Security.Cryptography.X509Certificates.X509Store(storeName, storeLocation);
                store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

                foreach (var cert in store.Certificates)
                {
                    if (ct.IsCancellationRequested) break;
                    var key = $"{storeLabel}:{cert.Thumbprint}";
                    if (_baselineThumbprints.Contains(key)) continue;

                    var analysis = AnalyzeCert(cert);
                    var adderInfo = TraceAdderProcess(cert.Thumbprint);

                    // Known public root CAs: baseline silently
                    if (analysis.IsPublicRootCa && analysis.Confidence <= 0.50)
                    {
                        _baselineThumbprints.Add(key);
                        continue;
                    }

                    // TrustedPublisher additions are extra suspicious - used for BYOVD
                    if (storeLabel == "TrustedPublisher")
                    {
                        analysis.Confidence = Math.Max(analysis.Confidence, 0.75);
                        analysis.Reasons.Add("Added to TrustedPublisher store (BYOVD/driver signing attack vector)");
                    }

                    _logger.LogWarning("[TlsCertificateMonitor] New cert in {Store}: Subject={Subject}, Confidence={Conf:F2}",
                        storeLabel, cert.Subject, analysis.Confidence);

                    // Observe-first: never remove public roots; only remove high-confidence
                    // unknowns when ActiveResponse is enabled. Otherwise log only.
                    ResponseAction response = ResponseAction.LogOnly;
                    if (!analysis.IsPublicRootCa && !analysis.IsEnterpriseCa && !analysis.IsDevTool
                        && ResponsePolicy.MayPerformInlineHostMutation(_config))
                    {
                        if (analysis.Confidence >= 0.80)
                        {
                            response = adderInfo != null
                                ? ResponseAction.RemoveCertAndKillAdder
                                : ResponseAction.RemoveCert;
                        }
                        else if (analysis.Confidence >= 0.75)
                        {
                            // Raised from 0.65 - single weak signals (e.g. missing CRL on a
                            // legitimate but unknown CA) must not delete trust anchors.
                            response = ResponseAction.RemoveCert;
                        }
                    }

                    await EmitCertDetectionAsync(cert, analysis, adderInfo, isStartupScan: false, response);

                    // BYOVD chain trace: if a TrustedPublisher cert was removed,
                    // scan for drivers signed by this cert and quarantine them.
                    if (storeLabel == "TrustedPublisher" && response != ResponseAction.LogOnly)
                    {
                        await ScanAndQuarantineSignedDriversAsync(cert.Thumbprint, cert.Subject);
                    }

                    _baselineThumbprints.Add(key);
                }
            }
            catch { }
        }

        /// <summary>
        /// After removing a malicious code-signing cert from TrustedPublisher,
        /// scan the drivers directory for any .sys files signed by that cert.
        /// Quarantine the driver + remove its service registration.
        /// </summary>
        private async Task ScanAndQuarantineSignedDriversAsync(string certThumbprint, string certSubject)
        {
            try
            {
                // v1.8.1 RT-NEW-1: require a real thumbprint - never match by empty CN (Contains("") == true)
                if (string.IsNullOrWhiteSpace(certThumbprint) || certThumbprint.Length < 16)
                {
                    _logger.LogWarning("[TlsCertificateMonitor] BYOVD scan skipped - missing/short cert thumbprint");
                    return;
                }

                var driversDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers");
                if (!Directory.Exists(driversDir)) return;

                const int maxDriversPerCert = 5;
                int acted = 0;

                foreach (var driverPath in Directory.EnumerateFiles(driversDir, "*.sys"))
                {
                    if (acted >= maxDriversPerCert) break;

                    try
                    {
                        var signerCert = GetFileCertificate(driverPath);
                        if (signerCert == null) continue;

                        // EXACT thumbprint only - subject substring matching removed (empty CN bricked hosts)
                        bool matchesThumbprint = signerCert.Thumbprint?.Equals(
                            certThumbprint) == true;
                        if (!matchesThumbprint) continue;

                        var driverName = Path.GetFileNameWithoutExtension(driverPath);

                        _logger.LogWarning("[TlsCertificateMonitor] BYOVD: driver '{Driver}' signed by removed cert (thumbprint match). Neutralizing service.", driverName);

                        await _eventLogger.LogEventAsync("response", new ResponseEvent
                        {
                            ProcessId = 0,
                            ProcessName = "TlsCertificateMonitor",
                            ActionTaken = "NEUTRALIZE_BYOVD_DRIVER",
                            Reason = $"Driver '{driverPath}' exact thumbprint match for removed TrustedPublisher cert '{certSubject}'. Stopping service + deleting service key. File NOT deleted from System32\\drivers (WRP-safe)."
                        });

                        // Stop service + remove registration. Do NOT delete the .sys under System32\drivers -
                        // WRP/OS integrity; mass-delete was a bricking risk when matching was too broad.
                        try
                        {
                            using var sc = new System.ServiceProcess.ServiceController(driverName);
                            if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                                sc.Stop();
                        }
                        catch { }

                        try
                        {
                            using var servicesKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                                @"SYSTEM\CurrentControlSet\Services", writable: true);
                            servicesKey?.DeleteSubKeyTree(driverName, throwOnMissingSubKey: false);
                        }
                        catch { }

                        acted++;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "BYOVD: Vulnerable Driver Neutralized",
                            Evidence = $"Driver '{driverName}.sys' matched removed TrustedPublisher thumbprint. Service registration removed. Binary left in place for OS integrity.",
                            Reasoning = "BYOVD neutralization stops the service and removes its SCM registration. " +
                                        "v1.8.1 no longer deletes System32\\drivers binaries (RT-NEW-1: empty-CN subject match could wipe all drivers).",
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = driverName,
                            ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                { "CertThumbprint", certThumbprint },
                                { "DriverPath", driverPath }
                            }
                        });
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[TlsCertificateMonitor] BYOVD driver scan error");
            }
        }

        private static System.Security.Cryptography.X509Certificates.X509Certificate2? GetFileCertificate(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is obsolete but has no X509CertificateLoader equivalent for Authenticode
                var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
                return cert;
            }
            catch { return null; }
        }

        // Known legitimate public root CA patterns - these are trusted global CAs.
        // Keep in sync with common Microsoft AuthRoot / browser root store names.
        // Missing entries cause false "suspicious root" alerts when Windows updates the store.
        private static readonly string[] KnownPublicRootCAs =
        {
            "DigiCert", "GlobalSign", "VeriSign", "Verizon", "Entrust", "GeoTrust",
            "GoDaddy", "Thawte", "Comodo", "Sectigo", "Starfield", "Let's Encrypt",
            "ISRG Root", "Internet Security Research Group", "IdenTrust", "Baltimore",
            "CyberTrust", "QuoVadis",
            "Trustwave", "GTS Root", "Google Trust Services", "Google Trust", "GlobalTrust",
            "SwissSign", "Certum",
            "AffirmTrust", "Amazon Root", "Amazon", "Apple Root", "Microsoft Root",
            "Microsoft Corporation", "Microsoft RSA", "Microsoft ECC",
            // Common web PKI roots that Windows installs via automatic root updates
            "SSL.com", "SSL Corporation", "Cloudflare", "Certainly", "ZeroSSL",
            "HARICA", "Actalis", "NAVER", "SecureTrust", "XRamp", "Secure Global",
            "COMODO", "AAA Certificate Services", "USERTrust RSA", "USERTrust ECC",
            "Chunghwa Telecom", "Hongkong Post", "Japan Registry", "WISeKey",
            "Buypass", "D-TRUST", "Telia", "Telekom", "Deutsche Telekom",
            "Staat der", "Government", "eID", "Network Solutions",
            "AddTrust", "USERTrust", "SECOM", "Unizeto", "TRKTRUST", "AC RAIZ",
            "Autoridad de Certificacion", "Certigna", "Certinomis", "ACCV",
            "ANF", "A-Trust", "BGC", "BNA", "CFCA", "China Internet", "CNNIC",
            "E-Tugra", "GDCA", "Hellenic", "HongKong Post", "Izenpe", "KISA",
            "KOICA", "Microsec", "NetLock", "OISTE", "PSC", "SK ID", "SSC",
            "StartCom", "TB", "TWCA", "VRK", "WoSign", "SecureSign", "Macao",
            "Atos", "TWCA Root", "emSign", "vTrus", "UCA Global", "TrustAsia",
            "BJCA", "CFCA EV ROOT", "GDCA TrustAUTH"
        };

        /// <summary>
        /// Analyzes a certificate and returns a confidence score + tier + reasoning.
        /// Key insight: ALL root CAs are self-signed by definition, so self-signed alone is NOT suspicious.
        /// We look for multiple corroborating attack indicators: short validity + no CRL + random name + expired.
        /// </summary>
        internal static CertAnalysisResult AnalyzeCert(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
        {
            // Start with LOW base confidence - require MULTIPLE strong indicators to reach action threshold
            double confidence = 0.40;
            var tier = DetectionTier.Tier2Indicator;
            var reasons = new List<string>();

            var subject = cert.Subject ?? string.Empty;
            var issuer = cert.Issuer ?? string.Empty;

            // 1. Self-signed check (Subject == Issuer)
            // NOTE: All root CAs are self-signed! This is NORMAL, not suspicious.
            bool isSelfSigned = subject.Equals(issuer);
            // DO NOT add confidence for self-signed - this is expected for root certs

            // 2. Check for known legitimate public root CA - downgrade to Tier2 immediately
            bool isPublicRootCA = KnownPublicRootCAs.Any(ca =>
                subject.Contains(ca));

            // 3. Known enterprise CA - downgrade to Tier2, reduce confidence
            bool isEnterpriseCa = KnownEnterpriseCAs.Any(ca =>
                subject.Contains(ca));

            // 4. Known dev tool - downgrade to Tier2, reduce confidence
            bool isDevTool = KnownDevToolCAs.Any(dt =>
                subject.Contains(dt));

            // If it's a known legitimate CA (public, enterprise, or dev tool), cap confidence and downgrade tier
            if (isPublicRootCA)
            {
                tier = DetectionTier.Tier2Indicator;
                confidence = Math.Min(confidence, 0.50);
                reasons.Add("Known public root CA");
            }
            else if (isEnterpriseCa)
            {
                tier = DetectionTier.Tier2Indicator;
                confidence = Math.Min(confidence, 0.65);
                reasons.Add("Known enterprise TLS inspection CA");
            }
            else if (isDevTool)
            {
                tier = DetectionTier.Tier2Indicator;
                confidence = Math.Min(confidence, 0.55);
                reasons.Add("Known developer/debugging tool CA");
            }

            // Only apply suspicion signals if NOT a known legitimate CA
            if (!isPublicRootCA && !isEnterpriseCa && !isDevTool)
            {
                // 5. Short validity period (< 1 year - real root CAs are 10-25 years)
                var validity = cert.NotAfter - cert.NotBefore;
                if (validity.TotalDays < 365)
                {
                    confidence += 0.15; // Increased from 0.10 - this is a strong signal
                    reasons.Add($"Short validity ({validity.TotalDays:F0} days, expected 3650+)");
                }

                // 6. Very short validity (< 90 days - highly suspicious for a root CA)
                if (validity.TotalDays < 90)
                {
                    confidence += 0.10; // Increased from 0.05
                    reasons.Add("Extremely short validity (<90 days)");
                }

                // 7. No CRL Distribution Points or Authority Info Access (OCSP)
                // IMPORTANT: Many legitimate *root* CAs intentionally omit CRL/AIA (they are
                // the trust anchor; revocation is for intermediates/leaves). Only score this
                // against short-lived or non-self-signed certs that look like MitM injects.
                bool hasCrl = false;
                bool hasOcsp = false;
                foreach (var ext in cert.Extensions)
                {
                    // OID 2.5.29.31 = CRL Distribution Points
                    if (ext.Oid?.Value == "2.5.29.31") hasCrl = true;
                    // OID 1.3.6.1.5.5.7.1.1 = Authority Information Access (OCSP)
                    if (ext.Oid?.Value == "1.3.6.1.5.5.7.1.1") hasOcsp = true;
                }

                // Long-lived self-signed roots (>=5y) commonly have no CRL/AIA - do not score.
                bool looksLikeLongLivedRoot = isSelfSigned && validity.TotalDays >= 365 * 5;
                if (!hasCrl && !hasOcsp && !looksLikeLongLivedRoot)
                {
                    confidence += 0.15;
                    reasons.Add("No CRL/OCSP distribution points");
                }

                // 8. Generic/random Subject CN - real CAs have well-known names
                var cn = ExtractCN(subject);
                if (!string.IsNullOrEmpty(cn))
                {
                    // Check for very short generic names or hex-like random strings
                    if (cn.Length <= 4)
                    {
                        confidence += 0.10;
                        reasons.Add($"Very short Subject CN: '{cn}'");
                    }
                    else if (cn.Length > 6 && IsHexLike(cn))
                    {
                        confidence += 0.15;
                        reasons.Add($"Random/hex-like Subject CN: '{cn}'");
                    }
                }

                // 9. Already expired - suspicious to install an expired root cert
                if (cert.NotAfter < DateTime.UtcNow)
                {
                    confidence += 0.10;
                    reasons.Add($"Already expired (NotAfter={cert.NotAfter:u})");
                }

                // 10. Suspicious keywords in subject - some malware uses obvious names
                var lowerSubject = subject.ToLowerInvariant();
                if (lowerSubject.Contains("test") || lowerSubject.Contains("fake") ||
                    lowerSubject.Contains("evil") || lowerSubject.Contains("malware") ||
                    lowerSubject.Contains("mitm") || lowerSubject.Contains("proxy"))
                {
                    confidence += 0.10;
                    reasons.Add("Suspicious keywords in Subject");
                }

                // 11. Machine-name CN (hostname pattern) - MitM certs generated by RDP/attack tools
                // Real CAs never have bare hostnames as their CN
                if (!string.IsNullOrEmpty(cn) && IsHostnameLike(cn))
                {
                    confidence += 0.25;
                    reasons.Add($"CN looks like a machine hostname: '{cn}'");
                }

                // 12. Absurd validity (>100 years) - attack certs use 999-year validity
                // No legitimate CA issues certs for more than 25 years
                if (validity.TotalDays > 36500) // >100 years
                {
                    confidence += 0.20;
                    reasons.Add($"Absurd validity period ({validity.TotalDays / 365:F0} years)");
                }
            }

            // 13. EKU capability analysis: Server Auth (TLS intercept), Code Signing (BYOVD/malware),
            // and All-Purpose (no EKU constraint = unrestricted power under RFC 5280).
            bool hasServerAuthEku = false;
                bool hasCodeSigningEku = false;
                bool isAllPurpose = false;
                bool hasEkuExtension = false;

                try
                {
                    foreach (var ext in cert.Extensions)
                    {
                        if (ext is System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension ekuExt)
                        {
                            hasEkuExtension = true;
                            foreach (var oid in ekuExt.EnhancedKeyUsages)
                            {
                                if (oid.Value == "1.3.6.1.5.5.7.3.1") hasServerAuthEku = true;
                                else if (oid.Value == "1.3.6.1.5.5.7.3.3" || oid.Value == "1.3.6.1.4.1.311.61.1.1") hasCodeSigningEku = true;
                                else if (oid.Value == "2.5.29.37.0") isAllPurpose = true;
                            }
                        }
                        else if (ext.Oid?.Value == "2.5.29.37")
                        {
                            hasEkuExtension = true;
                            var ekuText = ext.Format(false);
                            if (ekuText.Contains("1.3.6.1.5.5.7.3.1") || ekuText.IndexOf("Server Authentication", StringComparison.OrdinalIgnoreCase) >= 0)
                                hasServerAuthEku = true;
                            if (ekuText.Contains("1.3.6.1.5.5.7.3.3") || ekuText.Contains("1.3.6.1.4.1.311.61.1.1") ||
                                ekuText.IndexOf("Code Signing", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                ekuText.IndexOf("Potpisivanje koda", StringComparison.OrdinalIgnoreCase) >= 0)
                                hasCodeSigningEku = true;
                            if (ekuText.Contains("2.5.29.37.0") || ekuText.IndexOf("All Purposes", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                ekuText.IndexOf("Any Extended Key Usage", StringComparison.OrdinalIgnoreCase) >= 0)
                                isAllPurpose = true;
                        }
                    }

                    if (!hasEkuExtension)
                    {
                        // RFC 5280: If EKU extension is omitted, cert can be used for ANY purpose
                        isAllPurpose = true;
                    }
                }
                catch { }

                // Score non-public CAs based on high-privilege capabilities:
                if (!isPublicRootCA && !isEnterpriseCa && !isDevTool)
                {
                    if (hasServerAuthEku)
                    {
                        confidence += 0.20;
                        reasons.Add("Root cert has Server Authentication EKU (designed for TLS interception)");
                    }

                    if (hasCodeSigningEku)
                    {
                        confidence += 0.25;
                        reasons.Add("Root cert has Code Signing EKU (driver / binary signing bypass indicator)");
                    }

                    if (isAllPurpose)
                    {
                        confidence += 0.25;
                        reasons.Add("Root cert has no EKU restriction / All-Purpose (unrestricted authority to sign TLS or code)");
                    }
                }

                // Cap confidence at 0.99
                confidence = Math.Min(confidence, 0.99);

                // High confidence unknown certs: promote to Tier1 so response engine acts on them
                if (!isPublicRootCA && !isEnterpriseCa && !isDevTool && confidence >= 0.80)
                {
                    tier = DetectionTier.Tier1Behavioral;
                }

                return new CertAnalysisResult
                {
                    Confidence = confidence,
                    Tier = tier,
                    Reasons = reasons,
                    IsSelfSigned = isSelfSigned,
                    IsPublicRootCa = isPublicRootCA,
                    IsEnterpriseCa = isEnterpriseCa,
                    IsDevTool = isDevTool,
                    HasRevocationInfo = true,
                    HasServerAuthEku = hasServerAuthEku,
                    HasCodeSigningEku = hasCodeSigningEku,
                    IsAllPurpose = isAllPurpose
                };
            }

        /// <summary>
        /// Extracts the CN value from a distinguished name string.
        /// </summary>
        private static string ExtractCN(string distinguishedName)
        {
            // Subject format: "CN=Name, O=Org, ..." - extract CN value
            var parts = distinguishedName.Split(',');
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("CN="))
                    return trimmed.Substring(3).Trim();
            }
            return string.Empty;
        }

        /// <summary>
        /// Checks if a string looks like a random hex/GUID string (common in attack certs).
        /// </summary>
        private static bool IsHexLike(string s)
        {
            int hexChars = 0;
            foreach (char c in s)
            {
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-')
                    hexChars++;
            }
            return hexChars > s.Length * 0.7;
        }

        /// <summary>
        /// Checks if a CN looks like a machine hostname rather than a CA organization name.
        /// Hostnames are typically: DESKTOP-XXXXXXX, WIN-XXXXXXX, LAPTOP-XXXXXXX, or short
        /// uppercase alphanumeric strings without spaces or organization-like structure.
        /// </summary>
        private static bool IsHostnameLike(string cn)
        {
            if (string.IsNullOrEmpty(cn)) return false;
            // Contains spaces/commas/dots = org name, not hostname
            if (cn.IndexOf(' ') >= 0 || cn.IndexOf(',') >= 0 || cn.IndexOf('.') >= 0) return false;
            // Contains CA-like words = not a hostname
            var lower = cn.ToLowerInvariant();
            if (lower.Contains("root") || lower.Contains("ca") || lower.Contains("cert") ||
                lower.Contains("authority") || lower.Contains("trust") || lower.Contains("sign"))
                return false;

            var upper = cn.ToUpperInvariant();
            // Common Windows auto-generated hostname prefixes
            if (upper.StartsWith("WIN-") || upper.StartsWith("DESKTOP-") ||
                upper.StartsWith("LAPTOP-") || upper.StartsWith("WORKSTATION-") ||
                upper.StartsWith("PC-") || upper.StartsWith("SERVER-"))
                return true;
            // Matches local machine name - definitely a self-signed MitM cert
            try
            {
                var machineName = Environment.MachineName;
                if (cn.Equals(machineName))
                    return true;
            }
            catch { }
            // All-caps with dash, 8-15 chars = likely Windows auto-generated hostname
            if (cn.Length >= 8 && cn.Length <= 15 && cn.IndexOf('-') >= 0 &&
                cn.All(c => char.IsLetterOrDigit(c) || c == '-'))
                return true;
            return false;
        }

        /// <summary>
        /// Attempts to trace which process added a cert by querying the Security Event Log
        /// for recent registry write events to the cert store path.
        /// Returns the adder process info if found.
        /// </summary>
        private AdderProcessInfo? TraceAdderProcess(string thumbprint)
        {
            try
            {
                // Security Event ID 4657: A registry value was modified
                // The cert store is at: HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\{thumbprint}
                var log = new System.Diagnostics.EventLog("Security");
                var cutoff = DateTime.UtcNow.AddMinutes(-5);

                // Iterate backwards (most recent first) for efficiency
                for (int i = log.Entries.Count - 1; i >= 0 && i >= log.Entries.Count - 500; i--)
                {
                    try
                    {
                        var entry = log.Entries[i];
                        if (entry.TimeGenerated.ToUniversalTime() < cutoff) break;

                        // Event ID 4657 = Registry value modified (WRITE only)
                        // Do NOT use 4663 (Object access) - it fires on READS too, causing misattribution
                        if (entry.InstanceId != 4657) continue;

                        var message = entry.Message ?? string.Empty;

                        // Check if this event relates to the cert store
                        if (!message.Contains("SystemCertificates") &&
                            !message.Contains("ROOT\\Certificates"))
                            continue;

                        // ONLY match events that contain our specific thumbprint
                        // Do NOT fall back to generic "ROOT\Certificates" matching - that causes
                        // misattribution when legitimate processes (browsers) touch the cert store
                        if (!string.IsNullOrEmpty(thumbprint) &&
                            !message.Contains(thumbprint))
                            continue;

                        // Extract process info from the event
                        var processId = ExtractFieldFromEventMessage(message, "Process ID");
                        var processName = ExtractFieldFromEventMessage(message, "Process Name");

                        if (int.TryParse(processId?.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out int pid) && pid > 4)
                        {
                            return new AdderProcessInfo
                            {
                                ProcessId = pid,
                                ProcessName = processName ?? "Unknown",
                                EventTimestamp = entry.TimeGenerated.ToUniversalTime()
                            };
                        }
                    }
                    catch { continue; }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[TlsCertificateMonitor] Failed to trace cert adder process");
            }

            return null;
        }

        /// <summary>
        /// Extracts a field value from a Windows Event Log message by field label.
        /// Event messages have format "Label:\t\tValue" or "Label:  Value".
        /// </summary>
        private static string? ExtractFieldFromEventMessage(string message, string fieldName)
        {
            var idx = message.IndexOf(fieldName + ":");
            if (idx < 0) return null;

            var start = idx + fieldName.Length + 1;
            if (start >= message.Length) return null;

            // Skip whitespace/tabs
            while (start < message.Length && (message[start] == ' ' || message[start] == '\t'))
                start++;

            var end = start;
            while (end < message.Length && message[end] != '\r' && message[end] != '\n')
                end++;

            return message.Substring(start, end - start).Trim();
        }

        /// <summary>
        /// Emits a detection event for a suspicious certificate.
        /// </summary>
        private async Task EmitCertDetectionAsync(
            System.Security.Cryptography.X509Certificates.X509Certificate2 cert,
            CertAnalysisResult analysis,
            AdderProcessInfo? adderInfo,
            bool isStartupScan,
            ResponseAction? overrideResponse = null)
        {
            var cn = ExtractCN(cert.Subject);
            var scanPhase = isStartupScan ? "Startup scan" : "Runtime detection";
            var reasonsList = string.Join("; ", analysis.Reasons);

            var evidence = $"{scanPhase}: Root cert Subject='{cert.Subject}', " +
                           $"Thumbprint={cert.Thumbprint}, " +
                           $"Validity={cert.NotBefore:yyyy-MM-dd}->{cert.NotAfter:yyyy-MM-dd}, " +
                           $"Signals=[{reasonsList}]";

            if (adderInfo != null)
            {
                evidence += $", Adder='{adderInfo.ProcessName}' PID={adderInfo.ProcessId} at {adderInfo.EventTimestamp:u}";
            }

            var reasoning = $"A new root certificate '{cn}' was added to the machine trust store. ";
            reasoning += "If unauthorized, this could enable TLS interception of HTTPS traffic. ";
            reasoning += $"Assessment signals: {reasonsList}.";

            var metadata = new Dictionary<string, string>
            {
                { "CertThumbprint", cert.Thumbprint },
                { "CertSubject", cert.Subject },
                { "CertIssuer", cert.Issuer },
                { "CertNotBefore", cert.NotBefore.ToString("o") },
                { "CertNotAfter", cert.NotAfter.ToString("o") },
                { "IsSelfSigned", analysis.IsSelfSigned.ToString() },
                { "IsEnterpriseCa", analysis.IsEnterpriseCa.ToString() },
                { "IsDevTool", analysis.IsDevTool.ToString() },
                { "HasRevocationInfo", analysis.HasRevocationInfo.ToString() },
                { "ScanPhase", isStartupScan ? "Startup" : "Runtime" },
                { "HasServerAuthEku", analysis.HasServerAuthEku.ToString() },
                { "HasCodeSigningEku", analysis.HasCodeSigningEku.ToString() },
                { "IsAllPurpose", analysis.IsAllPurpose.ToString() }
            };

            if (adderInfo != null)
            {
                metadata["AdderProcessId"] = adderInfo.ProcessId.ToString();
                metadata["AdderProcessName"] = adderInfo.ProcessName;
            }

            var authorizedResponse = overrideResponse ?? ResponseAction.LogOnly;

            // Startup scans never auto-remove (user may have installed them intentionally)
            // Exception: high-conf MitM plant under MitmDefense (caller sets isStartupScan=false + RemoveCert)
            if (isStartupScan) authorizedResponse = ResponseAction.LogOnly;

            // MitM suite: planted root powers invisible process + fake Chromecast C2
            bool removing = authorizedResponse == ResponseAction.RemoveCert
                         || authorizedResponse == ResponseAction.RemoveCertAndKillAdder;
            if (removing || ProductPosture.AllowsMitmDefenseMutations(_config))
            {
                metadata["MitmDefense"] = "true";
                reasoning += " Part of MitM defense chain: planted root enables TLS intercept and/or " +
                             "trust for a hollowed process that talks to a rogue Cast/fake Chromecast.";
            }

            var tier = analysis.Tier;
            if (removing)
                tier = DetectionTier.Tier1Behavioral;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = removing
                    ? "TLS: MitM Planted Root Certificate - Removing"
                    : "TLS: Suspicious Root Certificate Detected",
                Evidence = evidence,
                Reasoning = reasoning,
                Confidence = analysis.Confidence,
                Tier = tier,
                AuthorizedResponse = authorizedResponse,
                ProcessName = adderInfo?.ProcessName ?? "SYSTEM",
                ProcessId = adderInfo?.ProcessId ?? 0,
                SignalType = SignalType.SecurityEvasion,
                Metadata = metadata
            });
        }


        /// <summary>Result of analyzing a single certificate.</summary>
        internal class CertAnalysisResult
        {
            public double Confidence { get; set; }
            public DetectionTier Tier { get; set; }
            public List<string> Reasons { get; set; } = new();
            public bool IsSelfSigned { get; set; }
            public bool IsPublicRootCa { get; set; }
            public bool IsEnterpriseCa { get; set; }
            public bool IsDevTool { get; set; }
            public bool HasRevocationInfo { get; set; }

            // v2.9.4: certificate capability profile (EKU). Surfaced for operator visibility on
            // every cert; only used to raise confidence on UNKNOWN (non-public/enterprise/dev) CAs.
            /// <summary>Cert asserts Code Signing EKU (OID 1.3.6.1.5.5.7.3.5) - can vouch for signed code/drivers.</summary>
            public bool HasCodeSigningEku { get; set; }
            /// <summary>Cert asserts Server Authentication EKU (OID 1.3.6.1.5.5.7.3.1) - TLS interception surface.</summary>
            public bool HasServerAuthEku { get; set; }
            /// <summary>Cert carries NO EKU extension = trusted for ALL purposes (unconstrained).</summary>
            public bool IsAllPurpose { get; set; }
        }

        /// <summary>Info about the process that added a cert to the store.</summary>
        private class AdderProcessInfo
        {
            public int ProcessId { get; set; }
            public string ProcessName { get; set; } = string.Empty;
            public DateTime EventTimestamp { get; set; }
        }
    }


    // 
    // UAC Bypass Surface Monitor - detects autoelevate binary abuse
    // 
    public sealed class UacBypassSurfaceMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<UacBypassSurfaceMonitor> _logger;

        // Auto-elevate binaries commonly abused for UAC bypass
        private static readonly string[] AutoElevateBinaries = {
            "fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "eventvwr.exe", "slui.exe"
        };

        public UacBypassSurfaceMonitor(DetectionEngine de, ILogger<UacBypassSurfaceMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[UacBypassSurfaceMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);
                    foreach (var binName in AutoElevateBinaries)
                    {
                        var procs = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(binName));
                        foreach (var proc in procs)
                        {
                            try
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "UAC Bypass: Auto-Elevate Binary Launched",
                                    Evidence = $"Auto-elevate binary '{proc.ProcessName}' running (PID {proc.Id})",
                                    Reasoning = "A Windows auto-elevate binary known to be abused for UAC bypass was detected running. Correlate with registry changes.",
                                    Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                                    ProcessName = proc.ProcessName, ProcessId = proc.Id
                                });
                            }
                            catch { }
                            finally { proc.Dispose(); }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[UacBypassSurfaceMonitor] Error"); }
            }
        }
    }


    // 
    // Windows Update Integrity Monitor - WU tampering + patch posture (v2.1.0)
    // LogOnly only - never force install updates (work-first).
    // 
    public sealed class WindowsUpdateIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WindowsUpdateIntegrityMonitor> _logger;
        private readonly ToastService? _toast;
        private DateTime _lastPostureAlert = DateTime.MinValue;
        private DateTime _lastKevAlert = DateTime.MinValue;
        private DateTime _lastMissedPtAlert = DateTime.MinValue;

        // State-change dedup for static posture facts (WU disabled, AU policy blocked). These
        // change rarely; re-emitting them on every 10-min cycle bloats the event log. Only emit
        // on a transition into the bad state; reset when the condition clears so it re-alerts later.
        private readonly Dictionary<string, bool> _lastBadState = new();

        public WindowsUpdateIntegrityMonitor(
            DetectionEngine de,
            ILogger<WindowsUpdateIntegrityMonitor> l,
            ToastService? toast = null)
        {
            _detectionEngine = de;
            _logger = l;
            _toast = toast;
        }

        /// <summary>
        /// True only on a new transition into the bad state for <paramref name="checkKey"/>
        /// (caller should emit). Repeated bad observations are suppressed; a good observation
        /// clears the latch so a future regression re-alerts.
        /// </summary>
        private bool ShouldEmit(string checkKey, bool isBad)
        {
            _lastBadState.TryGetValue(checkKey, out bool wasBad);
            _lastBadState[checkKey] = isBad;
            if (isBad && !wasBad) return true;
            if (!isBad && wasBad)
                _logger.LogInformation("[WindowsUpdateIntegrityMonitor] {Check} recovered (now healthy)", checkKey);
            return false;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WindowsUpdateIntegrityMonitor] Started - service + policy + posture");

            // First posture check after 2 minutes (avoid boot noise)
            try { await Task.Delay(TimeSpan.FromMinutes(2), ct); } catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await CheckWuServiceDisabledAsync().ConfigureAwait(false);
                    await CheckAuPolicyAsync().ConfigureAwait(false);
                    await CheckPostureStaleAsync().ConfigureAwait(false);
                    await CheckKevPatchAsync().ConfigureAwait(false);
                    await CheckMissedPatchTuesdayAsync().ConfigureAwait(false);

                    await Task.Delay(TimeSpan.FromMinutes(10), ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WindowsUpdateIntegrityMonitor] Error"); }
            }
        }

        private async Task CheckWuServiceDisabledAsync()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\wuauserv");
                var startVal = key?.GetValue("Start");
                bool wuDisabled = startVal is int start && start == 4; // Disabled
                if (ShouldEmit("WUServiceDisabled", wuDisabled))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Tampering: Windows Update Service Disabled",
                        Evidence = "wuauserv service Start value is 4 (Disabled)",
                        Reasoning = "Windows Update disabled - blocks security patches (e.g. kernel LPE fixes). Common malware / ransomware technique. Sentinel cannot replace missing OS patches.",
                        Confidence = 0.88,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { ["Posture"] = "WUDisabled" }
                    }).ConfigureAwait(false);
                }
            }
            catch { }
        }

        private async Task CheckAuPolicyAsync()
        {
            try
            {
                // NoAutoUpdate = 1 or AUOptions = 1 (never check) under WindowsUpdate\AU
                using var au = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU");
                if (au == null) return;

                var noAuto = au.GetValue("NoAutoUpdate");
                var auOpts = au.GetValue("AUOptions");
                bool blocked = (noAuto is int n && n == 1) || (auOpts is int o && o == 1);
                if (!ShouldEmit("AUPolicyBlocked", blocked)) return;

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Patch Posture: Automatic Updates Policy Blocked",
                    Evidence = $"WindowsUpdate\\AU NoAutoUpdate={noAuto} AUOptions={auOpts}",
                    Reasoning =
                        "Group Policy / registry disables automatic updates. Host may miss critical patches " +
                        "(including actively exploited kernel bugs). LogOnly - operator must remediate policy.",
                    Confidence = 0.80,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string> { ["Posture"] = "AUPolicyBlocked" }
                }).ConfigureAwait(false);
            }
            catch { }
        }

        private async Task CheckPostureStaleAsync()
        {
            // Rate-limit posture alerts to once per 24h
            if (DateTime.UtcNow - _lastPostureAlert < TimeSpan.FromHours(24))
                return;

            try
            {
                // Auto Update Detection frequency / last success under WindowsUpdate\UX\Settings
                // Fallback: Wuauserv last start is weak - use DetectionFrequency or Servicing stack
                using var ux = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings");
                var lastSuccess = ux?.GetValue("LastSuccessfulScanTimeUtc") ??
                                  ux?.GetValue("LastScanTimeUtc");

                // Alternate: CBS package age is expensive; use WU API-free heuristic -
                // if Suspended or Pause feature updates forever
                var pause = ux?.GetValue("PauseFeatureUpdatesStartTime") ??
                            ux?.GetValue("FlightSettingsMaxPauseDays");

                using var wu = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install");
                var lastInstall = wu?.GetValue("LastSuccessTime") as string;

                bool stale = false;
                string detail = "";
                if (!string.IsNullOrEmpty(lastInstall) &&
                    DateTime.TryParse(lastInstall, out var installDt))
                {
                    var age = DateTime.Now - installDt;
                    if (age > TimeSpan.FromDays(45))
                    {
                        stale = true;
                        detail = $"Last successful update install ~{age.TotalDays:F0} days ago ({lastInstall})";
                    }
                }

                if (!stale) return;

                _lastPostureAlert = DateTime.UtcNow;
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Patch Posture: Security Updates Stale",
                    Evidence = detail,
                    Reasoning =
                        "No successful Windows Update install in >45 days. Kernel and server RCEs " +
                        "(e.g. actively exploited afd.sys LPE) require OS patches Sentinel cannot apply. " +
                        "Install the latest cumulative update. This alert is LogOnly.",
                    Confidence = 0.70,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string> { ["Posture"] = "UpdatesStale" }
                }).ConfigureAwait(false);
            }
            catch { }
        }

        private async Task CheckKevPatchAsync()
        {
            if (DateTime.UtcNow - _lastKevAlert < TimeSpan.FromHours(24))
                return;

            try
            {
                using var cv = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                var buildStr = cv?.GetValue("CurrentBuild") as string ?? cv?.GetValue("CurrentBuildNumber") as string;
                var ubrObj = cv?.GetValue("UBR");
                int.TryParse(buildStr, out var build);
                var ubr = ubrObj is int ui ? ui : (int.TryParse(ubrObj?.ToString(), out var up) ? up : 0);

                DateTime? lastInstall = null;
                using var wu = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install");
                var lastInstallStr = wu?.GetValue("LastSuccessTime") as string;
                if (!string.IsNullOrEmpty(lastInstallStr) && DateTime.TryParse(lastInstallStr, out var dt))
                    lastInstall = dt;

                var eval = August2026CveHeuristics.EvaluateKevAfdPatch(build, ubr, lastInstall);
                if (!eval.Unpatched) return;

                _lastKevAlert = DateTime.UtcNow;
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Patch Posture: KEV unpatched (CVE-2026-68820)",
                    Evidence = eval.Detail,
                    Reasoning =
                        "CISA KEV: CVE-2026-68820 (afd.sys WinSock LPE, exploited by Lazarus). " +
                        "Sentinel cannot patch the kernel race. Install KB5121003 (Win11 build UBR 9168+) and reboot. " +
                        "LogOnly + toast - never force-patches.",
                    Confidence = eval.HighConfidence ? 0.90 : 0.72,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string>
                    {
                        ["Posture"] = "KevUnpatched",
                        ["CVE"] = eval.CveId,
                        ["KB"] = August2026CveHeuristics.August2026KbWin11,
                    }
                }).ConfigureAwait(false);

                try
                {
                    _toast?.ShowCriticalToast(
                        "Sentinel: Windows KEV unpatched",
                        "CVE-2026-68820 (afd.sys) is exploited in the wild. Install this month's Windows Update and reboot.");
                }
                catch { }
            }
            catch { }
        }

        private async Task CheckMissedPatchTuesdayAsync()
        {
            if (DateTime.UtcNow - _lastMissedPtAlert < TimeSpan.FromHours(24))
                return;

            try
            {
                DateTime? lastInstall = null;
                using var wu = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install");
                var lastInstallStr = wu?.GetValue("LastSuccessTime") as string;
                if (!string.IsNullOrEmpty(lastInstallStr) && DateTime.TryParse(lastInstallStr, out var dt))
                    lastInstall = dt;

                var now = DateTime.Now;
                if (!CveCoverageHeuristics.MissedLatestPatchTuesday(lastInstall, now))
                    return;

                var pt = CveCoverageHeuristics.MostRecentPatchTuesday(now);
                _lastMissedPtAlert = DateTime.UtcNow;
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Patch Posture: Missed Patch Tuesday",
                    Evidence = lastInstall.HasValue
                        ? $"Last successful Windows Update install {lastInstall.Value:yyyy-MM-dd} is before Patch Tuesday {pt:yyyy-MM-dd}."
                        : $"No LastSuccessTime; Patch Tuesday {pt:yyyy-MM-dd} has passed the 7-day grace window.",
                    Reasoning =
                        "Host has not applied the latest monthly cumulative update. New CVEs (kernel EoP, installer EoP, " +
                        "browser RCE) require OS patches Sentinel cannot apply. LogOnly + toast - never force-patches.",
                    Confidence = lastInstall.HasValue ? 0.86 : 0.70,
                    Tier = DetectionTier.Tier2Indicator,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "SYSTEM",
                    ProcessId = 0,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string>
                    {
                        ["Posture"] = "MissedPatchTuesday",
                        ["PatchTuesday"] = pt.ToString("yyyy-MM-dd"),
                        ["LastInstall"] = lastInstall?.ToString("yyyy-MM-dd") ?? "",
                    }
                }).ConfigureAwait(false);

                try
                {
                    _toast?.ShowCriticalToast(
                        "Sentinel: Windows Update overdue",
                        "This PC missed the latest Patch Tuesday. Install Windows Updates and reboot - Sentinel cannot patch kernel bugs.");
                }
                catch { }
            }
            catch { }
        }
    }


    // 
    // WMI Persistence Monitor - filter + consumer + binding (T1546.003)
    // v2.2.8: names alone are spoofable. Snapshot the triple across
    // root\subscription and root\default. Hostile CommandLine / ActiveScript
    // consumers are a persistence terminal, not LogOnly wallpaper.
    // 
    public sealed class WmiPersistenceMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WmiPersistenceMonitor> _logger;
        private readonly HashSet<string> _baselineSubscriptions = new(StringComparer.OrdinalIgnoreCase);

        public WmiPersistenceMonitor(DetectionEngine de, ILogger<WmiPersistenceMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WmiPersistenceMonitor] Started - filter/consumer/binding triple");
            SnapshotSubscriptions(_baselineSubscriptions);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    SnapshotSubscriptions(current);
                    foreach (var sub in current.Except(_baselineSubscriptions))
                    {
                        bool hostile = WmiPersistenceSignals.LooksHostile(sub);
                        int pid = WmiPersistenceSignals.TryGetLiveWmiHostPid();
                        if (hostile)
                            WmiPersistenceSignals.MarkHostileObserved();

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = hostile
                                ? "WMI Persistence: Hostile Event Subscription"
                                : "Persistence: New WMI Event Subscription",
                            Evidence = hostile
                                ? $"Hostile WMI persistence object: '{sub}'"
                                : $"New WMI event subscription detected: '{sub}'",
                            Reasoning = hostile
                                ? "A WMI __EventFilter / EventConsumer / __FilterToConsumerBinding was created " +
                                  "whose command or script executes a LOLBin or user-writable payload (T1546.003). " +
                                  "WmiPrvSE.exe / scrcons.exe will run it as SYSTEM with no autorun entry."
                                : "A new WMI event subscription was created. Name-only consumers without an executable " +
                                  "command are observe fuel; the filter+consumer+binding triple is the implant.",
                            Confidence = hostile ? 0.92 : 0.75,
                            Tier = hostile ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = pid > 4 ? "WmiPrvSE.exe" : "SYSTEM",
                            ProcessId = pid,
                            SignalType = SignalType.SecurityEvasion,
                            // Terminal WmiPersistence only for the hostile branch (rule name
                            // "WMI Persistence: Hostile Event Subscription" matches a fragment).
                            // The non-hostile "Persistence: New WMI Event Subscription" matches no
                            // fragment and stays non-terminal today - keep it null.
                            Family = hostile ? (TerminalFamily?)TerminalFamily.WmiPersistence : null,
                            Metadata = new Dictionary<string, string>
                            {
                                { "WmiSnapshotKey", sub },
                                { "HostileConsumer", hostile ? "true" : "false" },
                            }
                        });
                        _baselineSubscriptions.Add(sub);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WmiPersistenceMonitor] Error"); }
            }
        }

        internal static void SnapshotSubscriptions(HashSet<string> target)
        {
            foreach (var ns in WmiPersistenceSignals.SubscriptionNamespaces)
            {
                SnapshotClass(target, ns, "__EventFilter", "filter",
                    o => Combine(o, "Name", "Query"));
                SnapshotClass(target, ns, "CommandLineEventConsumer", "cmdConsumer",
                    o => Combine(o, "Name", "CommandLineTemplate", "ExecutablePath"));
                SnapshotClass(target, ns, "ActiveScriptEventConsumer", "scriptConsumer",
                    o => Combine(o, "Name", "ScriptText", "ScriptingEngine"));
                SnapshotClass(target, ns, "__EventConsumer", "consumer",
                    o => Combine(o, "Name", "__CLASS"));
                SnapshotClass(target, ns, "__FilterToConsumerBinding", "binding",
                    o => Combine(o, "Filter", "Consumer"));
            }
        }

        private static void SnapshotClass(
            HashSet<string> target, string ns, string className, string kind,
            Func<ManagementBaseObject, string> detail)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(ns, "SELECT * FROM " + className);
                searcher.Options.Timeout = TimeSpan.FromSeconds(8);
                foreach (ManagementObject obj in searcher.Get())
                {
                    try
                    {
                        var name = obj["Name"]?.ToString()
                                   ?? obj["Filter"]?.ToString()
                                   ?? obj.GetHashCode().ToString();
                        target.Add(WmiPersistenceSignals.SnapshotKey(kind, ns, name, detail(obj)));
                    }
                    catch { }
                    finally { obj.Dispose(); }
                }
            }
            catch { }
        }

        private static string Combine(ManagementBaseObject obj, params string[] props)
        {
            var parts = new List<string>(props.Length);
            foreach (var p in props)
            {
                try
                {
                    var v = obj[p]?.ToString();
                    if (!string.IsNullOrWhiteSpace(v))
                        parts.Add(v!);
                }
                catch { }
            }
            return string.Join(" ", parts);
        }
    }


    // 
    // WMI Policy Rewrite Monitor - StdRegProv / provider-host policy overwrite
    // v2.2.8: user Policies hives rewritten via WMI have no autorun. Correlate
    // Kernel-Registry writes from WmiPrvSE/wmiadap/scrcons with HKLM/HKU Policies trees.
    // 
    public sealed class WmiPolicyRewriteMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WmiPolicyRewriteMonitor> _logger;
        private string _baselineFingerprint = "";
        private DateTime _lastEmitUtc = DateTime.MinValue;

        public WmiPolicyRewriteMonitor(DetectionEngine de, ILogger<WmiPolicyRewriteMonitor> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WmiPolicyRewriteMonitor] Started - HKLM/HKU Policies attribution");
            _baselineFingerprint = FingerprintPolicyHives();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);
                    var current = FingerprintPolicyHives();
                    if (string.Equals(current, _baselineFingerprint, StringComparison.Ordinal))
                        continue;

                    _baselineFingerprint = current;
                    await OnPolicyHiveChangedAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WmiPolicyRewriteMonitor] Error"); }
            }
        }

        private async Task OnPolicyHiveChangedAsync(CancellationToken ct)
        {
            if (DateTime.UtcNow - _lastEmitUtc < TimeSpan.FromSeconds(20))
                return;

            bool wmiHint = WmiHostRegistryHint.TryGetRecent(TimeSpan.FromSeconds(8), out var hintPid, out var hintName);
            bool recentHostile = WmiPersistenceSignals.HostileObservedRecently(TimeSpan.FromMinutes(5));
            if (!wmiHint && !recentHostile)
                return;

            if (WmiPersistenceSignals.IsSentinelSelfProcess(hintName))
                return;

            int pid = hintPid;
            string procName = string.IsNullOrEmpty(hintName) ? "WmiPrvSE.exe" : hintName;
            if (pid <= 4)
                pid = WmiPersistenceSignals.TryGetLiveWmiHostPid();

            bool chain = wmiHint && recentHostile;
            if (chain)
                WmiPersistenceSignals.MarkHostileObserved();

            _lastEmitUtc = DateTime.UtcNow;
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = chain
                    ? "WMI Persistence + Policy Rewrite"
                    : "WMI Policy Rewrite: Provider Host Wrote Policies",
                Evidence = $"SOFTWARE\\Policies / CurrentVersion\\Policies hive changed. " +
                           $"WriterHint='{procName}' PID={pid} WmiHostRegistryRecent={wmiHint} " +
                           $"HostileSubscriptionRecent={recentHostile}",
                Reasoning = "WMI StdRegProv (hosted in WmiPrvSE.exe / wmiadap.exe / scrcons.exe) can silently " +
                            "overwrite user and machine policy without a .reg file or gpupdate. Combined with a " +
                            "WMI event subscription this is fileless stay-behind plus policy capture.",
                Confidence = chain ? 0.94 : 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = procName,
                ProcessId = pid,
                SignalType = SignalType.SecurityEvasion,
                // Terminal WmiPersistence: both rule-name branches ("WMI Persistence + Policy
                // Rewrite" and "WMI Policy Rewrite: ...") match WmiPersistence fragments today.
                // Preserves current substring classification.
                Family = TerminalFamily.WmiPersistence,
                Metadata = new Dictionary<string, string>
                {
                    { "WmiHostHint", wmiHint ? "true" : "false" },
                    { "HostileSubscriptionRecent", recentHostile ? "true" : "false" },
                }
            });
        }

        /// <summary>
        /// Compact fingerprint of policy hives (HKLM + interactive HKU SIDs). Bounded.
        /// </summary>
        internal static string FingerprintPolicyHives()
        {
            var sb = new StringBuilder(2048);
            AppendKeyFingerprint(sb, Registry.LocalMachine, @"SOFTWARE\Policies");
            AppendKeyFingerprint(sb, Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies");
            try
            {
                using var users = Registry.Users;
                if (users != null)
                {
                    int sidCount = 0;
                    foreach (var sid in users.GetSubKeyNames())
                    {
                        if (sidCount >= 8) break;
                        if (sid == null || !sid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
                            continue;
                        if (sid.IndexOf("_Classes", StringComparison.OrdinalIgnoreCase) >= 0)
                            continue;
                        sidCount++;
                        AppendKeyFingerprint(sb, users, sid + @"\SOFTWARE\Policies");
                        AppendKeyFingerprint(sb, users, sid + @"\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies");
                    }
                }
            }
            catch { }

            return sb.ToString();
        }

        private static void AppendKeyFingerprint(StringBuilder sb, RegistryKey hive, string path)
        {
            try
            {
                using var key = hive.OpenSubKey(path, false);
                if (key == null) return;
                sb.Append(path).Append('=');
                AppendValuesLimited(sb, key, depth: 0);
                sb.Append(';');
            }
            catch { }
        }

        private static void AppendValuesLimited(StringBuilder sb, RegistryKey key, int depth)
        {
            if (depth > 3 || sb.Length > 16000) return;
            try
            {
                foreach (var name in key.GetValueNames())
                {
                    var v = key.GetValue(name);
                    sb.Append(name).Append(':').Append(v).Append('|');
                }
            }
            catch { }

            if (depth >= 2) return;
            try
            {
                int n = 0;
                foreach (var sub in key.GetSubKeyNames())
                {
                    if (n++ >= 24 || sb.Length > 16000) break;
                    try
                    {
                        using var child = key.OpenSubKey(sub, false);
                        if (child == null) continue;
                        sb.Append(sub).Append('/');
                        AppendValuesLimited(sb, child, depth + 1);
                    }
                    catch { }
                }
            }
            catch { }
        }
    }


    // 
    // Work Folders Exfil Monitor - detects mass file sync
    // 
    public sealed class WorkFoldersExfilMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WorkFoldersExfilMonitor> _logger;
        private long _baselineFileCount;

        public WorkFoldersExfilMonitor(DetectionEngine de, ILogger<WorkFoldersExfilMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WorkFoldersExfilMonitor] Started");
            var workFolders = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Work Folders");

            // Baseline file count
            if (Directory.Exists(workFolders))
            {
                try { _baselineFileCount = Directory.EnumerateFiles(workFolders, "*", SearchOption.AllDirectories).LongCount(); }
                catch { _baselineFileCount = 0; }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    if (!Directory.Exists(workFolders)) continue;

                    long currentCount = 0;
                    try { currentCount = Directory.EnumerateFiles(workFolders, "*", SearchOption.AllDirectories).LongCount(); }
                    catch { continue; }

                    // If file count suddenly drops by 50+ files, possible bulk exfiltration/deletion
                    if (_baselineFileCount > 50 && currentCount < _baselineFileCount - 50)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Data Exfiltration: Work Folders Mass File Removal",
                            Evidence = $"Work Folders file count dropped from {_baselineFileCount} to {currentCount} ({_baselineFileCount - currentCount} files removed)",
                            Reasoning = "A large number of files were removed from the Work Folders sync directory in a short period, which may indicate data exfiltration via sync or ransomware activity.",
                            Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                    }
                    // If file count increases dramatically (100+ new files added quickly) - staging for sync exfil
                    else if (currentCount > _baselineFileCount + 100)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Data Exfiltration: Work Folders Mass File Addition",
                            Evidence = $"Work Folders file count increased from {_baselineFileCount} to {currentCount} ({currentCount - _baselineFileCount} files added)",
                            Reasoning = "A large number of files were rapidly added to the Work Folders sync directory, which may indicate data staging for cloud exfiltration.",
                            Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                    }

                    _baselineFileCount = currentCount;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WorkFoldersExfilMonitor] Error"); }
            }
        }
    }


    // 
    // Browser DNS Policy Guard - forces ALL apps to use OS DNS resolver (respects hosts file)
    // 
    public sealed class BrowserDnsPolicyGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BrowserDnsPolicyGuard> _logger;
        private bool _initialEnforcement;
        private DateTime _lastTamperAlert = DateTime.MinValue;

        // Chromium-based browser policy keys (HKLM\SOFTWARE\Policies\...)
        private static readonly (string Key, string Name)[] ChromiumBrowsers = new[]
        {
            (@"SOFTWARE\Policies\Google\Chrome", "Chrome"),
            (@"SOFTWARE\Policies\Microsoft\Edge", "Edge"),
            (@"SOFTWARE\Policies\BraveSoftware\Brave", "Brave"),
            (@"SOFTWARE\Policies\Vivaldi", "Vivaldi"),
            (@"SOFTWARE\Policies\Opera Software\Opera", "Opera"),
            (@"SOFTWARE\Policies\Chromium", "Chromium"),
        };

        // Windows system-level DoH registry
        private const string DnsCacheParamsKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
        private const string EnableAutoDohValue = "EnableAutoDoh";

        // Firefox uses a different mechanism - policies.json or registry
        private const string FirefoxPolicyKey = @"SOFTWARE\Policies\Mozilla\Firefox";
        private const string FirefoxDnsOverHttpsKey = @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS";

        public BrowserDnsPolicyGuard(DetectionEngine de, ILogger<BrowserDnsPolicyGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BrowserDnsPolicyGuard] Started - enforcing OS DNS resolver for all browsers and disabling system DoH");

            await Task.Delay(10000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    bool anyChanged = false;

                    // 1. Disable Windows system-level DoH (EnableAutoDoh = 0)
                    anyChanged |= EnforceSystemDoh();

                    // 2. Enforce all Chromium browsers
                    foreach (var (key, name) in ChromiumBrowsers)
                        anyChanged |= EnforceChromiumPolicy(key, name);

                    // 3. Enforce Firefox
                    anyChanged |= EnforceFirefoxPolicy();

                    if (anyChanged && !_initialEnforcement)
                    {
                        _initialEnforcement = true;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Hardening: System-Wide DNS Policy Enforced",
                            Evidence = "Disabled DNS-over-HTTPS system-wide (Windows DoH + all browser policies). " +
                                       "All DNS resolution now goes through the OS resolver which respects the hosts file.",
                            Reasoning = "DNS-over-HTTPS in browsers and at the OS level bypasses the local hosts file entirely. " +
                                        "Any hosts-file-based blocking (ads, trackers, malware domains) has zero effect when " +
                                        "DoH is active. Sentinel disables DoH at every layer: Windows DNS client, Chrome, Edge, " +
                                        "Brave, Vivaldi, Opera, Chromium, and Firefox. The hosts file becomes the single " +
                                        "authoritative DNS override point.",
                            Confidence = 0.99,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion,
                            Metadata = new Dictionary<string, string>
                            {
                                { "Action", "PolicyEnforced" },
                                { "EnableAutoDoh", "0" },
                                { "BuiltInDnsClientEnabled", "0" },
                                { "DnsOverHttpsMode", "off" },
                                { "Firefox.DNSOverHTTPS.Enabled", "false" }
                            }
                        });
                    }
                    else if (anyChanged && DateTime.UtcNow - _lastTamperAlert > TimeSpan.FromMinutes(5))
                    {
                        _lastTamperAlert = DateTime.UtcNow;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: DNS Policy Reverted and Re-Applied",
                            Evidence = "DNS-over-HTTPS was found re-enabled (system or browser level). Re-enforced.",
                            Reasoning = "Something re-enabled DoH, bypassing the hosts file. Could be a Windows update, " +
                                        "browser update, user action, or malware circumventing DNS-level blocking.",
                            Confidence = 0.80,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion
                        });
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Error"); }

                await Task.Delay(15000, ct);
            }
        }

        /// <summary>
        /// Disables Windows system-level DNS-over-HTTPS.
        /// EnableAutoDoh: 0 = disabled, 2 = enabled.
        /// This ensures the OS DNS client uses plain DNS which reads the hosts file first.
        /// </summary>
        private bool EnforceSystemDoh()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(DnsCacheParamsKey, true);
                if (key == null) return false;

                var current = key.GetValue(EnableAutoDohValue);
                // Force EnableAutoDoh=0 whenever it is not already 0 - INCLUDING when the value
                // is absent. If the value is missing, Windows' default auto-DoH can still send
                // encrypted DNS that bypasses the hosts file and the NRPT rule, so a missing
                // value must be treated as "not enforced" and written explicitly.
                if (current == null || (int)current != 0)
                {
                    key.SetValue(EnableAutoDohValue, 0, RegistryValueKind.DWord);
                    _logger.LogDebug("[BrowserDnsPolicyGuard] Disabled system-level DoH (EnableAutoDoh=0)");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Failed to enforce system DoH");
            }
            return false;
        }

        /// <summary>
        /// Enforces Chromium-based browser policies:
        /// - BuiltInDnsClientEnabled = 0 (use OS resolver)
        /// - DnsOverHttpsMode = "off"
        /// </summary>
        private bool EnforceChromiumPolicy(string policyKey, string browserName)
        {
            bool changed = false;
            try
            {
                // Only create the policy key if the browser is actually installed
                // (check if the parent policy path or browser exe exists)
                using var existingKey = Registry.LocalMachine.OpenSubKey(policyKey, true);
                var key = existingKey ?? Registry.LocalMachine.CreateSubKey(policyKey, true);
                if (key == null) return false;
                // If we created the key fresh, don't report as "changed" (avoids alert spam for uninstalled browsers)
                bool isNewKey = existingKey == null;

                var dnsClient = key.GetValue("BuiltInDnsClientEnabled");
                if (dnsClient == null || (int)dnsClient != 0)
                {
                    key.SetValue("BuiltInDnsClientEnabled", 0, RegistryValueKind.DWord);
                    if (!isNewKey) changed = true;
                    else _logger.LogDebug("[BrowserDnsPolicyGuard] Set BuiltInDnsClientEnabled=0 for {Browser} (new key)", browserName);
                }

                var dohMode = key.GetValue("DnsOverHttpsMode") as string;
                if (dohMode == null || !string.Equals(dohMode, "off"))
                {
                    key.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
                    if (!isNewKey) changed = true;
                    else _logger.LogDebug("[BrowserDnsPolicyGuard] Set DnsOverHttpsMode=off for {Browser} (new key)", browserName);
                }

                if (existingKey == null) key.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Failed to enforce policy for {Browser}", browserName);
            }
            return changed;
        }

        /// <summary>
        /// Enforces Firefox DNS policy via registry:
        /// - DNSOverHTTPS\Enabled = 0 (disable DoH)
        /// - DNSOverHTTPS\Locked = 1 (prevent user from re-enabling)
        /// </summary>
        private bool EnforceFirefoxPolicy()
        {
            bool changed = false;
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(FirefoxDnsOverHttpsKey, true);
                if (key == null) return false;

                var enabled = key.GetValue("Enabled");
                if (enabled == null || (int)enabled != 0)
                {
                    key.SetValue("Enabled", 0, RegistryValueKind.DWord);
                    changed = true;
                    _logger.LogWarning("[BrowserDnsPolicyGuard] Enforced DNSOverHTTPS.Enabled=0 for Firefox");
                }

                var locked = key.GetValue("Locked");
                if (locked == null || (int)locked != 1)
                {
                    key.SetValue("Locked", 1, RegistryValueKind.DWord);
                    changed = true;
                    _logger.LogWarning("[BrowserDnsPolicyGuard] Enforced DNSOverHTTPS.Locked=1 for Firefox");
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Failed to enforce Firefox policy");
            }
            return changed;
        }
    }


    // 
    // Hosts File Guard - monitors hosts file for suspicious modifications (malware indicators)
    // Users may freely edit the hosts file; only MitM-defense lines are enforced when enabled.
    // 
    public sealed class HostsFileGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<HostsFileGuard> _logger;
        // v2.8.7: runtime-mutable blocklist. HostsFileGuard enforces the UNION of the static
        // SentinelConfig.EnforcedDomainBlocks/EnforcedIpBlocks arrays and this service's entries,
        // and tears down any block that has since been removed from both. Optional so existing
        // tests that construct the guard without it keep working.
        private readonly RuntimeBlocklistService? _runtimeBlocklist;
        private FileSystemWatcher? _watcher;

        private static readonly string DriversEtcPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "drivers", "etc");

        private static readonly string HostsFilePath = Path.Combine(DriversEtcPath, "hosts");

        // Debounce to avoid alert storms on rapid writes
        private readonly ConcurrentDictionary<string, DateTime> _eventCooldown = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan CooldownPeriod = TimeSpan.FromSeconds(5);

        private readonly SemaphoreSlim _scanLock = new(1, 1);

        // Previous file hash - used to detect actual changes (not just watcher noise)
        private string _lastKnownHash = string.Empty;

        // Enforced hosts baseline: the standard localhost/loopback header only.
        //
        // v2.7.6: the forum.hr blackhole (apex + subdomains) was REMOVED. The generic
        // baseline-enforcement mechanism is kept - it appends any missing baseline line and
        // preserves all other user content - so a future domain block can be reintroduced by
        // adding "0.0.0.0 <host>" lines here (plus an NRPT rule via BuildDomainNrptRule). No
        // domain is blocked by default. Works because BrowserDnsPolicyGuard disables DoH,
        // making the hosts file the authoritative DNS override point.
        private static readonly string[] HostsBaselineLines = new[]
        {
            // Localhost / loopback header
            "127.0.0.1 localhost",
            "127.0.0.1 localhost.localdomain",
            "127.0.0.1 local",
            "255.255.255.255 broadcasthost",
            "::1 localhost",
            "::1 ip6-localhost",
            "::1 ip6-loopback",
            "fe80::1%lo0 localhost",
            "ff00::0 ip6-localnet",
            "ff00::0 ip6-mcastprefix",
            "ff02::1 ip6-allnodes",
            "ff02::2 ip6-allrouters",
            "ff02::3 ip6-allhosts",
            "0.0.0.0 0.0.0.0",
        };

        // Generic wildcard DNS-policy (NRPT) capability, kept for future domain blocks.
        // The hosts file can only match exact hostnames; the Name Resolution Policy Table
        // supports a leading-dot suffix match (".example.com" matches the apex + all
        // subdomains) pointed at a sinkhole. Policy-scope NRPT (the GP-managed hive) is the
        // authoritative override the DNS client honors - the same hive BrowserDnsPolicyGuard
        // uses for its DoH policy. No rule is created by default in v2.7.6.
        private const string DnsPolicyConfigKey =
            @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

        // Test-visible accessors (InternalsVisibleTo Sentinel.Tests). These let tests assert the
        // enforced content without touching the live hosts file or registry.
        internal static IReadOnlyList<string> HostsBaselineLinesForTest => HostsBaselineLines;
        internal static string DnsPolicyConfigKeyForTest => DnsPolicyConfigKey;

        /// <summary>
        /// Whether the hosts-baseline proactive host mutation (localhost header enforcement +
        /// retired-artifact cleanup) is permitted. Follows the always-on hardening posture
        /// (<see cref="ProductPosture.AllowsProactiveHostLockdown"/>), so a null/default config
        /// still allows it. Exposed for the default-deny test.
        /// </summary>
        internal static bool MayEnforceHostsBaseline(SentinelConfig? config) =>
            ProductPosture.AllowsProactiveHostLockdown(config);

        // MitM defense: FCM mtalk lines that must remain present when MitmDefense is active
        private readonly bool _enforceMitmLines;
        private static readonly string[] MitmRequiredLines = new[]
        {
            "0.0.0.0 mtalk.google.com",
            "0.0.0.0 mobile-gtalk.l.google.com",
            "0.0.0.0 alt1-mtalk.google.com",
            "0.0.0.0 alt2-mtalk.google.com",
            "0.0.0.0 alt3-mtalk.google.com",
            "0.0.0.0 alt4-mtalk.google.com",
            "0.0.0.0 alt5-mtalk.google.com",
            "0.0.0.0 alt6-mtalk.google.com",
            "0.0.0.0 alt7-mtalk.google.com",
            "0.0.0.0 alt8-mtalk.google.com",
        };

        // Patterns that indicate malware DNS hijacking (not legitimate user edits)
        private static readonly string[] SuspiciousRedirectTargets = new[]
        {
            // Known malware/C2 IP patterns - redirecting legitimate domains to these is suspicious
            "185.215.", "194.180.", "91.215.", "45.133.", "23.106.",
            "193.233.", "77.91.", "79.137.", "94.232.", "5.42.",
        };

        // Domains that should never be redirected away from their real IPs -
        // if someone points these at 127.0.0.1 or another IP, it's likely malware blocking security updates
        private static readonly HashSet<string> ProtectedDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            // Windows Update
            "windowsupdate.com", "update.microsoft.com", "download.microsoft.com",
            "windowsupdate.microsoft.com", "ntservicepack.microsoft.com",
            // Security vendors
            "microsoft.com", "defender.microsoft.com",
            "virustotal.com", "malwarebytes.com", "kaspersky.com",
            "avast.com", "avg.com", "eset.com", "bitdefender.com",
            "norton.com", "symantec.com", "mcafee.com", "trendmicro.com",
            // Certificate revocation
            "ocsp.digicert.com", "crl.microsoft.com", "ocsp.msocsp.com",
            "mscrl.microsoft.com", "crl3.digicert.com", "crl4.digicert.com",
        };

        public HostsFileGuard(DetectionEngine de, SentinelConfig config, ILogger<HostsFileGuard> l,
            RuntimeBlocklistService? runtimeBlocklist = null)
        {
            _detectionEngine = de;
            _config = config;
            _logger = l;
            _runtimeBlocklist = runtimeBlocklist;
            _enforceMitmLines = config.BlockFcmPushChannel
                || (config.MitmDefense?.Enabled == true && config.MitmDefense.BlockFcmPushChannel);
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation(
                "[HostsFileGuard] Started - monitoring hosts file for suspicious modifications (MitM enforce={MitM}) in {Path}",
                _enforceMitmLines, DriversEtcPath);

            if (!Directory.Exists(DriversEtcPath))
            {
                _logger.LogError("[HostsFileGuard] Directory not found: {Path}", DriversEtcPath);
                return;
            }

            // Capture initial baseline hash
            _lastKnownHash = ComputeFileHash(HostsFilePath);

            // Enforce the localhost/loopback hosts baseline on startup.
            await EnsureHostsBaselineAsync("Startup", ct);

            // v2.8.7: the automatic forum.hr cleanup (CleanupRetiredForumHrArtifacts) was REMOVED
            // from the startup path. Machines are no longer blindly un-blocked. Un-blocking is now
            // a deliberate act: a block is torn down only when it drops out of the desired set
            // (config array or RuntimeBlocklistService) via RemoveStaleDomainBlocks. forum.hr is
            // re-seeded as a default block by RuntimeBlocklistService on first run.

            // Enforce the union of operator-config + runtime blocklist (forum.hr seeded by default).
            await EnforceConfiguredBlocks("Startup", ct);

            // If MitM defense is active, ensure the FCM lines are present on startup
            if (_enforceMitmLines)
                await EnsureMitmLinesAsync("Startup", ct);

            // Set up FileSystemWatcher
            StartWatcher();

            // Periodic scan (catches offline modifications)
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    await ScanHostsFileAsync("PeriodicCheck", ct);
                    // Re-assert operator-defined domain + IP blocks (self-heal on tamper).
                    await EnforceConfiguredBlocks("PeriodicCheck", ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[HostsFileGuard] Periodic check error");
                }
            }

            DisposeWatcher();
        }

        /// <summary>
        /// Scans hosts file for suspicious entries. Does NOT overwrite user content.
        /// Only enforces MitM-defense lines when that feature is enabled.
        /// </summary>
        private async Task ScanHostsFileAsync(string trigger, CancellationToken ct)
        {
            await _scanLock.WaitAsync(ct);
            try
            {
                if (!File.Exists(HostsFilePath)) return;

                // Check if file actually changed
                var currentHash = ComputeFileHash(HostsFilePath);
                if (string.Equals(currentHash, _lastKnownHash))
                    return;

                _lastKnownHash = currentHash;

                // Read and analyze the hosts file
                var lines = await ReadHostsFileSafe();
                if (lines == null) return;

                await AnalyzeForSuspiciousEntries(lines, trigger, ct);

                // Re-enforce the localhost/loopback baseline if any line was removed
                await EnsureHostsBaselineAsync(trigger, ct);

                // If MitM defense is active, ensure FCM lines haven't been removed
                if (_enforceMitmLines)
                    await EnsureMitmLinesAsync(trigger, ct);
            }
            finally
            {
                _scanLock.Release();
            }
        }

        private async Task AnalyzeForSuspiciousEntries(string[] lines, string trigger, CancellationToken ct)
        {
            var suspiciousEntries = new List<string>();

            foreach (var rawLine in lines)
            {
                var line = rawLine.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                    continue;

                // Parse: <ip> <hostname> [<hostname2> ...]
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;

                var ip = parts[0];

                for (int i = 1; i < parts.Length; i++)
                {
                    var hostname = parts[i];
                    if (hostname.StartsWith("#")) break; // inline comment

                    // Check 1: Is a protected domain being redirected?
                    if (IsProtectedDomain(hostname) && !IsLoopback(ip))
                    {
                        suspiciousEntries.Add($"Protected domain '{hostname}' redirected to {ip}");
                    }

                    // Check 2: Is any domain being redirected to a known malicious IP range?
                    if (IsSuspiciousIp(ip))
                    {
                        suspiciousEntries.Add($"Domain '{hostname}' redirected to suspicious IP {ip}");
                    }
                }
            }

            if (suspiciousEntries.Count > 0)
            {
                var evidence = string.Join("; ", suspiciousEntries.Take(10));
                var (pid, processName) = GetModifyingProcess(HostsFilePath);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Hosts File: Suspicious DNS Redirect Detected",
                    Evidence = $"Hosts file contains {suspiciousEntries.Count} suspicious entries (trigger: {trigger}). " +
                               $"Examples: {evidence}. Last modifier: {processName} (PID {pid})",
                    Reasoning = "Malware modifies the hosts file to redirect security update domains, " +
                                "antivirus update servers, or legitimate sites to C2/phishing IPs. " +
                                "Sentinel monitors for known malicious patterns without overwriting user content.",
                    Confidence = suspiciousEntries.Count >= 3 ? 0.92 : 0.75,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = (pid > 0 && suspiciousEntries.Count >= 3)
                        ? ResponseAction.KillProcessTree : ResponseAction.LogOnly,
                    ProcessName = processName,
                    ProcessId = pid,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string>
                    {
                        { "File", "hosts" },
                        { "Trigger", trigger },
                        { "SuspiciousCount", suspiciousEntries.Count.ToString() }
                    }
                });
            }
        }

        /// <summary>
        /// Ensures the enforced hosts baseline is present: the localhost/loopback header only.
        /// Domain blocks (e.g. forum.hr) are NOT part of this baseline - they are applied
        /// separately via EnforceConfiguredBlocks from the config + runtime blocklist union.
        /// Appends any missing baseline lines and does NOT touch other user content.
        /// </summary>
        private async Task EnsureHostsBaselineAsync(string trigger, CancellationToken ct)
        {
            // Proactive host mutation (writing the hosts file) - gated on the always-on
            // hardening posture. AllowsProactiveHostLockdown returns true unconditionally
            // (v2.5.5+), so the baseline is always enforced, but the gate makes the intent
            // explicit and gives a single seam that a future posture change would honor.
            if (!MayEnforceHostsBaseline(_config)) return;

            try
            {
                var content = await ReadHostsFileSafe();
                if (content == null) return;

                var existingLines = new HashSet<string>(
                    content.Select(l => l.Trim()),
                    StringComparer.OrdinalIgnoreCase);

                var missingLines = HostsBaselineLines
                    .Where(l => !existingLines.Contains(l))
                    .ToList();

                if (missingLines.Count == 0) return;

                _logger.LogWarning(
                    "[HostsFileGuard] Restoring {Count} missing hosts baseline line(s) (localhost header) (trigger: {Trigger})",
                    missingLines.Count, trigger);

                var appendText = "\r\n# Sentinel - enforced hosts baseline (localhost header; do not remove)\r\n" +
                                 string.Join("\r\n", missingLines) + "\r\n";

                for (int i = 0; i < 3; i++)
                {
                    try
                    {
                        File.AppendAllText(HostsFilePath, appendText, new UTF8Encoding(false));
                        break;
                    }
                    catch (IOException) when (i < 2)
                    {
                        await Task.Delay(500, ct);
                    }
                }

                // Update hash after our own write so the change isn't flagged as tampering
                _eventCooldown[HostsFilePath] = DateTime.UtcNow;
                _lastKnownHash = ComputeFileHash(HostsFilePath);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Hosts File: Baseline Restored (localhost header)",
                    Evidence = $"{missingLines.Count} enforced hosts baseline line(s) (localhost/loopback header) " +
                               $"were missing from the hosts file and have been re-appended (trigger: {trigger}).",
                    Reasoning = "The hosts file enforces a standard localhost/loopback header. Removal of these " +
                                "lines can break local name resolution or indicate tampering, so the baseline is " +
                                "self-healed. No external domain is blocked by this baseline.",
                    Confidence = 0.85,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "Sentinel",
                    ProcessId = System.Net48Environment.ProcessId,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string>
                    {
                        { "File", "hosts" },
                        { "Trigger", trigger },
                        { "MissingLines", missingLines.Count.ToString() }
                    }
                });
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] EnsureHostsBaseline error");
            }
        }

        // v2.8.7: CleanupRetiredForumHrArtifacts (the automatic startup un-block of forum.hr)
        // was removed. Un-blocking only tears down the NRPT rule (and firewall rules for IPs).
        // Hosts-file sinkhole entries are NEVER cleared to ensure threats cannot auto-allow themselves.
        // forum.hr is re-seeded as a default block by RuntimeBlocklistService on first run.

        /// <summary>
        /// Generic, reusable NRPT wildcard-block builder kept for FUTURE domain blocks (the
        /// forum.hr-specific caller was removed in v2.7.6). Creates/repairs an NRPT rule under
        /// the GP-managed DnsPolicyConfig hive that sinkholes <paramref name="domainSuffix"/>
        /// (leading-dot suffix, e.g. ".example.com" -> apex + all subdomains) to 0.0.0.0.
        /// No caller invokes this by default; wire it up with a concrete domain + a stable
        /// rule GUID when a new block is needed. Returns true if a change was written.
        /// </summary>
        internal bool BuildDomainNrptRule(string ruleGuid, string domainSuffix, string sinkhole = "0.0.0.0")
        {
            if (!MayEnforceHostsBaseline(_config)) return false;
            if (string.IsNullOrWhiteSpace(ruleGuid) || string.IsNullOrWhiteSpace(domainSuffix)) return false;

            try
            {
                using var policyRoot = Registry.LocalMachine.CreateSubKey(DnsPolicyConfigKey, true);
                if (policyRoot == null) return false;
                using var rule = policyRoot.CreateSubKey(ruleGuid, true);
                if (rule == null) return false;

                bool changed = false;
                var name = rule.GetValue("Name") as string[];
                if (name == null || name.Length != 1 ||
                    !string.Equals(name[0], domainSuffix, StringComparison.OrdinalIgnoreCase))
                {
                    rule.SetValue("Name", new[] { domainSuffix }, RegistryValueKind.MultiString);
                    changed = true;
                }
                if (rule.GetValue("Version") is not int v || v != 2)
                {
                    rule.SetValue("Version", 2, RegistryValueKind.DWord); changed = true;
                }
                if (rule.GetValue("ConfigOptions") is not int co || co != 0x8)
                {
                    rule.SetValue("ConfigOptions", 0x8, RegistryValueKind.DWord); changed = true;
                }
                if (rule.GetValue("GenericDNSServers") as string != sinkhole)
                {
                    rule.SetValue("GenericDNSServers", sinkhole, RegistryValueKind.String); changed = true;
                }
                if (rule.GetValue("IPSECCARestriction") == null)
                {
                    rule.SetValue("IPSECCARestriction", "", RegistryValueKind.String); changed = true;
                }

                if (changed) { try { DnsFlushResolverCache(); } catch { } }
                return changed;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] BuildDomainNrptRule error");
                return false;
            }
        }

        // 
        // v2.7.6: Operator-defined reusable blocks (empty by default). Domain blocks reuse the
        // proven forum.hr path (hosts line + wildcard NRPT + DoH-off authority). IP blocks use
        // inbound/outbound Windows Firewall rules. Both gate on the always-on hardening posture.
        // 

        // Track applied artifacts so we only write/log on change (idempotent self-heal) and so we
        // can tear a block down when it is later removed from the desired set (explicit unblock).
        private readonly HashSet<string> _appliedIpBlocks = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _appliedDomains = new(StringComparer.OrdinalIgnoreCase);
        private const string EnforcedIpBlockRulePrefix = "Sentinel-EnforcedIpBlock-";

        /// <summary>
        /// Test seam / posture gate for the operator-defined block enforcement. Follows the
        /// always-on hardening posture, so a null/default config still authorizes it (there is
        /// simply nothing to enforce when the lists are empty). Exposed for the default-deny test.
        /// </summary>
        internal static bool MayEnforceConfiguredBlocks(SentinelConfig? config) =>
            ProductPosture.AllowsProactiveHostLockdown(config);

        /// <summary>
        /// Derives a stable, Sentinel-owned NRPT rule GUID from a domain so the same domain
        /// always maps to the same rule (find/repair/remove). Pure and testable.
        /// </summary>
        internal static string NrptRuleGuidForDomain(string domain)
        {
            using var md5 = System.Security.Cryptography.MD5.Create();
            var hash = md5.ComputeHash(Encoding.UTF8.GetBytes("Sentinel-EnforcedDomainBlock|" + domain.Trim().ToLowerInvariant()));
            return new Guid(hash).ToString("B"); // {xxxxxxxx-....}
        }

        /// <summary>Normalizes a config domain to a bare lowercase host (strips scheme/path/port).</summary>
        internal static string? NormalizeBlockDomain(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            var d = raw!.Trim().ToLowerInvariant();
            int scheme = d.IndexOf("://", StringComparison.Ordinal);
            if (scheme >= 0) d = d.Substring(scheme + 3);
            d = d.Split('/')[0].Split(':')[0].TrimStart('.');
            return string.IsNullOrWhiteSpace(d) ? null : d;
        }

        private async Task EnforceConfiguredBlocks(string trigger, CancellationToken ct)
        {
            if (!MayEnforceConfiguredBlocks(_config)) return;

            // Desired set = UNION of the static operator config arrays and the runtime blocklist
            // service (empty when the service is not wired in, e.g. some tests). Normalized so
            // config + runtime entries dedupe identically.
            var desiredDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in _config?.EnforcedDomainBlocks ?? Array.Empty<string>())
            {
                var d = NormalizeBlockDomain(raw);
                if (d != null) desiredDomains.Add(d);
            }
            var desiredIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in _config?.EnforcedIpBlocks ?? Array.Empty<string>())
            {
                var ip = raw?.Trim();
                if (!string.IsNullOrEmpty(ip)) desiredIps.Add(ip!);
            }
            if (_runtimeBlocklist != null)
            {
                foreach (var d in _runtimeBlocklist.GetBlockedDomains()) desiredDomains.Add(d);
                foreach (var ip in _runtimeBlocklist.GetBlockedIps()) desiredIps.Add(ip);
            }

            // Tear down NRPT rule / firewall blocks for entries no longer desired.
            // Note: hosts-file entries are never cleared so threats cannot auto-allow themselves.
            RemoveStaleDomainBlocks(desiredDomains, trigger);
            RemoveStaleIpBlocks(desiredIps, trigger);

            if (desiredDomains.Count == 0 && desiredIps.Count == 0) return; // nothing to enforce

            // --- Domain blocks: hosts line (exact) + wildcard NRPT (apex + subdomains) ---
            var missingHostLines = new List<string>();
            foreach (var domain in desiredDomains)
            {
                // NRPT wildcard rule (leading-dot suffix) with a stable per-domain GUID.
                BuildDomainNrptRule(NrptRuleGuidForDomain(domain), "." + domain);
                _appliedDomains.Add(domain);

                // Hosts lines for the apex + www (exact-match layer alongside the NRPT wildcard).
                foreach (var host in new[] { domain, "www." + domain })
                    missingHostLines.Add("0.0.0.0 " + host);
            }

            if (missingHostLines.Count > 0)
            {
                try
                {
                    var content = await ReadHostsFileSafe();
                    if (content != null)
                    {
                        var existing = new HashSet<string>(content.Select(l => l.Trim()), StringComparer.OrdinalIgnoreCase);
                        var toAppend = missingHostLines.Where(l => !existing.Contains(l)).Distinct().ToList();
                        if (toAppend.Count > 0)
                        {
                            var appendText = "\r\n# Sentinel - enforced domain blocks (do not remove)\r\n" +
                                             string.Join("\r\n", toAppend) + "\r\n";
                            for (int i = 0; i < 3; i++)
                            {
                                try { File.AppendAllText(HostsFilePath, appendText, new UTF8Encoding(false)); break; }
                                catch (IOException) when (i < 2) { await Task.Delay(500, ct); }
                            }
                            _eventCooldown[HostsFilePath] = DateTime.UtcNow;
                            _lastKnownHash = ComputeFileHash(HostsFilePath);
                            _logger.LogWarning(
                                "[HostsFileGuard] Enforced {N} domain-block hosts line(s) (trigger: {Trigger})",
                                toAppend.Count, trigger);
                        }
                    }
                }
                catch (Exception ex) { _logger.LogDebug(ex, "[HostsFileGuard] EnforceConfiguredBlocks (domain hosts) error"); }
            }

            // --- IP blocks: inbound + outbound firewall block rules ---
            foreach (var ip in desiredIps)
            {
                if (_appliedIpBlocks.Contains(ip)) continue;
                if (EnsureIpFirewallBlock(ip))
                {
                    _appliedIpBlocks.Add(ip);
                    _logger.LogWarning("[HostsFileGuard] Enforced firewall IP block {IP} (trigger: {Trigger})", ip, trigger);
                    _ = _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Hardening: Operator IP Block Enforced",
                        Evidence = $"Inbound + outbound Windows Firewall block rules applied for IP {ip} (trigger: {trigger}).",
                        Reasoning = "A listed IP is blocked at the firewall (both directions). This is a " +
                                    "config/runtime-driven hardening block, not a detection - empty by default; only " +
                                    "IPs explicitly listed (operator config or runtime blocklist) are blocked.",
                        Confidence = 0.99,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string>
                        {
                            { "Action", "FirewallBlock" },
                            { "TargetIP", ip },
                            { "Trigger", trigger }
                        }
                    });
                }
            }
        }

        /// <summary>
        /// Removes the NRPT rule for any domain we previously applied that is no longer in the
        /// desired set (an explicit unblock).
        /// Note: hosts-file lines are NEVER cleared/stripped - once sinkholed in hosts to 0.0.0.0,
        /// entries remain intact so threats and malware cannot auto-allow themselves.
        /// </summary>
        private void RemoveStaleDomainBlocks(HashSet<string> desired, string trigger)
        {
            var stale = _appliedDomains.Where(d => !desired.Contains(d)).ToList();
            if (stale.Count == 0) return;

            foreach (var domain in stale)
            {
                // Delete the wildcard NRPT rule for this domain.
                RemoveDomainNrptRule(NrptRuleGuidForDomain(domain));
                _appliedDomains.Remove(domain);
            }

            _logger.LogWarning(
                "[HostsFileGuard] Removed domain NRPT rule(s) [{Domains}] on unblock (hosts lines preserved) (trigger: {Trigger})",
                string.Join(", ", stale), trigger);
        }

        /// <summary>Removes an NRPT wildcard rule by its Sentinel-owned GUID. Idempotent/best-effort.</summary>
        private void RemoveDomainNrptRule(string ruleGuid)
        {
            try
            {
                using var policyRoot = Registry.LocalMachine.OpenSubKey(DnsPolicyConfigKey, true);
                if (policyRoot == null) return;
                if (Array.IndexOf(policyRoot.GetSubKeyNames(), ruleGuid) < 0) return;
                policyRoot.DeleteSubKeyTree(ruleGuid, throwOnMissingSubKey: false);
                try { DnsFlushResolverCache(); } catch { }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[HostsFileGuard] RemoveDomainNrptRule error"); }
        }

        /// <summary>
        /// Removes firewall rules for any IP we previously applied that is no longer desired.
        /// </summary>
        private void RemoveStaleIpBlocks(HashSet<string> desired, string trigger)
        {
            var stale = _appliedIpBlocks.Where(ip => !desired.Contains(ip)).ToList();
            foreach (var ip in stale)
            {
                if (RemoveIpFirewallBlock(ip))
                {
                    _appliedIpBlocks.Remove(ip);
                    _logger.LogWarning("[HostsFileGuard] Removed firewall IP block {IP} on unblock (trigger: {Trigger})", ip, trigger);
                }
            }
        }

        /// <summary>Deletes the inbound + outbound Sentinel firewall rules for an IP. Best-effort.</summary>
        private bool RemoveIpFirewallBlock(string ip)
        {
            try
            {
                var safeLabel = ip.Replace(':', '_').Replace('.', '_');
                var ruleName = EnforcedIpBlockRulePrefix + safeLabel;
                foreach (var dir in new[] { "OUT", "IN" })
                {
                    var psi = new ProcessStartInfo("netsh",
                        $"advfirewall firewall delete rule name=\"{ruleName}-{dir}\"")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(15000);
                }
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] RemoveIpFirewallBlock failed for {IP}", ip);
                return false;
            }
        }

        /// <summary>
        /// Applies inbound + outbound Windows Firewall block rules for a single IP. Refuses
        /// loopback / broadcast / invalid addresses (never self-inflict a lockout). Modeled on
        /// CastDeviceGuard's block helper. Returns true if rules were applied.
        /// </summary>
        private bool EnsureIpFirewallBlock(string ip)
        {
            if (!System.Net.IPAddress.TryParse(ip, out var parsed) ||
                System.Net.IPAddress.IsLoopback(parsed) ||
                parsed.Equals(System.Net.IPAddress.Broadcast) ||
                parsed.Equals(System.Net.IPAddress.Any))
            {
                _logger.LogDebug("[HostsFileGuard] Refusing firewall block for invalid/reserved IP: {IP}", ip);
                return false;
            }

            try
            {
                var safeLabel = ip.Replace(':', '_').Replace('.', '_');
                var ruleName = EnforcedIpBlockRulePrefix + safeLabel;

                foreach (var dir in new[] { "out", "in" })
                {
                    var psi = new ProcessStartInfo("netsh",
                        $"advfirewall firewall add rule name=\"{ruleName}-{dir.ToUpperInvariant()}\" dir={dir} action=block remoteip={ip} enable=yes")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(15000);
                }
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] EnsureIpFirewallBlock failed for {IP}", ip);
                return false;
            }
        }

        /// <summary>
        /// When MitM defense is active, ensures the FCM mtalk blocking lines are present.
        /// Appends them if missing - does NOT touch any other user content.
        /// </summary>
        private async Task EnsureMitmLinesAsync(string trigger, CancellationToken ct)
        {
            try
            {
                var content = await ReadHostsFileSafe();
                if (content == null) return;

                var existingLines = new HashSet<string>(
                    content.Select(l => l.Trim()),
                    StringComparer.OrdinalIgnoreCase);

                var missingLines = MitmRequiredLines
                    .Where(l => !existingLines.Contains(l))
                    .ToList();

                if (missingLines.Count == 0) return;

                // Append missing MitM lines - preserve everything else
                _logger.LogWarning(
                    "[HostsFileGuard] MitM defense active - appending {Count} missing FCM block lines (trigger: {Trigger})",
                    missingLines.Count, trigger);

                var appendText = "\r\n# Sentinel MitM Defense - FCM push channel block (do not remove while MitmDefense is enabled)\r\n" +
                                 string.Join("\r\n", missingLines) + "\r\n";

                for (int i = 0; i < 3; i++)
                {
                    try
                    {
                        File.AppendAllText(HostsFilePath, appendText, new UTF8Encoding(false));
                        break;
                    }
                    catch (IOException) when (i < 2)
                    {
                        await Task.Delay(500, ct);
                    }
                }

                // Update hash after our write
                _eventCooldown[HostsFilePath] = DateTime.UtcNow;
                _lastKnownHash = ComputeFileHash(HostsFilePath);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "MitM Defense: FCM Hosts Lines Restored",
                    Evidence = $"MitM defense is active but {missingLines.Count} FCM blocking lines were missing from hosts. " +
                               $"Lines have been re-appended (trigger: {trigger}).",
                    Reasoning = "When MitmDefense is enabled, the FCM push channel (mtalk.google.com) must be " +
                                "blocked in hosts to prevent 'Send Tab to Self' attacks after Chrome token theft. " +
                                "Removal of these lines while MitmDefense is active indicates tampering.",
                    Confidence = 0.85,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = "Sentinel",
                    ProcessId = System.Net48Environment.ProcessId,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string>
                    {
                        { "File", "hosts" },
                        { "Trigger", trigger },
                        { "MissingLines", missingLines.Count.ToString() }
                    }
                });
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] EnsureMitmLines error");
            }
        }

        private static bool IsProtectedDomain(string hostname)
        {
            foreach (var domain in ProtectedDomains)
            {
                if (string.Equals(hostname, domain, StringComparison.OrdinalIgnoreCase) ||
                    hostname.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private static bool IsSuspiciousIp(string ip)
        {
            foreach (var prefix in SuspiciousRedirectTargets)
            {
                if (ip.StartsWith(prefix, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }

        private static bool IsLoopback(string ip)
        {
            return ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0";
        }

        private static async Task<string[]?> ReadHostsFileSafe()
        {
            try
            {
                // Use FileShare.ReadWrite so we don't block other editors
                using var stream = File.Open(HostsFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(stream, Encoding.UTF8);
                var text = await reader.ReadToEndAsync();
                return text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            }
            catch { return null; }
        }

        private void StartWatcher()
        {
            try
            {
                _watcher = new FileSystemWatcher(DriversEtcPath)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size,
                    Filter = "hosts",
                    IncludeSubdirectories = false,
                    EnableRaisingEvents = true
                };

                _watcher.Changed += OnHostsChanged;

                _logger.LogInformation("[HostsFileGuard] Watcher active on {Path}", HostsFilePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[HostsFileGuard] Failed to start watcher");
            }
        }

        private async void OnHostsChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                // Cooldown check (avoid processing our own MitM line appends)
                if (_eventCooldown.TryGetValue(e.FullPath, out var lastAction) &&
                    DateTime.UtcNow - lastAction < CooldownPeriod)
                    return;

                await ScanHostsFileAsync(e.ChangeType.ToString(), CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] OnHostsChanged error");
            }
        }

        private static (int pid, string name) GetModifyingProcess(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return (0, "Unknown");
                var lastWrite = File.GetLastWriteTimeUtc(filePath);
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var name = proc.ProcessName;
                        if (string.Equals(name, "csrss") || string.Equals(name, "wininit") ||
                            string.Equals(name, "services") || string.Equals(name, "smss") ||
                            string.Equals(name, "lsass") || string.Equals(name, "svchost") ||
                            string.Equals(name, "winlogon") || string.Equals(name, "explorer") ||
                            string.Equals(name, "dwm") || string.Equals(name, "System") ||
                            string.Equals(name, "msiexec") || string.Equals(name, "TrustedInstaller") ||
                            string.Equals(name, "cmd") || string.Equals(name, "powershell") ||
                            string.Equals(name, "pwsh") || string.Equals(name, "notepad") ||
                            string.Equals(name, "code"))
                        {
                            continue;
                        }

                        if (proc.StartTime.ToUniversalTime() <= lastWrite &&
                            proc.StartTime.ToUniversalTime() > lastWrite.AddSeconds(-5) &&
                            proc.Id > 4)
                        {
                            return (proc.Id, name);
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return (0, "Unknown");
        }

        private static string ComputeFileHash(string path)
        {
            try
            {
                using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sha = SHA256.Create();
                return ConvertHex.ToHexString(sha.ComputeHash(stream));
            }
            catch { return string.Empty; }
        }

        private void DisposeWatcher()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }
        }

        public override async Task StopAsync(CancellationToken ct)
        {
            DisposeWatcher();
            await base.StopAsync(ct);
        }

        // Documented public Win32 API - clears the DNS resolver cache (equivalent to
        // "ipconfig /flushdns") so a freshly applied NRPT rule blocks forum.hr right away.
        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        private static extern uint DnsFlushResolverCache();
    }


    // 
    // Boot Integrity Guard - monitors bcdedit, EFI, and driver load order for rootkit persistence
    // 
    public sealed class BootIntegrityGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BootIntegrityGuard> _logger;

        private Dictionary<string, string> _baselineBcd = new();
        private List<string> _baselineBootDrivers = new();
        private bool _baselineCaptured;

        private static readonly HashSet<string> TrustedBootDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "WdBoot", "WdFilter", "Wof", "EhStorClass", "FileInfo",
            "hwpolicy", "SgrmAgent", "WindowsTrustedRT", "WindowsTrustedRTProxy",
            "iorate", "dam", "pcw", "volmgrx", "pdc", "CEA",
            "intelpep", "IntelPMT", "CLFS", "Fs_Rec", "Ntfs",
            "CimFS", "msisadrv", "pci", "vdrvroot", "partmgr", "volmgr",
            "mountmgr", "storahci", "stornvme", "EhStorTcgDrv",
            "fvevol", "rdyboost", "mup", "disk", "CLASSPNP",
            "crashdmp", "cdrom", "filecrypt", "tbs", "Null",
            "Beep", "dxgkrnl", "watchdog", "BasicDisplay", "BasicRender",
            "Npfs", "Msfs", "tdx", "TDI", "netbt", "afunix",
            "IKEEXT", "PolicyAgent", "BFE", "wfplwfs", "Dhcp",
            "Dnscache", "nsi", "Tcpip", "NDIS", "afd", "spaceport",
            // Microsoft system drivers commonly present on non-debloated Windows
            "UCPD", "MsSecFlt", "SgrmBroker", "bindflt", "wcifs",
            "storqosflt", "wcnfs", "CldFlt", "FileCrypt",
        };

        private static readonly string[] SuspiciousDriverPaths = new[]
        {
            @"\temp\", @"\tmp\", @"\downloads\", @"\appdata\",
            @"\users\", @"\desktop\", @"\documents\"
        };

        public BootIntegrityGuard(DetectionEngine de, ILogger<BootIntegrityGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BootIntegrityGuard] Started - monitoring boot configuration, EFI, and driver load order");

            await Task.Delay(30000, ct);
            await CaptureBaselineAsync();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    await CheckBcdIntegrityAsync();
                    await CheckBootDriversAsync();
                    await CheckEfiPartitionAsync();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[BootIntegrityGuard] Error");
                }
            }
        }

        private Task CaptureBaselineAsync()
        {
            try
            {
                _baselineBcd = CaptureBcdEntries();
                _baselineBootDrivers = CaptureBootDriverList();
                _baselineCaptured = true;
                _logger.LogInformation("[BootIntegrityGuard] Baseline: {Bcd} BCD entries, {Drv} boot drivers",
                    _baselineBcd.Count, _baselineBootDrivers.Count);
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] Baseline capture failed"); }
            return Task.CompletedTask;
        }

        private async Task CheckBcdIntegrityAsync()
        {
            try
            {
                var current = CaptureBcdEntries();

                if (current.TryGetValue("testsigning", out var ts) &&
                    string.Equals(ts, "Yes"))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: Test Signing Enabled",
                        Evidence = "bcdedit testsigning=Yes - unsigned kernel drivers can load.",
                        Reasoning = "Rootkits enable test signing to load unsigned kernel components.",
                        Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "Setting", "testsigning" }, { "Value", "Yes" } }
                    });
                }

                if (current.TryGetValue("debug", out var dbg) &&
                    string.Equals(dbg, "Yes"))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: Kernel Debug Mode Enabled",
                        Evidence = "bcdedit debug=Yes - kernel debugger can attach.",
                        Reasoning = "Kernel debug mode allows remote kernel access. Rootkits enable this for persistent control.",
                        Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "Setting", "debug" }, { "Value", "Yes" } }
                    });
                }

                if (current.TryGetValue("nointegritychecks", out var nic) &&
                    string.Equals(nic, "Yes"))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: Integrity Checks Disabled",
                        Evidence = "bcdedit nointegritychecks=Yes - boot code integrity bypassed.",
                        Reasoning = "Disabling integrity checks allows tampered boot components to load unchallenged.",
                        Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "Setting", "nointegritychecks" }, { "Value", "Yes" } }
                    });
                }

                if (_baselineCaptured)
                {
                    foreach (var kvp in current)
                    {
                        if (!_baselineBcd.ContainsKey(kvp.Key))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: New BCD Entry",
                                Evidence = $"New boot config: {kvp.Key}={kvp.Value}",
                                Reasoning = "Bootkits add BCD entries for persistence.",
                                Confidence = 0.75, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "Entry", kvp.Key }, { "Value", kvp.Value } }
                            });
                        }
                        else if (_baselineBcd[kvp.Key] != kvp.Value)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: BCD Entry Modified",
                                Evidence = $"{kvp.Key}: '{_baselineBcd[kvp.Key]}' -> '{kvp.Value}'",
                                Reasoning = "Boot configuration was modified at runtime - possible bootkit activity.",
                                Confidence = 0.80, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "Entry", kvp.Key }, { "Old", _baselineBcd[kvp.Key] }, { "New", kvp.Value } }
                            });
                        }
                    }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] BCD check error"); }
        }

        private async Task CheckBootDriversAsync()
        {
            try
            {
                if (!_baselineCaptured) return;
                var current = CaptureBootDriverList();
                var newDrivers = current.Except(_baselineBootDrivers, StringComparer.OrdinalIgnoreCase).ToList();

                foreach (var driver in newDrivers)
                {
                    if (TrustedBootDrivers.Contains(driver)) continue;

                    var imagePath = GetDriverImagePath(driver);
                    bool suspicious = !string.IsNullOrEmpty(imagePath) &&
                        SuspiciousDriverPaths.Any(p => imagePath!.Contains(p));

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: New Boot Driver Registered",
                        Evidence = $"New boot driver '{driver}' - ImagePath: {imagePath ?? "unknown"}",
                        Reasoning = "Rootkits register kernel drivers for boot-start to load before security software.",
                        Confidence = suspicious ? 0.95 : 0.80,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string>
                        {
                            { "Driver", driver },
                            { "ImagePath", imagePath ?? "unknown" },
                            { "SuspiciousPath", suspicious.ToString() }
                        }
                    });
                }

                // Update baseline with current state so we only alert once per new driver
                if (newDrivers.Count > 0)
                {
                    _baselineBootDrivers = current;
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] Driver check error"); }
        }

        private async Task CheckEfiPartitionAsync()
        {
            string? efiDir = null;
            bool mountedByUs = false;
            try
            {
                var result = FindEfiMountPoint();
                efiDir = result.Path;
                mountedByUs = result.MountedByUs;
                if (string.IsNullOrEmpty(efiDir)) return;

                // Check for bootmgfw.efi.bak - classic bootkit signature
                var bakPath = Path.Combine(efiDir, "EFI", "Microsoft", "Boot", "bootmgfw.efi.bak");
                if (File.Exists(bakPath))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: EFI Boot Manager Backup Found",
                        Evidence = $"File: {bakPath} - original boot manager may have been replaced.",
                        Reasoning = "EFI bootkits (BlackLotus, ESPecter) rename bootmgfw.efi to .bak and replace it.",
                        Confidence = 0.92, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "File", bakPath } }
                    });
                }

                // Unknown .efi binaries in boot directory
                var bootDir = Path.Combine(efiDir, "EFI", "Microsoft", "Boot");
                if (Directory.Exists(bootDir))
                {
                    var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    { "bootmgfw.efi", "memtest.efi", "bootmgr.efi", "cdboot.efi",
                      "SecureBootRecovery.efi", "bootx64.efi", "bootaa64.efi",
                      "fwupx64.efi", "fwupaa64.efi", "mmx64.efi", "shimx64.efi" };

                    foreach (var file in Directory.GetFiles(bootDir, "*.efi"))
                    {
                        var name = Path.GetFileName(file);
                        if (!known.Contains(name) && !name.StartsWith("boot"))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: Unknown EFI Binary",
                                Evidence = $"Unknown EFI file: {file} ({new FileInfo(file).Length} bytes)",
                                Reasoning = "EFI bootkits place payloads in the Microsoft Boot directory to execute before the OS kernel.",
                                Confidence = 0.88, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "File", file } }
                            });
                        }
                    }
                }

                // Unknown directories in EFI root
                var efiRoot = Path.Combine(efiDir, "EFI");
                if (Directory.Exists(efiRoot))
                {
                    var knownDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    { "Microsoft", "Boot", "HP", "Dell", "Lenovo", "ASUS", "Acer", "Intel", "OEM", "ubuntu", "grub", "refind" };

                    foreach (var dir in Directory.GetDirectories(efiRoot))
                    {
                        var dirName = Path.GetFileName(dir);
                        if (!knownDirs.Contains(dirName))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: Unknown EFI Directory",
                                Evidence = $"Unknown EFI partition directory: {dir}",
                                Reasoning = "Advanced bootkits create directories in ESP to store payloads.",
                                Confidence = 0.70, Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "Directory", dir } }
                            });
                        }
                    }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] EFI check error"); }
            finally
            {
                if (mountedByUs && efiDir != null)
                {
                    UnmountEfiVolume(efiDir);
                }
            }
        }

        private static Dictionary<string, string> CaptureBcdEntries()
        {
            var entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var psi = new ProcessStartInfo("bcdedit.exe", "/enum all")
                { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true };
                using var proc = Process.Start(psi);
                if (proc == null) return entries;
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(10000);

                foreach (var line in output.Split('\n'))
                {
                    var trimmed = line.Trim();
                    var idx = trimmed.IndexOf(' ');
                    if (idx > 0)
                    {
                        var key = trimmed[..idx].Trim();
                        var val = trimmed[(idx + 1)..].Trim();
                        if (!string.IsNullOrEmpty(key))
                            entries.TryAdd(key, val);
                    }
                }
            }
            catch { }
            return entries;
        }

        private static List<string> CaptureBootDriverList()
        {
            var drivers = new List<string>();
            try
            {
                using var svcKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (svcKey == null) return drivers;

                foreach (var name in svcKey.GetSubKeyNames())
                {
                    try
                    {
                        using var dk = svcKey.OpenSubKey(name);
                        if (dk == null) continue;
                        var start = dk.GetValue("Start");
                        var type = dk.GetValue("Type");
                        if (start is int s && type is int t && s <= 1 && (t == 1 || t == 2))
                            drivers.Add(name);
                    }
                    catch { }
                }
            }
            catch { }
            return drivers;
        }

        private static string? GetDriverImagePath(string driverName)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{driverName}");
                return key?.GetValue("ImagePath") as string;
            }
            catch { return null; }
        }

        private static (string? Path, bool MountedByUs) FindEfiMountPoint()
        {
            try
            {
                // Check all drive letters A-Z for an already-mounted EFI partition
                for (char c = 'A'; c <= 'Z'; c++)
                {
                    var candidate = $@"{c}:\";
                    try
                    {
                        if (Directory.Exists(Path.Combine(candidate, "EFI")))
                            return (candidate, false);
                    }
                    catch { }
                }

                // Find a free drive letter to mount onto - avoid any letter already in use
                var usedLetters = new HashSet<char>(
                    DriveInfo.GetDrives()
                        .Where(d => d.Name.Length >= 1)
                        .Select(d => char.ToUpperInvariant(d.Name[0])));

                // Prefer letters near the end of the alphabet that are unlikely to conflict
                char mountLetter = '\0';
                foreach (char preferred in "ZYXWVUTSRQPONMLKJIHGFEDCBA")
                {
                    if (!usedLetters.Contains(preferred))
                    {
                        mountLetter = preferred;
                        break;
                    }
                }

                if (mountLetter == '\0') return (null, false); // No free letter

                var mountPath = $@"{mountLetter}:\";
                var psi = new ProcessStartInfo("mountvol.exe", $@"{mountPath} /S")
                { CreateNoWindow = true, UseShellExecute = false };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(5000);

                if (Directory.Exists(Path.Combine(mountPath, "EFI")))
                    return (mountPath, true);

                // Mount failed or no EFI folder - clean up immediately
                UnmountEfiVolume(mountPath);
            }
            catch { }
            return (null, false);
        }

        private static void UnmountEfiVolume(string? mountPath = null)
        {
            // If no path given, try to unmount S:\ for backward compat
            var target = mountPath ?? @"S:\";
            try
            {
                var psi = new ProcessStartInfo("mountvol.exe", $@"{target} /D")
                { CreateNoWindow = true, UseShellExecute = false };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(5000);
            }
            catch { }
        }
    }


    // 
    // WMI Provider Integrity Monitor - detects malicious WMI provider DLLs (v1.6.6)
    // 
    // A malicious WMI provider DLL runs inside WmiPrvSE.exe (legitimate SYSTEM process)
    // and can intercept/modify WMI query results (fake thermals, throttle power settings)
    // or execute arbitrary code on any WMI query to its namespace - without any visible
    // process, autorun entry, scheduled task, or WMI event subscription.
    //
    // This monitor:
    //   1. Enumerates all __Win32Provider objects across WMI namespaces
    //   2. Resolves CLSID -> InprocServer32 -> DLL path
    //   3. Validates Authenticode signatures (unsigned in sensitive namespace = Tier1)
    //   4. Baselines known providers at startup; alerts on new providers at runtime
    //   5. Scans WmiPrvSE.exe loaded modules for non-system DLLs
    //   6. Checks for MOF auto-recovery persistence
    // 
    public sealed class WmiProviderIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WmiProviderIntegrityMonitor> _logger;

        // Baseline: provider name -> resolved DLL path (from first scan)
        private readonly Dictionary<string, WmiProviderInfo> _baselineProviders = new(StringComparer.OrdinalIgnoreCase);
        private bool _baselineEstablished;

        // MOF paths already alerted this process lifetime (avoid re-emitting every scan)
        private readonly HashSet<string> _alertedMofPaths = new(StringComparer.OrdinalIgnoreCase);

        // Sensitive WMI namespaces - unsigned providers here are high-confidence threats
        // (power management, thermal, Intel DTT, hardware monitoring)
        private static readonly HashSet<string> SensitiveNamespaces = new(StringComparer.OrdinalIgnoreCase)
        {
            @"root\wmi",
            @"root\intel",
            @"root\intel\dtt",
            @"root\cimv2\power",
            @"root\cimv2\thermal",
            @"root\hardware",
            @"root\microsoft\windows\storage",
            @"root\standardcimv2",
        };

        // Known legitimate non-Microsoft providers that will be unsigned or third-party signed
        // (GPU drivers, OEM tools, etc.) - suppress false positives
        private static readonly HashSet<string> KnownThirdPartyProviders = new(StringComparer.OrdinalIgnoreCase)
        {
            "NVDisplay.ContainerLocalSystem",   // NVIDIA
            "nvloggr",                          // NVIDIA logging
            "RmProvider",                       // NVIDIA resource manager
            "IntelProv",                        // Intel chipset
            "AmdProv",                          // AMD
            "ASUSWMIProvider",                  // ASUS motherboard
            "MSIWmiProvider",                   // MSI motherboard
            "GigabyteProvider",                 // Gigabyte motherboard
            "RealtekProv",                      // Realtek audio/NIC
            "WmiPerfClass",                     // Windows perf counters (catalog-signed)
            "CIMWin32",                         // Core Windows provider (catalog-signed)
            "Win32ClockProvider",               // Windows time provider
            "StandardCimv2",                    // Windows networking provider
        };

        // Scan interval: 5 minutes (balances detection speed vs performance)
        private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(5);

        public WmiProviderIntegrityMonitor(DetectionEngine de, ILogger<WmiProviderIntegrityMonitor> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WmiProviderIntegrityMonitor] Started - scanning WMI provider DLLs for integrity");

            // Initial delay to let system stabilize after boot
            await Task.Delay(15000, ct);

            // Establish baseline
            var providers = EnumerateAllProviders();
            foreach (var p in providers)
                _baselineProviders[p.ProviderKey] = p;
            _baselineEstablished = true;

            _logger.LogInformation("[WmiProviderIntegrityMonitor] Baseline established: {Count} providers", _baselineProviders.Count);

            // Scan baseline for existing suspicious providers (pre-installed rootkit)
            await ScanForSuspiciousProvidersAsync(_baselineProviders.Values, isBaseline: _baselineEstablished, ct);

            // Periodic scanning loop
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);

                    // Re-enumerate and check for new providers
                    var current = EnumerateAllProviders();
                    var newProviders = new List<WmiProviderInfo>();

                    foreach (var p in current)
                    {
                        if (!_baselineProviders.ContainsKey(p.ProviderKey))
                        {
                            newProviders.Add(p);
                            _baselineProviders[p.ProviderKey] = p;
                        }
                    }

                    // Alert on new providers
                    if (newProviders.Count > 0)
                    {
                        await ScanForSuspiciousProvidersAsync(newProviders, isBaseline: false, ct);
                    }

                    // Scan WmiPrvSE.exe + wmiadap.exe loaded modules
                    await ScanWmiPrvSeModulesAsync(ct);
                    await ScanWmiHostModulesAsync("wmiadap", "wmiadap.exe", ct);

                    // Check MOF auto-recovery
                    await CheckMofAutoRecoveryAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WmiProviderIntegrityMonitor] Error in scan loop"); }
            }
        }

        /// <summary>
        /// Enumerates __Win32Provider objects across common WMI namespaces.
        /// Resolves each provider's CLSID to its InprocServer32 DLL path.
        /// </summary>
        private List<WmiProviderInfo> EnumerateAllProviders()
        {
            var results = new List<WmiProviderInfo>();
            var namespacesToScan = GetWmiNamespaces();

            foreach (var ns in namespacesToScan)
            {
                try
                {
                    using var searcher = new ManagementObjectSearcher(ns, "SELECT * FROM __Win32Provider");
                    searcher.Options.Timeout = TimeSpan.FromSeconds(10);

                    foreach (ManagementObject obj in searcher.Get())
                    {
                        try
                        {
                            var name = obj["Name"]?.ToString() ?? "";
                            var clsid = obj["CLSID"]?.ToString() ?? "";

                            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(clsid))
                                continue;

                            var dllPath = ResolveCLSIDtoDll(clsid);

                            results.Add(new WmiProviderInfo
                            {
                                Name = name,
                                Namespace = ns,
                                CLSID = clsid,
                                DllPath = dllPath,
                                ProviderKey = $"{ns}\\{name}\\{clsid}"
                            });
                        }
                        catch { }
                    }
                }
                catch { } // Namespace may not exist or be inaccessible
            }

            return results;
        }

        /// <summary>
        /// Gets all WMI namespaces to scan by recursively enumerating from root.
        /// Falls back to a hardcoded list of common namespaces if enumeration fails.
        /// </summary>
        private List<string> GetWmiNamespaces()
        {
            var namespaces = new List<string>();
            try
            {
                // Start with root and enumerate child namespaces
                EnumerateNamespacesRecursive(@"root", namespaces, depth: 0, maxDepth: 3);
            }
            catch
            {
                // Fallback: common namespaces where malicious providers would register
                namespaces.AddRange(new[]
                {
                    @"root\cimv2",
                    @"root\wmi",
                    @"root\default",
                    @"root\subscription",
                    @"root\standardcimv2",
                    @"root\microsoft\windows\storage",
                    @"root\intel",
                });
            }

            return namespaces;
        }

        private void EnumerateNamespacesRecursive(string parentNs, List<string> results, int depth, int maxDepth)
        {
            results.Add(parentNs);
            if (depth >= maxDepth) return;

            try
            {
                using var searcher = new ManagementObjectSearcher(parentNs, "SELECT * FROM __NAMESPACE");
                searcher.Options.Timeout = TimeSpan.FromSeconds(5);

                foreach (ManagementObject obj in searcher.Get())
                {
                    var childName = obj["Name"]?.ToString();
                    if (!string.IsNullOrEmpty(childName))
                    {
                        var childPath = $@"{parentNs}\{childName}";
                        EnumerateNamespacesRecursive(childPath, results, depth + 1, maxDepth);
                    }
                }
            }
            catch { } // Some namespaces deny enumeration - skip silently
        }

        /// <summary>
        /// Resolves a COM CLSID to its InprocServer32 DLL path via the registry.
        /// </summary>
        private static string? ResolveCLSIDtoDll(string clsid)
        {
            if (string.IsNullOrEmpty(clsid)) return null;

            // Normalize CLSID format
            if (!clsid.StartsWith("{")) clsid = "{" + clsid + "}";

            try
            {
                // Check 64-bit registry view first
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32", false);
                if (key != null)
                {
                    var dll = key.GetValue("")?.ToString() ?? key.GetValue("(Default)")?.ToString();
                    if (!string.IsNullOrEmpty(dll))
                        return Environment.ExpandEnvironmentVariables(dll);
                }

                // Check WOW64 (32-bit) registry view
                using var wow64Key = Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\WOW6432Node\Classes\CLSID\{clsid}\InprocServer32", false);
                if (wow64Key != null)
                {
                    var dll = wow64Key.GetValue("")?.ToString() ?? wow64Key.GetValue("(Default)")?.ToString();
                    if (!string.IsNullOrEmpty(dll))
                        return Environment.ExpandEnvironmentVariables(dll);
                }
            }
            catch { }

            return null;
        }

        /// <summary>
        /// Analyzes providers for suspicious characteristics:
        /// - Unsigned DLL in a sensitive namespace (power, thermal, Intel) -> Tier1 (0.88)
        /// - Unsigned DLL in non-system path -> Tier1 (0.80)
        /// - New provider added at runtime (not in baseline) -> Tier1 (0.82)
        /// - Unsigned DLL in standard namespace -> Tier2 (0.65)
        /// </summary>
        private async Task ScanForSuspiciousProvidersAsync(
            IEnumerable<WmiProviderInfo> providers, bool isBaseline, CancellationToken ct)
        {
            foreach (var provider in providers)
            {
                if (ct.IsCancellationRequested) break;

                // Skip providers with no resolved DLL (out-of-process or missing)
                if (string.IsNullOrEmpty(provider.DllPath)) continue;

                // Skip known third-party providers (GPU drivers, OEM tools)
                if (KnownThirdPartyProviders.Contains(provider.Name)) continue;

                // Check if the DLL exists on disk
                if (!File.Exists(provider.DllPath)) continue;

                // Check if DLL is in a system-protected path
                bool isSystemPath = IsSystemProtectedPath(provider.DllPath!);

                // Verify Authenticode signature
                bool isSigned = SecurityValidation.VerifyAuthenticodeSignature(provider.DllPath!);

                // Determine if namespace is sensitive (power/thermal/hardware)
                bool isSensitiveNs = IsSensitiveNamespace(provider.Namespace);

                // Extract publisher for logging
                string publisher = isSigned ? GetSignerPublisher(provider.DllPath!) : "UNSIGNED";

                // Decision matrix:
                if (!isSigned && isSensitiveNs)
                {
                    // HIGHEST THREAT: Unsigned DLL in power/thermal/Intel namespace
                    // This is the exact pattern a performance-throttling rootkit would use
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WMI Provider Integrity: Unsigned Provider in Sensitive Namespace",
                        Evidence = $"Unsigned WMI provider DLL in sensitive namespace. " +
                                   $"Provider: '{provider.Name}', Namespace: '{provider.Namespace}', " +
                                   $"CLSID: {provider.CLSID}, DLL: '{provider.DllPath}', " +
                                   $"NewAtRuntime: {!isBaseline}",
                        Reasoning = "An unsigned DLL is registered as a WMI provider in a power, thermal, or hardware " +
                                    "namespace. This is the exact technique used by performance-throttling rootkits that " +
                                    "intercept WMI queries to fake thermal readings or modify power settings. The DLL " +
                                    "executes inside WmiPrvSE.exe (SYSTEM) with no visible process or autorun entry.",
                        Confidence = 0.88,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcess,
                        ProcessName = "WmiPrvSE.exe",
                        ProcessId = 0
                    });
                    _logger.LogWarning("[WmiProviderIntegrityMonitor] ALERT: Unsigned provider in sensitive namespace: " +
                        "{Name} @ {Namespace} -> {Dll}", provider.Name, provider.Namespace, provider.DllPath);
                }
                else if (!isSigned && !isSystemPath)
                {
                    // HIGH THREAT: Unsigned DLL outside system paths (staging/temp/user dirs)
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WMI Provider Integrity: Unsigned Provider from Non-System Path",
                        Evidence = $"Unsigned WMI provider DLL loaded from non-system path. " +
                                   $"Provider: '{provider.Name}', Namespace: '{provider.Namespace}', " +
                                   $"CLSID: {provider.CLSID}, DLL: '{provider.DllPath}', Publisher: {publisher}",
                        Reasoning = "A WMI provider DLL that is unsigned and located outside of Windows system directories " +
                                    "was detected. Legitimate providers are typically signed and installed under System32 or " +
                                    "Program Files. This pattern matches malicious WMI provider persistence (T1546.003 variant).",
                        Confidence = isBaseline ? 0.75 : 0.82,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "WmiPrvSE.exe",
                        ProcessId = 0
                    });
                    _logger.LogWarning("[WmiProviderIntegrityMonitor] Suspicious unsigned provider: {Name} -> {Dll}",
                        provider.Name, provider.DllPath);
                }
                else if (!isBaseline && !isSigned)
                {
                    // MEDIUM: New unsigned provider appeared at runtime (even in system path)
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WMI Provider Integrity: New Unsigned Provider at Runtime",
                        Evidence = $"New unsigned WMI provider registered since startup. " +
                                   $"Provider: '{provider.Name}', Namespace: '{provider.Namespace}', " +
                                   $"CLSID: {provider.CLSID}, DLL: '{provider.DllPath}'",
                        Reasoning = "A new WMI provider was registered after Sentinel baseline was established. " +
                                    "Runtime provider registration is uncommon outside of software installation and " +
                                    "may indicate a rootkit installing a persistent WMI provider.",
                        Confidence = 0.70,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "WmiPrvSE.exe",
                        ProcessId = 0
                    });
                }
            }
        }

        /// <summary>
        /// Scans all WmiPrvSE.exe instances for loaded DLLs outside system directories.
        /// A legitimate WmiPrvSE should only load DLLs from System32, WinSxS, and
        /// registered provider paths (Program Files). Non-system DLLs indicate injection
        /// or a malicious provider that sideloaded additional components.
        /// </summary>
        private Task ScanWmiPrvSeModulesAsync(CancellationToken ct)
            => ScanWmiHostModulesAsync("WmiPrvSE", "WmiPrvSE.exe", ct);

        /// <summary>
        /// v2.2.8: same module walk for WMI Performance Adapter (wmiadap.exe).
        /// Policy overwrite and provider abuse also execute from this host.
        /// </summary>
        private async Task ScanWmiHostModulesAsync(string processName, string displayName, CancellationToken ct)
        {
            try
            {
                var wmiProcs = Process.GetProcessesByName(processName);
                foreach (var proc in wmiProcs)
                {
                    try
                    {
                        if (ct.IsCancellationRequested) break;

                        foreach (ProcessModule module in proc.Modules)
                        {
                            try
                            {
                                var modulePath = module.FileName;
                                if (string.IsNullOrEmpty(modulePath)) continue;

                                // Skip known-good system paths
                                if (IsSystemProtectedPath(modulePath)) continue;

                                // Skip known Program Files paths (legitimate third-party providers)
                                if (IsInProgramFiles(modulePath)) continue;

                                bool isSigned = SecurityValidation.VerifyAuthenticodeSignature(modulePath);
                                if (!isSigned)
                                {
                                    var ruleHost = displayName.Equals("WmiPrvSE.exe", StringComparison.OrdinalIgnoreCase)
                                        ? "WmiPrvSE"
                                        : displayName;
                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "WMI Provider Integrity: Suspicious Module in " + ruleHost,
                                        Evidence = $"Unsigned non-system DLL loaded in {displayName} (PID {proc.Id}): '{modulePath}'",
                                        Reasoning = displayName + " has loaded an unsigned DLL from a non-system path. " +
                                                    "This process hosts WMI providers and should only load system DLLs and " +
                                                    "registered provider binaries. An unsigned module may indicate a " +
                                                    "malicious WMI provider, StdRegProv policy rewrite helper, or DLL injection.",
                                        Confidence = 0.85,
                                        Tier = DetectionTier.Tier1Behavioral,
                                        AuthorizedResponse = ResponseAction.LogOnly,
                                        ProcessName = displayName,
                                        ProcessId = proc.Id
                                    });
                                    _logger.LogWarning("[WmiProviderIntegrityMonitor] Unsigned module in {Host} PID {Pid}: {Path}",
                                        displayName, proc.Id, modulePath);
                                }
                            }
                            catch { } // Module access may fail for protected modules
                        }
                    }
                    catch { } // Process may exit during enumeration
                    finally { proc.Dispose(); }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[WmiProviderIntegrityMonitor] Error scanning {Host} modules", displayName);
            }
        }

        /// <summary>
        /// Checks the MOF auto-recovery registry key for non-Windows MOF files.
        /// MOF auto-recovery is a legacy persistence mechanism that auto-compiles
        /// MOF files into WMI on repository rebuild - survives WMI reset.
        /// </summary>
        private async Task CheckMofAutoRecoveryAsync(CancellationToken ct)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\WBEM\CIMOM", false);
                if (key == null) return;

                var mofs = key.GetValue("Autorecover MOFs") as string[];
                if (mofs == null || mofs.Length == 0) return;

                // Track currently present paths so we can re-alert if a path is removed then re-added
                var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var mof in mofs)
                {
                    if (ct.IsCancellationRequested) break;
                    if (string.IsNullOrWhiteSpace(mof)) continue;

                    // System / Microsoft product MOFs are legitimate (Defender, Office, etc.)
                    var expanded = Environment.ExpandEnvironmentVariables(mof);
                    string normalized;
                    try { normalized = Path.GetFullPath(expanded); }
                    catch { normalized = expanded; }

                    present.Add(normalized);
                    if (IsSystemProtectedPath(normalized) || IsMicrosoftProductMofPath(normalized))
                        continue;

                    // Alert once per path per process lifetime (was flooding every scan)
                    if (!_alertedMofPaths.Add(normalized))
                        continue;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WMI Provider Integrity: Suspicious MOF Auto-Recovery Entry",
                        Evidence = $"Non-system MOF file in auto-recovery list: '{normalized}'",
                        Reasoning = "A MOF file outside of the Windows system directory is registered for " +
                                    "WMI auto-recovery. This legacy mechanism auto-compiles MOF definitions " +
                                    "into the WMI repository on rebuild, providing rootkit-level persistence " +
                                    "that survives WMI repository resets.",
                        Confidence = 0.80,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0
                    });
                    _logger.LogWarning("[WmiProviderIntegrityMonitor] Suspicious MOF auto-recovery: {Path}", normalized);
                }

                // Drop alert memory for paths no longer in the list so a re-add alerts again
                _alertedMofPaths.RemoveWhere(p => !present.Contains(p));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[WmiProviderIntegrityMonitor] Error checking MOF auto-recovery");
            }
        }

        /// <summary>
        /// Checks if a path is under Windows system-protected directories.
        /// Comparison is case-insensitive (WMI registry often stores C:\WINDOWS\...).
        /// </summary>
        private static bool IsSystemProtectedPath(string path)
        {
            string normalized;
            try { normalized = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar); }
            catch { normalized = path.TrimEnd(Path.DirectorySeparatorChar); }

            var sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var sys32 = Path.Combine(sysRoot, "System32");
            var sysWow = Path.Combine(sysRoot, "SysWOW64");
            var winsxs = Path.Combine(sysRoot, "WinSxS");
            var assembly = sysRoot + @"\assembly";

            return normalized.StartsWith(sys32, StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(sysWow, StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(winsxs, StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(assembly, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Microsoft product MOF paths that legitimately live outside System32
        /// (notably Windows Defender under Program Files).
        /// </summary>
        private static bool IsMicrosoftProductMofPath(string path)
        {
            string normalized;
            try { normalized = Path.GetFullPath(path); }
            catch { normalized = path; }

            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

            // Common Microsoft install roots that ship legitimate autorecover MOFs
            string[] roots =
            {
                Path.Combine(pf, "Windows Defender"),
                Path.Combine(pf, "Microsoft"),
                Path.Combine(pf86, "Windows Defender"),
                Path.Combine(pf86, "Microsoft"),
                Path.Combine(programData, "Microsoft"),
                // Some installs use lowercase "windows defender"
                Path.Combine(pf, "windows defender"),
                Path.Combine(pf86, "windows defender"),
            };

            foreach (var root in roots)
            {
                if (string.IsNullOrEmpty(root)) continue;
                if (normalized.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Checks if a path is under Program Files (legitimate third-party install location).
        /// </summary>
        private static bool IsInProgramFiles(string path)
        {
            var normalized = Path.GetFullPath(path);
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            return normalized.StartsWith(pf) ||
                   (!string.IsNullOrEmpty(pf86) && normalized.StartsWith(pf86));
        }

        /// <summary>
        /// Determines if a namespace is in the sensitive list (power/thermal/hardware).
        /// </summary>
        private static bool IsSensitiveNamespace(string ns)
        {
            foreach (var sensitive in SensitiveNamespaces)
            {
                if (ns.StartsWith(sensitive))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Extracts the publisher/signer subject from a signed binary.
        /// Returns "Unknown" if the cert cannot be read.
        /// </summary>
        private static string GetSignerPublisher(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                return cert?.Subject ?? "Unknown";
            }
            catch { return "Unknown"; }
        }

        /// <summary>
        /// Tracks information about a WMI provider registration.
        /// </summary>
        private sealed class WmiProviderInfo
        {
            public string Name { get; set; } = "";
            public string Namespace { get; set; } = "";
            public string CLSID { get; set; } = "";
            public string? DllPath { get; set; }
            /// <summary>Unique key: namespace\name\clsid for deduplication.</summary>
            public string ProviderKey { get; set; } = "";
        }
    }


}
