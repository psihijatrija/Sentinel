using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// v-next: Winsock LSP (Layered Service Provider) integrity monitor.
    ///
    /// A Layered Service Provider is a DLL registered in the Winsock2 catalog that Windows
    /// loads into EVERY process that opens a socket. A malicious LSP is therefore a
    /// system-wide, in-process network hook - it can inspect, redirect, or exfiltrate the
    /// traffic of every networked application without a kernel driver. This is a classic
    /// userland persistence + traffic-hijack technique (WebHancer, New.Net, CommonName, and
    /// modern re-implementations). It lives entirely in userland, so it is squarely in
    /// Sentinel's scope, and no existing monitor enumerates the catalog.
    ///
    /// DETECTION (behavioral, observe-only):
    ///   1. A protocol/namespace catalog provider whose backing DLL is NOT Microsoft-signed
    ///      (unsigned, or signed by a non-Microsoft publisher). Legitimate third-party LSPs
    ///      exist (some VPN/AV/proxy products) so this is a signal, not a solo kill.
    ///   2. A gap in the catalog chain (a Num_Catalog_Entries count with a missing indexed
    ///      entry) - the "broken LSP chain" shape left behind by clumsy LSP removal or a
    ///      hijack that severs Internet access. HijackThis flags this as O10.
    ///   3. A provider whose backing DLL is missing on disk (dangling LibraryPath).
    ///
    /// RESPONSE: LogOnly only. Sentinel never rewrites the Winsock catalog inline - a wrong
    /// edit breaks all networking on the host. Repair requires "netsh winsock reset" + reboot,
    /// which is a human decision. This monitor is chain fuel + explainability, not a mutator.
    ///
    /// The reference technique (catalog layout, provider-path resolution) is derived from the
    /// public HijackThis O10 check; all data and code here are original.
    /// </summary>
    public sealed class WinsockLspIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<WinsockLspIntegrityMonitor> _logger;

        // Re-scan is cheap and the catalog rarely changes; a slow cadence avoids noise and
        // gives the disk/signature cache time to settle after installs.
        private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(20);

        private const string WinsockParamsKey =
            @"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters";

        // Emit each distinct provider finding once per DLL path to avoid re-alerting on
        // every 10-minute pass for a provider the user has already seen.
        private readonly HashSet<string> _reportedProviders =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedChainGaps =
            new(StringComparer.OrdinalIgnoreCase);

        public WinsockLspIntegrityMonitor(
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            ILogger<WinsockLspIntegrityMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _signerTrust = signerTrust;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WinsockLspIntegrityMonitor] Started");

            try { await Task.Delay(StartupDelay, ct); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await ScanCatalogAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    // Graceful degradation: a catalog read failure must never crash the host.
                    _logger.LogDebug(ex, "[WinsockLspIntegrityMonitor] Scan error");
                }

                try { await Task.Delay(ScanInterval, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        private async Task ScanCatalogAsync(CancellationToken ct)
        {
            using var paramsKey = Registry.LocalMachine.OpenSubKey(WinsockParamsKey, writable: false);
            if (paramsKey == null)
            {
                _logger.LogDebug("[WinsockLspIntegrityMonitor] Winsock2 Parameters key not found");
                return;
            }

            var currentProtocol = paramsKey.GetValue("Current_Protocol_Catalog") as string;
            var currentNamespace = paramsKey.GetValue("Current_NameSpace_Catalog") as string;

            if (!string.IsNullOrEmpty(currentProtocol))
            {
                await ScanProtocolCatalogAsync(
                    $@"{WinsockParamsKey}\{currentProtocol}", ct);
            }

            if (!string.IsNullOrEmpty(currentNamespace))
            {
                await ScanNamespaceCatalogAsync(
                    $@"{WinsockParamsKey}\{currentNamespace}", ct);
            }
        }

        private async Task ScanProtocolCatalogAsync(string catalogKeyPath, CancellationToken ct)
        {
            using var catalogKey = Registry.LocalMachine.OpenSubKey(catalogKeyPath, writable: false);
            if (catalogKey == null) return;

            int count = ReadDword(catalogKey, "Num_Catalog_Entries");
            if (count <= 0) return;

            for (int i = 1; i <= count; i++)
            {
                if (ct.IsCancellationRequested) return;

                string entryName = FormatCatalogEntry(i);
                string entryPath = $@"{catalogKeyPath}\Catalog_Entries\{entryName}";

                using var entryKey = Registry.LocalMachine.OpenSubKey(entryPath, writable: false);
                if (entryKey == null)
                {
                    await ReportChainGapAsync("Protocol", i, count, ct);
                    continue;
                }

                var packed = entryKey.GetValue("PackedCatalogItem") as byte[];
                string? dllPath = ExtractPathFromPackedCatalogItem(packed);
                await EvaluateProviderAsync("Protocol", dllPath, ct);
            }
        }

        private async Task ScanNamespaceCatalogAsync(string catalogKeyPath, CancellationToken ct)
        {
            using var catalogKey = Registry.LocalMachine.OpenSubKey(catalogKeyPath, writable: false);
            if (catalogKey == null) return;

            int count = ReadDword(catalogKey, "Num_Catalog_Entries");
            if (count <= 0) return;

            for (int i = 1; i <= count; i++)
            {
                if (ct.IsCancellationRequested) return;

                string entryName = FormatCatalogEntry(i);
                string entryPath = $@"{catalogKeyPath}\Catalog_Entries\{entryName}";

                using var entryKey = Registry.LocalMachine.OpenSubKey(entryPath, writable: false);
                if (entryKey == null)
                {
                    await ReportChainGapAsync("NameSpace", i, count, ct);
                    continue;
                }

                var libraryPath = entryKey.GetValue("LibraryPath") as string;
                string? dllPath = string.IsNullOrEmpty(libraryPath)
                    ? null
                    : Environment.ExpandEnvironmentVariables(libraryPath!);
                await EvaluateProviderAsync("NameSpace", dllPath, ct);
            }
        }

        /// <summary>
        /// Classifies a single catalog provider DLL and emits an observe-only detection when the
        /// DLL is missing, unsigned, or signed by a non-Microsoft publisher. Each distinct DLL
        /// path is reported at most once per process lifetime.
        /// </summary>
        private async Task EvaluateProviderAsync(string catalogType, string? dllPath, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(dllPath)) return;

            string normalized = dllPath!.Trim();

            lock (_reportedProviders)
            {
                if (!_reportedProviders.Add(normalized)) return; // already reported this DLL
            }

            // Missing backing DLL - dangling provider (broken chain / removal residue).
            if (!File.Exists(normalized))
            {
                await _detectionEngine.EmitAsync(BuildMissingProviderEvent(catalogType, normalized));
                return;
            }

            bool signed = _signerTrust.IsSignedFile(normalized);
            string? signer = signed ? _signerTrust.GetSignerName(normalized) : null;
            bool microsoftSigned = signed && IsMicrosoftSigner(signer);

            if (microsoftSigned) return; // Microsoft-provided LSP - baseline, no alert.

            await _detectionEngine.EmitAsync(BuildNonMicrosoftProviderEvent(catalogType, normalized, signed, signer));
        }

        // ---- Detection-event builders (pure; unit-tested directly) ----

        internal static DetectionEvent BuildMissingProviderEvent(string catalogType, string providerDll)
            => new DetectionEvent
            {
                RuleName = "Network: Winsock LSP Provider Missing",
                Evidence = $"Winsock {catalogType} catalog references a provider DLL that is not present on disk: '{providerDll}'.",
                Reasoning = "A Winsock catalog entry points at a Layered Service Provider DLL that no longer " +
                            "exists. This is the 'broken LSP' residue left by malware or by clumsy LSP removal " +
                            "and can sever Internet access for every socket-using process. Repair requires " +
                            "'netsh winsock reset' + reboot - a human decision; Sentinel does not edit the catalog.",
                Confidence = 0.55,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                Metadata = new Dictionary<string, string>
                {
                    ["Catalog"] = catalogType,
                    ["ProviderDll"] = providerDll,
                    ["Condition"] = "Missing"
                }
            };

        internal static DetectionEvent BuildNonMicrosoftProviderEvent(
            string catalogType, string providerDll, bool signed, string? signer)
            => new DetectionEvent
            {
                RuleName = "Network: Non-Microsoft Winsock LSP Provider",
                Evidence = $"Winsock {catalogType} catalog loads a {(signed ? "non-Microsoft-signed" : "unsigned")} " +
                           $"Layered Service Provider DLL system-wide: '{providerDll}'" +
                           (signed ? $" (signer: {signer})." : "."),
                Reasoning = "A Layered Service Provider is loaded into every process that opens a socket, giving it " +
                            "in-process visibility and control over all network traffic on the host - a userland, " +
                            "driverless traffic-hijack and persistence surface. A Microsoft-signed provider is baseline; " +
                            "an unsigned or third-party one warrants review (some VPN/AV/proxy products install " +
                            "legitimate LSPs, so this is an observe-only signal and chain fuel, not a solo kill).",
                Confidence = signed ? 0.50 : 0.68,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                Metadata = new Dictionary<string, string>
                {
                    ["Catalog"] = catalogType,
                    ["ProviderDll"] = providerDll,
                    ["Condition"] = signed ? $"Non-Microsoft signer ({signer})" : "Unsigned",
                    ["Signed"] = signed.ToString()
                }
            };

        private async Task ReportChainGapAsync(string catalogType, int missingIndex, int total, CancellationToken ct)
        {
            string key = $"{catalogType}:{missingIndex}/{total}";
            lock (_reportedChainGaps)
            {
                if (!_reportedChainGaps.Add(key)) return;
            }

            await _detectionEngine.EmitAsync(BuildChainGapEvent(catalogType, missingIndex, total));
        }

        internal static DetectionEvent BuildChainGapEvent(string catalogType, int missingIndex, int total)
            => new DetectionEvent
            {
                RuleName = "Network: Winsock LSP Chain Gap",
                Evidence = $"Winsock {catalogType} catalog declares {total} entries but entry #{missingIndex} is missing.",
                Reasoning = "A gap in the Winsock catalog chain means an indexed provider entry is absent while the " +
                            "catalog count still claims it exists. This 'broken LSP chain' shape is left behind by " +
                            "malicious or incomplete LSP removal and commonly breaks Internet access. Repair is " +
                            "'netsh winsock reset' + reboot; Sentinel reports only.",
                Confidence = 0.5,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                Metadata = new Dictionary<string, string>
                {
                    ["Catalog"] = catalogType,
                    ["MissingIndex"] = missingIndex.ToString(),
                    ["DeclaredCount"] = total.ToString()
                }
            };

        /// <summary>
        /// Catalog entry subkeys are zero-padded to 12 digits, e.g. "000000000001".
        /// </summary>
        internal static string FormatCatalogEntry(int index) => index.ToString("D12");

        private static int ReadDword(RegistryKey key, string valueName)
        {
            try
            {
                var v = key.GetValue(valueName);
                if (v == null) return 0;
                return Convert.ToInt32(v);
            }
            catch { return 0; }
        }

        /// <summary>
        /// The protocol catalog stores providers as a serialized WSAPROTOCOL_INFOW blob whose
        /// trailing field (szProtocol) is not the DLL path; the backing DLL path is embedded as a
        /// null-terminated Unicode string within the PackedCatalogItem. Rather than depend on an
        /// exact struct offset (which varies by architecture), we scan the blob for the first
        /// plausible Unicode file-system path ending in ".dll". This is a best-effort extraction:
        /// if nothing is found we return null and the entry is skipped (graceful degradation).
        /// </summary>
        internal static string? ExtractPathFromPackedCatalogItem(byte[]? packed)
        {
            if (packed == null || packed.Length < 4) return null;

            try
            {
                // Decode as UTF-16LE and split on NUL to recover embedded strings.
                string decoded = Encoding.Unicode.GetString(packed);
                foreach (var segment in decoded.Split('\0'))
                {
                    string candidate = segment.Trim();
                    if (candidate.Length < 5) continue;

                    // A provider path looks like a drive path or an environment-var path to a DLL.
                    bool looksLikePath =
                        candidate.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                        (candidate.IndexOf(":\\", StringComparison.Ordinal) >= 0 ||
                         candidate.StartsWith("%", StringComparison.Ordinal) ||
                         candidate.StartsWith(@"\", StringComparison.Ordinal));

                    if (looksLikePath)
                    {
                        return Environment.ExpandEnvironmentVariables(candidate);
                    }
                }
            }
            catch
            {
                // Malformed blob - skip.
            }

            return null;
        }

        /// <summary>
        /// True when the Authenticode signer common-name belongs to Microsoft. Mirrors the
        /// signer-name substring check used by UpdateServicingMonitor so the two agree on what
        /// "Microsoft-signed" means.
        /// </summary>
        internal static bool IsMicrosoftSigner(string? signer)
        {
            if (string.IsNullOrEmpty(signer)) return false;
            return signer!.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
