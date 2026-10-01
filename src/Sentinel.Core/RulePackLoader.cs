using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Plugins;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.0 / v2.0.4 - Loads signed correlation rule packs from disk into PluginRegistry.
    ///
    /// Pack location (preferred): %ProgramData%\Sentinel\rules\packs\*.pack.json
    /// Fallback: {installDir}\rules\packs\*.pack.json
    ///
    /// Format:
    /// {
    ///   "name": "example-pack",
    ///   "version": "1.0",
    ///   "rules": [
    ///     {
    ///       "name": "Cred + Network",
    ///       "minSignals": 2,
    ///       "requiredFragments": ["LSASS", "Beacon"],
    ///       "confidence": 0.93,
    ///       "evidence": "Credential access with C2-like network"
    ///     }
    ///   ],
    ///   "signature": "..."
    /// }
    ///
    /// v2.0.4 CRIT-2: Switched from HMAC (symmetric, key on endpoint) to RSA-SHA256 asymmetric
    /// signature verification. Only the public key exists on the endpoint - the private signing
    /// key is kept offline. An attacker who achieves SYSTEM cannot forge rule packs.
    /// Legacy packs with "hmac" field are rejected (migration required).
    /// </summary>
    public sealed class RulePackLoader : BackgroundService
    {
        private readonly PluginRegistry _registry;
        private readonly ILogger<RulePackLoader> _logger;
        private readonly string _packsDir;
        private readonly System.Security.Cryptography.RSA? _verificationKey;
        private readonly HashSet<string> _loaded = new(StringComparer.OrdinalIgnoreCase);
        private FileSystemWatcher? _watcher;

        // v2.0.4: RSA-2048 public key for rule pack signature verification.
        // The private key is kept offline and used only by the pack signing tool.
        // To rotate: generate new keypair, update this constant, re-sign all packs.
        private const string RulePackPublicKeyXml = @"<RSAKeyValue><Modulus>yR9H4x9GqV8a5TKBX7TJfBjDp3WJY8hIxE6R+d3gFsCn3YGVfX0bnQaJGNkFNAaOhJ7pVr0AqM14uQGbcK2RjZ5GvX5CfE6W9HfN7zPzLkz/V2s9Q0Hy48KJd8K3VxB0J6IQXDA0SvaVz6FPuhbRkH0E3YxiLnMmVTP1KkNsOoZH2Q7T0EGmKNfqJ0dn4VE9oP5b8FGYJLxS6V0TgIq5Ka0vSW3C1C8NJHdJ7B8Gx+F0ZQyVR2IxRnKPfM2x1+EbftdH4WJYqHZ4H6e+JQdR7LR4P8E5gN0Xx1K0MZuqE8R9V3K7bS9B2G4tA0J6L8HlD+J7F0K4g9X2P5h5C8w==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        public RulePackLoader(PluginRegistry registry, ILogger<RulePackLoader> logger)
        {
            _registry = registry;
            _logger = logger;
            _verificationKey = LoadVerificationKey();

            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            _packsDir = Path.Combine(programData, "Sentinel", "rules", "packs");
        }

        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                if (!Directory.Exists(_packsDir))
                    Directory.CreateDirectory(_packsDir);

                // Also scan install-dir packs if present
                LoadAllPacks();

                _watcher = new FileSystemWatcher(_packsDir, "*.pack.json")
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                };
                _watcher.Created += (_, _) => SafeReload();
                _watcher.Changed += (_, _) => SafeReload();
                _watcher.EnableRaisingEvents = true;

                _logger.LogInformation("[RulePacks] Watching {Dir} (loaded={Count})",
                    _packsDir, _loaded.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[RulePacks] Init failed - continuing without packs");
            }

            return WaitForeverAsync(stoppingToken);
        }

        private static async Task WaitForeverAsync(CancellationToken ct)
        {
            try { await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }

        private void SafeReload()
        {
            try { LoadAllPacks(); }
            catch (Exception ex) { _logger.LogDebug(ex, "[RulePacks] Reload error"); }
        }

        public int LoadAllPacks()
        {
            var dirs = new List<string> { _packsDir };
            try
            {
                var installPacks = Path.Combine(AppContext.BaseDirectory, "rules", "packs");
                if (Directory.Exists(installPacks))
                    dirs.Add(installPacks);
            }
            catch { }

            int added = 0;
            foreach (var dir in dirs.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var file in Directory.EnumerateFiles(dir, "*.pack.json"))
                {
                    if (_loaded.Contains(file)) continue;
                    if (TryLoadPack(file))
                    {
                        _loaded.Add(file);
                        added++;
                    }
                }
            }
            return added;
        }

        /// <summary>Test helper: load a pack file path directly.</summary>
        public bool TryLoadPack(string filePath)
        {
            try
            {
                // v2.0.4 MED-6: Read with exclusive lock to prevent TOCTOU race condition.
                // If another process modifies the file between read and verify, the lock
                // ensures we get a consistent snapshot.
                string content;
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var reader = new StreamReader(fs, Encoding.UTF8))
                {
                    content = reader.ReadToEnd();
                }

                if (!VerifySignature(content, filePath))
                    return false;

                var pack = JsonSerializer.Deserialize<RulePackFile>(content, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                if (pack?.Rules == null || pack.Rules.Count == 0)
                {
                    _logger.LogWarning("[RulePacks] Empty pack {File}", Path.GetFileName(filePath));
                    return false;
                }

                foreach (var rule in pack.Rules)
                {
                    if (string.IsNullOrWhiteSpace(rule.Name) ||
                        rule.RequiredFragments == null ||
                        rule.RequiredFragments.Count == 0)
                        continue;

                    _registry.Register(new FragmentCorrelationRule(rule, pack.Name));
                    _logger.LogInformation("[RulePacks] Registered correlation rule '{Rule}' from pack '{Pack}'",
                        rule.Name, pack.Name);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[RulePacks] Failed to load {File}", Path.GetFileName(filePath));
                return false;
            }
        }

        private bool VerifySignature(string fileContent, string filePath)
        {
            if (_verificationKey == null)
            {
                _logger.LogError("[RulePacks] REJECTED {File} - RSA verification key unavailable (fail-closed)",
                    Path.GetFileName(filePath));
                return false;
            }

            try
            {
                using var doc = JsonDocument.Parse(fileContent);

                // v2.0.4: Reject legacy HMAC-signed packs - they must be re-signed with RSA
                if (doc.RootElement.TryGetProperty("hmac", out _))
                {
                    _logger.LogWarning("[RulePacks] REJECTED {File} - legacy HMAC signature not accepted (v2.0.4 requires RSA)",
                        Path.GetFileName(filePath));
                    return false;
                }

                if (!doc.RootElement.TryGetProperty("signature", out var sigEl))
                {
                    _logger.LogWarning("[RulePacks] REJECTED {File} - missing 'signature' field", Path.GetFileName(filePath));
                    return false;
                }
                var signatureBase64 = sigEl.GetString();
                if (string.IsNullOrEmpty(signatureBase64)) return false;

                byte[] signatureBytes;
                try { signatureBytes = Convert.FromBase64String(signatureBase64); }
                catch { _logger.LogWarning("[RulePacks] REJECTED {File} - invalid base64 signature", Path.GetFileName(filePath)); return false; }

                var toVerify = RemoveSignatureField(fileContent);
                var dataBytes = Encoding.UTF8.GetBytes(toVerify);

                var ok = _verificationKey.VerifyData(dataBytes, signatureBytes,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                if (!ok)
                    _logger.LogWarning("[RulePacks] REJECTED {File} - RSA signature verification failed", Path.GetFileName(filePath));
                return ok;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[RulePacks] Signature verification error for {File}", Path.GetFileName(filePath));
                return false;
            }
        }

        /// <summary>Test-only path: load without HMAC (unit tests).</summary>
        public int LoadPackForTest(RulePackFile pack)
        {
            if (pack.Rules == null) return 0;
            int n = 0;
            foreach (var rule in pack.Rules)
            {
                if (rule.RequiredFragments == null || rule.RequiredFragments.Count == 0) continue;
                _registry.Register(new FragmentCorrelationRule(rule, pack.Name ?? "test"));
                n++;
            }
            return n;
        }

        private static string RemoveSignatureField(string json)
        {
            using var doc = JsonDocument.Parse(json);
            using var ms = new MemoryStream();
            using (var writer = new Utf8JsonWriter(ms))
            {
                writer.WriteStartObject();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.NameEquals("signature")) continue;
                    prop.WriteTo(writer);
                }
                writer.WriteEndObject();
            }
            return Encoding.UTF8.GetString(ms.ToArray());
        }

        /// <summary>
        /// v2.0.4 CRIT-2 / v2.0.8: Load RSA public key for verification.
        ///
        /// v2.0.8 RT-2026-04: External <c>rulepack_pubkey.xml</c> is no longer trusted by
        /// default. An Administrator with write access to ProgramData could replace it with
        /// their own public key and load attacker-signed packs that drive false chain-nukes.
        /// Only the embedded public key is used. Key rotation requires a product update that
        /// ships a new embedded key (or a future signed key-pin list).
        /// </summary>
        private static System.Security.Cryptography.RSA? LoadVerificationKey()
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var externalKeyPath = Path.Combine(programData, "Sentinel", "Secure", "rulepack_pubkey.xml");
                if (File.Exists(externalKeyPath))
                {
                    // Log-and-ignore: never load admin-writable replacement keys.
                    System.Diagnostics.Debug.WriteLine(
                        "[RulePacks] Ignoring external rulepack_pubkey.xml (v2.0.8: embedded key only)");
                }

                var keyXml = RulePackPublicKeyXml;
                // Refuse private key material if someone ever embeds one by mistake
                if (keyXml.Contains("<D>") || keyXml.Contains("<P>") || keyXml.Contains("<InverseQ>"))
                    return null;

                var rsa = System.Security.Cryptography.RSA.Create();
                rsa.FromXmlString(keyXml);
                return rsa;
            }
            catch
            {
                return null;
            }
        }

        public override void Dispose()
        {
            _watcher?.Dispose();
            base.Dispose();
        }
    }

    public sealed class RulePackFile
    {
        public string Name { get; set; } = "pack";
        public string Version { get; set; } = "1.0";
        public List<RulePackCorrelationRule> Rules { get; set; } = new();
        /// <summary>v2.0.4: RSA-SHA256 signature (base64). Replaces legacy HMAC field.</summary>
        public string? Signature { get; set; }
        [JsonPropertyName("hmac")]
        [Obsolete("v2.0.4: HMAC signing removed. Use 'signature' (RSA-SHA256) instead.")]
        public string? Hmac { get; set; }
    }

    public sealed class RulePackCorrelationRule
    {
        public string Name { get; set; } = "";
        public int MinSignals { get; set; } = 2;
        public List<string> RequiredFragments { get; set; } = new();
        public double Confidence { get; set; } = 0.92;
        public string Evidence { get; set; } = "Rule pack multi-signal match";
        public string Reasoning { get; set; } = "Signed rule pack correlation matched required fragments on one process.";
        public List<string>? AttackTechniques { get; set; }
    }

    /// <summary>
    /// Correlation rule from a signed pack: all RequiredFragments must appear in
    /// distinct rule names within the PID signal buffer (case-insensitive Contains).
    /// </summary>
    public sealed class FragmentCorrelationRule : ICorrelationRule
    {
        private readonly RulePackCorrelationRule _def;
        private readonly string _packName;

        public FragmentCorrelationRule(RulePackCorrelationRule def, string packName)
        {
            _def = def;
            _packName = packName;
        }

        public string Name => $"Pack:{_packName}:{_def.Name}";
        public double MinConfidence => _def.Confidence;

        public DetectionEvent? Evaluate(int processId, string processName, IReadOnlyList<DetectionEvent> signals)
        {
            if (signals == null || signals.Count < Math.Max(2, _def.MinSignals))
                return null;
            if (_def.RequiredFragments == null || _def.RequiredFragments.Count == 0)
                return null;

            var names = signals.Select(s => s.RuleName ?? "").ToList();
            foreach (var frag in _def.RequiredFragments)
            {
                if (string.IsNullOrWhiteSpace(frag)) continue;
                if (!names.Any(n => n.IndexOf(frag, StringComparison.OrdinalIgnoreCase) >= 0))
                    return null;
            }

            var meta = new Dictionary<string, string>
            {
                ["RulePack"] = _packName,
                ["RulePackRule"] = _def.Name,
                [ResponsePolicy.ChainConfirmedKey] = "true",
                [ResponsePolicy.TerminalOutcomeKey] = "Composite",
            };
            if (_def.AttackTechniques != null && _def.AttackTechniques.Count > 0)
                meta["AttackTechniques"] = string.Join(",", _def.AttackTechniques);

            return new DetectionEvent
            {
                RuleName = $"Rule Pack: {_def.Name}",
                ProcessId = processId,
                ProcessName = processName,
                Confidence = Math.Min(0.97, Math.Max(0.85, _def.Confidence)),
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
                SignalType = SignalType.SuspiciousProcess,
                Evidence = $"[COMPOSITE] {_def.Evidence} (pack={_packName}, PID {processId})",
                Reasoning = _def.Reasoning,
                Timestamp = DateTime.UtcNow,
                Metadata = meta
            };
        }
    }
}
