using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.0.4: DPAPI-encrypted configuration store for per-deployment secrets and overrides.
    ///
    /// All operational defaults are compiled into the binary
    /// (SentinelConfig / ThreatReportingConfig property initializers).
    /// Only per-deployment values that MUST vary (secrets, trusted devices, victim info)
    /// are stored in a DPAPI-encrypted file at %ProgramData%\Sentinel\Secure\config.enc
    ///
    /// Security properties:
    ///   - Machine-scope DPAPI: only processes on this host can decrypt
    ///   - SYSTEM + Admins ACL: standard users cannot read the ciphertext
    ///   - Integrity HMAC: HMAC-SHA256 over ciphertext with a DPAPI-protected key (v2.2.0).
    ///     Legacy blobs (no SCFG2 header) still decrypt via DPAPI alone.
    ///   - No plaintext config on disk: physical access attacker must break DPAPI
    ///
    /// Opt-in host surface (Hardened Mode, victim identity) via
    /// Sentinel.Service.exe --set-config Key=Value. Cannot disable detection
    /// or rewrite the compiled threat-proxy HMAC.
    /// </summary>
    public sealed class EncryptedConfigStore
    {
        private readonly string _configPath;
        private readonly ILogger? _logger;
        private Dictionary<string, string> _overrides = new(StringComparer.OrdinalIgnoreCase);

        private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public int dwPromptFlags;
            public IntPtr hwndApp;
            public string szPrompt;
        }

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptProtectData(
            ref DATA_BLOB pDataIn, string szDataDescr, ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved, ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            int dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn, IntPtr ppszDataDescr, ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved, ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            int dwFlags, ref DATA_BLOB pDataOut);

        public static string DefaultConfigPath
        {
            get
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                return Path.Combine(programData, "Sentinel", "Secure", "config.enc");
            }
        }

        public EncryptedConfigStore(ILogger? logger = null, string? customPath = null)
        {
            _configPath = customPath ?? DefaultConfigPath;
            _logger = logger;
            Load();
        }

        /// <summary>Gets an override value, or null if not set.</summary>
        public string? GetOverride(string key)
        {
            return _overrides.TryGetValue(key, out var val) ? val : null;
        }

        /// <summary>Sets an override value. Call Save() to persist.</summary>
        public void SetOverride(string key, string? value)
        {
            if (value == null)
                _overrides.Remove(key);
            else
                _overrides[key] = value;
        }

        /// <summary>Returns all override keys (for enumeration/diagnostics).</summary>
        public IReadOnlyCollection<string> Keys => _overrides.Keys;

        /// <summary>Loads and decrypts the config file. Silent on failure (defaults apply).</summary>
        public void Load()
        {
            _overrides.Clear();
            try
            {
                if (!File.Exists(_configPath))
                    return;

                var cipherBytes = File.ReadAllBytes(_configPath);
                if (cipherBytes.Length == 0) return;

                var plainBytes = UnwrapAndUnprotect(cipherBytes);
                if (plainBytes == null || plainBytes.Length == 0)
                {
                    _logger?.LogWarning("[EncryptedConfigStore] Failed to decrypt config.enc - using compiled defaults");
                    return;
                }

                var json = Encoding.UTF8.GetString(plainBytes);
                var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (dict != null)
                    _overrides = new Dictionary<string, string>(dict, StringComparer.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "[EncryptedConfigStore] Error loading config.enc - using compiled defaults");
            }
        }

        /// <summary>Encrypts and saves current overrides to disk.</summary>
        public bool Save()
        {
            try
            {
                var dir = Path.GetDirectoryName(_configPath)!;
                if (!Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                var json = JsonSerializer.Serialize(_overrides, new JsonSerializerOptions { WriteIndented = false });
                var plainBytes = Encoding.UTF8.GetBytes(json);
                var cipherBytes = ProtectAndWrap(plainBytes);
                if (cipherBytes == null)
                {
                    _logger?.LogError("[EncryptedConfigStore] DPAPI encryption failed - config not saved");
                    return false;
                }

                File.WriteAllBytes(_configPath, cipherBytes);
                // Production Secure\config.enc only - unit-test temp paths must stay readable.
                try
                {
                    if (string.Equals(
                            Path.GetFullPath(_configPath),
                            Path.GetFullPath(DefaultConfigPath),
                            StringComparison.OrdinalIgnoreCase))
                        LockFileAcl(_configPath);
                }
                catch { }
                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[EncryptedConfigStore] Failed to save config.enc");
                return false;
            }
        }

        /// <summary>
        /// Applies overrides to the config objects after they are populated from compiled defaults.
        /// Called during service startup.
        /// </summary>
        public void ApplyOverrides(SentinelConfig config, ThreatReportingConfig? threatConfig = null,
            AutoIncidentReportingConfig? incidentConfig = null)
        {
            foreach (var kvp in _overrides)
            {
                switch (kvp.Key)
                {
                    // Threat-proxy HMAC and endpoint are compiled into the binary.
                    // Disk overrides cannot redirect or blank reporting.

                    // Sentinel per-deployment
                    case "TrustedUsbDevices":
                        config.TrustedUsbDevices = kvp.Value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                        break;
                    case "LogPath":
                        config.LogPath = kvp.Value;
                        break;
                    case "WatchPath":
                        config.WatchPath = kvp.Value;
                        break;
                    case "RestrictivePortHardening":
                        // v2.5.5: Hardening is always-on - disk cannot disable it. Silent no-op.
                        break;

                    // Incident reporting identity
                    case "VictimFullName":
                        if (incidentConfig != null) incidentConfig.VictimFullName = kvp.Value;
                        break;
                    case "VictimEmail":
                        if (incidentConfig != null) incidentConfig.VictimEmail = kvp.Value;
                        break;
                    case "VictimPhone":
                        if (incidentConfig != null) incidentConfig.VictimPhone = kvp.Value;
                        break;
                    case "VictimAddress":
                        if (incidentConfig != null) incidentConfig.VictimAddress = kvp.Value;
                        break;
                    case "CountryCode":
                        if (incidentConfig != null) incidentConfig.CountryCode = kvp.Value;
                        break;
                    case "ReportDirectory":
                        if (incidentConfig != null) incidentConfig.ReportDirectory = kvp.Value;
                        break;
                }
            }
        }

        /// <summary>Computes a SHA-256 hash of the encrypted file for integrity monitoring.</summary>
        public string? GetFileHash()
        {
            try
            {
                if (!File.Exists(_configPath)) return null;
                var bytes = File.ReadAllBytes(_configPath);
                return ConvertHex.ToHexString(Sha256Net48.HashData(bytes));
            }
            catch { return null; }
        }

        private static readonly byte[] Scfg2Magic = Encoding.ASCII.GetBytes("SCFG2");

        /// <summary>
        /// v2.2.0 envelope: SCFG2 | keyLen | DPAPI(hmacKey) | HMAC-SHA256(cipher) | DPAPI(json).
        /// Legacy files (no magic) decrypt as raw DPAPI.
        /// </summary>
        private static byte[]? ProtectAndWrap(byte[] data)
        {
            var cipher = Protect(data);
            if (cipher == null) return null;

            var hmacKey = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(hmacKey);

            var wrappedKey = Protect(hmacKey);
            if (wrappedKey == null) return null;

            byte[] hmac;
            using (var h = new HMACSHA256(hmacKey))
                hmac = h.ComputeHash(cipher);

            var envelope = new byte[Scfg2Magic.Length + 4 + wrappedKey.Length + 32 + cipher.Length];
            Buffer.BlockCopy(Scfg2Magic, 0, envelope, 0, Scfg2Magic.Length);
            var keyLen = BitConverter.GetBytes(wrappedKey.Length);
            Buffer.BlockCopy(keyLen, 0, envelope, Scfg2Magic.Length, 4);
            Buffer.BlockCopy(wrappedKey, 0, envelope, Scfg2Magic.Length + 4, wrappedKey.Length);
            Buffer.BlockCopy(hmac, 0, envelope, Scfg2Magic.Length + 4 + wrappedKey.Length, 32);
            Buffer.BlockCopy(cipher, 0, envelope, Scfg2Magic.Length + 4 + wrappedKey.Length + 32, cipher.Length);
            return envelope;
        }

        private static byte[]? UnwrapAndUnprotect(byte[] data)
        {
            if (data.Length >= Scfg2Magic.Length + 4 + 32 && StartsWithMagic(data))
            {
                int keyLen = BitConverter.ToInt32(data, Scfg2Magic.Length);
                if (keyLen < 16 || keyLen > 4096) return null;
                int keyOffset = Scfg2Magic.Length + 4;
                int hmacOffset = keyOffset + keyLen;
                int cipherOffset = hmacOffset + 32;
                if (cipherOffset >= data.Length) return null;

                var wrappedKey = new byte[keyLen];
                Buffer.BlockCopy(data, keyOffset, wrappedKey, 0, keyLen);
                var expectedHmac = new byte[32];
                Buffer.BlockCopy(data, hmacOffset, expectedHmac, 0, 32);
                var cipher = new byte[data.Length - cipherOffset];
                Buffer.BlockCopy(data, cipherOffset, cipher, 0, cipher.Length);

                var hmacKey = Unprotect(wrappedKey);
                if (hmacKey == null) return null;
                byte[] actualHmac;
                using (var h = new HMACSHA256(hmacKey))
                    actualHmac = h.ComputeHash(cipher);
                if (!SecurityValidation.SecureCompare(expectedHmac, actualHmac))
                    return null;
                return Unprotect(cipher);
            }

            // Legacy DPAPI-only blob
            return Unprotect(data);
        }

        private static bool StartsWithMagic(byte[] data)
        {
            for (int i = 0; i < Scfg2Magic.Length; i++)
            {
                if (data[i] != Scfg2Magic[i]) return false;
            }
            return true;
        }

        private static byte[]? Protect(byte[] data)
        {
            var blobIn = new DATA_BLOB();
            var blobOut = new DATA_BLOB();
            var blobEntropy = new DATA_BLOB();
            var prompt = new CRYPTPROTECT_PROMPTSTRUCT { cbSize = Marshal.SizeOf(typeof(CRYPTPROTECT_PROMPTSTRUCT)) };
            try
            {
                blobIn.pbData = Marshal.AllocHGlobal(data.Length);
                blobIn.cbData = data.Length;
                Marshal.Copy(data, 0, blobIn.pbData, data.Length);
                if (!CryptProtectData(ref blobIn, "SentinelConfig", ref blobEntropy, IntPtr.Zero,
                        ref prompt, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ref blobOut))
                    return null;
                var result = new byte[blobOut.cbData];
                Marshal.Copy(blobOut.pbData, result, 0, blobOut.cbData);
                return result;
            }
            catch { return null; }
            finally
            {
                if (blobIn.pbData != IntPtr.Zero) Marshal.FreeHGlobal(blobIn.pbData);
                if (blobOut.pbData != IntPtr.Zero) Marshal.FreeHGlobal(blobOut.pbData);
            }
        }

        private static byte[]? Unprotect(byte[] data)
        {
            var blobIn = new DATA_BLOB();
            var blobOut = new DATA_BLOB();
            var blobEntropy = new DATA_BLOB();
            var prompt = new CRYPTPROTECT_PROMPTSTRUCT { cbSize = Marshal.SizeOf(typeof(CRYPTPROTECT_PROMPTSTRUCT)) };
            try
            {
                blobIn.pbData = Marshal.AllocHGlobal(data.Length);
                blobIn.cbData = data.Length;
                Marshal.Copy(data, 0, blobIn.pbData, data.Length);
                if (!CryptUnprotectData(ref blobIn, IntPtr.Zero, ref blobEntropy, IntPtr.Zero,
                        ref prompt, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ref blobOut))
                    return null;
                var result = new byte[blobOut.cbData];
                Marshal.Copy(blobOut.pbData, result, 0, blobOut.cbData);
                return result;
            }
            catch { return null; }
            finally
            {
                if (blobIn.pbData != IntPtr.Zero) Marshal.FreeHGlobal(blobIn.pbData);
                if (blobOut.pbData != IntPtr.Zero) Marshal.FreeHGlobal(blobOut.pbData);
            }
        }

        private static void LockFileAcl(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                var security = fi.GetAccessControl();
                security.SetAccessRuleProtection(true, false);
                foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    security.RemoveAccessRuleAll(rule);

                var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    system, FileSystemRights.FullControl, AccessControlType.Allow));

                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    admins, FileSystemRights.FullControl, AccessControlType.Allow));

                fi.SetAccessControl(security);
            }
            catch { }
        }
    }
}
