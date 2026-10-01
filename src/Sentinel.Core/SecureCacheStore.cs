using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Sentinel.Core
{
    public class SecureCacheStore
    {
        private readonly string _secureDir;
        private readonly byte[] _hmacKey;

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
            ref DATA_BLOB pDataIn,
            string szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            int dwFlags,
            ref DATA_BLOB pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn,
            IntPtr ppszDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            ref CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            int dwFlags,
            ref DATA_BLOB pDataOut);

        private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        // v1.6.0: Machine-scope DPAPI - service runs as SYSTEM; bind ciphertext to host.
        private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

        public SecureCacheStore(string? customPath = null)
        {
            bool isDefaultPath = string.IsNullOrWhiteSpace(customPath);
            if (!isDefaultPath)
            {
                _secureDir = customPath!;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _secureDir = Path.Combine(programData, "Sentinel", "Secure");
            }

            try
            {
                if (!Directory.Exists(_secureDir))
                {
                    Directory.CreateDirectory(_secureDir);
                }
                
                // Only lock ACLs to SYSTEM + Administrators in production (default path)
                if (isDefaultPath)
                {
                    LockDirectoryAcl(_secureDir);
                }
            }
            catch
            {
                // Degrade gracefully
            }

            // Generate a boot-nonce-bound HMAC key
            _hmacKey = GenerateBootBoundKey();
        }

        private static byte[] GenerateBootBoundKey()
        {
            // SECURITY v1.4.4: Removed predictable components (boot time from PID 4, process ID).
            // Boot time is publicly readable by any standard user. Process ID is visible in task
            // manager. Previously these were 2 of 4 key derivation inputs - an attacker with
            // standard user access could observe both, reducing the key strength to the 2
            // protected components. Now the key derives from ONLY protected/unpredictable sources:
            //   1. Machine GUID (readable by standard users via registry, but unique per machine)
            //   2. Installation entropy (32 random bytes, ACL-locked to SYSTEM + Admins)
            // The combination requires SYSTEM/Admin access to fully reconstruct.

            using var ms = new MemoryStream();

            // 1. Machine GUID - unique per Windows installation, survives reboots.
            // Readable by standard users but combined with entropy below provides
            // machine-binding (key is invalid on a different machine).
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Cryptography");
                var machineGuid = key?.GetValue("MachineGuid")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(machineGuid))
                {
                    ms.Write(Encoding.UTF8.GetBytes(machineGuid));
                }
            }
            catch { }

            // 2. Installation-specific random entropy (32 bytes).
            // v1.6.0: File ACL is SYSTEM-only (Administrators removed) so local admins
            // cannot read the entropy to forge dynamic rules or cache HMACs without
            // first taking ownership / escalating to SYSTEM.
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var entropyFile = Path.Combine(programData, "Sentinel", "Secure", ".install_entropy");
                if (File.Exists(entropyFile))
                {
                    // Best-effort re-lock on every load (upgrades from older ACLs)
                    LockEntropyFileAcl(entropyFile);
                    var entropy = File.ReadAllBytes(entropyFile);
                    if (entropy.Length == 32)
                    {
                        ms.Write(entropy);
                    }
                }
                else
                {
                    // First run: generate and persist random entropy
                    var entropy = new byte[32];
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(entropy);
                    }
                    var dir = Path.GetDirectoryName(entropyFile)!;
                    if (!Directory.Exists(dir))
                        Directory.CreateDirectory(dir);
                    File.WriteAllBytes(entropyFile, entropy);
                    LockEntropyFileAcl(entropyFile);
                    ms.Write(entropy);
                }
            }
            catch { }

            // 3. v2.0 RT-CRIT-3: DPAPI-bound machine secret (SYSTEM-context ciphertext).
            // Even if .install_entropy ACL is weakened and MachineGuid is public, an attacker
            // still needs LocalMachine DPAPI unprotect on this host to reconstruct the key.
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var secretPath = Path.Combine(programData, "Sentinel", "Secure", ".machine_secret.dpapi");
                byte[] plainSecret;
                if (File.Exists(secretPath))
                {
                    LockEntropyFileAcl(secretPath);
                    var cipher = File.ReadAllBytes(secretPath);
                    var plain = UnprotectStatic(cipher);
                    plainSecret = plain != null && plain.Length == 32 ? plain : CreateAndPersistMachineSecret(secretPath);
                }
                else
                {
                    plainSecret = CreateAndPersistMachineSecret(secretPath);
                }
                ms.Write(plainSecret, 0, plainSecret.Length);
            }
            catch
            {
                // Fail-soft: older installs without secret still derive from entropy+GUID
            }

            // 4. v2.0.4 HIGH-1: Process-specific entropy - SHA-256 of our own executable.
            // Even if an attacker achieves SYSTEM, they cannot forge cache entries without
            // also having access to the exact Sentinel binary that generated the key.
            // This binds the HMAC key to the specific Sentinel build/version.
            try
            {
                var ownExe = System.Net48Environment.ProcessPath;
                if (!string.IsNullOrEmpty(ownExe) && File.Exists(ownExe))
                {
                    using var exeStream = new FileStream(ownExe, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sha = SHA256.Create();
                    var exeHash = sha.ComputeHash(exeStream);
                    ms.Write(exeHash, 0, exeHash.Length);
                }
            }
            catch { }

            // 5. Domain-specific label to derive a unique key for cache HMAC
            // (prevents reuse of this key material for other purposes)
            ms.Write(Encoding.UTF8.GetBytes("sentinel-secure-cache-hmac-v4"));

            return System.Security.Cryptography.Sha256Net48.HashData(ms.ToArray());
        }

        private static byte[] CreateAndPersistMachineSecret(string secretPath)
        {
            var secret = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(secret);

            var dir = Path.GetDirectoryName(secretPath)!;
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            var cipher = ProtectStatic(secret);
            if (cipher != null && cipher.Length > 0)
                File.WriteAllBytes(secretPath, cipher);
            LockEntropyFileAcl(secretPath);
            return secret;
        }

        private static byte[]? ProtectStatic(byte[] data)
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
                if (!CryptProtectData(ref blobIn, "SentinelMachineSecret", ref blobEntropy, IntPtr.Zero,
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

        private static byte[]? UnprotectStatic(byte[] data)
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

        public void Save(string cacheName, string key, string value)
        {
            try
            {
                var cacheFilePath = Path.Combine(_secureDir, $"{cacheName}.cache");
                var rawData = $"{key}:{value}";
                var rawBytes = Encoding.UTF8.GetBytes(rawData);

                // Compute HMAC
                byte[] hash;
                using (var hmac = new HMACSHA256(_hmacKey))
                {
                    hash = hmac.ComputeHash(rawBytes);
                }

                // Payload: [HMAC 32 bytes] + [Raw Data]
                var payload = new byte[hash.Length + rawBytes.Length];
                Buffer.BlockCopy(hash, 0, payload, 0, hash.Length);
                Buffer.BlockCopy(rawBytes, 0, payload, hash.Length, rawBytes.Length);

                // DPAPI Encrypt
                var encryptedBytes = Protect(payload);
                File.WriteAllBytes(cacheFilePath, encryptedBytes);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SecureCacheStore Save error: {ex.Message}");
            }
        }

        public string? Load(string cacheName, string key)
        {
            try
            {
                var cacheFilePath = Path.Combine(_secureDir, $"{cacheName}.cache");
                if (!File.Exists(cacheFilePath)) return null;

                var encryptedBytes = File.ReadAllBytes(cacheFilePath);
                var payload = Unprotect(encryptedBytes);
                if (payload == null || payload.Length <= 32) return null;

                // Extract HMAC and Data
                var hmacHash = new byte[32];
                var rawBytes = new byte[payload.Length - 32];
                Buffer.BlockCopy(payload, 0, hmacHash, 0, 32);
                Buffer.BlockCopy(payload, 32, rawBytes, 0, rawBytes.Length);

                // Verify HMAC
                byte[] computedHash;
                using (var hmac = new HMACSHA256(_hmacKey))
                {
                    computedHash = hmac.ComputeHash(rawBytes);
                }

                if (!SecurityValidation.SecureCompare(hmacHash, computedHash))
                {
                    // Tampered or old boot session cache file
                    File.Delete(cacheFilePath);
                    return null;
                }

                var rawData = Encoding.UTF8.GetString(rawBytes);
                var splitIdx = rawData.IndexOf(':');
                if (splitIdx == -1) return null;

                var loadedKey = rawData[..splitIdx];
                var loadedValue = rawData[(splitIdx + 1)..];

                if (loadedKey == key)
                {
                    return loadedValue;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SecureCacheStore Load error: {ex.Message}");
            }
            return null;
        }

        private static byte[] Protect(byte[] data)
        {
            var dataIn = new DATA_BLOB { cbData = data.Length, pbData = Marshal.AllocHGlobal(data.Length) };
            Marshal.Copy(data, 0, dataIn.pbData, data.Length);

            var dataOut = new DATA_BLOB();
            var entropy = new DATA_BLOB();
            var prompt = new CRYPTPROTECT_PROMPTSTRUCT
            {
                cbSize = Marshal.SizeOf<CRYPTPROTECT_PROMPTSTRUCT>()
            };

            try
            {
                int flags = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE;
                if (CryptProtectData(ref dataIn, "SentinelCache", ref entropy, IntPtr.Zero, ref prompt, flags, ref dataOut))
                {
                    var result = new byte[dataOut.cbData];
                    Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData);
                    return result;
                }
                throw new CryptographicException("DPAPI encryption failed");
            }
            finally
            {
                Marshal.FreeHGlobal(dataIn.pbData);
                if (dataOut.pbData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(dataOut.pbData);
                }
            }
        }

        private static byte[]? Unprotect(byte[] data)
        {
            var dataIn = new DATA_BLOB { cbData = data.Length, pbData = Marshal.AllocHGlobal(data.Length) };
            Marshal.Copy(data, 0, dataIn.pbData, data.Length);

            var dataOut = new DATA_BLOB();
            var entropy = new DATA_BLOB();
            var prompt = new CRYPTPROTECT_PROMPTSTRUCT
            {
                cbSize = Marshal.SizeOf<CRYPTPROTECT_PROMPTSTRUCT>()
            };

            try
            {
                // Try machine-scope first (v1.6.0+), then user-scope for legacy cache migration
                int flags = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE;
                if (CryptUnprotectData(ref dataIn, IntPtr.Zero, ref entropy, IntPtr.Zero, ref prompt, flags, ref dataOut))
                {
                    var result = new byte[dataOut.cbData];
                    Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData);
                    return result;
                }
                if (dataOut.pbData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(dataOut.pbData);
                    dataOut.pbData = IntPtr.Zero;
                }
                // Legacy fallback (pre-1.6.0 user-scope blobs)
                if (CryptUnprotectData(ref dataIn, IntPtr.Zero, ref entropy, IntPtr.Zero, ref prompt, CRYPTPROTECT_UI_FORBIDDEN, ref dataOut))
                {
                    var result = new byte[dataOut.cbData];
                    Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData);
                    return result;
                }
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(dataIn.pbData);
                if (dataOut.pbData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(dataOut.pbData);
                }
            }
        }

        /// <summary>
        /// Locks the Secure directory ACL to SYSTEM full control + Administrators read.
        /// Entropy file itself is SYSTEM-only (see LockEntropyFileAcl).
        /// </summary>
        /// <summary>
        /// Public, best-effort reuse of the SYSTEM-full / Admins-read-execute directory ACL applied
        /// to Sentinel's ProgramData surfaces. Used by other reboot-durable stores (e.g.
        /// <see cref="ModuleBaselineStore"/>) so they don't reimplement the DACL. Never throws.
        /// </summary>
        public static void TryLockDirectoryAcl(string directoryPath) => LockDirectoryAcl(directoryPath);

        private static void LockDirectoryAcl(string directoryPath)
        {
            try
            {
                var dirInfo = new DirectoryInfo(directoryPath);
                var security = dirInfo.GetAccessControl();

                // Disable inheritance and remove all inherited ACEs
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                // Remove all existing access rules
                var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                foreach (FileSystemAccessRule rule in rules)
                {
                    security.RemoveAccessRuleAll(rule);
                }

                // Grant SYSTEM full control
                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    systemSid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                // v1.6.0: Administrators get read+execute only (not full control).
                // Prevents casual admin rewrite of cache; entropy is still SYSTEM-only.
                var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    adminSid,
                    FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                dirInfo.SetAccessControl(security);
            }
            catch
            {
                // Best effort - may fail if process is not elevated
            }
        }

        /// <summary>
        /// v1.6.0: SYSTEM-only DACL on .install_entropy so Administrators cannot
        /// read the rule/cache signing material without taking ownership.
        /// </summary>
        private static void LockEntropyFileAcl(string entropyFilePath)
        {
            try
            {
                if (!File.Exists(entropyFilePath)) return;
                var fileInfo = new FileInfo(entropyFilePath);
                var security = fileInfo.GetAccessControl();
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                foreach (FileSystemAccessRule rule in rules)
                {
                    security.RemoveAccessRuleAll(rule);
                }

                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    systemSid,
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));

                fileInfo.SetAccessControl(security);
            }
            catch
            {
                // Best effort - requires SYSTEM or equivalent to set
            }
        }
    }
}
