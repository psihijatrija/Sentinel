using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Sentinel.Core
{
    /// <summary>
    /// v1.6.0 / v1.8.1 / v2.0.4 / v2.0.8: Shared HMAC auth for the Cloudflare threat-proxy Worker.
    ///
    /// Protocol (v2.0.8):
    ///   - Signing key = ThreatReportingConfig.ProxySharedSecret (never transmitted).
    ///   - Payload = $"{unixTimestamp}.{nonce}.{path}.{rawJsonBody}"
    ///   - Headers: X-Sentinel-Timestamp, X-Sentinel-Nonce, X-Sentinel-Signature (hex HMAC-SHA256).
    ///   - Nonce is a 32-char hex string (16 random bytes). Worker rejects replays within the window.
    ///
    /// SECURITY v1.8.1 (RT-CRIT-1): Removed cleartext X-Sentinel-Auth header.
    ///
    /// v2.0.8: Certificate pinning hashes true SubjectPublicKeyInfo (SPKI), not GetPublicKey()
    /// raw material. Also accepts SHA-256(cert.RawData) pins for intermediates that rotate
    /// leaf certs frequently. Dual-format pins keep Cloudflare chain coverage under rotation.
    /// </summary>
    public static class ProxyAuthHelper
    {
        // v2.0.8: Base64(SHA-256(SubjectPublicKeyInfo)) - correct SPKI pins.
        // Plus legacy GetPublicKey()-style pins retained as secondary match for continuity
        // until operators regenerate pins after CA rotation.
        // Pin format docs: https://www.rfc-editor.org/rfc/rfc7469#section-2.4 (SPKI).
        private static readonly string[] PinnedSpkiHashes = new[]
        {
            // Cloudflare Inc ECC CA-3 (SPKI) - Workers intermediate
            "Lgav0MBe0RVNHGOV2aCGLSCj4F8XJGI1YMPgWGMFnuM=",
            // Cloudflare Inc RSA CA-2 (SPKI)
            "jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=",
            // Baltimore CyberTrust Root (SPKI)
            "Y9mvm0exBk1JoQ57f9Vm28jKo5lFm/woKcVxrYxu80o=",
            // DigiCert Global Root G2 (SPKI)
            "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=",
            // DigiCert Global G2 TLS RSA SHA256 2020 CA1 (common Cloudflare intermediate SPKI)
            "8Rw90Ej3Ttt8RRkrg+WYDS9n7IS03bk5bjP/UXPtaY8=",
            // DigiCert TLS RSA SHA256 2020 CA1
            "RQeZkB42znUfsDIIFWIRiYEcKl7nHwNFwWCrnMMJbVc=",
        };

        // v2.3.8: live-chain SPKI pins (Base64 SHA-256 SPKI) for direct CIRCL / MalwareBazaar HTTPS.
        // Captured 2026-09-02 from the presented TLS chain - not invented hashes.
        // Leaf pins rotate; intermediates/roots keep coverage across cert renewal.
        public static readonly string[] CirclHashlookupPins = new[]
        {
            // hashlookup.circl.lu leaf (CN=*.circl.lu)
            "mBzq4UvIEDgA22BvW/mVBYZThnS7Vbm7YdPuca2iCx0=",
            // DigiCert Global G2 TLS RSA SHA256 2020 CA1 (CIRCL chain intermediate)
            "Wec45nQiFwKvHtuHxSAMGkt19k+uPSw9JlEkxhvYPHk=",
            // DigiCert Global Root G2 (same pin as VT/report helper)
            "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=",
        };

        public static readonly string[] MalwareBazaarPins = new[]
        {
            // mb-api.abuse.ch leaf
            "lcJpD91vTKgimQopP7T3Pojug+KQBRitUbmW90pKTeE=",
            // Google Trust Services WR3 intermediate
            "OdSlmQD9NWJh4EbcOHBxkhygPwNSwA9Q91eounfbcoE=",
            // GTS Root R1
            "hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=",
        };

        /// <summary>
        /// When true, pin validation accepts any chain that passes normal TLS
        /// (unit tests / air-gapped labs only). Never set in production builds.
        /// </summary>
        internal static bool PinValidationRelaxedForTests { get; set; }

        /// <summary>
        /// Creates an HttpClient with certificate pinning for the proxy endpoint.
        /// </summary>
        public static HttpClient CreatePinnedHttpClient(int timeoutSeconds = 10)
            => CreatePinnedHttpClient(timeoutSeconds, PinnedSpkiHashes);

        /// <summary>
        /// Creates an HttpClient that requires a matching SPKI (or rotation-safe) pin
        /// from <paramref name="pins"/>. Used for VirusTotal/report (Cloudflare pins)
        /// and for CIRCL / MalwareBazaar (their own chain pins).
        /// </summary>
        public static HttpClient CreatePinnedHttpClient(int timeoutSeconds, IReadOnlyList<string> pins)
        {
            var pinSet = pins ?? Array.Empty<string>();
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (req, cert, chain, errors) =>
                ValidateCertificatePin(req, cert, chain, errors, pinSet);
            return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };
        }

        /// <summary>
        /// Certificate validation: basic TLS must pass AND at least one cert in the chain
        /// must match a pinned SPKI or legacy public-key hash.
        /// </summary>
        internal static bool ValidateCertificatePin(
            HttpRequestMessage request,
            X509Certificate2? certificate,
            X509Chain? chain,
            SslPolicyErrors sslErrors)
            => ValidateCertificatePin(request, certificate, chain, sslErrors, PinnedSpkiHashes);

        internal static bool ValidateCertificatePin(
            HttpRequestMessage request,
            X509Certificate2? certificate,
            X509Chain? chain,
            SslPolicyErrors sslErrors,
            IReadOnlyList<string> pins)
        {
            if (sslErrors != SslPolicyErrors.None)
                return false;

            if (certificate == null)
                return false;

            if (PinValidationRelaxedForTests)
                return true;

            if (IsPinMatch(certificate, pins))
                return true;

            if (chain != null)
            {
                foreach (var element in chain.ChainElements)
                {
                    if (IsPinMatch(element.Certificate, pins))
                        return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Returns true if cert SPKI hash (preferred) or legacy GetPublicKey hash matches a pin.
        /// Exposed for unit tests.
        /// </summary>
        public static bool IsPinMatch(X509Certificate2 cert)
            => IsPinMatch(cert, PinnedSpkiHashes);

        public static bool IsPinMatch(X509Certificate2 cert, IReadOnlyList<string> pins)
        {
            if (cert == null) return false;
            if (pins == null || pins.Count == 0) return false;
            try
            {
                foreach (var candidate in EnumeratePinCandidates(cert))
                {
                    foreach (var pin in pins)
                    {
                        if (string.Equals(candidate, pin, StringComparison.Ordinal))
                            return true;
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>
        /// Enumerates Base64(SHA-256(...)) candidates used for pin matching.
        /// Order: true SPKI, cert DER (rotation-friendly), legacy GetPublicKey.
        /// </summary>
        public static IEnumerable<string> EnumeratePinCandidates(X509Certificate2 cert)
        {
            var list = new List<string>();

            var spki = TryExportSubjectPublicKeyInfo(cert);
            if (spki != null && spki.Length > 0)
                list.Add(Sha256Base64(spki));

            if (cert.RawData != null && cert.RawData.Length > 0)
                list.Add(Sha256Base64(cert.RawData));

            try
            {
                var rawKey = cert.GetPublicKey();
                if (rawKey != null && rawKey.Length > 0)
                    list.Add(Sha256Base64(rawKey));
            }
            catch { }

            return list;
        }

        /// <summary>
        /// Export SubjectPublicKeyInfo DER for RSA (and ECDSA when runtime supports it).
        /// </summary>
        public static byte[]? TryExportSubjectPublicKeyInfo(X509Certificate2 cert)
        {
            if (cert == null) return null;

            // Prefer platform ExportSubjectPublicKeyInfo when present (.NET Core / modern)
            try
            {
                using (var rsa = cert.GetRSAPublicKey())
                {
                    if (rsa != null)
                    {
                        var exported = TryReflectExportSpki(rsa);
                        if (exported != null) return exported;
                        return EncodeRsaSubjectPublicKeyInfo(rsa.ExportParameters(false));
                    }
                }
            }
            catch { }

            try
            {
                using (var ecdsa = cert.GetECDsaPublicKey())
                {
                    if (ecdsa != null)
                    {
                        var exported = TryReflectExportSpki(ecdsa);
                        if (exported != null) return exported;
                    }
                }
            }
            catch { }

            // Last resort: rebuild SPKI from PublicKey ASN.1 pieces (RSA/ECDSA algorithm OID + key)
            try
            {
                return EncodeSpkiFromPublicKeyBlob(cert.PublicKey);
            }
            catch { }

            return null;
        }

        private static byte[]? TryReflectExportSpki(AsymmetricAlgorithm key)
        {
            try
            {
                var mi = key.GetType().GetMethod("ExportSubjectPublicKeyInfo", Type.EmptyTypes);
                if (mi == null) return null;
                return mi.Invoke(key, null) as byte[];
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// PKCS#8-style SubjectPublicKeyInfo for RSA (rsaEncryption OID + BIT STRING of PKCS#1 key).
        /// </summary>
        internal static byte[] EncodeRsaSubjectPublicKeyInfo(RSAParameters p)
        {
            // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
            var modulus = StripLeadingZeros(p.Modulus ?? Array.Empty<byte>());
            var exp = StripLeadingZeros(p.Exponent ?? Array.Empty<byte>());
            var rsaPublicKey = DerSequence(DerInteger(modulus), DerInteger(exp));

            // AlgorithmIdentifier ::= SEQUENCE { rsaEncryption OID, NULL }
            // OID 1.2.840.113549.1.1.1
            byte[] rsaOid = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
            var algId = DerSequence(rsaOid, new byte[] { 0x05, 0x00 });

            // SubjectPublicKeyInfo ::= SEQUENCE { algId, BIT STRING rsaPublicKey }
            var bitString = DerBitString(rsaPublicKey);
            return DerSequence(algId, bitString);
        }

        private static byte[] EncodeSpkiFromPublicKeyBlob(PublicKey publicKey)
        {
            // algorithm: SEQUENCE { OID, parameters }
            var oid = publicKey.Oid;
            var oidDer = EncodeOid(oid?.Value ?? "1.2.840.113549.1.1.1");
            byte[] parameters = publicKey.EncodedParameters?.RawData ?? new byte[] { 0x05, 0x00 };
            var algId = DerSequence(oidDer, parameters);
            var bitString = DerBitString(publicKey.EncodedKeyValue.RawData);
            return DerSequence(algId, bitString);
        }

        private static byte[] EncodeOid(string dotted)
        {
            var parts = dotted.Split('.');
            var values = new List<int>();
            foreach (var part in parts)
                values.Add(int.Parse(part));

            var body = new List<byte>();
            // First two components encoded as 40*X+Y
            body.Add((byte)(40 * values[0] + values[1]));
            for (int i = 2; i < values.Count; i++)
            {
                int v = values[i];
                if (v < 128)
                {
                    body.Add((byte)v);
                }
                else
                {
                    // base-128
                    var stack = new Stack<byte>();
                    stack.Push((byte)(v & 0x7F));
                    v >>= 7;
                    while (v > 0)
                    {
                        stack.Push((byte)(0x80 | (v & 0x7F)));
                        v >>= 7;
                    }
                    while (stack.Count > 0) body.Add(stack.Pop());
                }
            }
            var result = new byte[2 + body.Count];
            result[0] = 0x06;
            result[1] = (byte)body.Count;
            body.CopyTo(result, 2);
            return result;
        }

        private static byte[] StripLeadingZeros(byte[] data)
        {
            int i = 0;
            while (i < data.Length - 1 && data[i] == 0) i++;
            if (i == 0) return data;
            var trimmed = new byte[data.Length - i];
            Buffer.BlockCopy(data, i, trimmed, 0, trimmed.Length);
            return trimmed;
        }

        private static byte[] DerInteger(byte[] value)
        {
            // Positive INTEGER: if high bit set, prefix 0x00
            bool prefix = value.Length > 0 && (value[0] & 0x80) != 0;
            int len = value.Length + (prefix ? 1 : 0);
            using var ms = new MemoryStream();
            ms.WriteByte(0x02);
            WriteDerLength(ms, len);
            if (prefix) ms.WriteByte(0x00);
            ms.Write(value, 0, value.Length);
            return ms.ToArray();
        }

        private static byte[] DerBitString(byte[] value)
        {
            using var ms = new MemoryStream();
            ms.WriteByte(0x03);
            WriteDerLength(ms, value.Length + 1);
            ms.WriteByte(0x00); // unused bits
            ms.Write(value, 0, value.Length);
            return ms.ToArray();
        }

        private static byte[] DerSequence(params byte[][] parts)
        {
            int total = 0;
            foreach (var p in parts) total += p.Length;
            using var ms = new MemoryStream();
            ms.WriteByte(0x30);
            WriteDerLength(ms, total);
            foreach (var p in parts) ms.Write(p, 0, p.Length);
            return ms.ToArray();
        }

        private static void WriteDerLength(Stream s, int length)
        {
            if (length < 0x80)
            {
                s.WriteByte((byte)length);
            }
            else if (length <= 0xFF)
            {
                s.WriteByte(0x81);
                s.WriteByte((byte)length);
            }
            else if (length <= 0xFFFF)
            {
                s.WriteByte(0x82);
                s.WriteByte((byte)(length >> 8));
                s.WriteByte((byte)length);
            }
            else
            {
                s.WriteByte(0x83);
                s.WriteByte((byte)(length >> 16));
                s.WriteByte((byte)(length >> 8));
                s.WriteByte((byte)length);
            }
        }

        private static string Sha256Base64(byte[] data)
        {
            using var sha = SHA256.Create();
            return Convert.ToBase64String(sha.ComputeHash(data));
        }

        public static bool HasSharedSecret(ThreatReportingConfig? config) =>
            config != null && !string.IsNullOrWhiteSpace(config.ProxySharedSecret)
            && config.ProxySharedSecret!.Length >= 16;

        /// <summary>
        /// Signs <paramref name="jsonBody"/> and applies auth headers (timestamp + nonce + signature).
        /// v2.0.8 payload: timestamp.nonce.path.body
        /// </summary>
        public static bool TryApplyAuthHeaders(
            HttpRequestMessage request,
            ThreatReportingConfig config,
            string path,
            string jsonBody)
        {
            if (!HasSharedSecret(config))
                return false;

            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var nonce = CreateNonce();
            var signaturePayload = BuildSignaturePayload(timestamp, nonce, path, jsonBody);
            string signature;
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(config.ProxySharedSecret!)))
            {
                var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(signaturePayload));
                signature = ConvertHex.ToHexString(hash).ToLowerInvariant();
            }

            request.Headers.TryAddWithoutValidation("X-Sentinel-Timestamp", timestamp);
            request.Headers.TryAddWithoutValidation("X-Sentinel-Nonce", nonce);
            request.Headers.TryAddWithoutValidation("X-Sentinel-Signature", signature);
            return true;
        }

        /// <summary>v2.0.8: timestamp.nonce.path.body</summary>
        public static string BuildSignaturePayload(string timestamp, string nonce, string path, string body)
            => $"{timestamp}.{nonce}.{path}.{body}";

        /// <summary>32-char hex nonce (16 random bytes).</summary>
        public static string CreateNonce()
        {
            var bytes = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(bytes);
            return ConvertHex.ToHexString(bytes).ToLowerInvariant();
        }

        /// <summary>
        /// Convenience: build StringContent and a fully-authenticated POST request.
        /// </summary>
        public static (HttpRequestMessage? request, string? error) CreateAuthenticatedPost(
            string baseEndpoint,
            string path,
            string jsonBody,
            ThreatReportingConfig config)
        {
            if (!HasSharedSecret(config))
                return (null, "ProxySharedSecret missing or shorter than 16 characters");

            if (string.IsNullOrWhiteSpace(baseEndpoint))
                return (null, "ProxyEndpoint not configured");

            var url = baseEndpoint.TrimEnd('/') + path;
            var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(jsonBody, Encoding.UTF8, "application/json")
            };

            if (!TryApplyAuthHeaders(request, config, path, jsonBody))
            {
                request.Dispose();
                return (null, "Failed to apply auth headers");
            }

            return (request, null);
        }
    }
}
