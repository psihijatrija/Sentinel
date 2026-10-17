using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Sentinel.Core
{
    /// <summary>
    /// Reviews live Windows root-store contexts for AuthRoot CTL (property 98) and
    /// Microsoft root-program (property 105) markers. Missing markers can represent
    /// private/enterprise roots or an unsuccessful property read; they do not prove
    /// planting, malicious use or possession of a private key.
    /// This observer does not assess EKU/all-purpose usability and never authorizes
    /// removal. CertRemediator requires independent explicit thumbprint distrust.
    /// A present marker is not a guarantee against certificate or process abuse.
    /// </summary>
    public static class CertSuspicionAnalyzer
    {
        // wincrypt.h property IDs.
        private const uint CERT_AUTH_ROOT_SHA256_HASH_PROP_ID = 98; // AuthRoot CTL membership
        private const uint MS_ROOT_PROGRAM_POLICY_PROP_ID = 105;    // 311.60.3.2 program marker

        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertGetCertificateContextProperty(
            IntPtr pCertContext, uint dwPropId, byte[]? pvData, ref uint pcbData);

        /// <summary>
        /// True when the certificate context has the given store property set (non-empty).
        /// Reads off the live context handle; returns false on any failure (fail-safe: a
        /// read failure must never make a cert look MORE trusted than it is... but note this
        /// method reports presence of a TRUST stamp, so a false here only means "could not
        /// confirm the stamp", which the caller treats conservatively - see remarks).
        /// </summary>
        private static bool HasProp(IntPtr ctx, uint propId)
        {
            if (ctx == IntPtr.Zero) return false;
            try
            {
                uint cb = 0;
                return CertGetCertificateContextProperty(ctx, propId, null, ref cb) && cb > 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// True when the certificate carries the AuthRoot CTL membership stamp (public CA in
        /// the OS Trusted Root Program).
        /// </summary>
        public static bool HasCtlStamp(X509Certificate2 cert)
            => cert != null && HasProp(cert.Handle, CERT_AUTH_ROOT_SHA256_HASH_PROP_ID);

        /// <summary>
        /// True when the certificate carries the Microsoft root-program policy marker (OS
        /// program root that signs Windows components).
        /// </summary>
        public static bool HasMsProgramStamp(X509Certificate2 cert)
            => cert != null && HasProp(cert.Handle, MS_ROOT_PROGRAM_POLICY_PROP_ID);

        /// <summary>
        /// True when neither marker can be confirmed. This is review-only context,
        /// including property-read failures, not an autonomous removal verdict.
        /// </summary>
        public static bool IsSuspicious(X509Certificate2 cert)
        {
            if (cert == null) return false;
            return !HasCtlStamp(cert) && !HasMsProgramStamp(cert);
        }

        /// <summary>
        /// Human-readable reason string for logging/evidence.
        /// </summary>
        public static string DescribeVerdict(X509Certificate2 cert)
        {
            if (cert == null) return "null certificate";
            bool ctl = HasCtlStamp(cert);
            bool ms = HasMsProgramStamp(cert);
            if (ctl || ms)
                return $"trusted anchor (AuthRoot-CTL={ctl}, MS-program={ms})";
            return "no AuthRoot-CTL membership and no Microsoft root-program marker " +
                   "(not vouched for by the OS trusted-root program)";
        }
    }
}
