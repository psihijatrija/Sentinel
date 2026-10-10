using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Sentinel.Core
{
    /// <summary>
    /// Decides whether a root certificate sitting in a trusted store is "suspicious" using
    /// the two authoritative, non-attacker-controllable stamps Windows itself attaches to
    /// legitimate trust anchors - reverse-engineered from the Zemana AntiLogger "Suspicious
    /// Root CA" behavior and verified against a live Windows root store:
    ///
    ///   - <b>prop 98</b> (<c>CERT_AUTH_ROOT_SHA256_HASH_PROP_ID</c>): set on roots that are
    ///     members of the downloaded Microsoft AuthRoot CTL - i.e. public CAs in the OS
    ///     Trusted Root Program (DigiCert, GlobalSign, ISRG/Let's Encrypt, ...).
    ///   - <b>prop 105</b> (the Microsoft root-program policy marker carrying OID
    ///     <c>1.3.6.1.4.1.311.60.3.2</c>): set on the Microsoft OS program roots that sign
    ///     Windows itself (Microsoft Root CA 2010/2011, etc.).
    ///
    /// A legitimate root carries at least ONE of these stamps. A planted MITM root, an
    /// orphaned/legacy root, or a root Windows has stopped vouching for carries <b>neither</b> -
    /// it is physically in the trusted store but nothing authoritative anchors it.
    ///
    /// Both signals come from the OS CTL/authroot mechanism, not from anything the certificate
    /// itself claims (Subject/Issuer are attacker-controlled and are deliberately ignored).
    ///
    /// SAFETY FLOOR: because this drives autonomous removal, <see cref="IsSuspicious"/> is the
    /// hard gate - a root with EITHER stamp is never suspicious, which is what protects the
    /// load-bearing OS roots and every public CA from being auto-removed.
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
        /// The core verdict. A root is suspicious iff it carries NEITHER authoritative stamp.
        ///
        /// This is deliberately conservative: if either crypt32 read succeeds and reports a
        /// stamp, the cert is trusted and left alone. A cert is only ever flagged when BOTH
        /// reads come back empty, which on a healthy machine is true solely for orphaned /
        /// planted / de-vouched roots.
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
