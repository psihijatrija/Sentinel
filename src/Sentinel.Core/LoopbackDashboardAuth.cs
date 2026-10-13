using System;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.2.0 - Dashboard API authentication helpers.
    /// Bearer token is the only authenticator. Referer is never accepted as proof of origin
    /// (any local process can set an arbitrary Referer header on HttpListener).
    /// </summary>
    public static class LoopbackDashboardAuth
    {
        public const string BearerPrefix = "Bearer ";

        /// <summary>
        /// Extract a bearer token from Authorization header (preferred) or ?token= query.
        /// Returns false when neither is present.
        /// </summary>
        public static bool TryExtractBearer(string? authorizationHeader, string? queryToken, out string token)
        {
            token = "";
            if (!string.IsNullOrEmpty(authorizationHeader) &&
                authorizationHeader!.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
            {
                var extracted = authorizationHeader.Substring(BearerPrefix.Length).Trim();
                if (extracted.Length > 0)
                {
                    token = extracted;
                    return true;
                }
            }

            if (!string.IsNullOrWhiteSpace(queryToken))
            {
                token = queryToken!.Trim();
                return token.Length > 0;
            }

            return false;
        }

        /// <summary>
        /// Authenticate a request. Referer is ignored on purpose - it is client-controlled.
        /// </summary>
        public static bool Authenticate(string? authorizationHeader, string? queryToken, string expectedToken)
        {
            if (string.IsNullOrEmpty(expectedToken))
                return false;
            if (!TryExtractBearer(authorizationHeader, queryToken, out var provided))
                return false;
            return ConstantTimeEquals(provided, expectedToken);
        }

        /// <summary>
        /// Constant-time compare. Length mismatch returns false immediately (token lengths are public).
        /// </summary>
        public static bool ConstantTimeEquals(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }

        /// <summary>
        /// Referer is not an authenticator. Exposed so tests lock this invariant.
        /// </summary>
        public static bool RefererGrantsAccess(string? referer) => false;
    }
}
