using System;

namespace Sentinel.Core.Ml
{
    /// <summary>Release-reviewed model bytes. A writable sidecar cannot authorize a model.
    /// Updating a model requires a reviewed pin update alongside its training report.</summary>
    internal static class ModelIntegrity
    {
        internal static bool IsApproved(string name, string hash) => name switch
        {
                "pe_model.zip" => string.Equals(hash, "3213a8dada1d4393f436c7c635b53c144a92e67c74762cd9d04ff541c99154a6", StringComparison.OrdinalIgnoreCase),
                "url_model.zip" => string.Equals(hash, "8d1bfc04a5872628a624982f86de22543c105620d7b630e700f9759f5e78b635", StringComparison.OrdinalIgnoreCase),
                _ => false
        };
    }
}
