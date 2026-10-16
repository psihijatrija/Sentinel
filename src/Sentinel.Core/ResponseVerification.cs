using System;
using System.IO;

namespace Sentinel.Core
{
    internal static class ResponseVerification
    {
        internal static ResponseEffect Quarantine(string source, string? vaultPath)
        {
            var effect = new ResponseEffect { Action = "Quarantine", Target = source };
            try
            {
                if (string.IsNullOrEmpty(vaultPath))
                {
                    effect.Status = ResponseExecutionStatus.Refused;
                    effect.Detail = "Quarantine was refused or no vault receipt was returned.";
                }
                else if (IsAbsent(vaultPath!) || (File.GetAttributes(vaultPath!) & FileAttributes.Directory) != 0)
                {
                    effect.Status = ResponseExecutionStatus.Failed;
                    effect.Detail = "Vault receipt returned, but the vault file could not be verified.";
                }
                else if (!IsAbsent(source))
                {
                    effect.Status = ResponseExecutionStatus.Attempted;
                    effect.Detail = "Vault copy exists; source remains present. Removal is deferred or incomplete.";
                }
                else
                {
                    effect.Status = ResponseExecutionStatus.Verified;
                    effect.Detail = "Vault file exists and the source is absent.";
                }
            }
            catch (Exception ex)
            {
                effect.Status = ResponseExecutionStatus.Failed;
                effect.Detail = "Quarantine read-back failed: " + ex.Message;
            }
            return effect;
        }

        internal static bool IsAbsent(string path)
        {
            try { File.GetAttributes(path); return false; }
            catch (FileNotFoundException) { return true; }
            catch (DirectoryNotFoundException) { return true; }
        }
    }
}
