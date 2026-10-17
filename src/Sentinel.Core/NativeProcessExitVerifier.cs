using System;
using System.ComponentModel;

namespace Sentinel.Core
{
    /// <summary>Requires an observed exit on the original process handle, even when termination was denied.</summary>
    internal static class NativeProcessExitVerifier
    {
        internal static bool TerminateAndWait(int processId, int timeoutMilliseconds,
            Func<bool> terminate, Func<int> lastError, Func<int, uint> wait)
        {
            bool requested = terminate();
            // Preserve the termination error before waiting invokes another native API.
            int terminationError = requested ? 0 : lastError();

            // TerminateProcess may return ERROR_ACCESS_DENIED while another actor is already
            // terminating this process. Its handle need not be signaled yet. Wait for proof
            // within the same budget instead of treating that transient state as final failure.
            uint status = wait(timeoutMilliseconds);
            if (status == 0) return true; // WAIT_OBJECT_0: pinned process instance exited
            if (status == 0xFFFFFFFF)
            {
                int error = lastError();
                throw new Win32Exception(error, $"Exit wait failed for PID {processId}: {new Win32Exception(error).Message}");
            }
            if (status != 0x102) // WAIT_TIMEOUT
                throw new InvalidOperationException($"Unexpected exit-wait status {status} for PID {processId}.");
            if (!requested)
                throw new Win32Exception(terminationError,
                    $"Termination failed for PID {processId}; exit not observed within {timeoutMilliseconds}ms: " +
                    new Win32Exception(terminationError).Message);
            return false;
        }
    }
}
