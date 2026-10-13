using System;
using System.Threading;

namespace Sentinel.Core
{
    /// <summary>
    /// Reason a Sentinel process shutdown is considered <b>expected</b> (i.e. cooperative /
    /// legitimate) rather than a possible tamper stop.
    /// </summary>
    public enum ExpectedShutdownReason
    {
        /// <summary>No expected-stop was recorded - treat exit as unexpected/suspicious.</summary>
        None = 0,

        /// <summary>Service Control Manager issued a normal Stop (e.g. admin `sc stop`, host StopAsync).</summary>
        ServiceControllerStop,

        /// <summary>OS is shutting down / user session ending (SERVICE_CONTROL_SHUTDOWN / SessionEnding).</summary>
        SystemShutdown,

        /// <summary>An upgrade is replacing the running build.</summary>
        Upgrade,

        /// <summary>The product is being uninstalled.</summary>
        Uninstall
    }

    /// <summary>
    /// Process-lifetime signal that records whether the current process is being stopped for a
    /// <i>legitimate</i> reason. The exit hook (<see cref="AntiTamperGuard"/>) reads this to decide
    /// whether an exit is a normal lifecycle event or a suspicious stop worth a durable tamper
    /// record (threat-model bypass B1 - "alert before suppression").
    ///
    /// This is deliberate <b>process-lifetime lifecycle metadata</b>, not application state: it is
    /// a single last-writer-wins reason plus timestamp, set only by the cooperative shutdown paths.
    /// The "no static mutable state" rule targets shared <i>domain</i> state that needs
    /// synchronization; a one-shot exit signal is exempt by design and documented here. Access is
    /// still made safe via <see cref="Interlocked"/>/<c>volatile</c>.
    /// </summary>
    public static class ShutdownContext
    {
        // Stored as int for Interlocked; maps to ExpectedShutdownReason.
        private static int _reason = (int)ExpectedShutdownReason.None;
        private static long _markedAtUtcTicks;

        /// <summary>
        /// Records that the process is stopping for an expected reason. First non-None mark wins so
        /// an early legitimate signal is not clobbered by a later teardown step.
        /// </summary>
        public static void MarkExpected(ExpectedShutdownReason reason)
        {
            if (reason == ExpectedShutdownReason.None) return;

            // Only set if currently None (first legitimate reason wins).
            var previous = Interlocked.CompareExchange(
                ref _reason, (int)reason, (int)ExpectedShutdownReason.None);
            if (previous == (int)ExpectedShutdownReason.None)
            {
                Interlocked.Exchange(ref _markedAtUtcTicks, DateTime.UtcNow.Ticks);
            }
        }

        /// <summary>
        /// True when a cooperative/legitimate shutdown reason has been recorded.
        /// </summary>
        public static bool IsExpected =>
            Volatile.Read(ref _reason) != (int)ExpectedShutdownReason.None;

        /// <summary>The recorded expected-stop reason (or <see cref="ExpectedShutdownReason.None"/>).</summary>
        public static ExpectedShutdownReason Reason =>
            (ExpectedShutdownReason)Volatile.Read(ref _reason);

        /// <summary>UTC time the expected reason was recorded, or null if none.</summary>
        public static DateTime? MarkedAtUtc
        {
            get
            {
                var ticks = Interlocked.Read(ref _markedAtUtcTicks);
                return ticks == 0 ? (DateTime?)null : new DateTime(ticks, DateTimeKind.Utc);
            }
        }

        /// <summary>
        /// Test-only reset of the process-lifetime signal. Not intended for production use.
        /// </summary>
        internal static void ResetForTests()
        {
            Interlocked.Exchange(ref _reason, (int)ExpectedShutdownReason.None);
            Interlocked.Exchange(ref _markedAtUtcTicks, 0);
        }
    }
}
