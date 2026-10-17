using System;
using System.ComponentModel;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class NativeProcessExitVerifierTests
    {
        [Fact]
        public void DeniedTerminationStillWaitsForAlreadyTerminatingProcess()
        {
            int error = 5;
            bool waited = false;
            bool result = NativeProcessExitVerifier.TerminateAndWait(123, 250,
                () => false, () => error, timeout =>
                {
                    waited = true;
                    Assert.Equal(250, timeout);
                    error = 0; // Waiting must not erase the termination error before capture.
                    return 0;
                });
            Assert.True(waited);
            Assert.True(result);
        }

        [Fact]
        public void DeniedTerminationWithoutObservedExitPreservesOriginalError()
        {
            int error = 5;
            var exception = Assert.Throws<Win32Exception>(() =>
                NativeProcessExitVerifier.TerminateAndWait(123, 250,
                    () => false, () => error, timeout => { error = 0; return 0x102; }));
            Assert.Equal(5, exception.NativeErrorCode);
            Assert.Contains("PID 123", exception.Message);
            Assert.Contains("exit not observed", exception.Message);
        }

        [Fact]
        public void SuccessfulTerminationRequestWithoutObservedExitIsIncomplete()
        {
            Assert.False(NativeProcessExitVerifier.TerminateAndWait(123, 250,
                () => true, () => throw new InvalidOperationException("No termination error expected"), _ => 0x102));
        }

        [Fact]
        public void WaitFailureCannotBecomeVerifiedExit()
        {
            var exception = Assert.Throws<Win32Exception>(() =>
                NativeProcessExitVerifier.TerminateAndWait(123, 250,
                    () => true, () => 6, _ => 0xFFFFFFFF));
            Assert.Equal(6, exception.NativeErrorCode);
            Assert.Contains("Exit wait failed", exception.Message);
        }

        [Fact]
        public void SuccessfulRequestRequiresSignaledHandle()
        {
            Assert.True(NativeProcessExitVerifier.TerminateAndWait(123, 250,
                () => true, () => 0, _ => 0));
            Assert.Throws<InvalidOperationException>(() =>
                NativeProcessExitVerifier.TerminateAndWait(123, 250,
                    () => true, () => 0, _ => 0x80));
        }
    }
}
