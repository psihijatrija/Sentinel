using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>v1.7.2: Failed-USB classification must not false-positive blank names.</summary>
    public class V172UsbFailedEnumerationTests
    {
        [Theory]
        [InlineData("0000", "Unknown USB Device (Device Descriptor Request Failed)", true)]
        [InlineData("0000", "", true)] // VID_0000 alone is enough
        [InlineData("0000", "Some Composite", true)]
        [InlineData("0951", "Unknown USB Device (Device Descriptor Request Failed)", true)]
        [InlineData("0951", "Device Descriptor Request Failed", true)]
        [InlineData("0951", "Device Descriptor Failure", true)]
        [InlineData("0951", "Unknown USB Device (Port Reset Failed)", true)]
        [InlineData("0951", "Unknown USB Device (Set Address Failed)", true)]
        [InlineData("0951", "Unknown USB Device (Device Descriptor Failure)", true)]
        public void IsFailedEnumerationSignals_DetectsRealWindowsFailures(string vid, string name, bool expected)
        {
            Assert.Equal(expected, UsbDeviceFingerprinter.IsFailedEnumerationSignals(vid, name));
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("0951", "")]
        [InlineData("0951", "USB Mass Storage Device")]
        [InlineData("0951", "Kingston DataTraveler")]
        [InlineData("046D", "Logitech USB Input Device")]
        [InlineData("05E3", "Generic USB Hub")]
        [InlineData("", "USB Composite Device")]
        // Bare "Unknown USB Device" without parenthetical reason must NOT match -
        // pre-1.7.2 invented this name for blank descriptions and disabled healthy devices.
        [InlineData("0951", "Unknown USB Device")]
        [InlineData("18F8", "Unknown USB Device")]
        public void IsFailedEnumerationSignals_DoesNotFalsePositiveNormalDevices(string vid, string name)
        {
            Assert.False(UsbDeviceFingerprinter.IsFailedEnumerationSignals(vid, name));
        }

        [Fact]
        public void IsFailedEnumerationDevice_UsesFlagAndSignals()
        {
            var flagged = new UsbDevice
            {
                Vid = "0951",
                Pid = "1666",
                Name = "Kingston",
                IsFailedEnumeration = true
            };
            Assert.True(UsbDeviceFingerprinter.IsFailedEnumerationDevice(flagged));

            var realFail = new UsbDevice
            {
                Vid = "0000",
                Pid = "0002",
                Name = "Unknown USB Device (Device Descriptor Request Failed)",
                IsFailedEnumeration = false
            };
            Assert.True(UsbDeviceFingerprinter.IsFailedEnumerationDevice(realFail));

            var blankNameHealthyVid = new UsbDevice
            {
                Vid = "0951",
                Pid = "1666",
                Name = "",
                IsFailedEnumeration = false
            };
            Assert.False(UsbDeviceFingerprinter.IsFailedEnumerationDevice(blankNameHealthyVid));
        }

        [Fact]
        public void IsFailedEnumerationDevice_MatchesProductionZombieInstance()
        {
            // Live machine: USB\VID_0000&PID_0002\5&230b5917&0&1
            var zombie = new UsbDevice
            {
                DeviceId = @"USB\VID_0000&PID_0002\5&230b5917&0&1",
                Vid = "0000",
                Pid = "0002",
                Name = "Unknown USB Device (Device Descriptor Request Failed)",
                IsFailedEnumeration = true
            };
            Assert.True(UsbDeviceFingerprinter.IsFailedEnumerationDevice(zombie));
            Assert.True(UsbDeviceFingerprinter.IsFailedEnumerationSignals(zombie.Vid, zombie.Name));
        }
    }
}
