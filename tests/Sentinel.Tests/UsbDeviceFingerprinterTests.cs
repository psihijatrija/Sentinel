using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class UsbDeviceFingerprinterTests
    {
        //  NormalizeVidPid 

        [Theory]
        [InlineData("0951:1666", "0951:1666")]
        [InlineData("VID_0951&PID_1666", "0951:1666")]
        [InlineData("vid_0951&pid_1666", "0951:1666")]
        [InlineData("0951-1666", "0951:1666")]
        [InlineData("VID_ABCD&PID_EF01", "ABCD:EF01")]
        public void NormalizeVidPid_NormalizesCorrectly(string input, string expected)
        {
            var result = UsbDeviceFingerprinter.NormalizeVidPid(input);
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("garbage")]
        [InlineData("VID_only")]
        [InlineData("12345:67890")] // too long
        public void NormalizeVidPid_ReturnsNull_ForInvalid(string? input)
        {
            Assert.Null(UsbDeviceFingerprinter.NormalizeVidPid(input));
        }

        //  IsFailedEnumerationDevice 

        [Fact]
        public void IsFailedEnumerationDevice_ReturnsTrue_ForFailedDevice()
        {
            var device = new UsbDevice
            {
                DeviceId = "USB\\VID_0000&PID_0000\\0000",
                Vid = "0000",
                Pid = "0000",
                Name = "Unknown USB Device (Device Descriptor Request Failed)",
                IsFailedEnumeration = true
            };
            Assert.True(UsbDeviceFingerprinter.IsFailedEnumerationDevice(device));
        }

        [Fact]
        public void IsFailedEnumerationDevice_ReturnsFalse_ForNormalDevice()
        {
            var device = new UsbDevice
            {
                DeviceId = "USB\\VID_1234&PID_5678\\serial123",
                Vid = "1234",
                Pid = "5678",
                Name = "USB Mass Storage Device",
                IsFailedEnumeration = false
            };
            Assert.False(UsbDeviceFingerprinter.IsFailedEnumerationDevice(device));
        }

        //  IsFailedEnumerationSignals 

        [Theory]
        [InlineData("0000", null)]
        [InlineData("0000", "Something")]
        [InlineData("1234", "Unknown USB Device (Device Descriptor Request Failed)")]
        [InlineData("ABCD", "Device Descriptor Failure")]
        [InlineData("1111", "Port Reset Failed")]
        [InlineData("2222", "Set Address Failed")]
        public void IsFailedEnumerationSignals_ReturnsTrue_ForBadSignals(string? vid, string? name)
        {
            Assert.True(UsbDeviceFingerprinter.IsFailedEnumerationSignals(vid, name));
        }

        [Theory]
        [InlineData("1234", "USB Mass Storage Device")]
        [InlineData("ABCD", "Logitech Mouse")]
        [InlineData("046D", "Logitech USB Keyboard")]
        public void IsFailedEnumerationSignals_ReturnsFalse_ForGoodDevices(string vid, string name)
        {
            Assert.False(UsbDeviceFingerprinter.IsFailedEnumerationSignals(vid, name));
        }

        [Fact]
        public void IsFailedEnumerationSignals_BothNull_ReturnsFalse()
        {
            Assert.False(UsbDeviceFingerprinter.IsFailedEnumerationSignals(null, null));
        }

        [Fact]
        public void IsFailedEnumerationSignals_BlankName_ReturnsFalse()
        {
            // Blank name is NOT a failure signal (v1.7.2 fix)
            Assert.False(UsbDeviceFingerprinter.IsFailedEnumerationSignals("1234", ""));
            Assert.False(UsbDeviceFingerprinter.IsFailedEnumerationSignals("1234", "   "));
        }

        [Fact]
        public void IsFailedEnumerationSignals_UnknownWithoutParens_ReturnsFalse()
        {
            // "Unknown USB Device" without parenthetical reason is NOT treated as failed
            Assert.False(UsbDeviceFingerprinter.IsFailedEnumerationSignals("1234", "Unknown USB Device"));
        }
    }
}
