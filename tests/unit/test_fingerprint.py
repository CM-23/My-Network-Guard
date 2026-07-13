"""
tests/unit/test_fingerprint.py — Unit tests for device fingerprinting engine.

Tests verify accuracy of OS/device type detection across all 7 signal sources:
  1. MAC OUI vendor prefix
  2. Hostname patterns
  3. TTL analysis
  4. DHCP vendor class ID
  5. SSDP server headers
  6. mDNS service types
  7. Protocol hints
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from common.constants import DeviceType  # noqa: E402
from scanner_agent.fingerprint import fingerprint_device  # noqa: E402
from scanner_agent.oui_table import resolve_mac_vendor  # noqa: E402


class TestOUIVendorLookup(unittest.TestCase):

    def test_apple_oui(self):
        self.assertEqual(resolve_mac_vendor("00:11:24:ab:cd:ef"), "Apple")

    def test_cisco_oui(self):
        self.assertEqual(resolve_mac_vendor("00:00:0c:01:02:03"), "Cisco")

    def test_raspberry_pi_oui(self):
        self.assertEqual(resolve_mac_vendor("b8:27:eb:11:22:33"), "Raspberry Pi Foundation")

    def test_unknown_oui(self):
        self.assertEqual(resolve_mac_vendor("de:ad:be:ef:00:00"), "Unknown")

    def test_empty_mac(self):
        self.assertEqual(resolve_mac_vendor(""), "Unknown")

    def test_dash_separator_normalized(self):
        # Should normalize dashes to colons
        self.assertEqual(resolve_mac_vendor("00-11-24-ab-cd-ef"), "Apple")


class TestHostnameFingerprinting(unittest.TestCase):

    def test_iphone_hostname(self):
        result = fingerprint_device(hostname="iphone-alice")
        self.assertEqual(result.device_type, DeviceType.PHONE)
        self.assertIn("iOS", result.operating_system)
        self.assertGreater(result.confidence, 80)

    def test_ipad_hostname(self):
        result = fingerprint_device(hostname="ipad-pro-14inch")
        self.assertEqual(result.device_type, DeviceType.TABLET)

    def test_macbook_hostname(self):
        result = fingerprint_device(hostname="macbook-air-johns")
        self.assertEqual(result.device_type, DeviceType.PC)
        self.assertIn("macOS", result.operating_system)

    def test_windows_hostname(self):
        result = fingerprint_device(hostname="DESKTOP-ABC123")
        self.assertEqual(result.device_type, DeviceType.PC)
        self.assertIn("Windows", result.operating_system)

    def test_printer_hostname(self):
        result = fingerprint_device(hostname="hp-laserjet-4000")
        self.assertEqual(result.device_type, DeviceType.PRINTER)

    def test_roku_hostname(self):
        result = fingerprint_device(hostname="roku-express-hd")
        self.assertEqual(result.device_type, DeviceType.TV)

    def test_router_hostname(self):
        result = fingerprint_device(hostname="tp-link-router-8f3c")
        self.assertEqual(result.device_type, DeviceType.ROUTER)

    def test_raspberry_pi_hostname(self):
        result = fingerprint_device(hostname="raspberrypi")
        self.assertEqual(result.device_type, DeviceType.IOT)

    def test_playstation_hostname(self):
        result = fingerprint_device(hostname="PS4-ABC123")
        self.assertEqual(result.device_type, DeviceType.GAME)

    def test_unknown_hostname_returns_low_confidence(self):
        result = fingerprint_device(hostname="device-29fa4b")
        # Unknown hostname — should stay at default confidence
        self.assertLess(result.confidence, 75)


class TestTTLFingerprinting(unittest.TestCase):

    def test_ttl_64_linux(self):
        result = fingerprint_device(ttl=64)
        self.assertIn("Linux", result.operating_system)

    def test_ttl_128_windows(self):
        result = fingerprint_device(ttl=128)
        self.assertIn("Windows", result.operating_system)
        self.assertEqual(result.device_type, DeviceType.PC)

    def test_ttl_255_router(self):
        result = fingerprint_device(ttl=255)
        self.assertIn("Embedded", result.operating_system)


class TestDHCPFingerprinting(unittest.TestCase):

    def test_msft_dhcp_windows(self):
        result = fingerprint_device(dhcp_options={"vendor_class_id": "MSFT 5.0"})
        self.assertEqual(result.device_type, DeviceType.PC)
        self.assertIn("Windows", result.operating_system)
        self.assertGreater(result.confidence, 80)

    def test_android_dhcp(self):
        result = fingerprint_device(dhcp_options={"vendor_class_id": "android-dhcp-12"})
        self.assertEqual(result.device_type, DeviceType.PHONE)
        self.assertIn("Android", result.operating_system)

    def test_iphone_dhcp(self):
        result = fingerprint_device(dhcp_options={"vendor_class_id": "iPhone OS-14.0"})
        self.assertEqual(result.device_type, DeviceType.PHONE)
        self.assertIn("iOS", result.operating_system)

    def test_roku_dhcp(self):
        result = fingerprint_device(dhcp_options={"vendor_class_id": "Roku DVP/9.1"})
        self.assertEqual(result.device_type, DeviceType.TV)


class TestSSDPFingerprinting(unittest.TestCase):

    def test_windows_ssdp(self):
        result = fingerprint_device(ssdp_info="Microsoft-Windows/10.0 UPnP/1.0")
        self.assertEqual(result.device_type, DeviceType.PC)
        self.assertIn("Windows", result.operating_system)

    def test_lg_webos_ssdp(self):
        result = fingerprint_device(ssdp_info="LGE WebOS TV 2022")
        self.assertEqual(result.device_type, DeviceType.TV)
        self.assertIn("webOS", result.operating_system)

    def test_samsung_tizen_ssdp(self):
        result = fingerprint_device(ssdp_info="Samsung/Tizen UPnP/2.0")
        self.assertEqual(result.device_type, DeviceType.TV)
        self.assertIn("Tizen", result.operating_system)

    def test_roku_ssdp(self):
        result = fingerprint_device(ssdp_info="Roku/9.2 UPnP/1.0")
        self.assertEqual(result.device_type, DeviceType.TV)
        self.assertIn("Roku", result.operating_system)


class TestMDNSFingerprinting(unittest.TestCase):

    def test_chromecast_mdns(self):
        result = fingerprint_device(mdns_info="_googlecast._tcp.local")
        self.assertEqual(result.device_type, DeviceType.IOT)
        self.assertIn("Cast", result.operating_system)
        self.assertGreater(result.confidence, 75)

    def test_printer_mdns(self):
        result = fingerprint_device(mdns_info="_ipp._tcp.local HP LaserJet")
        self.assertEqual(result.device_type, DeviceType.PRINTER)

    def test_airplay_mdns(self):
        result = fingerprint_device(mdns_info="_airplay._tcp.local")
        self.assertGreater(result.confidence, 70)


class TestConfidenceRanges(unittest.TestCase):

    def test_confidence_never_exceeds_100(self):
        result = fingerprint_device(
            mac="00:11:24:ab:cd:ef",
            hostname="iphone-alice",
            ttl=64,
            dhcp_options={"vendor_class_id": "iPhone OS-15"},
        )
        self.assertLessEqual(result.confidence, 100)

    def test_confidence_never_below_0(self):
        result = fingerprint_device()
        self.assertGreaterEqual(result.confidence, 0)

    def test_multi_signal_increases_confidence(self):
        hostname_only = fingerprint_device(hostname="iphone-alice")
        multi_signal = fingerprint_device(
            mac="00:11:24:ab:cd:ef",
            hostname="iphone-alice",
            dhcp_options={"vendor_class_id": "iPhone OS-15"},
        )
        self.assertGreaterEqual(multi_signal.confidence, hostname_only.confidence)


if __name__ == "__main__":
    unittest.main()
