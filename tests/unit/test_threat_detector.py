"""
tests/unit/test_threat_detector.py — Unit tests for the threat detection engine.

Tests verify that each detection heuristic:
  1. Triggers under the correct conditions
  2. Does not false-positive on benign traffic
  3. Produces ThreatEvents with correct alert_type, severity, MITRE, and CWE fields
  4. Deduplicates correctly (does not re-alert the same incident repeatedly)
"""

import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from common.constants import AlertType, MitreAttack, Severity  # noqa: E402
from scanner_agent.threat_detector import ThreatDetector  # noqa: E402
from shared.models import PacketPayload  # noqa: E402


def _ts() -> str:
    return datetime.utcnow().isoformat()


def _pkt(**kwargs) -> PacketPayload:
    defaults = {
        "timestamp": _ts(),
        "src_mac": "aa:bb:cc:dd:ee:01",
        "dst_mac": "ff:ff:ff:ff:ff:ff",
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": "TCP",
    }
    defaults.update(kwargs)
    return PacketPayload(**defaults)


class TestARPSpoofingDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ThreatDetector(
            {
                "local_networks": ["192.168.", "10.", "172.16."],
            }
        )

    def test_detect_multiple_macs_same_ip(self):
        """Two different MACs claiming the same IP should trigger ARP Spoofing."""
        p1 = _pkt(protocol="ARP", src_mac="aa:bb:cc:dd:ee:01", src_ip="192.168.1.1", dst_mac="ff:ff:ff:ff:ff:ff")
        p2 = _pkt(protocol="ARP", src_mac="11:22:33:44:55:66", src_ip="192.168.1.1", dst_mac="ff:ff:ff:ff:ff:ff")

        self.detector.process(p1)
        events = self.detector.process(p2)

        arp_events = [e for e in events if e.alert_type == AlertType.ARP_SPOOFING]
        self.assertTrue(len(arp_events) > 0, "Expected ARP Spoofing alert")
        self.assertEqual(arp_events[0].severity, Severity.HIGH)
        self.assertEqual(arp_events[0].mitre_attack, MitreAttack.ARP_CACHE_POISONING)

    def test_no_false_positive_single_mac(self):
        """Single MAC with single IP should not trigger ARP Spoofing."""
        p1 = _pkt(protocol="ARP", src_mac="aa:bb:cc:dd:ee:01", src_ip="192.168.1.5")
        events = self.detector.process(p1)
        arp_events = [e for e in events if e.alert_type == AlertType.ARP_SPOOFING]
        self.assertEqual(len(arp_events), 0)

    def test_deduplication_no_repeat_alert(self):
        """Same ARP conflict should not generate duplicate alerts."""
        p1 = _pkt(protocol="ARP", src_mac="aa:bb:cc:dd:ee:01", src_ip="192.168.1.1")
        p2 = _pkt(protocol="ARP", src_mac="11:22:33:44:55:66", src_ip="192.168.1.1")

        self.detector.process(p1)
        events1 = self.detector.process(p2)
        events2 = self.detector.process(p2)  # Same pair again

        arp1 = [e for e in events1 if e.alert_type == AlertType.ARP_SPOOFING]
        arp2 = [e for e in events2 if e.alert_type == AlertType.ARP_SPOOFING]

        self.assertEqual(len(arp1), 1, "First detection should produce 1 alert")
        self.assertEqual(len(arp2), 0, "Duplicate should be suppressed")


class TestMACSpooifngDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ThreatDetector()

    def test_detect_mac_change_for_known_ip(self):
        """IP switching to a new MAC should trigger MAC Spoofing."""
        p1 = _pkt(src_ip="192.168.1.10", src_mac="aa:bb:cc:dd:ee:01")
        p2 = _pkt(src_ip="192.168.1.10", src_mac="11:22:33:44:55:66")

        self.detector.process(p1)
        events = self.detector.process(p2)

        mac_events = [e for e in events if e.alert_type == AlertType.MAC_SPOOFING]
        self.assertEqual(len(mac_events), 1)
        self.assertIn("192.168.1.10", mac_events[0].description)

    def test_no_alert_same_mac_same_ip(self):
        """Stable IP/MAC pair should not trigger."""
        p = _pkt(src_ip="192.168.1.20", src_mac="aa:bb:cc:dd:ee:ff")
        self.detector.process(p)
        events = self.detector.process(p)
        mac_events = [e for e in events if e.alert_type == AlertType.MAC_SPOOFING]
        self.assertEqual(len(mac_events), 0)


class TestDNSTunnelingDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ThreatDetector(
            {
                "dns_entropy_threshold": 4.5,
                "dns_length_threshold": 60,
            }
        )

    def test_detect_high_entropy_domain(self):
        """High-entropy domain should trigger DNS tunneling alert."""
        tunnel_domain = "w9x7y2z1a5b8c3d6e4f0g2h1i5j8k3l9m7n1o6p2q4r.evil.com"
        p = _pkt(dst_port=53, dns_query=tunnel_domain)
        events = self.detector.process(p)
        dns_events = [e for e in events if e.alert_type == AlertType.DNS_TUNNELING]
        self.assertTrue(len(dns_events) > 0, f"Expected DNS tunneling alert for: {tunnel_domain}")
        self.assertIn("entropy", dns_events[0].description.lower())

    def test_detect_long_domain(self):
        """Very long domain query should trigger alert."""
        long_domain = "a" * 80 + ".example.com"
        p = _pkt(dst_port=53, dns_query=long_domain)
        events = self.detector.process(p)
        dns_events = [e for e in events if e.alert_type == AlertType.DNS_TUNNELING]
        self.assertTrue(len(dns_events) > 0)

    def test_no_false_positive_google(self):
        """google.com should never trigger DNS tunneling."""
        p = _pkt(dst_port=53, dns_query="www.google.com")
        events = self.detector.process(p)
        dns_events = [e for e in events if e.alert_type == AlertType.DNS_TUNNELING]
        self.assertEqual(len(dns_events), 0)

    def test_no_false_positive_short_normal_domain(self):
        """Short, low-entropy domain should not trigger."""
        p = _pkt(dst_port=53, dns_query="github.com")
        events = self.detector.process(p)
        dns_events = [e for e in events if e.alert_type == AlertType.DNS_TUNNELING]
        self.assertEqual(len(dns_events), 0)


class TestPortScanDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ThreatDetector()

    def test_detect_port_scan_above_threshold(self):
        """16 unique destination ports from same source IP should trigger port scan."""
        events_all = []
        for port in range(20, 37):  # 17 ports
            p = _pkt(
                protocol="TCP", src_ip="10.0.0.5", dst_ip="192.168.1.50", dst_port=port, src_mac="aa:bb:cc:dd:ee:02"
            )
            events_all.extend(self.detector.process(p))

        scan_events = [e for e in events_all if e.alert_type == AlertType.PORT_SCAN]
        self.assertTrue(len(scan_events) > 0, "Expected port scan detection")
        self.assertGreater(scan_events[0].confidence, 50)

    def test_no_false_positive_single_port(self):
        """Repeated traffic to same single port should not trigger port scan."""
        events_all = []
        for _ in range(20):
            p = _pkt(protocol="TCP", src_ip="10.0.0.10", dst_ip="192.168.1.1", dst_port=443)
            events_all.extend(self.detector.process(p))

        scan_events = [e for e in events_all if e.alert_type == AlertType.PORT_SCAN]
        self.assertEqual(len(scan_events), 0)


class TestRogueDHCPDetector(unittest.TestCase):

    def setUp(self):
        self.detector = ThreatDetector()

    def test_detect_second_dhcp_server(self):
        """A second unique DHCP server IP should be flagged as rogue."""
        p1 = _pkt(protocol="DHCP", src_ip="192.168.1.1", src_mac="aa:bb:cc:dd:ee:01")
        p2 = _pkt(protocol="DHCP", src_ip="192.168.1.99", src_mac="de:ad:be:ef:00:01")

        self.detector.process(p1)
        events = self.detector.process(p2)

        dhcp_events = [e for e in events if e.alert_type == AlertType.ROGUE_DHCP]
        self.assertEqual(len(dhcp_events), 1)
        self.assertEqual(dhcp_events[0].severity, Severity.HIGH)

    def test_no_alert_for_first_dhcp_server(self):
        """First DHCP server should not be flagged."""
        p = _pkt(protocol="DHCP", src_ip="192.168.1.1", src_mac="aa:bb:cc:dd:ee:01")
        events = self.detector.process(p)
        dhcp_events = [e for e in events if e.alert_type == AlertType.ROGUE_DHCP]
        self.assertEqual(len(dhcp_events), 0)


class TestThreatEventModel(unittest.TestCase):

    def test_to_alert_produces_valid_alert(self):
        """ThreatEvent.to_alert() should produce a serializable Alert."""
        from shared.models import ThreatEvent

        event = ThreatEvent(
            alert_type="TEST",
            description="Test event",
            severity=Severity.MEDIUM,
            confidence=70,
            evidence={"key": "value"},
            mitre_attack="T1046",
            cwe_id="CWE-400",
            recommended_action="Do something",
        )
        alert = event.to_alert()
        d = alert.to_dict()
        self.assertEqual(d["alert_type"], "TEST")
        self.assertEqual(d["severity"], Severity.MEDIUM)
        self.assertIn("key", d["evidence"])


if __name__ == "__main__":
    unittest.main()
