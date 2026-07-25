import os
import sys
import unittest

# Append project directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluator import _config, calculate_entropy, is_local_ip  # noqa: E402


class TestNIDSEvaluator(unittest.TestCase):

    def setUp(self):
        # Configure evaluator settings dynamically for test stability
        _config["local_networks"] = ["192.168.", "10.", "172.16."]
        _config["dns_entropy_threshold"] = 4.5
        _config["dns_length_threshold"] = 60

    def test_shannon_entropy_calculation(self):
        # Test empty string returns 0.0
        self.assertEqual(calculate_entropy(""), 0.0)

        # Test normal low-entropy domain names
        # "google.com" has repeated letters, lower entropy
        self.assertLess(calculate_entropy("google.com"), 3.5)
        self.assertLess(calculate_entropy("github.com"), 3.5)

        # Test high-entropy base32/base64 encoded payloads (tunneling)
        # Random unique letters should yield maximum entropy
        self.assertGreater(calculate_entropy("abcdefghijklmnopqrstuvwxyz12345"), 4.5)

        # Base64 string typical of tunnels
        tunneling_str = "w9x7y2z1a5b8c3d6e4f0g2h1i5j8k3l9m7n1o6p2q4r"
        self.assertGreater(calculate_entropy(tunneling_str), 4.5)

    def test_local_ip_classification(self):
        # Test standard RFC1918 local IPs
        self.assertTrue(is_local_ip("192.168.1.1"))
        self.assertTrue(is_local_ip("192.168.100.250"))
        self.assertTrue(is_local_ip("10.0.0.1"))
        self.assertTrue(is_local_ip("10.255.255.254"))
        self.assertTrue(is_local_ip("172.16.5.9"))

        # Test Loopback
        self.assertTrue(is_local_ip("127.0.0.1"))
        self.assertTrue(is_local_ip("::1"))

        # Test WAN Gateways / Public IPs (non-local)
        self.assertFalse(is_local_ip("8.8.8.8"))
        self.assertFalse(is_local_ip("1.1.1.1"))
        self.assertFalse(is_local_ip("198.51.100.42"))

        # Test Broadcast / Multicast / Invalid IPs
        self.assertFalse(is_local_ip("224.0.0.1"))
        self.assertFalse(is_local_ip("255.255.255.255"))
        self.assertFalse(is_local_ip("0.0.0.0"))
        self.assertFalse(is_local_ip(None))


if __name__ == "__main__":
    unittest.main()
