"""
common/constants.py — Application-wide constants.

All magic strings, enumerations, and tunable defaults live here
so they can be imported from a single location.

OWASP ASVS V1.1: Centralise configuration and avoid scatter.
"""


# ─── Severity Levels ────────────────────────────────────────────────────────
class Severity:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    ALL = (LOW, MEDIUM, HIGH, CRITICAL)


# ─── Alert Types ─────────────────────────────────────────────────────────────
class AlertType:
    # Discovery
    NEW_DEVICE = "NEW_DEVICE_ON_JOIN"

    # Threat detections
    ARP_SPOOFING = "ARP_SPOOFING"
    DNS_TUNNELING = "SUSPICIOUS_DNS"
    PORT_SCAN = "PORT_SCAN"
    MASS_SCAN = "MASS_SCAN"
    ROGUE_DHCP = "ROGUE_DHCP"
    MAC_SPOOFING = "MAC_SPOOFING"
    BEACONING = "BEACONING_C2"
    OUT_OF_HOURS = "UNUSUAL_HOURS"
    MITM = "MITM_DETECTED"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"

    # System
    TEST_ALERT = "TEST_ALERT"


# ─── Device Types ─────────────────────────────────────────────────────────────
class DeviceType:
    PC = "pc"
    PHONE = "phone"
    TABLET = "tablet"
    ROUTER = "router"
    PRINTER = "printer"
    CAMERA = "camera"
    TV = "tv"
    IOT = "iot"
    SERVER = "server"
    GAME = "game_console"
    UNKNOWN = "unknown"

    ALL = (PC, PHONE, TABLET, ROUTER, PRINTER, CAMERA, TV, IOT, SERVER, GAME, UNKNOWN)


# ─── MITRE ATT&CK Mapping ────────────────────────────────────────────────────
class MitreAttack:
    """MITRE ATT&CK technique IDs for Network-based detections (ICS + Enterprise)."""

    ARP_CACHE_POISONING = "T1557.002"  # MITM: ARP Cache Poisoning
    DNS_TUNNELING = "T1071.004"  # C2: DNS Application Layer Protocol
    NETWORK_SERVICE_SCAN = "T1046"  # Discovery: Network Service Scanning
    ACTIVE_SCANNING = "T1595"  # Recon: Active Scanning
    ROGUE_DHCP = "T1557.003"  # MITM: DHCP Spoofing
    MAC_SPOOFING = "T1036"  # Defense Evasion: Masquerading
    C2_BEACONING = "T1071"  # C2: Application Layer Protocol
    LATERAL_MOVEMENT = "T1021"  # Lateral Movement
    OUT_OF_HOURS = "T1078"  # Valid Accounts (unusual hours)


# ─── CWE IDs ─────────────────────────────────────────────────────────────────
class CWE:
    """Common Weakness Enumeration IDs relevant to network threats."""

    ARP_SPOOFING = "CWE-300"  # Channel Accessible by Non-Endpoint
    UNAUTH_ACCESS = "CWE-284"  # Improper Access Control
    INJECTION = "CWE-77"  # Command Injection
    INFO_EXPOSURE = "CWE-200"  # Exposure of Sensitive Information
    INSECURE_COMM = "CWE-319"  # Cleartext Transmission
    RESOURCE_EXHAUSTION = "CWE-400"  # Uncontrolled Resource Consumption
    IMPROPER_AUTH = "CWE-287"  # Improper Authentication


# ─── User Roles ───────────────────────────────────────────────────────────────
class UserRole:
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

    ALL = (ADMIN, ANALYST, VIEWER)


# ─── Input Limits ─────────────────────────────────────────────────────────────
class InputLimits:
    MAX_SSID_LEN = 32
    MAX_PASSWORD_LEN = 64
    MAX_NAME_LEN = 64
    MAX_PHONE_LEN = 20
    MAX_URL_LEN = 2048
    MAX_TOKEN_LEN = 100
    MAX_CHAT_ID_LEN = 20
    MAX_NOTES_LEN = 500


# ─── Scan Modes ──────────────────────────────────────────────────────────────
class ScanMode:
    SIMULATION = "SIMULATION"
    ACTIVE_SCAN = "ACTIVE_SCAN"
    PASSIVE = "PASSIVE_ONLY"
    ARP_CACHE = "ARP_CACHE"


# ─── API Version ─────────────────────────────────────────────────────────────
API_VERSION = "v1"
API_PREFIX = f"/api/{API_VERSION}"
APP_NAME = "My Network Guard"
APP_VERSION = "2.0.0"
