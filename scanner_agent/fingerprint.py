"""
scanner_agent/fingerprint.py — Device OS and type fingerprinting engine.

Extracted from evaluator.py for single-responsibility.
Uses multiple signal sources to identify device type, OS, and confidence:
  1. MAC OUI vendor prefix
  2. IP TTL analysis
  3. Hostname pattern matching
  4. DHCP vendor class identifier
  5. SSDP/UPnP server headers
  6. mDNS service types
  7. Protocol behaviour patterns

Returns a FingerprintResult with device_type, operating_system, confidence,
vendor, and evidence_sources for transparency.

MITRE ATT&CK: T1592 - Gather Victim Host Information
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from common.constants import DeviceType
from scanner_agent.oui_table import resolve_mac_vendor
from shared.models import FingerprintResult

logger = logging.getLogger("Fingerprint")


# ─── Hostname Patterns ───────────────────────────────────────────────────────

_HOSTNAME_PATTERNS: list[tuple[list[str], str, str, int]] = [
    # (keywords, device_type, os_name, confidence)
    (["iphone", "ipad", "ipod"], DeviceType.PHONE, "iOS", 95),
    (["apple-watch", "applewatch"], DeviceType.IOT, "watchOS", 92),
    (["macbook", "imac", "mac-", "macmini", "macpro", "mac-pro"], DeviceType.PC, "macOS", 95),
    (["android-"], DeviceType.PHONE, "Android", 92),
    (["desktop-", "laptop-", "win-", "windows"], DeviceType.PC, "Windows", 90),
    (
        ["printer", "print", "laserjet", "deskjet", "officejet", "epson", "pixma", "mfc-"],
        DeviceType.PRINTER,
        "Embedded RTOS",
        90,
    ),
    (["tv", "roku", "firetv", "chromecast", "smarttv", "shield", "bravia"], DeviceType.TV, "Smart TV OS", 88),
    (["samsung-tv", "lg-tv", "lgtv"], DeviceType.TV, "Smart TV OS", 90),
    (["router", "gateway", "ap-", "modem", "switch", "hub", "access-point"], DeviceType.ROUTER, "Linux/Embedded", 85),
    (["camera", "cam-", "ipcam", "dvr", "nvr", "nest", "ring", "arlo"], DeviceType.CAMERA, "Embedded Linux", 85),
    (["alexa", "echo-", "echo.", "fire-tv"], DeviceType.IOT, "Amazon OS", 90),
    (["homepod", "airplay"], DeviceType.IOT, "audioOS", 88),
    (["ps4", "ps5", "playstation"], DeviceType.GAME, "PlayStation OS", 90),
    (["xbox"], DeviceType.GAME, "Xbox OS", 90),
    (["nintendo", "switch"], DeviceType.GAME, "Nintendo OS", 88),
    (["android"], DeviceType.PHONE, "Android", 85),
    (["raspberrypi", "raspberry-pi", "pi-model"], DeviceType.IOT, "Raspberry Pi OS", 88),
    (["linux", "ubuntu", "debian", "fedora", "centos"], DeviceType.SERVER, "Linux", 80),
    (["synology", "qnap", "nas-"], DeviceType.SERVER, "NAS OS", 88),
]

# ─── Vendor Classification Rules ──────────────────────────────────────────────

_VENDOR_RULES: dict[str, tuple[str, str, int]] = {
    # vendor_name -> (device_type, os_name, confidence)
    "Apple": (DeviceType.PHONE, "iOS/macOS", 65),
    "Samsung": (DeviceType.PHONE, "Android", 60),
    "Google": (DeviceType.IOT, "Android", 65),
    "Microsoft": (DeviceType.PC, "Windows", 80),
    "HP": (DeviceType.PRINTER, "Embedded RTOS", 75),
    "Epson": (DeviceType.PRINTER, "Embedded RTOS", 80),
    "Canon": (DeviceType.PRINTER, "Embedded RTOS", 80),
    "LG": (DeviceType.TV, "webOS", 70),
    "Sony": (DeviceType.TV, "Smart TV OS", 70),
    "Raspberry Pi Foundation": (DeviceType.IOT, "Raspberry Pi OS", 90),
    "Amazon": (DeviceType.IOT, "Amazon OS", 75),
    "Roku": (DeviceType.TV, "Roku OS", 90),
    "Sonos": (DeviceType.IOT, "Sonos OS", 90),
    "Nintendo": (DeviceType.GAME, "Nintendo OS", 90),
    "Ubiquiti": (DeviceType.ROUTER, "Linux", 85),
    "Cisco": (DeviceType.ROUTER, "Cisco IOS/NX-OS", 85),
    "TP-Link": (DeviceType.ROUTER, "Linux/Embedded", 75),
    "Netgear": (DeviceType.ROUTER, "Linux/Embedded", 75),
    "ASUS": (DeviceType.ROUTER, "Linux/Embedded", 70),
    "D-Link": (DeviceType.ROUTER, "Linux/Embedded", 70),
    "Linksys": (DeviceType.ROUTER, "Linux/Embedded", 70),
    "Synology": (DeviceType.SERVER, "DSM", 90),
    "QNAP": (DeviceType.SERVER, "QTS", 90),
    "VMware": (DeviceType.SERVER, "Virtual Machine", 95),
    "Docker": (DeviceType.SERVER, "Container", 90),
    "Philips Hue": (DeviceType.IOT, "Embedded", 90),
    "Google Nest": (DeviceType.IOT, "Cast OS", 90),
    "Nest": (DeviceType.IOT, "Embedded", 85),
    "Dell": (DeviceType.PC, "Windows/Linux", 60),
    "Lenovo": (DeviceType.PC, "Windows/Linux", 60),
    "Intel": (DeviceType.PC, "Unknown", 40),
    "Huawei": (DeviceType.PHONE, "Android/HarmonyOS", 60),
}

# ─── TTL Fingerprint Rules ─────────────────────────────────────────────────────

_TTL_RULES: list[tuple[range, str, str, int]] = [
    # (ttl_range, os_name, device_type_hint, confidence)
    (range(60, 66), "Linux/Android/Apple OS", DeviceType.UNKNOWN, 55),
    (range(125, 130), "Windows", DeviceType.PC, 65),
    (range(253, 256), "Embedded/Router OS", DeviceType.ROUTER, 55),
    (range(30, 35), "Older Linux/Solaris", DeviceType.SERVER, 45),
]

# ─── DHCP Vendor Class Rules ──────────────────────────────────────────────────

_DHCP_VENDOR_CLASS_RULES: list[tuple[str, str, str, int]] = [
    # (substring, os_name, device_type, confidence)
    ("msft", "Windows", DeviceType.PC, 95),
    ("android", "Android", DeviceType.PHONE, 95),
    ("dhcpcd", "Linux", DeviceType.UNKNOWN, 85),
    ("iphone", "iOS", DeviceType.PHONE, 98),
    ("ipad", "iOS", DeviceType.TABLET, 98),
    ("macos", "macOS", DeviceType.PC, 95),
    ("darwin", "macOS/iOS", DeviceType.PC, 88),
    ("raspberrypi", "Raspberry Pi", DeviceType.IOT, 95),
    ("synology", "DSM", DeviceType.SERVER, 95),
    ("roku", "Roku OS", DeviceType.TV, 95),
    ("amazon", "Amazon OS", DeviceType.IOT, 90),
    ("nintendo", "Nintendo OS", DeviceType.GAME, 95),
]


def fingerprint_device(
    mac: Optional[str] = None,
    hostname: Optional[str] = None,
    ip: Optional[str] = None,
    protocol: Optional[str] = None,
    ttl: Optional[int] = None,
    dhcp_options: Optional[Dict[str, Any]] = None,
    mdns_info: Optional[str] = None,
    ssdp_info: Optional[str] = None,
) -> FingerprintResult:
    """
    Perform multi-signal device fingerprinting.

    Signals are applied in order of increasing confidence:
    TTL < vendor < hostname < DHCP < SSDP
    Later signals can only raise confidence, not lower it.

    Args:
        mac:          Raw MAC address string
        hostname:     Hostname from DNS/mDNS/NBNS/DHCP
        ip:           Source IP address
        protocol:     Protocol hint (mDNS, DHCP, SSDP, etc.)
        ttl:          IP TTL value
        dhcp_options: Dict of DHCP option key->value
        mdns_info:    mDNS service info string
        ssdp_info:    SSDP Server header string

    Returns:
        FingerprintResult with device_type, os, confidence, vendor, and sources
    """
    result = FingerprintResult(
        device_type="unknown",
        operating_system="Unknown",
        confidence=40,
        vendor="Unknown",
        evidence_sources=[],
    )

    mac_clean = (mac or "").lower().replace("-", ":")
    host_clean = (hostname or "").lower()

    # ── 1. Vendor lookup ──────────────────────────────────────────────────────
    vendor = resolve_mac_vendor(mac_clean)
    result.vendor = vendor

    if vendor != "Unknown":
        vr = _VENDOR_RULES.get(vendor)
        if vr:
            dev_type, os_name, conf = vr
            result.device_type = dev_type
            result.operating_system = os_name
            result.confidence = max(result.confidence, conf)
            result.evidence_sources.append(f"OUI:{vendor}")

    # ── 2. TTL analysis ───────────────────────────────────────────────────────
    if ttl is not None:
        for ttl_range, os_name, dev_hint, conf in _TTL_RULES:
            if ttl in ttl_range:
                result.operating_system = os_name
                if result.device_type == "unknown" and dev_hint != DeviceType.UNKNOWN:
                    result.device_type = dev_hint
                result.confidence = max(result.confidence, conf)
                result.evidence_sources.append(f"TTL:{ttl}")
                break

    # ── 3. Protocol hints ─────────────────────────────────────────────────────
    if protocol == "mDNS":
        result.confidence = max(result.confidence, 60)
        result.evidence_sources.append("protocol:mDNS")
    elif protocol == "DHCP":
        result.confidence = max(result.confidence, 70)
        result.evidence_sources.append("protocol:DHCP")
    elif protocol == "SSDP":
        result.confidence = max(result.confidence, 60)
        result.evidence_sources.append("protocol:SSDP")

    # ── 4. Hostname matching ──────────────────────────────────────────────────
    if host_clean and host_clean not in ("unknown", "localhost"):
        for keywords, dev_type, os_name, conf in _HOSTNAME_PATTERNS:
            if any(kw in host_clean for kw in keywords):
                result.device_type = dev_type
                result.operating_system = os_name
                result.confidence = max(result.confidence, conf)
                result.evidence_sources.append(f"hostname:{host_clean[:20]}")
                break

        # iPad specifically (subset of Apple)
        if "ipad" in host_clean:
            result.device_type = DeviceType.TABLET

    # ── 5. DHCP vendor class ID ───────────────────────────────────────────────
    if dhcp_options and isinstance(dhcp_options, dict):
        vendor_class = str(dhcp_options.get("vendor_class_id", "")).lower()
        if vendor_class:
            for substr, os_name, dev_type, conf in _DHCP_VENDOR_CLASS_RULES:
                if substr in vendor_class:
                    result.device_type = dev_type
                    result.operating_system = os_name
                    result.confidence = max(result.confidence, conf)
                    result.evidence_sources.append(f"DHCP_class:{vendor_class[:20]}")
                    break

    # ── 6. SSDP/UPnP headers ─────────────────────────────────────────────────
    if ssdp_info:
        ssdp_lower = ssdp_info.lower()
        if "windows" in ssdp_lower:
            result.device_type = DeviceType.PC
            result.operating_system = "Windows"
            result.confidence = max(result.confidence, 92)
            result.evidence_sources.append("SSDP:Windows")
        elif "lge" in ssdp_lower or "webos" in ssdp_lower:
            result.device_type = DeviceType.TV
            result.operating_system = "webOS"
            result.confidence = max(result.confidence, 95)
            result.evidence_sources.append("SSDP:LG_webOS")
        elif "samsung" in ssdp_lower or "tizen" in ssdp_lower:
            result.device_type = DeviceType.TV
            result.operating_system = "Tizen"
            result.confidence = max(result.confidence, 95)
            result.evidence_sources.append("SSDP:Samsung_Tizen")
        elif "sony" in ssdp_lower:
            result.device_type = DeviceType.TV
            result.operating_system = "Sony Smart TV OS"
            result.confidence = max(result.confidence, 90)
            result.evidence_sources.append("SSDP:Sony")
        elif "roku" in ssdp_lower:
            result.device_type = DeviceType.TV
            result.operating_system = "Roku OS"
            result.confidence = max(result.confidence, 95)
            result.evidence_sources.append("SSDP:Roku")
        elif "xbox" in ssdp_lower:
            result.device_type = DeviceType.GAME
            result.operating_system = "Xbox OS"
            result.confidence = max(result.confidence, 95)
            result.evidence_sources.append("SSDP:Xbox")

    # ── 7. mDNS service hints ─────────────────────────────────────────────────
    if mdns_info:
        mdns_lower = mdns_info.lower()
        if "_airplay" in mdns_lower or "_raop" in mdns_lower:
            result.evidence_sources.append("mDNS:AirPlay")
            result.confidence = max(result.confidence, 80)
        elif "_googlecast" in mdns_lower:
            result.device_type = DeviceType.IOT
            result.operating_system = "Cast OS"
            result.confidence = max(result.confidence, 90)
            result.evidence_sources.append("mDNS:Chromecast")
        elif "_smb" in mdns_lower or "_afpovertcp" in mdns_lower:
            result.device_type = DeviceType.PC
            result.confidence = max(result.confidence, 70)
            result.evidence_sources.append("mDNS:FileSharingService")
        elif "_printer" in mdns_lower or "_ipp" in mdns_lower:
            result.device_type = DeviceType.PRINTER
            result.confidence = max(result.confidence, 88)
            result.evidence_sources.append("mDNS:Printer")

    # ── Clamp confidence ─────────────────────────────────────────────────────
    result.confidence = max(0, min(100, result.confidence))

    return result
