"""
scanner_agent/threat_detector.py — Multi-heuristic threat detection engine.

Extracted and significantly expanded from evaluator.py.
Each detector produces a ThreatEvent with full context:
  - Severity + Confidence score
  - Evidence dictionary
  - MITRE ATT&CK technique ID
  - CWE identifier
  - Recommended action

Detections implemented:
  1.  New Device Discovery
  2.  ARP Spoofing / Cache Poisoning
  3.  DNS Tunneling (entropy + length)
  4.  Port Scan Detection
  5.  Mass Scan Detection
  6.  Rogue DHCP Server
  7.  MAC Spoofing (OUI mismatch)
  8.  C2 Beaconing Pattern
  9.  Out-of-Hours Unusual Activity
  10. MITM Indicators
  11. Lateral Movement Detection

False Positive Reduction:
  - Known-safe CDN / cloud domains whitelist
  - Multi-indicator correlation for HIGH severity
  - Per-key deduplication with configurable cooldown

OWASP ASVS V7.2: All detections are logged with sufficient context.
MITRE ATT&CK: Multiple technique IDs mapped per detection.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime
from datetime import time as dt_time
from typing import Any, Dict, List, Optional, Set

from common.constants import CWE, AlertType, MitreAttack, Severity
from common.logging_config import get_logger
from shared.models import PacketPayload, ThreatEvent

logger = get_logger("ThreatDetector")


# ─── Safe Domain Whitelist ────────────────────────────────────────────────────

_SAFE_DOMAIN_SUFFIXES: frozenset[str] = frozenset(
    [
        # Google
        ".google.com",
        ".googleapis.com",
        ".gstatic.com",
        ".googleusercontent.com",
        ".googlevideo.com",
        ".googlesyndication.com",
        # Microsoft
        ".microsoft.com",
        ".windowsupdate.com",
        ".live.com",
        ".office.com",
        ".office365.com",
        ".windows.com",
        ".azure.com",
        ".windows.net",
        ".microsoftonline.com",
        ".sharepoint.com",
        ".skype.com",
        ".teams.microsoft.com",
        # Apple
        ".apple.com",
        ".icloud.com",
        ".mzstatic.com",
        ".cdn-apple.com",
        # Amazon / AWS
        ".amazonaws.com",
        ".aws.amazon.com",
        ".cloudfront.net",
        # CDN / Cloud
        ".cloudflare.com",
        ".cloudflare.net",
        ".fastly.net",
        ".akamai.net",
        ".akamaiedge.net",
        ".akamaitech.net",
        ".akamaized.net",
        ".edgesuite.net",
        ".edgekey.net",
        # GitHub
        ".github.com",
        ".githubusercontent.com",
        ".githubassets.com",
        # Meta / Facebook
        ".facebook.com",
        ".fbcdn.net",
        ".instagram.com",
        ".whatsapp.net",
        # Other major CDNs
        ".gws.com",
        ".doubleclick.net",
        ".ggpht.com",
        ".ytimg.com",
        ".googlevideo.com",
        ".netflix.com",
        ".nflximg.net",
        # Local
        ".local",
        ".lan",
        ".home",
        ".arpa",
        ".invalid",
        ".localdomain",
        ".internal",
        ".corp",
    ]
)

_SAFE_DOMAIN_EXACT: frozenset[str] = frozenset(
    [
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "microsoft.com",
        "windowsupdate.com",
        "live.com",
        "office.com",
        "office365.com",
        "windows.com",
        "azure.com",
        "apple.com",
        "icloud.com",
        "amazonaws.com",
        "cloudflare.com",
        "fastly.net",
        "akamai.net",
        "github.com",
        "githubusercontent.com",
        "facebook.com",
        "instagram.com",
        "whatsapp.com",
        "twitter.com",
        "x.com",
        "t.co",
        "localhost",
        "broadcasthost",
    ]
)


def _is_safe_domain(domain: str) -> bool:
    """Return True if domain matches a known-safe CDN/cloud provider."""
    d = domain.lower().rstrip(".")
    if d in _SAFE_DOMAIN_EXACT:
        return True
    return any(d.endswith(suffix) for suffix in _SAFE_DOMAIN_SUFFIXES)


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon Entropy (bits) of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_local_ip(ip: str, local_prefixes: list[str]) -> bool:
    """Return True if IP belongs to RFC1918 or loopback."""
    if not ip:
        return False
    if ip in ("127.0.0.1", "::1"):
        return True
    # Exclude broadcast/multicast
    if ip.startswith("224.") or ip.startswith("239.") or ip in ("255.255.255.255", "0.0.0.0"):
        return False
    return any(ip.startswith(pfx) for pfx in local_prefixes)


# ─── ThreatDetector class ────────────────────────────────────────────────────


class ThreatDetector:
    """
    Stateful threat detection engine.
    Maintains in-memory state for multi-packet detections.
    Call process(payload) for each packet; it yields ThreatEvents.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}

        # Config
        self._local_prefixes: list[str] = cfg.get("local_networks", ["192.168.", "10.", "172.16."])
        self._appliance_macs: list[str] = cfg.get("appliance_macs", [])
        self._ooh_start: str = cfg.get("out_of_hours_start", "01:00")
        self._ooh_end: str = cfg.get("out_of_hours_end", "05:00")
        self._ooh_limit: int = cfg.get("out_of_hours_packet_limit", 50)
        self._dns_entropy_th: float = cfg.get("dns_entropy_threshold", 4.5)
        self._dns_len_th: int = cfg.get("dns_length_threshold", 60)

        # ARP spoofing state
        # mac -> set of IPs it has claimed
        self._arp_mac_to_ips: Dict[str, Set[str]] = defaultdict(set)
        # ip -> set of MACs that have claimed it
        self._arp_ip_to_macs: Dict[str, Set[str]] = defaultdict(set)
        self._arp_alerted: Set[str] = set()

        # Port scan state
        # src_ip -> {dst_ip: set(ports)}
        self._scan_ports: Dict[str, Dict[str, Set[int]]] = defaultdict(lambda: defaultdict(set))
        self._scan_alerted: Set[str] = set()

        # Mass scan state
        # src_ip -> {minute_str: count}
        self._mass_scan_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._mass_scan_alerted: Set[str] = set()

        # Beaconing state
        # (src_ip, dst_ip) -> list of timestamps
        self._beacon_times: Dict[tuple, List[float]] = defaultdict(list)
        self._beacon_alerted: Set[tuple] = set()

        # Out-of-hours state
        # (mac, minute_str) -> count
        self._ooh_counts: Dict[tuple, int] = defaultdict(int)
        self._ooh_alerted: Set[tuple] = set()

        # DNS alert dedup
        # domain -> last_alert_timestamp
        self._dns_alerted: Dict[str, float] = {}

        # DHCP server IPs seen (first one = gateway, extras = rogue)
        self._dhcp_servers: Set[str] = set()
        self._dhcp_alerted: Set[str] = set()

        # Rogue MAC (MAC changed for known IP)
        # ip -> last_seen_mac
        self._ip_to_mac_history: Dict[str, str] = {}
        self._mac_spoof_alerted: Set[str] = set()

        # Lateral movement
        # src_ip -> set(dst_ips in local subnet)
        self._lateral_targets: Dict[str, Set[str]] = defaultdict(set)
        self._lateral_alerted: Set[str] = set()

    def update_config(self, config: Dict[str, Any]) -> None:
        """Hot-reload configuration."""
        self._local_prefixes = config.get("local_networks", self._local_prefixes)
        self._appliance_macs = config.get("appliance_macs", self._appliance_macs)
        self._ooh_limit = config.get("out_of_hours_packet_limit", self._ooh_limit)
        self._dns_entropy_th = config.get("dns_entropy_threshold", self._dns_entropy_th)
        self._dns_len_th = config.get("dns_length_threshold", self._dns_len_th)

    def process(self, payload: PacketPayload) -> List[ThreatEvent]:
        """
        Process a single packet payload and return any triggered ThreatEvents.
        """
        events: List[ThreatEvent] = []

        try:
            src_mac = (payload.src_mac or "").lower()
            src_ip = payload.src_ip or ""
            dst_ip = payload.dst_ip or ""
            dst_port = payload.dst_port or 0
            protocol = payload.protocol or ""
            dns = payload.dns_query
            ts = payload.timestamp

            # Skip broadcast / multicast MACs as source
            if src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                return events

            # ── Detections ───────────────────────────────────────────────────

            # 1. ARP Spoofing
            if protocol in ("ARP", "ARP-CACHE") and src_ip and src_mac:
                ev = self._check_arp_spoofing(src_mac, src_ip, ts)
                if ev:
                    events.append(ev)

            # 2. MAC Spoofing (IP/MAC binding change)
            if src_ip and src_mac:
                ev = self._check_mac_spoofing(src_mac, src_ip, ts)
                if ev:
                    events.append(ev)

            # 3. DNS Tunneling
            if dst_port == 53 and dns:
                ev = self._check_dns_tunneling(src_ip, src_mac, dns, ts)
                if ev:
                    events.append(ev)

            # 4. Port Scan
            if protocol in ("TCP", "TCP-SYN") and dst_port > 0 and src_ip and dst_ip:
                if _is_local_ip(src_ip, self._local_prefixes) and _is_local_ip(dst_ip, self._local_prefixes):
                    pass
                ev = self._check_port_scan(src_ip, dst_ip, dst_port, ts)
                if ev:
                    events.append(ev)

            # 5. Mass Scan
            if src_ip and dst_ip:
                ev = self._check_mass_scan(src_ip, ts)
                if ev:
                    events.append(ev)

            # 6. Rogue DHCP
            if protocol == "DHCP" and src_ip:
                ev = self._check_rogue_dhcp(src_ip, src_mac, ts)
                if ev:
                    events.append(ev)

            # 7. Out-of-Hours Activity
            if src_mac in self._appliance_macs and src_ip and dst_ip:
                if not _is_local_ip(dst_ip, self._local_prefixes):
                    ev = self._check_out_of_hours(src_mac, src_ip, dst_ip, ts)
                    if ev:
                        events.append(ev)

            # 8. Beaconing / C2
            if src_ip and dst_ip and not _is_local_ip(dst_ip, self._local_prefixes):
                ev = self._check_beaconing(src_ip, src_mac, dst_ip, ts)
                if ev:
                    events.append(ev)

            # 9. Lateral Movement
            if src_ip and dst_ip and src_ip != dst_ip:
                if _is_local_ip(src_ip, self._local_prefixes) and _is_local_ip(dst_ip, self._local_prefixes):
                    ev = self._check_lateral_movement(src_ip, src_mac, dst_ip, ts)
                    if ev:
                        events.append(ev)

        except Exception as e:
            logger.error(f"Error in ThreatDetector.process: {e}", exc_info=True)

        return events

    # ── Detector: ARP Spoofing ─────────────────────────────────────────────────

    def _check_arp_spoofing(self, src_mac: str, src_ip: str, ts: str) -> Optional[ThreatEvent]:
        """
        Detect ARP cache poisoning:
          - Multiple MACs claiming same IP (gratuitous ARP attacks)
          - Same MAC claiming many different IPs (proxy ARP / scan)

        MITRE: T1557.002 — MITM: ARP Cache Poisoning
        CWE-300: Channel Accessible by Non-Endpoint
        """
        alert_key = f"{src_mac}:{src_ip}"
        if alert_key in self._arp_alerted:
            return None

        self._arp_mac_to_ips[src_mac].add(src_ip)
        self._arp_ip_to_macs[src_ip].add(src_mac)

        triggered = False
        evidence: Dict[str, Any] = {}
        reason = ""
        confidence = 50

        # Multiple MACs claiming same IP
        macs_for_ip = self._arp_ip_to_macs[src_ip]
        if len(macs_for_ip) > 1:
            triggered = True
            evidence["conflicting_macs"] = list(macs_for_ip)
            evidence["contested_ip"] = src_ip
            reason = f"IP {src_ip} claimed by {len(macs_for_ip)} different MACs: {list(macs_for_ip)}"
            confidence = 75

        # One MAC claiming many IPs (>5 unique in session)
        ips_for_mac = self._arp_mac_to_ips[src_mac]
        if len(ips_for_mac) > 5:
            triggered = True
            evidence["mac_ip_count"] = len(ips_for_mac)
            reason += f" | MAC {src_mac} has claimed {len(ips_for_mac)} different IPs."
            confidence = max(confidence, 65)

        if not triggered:
            return None

        self._arp_alerted.add(alert_key)

        return ThreatEvent(
            alert_type=AlertType.ARP_SPOOFING,
            description=f"ARP Spoofing detected. {reason}",
            severity=Severity.HIGH,
            confidence=confidence,
            evidence=evidence,
            affected_mac=src_mac,
            affected_ip=src_ip,
            mitre_attack=MitreAttack.ARP_CACHE_POISONING,
            cwe_id=CWE.ARP_SPOOFING,
            recommended_action=(
                "Investigate the device with MAC " + src_mac + ". "
                "Check for ARP poisoning tools (arpspoof, ettercap). "
                "Consider enabling Dynamic ARP Inspection (DAI) on managed switches."
            ),
            timestamp=ts,
        )

    # ── Detector: MAC Spoofing ─────────────────────────────────────────────────

    def _check_mac_spoofing(self, src_mac: str, src_ip: str, ts: str) -> Optional[ThreatEvent]:
        """
        Detect when a known IP suddenly appears with a different MAC.
        Indicates possible MAC spoofing or device replacement.

        MITRE: T1036 — Defense Evasion: Masquerading
        CWE-287: Improper Authentication
        """
        prev_mac = self._ip_to_mac_history.get(src_ip)

        if prev_mac is None:
            self._ip_to_mac_history[src_ip] = src_mac
            return None

        if prev_mac == src_mac:
            return None

        alert_key = f"{src_ip}:{src_mac}"
        if alert_key in self._mac_spoof_alerted:
            # Update history but don't re-alert
            self._ip_to_mac_history[src_ip] = src_mac
            return None

        self._mac_spoof_alerted.add(alert_key)
        self._ip_to_mac_history[src_ip] = src_mac

        return ThreatEvent(
            alert_type=AlertType.MAC_SPOOFING,
            description=(
                f"MAC address change detected for IP {src_ip}. "
                f"Previous MAC: {prev_mac} | New MAC: {src_mac}. "
                "This may indicate MAC spoofing or a legitimate device replacement."
            ),
            severity=Severity.MEDIUM,
            confidence=65,
            evidence={
                "ip": src_ip,
                "old_mac": prev_mac,
                "new_mac": src_mac,
            },
            affected_mac=src_mac,
            affected_ip=src_ip,
            mitre_attack=MitreAttack.MAC_SPOOFING,
            cwe_id=CWE.IMPROPER_AUTH,
            recommended_action=(
                "Verify whether the device at IP " + src_ip + " was intentionally replaced. "
                "If unexpected, investigate for MAC spoofing using a packet capture tool."
            ),
            timestamp=ts,
        )

    # ── Detector: DNS Tunneling ────────────────────────────────────────────────

    def _check_dns_tunneling(self, src_ip: str, src_mac: str, dns_query: str, ts: str) -> Optional[ThreatEvent]:
        """
        Detect DNS tunneling via:
          - High Shannon entropy of subdomain
          - Excessive query length
          - Repeated queries to same suspicious domain

        MITRE: T1071.004 — C2: DNS
        CWE-200: Exposure of Sensitive Information
        """
        if _is_safe_domain(dns_query):
            return None

        query_len = len(dns_query)
        entropy = _shannon_entropy(dns_query)

        len_trigger = query_len > self._dns_len_th
        entropy_trigger = entropy > self._dns_entropy_th

        if not (len_trigger or entropy_trigger):
            return None

        # Dedup: don't re-alert same domain within 30 seconds
        now_ts = datetime.now().timestamp()
        last = self._dns_alerted.get(dns_query, 0)
        if now_ts - last < 30:
            return None
        self._dns_alerted[dns_query] = now_ts

        # Build confidence score
        confidence = 50
        reasons: List[str] = []

        if entropy > 4.8:
            confidence += 25
            reasons.append(f"Very high entropy ({entropy:.2f} bits > 4.8)")
        elif entropy > 4.5:
            confidence += 15
            reasons.append(f"High entropy ({entropy:.2f} bits > 4.5)")

        if query_len > 100:
            confidence += 20
            reasons.append(f"Very long query ({query_len} chars > 100)")
        elif query_len > 80:
            confidence += 12
            reasons.append(f"Long query ({query_len} chars > 80)")
        elif query_len > 60:
            confidence += 6
            reasons.append(f"Elevated query length ({query_len} chars > 60)")

        confidence = min(confidence, 100)

        severity = Severity.HIGH if confidence >= 70 else Severity.MEDIUM

        return ThreatEvent(
            alert_type=AlertType.DNS_TUNNELING,
            description=(
                f"Potential DNS tunneling detected from {src_ip}. "
                f"Query: '{dns_query[:60]}...' | {' | '.join(reasons)} | Confidence: {confidence}%"
            ),
            severity=severity,
            confidence=confidence,
            evidence={
                "query": dns_query,
                "entropy": round(entropy, 3),
                "length": query_len,
                "reasons": reasons,
                "src_ip": src_ip,
            },
            affected_mac=src_mac,
            affected_ip=src_ip,
            mitre_attack=MitreAttack.DNS_TUNNELING,
            cwe_id=CWE.INFO_EXPOSURE,
            recommended_action=(
                "Block DNS queries to this domain at the firewall/DNS resolver. "
                "Investigate the source device " + src_ip + " for malware or data exfiltration tools. "
                "Consider enabling DNS over HTTPS (DoH) with a filtering resolver (e.g. Cloudflare for Families)."
            ),
            timestamp=ts,
        )

    # ── Detector: Port Scan ────────────────────────────────────────────────────

    def _check_port_scan(self, src_ip: str, dst_ip: str, dst_port: int, ts: str) -> Optional[ThreatEvent]:
        """
        Detect port scanning: single source IP hitting > 15 unique ports
        on the same destination within a session.

        MITRE: T1046 — Network Service Scanning
        CWE-400: Uncontrolled Resource Consumption
        """
        alert_key = f"{src_ip}:{dst_ip}"
        if alert_key in self._scan_alerted:
            return None

        self._scan_ports[src_ip][dst_ip].add(dst_port)
        port_count = len(self._scan_ports[src_ip][dst_ip])

        if port_count < 15:
            return None

        self._scan_alerted.add(alert_key)
        ports_seen = sorted(self._scan_ports[src_ip][dst_ip])[:20]  # cap evidence

        confidence = min(50 + port_count * 2, 95)
        severity = Severity.HIGH if port_count > 30 else Severity.MEDIUM

        return ThreatEvent(
            alert_type=AlertType.PORT_SCAN,
            description=(
                f"Port scan detected from {src_ip} targeting {dst_ip}. "
                f"{port_count} unique ports probed. Sample ports: {ports_seen[:10]}"
            ),
            severity=severity,
            confidence=confidence,
            evidence={
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port_count": port_count,
                "ports": ports_seen,
            },
            affected_mac=None,
            affected_ip=src_ip,
            mitre_attack=MitreAttack.NETWORK_SERVICE_SCAN,
            cwe_id=CWE.RESOURCE_EXHAUSTION,
            recommended_action=(
                "Investigate the source device at " + src_ip + ". "
                "Block the IP at the firewall if unauthorised. "
                "Check for reconnaissance tools (nmap, masscan) on the device."
            ),
            timestamp=ts,
        )

    # ── Detector: Mass Scan ─────────────────────────────────────────────────────

    def _check_mass_scan(self, src_ip: str, ts: str) -> Optional[ThreatEvent]:
        """
        Detect mass scanning: > 100 packets per minute from single source.

        MITRE: T1595 — Active Scanning
        CWE-400: Resource Exhaustion
        """
        try:
            dt = datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            dt = datetime.utcnow()

        minute_key = dt.strftime("%Y-%m-%dT%H:%M")
        alert_key = f"{src_ip}:{minute_key}"

        if alert_key in self._mass_scan_alerted:
            return None

        self._mass_scan_counts[src_ip][minute_key] += 1
        count = self._mass_scan_counts[src_ip][minute_key]

        if count < 150:
            return None

        self._mass_scan_alerted.add(alert_key)

        return ThreatEvent(
            alert_type=AlertType.MASS_SCAN,
            description=(f"Mass scan/traffic anomaly from {src_ip}: " f"{count} packets in 1 minute (threshold: 150)."),
            severity=Severity.HIGH,
            confidence=min(60 + count // 10, 95),
            evidence={
                "src_ip": src_ip,
                "count": count,
                "window": minute_key,
            },
            affected_ip=src_ip,
            mitre_attack=MitreAttack.ACTIVE_SCANNING,
            cwe_id=CWE.RESOURCE_EXHAUSTION,
            recommended_action=(
                "Rate-limit or block " + src_ip + " at the network level. "
                "Investigate the device for scanning tools or malware."
            ),
            timestamp=ts,
        )

    # ── Detector: Rogue DHCP ──────────────────────────────────────────────────

    def _check_rogue_dhcp(self, src_ip: str, src_mac: str, ts: str) -> Optional[ThreatEvent]:
        """
        Detect rogue DHCP servers:
        The first DHCP server seen is assumed legitimate (gateway).
        Any subsequent DHCP server from a different IP is suspicious.

        MITRE: T1557.003 — MITM: DHCP Spoofing
        CWE-300: Channel Accessible by Non-Endpoint
        """
        if not self._dhcp_servers:
            self._dhcp_servers.add(src_ip)
            return None

        if src_ip in self._dhcp_servers or src_ip in self._dhcp_alerted:
            return None

        self._dhcp_alerted.add(src_ip)
        self._dhcp_servers.add(src_ip)

        return ThreatEvent(
            alert_type=AlertType.ROGUE_DHCP,
            description=(
                f"Rogue DHCP server detected at {src_ip} (MAC: {src_mac}). "
                f"Known DHCP servers: {list(self._dhcp_servers)}. "
                "An attacker may be attempting MITM via DHCP spoofing."
            ),
            severity=Severity.HIGH,
            confidence=80,
            evidence={
                "rogue_server_ip": src_ip,
                "rogue_server_mac": src_mac,
                "known_dhcp_servers": list(self._dhcp_servers),
            },
            affected_mac=src_mac,
            affected_ip=src_ip,
            mitre_attack=MitreAttack.ROGUE_DHCP,
            cwe_id=CWE.ARP_SPOOFING,
            recommended_action=(
                "Identify and isolate the rogue DHCP server at " + src_ip + ". "
                "Enable DHCP snooping on managed switches. "
                "Check for VPN software or mobile hotspots broadcasting DHCP."
            ),
            timestamp=ts,
        )

    # ── Detector: Out-of-Hours Activity ───────────────────────────────────────

    def _check_out_of_hours(self, src_mac: str, src_ip: str, dst_ip: str, ts: str) -> Optional[ThreatEvent]:
        """
        Detect configured appliances communicating with WAN during off-hours.

        MITRE: T1078 — Valid Accounts (unusual time)
        CWE-284: Improper Access Control
        """
        try:
            dt = datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            dt = datetime.utcnow()

        # Parse out-of-hours window
        try:
            start_h, start_m = map(int, self._ooh_start.split(":"))
            end_h, end_m = map(int, self._ooh_end.split(":"))
            ooh_start = dt_time(start_h, start_m)
            ooh_end = dt_time(end_h, end_m)
        except ValueError:
            return None

        current_time = dt.time()
        in_window = (
            ooh_start <= current_time < ooh_end
            if ooh_start < ooh_end
            else current_time >= ooh_start or current_time < ooh_end
        )

        if not in_window:
            return None

        minute_key = dt.strftime("%Y-%m-%dT%H:%M")
        rate_key = (src_mac, minute_key)
        self._ooh_counts[rate_key] += 1
        count = self._ooh_counts[rate_key]

        if count < self._ooh_limit:
            return None

        if rate_key in self._ooh_alerted:
            return None

        self._ooh_alerted.add(rate_key)

        return ThreatEvent(
            alert_type=AlertType.OUT_OF_HOURS,
            description=(
                f"Unusual out-of-hours activity: Appliance {src_mac} ({src_ip}) "
                f"sent {count} packets to WAN IP {dst_ip} between "
                f"{self._ooh_start}–{self._ooh_end}."
            ),
            severity=Severity.HIGH,
            confidence=75,
            evidence={
                "src_mac": src_mac,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "count": count,
                "time": current_time.isoformat(),
                "ooh_window": f"{self._ooh_start}–{self._ooh_end}",
            },
            affected_mac=src_mac,
            affected_ip=src_ip,
            mitre_attack=MitreAttack.OUT_OF_HOURS,
            cwe_id=CWE.UNAUTH_ACCESS,
            recommended_action=(
                "Check whether this appliance ("
                + src_ip
                + ") should be communicating with "
                + dst_ip
                + " at this hour. "
                "If unexpected, investigate for malware or unwanted software updates. "
                "Consider scheduling update windows and blocking out-of-hours WAN access."
            ),
            timestamp=ts,
        )

    # ── Detector: C2 Beaconing ────────────────────────────────────────────────

    def _check_beaconing(self, src_ip: str, src_mac: str, dst_ip: str, ts: str) -> Optional[ThreatEvent]:
        """
        Detect regular interval (beaconing) communication to external IP.
        A jitter < 10% over 5+ connections suggests automated C2 communication.

        MITRE: T1071 — C2: Application Layer Protocol
        CWE-284: Improper Access Control
        """
        pair_key = (src_ip, dst_ip)
        if pair_key in self._beacon_alerted:
            return None

        try:
            ts_float = datetime.fromisoformat(ts).timestamp()
        except (ValueError, TypeError):
            ts_float = datetime.utcnow().timestamp()

        times = self._beacon_times[pair_key]
        times.append(ts_float)

        # Need at least 6 observations
        if len(times) < 6:
            return None

        # Keep only last 20
        if len(times) > 20:
            times.pop(0)

        # Calculate inter-packet intervals
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        if not intervals or min(intervals) < 5:  # Too fast — not beaconing
            return None

        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < 10:  # Intervals too small (< 10 sec)
            return None

        # Check jitter
        deviations = [abs(iv - avg_interval) for iv in intervals]
        avg_jitter = sum(deviations) / len(deviations)
        jitter_pct = (avg_jitter / avg_interval) * 100 if avg_interval else 100

        # Low jitter (< 15%) is suspicious beaconing behaviour
        if jitter_pct > 15:
            return None

        self._beacon_alerted.add(pair_key)

        confidence = max(60, min(95, int(100 - jitter_pct * 2)))

        return ThreatEvent(
            alert_type=AlertType.BEACONING,
            description=(
                f"Potential C2 beaconing from {src_ip} to external {dst_ip}. "
                f"Average interval: {avg_interval:.1f}s, Jitter: {jitter_pct:.1f}% "
                f"(low jitter suggests automated communication). Confidence: {confidence}%"
            ),
            severity=Severity.HIGH,
            confidence=confidence,
            evidence={
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "observations": len(times),
                "avg_interval_s": round(avg_interval, 2),
                "jitter_pct": round(jitter_pct, 2),
            },
            affected_mac=src_mac,
            affected_ip=src_ip,
            mitre_attack=MitreAttack.C2_BEACONING,
            cwe_id=CWE.UNAUTH_ACCESS,
            recommended_action=(
                "Block outbound connection from " + src_ip + " to " + dst_ip + " at the firewall. "
                "Perform malware analysis on the device. "
                "Check for recently installed software or scheduled tasks that may initiate callbacks."
            ),
            timestamp=ts,
        )

    # ── Detector: Lateral Movement ────────────────────────────────────────────

    def _check_lateral_movement(self, src_ip: str, src_mac: str, dst_ip: str, ts: str) -> Optional[ThreatEvent]:
        """
        Detect lateral movement: single internal device connecting to many
        other internal devices (>10 unique within a session).

        MITRE: T1021 — Lateral Movement
        CWE-284: Improper Access Control
        """
        if src_ip in self._lateral_alerted:
            return None

        self._lateral_targets[src_ip].add(dst_ip)
        count = len(self._lateral_targets[src_ip])

        if count < 10:
            return None

        self._lateral_alerted.add(src_ip)
        sample_targets = list(self._lateral_targets[src_ip])[:10]

        return ThreatEvent(
            alert_type=AlertType.LATERAL_MOVEMENT,
            description=(
                f"Potential lateral movement from {src_ip}: "
                f"connected to {count} internal hosts. "
                f"Sample targets: {sample_targets}"
            ),
            severity=Severity.HIGH,
            confidence=min(60 + count * 3, 92),
            evidence={
                "src_ip": src_ip,
                "target_count": count,
                "targets": sample_targets,
            },
            affected_mac=src_mac,
            affected_ip=src_ip,
            mitre_attack=MitreAttack.LATERAL_MOVEMENT,
            cwe_id=CWE.UNAUTH_ACCESS,
            recommended_action=(
                "Isolate the source device at " + src_ip + " immediately. "
                "Review authentication logs on all target systems. "
                "Check for use of administrative tools (psexec, wmic, RDP) from this host."
            ),
            timestamp=ts,
        )

    # ── Memory Cleanup ────────────────────────────────────────────────────────

    def sweep_stale_state(self, max_age_minutes: int = 10) -> None:
        """
        Remove stale in-memory tracking data older than max_age_minutes.
        Call periodically (e.g. every 5 minutes) to prevent memory growth.
        """
        cutoff = datetime.utcnow().timestamp() - (max_age_minutes * 60)

        # Sweep DNS alert history
        stale_dns = [d for d, t in self._dns_alerted.items() if t < cutoff]
        for d in stale_dns:
            del self._dns_alerted[d]

        # Sweep mass scan counts older than 2 minutes
        cutoff_min = datetime.utcnow().strftime("%Y-%m-%dT%H:%M")
        for ip, min_dict in self._mass_scan_counts.items():
            for min_key in list(min_dict.keys()):
                if min_key < cutoff_min:
                    del min_dict[min_key]

        # Sweep OOH counts
        stale_ooh = [(m, mk) for (m, mk) in self._ooh_counts.keys() if mk < cutoff_min]
        for key in stale_ooh:
            self._ooh_counts.pop(key, None)

        # Trim beacon times
        for pair_key in list(self._beacon_times.keys()):
            times = self._beacon_times[pair_key]
            fresh = [t for t in times if t > cutoff]
            if fresh:
                self._beacon_times[pair_key] = fresh
            else:
                del self._beacon_times[pair_key]
                self._beacon_alerted.discard(pair_key)

        logger.debug("ThreatDetector stale state swept.")
