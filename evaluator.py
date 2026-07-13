"""
evaluator.py — Passive packet evaluator.

Acts as the consumer thread for the packet queue.
Takes PacketPayload objects from the queue, executes:
  1. Device discovery & tracking (delegates to fingerprint.py + OUI resolution)
  2. Aggregated flow statistics (inserts into traffic_logs)
  3. Stateful threat detection (delegates to threat_detector.py)

MITRE ATT&CK & CWE information is recorded for every threat event.
OWASP ASVS V7.2: Logs all security-relevant alerts with sufficient context.
"""

from __future__ import annotations

import logging
import queue
import threading
import socket
import concurrent.futures
from datetime import datetime

import database
import notifier
from common.logging_config import get_logger
from shared.models import PacketPayload, Device, Alert
from scanner_agent.fingerprint import fingerprint_device
from scanner_agent.oui_table import resolve_mac_vendor
from scanner_agent.threat_detector import ThreatDetector

logger = get_logger("Evaluator")

# ─── Threading State ─────────────────────────────────────────────────────────

_evaluator_thread: Optional[threading.Thread] = None
_shutdown_event = threading.Event()
_resolver_pool  = concurrent.futures.ThreadPoolExecutor(max_workers=5, thread_name_prefix="DNSResolver")

# Config parameters
_config: dict = {}
_threat_detector: Optional[ThreatDetector] = None


# ─── Helper wrappers (backward compatibility for test_heuristics.py) ──────────

def calculate_entropy(s: str) -> float:
    from scanner_agent.threat_detector import _shannon_entropy
    return _shannon_entropy(s)


def is_local_ip(ip: str) -> bool:
    from scanner_agent.threat_detector import _is_local_ip
    prefixes = _config.get("local_networks", ["192.168.", "10.", "172.16."])
    return _is_local_ip(ip, prefixes)


# ─── Hostname Resolution ──────────────────────────────────────────────────────

def resolve_hostname_async(mac_address: str, ip: str) -> None:
    """Resolve a hostname asynchronously in a thread pool to avoid blocking the main evaluator loop."""
    def lookup():
        try:
            socket.setdefaulttimeout(1.0)
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            # Fallback hostname format
            suffix = mac_address.replace(":", "")[-6:]
            hostname = f"Device-{suffix}"

        logger.info(f"Resolved hostname for {ip} / {mac_address} -> {hostname}")
        database.execute_write_async(
            "UPDATE devices SET hostname = ? WHERE mac_address = ?",
            (hostname, mac_address)
        )
    _resolver_pool.submit(lookup)


# ─── Evaluator Lifecycle ──────────────────────────────────────────────────────

def start_evaluator(packet_queue: queue.Queue, config: dict) -> None:
    """Start the background packet evaluation thread."""
    global _evaluator_thread, _config, _threat_detector
    _config = config
    _threat_detector = ThreatDetector(config)
    _shutdown_event.clear()

    _evaluator_thread = threading.Thread(
        target=_evaluator_worker,
        args=(packet_queue,),
        name="EvaluatorThread",
        daemon=True
    )
    _evaluator_thread.start()
    logger.info("Evaluator worker thread started.")


def stop_evaluator() -> None:
    """Stop the evaluator worker thread."""
    global _evaluator_thread
    if _evaluator_thread:
        logger.info("Stopping evaluator worker...")
        _shutdown_event.set()
        _evaluator_thread.join(timeout=5.0)
        _evaluator_thread = None


# ─── Evaluator Worker ──────────────────────────────────────────────────────────

def _evaluator_worker(packet_queue: queue.Queue) -> None:
    """Loop pulling packet payloads from queue and evaluating heuristics."""
    global _threat_detector
    last_cleanup_time = datetime.now()

    while not _shutdown_event.is_set():
        try:
            try:
                # Polling wait to check shutdown event
                raw_payload = packet_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            # Perform periodic cache cleanup (every 5 minutes)
            now_dt = datetime.now()
            if (now_dt - last_cleanup_time).total_seconds() > 300:
                if _threat_detector:
                    _threat_detector.sweep_stale_state(max_age_minutes=10)
                last_cleanup_time = now_dt

            # Ensure we have a proper PacketPayload object
            if isinstance(raw_payload, dict):
                # Construct models.PacketPayload from dict
                payload = PacketPayload(
                    timestamp    = raw_payload.get("timestamp"),
                    src_mac      = raw_payload.get("src_mac"),
                    dst_mac      = raw_payload.get("dst_mac"),
                    src_ip       = raw_payload.get("src_ip"),
                    dst_ip       = raw_payload.get("dst_ip"),
                    src_port     = raw_payload.get("src_port"),
                    dst_port     = raw_payload.get("dst_port"),
                    protocol     = raw_payload.get("protocol"),
                    ttl          = raw_payload.get("ttl"),
                    dns_query    = raw_payload.get("dns_query"),
                    dhcp_options = raw_payload.get("dhcp_options"),
                    mdns_info    = raw_payload.get("mdns_info"),
                    ssdp_info    = raw_payload.get("ssdp_info"),
                )
                resolved_hostname = raw_payload.get("hostname")
            elif isinstance(raw_payload, PacketPayload):
                payload = raw_payload
                resolved_hostname = None
            else:
                packet_queue.task_done()
                continue

            src_mac  = payload.src_mac
            src_ip   = payload.src_ip
            dst_ip   = payload.dst_ip
            dst_port = payload.dst_port or 0
            protocol = payload.protocol or ""
            timestamp = payload.timestamp

            if not src_mac or src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                packet_queue.task_done()
                continue

            # ── 1. Device Discovery & Tracking ────────────────────────────────
            device_record = database.execute_read(
                "SELECT mac_address FROM devices WHERE mac_address = ?", (src_mac,)
            )
            vendor = resolve_mac_vendor(src_mac)

            # Resolve fingerprint details
            fingerprint = fingerprint_device(
                mac          = src_mac,
                hostname     = resolved_hostname,
                ip           = src_ip,
                protocol     = protocol,
                ttl          = payload.ttl,
                dhcp_options = payload.dhcp_options,
                mdns_info    = payload.mdns_info,
                ssdp_info    = payload.ssdp_info
            )

            if not device_record:
                # Use pre-resolved hostname or default
                initial_hostname = resolved_hostname or f"Device-{src_mac.replace(':', '')[-6:]}"

                database.execute_write_sync(
                    """INSERT INTO devices (
                        mac_address, last_known_ip, hostname, device_type, vendor,
                        is_online, operating_system, confidence_score, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)""",
                    (
                        src_mac, src_ip, initial_hostname, fingerprint.device_type,
                        vendor, fingerprint.operating_system, fingerprint.confidence,
                        timestamp, timestamp
                    )
                )

                if not resolved_hostname and src_ip:
                    resolve_hostname_async(src_mac, src_ip)

                # Record alert for new device
                alert_type  = "NEW_DEVICE_ON_JOIN"
                description = (
                    f"New device discovered: MAC: {src_mac}, IP: {src_ip}, "
                    f"Name: {initial_hostname} ({fingerprint.device_type}), "
                    f"OS: {fingerprint.operating_system} ({fingerprint.confidence}%), "
                    f"Vendor: {vendor}"
                )
                severity = "MEDIUM"

                database.execute_write_async(
                    "INSERT INTO alerts (timestamp, alert_type, description, severity, is_resolved) VALUES (?, ?, ?, ?, 0)",
                    (timestamp, alert_type, description, severity)
                )
                notifier.queue_alert(alert_type, description, severity, timestamp)
                logger.info(f"New device registered: MAC {src_mac} / IP {src_ip}")

            else:
                # Update existing device record
                if resolved_hostname:
                    database.execute_write_async(
                        """UPDATE devices SET last_known_ip = ?, last_seen = ?, hostname = ?,
                                              vendor = ?, device_type = ?, operating_system = ?,
                                              confidence_score = ?, is_online = 1
                           WHERE mac_address = ?""",
                        (
                            src_ip, timestamp, resolved_hostname, vendor,
                            fingerprint.device_type, fingerprint.operating_system,
                            fingerprint.confidence, src_mac
                        )
                    )
                else:
                    database.execute_write_async(
                        """UPDATE devices SET last_known_ip = ?, last_seen = ?, vendor = ?,
                                              device_type = ?, operating_system = ?,
                                              confidence_score = ?, is_online = 1
                           WHERE mac_address = ?""",
                        (
                            src_ip, timestamp, vendor, fingerprint.device_type,
                            fingerprint.operating_system, fingerprint.confidence, src_mac
                        )
                    )

            # ── 2. Aggregated Traffic Logging ─────────────────────────────────
            if src_ip and dst_ip:
                database.execute_write_async(
                    """
                    INSERT INTO traffic_logs (source_ip, dest_ip, dest_port, protocol, packet_count, last_active)
                    VALUES (?, ?, ?, ?, 1, ?)
                    ON CONFLICT(source_ip, dest_ip, dest_port, protocol)
                    DO UPDATE SET packet_count = packet_count + 1, last_active = excluded.last_active
                    """,
                    (src_ip, dst_ip, dst_port, protocol, timestamp)
                )

            # ── 3. Stateful Threat Detection ──────────────────────────────────
            if _threat_detector:
                events = _threat_detector.process(payload)
                for ev in events:
                    # Write alert to database with MITRE & CWE fields
                    database.execute_write_async(
                        """INSERT INTO alerts (
                            timestamp, alert_type, description, severity, confidence,
                            evidence, affected_mac, mitre_attack, cwe_id, recommended_action, is_resolved
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                        (
                            ev.timestamp, ev.alert_type, ev.description, ev.severity,
                            ev.confidence, str(ev.evidence), ev.affected_mac,
                            ev.mitre_attack, ev.cwe_id, ev.recommended_action
                        )
                    )
                    # Dispatch notifications
                    notifier.queue_alert(ev.alert_type, ev.description, ev.severity, ev.timestamp)
                    logger.info(f"Threat alert triggered: {ev.alert_type} ({ev.severity}) for MAC {src_mac}")

            packet_queue.task_done()

        except Exception as e:
            logger.error(f"Error in evaluator worker loop: {e}", exc_info=True)
