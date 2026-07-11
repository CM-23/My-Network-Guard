import time
import queue
import threading
import logging
import socket
from datetime import datetime

import wifi_manager

logger = logging.getLogger("Sniffer")

_sniffer_thread = None
_arp_scan_thread = None
_shutdown_event = threading.Event()
_elevated = False

# Scapy import with graceful fallback
scapy_available = False
try:
    import scapy.all as scapy
    scapy_available = True
except ImportError:
    logger.warning("Scapy not installed. Live ARP scanning unavailable.")

def _check_elevated():
    """Return True if the process has elevated privileges (root/admin)."""
    import os
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        return os.getuid() == 0
    except Exception:
        return False

def _simulation_worker(packet_queue):
    """
    Simulation Mode: Periodically inject mock device network packets into the queue.
    Helps test evaluator heuristics, alerts, and Telegram bots without live capture.
    """
    logger.info("Starting packet sniffer in SIMULATION MODE...")
    logger.info("Simulation packet loop active.")

    # Base devices to start with
    init_devs = [
        {"mac": "50:c7:bf:11:22:33", "ip": "192.168.1.20", "name": "Smart-TV"},
        {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.15", "name": "Smart-Fridge"},
        {"mac": "00:1a:2b:3c:4d:5e", "ip": "192.168.1.10", "name": "Home-IoT-Gateway"}
    ]

    for dev in init_devs:
        payload = {
            "timestamp": datetime.now().isoformat(),
            "src_mac": dev["mac"],
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": dev["ip"],
            "dst_ip": "192.168.1.1",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "ARP",
            "dns_query": None,
            "hostname": dev["name"]
        }
        packet_queue.put(payload)
        time.sleep(1.0)

    # Anomaly rotation list
    anomalies = [
        "NEW_DEVICE",
        "OUT_OF_HOURS",
        "DNS_TUNNEL_LONG",
        "DNS_TUNNEL_ENTROPY"
    ]
    idx = 0

    while not _shutdown_event.is_set():
        # Wait 25 seconds
        for _ in range(25):
            if _shutdown_event.is_set():
                break
            time.sleep(1.0)
        if _shutdown_event.is_set():
            break

        anomaly = anomalies[idx]
        idx = (idx + 1) % len(anomalies)

        logger.info(f"[SIMULATOR] Injecting mock anomaly: {anomaly}")
        ts = datetime.now().isoformat()

        if anomaly == "NEW_DEVICE":
            import random
            mac_suffix = f"{random.randint(0x10, 0xef):02x}:{random.randint(0x10, 0xef):02x}:{random.randint(0x10, 0xef):02x}"
            mac = f"00:23:29:{mac_suffix}"
            ip = f"192.168.1.{random.randint(100, 200)}"
            payload = {
                "timestamp": ts,
                "src_mac": mac,
                "dst_mac": "ff:ff:ff:ff:ff:ff",
                "src_ip": ip,
                "dst_ip": "192.168.1.1",
                "src_port": 0,
                "dst_port": 0,
                "protocol": "ARP",
                "dns_query": None,
                "hostname": None
            }
            packet_queue.put(payload)

        elif anomaly == "OUT_OF_HOURS":
            today = datetime.now()
            mock_time = datetime(today.year, today.month, today.day, 2, 30).isoformat()
            for _ in range(55):
                payload = {
                    "timestamp": mock_time,
                    "src_mac": "00:1a:2b:3c:4d:5e",
                    "dst_mac": "00:11:22:33:44:55",
                    "src_ip": "192.168.1.99",
                    "dst_ip": "198.51.100.42",
                    "src_port": 12345,
                    "dst_port": 443,
                    "protocol": "TCP",
                    "dns_query": None,
                    "hostname": "Home-IoT-Gateway"
                }
                packet_queue.put(payload)

        elif anomaly == "DNS_TUNNEL_LONG":
            payload = {
                "timestamp": ts,
                "src_mac": "00:1a:2b:3c:4d:5e",
                "dst_mac": "00:11:22:33:44:55",
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "src_port": 53535,
                "dst_port": 53,
                "protocol": "UDP",
                "dns_query": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.exfiltration-channel.attacker-site-control.net",
                "hostname": None
            }
            packet_queue.put(payload)

        elif anomaly == "DNS_TUNNEL_ENTROPY":
            payload = {
                "timestamp": ts,
                "src_mac": "aa:bb:cc:dd:ee:ff",
                "dst_mac": "00:11:22:33:44:55",
                "src_ip": "192.168.1.15",
                "dst_ip": "8.8.8.8",
                "src_port": 53535,
                "dst_port": 53,
                "protocol": "UDP",
                "dns_query": "w9x7y2z1a5b8c3d6e4f0g2h1i5j8k3l9m7n1o6p2q4r.tunnel.attacker.com",
                "hostname": None
            }
            packet_queue.put(payload)

    logger.info("Simulation packet loop stopped.")

def start_sniffer(packet_queue, interface=None, simulation_mode=False):
    """
    Start network scanning or simulation mode.
    """
    global _sniffer_thread, _arp_scan_thread, _elevated
    _shutdown_event.clear()

    if simulation_mode:
        _sniffer_thread = threading.Thread(
            target=_simulation_worker,
            args=(packet_queue,),
            name="SimulationSnifferThread",
            daemon=True
        )
        _sniffer_thread.start()
        return

    _elevated = _check_elevated()

    if not scapy_available:
        logger.warning("Scapy unavailable. Device discovery will rely on system ARP cache only.")
        _sniffer_thread = threading.Thread(
            target=_arp_cache_worker,
            args=(packet_queue,),
            name="ArpCacheThread",
            daemon=True
        )
        _sniffer_thread.start()
        return

    if _elevated:
        logger.info("Elevated privileges confirmed. Starting active ARP scanner + passive sniffer.")
        # Active subnet scanner thread
        _arp_scan_thread = threading.Thread(
            target=_active_arp_scanner,
            args=(packet_queue, interface),
            name="ActiveARPScanner",
            daemon=True
        )
        _arp_scan_thread.start()

        # Passive sniffer thread
        _sniffer_thread = threading.Thread(
            target=_passive_sniffer_worker,
            args=(packet_queue, interface),
            name="PassiveSnifferThread",
            daemon=True
        )
        _sniffer_thread.start()
    else:
        logger.warning("No elevated privileges. Running passive ARP observer only.")
        _sniffer_thread = threading.Thread(
            target=_passive_sniffer_worker,
            args=(packet_queue, interface),
            name="PassiveSnifferThread",
            daemon=True
        )
        _sniffer_thread.start()

def stop_sniffer():
    """Stop all sniffer and scanner threads."""
    global _sniffer_thread, _arp_scan_thread
    _shutdown_event.set()
    if _sniffer_thread:
        _sniffer_thread.join(timeout=5.0)
        _sniffer_thread = None
    if _arp_scan_thread:
        _arp_scan_thread.join(timeout=5.0)
        _arp_scan_thread = None
    logger.info("All sniffer threads stopped.")

def is_elevated():
    return _elevated

def trigger_arp_scan(packet_queue):
    """
    Manually trigger a one-shot ARP scan of the current subnet.
    Called from the API on demand.
    """
    if not scapy_available:
        logger.warning("Cannot trigger ARP scan: Scapy not installed.")
        return
    t = threading.Thread(
        target=_run_arp_scan,
        args=(packet_queue,),
        name="ManualARPScan",
        daemon=True
    )
    t.start()

# ─────────────────────────────────────────
# Active ARP Scanner
# ─────────────────────────────────────────

def _active_arp_scanner(packet_queue, interface):
    """Periodically sends ARP broadcast to the entire local subnet to discover all devices."""
    logger.info("Active ARP subnet scanner started.")
    # First scan immediately, then every 30 seconds
    _run_arp_scan(packet_queue, interface)

    while not _shutdown_event.is_set():
        # Wait 30 seconds between scans, checking shutdown every second
        for _ in range(30):
            if _shutdown_event.is_set():
                break
            time.sleep(1.0)
        if not _shutdown_event.is_set():
            _run_arp_scan(packet_queue, interface)

    logger.info("Active ARP scanner stopped.")

def _run_arp_scan(packet_queue, interface=None):
    """Execute a single ARP scan on the local /24 subnet."""
    subnet = wifi_manager.get_subnet()
    logger.info(f"Running ARP scan on subnet: {subnet}")
    try:
        # Construct Layer 2 ARP broadcast packet
        ether_pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_pkt = scapy.ARP(pdst=subnet)
        packet = ether_pkt / arp_pkt
        
        # Send and receive at Layer 2
        srp_kwargs = {"timeout": 3, "verbose": False}
        if interface:
            srp_kwargs["iface"] = interface

        answered, _ = scapy.srp(packet, **srp_kwargs)

        for sent, received in answered:
            src_mac = received.hwsrc.lower()
            src_ip = received.psrc
            ts = datetime.now().isoformat()

            hostname = _resolve_hostname(src_ip)

            payload = {
                "timestamp": ts,
                "src_mac": src_mac,
                "dst_mac": "ff:ff:ff:ff:ff:ff",
                "src_ip": src_ip,
                "dst_ip": wifi_manager.get_local_ip(),
                "src_port": 0,
                "dst_port": 0,
                "protocol": "ARP",
                "dns_query": None,
                "hostname": hostname
            }
            packet_queue.put(payload)

    except Exception as e:
        logger.error(f"ARP scan error: {e}")

# ─────────────────────────────────────────
# Passive Sniffer
# ─────────────────────────────────────────

def _passive_sniffer_worker(packet_queue, interface):
    """Passively observe ARP replies and IP packets to discover devices."""
    logger.info("Passive packet sniffer started (observing ARP + IP traffic).")
    iface_arg = interface if interface else None
    _consecutive_errors = 0

    while not _shutdown_event.is_set():
        try:
            scapy.sniff(
                iface=iface_arg,
                filter="arp or ip",
                prn=lambda pkt: _handle_packet(pkt, packet_queue),
                store=0,
                count=50,
                timeout=2.0
            )
            _consecutive_errors = 0  # reset on success
        except Exception as e:
            _consecutive_errors += 1
            if _consecutive_errors == 1:
                # Only log once — don't spam
                logger.warning(f"Passive sniffer unavailable (no winpcap/npcap): {e}")
                logger.info("Falling back to ARP cache reader for device discovery.")
            if _consecutive_errors >= 3:
                # Switch permanently to ARP cache fallback
                logger.info("Passive sniffer disabled. Using ARP cache reader.")
                _arp_cache_worker(packet_queue)
                return
            time.sleep(2.0)

    logger.info("Passive sniffer stopped.")

def _handle_packet(pkt, packet_queue):
    """Parse a captured packet and push a structured payload to the queue."""
    try:
        payload = _parse_packet(pkt)
        if payload:
            packet_queue.put(payload)
    except Exception as e:
        logger.error(f"Error handling packet: {e}")

def _parse_packet(pkt):
    """Extract relevant fields from a captured Scapy packet."""
    payload = {
        "timestamp": datetime.now().isoformat(),
        "src_mac": "00:00:00:00:00:00",
        "dst_mac": "00:00:00:00:00:00",
        "src_ip": None,
        "dst_ip": None,
        "src_port": 0,
        "dst_port": 0,
        "protocol": "Unknown",
        "dns_query": None,
        "hostname": None
    }

    if pkt.haslayer(scapy.Ether):
        payload["src_mac"] = pkt[scapy.Ether].src.lower()
        payload["dst_mac"] = pkt[scapy.Ether].dst.lower()

    if pkt.haslayer(scapy.ARP):
        payload["src_mac"] = pkt[scapy.ARP].hwsrc.lower()
        payload["src_ip"] = pkt[scapy.ARP].psrc
        payload["dst_ip"] = pkt[scapy.ARP].pdst
        payload["protocol"] = "ARP"

    elif pkt.haslayer(scapy.IP):
        payload["src_ip"] = pkt[scapy.IP].src
        payload["dst_ip"] = pkt[scapy.IP].dst

        proto = pkt[scapy.IP].proto
        if proto == 6 and pkt.haslayer(scapy.TCP):
            payload["protocol"] = "TCP"
            payload["src_port"] = pkt[scapy.TCP].sport
            payload["dst_port"] = pkt[scapy.TCP].dport
        elif proto == 17 and pkt.haslayer(scapy.UDP):
            payload["protocol"] = "UDP"
            payload["src_port"] = pkt[scapy.UDP].sport
            payload["dst_port"] = pkt[scapy.UDP].dport
            if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qd:
                qname = pkt[scapy.DNS].qd.qname
                if isinstance(qname, bytes):
                    payload["dns_query"] = qname.decode("utf-8", errors="ignore").rstrip(".")
        elif proto == 1:
            payload["protocol"] = "ICMP"
    else:
        return None

    if not payload["src_ip"]:
        return None

    return payload

# ─────────────────────────────────────────
# ARP Cache Fallback (no Scapy)
# ─────────────────────────────────────────

def _arp_cache_worker(packet_queue):
    """
    Fallback: read the system ARP cache to find already-known devices.
    Works on any platform without elevated privileges or Scapy.
    Runs every 30 seconds.
    """
    logger.info("ARP cache reader started (Scapy unavailable fallback).")
    while not _shutdown_event.is_set():
        try:
            import subprocess, re
            import platform as pf

            if pf.system() == "Windows":
                out = subprocess.check_output("arp -a", shell=True).decode(errors="ignore")
                # Windows: "  192.168.1.1        aa-bb-cc-dd-ee-ff    dynamic"
                pattern = re.compile(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})"
                )
            else:
                out = subprocess.check_output("arp -n", shell=True).decode(errors="ignore")
                # Linux: "192.168.1.1  ether  aa:bb:cc:dd:ee:ff"
                pattern = re.compile(
                    r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([\da-fA-F:]{17})"
                )

            seen = set()
            for match in pattern.finditer(out):
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").lower()
                if mac == "ff:ff:ff:ff:ff:ff" or ip in seen:
                    continue
                seen.add(ip)

                payload = {
                    "timestamp": datetime.now().isoformat(),
                    "src_mac": mac,
                    "dst_mac": "ff:ff:ff:ff:ff:ff",
                    "src_ip": ip,
                    "dst_ip": wifi_manager.get_local_ip(),
                    "src_port": 0,
                    "dst_port": 0,
                    "protocol": "ARP-CACHE",
                    "dns_query": None,
                    "hostname": _resolve_hostname(ip)
                }
                packet_queue.put(payload)

        except Exception as e:
            logger.error(f"ARP cache reader error: {e}")

        # Wait 30 seconds
        for _ in range(30):
            if _shutdown_event.is_set():
                break
            time.sleep(1.0)

    logger.info("ARP cache reader stopped.")

# ─────────────────────────────────────────
# Hostname Resolution
# ─────────────────────────────────────────

def _resolve_hostname(ip):
    """Attempt a reverse DNS lookup, return None if not found."""
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
