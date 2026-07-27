import logging
import socket
import threading
import time
from datetime import datetime

import wifi_manager

logger = logging.getLogger("Sniffer")

_sniffer_thread = None
_arp_scan_thread = None
_shutdown_event = threading.Event()
_elevated = False
_simulation_mode = False

_diagnostics = {
    "npcap_installed": False,
    "packet_capture_active": False,
    "passive_discovery_active": False,
    "active_arp_active": False,
    "active_arp_disabled_reason": "Not started",
    "current_interface": "Unknown",
    "subnet": "Unknown",
    "gateway": "Unknown",
    "packet_count": 0,
    "arp_requests_sent": 0,
    "packets_captured": 0,
    "devices_discovered": 0,
    "last_scan_time": "Never",
}


def get_diagnostics():
    try:
        import database

        res = database.execute_read("SELECT count(*) as c FROM devices")
        if res:
            _diagnostics["devices_discovered"] = res[0]["c"]
    except Exception:
        pass
    return _diagnostics


# Scapy import with graceful fallback
scapy_available = False
try:
    import scapy.all as scapy

    scapy_available = True
except ImportError:
    logger.warning("Scapy not installed. Live ARP scanning unavailable.")


def check_npcap_missing():
    if not scapy_available:
        return False
    try:
        # Check Scapy's conf.L2socket class name
        if "NotAvailableSocket" in getattr(scapy.conf.L2socket, "__name__", ""):
            return True
        # Try test instantiating L2socket on Windows
        scapy.conf.L2socket()
    except Exception as e:
        err_msg = str(e).lower()
        if "winpcap is not installed" in err_msg or "wpcap.dll missing" in err_msg or "layer 2" in err_msg:
            return True
    return False


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
        {"mac": "00:1a:2b:3c:4d:5e", "ip": "192.168.1.10", "name": "Home-IoT-Gateway"},
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
            "hostname": dev["name"],
        }
        packet_queue.put(payload)
        time.sleep(1.0)

    # Anomaly rotation list
    anomalies = ["NEW_DEVICE", "OUT_OF_HOURS", "DNS_TUNNEL_LONG", "DNS_TUNNEL_ENTROPY"]
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

            mac_suffix = (
                f"{random.randint(0x10, 0xef):02x}:{random.randint(0x10, 0xef):02x}:{random.randint(0x10, 0xef):02x}"
            )
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
                "hostname": None,
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
                    "hostname": "Home-IoT-Gateway",
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
                "dns_query": (
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    ".exfiltration-channel.attacker-site-control.net"
                ),
                "hostname": None,
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
                "hostname": None,
            }
            packet_queue.put(payload)

    logger.info("Simulation packet loop stopped.")


def auto_detect_interface():
    """
    Selects the active network interface by querying scapy route configuration
    and filtering out forbidden keywords (loopback, virtualbox, vmware, wsl, etc.).
    """
    if not scapy_available:
        return None

    try:
        # Get active default gateway interface
        scapy_iface_name, local_ip, gateway_ip = scapy.conf.route.route("8.8.8.8")

        # Excluded adapter names or descriptions
        forbidden = [
            "loopback",
            "docker",
            "virtualbox",
            "vmware",
            "wsl",
            "hyper-v",
            "bluetooth",
            "teredo",
            "host-only",
            "tap-",
        ]

        # Verify the interface is valid and not excluded
        for iface_id, iface in scapy.conf.ifaces.items():
            name = (getattr(iface, "name", "") or "").lower()
            desc = (getattr(iface, "description", "") or "").lower()
            pcap_name = (getattr(iface, "pcap_name", "") or "").lower()

            # If name or description matches scapy_iface_name
            if name == scapy_iface_name.lower() or pcap_name == scapy_iface_name.lower():
                if any(x in name or x in desc for x in forbidden):
                    continue
                return iface

        # If not found directly in ifaces list, check if default is in forbidden list
        name_lower = scapy_iface_name.lower()
        if not any(x in name_lower for x in forbidden):
            return scapy_iface_name
    except Exception as e:
        logger.warning(f"Error auto-detecting default interface: {e}")

    # Fallback to scapy's get_working_if()
    try:
        iface = scapy.get_working_if()
        if iface:
            return iface
    except Exception:
        pass

    return None


def test_active_scan_privileges(interface=None):
    """
    Attempt an actual L2 packet send/recv using Scapy to confirm active scanning capability.
    Returns (success, reason_str).
    """
    if not scapy_available:
        return False, "Scapy not available."
    if check_npcap_missing():
        return False, "Npcap driver is missing."

    try:
        dst_ip = "127.0.0.1"
        try:
            gw = wifi_manager.get_gateway_ip()
            if gw and gw != "127.0.0.1":
                dst_ip = gw
        except Exception:
            pass

        pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=dst_ip)

        srp_kwargs = {"timeout": 0.5, "verbose": False}
        if interface:
            # Handle iface string or scapy adapter object
            srp_kwargs["iface"] = getattr(interface, "pcap_name", interface)

        scapy.srp(pkt, **srp_kwargs)
        return True, "Active scanning verification successful."
    except Exception as e:
        err_str = str(e)
        return False, err_str


def log_startup_diagnostics(config_path, config):
    import platform
    import sys

    npcap_missing = check_npcap_missing()
    npcap_status = "[ ] Npcap not detected" if npcap_missing else "[x] Npcap detected"
    print(npcap_status)  # print directly to stdout as requested!

    scapy_ver = "Not installed"
    if scapy_available:
        try:
            import scapy as scapy_base

            scapy_ver = scapy_base.__version__
        except Exception:
            scapy_ver = "Installed"
    py_ver = sys.version.replace("\n", " ")
    os_name = f"{platform.system()} {platform.release()} ({platform.version()})"

    # Auto-detected interface details
    selected_iface = config.get("interface") or "Auto-detected"
    selected_subnet = wifi_manager.get_subnet()
    gateway = wifi_manager.get_gateway_ip()
    privilege_status = "Administrator/Root" if _check_elevated() else "Standard User"

    logger.info("============================================================")
    logger.info("                STARTUP DIAGNOSTICS REPORT                  ")
    logger.info("============================================================")
    logger.info(f"Resolved config path: {config_path}")
    logger.info(f"Npcap status        : {npcap_status}")
    logger.info(f"Scapy version       : {scapy_ver}")
    logger.info(f"Python version      : {py_ver}")
    logger.info(f"Operating system    : {os_name}")
    logger.info(f"Selected interface  : {selected_iface}")
    logger.info(f"Selected subnet     : {selected_subnet}")
    logger.info(f"Gateway             : {gateway}")
    logger.info(f"Privilege status    : {privilege_status}")
    logger.info("============================================================")


def start_sniffer(packet_queue, interface=None, simulation_mode=False):
    """
    Start network scanning or simulation mode.
    """
    global _sniffer_thread, _arp_scan_thread, _elevated, _simulation_mode
    _shutdown_event.clear()
    _simulation_mode = simulation_mode

    # Configure base diagnostics
    npcap_missing = check_npcap_missing()
    _diagnostics["npcap_installed"] = not npcap_missing
    _diagnostics["current_interface"] = interface or "Auto-detected"
    _diagnostics["subnet"] = wifi_manager.get_subnet()
    _diagnostics["gateway"] = wifi_manager.get_gateway_ip()

    if _simulation_mode:
        _diagnostics["packet_capture_active"] = True
        _diagnostics["passive_discovery_active"] = True
        _diagnostics["active_arp_active"] = True
        _diagnostics["active_arp_disabled_reason"] = "N/A (Simulation Mode)"
        logger.info("[INFO] Simulation mode enabled. Showing simulated devices only.")
        _sniffer_thread = threading.Thread(
            target=_simulation_worker, args=(packet_queue,), name="SimulationSnifferThread", daemon=True
        )
        _sniffer_thread.start()
        return

    _elevated = _check_elevated()

    if npcap_missing:
        _diagnostics["packet_capture_active"] = False
        _diagnostics["passive_discovery_active"] = False
        _diagnostics["active_arp_active"] = False
        _diagnostics["active_arp_disabled_reason"] = "Npcap driver not found"
        logger.error("[ERROR] Npcap/WinPcap driver not found. Real device discovery cannot run.")
        return

    if not scapy_available:
        _diagnostics["packet_capture_active"] = False
        _diagnostics["passive_discovery_active"] = False
        _diagnostics["active_arp_active"] = False
        _diagnostics["active_arp_disabled_reason"] = "Scapy not installed"
        logger.warning("Scapy unavailable. Device discovery will rely on system ARP cache only.")
        _sniffer_thread = threading.Thread(
            target=_arp_cache_worker, args=(packet_queue,), name="ArpCacheThread", daemon=True
        )
        _sniffer_thread.start()
        return

    # Dynamic interface auto-detection
    if not interface:
        detected = auto_detect_interface()
        if detected:
            if isinstance(detected, str):
                interface = detected
            else:
                interface = getattr(detected, "name", str(detected))
                desc = getattr(detected, "description", "")
                _diagnostics["current_interface"] = f"{desc} ({interface})" if desc else interface

    # Check active scan privileges and capability
    active_ok, active_reason = test_active_scan_privileges(interface)

    _diagnostics["packet_capture_active"] = True
    _diagnostics["passive_discovery_active"] = True

    if active_ok:
        _diagnostics["active_arp_active"] = True
        _diagnostics["active_arp_disabled_reason"] = ""
        logger.info(f"Active scan verified on interface: {interface}")
        _arp_scan_thread = threading.Thread(
            target=_active_arp_scanner, args=(packet_queue, interface), name="ActiveARPScanner", daemon=True
        )
        _arp_scan_thread.start()
    else:
        _diagnostics["active_arp_active"] = False
        _diagnostics["active_arp_disabled_reason"] = f"Permissions/L2 error: {active_reason}"
        logger.warning(
            f"Active scanning disabled: {active_reason}. Falling back to passive sniffing + ARP cache reader."
        )

        # Standard user fallback: run both passive sniffer AND the ARP cache reader
        _arp_scan_thread = threading.Thread(
            target=_arp_cache_worker, args=(packet_queue,), name="ArpCacheThread", daemon=True
        )
        _arp_scan_thread.start()

    # Passive Sniffer Thread
    _sniffer_thread = threading.Thread(
        target=_passive_sniffer_worker, args=(packet_queue, interface), name="PassiveSnifferThread", daemon=True
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


def get_scan_mode():
    if _simulation_mode:
        return "SIMULATION"
    if not scapy_available:
        return "ARP_CACHE"
    if _elevated:
        return "ACTIVE_SCAN"
    return "PASSIVE_ONLY"


def trigger_arp_scan(packet_queue):
    """
    Manually trigger a one-shot ARP scan of the current subnet.
    Called from the API on demand.
    """
    if _simulation_mode:
        logger.info("Simulation mode: manual ARP scan triggered successfully (no-op).")
        return
    if check_npcap_missing():
        raise RuntimeError(
            "Npcap is not installed. Real network discovery is disabled. "
            "Install Npcap with 'WinPcap API-compatible Mode' enabled and restart the application."
        )
    if not scapy_available:
        raise ImportError("Scapy not installed. Live ARP scanning unavailable.")
    if not is_elevated():
        raise PermissionError("insufficient permissions. Run as Administrator/sudo.")

    # Execute scan synchronously in the trigger request thread
    _run_arp_scan(packet_queue)


# ─────────────────────────────────────────
# Active ARP Scanner
# ─────────────────────────────────────────


def _active_arp_scanner(packet_queue, interface):
    """Periodically sends ARP broadcast to the entire local subnet to discover all devices."""
    logger.info("Active ARP subnet scanner started.")
    # First scan immediately, then every 30 seconds
    try:
        _run_arp_scan(packet_queue, interface)
    except Exception as e:
        logger.error(f"Initial active ARP scan failed: {e}")

    while not _shutdown_event.is_set():
        # Wait 30 seconds between scans, checking shutdown every second
        for _ in range(30):
            if _shutdown_event.is_set():
                break
            time.sleep(1.0)
        if not _shutdown_event.is_set():
            try:
                _run_arp_scan(packet_queue, interface)
            except Exception as e:
                logger.error(f"Active ARP scan failed: {e}")

    logger.info("Active ARP scanner stopped.")


def _run_arp_scan(packet_queue, interface=None):
    """Execute a single ARP scan on the local /24 subnet."""
    subnet = wifi_manager.get_subnet()
    logger.info(f"Running ARP scan on subnet: {subnet}")
    _diagnostics["arp_requests_sent"] += 254
    _diagnostics["last_scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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

        responded_macs = []
        for sent, received in answered:
            src_mac = received.hwsrc.lower()
            src_ip = received.psrc
            responded_macs.append(src_mac)
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
                "hostname": hostname,
            }
            packet_queue.put(payload)

        # Mark all other devices offline
        if responded_macs:
            import database

            placeholders = ",".join("?" for _ in responded_macs)
            database.execute_write_async(
                f"UPDATE devices SET is_online = 0 WHERE mac_address NOT IN ({placeholders})", tuple(responded_macs)
            )

    except Exception as e:
        logger.error(f"ARP scan error: {e}")
        # If it's a permission error or L2 raw socket error, raise descriptive exception
        err_msg = str(e).lower()
        if (
            "permission" in err_msg
            or "operation not permitted" in err_msg
            or "socket" in err_msg
            or "winpcap" in err_msg
        ):
            raise PermissionError("insufficient permissions. Run as Administrator/sudo.")
        raise


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
                timeout=2.0,
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
        _diagnostics["packet_count"] += 1
        _diagnostics["packets_captured"] += 1
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
        "hostname": None,
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

        payload["ttl"] = pkt[scapy.IP].ttl
        proto = pkt[scapy.IP].proto
        if proto == 6 and pkt.haslayer(scapy.TCP):
            payload["protocol"] = "TCP"
            payload["src_port"] = pkt[scapy.TCP].sport
            payload["dst_port"] = pkt[scapy.TCP].dport
            flags = pkt[scapy.TCP].flags
            if "S" in str(flags):
                payload["protocol"] = "TCP-SYN"
        elif proto == 17 and pkt.haslayer(scapy.UDP):
            payload["protocol"] = "UDP"
            payload["src_port"] = pkt[scapy.UDP].sport
            payload["dst_port"] = pkt[scapy.UDP].dport

            sport = pkt[scapy.UDP].sport
            dport = pkt[scapy.UDP].dport

            # DNS queries
            if (sport == 53 or dport == 53) and pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qd:
                qname = pkt[scapy.DNS].qd.qname
                if isinstance(qname, bytes):
                    payload["dns_query"] = qname.decode("utf-8", errors="ignore").rstrip(".")
                    payload["protocol"] = "DNS"

            # mDNS local discovery
            elif sport == 5353 or dport == 5353:
                payload["protocol"] = "mDNS"
                if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qd:
                    qname = pkt[scapy.DNS].qd.qname
                    if isinstance(qname, bytes):
                        payload["hostname"] = qname.decode("utf-8", errors="ignore").rstrip(".local").rstrip(".")

            # LLMNR queries
            elif sport == 5355 or dport == 5355:
                payload["protocol"] = "LLMNR"
                if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qd:
                    qname = pkt[scapy.DNS].qd.qname
                    if isinstance(qname, bytes):
                        payload["hostname"] = qname.decode("utf-8", errors="ignore").rstrip(".")

            # NBNS queries
            elif sport == 137 or dport == 137:
                payload["protocol"] = "NBNS"
                if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qd:
                    qname = pkt[scapy.DNS].qd.qname
                    if isinstance(qname, bytes):
                        payload["hostname"] = qname.decode("utf-8", errors="ignore").rstrip(".")

            # SSDP broadcast
            elif sport == 1900 or dport == 1900:
                payload["protocol"] = "SSDP"
                if pkt.haslayer(scapy.Raw):
                    try:
                        raw_data = pkt[scapy.Raw].load.decode(errors="ignore")
                        for line in raw_data.splitlines():
                            if line.lower().startswith("server:"):
                                payload["ssdp_info"] = line.split(":", 1)[1].strip()
                    except Exception:
                        pass

            # DHCP packets
            elif sport == 67 or dport == 67 or sport == 68 or dport == 68:
                payload["protocol"] = "DHCP"
                if pkt.haslayer(scapy.DHCP):
                    try:
                        opts = pkt[scapy.DHCP].options
                        dhcp_opts = {}
                        for opt in opts:
                            if isinstance(opt, tuple):
                                key, val = opt
                                if key == "hostname":
                                    if isinstance(val, bytes):
                                        val = val.decode(errors="ignore")
                                    payload["hostname"] = val
                                    dhcp_opts["hostname"] = val
                                elif key == "vendor_class_id":
                                    if isinstance(val, bytes):
                                        val = val.decode(errors="ignore")
                                    dhcp_opts["vendor_class_id"] = val
                        if dhcp_opts:
                            payload["dhcp_options"] = dhcp_opts
                    except Exception:
                        pass
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
            import platform as pf
            import re
            import subprocess

            if pf.system() == "Windows":
                out = subprocess.check_output(["arp", "-a"]).decode(errors="ignore")
                # Windows: "  192.168.1.1        aa-bb-cc-dd-ee-ff    dynamic"
                pattern = re.compile(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F]{2}[-:][\da-fA-F]{2}"
                    r"[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})"
                )
            else:
                out = subprocess.check_output(["arp", "-n"]).decode(errors="ignore")
                # Linux: "192.168.1.1  ether  aa:bb:cc:dd:ee:ff"
                pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([\da-fA-F:]{17})")

            seen = set()
            responded_macs = []
            for match in pattern.finditer(out):
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").lower()
                if mac == "ff:ff:ff:ff:ff:ff" or ip in seen:
                    continue
                seen.add(ip)
                responded_macs.append(mac)

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
                    "hostname": _resolve_hostname(ip),
                }
                packet_queue.put(payload)

            if responded_macs:
                import database

                placeholders = ",".join("?" for _ in responded_macs)
                database.execute_write_async(
                    f"UPDATE devices SET is_online = 0 WHERE mac_address NOT IN ({placeholders})", tuple(responded_macs)
                )

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
