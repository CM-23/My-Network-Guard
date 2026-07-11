import logging
import threading
import queue
import platform

logger = logging.getLogger("Blocker")
_OS = platform.system()

# Track blocked IPs in memory for fast lookups
_blocked_ips = set()
_lock = threading.Lock()

# ─────────────────────────────────────────
# Public API
# ─────────────────────────────────────────

def block_device(ip: str, mac: str = "") -> dict:
    """
    Block a device by IP using OS firewall rules.
    Returns {success: bool, message: str}
    """
    import subprocess
    ip = ip.strip()
    if not ip or ip == "0.0.0.0":
        return {"success": False, "message": "Invalid IP address."}

    if is_blocked(ip):
        return {"success": True, "message": f"{ip} is already blocked."}

    try:
        if _OS == "Windows":
            result = _block_windows(ip)
        elif _OS == "Linux":
            result = _block_linux(ip)
        elif _OS == "Darwin":
            result = _block_macos(ip)
        else:
            return {"success": False, "message": f"Unsupported OS: {_OS}"}

        if result["success"]:
            with _lock:
                _blocked_ips.add(ip)
            logger.warning(f"[BLOCKED] Device IP: {ip} MAC: {mac}")

        return result

    except Exception as e:
        logger.error(f"Error blocking device {ip}: {e}")
        return {"success": False, "message": str(e)}


def unblock_device(ip: str) -> dict:
    """
    Remove a firewall block rule for a device IP.
    Returns {success: bool, message: str}
    """
    ip = ip.strip()
    try:
        if _OS == "Windows":
            result = _unblock_windows(ip)
        elif _OS == "Linux":
            result = _unblock_linux(ip)
        elif _OS == "Darwin":
            result = _unblock_macos(ip)
        else:
            return {"success": False, "message": f"Unsupported OS: {_OS}"}

        if result["success"]:
            with _lock:
                _blocked_ips.discard(ip)
            logger.info(f"[UNBLOCKED] Device IP: {ip}")

        return result

    except Exception as e:
        logger.error(f"Error unblocking {ip}: {e}")
        return {"success": False, "message": str(e)}


def is_blocked(ip: str) -> bool:
    with _lock:
        return ip in _blocked_ips


def load_blocked_from_db(db_read_fn):
    """
    On startup, reload all blocked IPs from the database into memory.
    Pass database.execute_read as db_read_fn.
    """
    global _blocked_ips
    try:
        rows = db_read_fn("SELECT ip FROM blocked_devices WHERE is_active=1")
        with _lock:
            _blocked_ips = {row["ip"] for row in rows}
        logger.info(f"Loaded {len(_blocked_ips)} blocked IP(s) from database.")
    except Exception as e:
        logger.error(f"Error loading blocked devices: {e}")

# ─────────────────────────────────────────
# Windows Firewall (netsh)
# ─────────────────────────────────────────

def _block_windows(ip):
    import subprocess
    rule_name = f"NetScanner_Block_{ip.replace('.', '_')}"
    # Block inbound and outbound
    cmds = [
        f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip} enable=yes',
        f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip} enable=yes',
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            logger.error(f"netsh error: {r.stderr}")
    return {"success": True, "message": f"Firewall rules added for {ip}."}


def _unblock_windows(ip):
    import subprocess
    rule_name = f"NetScanner_Block_{ip.replace('.', '_')}"
    cmds = [
        f'netsh advfirewall firewall delete rule name="{rule_name}_IN"',
        f'netsh advfirewall firewall delete rule name="{rule_name}_OUT"',
    ]
    for cmd in cmds:
        subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    return {"success": True, "message": f"Firewall rules removed for {ip}."}

# ─────────────────────────────────────────
# Linux (iptables)
# ─────────────────────────────────────────

def _block_linux(ip):
    import subprocess
    cmds = [
        f"iptables -A INPUT -s {ip} -j DROP",
        f"iptables -A FORWARD -s {ip} -j DROP",
        f"iptables -A OUTPUT -d {ip} -j DROP",
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            logger.warning(f"iptables warning: {r.stderr}")
    return {"success": True, "message": f"iptables rules added for {ip}."}


def _unblock_linux(ip):
    import subprocess
    cmds = [
        f"iptables -D INPUT -s {ip} -j DROP",
        f"iptables -D FORWARD -s {ip} -j DROP",
        f"iptables -D OUTPUT -d {ip} -j DROP",
    ]
    for cmd in cmds:
        subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
    return {"success": True, "message": f"iptables rules removed for {ip}."}

# ─────────────────────────────────────────
# macOS (pfctl)
# ─────────────────────────────────────────

def _block_macos(ip):
    import subprocess
    rule = f"block drop from {ip} to any\n"
    anchor = "netscanner"
    r = subprocess.run(
        f'echo "{rule}" | pfctl -a {anchor} -f -',
        shell=True, capture_output=True, text=True, timeout=10
    )
    if r.returncode == 0:
        return {"success": True, "message": f"pfctl rule added for {ip}."}
    return {"success": False, "message": r.stderr}


def _unblock_macos(ip):
    import subprocess
    anchor = "netscanner"
    subprocess.run(f"pfctl -a {anchor} -F rules", shell=True, capture_output=True, timeout=10)
    return {"success": True, "message": f"pfctl rules flushed for {ip}."}
