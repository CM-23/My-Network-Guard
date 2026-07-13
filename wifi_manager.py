import platform
import subprocess
import socket
import re
import logging
import os
from xml.sax.saxutils import escape as _xml_escape

logger = logging.getLogger("WiFiManager")

_OS = platform.system()  # 'Windows' or 'Linux' or 'Darwin'

# ─────────────────────────────────────────
# Network Info
# ─────────────────────────────────────────

def get_local_ip():
    """Returns the local machine IP address on the active interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_gateway_ip():
    """Returns the default gateway/router IP address."""
    try:
        if _OS == "Windows":
            local_ip = get_local_ip()
            out = subprocess.check_output("ipconfig", shell=True).decode(errors="ignore")
            # Scope the search to the adapter block that contains our active local IP,
            # otherwise a stale/disconnected adapter's gateway can be picked up instead.
            blocks = re.split(r"\r?\n\r?\n", out)
            target_blocks = [b for b in blocks if local_ip in b] or blocks
            for block in target_blocks:
                for line in block.splitlines():
                    if "Default Gateway" in line:
                        parts = line.split(":")
                        if len(parts) > 1:
                            ip = parts[-1].strip()
                            if ip and _is_valid_ip(ip):
                                return ip
        else:
            out = subprocess.check_output("ip route show default", shell=True).decode(errors="ignore")
            # e.g. "default via 192.168.1.1 dev wlan0"
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if match:
                return match.group(1)
    except Exception as e:
        logger.error(f"Error getting gateway IP: {e}")
    return None

def has_subnet_mismatch():
    gw = get_gateway_ip()
    local = get_local_ip()
    if not gw or not local or gw == "127.0.0.1" or local == "127.0.0.1":
        return False
    gw_parts = gw.split(".")
    local_parts = local.split(".")
    if len(gw_parts) == 4 and len(local_parts) == 4:
        return gw_parts[:3] != local_parts[:3]
    return False

def get_subnet():
    """Returns the /24 subnet string for the local interface (e.g. '192.168.1.0/24')."""
    if has_subnet_mismatch():
        logger.warning("Detected local IP and gateway IP are on different subnets — scan results may be incomplete, check for an active VPN")
    ip = get_local_ip()
    if ip and ip != "127.0.0.1":
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "192.168.1.0/24"

def get_current_ssid():
    """Returns the SSID of the currently connected WiFi network."""
    try:
        if _OS == "Windows":
            out = subprocess.check_output(
                "netsh wlan show interfaces", shell=True
            ).decode(errors="ignore")
            for line in out.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        ssid = ":".join(parts[1:]).strip()
                        if ssid:
                            return ssid
        elif _OS == "Linux":
            out = subprocess.check_output(
                "nmcli -t -f active,ssid dev wifi", shell=True
            ).decode(errors="ignore")
            for line in out.splitlines():
                if line.startswith("yes:"):
                    return line.split(":", 1)[1].strip()
        elif _OS == "Darwin":
            out = subprocess.check_output(
                "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I",
                shell=True
            ).decode(errors="ignore")
            for line in out.splitlines():
                if " SSID:" in line:
                    return line.split("SSID:")[1].strip()
    except Exception as e:
        logger.warning(f"Could not get current SSID: {e}")
    return None

def get_network_status():
    """Returns a complete status dict about the current network connection."""
    ssid = get_current_ssid()
    local_ip = get_local_ip()
    gateway = get_gateway_ip()
    
    # Auto-detect connection: if we have a valid non-loopback IP, we are connected to a network!
    connected = local_ip not in (None, "127.0.0.1", "0.0.0.0", "")
    
    if connected and not ssid:
        ssid = "Active Network"

    return {
        "connected": connected,
        "ssid": ssid or "",
        "local_ip": local_ip,
        "gateway_ip": gateway or "",
        "subnet": get_subnet(),
        "platform": _OS
    }

# ─────────────────────────────────────────
# WiFi Network Discovery
# ─────────────────────────────────────────

def scan_networks():
    """Returns a normalized list of visible WiFi networks: {ssid, signal_strength, security_type, bssid}."""
    networks = []
    try:
        if _OS == "Windows":
            out = subprocess.check_output(
                "netsh wlan show networks mode=bssid", shell=True
            ).decode(errors="ignore")
            networks = _parse_netsh_networks(out)
        elif _OS == "Linux":
            out = subprocess.check_output(
                "nmcli -t -f SSID,SIGNAL,SECURITY,BSSID dev wifi", shell=True
            ).decode(errors="ignore")
            networks = _parse_nmcli_networks(out)
        elif _OS == "Darwin":
            out = subprocess.check_output(
                "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s",
                shell=True
            ).decode(errors="ignore")
            networks = _parse_macos_airport(out)
    except Exception as e:
        logger.error(f"Error scanning WiFi networks: {e}")

    # Remove duplicates and sort by signal strength descending
    seen = set()
    unique_networks = []
    for net in networks:
        key = (net["ssid"], net["bssid"])
        if key not in seen:
            seen.add(key)
            unique_networks.append(net)
            
    unique_networks.sort(key=lambda x: x.get("signal_strength", 0), reverse=True)
    return unique_networks

def list_wifi_networks():
    """Returns a list of visible WiFi SSIDs (for backward compatibility)."""
    return list({net["ssid"] for net in scan_networks() if net["ssid"] and net["ssid"] != "Hidden Network"})

def _parse_netsh_networks(output):
    networks = []
    current_ssid = None
    current_auth = None
    current_encrypt = None
    current_bssid = None

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("SSID "):
            parts = line.split(":", 1)
            if len(parts) > 1:
                current_ssid = parts[1].strip()
            else:
                current_ssid = ""
            current_auth = "Open"
            current_encrypt = "None"
            current_bssid = None
        elif line.startswith("Authentication"):
            parts = line.split(":", 1)
            if len(parts) > 1:
                current_auth = parts[1].strip()
        elif line.startswith("Encryption"):
            parts = line.split(":", 1)
            if len(parts) > 1:
                current_encrypt = parts[1].strip()
        elif line.startswith("BSSID "):
            parts = line.split(":", 1)
            if len(parts) > 1:
                current_bssid = parts[1].strip().lower()
        elif line.startswith("Signal"):
            parts = line.split(":", 1)
            if len(parts) > 1:
                sig_str = parts[1].strip().replace("%", "")
                try:
                    signal = int(sig_str)
                except ValueError:
                    signal = 0
                
                security = current_auth
                if current_encrypt and current_encrypt != "None" and current_encrypt not in security:
                    security = f"{current_auth} ({current_encrypt})"
                
                networks.append({
                    "ssid": current_ssid or "Hidden Network",
                    "signal_strength": signal,
                    "security_type": security,
                    "bssid": current_bssid or ""
                })
    return networks

def _parse_nmcli_networks(output):
    networks = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = []
        current = []
        escaped = False
        for char in line:
            if escaped:
                current.append(char)
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == ':':
                parts.append("".join(current))
                current = []
            else:
                current.append(char)
        parts.append("".join(current))
        
        if len(parts) >= 4:
            ssid = parts[0].strip()
            sig_str = parts[1].strip()
            security = parts[2].strip()
            bssid = parts[3].strip().lower()
            
            try:
                signal = int(sig_str)
            except ValueError:
                signal = 0
                
            networks.append({
                "ssid": ssid or "Hidden Network",
                "signal_strength": signal,
                "security_type": security or "Open",
                "bssid": bssid
            })
    return networks

def _parse_macos_airport(output):
    import re
    networks = []
    lines = output.splitlines()
    if len(lines) <= 1:
        return networks
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 6:
            bssid_idx = -1
            for i, p in enumerate(parts):
                if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", p):
                    bssid_idx = i
                    break
            if bssid_idx != -1:
                ssid = " ".join(parts[:bssid_idx])
                bssid = parts[bssid_idx].lower()
                rssi_str = parts[bssid_idx+1]
                try:
                    rssi = int(rssi_str)
                    signal = min(max(2 * (rssi + 100), 0), 100)
                except ValueError:
                    signal = 0
                security = " ".join(parts[bssid_idx+4:]) if len(parts) > bssid_idx+4 else "Open"
                networks.append({
                    "ssid": ssid or "Hidden Network",
                    "signal_strength": signal,
                    "security_type": security,
                    "bssid": bssid
                })
    return networks

# ─────────────────────────────────────────
# WiFi Connection
# ─────────────────────────────────────────

def connect_to_wifi(ssid, password):
    """
    Attempts to connect to a WiFi network with given credentials.
    Returns dict: {success: bool, status: str, message: str}
    Where status is one of: CONNECTED, WRONG_PASSWORD, TIMEOUT, UNSUPPORTED_SECURITY
    """
    logger.info(f"Attempting WiFi connection to SSID: {ssid}")

    try:
        if _OS == "Windows":
            return _connect_windows(ssid, password)
        elif _OS == "Linux":
            return _connect_linux(ssid, password)
        elif _OS == "Darwin":
            return _connect_macos(ssid, password)
        else:
            return {"success": False, "status": "UNSUPPORTED_SECURITY", "message": f"Unsupported OS: {_OS}"}
    except Exception as e:
        logger.error(f"WiFi connection error: {e}")
        return {"success": False, "status": "TIMEOUT", "message": str(e)}

def _detect_security_type(ssid):
    """Looks up the security type of a given SSID from the last scan.
    Falls back to 'WPA2-Personal' if not found (safest common default)."""
    try:
        for net in scan_networks():
            if net["ssid"] == ssid:
                return net.get("security_type", "WPA2-Personal")
    except Exception:
        pass
    return "WPA2-Personal"

def _security_to_profile_auth(security_type):
    """Maps a scanned security_type string to the Windows WLAN profile
    <authentication> value. Returns (authentication, encryption, is_open)."""
    s = (security_type or "").lower()
    if "wpa3" in s:
        return "WPA3SSE", "AES", False
    if "wpa2" in s or "wpa" in s:
        return "WPA2PSK", "AES", False
    # Open / no security detected
    return "open", "none", True

def _connect_windows(ssid, password):
    """Connect to WiFi on Windows using netsh wlan."""
    # Escape SSID/password so special characters (&, <, >, ", ') don't corrupt the XML profile
    ssid_esc = _xml_escape(ssid)
    password_esc = _xml_escape(password) if password else ""

    security_type = _detect_security_type(ssid)
    auth, encryption, is_open = _security_to_profile_auth(security_type)

    if is_open or not password:
        profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid_esc}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid_esc}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>"""
    else:
        profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid_esc}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid_esc}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{auth}</authentication>
                <encryption>{encryption}</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password_esc}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""

    profile_path = os.path.join(os.environ.get("TEMP", "."), "nids_wifi_profile.xml")
    try:
        with open(profile_path, "w", encoding="utf-8") as f:
            f.write(profile_xml)

        # Step 2: Add profile
        add_result = subprocess.run(
            ["netsh", "wlan", "add", "profile", f"filename={profile_path}"],
            capture_output=True, text=True, timeout=10
        )
        if add_result.returncode != 0:
            logger.error(f"netsh add profile failed: {add_result.stdout} {add_result.stderr}")
            # WPA3SSE profiles fail on older Windows builds that don't support the tag —
            # retry once as WPA2PSK, which most WPA3 routers also accept in transition mode.
            if auth == "WPA3SSE":
                return _connect_windows_fallback_wpa2(ssid, password, ssid_esc, password_esc, profile_path)
            return {"success": False, "status": "UNSUPPORTED_SECURITY",
                    "message": f"Failed to add profile: {add_result.stderr.strip() or add_result.stdout.strip()}"}

        # Step 3: Connect
        subprocess.run(
            ["netsh", "wlan", "connect", f"name={ssid}"],
            capture_output=True, text=True, timeout=15
        )

        # Wait up to 8 seconds and check connection
        import time
        for _ in range(8):
            time.sleep(1.0)
            status = get_network_status()
            if status["connected"] and status["ssid"] == ssid:
                return {"success": True, "status": "CONNECTED", "message": f"Connected to {ssid} successfully."}

        # If not connected, assume wrong password or timeout
        return {"success": False, "status": "WRONG_PASSWORD", "message": f"Could not connect to '{ssid}'. Check your password."}

    finally:
        try:
            if os.path.exists(profile_path):
                os.remove(profile_path)
        except Exception:
            pass

def _connect_windows_fallback_wpa2(ssid, password, ssid_esc, password_esc, profile_path):
    """Retry as a standard WPA2PSK profile when WPA3SSE isn't supported by this Windows build."""
    profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid_esc}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid_esc}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password_esc}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""
    with open(profile_path, "w", encoding="utf-8") as f:
        f.write(profile_xml)

    add_result = subprocess.run(
        ["netsh", "wlan", "add", "profile", f"filename={profile_path}"],
        capture_output=True, text=True, timeout=10
    )
    if add_result.returncode != 0:
        return {"success": False, "status": "UNSUPPORTED_SECURITY",
                "message": f"Failed to add profile (WPA2 fallback): {add_result.stderr.strip() or add_result.stdout.strip()}"}

    subprocess.run(["netsh", "wlan", "connect", f"name={ssid}"], capture_output=True, text=True, timeout=15)

    import time
    for _ in range(8):
        time.sleep(1.0)
        status = get_network_status()
        if status["connected"] and status["ssid"] == ssid:
            return {"success": True, "status": "CONNECTED", "message": f"Connected to {ssid} successfully."}
    return {"success": False, "status": "WRONG_PASSWORD", "message": f"Could not connect to '{ssid}'. Check your password."}

def _connect_linux(ssid, password):
    """Connect to WiFi on Linux using nmcli."""
    if password:
        cmd = ["nmcli", "dev", "wifi", "connect", ssid, "password", password]
    else:
        # Open network — passing an empty password string to nmcli causes it to fail,
        # so omit the password argument entirely.
        cmd = ["nmcli", "dev", "wifi", "connect", ssid]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    output = (result.stdout + result.stderr).lower()
    if result.returncode == 0 or "successfully activated" in output:
        return {"success": True, "status": "CONNECTED", "message": f"Connected to {ssid} successfully."}
    elif "secrets were required" in output or "authorization" in output or "password" in output:
        return {"success": False, "status": "WRONG_PASSWORD", "message": "Incorrect password."}
    elif "timeout" in output:
        return {"success": False, "status": "TIMEOUT", "message": "Connection timed out."}
    else:
        return {"success": False, "status": "UNSUPPORTED_SECURITY", "message": f"Connection failed: {result.stderr.strip()}"}

def _connect_macos(ssid, password):
    """Connect to WiFi on macOS using networksetup."""
    result = subprocess.run(
        ["networksetup", "-setairportnetwork", "en0", ssid, password],
        capture_output=True, text=True, timeout=20
    )
    if result.returncode == 0:
        return {"success": True, "status": "CONNECTED", "message": f"Connected to {ssid} successfully."}
    else:
        return {"success": False, "status": "WRONG_PASSWORD", "message": result.stderr.strip() or "Connection failed."}

# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def _is_valid_ip(ip):
    """Basic check for a valid IPv4 address string."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False