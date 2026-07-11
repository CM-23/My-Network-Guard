import platform
import subprocess
import socket
import re
import logging
import os

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
            out = subprocess.check_output("ipconfig", shell=True).decode(errors="ignore")
            # Find 'Default Gateway' after the active adapter section
            for line in out.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        ip = parts[-1].strip()
                        if ip and ip != "" and _is_valid_ip(ip):
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

def get_subnet():
    """Returns the /24 subnet string for the local interface (e.g. '192.168.1.0/24')."""
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

def list_wifi_networks():
    """Returns a list of visible WiFi SSIDs."""
    networks = []
    try:
        if _OS == "Windows":
            out = subprocess.check_output(
                "netsh wlan show networks mode=Bssid", shell=True
            ).decode(errors="ignore")
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("SSID") and "BSSID" not in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        ssid = ":".join(parts[1:]).strip()
                        if ssid and ssid not in networks:
                            networks.append(ssid)
        elif _OS == "Linux":
            out = subprocess.check_output(
                "nmcli -t -f SSID dev wifi list", shell=True
            ).decode(errors="ignore")
            for line in out.splitlines():
                ssid = line.strip()
                if ssid and ssid not in networks:
                    networks.append(ssid)
        elif _OS == "Darwin":
            out = subprocess.check_output(
                "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s",
                shell=True
            ).decode(errors="ignore")
            for line in out.splitlines()[1:]:
                parts = line.split()
                if parts:
                    ssid = parts[0]
                    if ssid not in networks:
                        networks.append(ssid)
    except Exception as e:
        logger.error(f"Error listing WiFi networks: {e}")
    return networks

# ─────────────────────────────────────────
# WiFi Connection
# ─────────────────────────────────────────

def connect_to_wifi(ssid, password):
    """
    Attempts to connect to a WiFi network with given credentials.
    Returns dict: {success: bool, message: str}
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
            return {"success": False, "message": f"Unsupported OS: {_OS}"}
    except Exception as e:
        logger.error(f"WiFi connection error: {e}")
        return {"success": False, "message": str(e)}

def _connect_windows(ssid, password):
    """Connect to WiFi on Windows using netsh wlan."""
    # Step 1: Create a temporary XML profile
    profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
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
                <keyMaterial>{password}</keyMaterial>
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
            f'netsh wlan add profile filename="{profile_path}"',
            shell=True, capture_output=True, text=True, timeout=10
        )
        logger.info(f"Profile add result: {add_result.stdout.strip()}")

        # Step 3: Connect
        connect_result = subprocess.run(
            f'netsh wlan connect name="{ssid}"',
            shell=True, capture_output=True, text=True, timeout=15
        )
        output = connect_result.stdout.strip()
        logger.info(f"Connect result: {output}")

        # Step 4: Wait briefly and verify
        import time
        time.sleep(4)

        new_ssid = get_current_ssid()
        if new_ssid and new_ssid.strip() == ssid.strip():
            return {"success": True, "message": f"Connected to {ssid} successfully."}
        elif "Connection request was completed successfully" in output:
            return {"success": True, "message": f"Connected to {ssid} successfully."}
        else:
            return {"success": False, "message": f"Could not connect to '{ssid}'. Check your password and try again."}

    finally:
        try:
            os.remove(profile_path)
        except Exception:
            pass

def _connect_linux(ssid, password):
    """Connect to WiFi on Linux using nmcli."""
    result = subprocess.run(
        ["nmcli", "dev", "wifi", "connect", ssid, "password", password],
        capture_output=True, text=True, timeout=20
    )
    output = result.stdout + result.stderr
    if result.returncode == 0 or "successfully activated" in output.lower():
        return {"success": True, "message": f"Connected to {ssid} successfully."}
    else:
        return {"success": False, "message": output.strip() or "Connection failed. Check credentials."}

def _connect_macos(ssid, password):
    """Connect to WiFi on macOS using networksetup."""
    result = subprocess.run(
        ["networksetup", "-setairportnetwork", "en0", ssid, password],
        capture_output=True, text=True, timeout=20
    )
    if result.returncode == 0:
        return {"success": True, "message": f"Connected to {ssid} successfully."}
    else:
        return {"success": False, "message": result.stderr.strip() or "Connection failed."}

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
