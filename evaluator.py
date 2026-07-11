import logging
import queue
import threading
import math
import socket
import concurrent.futures
from datetime import datetime, time
from collections import Counter

import database
import notifier
import telegram_agent

logger = logging.getLogger("Evaluator")

_evaluator_thread = None
_shutdown_event = threading.Event()
_resolver_pool = concurrent.futures.ThreadPoolExecutor(max_workers=5, thread_name_prefix="DNSResolver")

# Config parameters cached locally
_config = {}

# In-memory tracking for Out-Of-Hours rate limits
# Key: (mac, minute_str), Value: count
_appliance_traffic_counts = {}
# Key: (mac, minute_str), Value: alerted (bool)
_appliance_alerted_minutes = {}

# In-memory tracking for recently alerted DNS queries to prevent spam
# Key: domain, Value: timestamp
_dns_alert_history = {}

def calculate_entropy(s: str) -> float:
    """Calculate the Shannon Entropy of a string in bits."""
    if not s:
        return 0.0
    entropy = 0.0
    length = len(s)
    counts = Counter(s)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def is_local_ip(ip):
    """Determine if an IP address belongs to local network prefixes."""
    if not ip:
        return False
    # Local loopback
    if ip == "127.0.0.1" or ip == "::1":
        return True
    
    # Broadcast / Multicast
    if ip.startswith("224.") or ip.startswith("239.") or ip == "255.255.255.255" or ip == "0.0.0.0":
        return False
        
    local_prefixes = _config.get("local_networks", ["192.168.", "10.", "172.16."])
    for prefix in local_prefixes:
        if ip.startswith(prefix):
            return True
    return False

def resolve_hostname_async(mac_address, ip):
    """Resolve a hostname asynchronously in a thread pool to avoid blocking the main evaluator loop."""
    def lookup():
        try:
            # Short timeout lookup using socket
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

def start_evaluator(packet_queue, config):
    """Start the background packet evaluation thread."""
    global _evaluator_thread, _config
    _config = config
    _shutdown_event.clear()
    
    _evaluator_thread = threading.Thread(
        target=_evaluator_worker, 
        args=(packet_queue,), 
        name="EvaluatorThread", 
        daemon=True
    )
    _evaluator_thread.start()

def stop_evaluator():
    """Stop the evaluator worker thread."""
    global _evaluator_thread
    if _evaluator_thread:
        logger.info("Stopping evaluator worker...")
        _shutdown_event.set()
        _evaluator_thread.join(timeout=5.0)
        _evaluator_thread = None

def _evaluator_worker(packet_queue):
    """Loop pulling packet payloads from queue and evaluating heuristics."""
    logger.info("Evaluator worker thread started.")
    
    # Track when to clean up in-memory caches (every 5 minutes)
    last_cleanup_time = datetime.now()
    
    while not _shutdown_event.is_set():
        try:
            try:
                # Polling wait to check shutdown event
                payload = packet_queue.get(timeout=1.0)
            except queue.Empty:
                continue
                
            # Perform periodic cache cleanup to keep memory usage under 150MB
            now_dt = datetime.now()
            if (now_dt - last_cleanup_time).total_seconds() > 300:
                cleanup_in_memory_caches()
                last_cleanup_time = now_dt
                
            # Extract basic elements
            timestamp = payload.get("timestamp")
            src_mac = payload.get("src_mac")
            dst_mac = payload.get("dst_mac")
            src_ip = payload.get("src_ip")
            dst_ip = payload.get("dst_ip")
            src_port = payload.get("src_port")
            dst_port = payload.get("dst_port")
            protocol = payload.get("protocol")
            dns_query = payload.get("dns_query")
            # hostname may be pre-resolved by the ARP scanner
            resolved_hostname = payload.get("hostname")
            
            # 1. Device tracking & New Device Discovery (MEDIUM)
            # Query db for existing device
            device_record = database.execute_read("SELECT mac_address FROM devices WHERE mac_address = ?", (src_mac,))
            
            if not device_record:
                # Use pre-resolved hostname from ARP scan, or generate default
                initial_hostname = resolved_hostname or f"Device-{src_mac.replace(':', '')[-6:]}"
                device_cat = _guess_device_type(initial_hostname)
                
                database.execute_write_sync(
                    "INSERT INTO devices (mac_address, last_known_ip, hostname, device_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                    (src_mac, src_ip, initial_hostname, device_cat, timestamp, timestamp)
                )
                
                # Also async resolve if not already resolved
                if not resolved_hostname:
                    resolve_hostname_async(src_mac, src_ip)
                
                # Trigger alert
                alert_type = "NEW_DEVICE"
                description = f"New device discovered on network. MAC: {src_mac}, IP: {src_ip}, Name: {initial_hostname} ({device_cat})"
                severity = "MEDIUM"

                database.execute_write_async(
                    "INSERT INTO alerts (timestamp, alert_type, description, severity, is_resolved) VALUES (?, ?, ?, ?, 0)",
                    (timestamp, alert_type, description, severity)
                )
                notifier.queue_alert(alert_type, description, severity, timestamp)

                # Trigger Telegram agent alert to root user
                telegram_agent.alert_new_device({
                    "mac_address": src_mac,
                    "last_known_ip": src_ip,
                    "hostname": initial_hostname,
                    "device_type": device_cat,
                    "first_seen": timestamp
                })

                logger.info(f"New device registered: MAC {src_mac} / IP {src_ip}")
            else:
                # Update last seen timestamp, IP, and hostname if we now have a better one
                if resolved_hostname:
                    database.execute_write_async(
                        "UPDATE devices SET last_known_ip = ?, last_seen = ?, hostname = ? WHERE mac_address = ? AND (hostname = 'Unknown' OR hostname LIKE 'Device-%')",
                        (src_ip, timestamp, resolved_hostname, src_mac)
                    )
                else:
                    database.execute_write_async(
                        "UPDATE devices SET last_known_ip = ?, last_seen = ? WHERE mac_address = ?",
                        (src_ip, timestamp, src_mac)
                    )
                
            # 2. Aggregated Traffic Logging
            # Log flow details. Clean duplicates using SQLite UNIQUE constraint on (source_ip, dest_ip, dest_port, protocol)
            database.execute_write_async(
                """
                INSERT INTO traffic_logs (source_ip, dest_ip, dest_port, protocol, packet_count, last_active)
                VALUES (?, ?, ?, ?, 1, ?)
                ON CONFLICT(source_ip, dest_ip, dest_port, protocol)
                DO UPDATE SET packet_count = packet_count + 1, last_active = excluded.last_active
                """,
                (src_ip, dst_ip, dst_port, protocol, timestamp)
            )
            
            # 3. Out-Of-Hours Alert (HIGH)
            # Triggered if local appliance sends > 50 packets per minute to external WAN gateways between 1:00 AM and 5:00 AM
            appliance_macs = _config.get("appliance_macs", [])
            if src_mac in appliance_macs:
                # Parse packet datetime
                try:
                    dt = datetime.fromisoformat(timestamp)
                except ValueError:
                    dt = datetime.now()
                    
                # Check if hour is in window (1:00 AM to 5:00 AM)
                start_h = 1
                end_h = 5
                
                if start_h <= dt.hour < end_h:
                    # Check if destination is WAN (not local, not multicast/broadcast)
                    if not is_local_ip(dst_ip):
                        minute_str = dt.strftime("%Y-%m-%dT%H:%M")
                        rate_key = (src_mac, minute_str)
                        
                        # Increment count
                        current_count = _appliance_traffic_counts.get(rate_key, 0) + 1
                        _appliance_traffic_counts[rate_key] = current_count
                        
                        limit = _config.get("out_of_hours_packet_limit", 50)
                        if current_count > limit:
                            # Check if alert already triggered for this device in this minute to avoid spam
                            alert_key = (src_mac, minute_str)
                            if not _appliance_alerted_minutes.get(alert_key, False):
                                _appliance_alerted_minutes[alert_key] = True
                                
                                alert_type = "UNUSUAL_HOURS"
                                description = f"Appliance {src_mac} (IP: {src_ip}) exceeded {limit} packets/min ({current_count}) to WAN IP {dst_ip} out-of-hours."
                                severity = "HIGH"
                                
                                database.execute_write_async(
                                    "INSERT INTO alerts (timestamp, alert_type, description, severity, is_resolved) VALUES (?, ?, ?, ?, 0)",
                                    (timestamp, alert_type, description, severity)
                                )
                                notifier.queue_alert(alert_type, description, severity, timestamp)
                                logger.info(f"Alert triggered: {alert_type} for MAC {src_mac} with rate {current_count}")
                                
            # 4. DNS Tunneling Detection (HIGH)
            # Triggered if DNS query length > 60 or entropy H > 4.5 bits
            if dst_port == 53 and dns_query:
                # Check length
                len_threshold = _config.get("dns_length_threshold", 60)
                entropy_threshold = _config.get("dns_entropy_threshold", 4.5)
                
                query_len = len(dns_query)
                entropy = calculate_entropy(dns_query)
                
                if query_len > len_threshold or entropy > entropy_threshold:
                    # Check if we recently alerted this domain to prevent DB spam
                    # Deduplicate within 10 seconds
                    last_alerted = _dns_alert_history.get(dns_query)
                    time_now = datetime.now()
                    
                    if not last_alerted or (time_now - last_alerted).total_seconds() > 10:
                        _dns_alert_history[dns_query] = time_now
                        
                        alert_type = "SUSPICIOUS_DNS"
                        reasons = []
                        if query_len > len_threshold:
                            reasons.append(f"length {query_len} > {len_threshold}")
                        if entropy > entropy_threshold:
                            reasons.append(f"entropy {entropy:.2f} > {entropy_threshold}")
                            
                        reason_str = " and ".join(reasons)
                        description = f"Suspicious DNS query payload on Port 53: '{dns_query}' ({reason_str}). Source IP: {src_ip}."
                        severity = "HIGH"
                        
                        database.execute_write_async(
                            "INSERT INTO alerts (timestamp, alert_type, description, severity, is_resolved) VALUES (?, ?, ?, ?, 0)",
                            (timestamp, alert_type, description, severity)
                        )
                        notifier.queue_alert(alert_type, description, severity, timestamp)
                        logger.info(f"Alert triggered: {alert_type} for query {dns_query[:20]}")
                        
            packet_queue.task_done()
            
        except Exception as e:
            logger.error(f"Error in evaluator worker loop: {e}")

def cleanup_in_memory_caches():
    """Clear memory of stale cached entries to enforce memory limits (<150MB)."""
    global _appliance_traffic_counts, _appliance_alerted_minutes, _dns_alert_history
    
    now = datetime.now()
    # Stale minutes: older than 5 minutes
    # Keep only the current and last 2 minutes
    stale_keys_traffic = []
    for key in _appliance_traffic_counts:
        mac, min_str = key
        try:
            dt = datetime.strptime(min_str, "%Y-%m-%dT%H:%M")
            if (now - dt).total_seconds() > 300:
                stale_keys_traffic.append(key)
        except ValueError:
            stale_keys_traffic.append(key)
            
    for key in stale_keys_traffic:
        _appliance_traffic_counts.pop(key, None)
        _appliance_alerted_minutes.pop(key, None)
        
    stale_dns = []
    for domain, ts in _dns_alert_history.items():
        if (now - ts).total_seconds() > 300:
            stale_dns.append(domain)
            
    for domain in stale_dns:
        _dns_alert_history.pop(domain, None)
        
    logger.debug("In-memory evaluation caches swept.")

def _guess_device_type(hostname: str) -> str:
    """Guess device type (phone, pc, tv, printer, router, iot, unknown) from hostname."""
    name = hostname.lower()
    if any(k in name for k in ["iphone", "android", "phone", "mobile", "galaxy", "pixel", "oneplus"]):
        return "phone"
    if any(k in name for k in ["desktop", "pc", "laptop", "macbook", "imac", "computer", "windows", "latitude", "thinkpad"]):
        return "pc"
    if any(k in name for k in ["tv", "television", "roku", "firetv", "chromecast", "smarttv"]):
        return "tv"
    if any(k in name for k in ["printer", "print", "laserjet", "deskjet"]):
        return "printer"
    if any(k in name for k in ["router", "gateway", "ap-", "modem", "switch", "hub"]):
        return "router"
    if any(k in name for k in ["camera", "cam", "nest", "ring", "bulb", "plug", "smart", "alexa", "echo", "homepod"]):
        return "iot"
    return "unknown"
