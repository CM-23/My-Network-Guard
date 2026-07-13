"""
scanner_agent — Local network scanning engine.

Responsible for:
  - Packet capture (Scapy / Npcap / libpcap)
  - ARP scanning (active + passive)
  - Multi-protocol device discovery (ARP, mDNS, SSDP, DHCP, NBNS, ICMP)
  - Device fingerprinting (OS, vendor, device type)
  - Threat detection heuristics
  - MAC OUI vendor resolution
"""
