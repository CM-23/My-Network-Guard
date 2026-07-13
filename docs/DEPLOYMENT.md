# Deployment Guide — My Network Guard

This guide details the steps required to deploy My Network Guard as a fully functional, production-ready Network Intrusion Detection & Response (NDR) platform in a real-world home or enterprise network.

---

## 1. Physical Deployment Architecture

To capture packet flows, the scanning engine needs visibility into the network. Choose one of the following setups:

```
Option A: Broadcast & Multicast (Zero-Config)
┌─────────────┐       ┌─────────────┐       ┌───────────────────────────┐
│  Smart TV   │       │   Laptop    │       │     My Network Guard      │
│ (Multicast) │       │ (Broadcast) │       │ (Captures Broadcasts/ARP) │
└──────┬──────┘       └──────┬──────┘       └─────────────┬─────────────┘
       │                     │                            │
 ──────┴─────────────────────┴────────────────────────────┴───── Local LAN
```
- **Description**: Run the app on any device on the local network (PC, Raspberry Pi, Home Server).
- **Pro**: Simple, requires no specialized network configuration.
- **Con**: Captures only broadcast traffic (ARP, DHCP, NBNS), multicast traffic (mDNS, SSDP), and traffic directly to/from the host machine. (Good for discovery, basic threat detection).

```
Option B: Port Mirroring / SPAN Port (Enterprise NDR)
┌─────────────┐       ┌─────────────┐       ┌───────────────────────────┐
│  Smart TV   │       │   Laptop    │       │     My Network Guard      │
│  (Traffic)  │       │  (Traffic)  │       │  (Passive Monitor Port)   │
└──────┬──────┘       └──────┬──────┘       └─────────────▲─────────────┘
       │                     │                            │
 ──────┴──────────┬──────────┴────────────────────────────┼───── Managed Switch
                  │                                       │
                  └───────── SPAN/Mirror Port copy ───────┘
```
- **Description**: Plug the host machine running the scanner into a **SPAN (Switch Port Analyzer) / Mirror Port** on a managed network switch. Configure the switch to copy all VLAN traffic to this port.
- **Pro**: Complete visibility into all unicast traffic, internal lateral movement, and WAN transfers.
- **Con**: Requires a managed switch.

---

## 2. Platform Prerequisites

| Platform | Requirements |
|---|---|
| **Windows** | 1. [Npcap](https://npcap.com/) driver installed (Check **"Install Npcap in WinPcap-compatible mode"**)<br>2. Run console/shell as **Administrator**. |
| **Linux** | 1. `libpcap` development headers installed:<br>   `sudo apt install libpcap-dev libcap2-bin`<br>2. Run process with root permissions (`sudo`) OR grant capability to Python:<br>   `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))` |
| **macOS** | 1. `libpcap` is pre-installed.<br>2. Run process as `sudo`. |

---

## 3. Configuration & Secrets

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Generate secure secret keys:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
3. Populate `.env` keys:
   - `FLASK_SECRET_KEY`: (Injected above)
   - `JWT_SECRET`: (Injected above)
   - `REQUIRE_AUTH`: Set to `true` if exposing the dashboard to the public web.
   - `TELEGRAM_BOT_TOKEN`: Create a bot via `@BotFather` on Telegram.
   - `TELEGRAM_CHAT_ID`: Get your ID via `@userinfobot` on Telegram.
   - `WEBHOOK_URL`: (Optional) Discord or Slack webhook URL.

---

## 4. Run Options

### Option A: Local Bare-Metal (Recommended for Raspberry Pi / local VM)
1. Install production dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the NIDS:
   ```bash
   # Windows (Elevated PowerShell/CMD)
   python main.py --confirm-owner

   # Linux / macOS
   sudo python main.py --confirm-owner
   ```

### Option B: Docker Container
Live packet capture in Docker requires the host network adapter and root packet capability.

1. Build the release container:
   ```bash
   make docker-build
   ```
2. Run with Compose on host network mode (uncomment `network_mode: host` and `cap_add` in [docker-compose.yml](file:///E:/network%20scanner%20ag/docker/docker-compose.yml)):
   ```bash
   make docker-up
   ```

---

## 5. Security & Maintenance Checklist

- [ ] **Database Backup**: Schedule backups for `nids.db`. It contains local network data, device profiles, and security history.
- [ ] **Retention Sweep**: Keep `TRAFFIC_RETENTION_DAYS=7` to prevent SQLite storage bloat.
- [ ] **HTTPS Certificates**: If exposing the dashboard, configure a reverse proxy (e.g. Nginx or Caddy) with Let's Encrypt certificates to encrypt HTTP traffic.
- [ ] **Structured Logs**: Set `LOG_FORMAT=json` if pushing application logs to a syslog collector or log analyzer.
