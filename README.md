# My Network Guard 🛡️

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Render-brightgreen?style=for-the-badge)](https://my-network-guard.onrender.com)

A lightweight, high-performance Network Intrusion Detection System (NIDS) built with Python, Scapy, and SQLite. It passively sniffs local network interfaces using Berkeley Packet Filters (BPF), aggregates flow logs, constructs hardware profiles, detects anomalous signatures, and dispatches real-time alerts (via Discord/Slack webhooks) and a local loopback Flask dashboard.

---

## Key Features

1. **Passive Sniffing**: Uses Scapy with BPF filters (`ip or arp`) to sniff network links without modifying data packages.
2. **Deterministic Heuristic Detection**:
   - **New Device Discovery** (Medium Severity): Alerts instantly when a new MAC address is detected.
   - **Out-of-Hours Activity** (High Severity): Alerts when configured IoT appliances exceed 50 packets/min to external WANs between 1:00 AM and 5:00 AM local time.
   - **DNS Tunneling** (High Severity): Detects subdomains exceeding 60 characters or demonstrating a Shannon Entropy score greater than $H = 4.5$ bits.
3. **Database Concurrency**: Employs SQLite in **Write-Ahead Logging (WAL)** mode, combining it with an isolated write-queue worker thread to eliminate `database is locked` occurrences under heavy packet loads.
4. **Interactive Dashboard**: Locked to loopback (`127.0.0.1:5000`) for data privacy, featuring dynamic tables, sorting, alert resolution, dynamic simulation toggling, and data purging.
5. **Cross-Platform Compatibility**: Automatically falls back to a high-fidelity **Simulation Mode** if elevated capture permissions or packet capture drivers are missing, making it fully functional on Windows, Linux, and standard web servers.

---

## Project Structure

- `main.py`: Core system runner and thread manager.
- `database.py`: Thread-safe SQLite WAL schemas and serialization engine.
- `sniffer.py`: Scapy packet capture socket and mock simulation packet generator.
- `evaluator.py`: Intrusion evaluation thread running detection heuristics.
- `notifier.py`: Outbound notification client (Discord rich embeds support).
- `app.py`: Flask REST API routes and dashboard backend.
- `templates/index.html`: Dashboard template layout.
- `static/style.css`: Premium dark-theme styling.
- `static/app.js`: Interactive frontend logic.
- `config.json`: Persistent settings file (updated dynamically).
- `requirements.txt`: Python package dependencies.
- `tests/test_heuristics.py`: Unit tests for heuristics.

---

## Installation & Setup

### 1. Prerequisites
- **Python**: Version 3.8 or higher is recommended.
- **Packet Capture Drivers (For Live Capture)**:
  - **Windows**: Install [Npcap](https://npcap.com/) (select "Install Npcap in WinPcap API-compatible Mode" during installation).
  - **Linux**: Install libpcap (`sudo apt-get install libpcap-dev` on Debian/Ubuntu).

### 2. Install Dependencies
Run the following command to install the required Python packages:
```bash
pip install -r requirements.txt
```

---

## How to Run

### Run with Simulation Mode (Safe for standard VPS or non-root accounts)
To run with simulated traffic to immediately test anomalies and inspect dashboard layouts:
```bash
python main.py --simulation
```

### Run Live Capture (Requires Elevated Privileges)
- **Windows** (Run command prompt or terminal as **Administrator**):
  ```cmd
  python main.py
  ```
- **Linux** (Run with `sudo` to bind capture socket):
  ```bash
  sudo python main.py
  ```

### CLI Command Options
```bash
python main.py --help
```
- `-i`, `--interface`: Specify a network interface (e.g. `eth0`, `wlan0`, or device UUID on Windows).
- `-s`, `--simulation`: Force simulation mode immediately.
- `-p`, `--port`: Port for the Flask web server (default is `5000`).
- `--db`: SQLite database file path (default is `nids.db`).

---

## Webhook Configuration

1. In the Web UI control panel, enter your Discord/Slack Webhook URL into the **Webhook Dispatcher** input.
2. Click **Save Webhook**.
3. Click **Test Notify** to send a test alert.
   - For Discord, this will dispatch a formatted color-coded embed message showing active severities.
