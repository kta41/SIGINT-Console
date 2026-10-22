<div align="center">

# 🛰️ SIGINT-Console
> **Central Wireless Intelligence, Correlation & Audit Hub for ESP32-S3 Sensor Nodes**

<p align="center">
  <img alt="Python 3.13" src="https://img.shields.io/badge/Python-3.13-blue?style=flat-square&logo=python">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker">
  <img alt="IEEE OUI" src="https://img.shields.io/badge/IEEE_OUI_DB-40%2C355_Prefixes-10b981?style=flat-square">
  <img alt="Sensors" src="https://img.shields.io/badge/Sensors-ESP32_Projects-orange?style=flat-square&logo=espressif">
</p>

</div>

---

**SIGINT-Console** is the centralized wireless intelligence, multi-session correlation, and spectrum-auditing web platform built as the **analysis brain** for the hardware sensors in [**kta41/ESP32_projects**](https://github.com/kta41/ESP32_projects):

| Hardware Sensor (`ESP32_projects`) | Status | Ingested Telemetry |
| :--- | :--- | :--- |
| [**`Wifi-Wardriving`**](https://github.com/kta41/ESP32_projects/tree/main/Wifi-Wardriving) | ✅ **Active** | Passive 802.11 channel sweeps + simultaneous promiscuous sniffing (`MGMT`/`DATA`), associated client stations (`ToDS`/`FromDS`), Probe Request PNLs, and `Deauth`/`Disassoc` frame counters. |
| [**`BLE-Recon`**](https://github.com/kta41/ESP32_projects/tree/main/BLE-Recon) | 🔜 *Planned* | Bluetooth Low Energy beacons (iBeacon, Eddystone, Apple FindMy / AirTag) and cross-protocol temporal correlation with Wi-Fi clients. |
| [**`ESP32-RF-Lab`**](https://github.com/kta41/ESP32_projects/tree/main/ESP32-RF-Lab) | 🔜 *Planned* | 2.4 GHz / Sub-GHz spectrum occupancy and physical-layer link metrics. |

---

## 🧠 Intelligence Capabilities

1. **Executive Summary & RF Exposure Posture Score (`0–100`)**:
   - Automated assessment of legacy/weak encryption (`OPEN`, `WEP`, `WPA1`, `TKIP` — *Beck-Tews / ChopChop*), exposed **WPS** (*Pixie-Dust / brute-force PIN*), hidden networks (*SSID Cloaking*), and Multi-BSSID collisions / potential *Evil Twins*.
2. **Network & Infrastructure Dossiers (`BSSID` / `SSID` Clusters)**:
   - One-click **`⚠️ Insecure Networks`** filter with per-network vulnerability breakdowns and severity ratings (`CRITICAL`, `HIGH`, `MEDIUM`, `INFO`).
   - Correlates which client stations are actively exchanging frames on each AP and which nearby devices are probing for that SSID.
3. **Client Device Intelligence (`STA MAC` & PNL Fingerprinting)**:
   - Links every client station to the APs it associates with and the list of networks it searches for via *Probe Requests* (highlighting whether a probed SSID is physically present in the audited environment or a remote profile).
4. **Complete IEEE OUI Database (`40,355` prefixes, Spain + Global)**:
   - Offline vendor resolution covering major mobile brands (`Apple`, `Samsung`, `Xiaomi/Redmi/POCO`, `Huawei`, `Honor`, `OPPO`, `realme`, `OnePlus`, `Google Pixel`, `Motorola`), ISP CPE routers (`Arcadyan`, `MitraStar`, `Askey`, `Sagemcom`, `Sercomm`, `ZTE`, `TP-Link`, `Mercusys`), and IoT hardware (`Espressif`, `Tuya`, `Amazon`, `Shelly`).
   - Automatic unmasking of **virtual BSSIDs** (locally-administered bit flipped over a registered IEEE OUI) vs. **randomized privacy MACs (iOS/Android)**.
5. **Cross-Session Persistence Tracking**:
   - Highlights client devices (`STA MAC`) and access points (`BSSID`) observed across multiple independent capture sessions.
6. **Session Management, Session-Level GPS & Persistent Entity Tagging (`tags.json`)**:
   - Assign custom names and GPS coordinates (`lat, lon`) to capture sessions, and tag devices or networks (`PROPIO`, `CONOCIDO`, `OBJETIVO`, `SOSPECHOSO`, `IGNORAR`) with one-click reset to default identifiers.
   - When running via Docker/HTTP, all tag edits are automatically persisted to `/data/tags.json` via `POST /api/tags`.

---

## 🐳 Quick Start with Docker

```bash
git clone https://github.com/kta41/SIGINT-Console.git
cd SIGINT-Console
docker compose up -d --build
```

Open in your browser:
- **`http://127.0.0.1:8080`** (or **`http://192.168.1.142:8080`** on LAN — using `127.0.0.1` instead of `localhost` avoids browser HSTS / forced-HTTPS certificate errors).

### Importing `.jsonl` Captures

1. **Directly from the Web UI (`http://127.0.0.1:8080`)**:
   - Click **`📥 Importar .JSONL al Servidor`** in the top bar and select one or more `wardrive_*.jsonl` files (or import a `tags.json` file).
2. **Dropping files into `./data/`**:
   - Any `.jsonl` file placed in `./data/` is automatically parsed and correlated on page reload (automatically synced when running `warpull` from `ESP32_projects/Wifi-Wardriving`).
3. **Via HTTP API (`curl` or direct sensor push)**:
   ```bash
   curl -X POST "http://127.0.0.1:8080/api/import?filename=audit_session.jsonl" \
        -H "Content-Type: application/x-ndjson" \
        --data-binary @wardrive_20261020_1313.jsonl
   ```

---

## 🔌 HTTP API Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Live SIGINT Web Console rendered from all `.jsonl` files in `/data`. |
| `GET` | `/api/dataset` | Full correlated intelligence dataset in JSON format. |
| `GET` | `/api/handshakes` | **Handshake Center**: captured EAPOL M1-M4 / PMKID material per BSSID merged with the evidence vault (`audit_status`, recovered `psk`). |
| `GET` | `/export/hc22000?bssid=XX:XX:XX:XX:XX:XX` | Downloads hashcat `22000` hashes — globally or filtered to a single BSSID. |
| `GET` | `/api/tags` | Returns active entity tags (`sessions`, `networks`, `devices`). |
| `POST` | `/api/tags` | Persists tag/alias/session GPS changes directly to `/data/tags.json`. |
| `POST` | `/api/import` | Validates and imports JSONL v1 lines into `/data/`. |
| `POST` | `/scans` | Native ESP32-S3 batch push endpoint compatible with `Wifi-Wardriving`. |
| `GET` | `/export/csv` | Downloads the deduplicated BSSID catalog as CSV. |
| `GET` | `/export/wigle` | Downloads networks in official **WiGLE CSV v1.4** format. |
| `GET` | `/health` | Container health status and loaded file list. |

---

## 💻 Running Without Docker (Pure Python 3 Standard Library)

No third-party `pip` packages are required:

```bash
python3 app/server.py --host 0.0.0.0 --port 8080 --data ./data
```

Or as a standalone static report generator:

```bash
python3 app/engine.py ./data/wardrive_*.jsonl \
    --csv ./data/networks.csv \
    --wigle ./data/wigle.csv \
    --html ./data/dashboard.html
```

