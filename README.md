# AI Threat Detection

A local-first, offline-capable Network Security project. The complete application, embedded dashboard, database layer, detection rules, model and self-tests are in `app.py`. It performs passive packet inspection, accepts normalized authentication/application audit events, and investigates PCAP files locally. The built-in lab is telemetry-only: it does not transmit packets or attack a service.

## Requirements and installation

Python 3.11 is recommended. Install the same dependencies on Windows and Kali Linux:

```text
python -m pip install -r requirements.txt
```

### Windows 10/11

1. Install Python 3.11 (64-bit) and ensure the Python launcher is available.
2. Install [Npcap](https://npcap.com/) for packet capture. Enable WinPcap API-compatible mode if offered. Live capture may require running the terminal as Administrator.
3. In PowerShell, from the project directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

If PowerShell script execution is restricted, use `.\.venv\Scripts\python.exe` directly instead of activating the environment.

### Kali Linux

Install Python 3.11, venv support, and packet-capture prerequisites from Kali's configured package repositories:

```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip libpcap-dev
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

If the Kali release does not provide `python3.11`, use an approved Python 3.11 installation; the application itself does not install system packages. Live packet capture usually needs root or `CAP_NET_RAW`/`CAP_NET_ADMIN`. Prefer running the application as an authorized user with narrowly scoped capture permissions rather than running the entire dashboard as root. PCAP analysis and the offline lab do not require live-capture permissions.

## First launch and LAN use

Start with `python app.py`. The dashboard binds to `127.0.0.1:5000` by default. On first run it generates a random password, prints it in the terminal, and stores it in `~/.aithreat/initial-password.txt` (permissions are restricted where supported). Set `AITHREAT_PASSWORD` to provide a password instead. Set `AITHREAT_SECRET_KEY` to a persistent random secret if sessions must survive application restarts. Data, SQLite database and locally trained model are stored in `~/.aithreat`; override paths with `AITHREAT_HOME`, `AITHREAT_DB`, or `AITHREAT_MODEL`.

LAN use is opt-in. Use `python app.py --host lan` to bind all interfaces, or `python app.py --host auto` to bind the OS-selected private IPv4 address. The authenticated dashboard rejects clients outside loopback and RFC1918 IPv4 ranges. Use only on a trusted private lab network, configure a strong `AITHREAT_PASSWORD`, and limit access with the host firewall. The app does not configure firewall rules or provide TLS; do not expose it directly to the public internet.

The primary IPv4 display is selected from the active default route without testing internet connectivity. Link-local and loopback addresses are excluded. The Scapy interface matching that address is preferred for capture; choose another enumerated interface in **Settings** for a private offline lab. If packet-capture drivers are unavailable, the dashboard remains usable for local audit ingestion, PCAP inspection (if Scapy is installed), and simulated lab scenarios.

## Demonstration

1. Run `python app.py`, sign in with the first-run password, and open **Detection lab**.
2. Run any scenario card. It creates a clearly labeled `simulated` incident record through the relevant detection logic. Scenarios cover port scan, SYN flood, DoS/DDoS indicators, brute-force audit failures, explicit unauthorized-access audit event, ARP mapping conflict, suspicious DNS, possible DNS tunneling, SQL injection signature, XSS signature, abnormal flow, and suspicious connection pattern. These are fixtures only; no traffic is sent.
3. Open an incident to inspect its observed fixture, score components, model contribution, rule reasoning, mitigation, MITRE reference and timeline. Mark an incident **false positive** to exclude it from active totals; status can be restored.
4. For real authentication observations, integrate an authorized local test service or audit-log collector and POST normalized JSON to `/api/logs` from an authenticated session. Event types are `auth` (`outcome` such as `failure`, with `service`, optional `username`/`src_ip`) and `http` (`request`, optional IPs/ports). The dashboard does not perform login attempts.
5. To inspect packets, select the authorized adapter under **Settings** and start passive capture, or upload a local `.pcap`/`.pcapng` under **Detection lab**. PCAP analysis is bounded to 24 MiB and 100,000 packets, runs offline, and does not replay packets onto a network.
6. Export retained incidents from the CSV or HTML report buttons. The reports include simulated records with their source label.

Run the built-in backend tests:

```text
python app.py --self-test
```

They exercise training/inference, SQLi/XSS rules, authentication rules, database persistence/correlation, status management, filters, settings validation, lab API and report routes. They create local test records in the configured database.

## Detection and model notes

Separate rules inspect rolling packet windows for port breadth, SYN-only volume, destination volume across sources, ARP IP-to-MAC changes, DNS label length/entropy and HTTP payload signatures. Authentication attacks are detected only from supplied audit records. Unauthorized access requires an explicit `unauthorized=true` marker. The generic anomaly alert is limited to an Isolation Forest result beyond its synthetic-normal calibration cut-off and does not rely on the Random Forest class alone.

The hybrid engine trains an Isolation Forest and Random Forest from deterministic **synthetic** feature examples on first launch, saves them locally, and reports metrics computed on a separate synthetic labeled holdout set. The model inspector identifies the data source and exposes the confusion matrix, macro precision/recall/F1 and benign false-positive rate. These metrics are not a claim of field performance. No evaluation uses real labeled captured data unless the project is extended to provide such a dataset.

Risk score (0–100) is an operational score, not a probability: rule severity (up to 45) + repeated frequency (up to 20) + persistence (up to 15) + model anomaly contribution (up to 20), capped at 100. Severity bands: low 0–24, medium 25–49, high 50–74, critical 75–100. Scores and model evidence are informational and should be corroborated before response.

## Troubleshooting and limitations

- **Cannot import a package:** activate the project virtual environment and run `python -m pip install -r requirements.txt`.
- **Live capture reports access denied/no adapters:** install Npcap on Windows; use an authorized interface and appropriate capture permissions on Kali. Live capture can fail gracefully; it is not required for offline testing.
- **No current IP is shown:** confirm that the operating system has an active IPv4 route and adapter address. A disconnected adapter, loopback, and `169.254.x.x` link-local address are not selected.
- **A rule did not trigger:** thresholds are configurable in Settings. Scan and flood rules require repeated packet evidence inside a rolling time window; normal individual connections are not treated as an attack. Encrypted HTTPS payload content is not inspected.
- **SQLi/XSS not visible in packets:** encrypted application payloads cannot be signature-inspected. Supply authorized application audit/request logs to `/api/logs`; logs should be normalized and protected by the caller.
- **Brute-force/unauthorized access not detected:** packet capture alone cannot establish authentication outcome. Send actual authentication audit events; one failure does not meet the repeated-failure threshold.
- **DNS tunneling results are heuristic:** long/high-entropy labels can have legitimate uses; validate resolver, endpoint and domain context.
- **Potential alert gaps:** thresholds are educational baselines, not a substitute for calibrated production monitoring. NAT, asymmetric routing, packet loss, IPv6 flow features, encrypted protocols, OS-specific capture behavior and missing audit sources can reduce visibility. ARP mapping alerts require the application to observe an earlier binding. Captures contain sensitive data; handle and retain them according to local policy.
- **Privacy and safety:** records, model, password file and uploaded PCAP processing are local. The app does not call external services. Use only on networks and data you are authorized to monitor.
