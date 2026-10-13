![banner](docs/banner.png)

## Architecture

![architecture](docs/architecture.png)

## Demo

![demo](docs/demo.png)

# SSRFNest

> 🇪🇸 Read this in [Spanish](README.md).

SSRFNest is a self-contained, Dockerized lab designed to practice detection and defense of **Server-Side Request Forgery (SSRF)** from a Blue Team perspective. It includes a deliberately vulnerable Flask app, an Nginx reverse proxy, simulated internal services (metadata and admin panel), and Suricata 7 acting as IDS with custom rules. A Python detector correlates Suricata alerts and produces a structured report.

## Ethical Warning

This project is **for educational purposes only**. It contains intentionally vulnerable code and simulated sensitive data. **Never expose this lab to the Internet** or use it outside an isolated environment. The authors are not responsible for any misuse.

## Architecture

Five Docker services orchestrated with Docker Compose:

1. **vulnapp** – Flask app with `/fetch?url=` endpoint that performs HTTP requests without validation (SSRF).
2. **nginx** – Reverse proxy on port 8080 that exposes vulnapp and mirrors traffic to Suricata.
3. **metadata** – Simulated metadata service (AWS IMDSv1 style) on port 9000, returns fake sensitive data.
4. **adminpanel** – Internal admin panel on port 9001, reachable only from the internal Docker network.
5. **suricata** – Suricata 7 in IDS mode with custom rules to detect SSRF patterns (RFC-1918, loopback, `/meta-data/`, `/admin`).

Flow: attacker → Nginx → vulnapp → internal services, while Suricata captures and alerts in parallel. The `ssrf_detector.py` script reads Suricata's `eve.json`, filters `alert` events, enriches them, and generates a JSON report plus rich terminal output.

## Prerequisites

- Docker 24+ and Docker Compose v2
- Python 3.11+ (for running the detector and attack script outside containers)
- `pip install -r requirements.txt`

## Installation

```bash
git clone https://github.com/javiergarrido/ssrfnest.git
cd ssrfnest
docker compose up --build
```

The lab will be available at:

- Vulnerable app via Nginx: `http://localhost:8080`
- Metadata service (internal): `http://metadata:9000`
- Admin panel (internal): `http://adminpanel:9001`

## Usage Examples

### Run the attack demo

```bash
python scripts/attack_demo.py --target http://localhost:8080
```

This sends a battery of SSRF payloads to populate Suricata logs.

### Inspect Suricata logs

```bash
docker compose exec suricata tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

### Run the detector

```bash
python src/ssrf_detector.py --eve-file /var/log/suricata/eve.json --output report.json
```

Produces a JSON report with correlated alerts and prints a rich summary to the terminal.

## Endpoints

| Service     | Endpoint              | Method | Description                              |
|-------------|-----------------------|--------|------------------------------------------|
| vulnapp     | `/fetch?url=`         | GET    | Fetches a URL without validation (SSRF)  |
| metadata    | `/latest/meta-data/`  | GET    | Returns fake AWS-style metadata          |
| adminpanel  | `/admin`              | GET    | Internal admin panel (network-restricted)|

## MITRE ATT&CK Mapping

- **T1190** – Exploit Public-Facing Application
- **T1071** – Application Layer Protocol
- **T1552.005** – Unsecured Credentials: Cloud Instance Metadata API
- **T1046** – Network Service Discovery (via SSRF)

## Suricata Rules Explanation

The custom rules in `suricata/rules/ssrf.rules` detect:

- Requests to RFC-1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Requests to loopback (127.0.0.0/8)
- Requests containing `/meta-data/` or `/admin` paths
- Requests with suspicious URL parameters (`url=`, `target=`, `dest=`)

Each rule generates an alert in `eve.json` with severity and HTTP metadata.

## Cleanup

```bash
docker compose down -v
```

Removes containers, networks, and volumes.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
