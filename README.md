<div align="center">

<br/>

```
██████╗  █████╗ ██████╗ ██████╗ ██╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝███████║██████╔╝██████╔╝ ╚████╔╝     ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═══╝ ██╔══██║██╔══██╗██╔══██╗  ╚██╔╝      ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ██║  ██║██║  ██║██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

**Enterprise Data Discovery Platform**

*PII detection · API key exposure · Credential scanning · Compliance-ready reporting*

<br/>

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.0-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Stars](https://img.shields.io/github/stars/parrysecurity/Data-Discovery-Scanner.svg?style=for-the-badge&logo=github&logoColor=white&color=f59e0b)](https://github.com/parrysecurity/Data-Discovery-Scanner/stargazers)

<br/>

> A **privacy-first, locally-executed** sensitive data discovery platform — scan files for PII, credentials, and API key exposure with an interactive dashboard and compliance-ready exports. No data ever leaves your server.

<br/>

[Live Demo](#) · [Report Bug](https://github.com/parrysecurity/Data-Discovery-Scanner/issues) · [Request Feature](https://github.com/parrysecurity/Data-Discovery-Scanner/issues) · [Documentation](#)

<br/>

---

</div>

<br/>

## ◈ Table of Contents

- [Overview](#-overview)
- [What It Detects](#-what-it-detects)
- [Features](#-features)
- [Dashboard Preview](#-dashboard-preview)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Risk Scoring](#-risk-scoring)
- [Security Model](#-security-model)
- [Usage Guide](#-usage-guide)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)

<br/>

---

## ◈ Overview

Parry Scanner is a **self-hosted, enterprise-grade** sensitive data discovery platform. It combines regex-based pattern matching with context-aware risk scoring to surface PII, credentials, and API key exposure across your file inventory — all processed locally with no external calls.

```
    Input File (TXT / CSV / JSON / LOG / PDF / XLSX)
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│               PARRY SCANNER ENGINE                  │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │   PII    │  │  Creds   │  │ API Keys │           │
│  │ Detector │  │ Detector │  │ Detector │           │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
│       └─────────────┴─────────────┘                 │
│                      │                              │
│           ┌──────────┴──────────┐                   │
│           │   Risk Score Engine │                   │
│           │  (context-weighted) │                   │
│           └──────────┬──────────┘                   │
│                      │                              │
│           ┌──────────┴──────────┐                   │
│           │    SQLite Storage   │                   │
│           └──────────┬──────────┘                   │
└──────────────────────┼──────────────────────────────┘
          │                       │
          ▼                       ▼
   FastAPI REST              HTML Dashboard
   (port 8000)               (port 3000)
```

<br/>

---

## ◈ What It Detects

Eight data categories with independently calibrated risk weights.

<br/>

| # | Data Type | Pattern | Risk Level | Example Match |
|---|-----------|---------|:----------:|---------------|
| 1 | **Email Addresses** | `user@domain.com` | Low | `john.doe@gmail.com` |
| 2 | **Credit Card Numbers** | Visa · Mastercard · Amex · Discover | Critical | `4111-1111-1111-1111` |
| 3 | **Social Security Numbers** | `XXX-XX-XXXX` | High | `123-45-6789` |
| 4 | **API Keys** | Google · AWS · Stripe · GitHub | Critical | `AIzaSyA1B2C3D4E5F6` |
| 5 | **IP Addresses** | IPv4 format | Medium | `192.168.1.1` |
| 6 | **Phone Numbers** | US & international formats | Medium | `(555) 123-4567` |
| 7 | **Plaintext Passwords** | Credential assignment patterns | Critical | `password=secret123` |
| 8 | **Database Connection Strings** | DSN / URL format | Critical | `postgresql://user:pass@host` |

<br/>

> **Custom patterns** can be added in `backend/patterns.py` — see [Configuration](#-configuration).

<br/>

---

## ◈ Features

| Category | Capability |
|----------|-----------|
| **Scanning** | Multi-format support: TXT, CSV, JSON, LOG, PDF, XLSX |
| **Detection** | 8 data categories with per-category risk calibration |
| **Reporting** | Export to CSV, JSON, or clipboard in one click |
| **Dashboard** | Real-time analytics — scan activity, risk distribution, heatmap, top finding types |
| **Privacy** | 100% local processing — no data leaves your server |
| **Security** | Extension whitelist, 50 MB file cap, auto-cleanup of temp files, audit log |
| **Deployment** | Docker Compose single-command deploy or manual Python/Nginx setup |
| **API** | Full REST API with OpenAPI docs at `/docs` |

<br/>

---

## ◈ Dashboard Preview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Parry Scanner                                             ● Connected      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Total Scans │  │  Findings   │  │  Avg Risk   │  │  Critical   │         │
│  │     247     │  │    1,892    │  │     42      │  │     23      │         │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                                             │
│  ┌──────────────────────────┐  ┌──────────────────────────┐                 │
│  │  Scan Activity (30 days) │  │    Risk Distribution     │                 │
│  │                          │  │                          │                 │
│  │     ╱╲                   │  │   ● Low        45%       │                 │
│  │    ╱  ╲      ╱╲          │  │   ● Medium     28%       │                 │
│  │   ╱    ╲    ╱  ╲         │  │   ● High       15%       │                 │
│  │  ╱      ╲__╱    ╲__      │  │   ● Critical   12%       │                 │
│  └──────────────────────────┘  └──────────────────────────┘                 │
│                                                                             │
│  ┌──────────────────────────┐  ┌──────────────────────────┐                 │
│  │    Activity Heatmap      │  │     Top Finding Types    │                 │
│  │  ████░░░░████░░░░████    │  │  ████████  Email   156   │                 │
│  │  ██░░████░░░░██████░░    │  │  ██████    Cards    89   │                 │
│  │  ░░████░░░░████░░░░██    │  │  ████      API Keys 67   │                 │
│  └──────────────────────────┘  └──────────────────────────┘                 │
│                                                                             │
│  Recent Scans                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  customer_data.csv     │  2024-01-15  │  23 findings  │  78  ⚠  View │   │
│  │  api_keys.json         │  2024-01-14  │  45 findings  │  92  ✕  View │   │
│  │  employee_records.xlsx │  2024-01-13  │  12 findings  │  34  ✓  View │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

<br/>

---

## ◈ Quick Start

### Docker *(recommended — single command)*

```bash
git clone https://github.com/parrysecurity/Data-Discovery-Scanner.git
cd Data-Discovery-Scanner
docker-compose up -d
```

| Service | URL |
|---------|-----|
| Dashboard | `http://localhost:3000` |
| API + Swagger docs | `http://localhost:8000/docs` |

<br/>

---

## ◈ Installation

### Option 1 — Docker Compose

```yaml
# docker-compose.yml (included in repo)
version: '3.8'

services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
    environment:
      - DATABASE_PATH=/app/data/scanner.db

  frontend:
    image: nginx:alpine
    ports:
      - "3000:80"
    volumes:
      - ./frontend:/usr/share/nginx/html
    depends_on:
      - backend
```

```bash
docker-compose up -d
```

<br/>

### Option 2 — Ubuntu / Debian (manual)

```bash
# 1. System dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.11 python3-pip nginx git

# 2. Clone repository
git clone https://github.com/parrysecurity/Data-Discovery-Scanner.git
cd Data-Discovery-Scanner

# 3. Backend
cd backend
pip3 install -r requirements.txt
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload

# 4. Frontend (new terminal)
cd ../frontend
python3 -m http.server 3000
```

<br/>

### Option 3 — Virtual environment (production)

```bash
# 1. Create directories
sudo mkdir -p /var/www/parry-scanner && cd /var/www/parry-scanner
sudo git clone https://github.com/parrysecurity/Data-Discovery-Scanner.git .

# 2. Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt

# 3. Data directories
mkdir -p data uploads
chmod 755 data uploads

# 4. Start backend
cd backend && python3 -m uvicorn app:app --host 0.0.0.0 --port 8000

# 5. Nginx (optional reverse proxy)
sudo cp nginx.conf /etc/nginx/sites-available/parry-scanner
sudo ln -s /etc/nginx/sites-available/parry-scanner /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

<br/>

---

## ◈ Configuration

### Environment variables

Create a `.env` file in the repo root:

```bash
# ── Database ─────────────────────────────────────────────
DATABASE_PATH=/var/www/parry-scanner/data/scanner.db

# ── API ──────────────────────────────────────────────────
API_HOST=0.0.0.0
API_PORT=8000

# ── Upload limits ─────────────────────────────────────────
MAX_FILE_SIZE=52428800          # 50 MB
ALLOWED_EXTENSIONS=txt,csv,json,log,pdf,xlsx

# ── Rate limiting ─────────────────────────────────────────
RATE_LIMIT=100                  # requests per minute
```

### Custom detection patterns

Add domain-specific patterns in `backend/patterns.py`:

```python
CUSTOM_PATTERNS = {
    'customer_id': {
        'regex': r'CUST-[0-9]{8}',
        'risk':  'medium',
        'score': 5,
        'name':  'Customer ID'
    },
    'internal_token': {
        'regex': r'tok_[a-zA-Z0-9]{32}',
        'risk':  'critical',
        'score': 20,
        'name':  'Internal Auth Token'
    }
}
```

<br/>

---

## ◈ API Reference

Full interactive documentation available at `http://localhost:8000/docs` (Swagger UI).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check |
| `GET` | `/api/dashboard` | Aggregate dashboard statistics |
| `POST` | `/api/upload` | Upload and scan a file |
| `GET` | `/api/scans` | List all scan records |
| `GET` | `/api/scan/{id}` | Retrieve a specific scan with findings |
| `DELETE` | `/api/scan/{id}` | Delete a scan record |
| `GET` | `/api/report/{id}/csv` | Export findings as CSV |

### Example requests

```bash
# Scan a file
curl -X POST http://localhost:8000/api/upload \
  -F "file=@customer_data.csv"

# List all scans
curl http://localhost:8000/api/scans

# Export findings
curl http://localhost:8000/api/report/1/csv > report.csv
```

<br/>

---

## ◈ Risk Scoring

Risk scores are computed per file using a normalized finding-density formula:

```
Risk Score = (Σ finding_scores) ÷ (file_size_KB) × 10
```

| Score Range | Level | Indicator | Recommended Action |
|:-----------:|-------|:---------:|--------------------|
| 0 – 25 | Low | 🟢 | Monitor — no immediate action |
| 25 – 50 | Medium | 🟡 | Review — assess data exposure |
| 50 – 75 | High | 🟠 | Investigate — notify data owner |
| 75 – 100 | Critical | 🔴 | Immediate remediation required |

Individual finding score weights:

| Finding Type | Score Weight |
|-------------|:------------:|
| Credit card, password, connection string, API key | 20 |
| SSN | 15 |
| Phone number, IP address | 5 |
| Email address | 3 |

<br/>

---

## ◈ Security Model

Parry Scanner is designed for **air-gapped or on-premise** deployment. The security posture is:

| Property | Implementation |
|----------|----------------|
| **Local-only processing** | Zero external HTTP calls during scanning |
| **Auto-redaction** | Sensitive values masked in UI display |
| **Audit trail** | Full scan history with timestamps |
| **Extension whitelist** | Only `txt csv json log pdf xlsx` accepted |
| **File size cap** | Hard 50 MB limit per upload |
| **Temp file cleanup** | Uploaded files deleted immediately post-scan |
| **No cloud storage** | All data persisted in local SQLite only |

<br/>

---

## ◈ Usage Guide

<details>
<summary><strong>Step 1 · Upload files</strong></summary>

<br/>

Click the upload zone or drag and drop files directly. Multiple files can be queued simultaneously. Each file is scanned independently — findings are stored per-file in the local database.

Supported: `TXT` `CSV` `JSON` `LOG` `PDF` `XLSX` · Maximum: 50 MB per file.

</details>

<details>
<summary><strong>Step 2 · Review findings</strong></summary>

<br/>

Each scan result shows a risk score, total finding count, and a breakdown by data type. Click any finding row to view the original context line with the sensitive value redacted. Filter findings by risk level or data category using the sidebar controls.

</details>

<details>
<summary><strong>Step 3 · Export reports</strong></summary>

<br/>

Select any scan from the history panel and export as CSV or JSON for compliance workflows. Use the clipboard button to copy a formatted summary for email or ticket submission.

</details>

<details>
<summary><strong>Step 4 · Monitor the dashboard</strong></summary>

<br/>

The dashboard auto-refreshes on load. It surfaces aggregate statistics (total scans, total findings, average risk, critical count), a 30-day scan activity trend, risk distribution pie chart, activity heatmap, and top finding types by volume.

</details>

<br/>

---

## ◈ Project Structure

```
Data-Discovery-Scanner/
│
├── backend/
│   ├── app.py                ← FastAPI application entry point
│   ├── patterns.py           ← Detection regex patterns + risk weights
│   ├── scanner.py            ← Core scanning engine
│   ├── database.py           ← SQLite ORM layer
│   └── requirements.txt      ← Python dependencies
│
├── frontend/
│   ├── index.html            ← Dashboard SPA
│   ├── app.js                ← Chart.js visualizations + API client
│   └── style.css             ← UI styles
│
├── data/                     ← SQLite database (auto-created)
├── uploads/                  ← Temp upload directory (auto-cleaned)
├── docker-compose.yml        ← Container orchestration
├── nginx.conf                ← Reverse proxy config (optional)
└── README.md
```

<br/>

---

## ◈ Contributing

Contributions are welcome — bug reports, feature requests, and pull requests.

```bash
# 1. Fork → clone → branch
git checkout -b feature/enf-batch-scanning

# 2. Install dev dependencies
pip install -r backend/requirements-dev.txt

# 3. Run tests
pytest tests/

# 4. Lint and format
flake8 backend/
black backend/

# 5. Open a PR with a clear description of what changed and why
```

<br/>

---

## ◈ License

Distributed under the **MIT License** — see [`LICENSE`](LICENSE) for full terms.

```
MIT License — Copyright (c) 2024 ParrySecurity
```

<br/>

---

## ◈ Support & Contact

| Channel | Link |
|---------|------|
| Email | alikhanuana@gmail.com
|       | ahmii.pk@hotmail.com
| GitHub Issues | [Create an issue](https://github.com/parrysecurity/Data-Discovery-Scanner/issues) |
| Documentation | [Project Wiki](https://github.com/parrysecurity/Data-Discovery-Scanner/wiki) |

<br/>

---

<div align="center">

Built with `FastAPI` · `SQLite` · `Chart.js` · `Nginx` · `Docker`

<br/>

*If Parry Scanner helped secure your data, consider leaving a ⭐ — it keeps the project alive.*

</div>
