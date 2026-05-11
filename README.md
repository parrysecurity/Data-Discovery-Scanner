# 🔍 Parry Scanner - Enterprise Data Discovery Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.0-green.svg)](https://fastapi.tiangolo.com/)
[![Frontend](https://img.shields.io/badge/frontend-HTML5/CSS3-orange.svg)](https://developer.mozilla.org/en-US/docs/Web/HTML)
[![GitHub stars](https://img.shields.io/github/stars/parrysecurity/Data-Discovery-Scanner.svg)](https://github.com/parrysecurity/Data-Discovery-Scanner/stargazers)

> **Professional sensitive data discovery tool that scans files for PII, credentials, API keys, and generates compliance-ready reports.**

[Live Demo](#) | [Report Bug](https://github.com/parrysecurity/Data-Discovery-Scanner/issues) | [Request Feature](https://github.com/parrysecurity/Data-Discovery-Scanner/issues)

---

## 📋 Table of Contents

- [✨ Features](#-features)
- [🎯 What It Detects](#-what-it-detects)
- [🖥️ Dashboard Preview](#️-dashboard-preview)
- [🚀 Quick Start](#-quick-start)
- [📦 Installation](#-installation)
  - [Ubuntu/Debian Setup](#ubuntudebian-setup)
  - [Docker Setup](#docker-setup)
  - [Manual Setup](#manual-setup)
- [🔧 Configuration](#-configuration)
- [📊 API Endpoints](#-api-endpoints)
- [📁 Project Structure](#-project-structure)
- [🛡️ Security Features](#️-security-features)
- [📈 Risk Scoring](#-risk-scoring)
- [📝 Usage Guide](#-usage-guide)
- [📸 Screenshots](#-screenshots)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📊 **Interactive Dashboard** | Real-time analytics with charts, heatmaps, and trend visualization |
| 🔍 **Multi-Format Scanning** | Supports TXT, CSV, JSON, LOG, PDF, XLSX files |
| 🎯 **Sensitive Data Detection** | PII, credit cards, SSN, API keys, passwords, IPs, phone numbers |
| 📈 **Risk Scoring System** | AI-powered risk assessment with context analysis |
| 🎨 **Modern UI** | Clean light-themed interface with responsive design |
| 📋 **Export Reports** | CSV, JSON, and clipboard copy functionality |
| 📱 **Mobile Responsive** | Works perfectly on all devices |
| 🐳 **Docker Support** | Easy deployment with Docker Compose |
| 🔒 **Privacy First** | All scanning happens locally - no data leaves your server |

---

## 🎯 What It Detects

| Data Type | Pattern | Risk Level | Examples |
|-----------|---------|------------|----------|
| 📧 **Email Addresses** | `user@domain.com` | Low | john.doe@gmail.com |
| 💳 **Credit Cards** | Visa, Mastercard, Amex, Discover | Critical | 4111-1111-1111-1111 |
| 🆔 **SSN** | `XXX-XX-XXXX` | High | 123-45-6789 |
| 🔑 **API Keys** | Google, AWS, Stripe, GitHub | Critical | AIzaSyA1B2C3D4E5F6 |
| 🌐 **IP Addresses** | IPv4 format | Medium | 192.168.1.1 |
| 📱 **Phone Numbers** | US/International formats | Medium | (555) 123-4567 |
| 🔒 **Passwords** | Plaintext credentials | Critical | password=secret123 |
| 🔌 **Connection Strings** | Database URLs | Critical | postgresql://user:pass@localhost |

---

## 🖥️ Dashboard Preview
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🔍 Parry Scanner 🟢 Connected │
├─────────────────────────────────────────────────────────────────────────────┤
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│ │ Total Scans │ │Total Findings│ │ Avg Risk │ │ Critical │ │
│ │ 247 │ │ 1,892 │ │ 42 │ │ 23 │ │
│ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ │
│ │
│ ┌─────────────────────────┐ ┌─────────────────────────┐ │
│ │ 📈 Scan Activity │ │ 🥧 Risk Distribution │ │
│ │ (30 Days) │ │ │ │
│ │ ╱╲ │ │ ● Low 45% │ │
│ │ ╱ ╲ │ │ ● Medium 28% │ │
│ │ ╱ ╲ │ │ ● High 15% │ │
│ │ ╱ ╲ │ │ ● Critical 12% │ │
│ └─────────────────────────┘ └─────────────────────────┘ │
│ │
│ ┌─────────────────────────┐ ┌─────────────────────────┐ │
│ │ 🔥 Activity Heatmap │ │ 📊 Top Data Types │ │
│ │ ████░░░░████░░░░ │ │ ████████ Email 156 │ │
│ │ ██░░████░░░░████ │ │ ██████ Credit 89 │ │
│ │ ████░░░░██████░░ │ │ ████ API Keys 67 │ │
│ └─────────────────────────┘ └─────────────────────────┘ │
│ │
│ 📋 Recent Scans │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ customer_data.csv │ 2024-01-15 │ 23 finds │ 78 ⚠️ │ View Details │ │
│ │ api_keys.json │ 2024-01-14 │ 45 finds │ 92 🔴 │ View Details │ │
│ │ employee_records.xlsx │ 2024-01-13 │ 12 finds │ 34 🟢 │ View Details │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘


---

## 🚀 Quick Start

### One-Line Deployment (Ubuntu/Debian)

```bash
git clone https://github.com/parrysecurity/Data-Discovery-Scanner.git
cd Data-Discovery-Scanner
sudo bash install.sh  # Coming soon
**Docker (Fastest)**
# Clone and run with Docker Compose
git clone https://github.com/parrysecurity/Data-Discovery-Scanner.git
cd Data-Discovery-Scanner
docker-compose up -d

# Access at http://localhost:3000
# API at http://localhost:8000
📦 Installation
Ubuntu/Debian Setup
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install dependencies
sudo apt install -y python3.11 python3-pip nginx git

# 3. Clone repository
git clone https://github.com/parrysecurity/Data-Discovery-Scanner.git
cd Data-Discovery-Scanner

# 4. Setup backend
cd backend
pip3 install -r requirements.txt

# 5. Start backend
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload

# 6. In another terminal, serve frontend
cd ../frontend
python3 -m http.server 3000

# 7. Open browser
# Frontend: http://localhost:3000
# API: http://localhost:8000
Docker Setup
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
docker-compose up -d
**Manual Setup (From Scratch)**
# 1. Create directory
sudo mkdir -p /var/www/sensitive-data-scanner
cd /var/www/sensitive-data-scanner

# 2. Clone repository
sudo git clone https://github.com/parrysecurity/Data-Discovery-Scanner.git .

# 3. Setup Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt

# 4. Create data directories
mkdir -p data uploads
chmod 755 data uploads

# 5. Start backend
cd backend
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000

# 6. Configure Nginx (optional)
sudo cp nginx.conf /etc/nginx/sites-available/scanner
sudo ln -s /etc/nginx/sites-available/scanner /etc/nginx/sites-enabled/
sudo systemctl restart nginx
 **Configuration**
Environment Variables
Create .env file in root directory:
# Database
DATABASE_PATH=/var/www/sensitive-data-scanner/data/scanner.db

# API Settings
API_HOST=0.0.0.0
API_PORT=8000

# Security
MAX_FILE_SIZE=52428800  # 50MB
ALLOWED_EXTENSIONS=txt,csv,json,log,pdf,xlsx

# Rate Limiting
RATE_LIMIT=100  # requests per minute
**Custom Detection Patterns**
Add custom regex patterns in backend/patterns.py:
CUSTOM_PATTERNS = {
    'custom_id': {
        'regex': r'CUST-[0-9]{8}',
        'risk': 'medium',
        'score': 5,
        'name': 'Customer ID'
    }
}
📊 API Endpoints
Method	Endpoint	Description
GET	/	API health check
GET	/api/dashboard	Dashboard statistics
POST	/api/upload	Upload and scan file
GET	/api/scans	List all scans
GET	/api/scan/{id}	Get specific scan
DELETE	/api/scan/{id}	Delete scan
GET	/api/report/{id}/csv	Export as CSV
Example API Usage

# Upload and scan a file
curl -X POST http://localhost:8000/api/upload \
  -F "file=@/path/to/file.txt"

# Get all scans
curl http://localhost:8000/api/scans

# Export scan as CSV
curl http://localhost:8000/api/report/1/csv > report.csv
🛡️ Security Features
Feature	Description
🔒 Local Processing	Files never leave your server
🎭 Auto-Redaction	Sensitive values masked in UI
📝 Audit Logging	Complete scan history
🚫 File Validation	Whitelist of allowed extensions
📏 Size Limits	Maximum 50MB per file
🔐 No External Calls	All processing offline
🧹 Auto-Cleanup	Temporary files deleted after scan
📈 Risk Scoring
Risk scores are calculated based on:

text
Risk Score = (Sum of finding scores) / (File size in KB) × 10
Score Range	Risk Level	Action Required
0 - 25	🟢 Low	Monitor
25 - 50	🟡 Medium	Review
50 - 75	🟠 High	Investigate
75 - 100	🔴 Critical	Immediate action
📝 Usage Guide
1. Upload Files
Click or drag & drop files into upload zone

Supports multiple files simultaneously

Maximum 50MB per file

2. Review Results
View risk score for each file

Click on findings to see context

Filter by risk level or data type

3. Export Reports
Select a scan from history

Export as CSV or JSON

Copy summary to clipboard

4. Monitor Dashboard
View real-time statistics

Analyze risk distribution

Track scan trends over time

🤝 Contributing
We welcome contributions!

bash
# 1. Fork the repository
# 2. Create your feature branch
git checkout -b feature/amazing-feature

# 3. Commit your changes
git commit -m 'Add some amazing feature'

# 4. Push to branch
git push origin feature/amazing-feature

# 5. Open a Pull Request
Development Setup
bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linter
flake8 backend/

# Format code
black backend/
📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

text
MIT License

Copyright (c) 2024 ParrySecurity

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...
🙏 Acknowledgments
FastAPI - Modern web framework for APIs

Chart.js - Beautiful charts and visualizations

FontAwesome - Professional icons

Google Fonts - Inter typeface

All Contributors - For testing and feedback

📞 Support
Channel	Link
📧 Email	alikhanuana@gmail.com
🐙 GitHub Issues	Create Issue
💬 Discord	Join Server
📖 Documentation	Wiki
