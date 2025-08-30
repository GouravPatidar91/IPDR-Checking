# Cybersecurity Tool: IPDR Log Mapping & Anomaly Detection

## Overview
This project parses IPDR logs, maps A-party ↔ B-party connections, detects suspicious patterns, and visualizes the network for analysts.

### Features
- Upload and parse IPDR logs (CSV/JSON)
- Map A ↔ B connections
- Anomaly detection (rule-based, ML-ready)
- Interactive network graph visualization
- Downloadable PDF/HTML reports
- REST API (FastAPI)
- Streamlit dashboard
- SQLite storage
- Unit tests & demo data

## Tech Stack

### Backend
- **Language:** Python 3.9+
- **Framework:** FastAPI (REST API)
- **Data Processing:** Pandas, NetworkX
- **Database:** SQLite (with abstraction for future Postgres)
- **Enrichment:** GeoIP (ip-api.com), AbuseIPDB (threat intelligence)
- **Other:** Uvicorn (ASGI server)

### Frontend
- **Framework:** Streamlit (Python)
- **Visualization:** PyVis (interactive network graph), Plotly (optional)
- **HTTP:** requests

### DevOps & Tooling
- **Environment:** venv/virtualenv
- **Testing:** pytest (unit tests)
- **Packaging:** requirements.txt
- **Other:** Docker-ready structure (optional)

### Integration
- **Real-time ingestion:** /stream/ endpoint (JSON, batch/single)
- **RESTful API:** Modular endpoints for upload, analyze, enrich, stream, connections

---

## Setup
1. Clone the repo
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run backend API:
   ```bash
   uvicorn backend.main:app --reload
   ```
4. Run Streamlit dashboard:
   ```bash
   streamlit run frontend/dashboard.py
   ```

## Folder Structure
- `backend/` - FastAPI backend, log parser, detection, DB
- `frontend/` - Streamlit dashboard
- `tests/` - Unit tests
- `data/` - Sample/demo data

## Demo
Sample IPDR log: `data/sample_ipdr.csv`

## Screenshots
![Dashboard Screenshot](screenshots/dashboard.png)

## License
MIT
