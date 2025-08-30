# Tech Stack: Cybersecurity IPDR Mapping & Anomaly Detection

## Backend
- **Language:** Python 3.9+
- **Framework:** FastAPI (REST API)
- **Data Processing:** Pandas, NetworkX
- **Database:** SQLite (with abstraction for future Postgres)
- **Enrichment:** GeoIP (ip-api.com), AbuseIPDB (threat intelligence)
- **Other:** Uvicorn (ASGI server)

## Frontend
- **Framework:** Streamlit (Python)
- **Visualization:** PyVis (interactive network graph), Plotly (optional)
- **HTTP:** requests

## DevOps & Tooling
- **Environment:** venv/virtualenv
- **Testing:** pytest (unit tests)
- **Packaging:** requirements.txt
- **Other:** Docker-ready structure (optional)

## Integration
- **Real-time ingestion:** /stream/ endpoint (JSON, batch/single)
- **RESTful API:** Modular endpoints for upload, analyze, enrich, stream, connections

## Optional/Planned
- **AbuseIPDB API key** for threat enrichment
- **GeoIP enrichment** for anomaly context
- **Export:** CSV, HTML (graph), PDF (planned)

---
This stack is designed for extensibility, hackathon-readiness, and rapid prototyping in cybersecurity analytics.
