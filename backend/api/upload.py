from fastapi import APIRouter, UploadFile, File, HTTPException
import io, os
from backend.core.parser import parse_ipdr_csv, parse_ipdr_json
from backend.core.anomaly import detect_anomalies
from backend.enrichment.geoip import geoip_lookup
from backend.db import insert_logs

router = APIRouter()

@router.post("/upload/")
def upload_log(file: UploadFile = File(...)):
    ext = os.path.splitext(file.filename)[1].lower()
    file.file.seek(0)
    content = file.file.read()
    file.file.seek(0)
    try:
        if ext == '.csv':
            decoded = content.decode('utf-8')
            df = parse_ipdr_csv(io.StringIO(decoded))
        elif ext == '.json':
            df = parse_ipdr_json(io.BytesIO(content))
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"File parsing error: {e}")
    insert_logs(df)
    return {"rows": len(df)}

@router.post("/analyze/")
@router.post("/analyze/")
def analyze_log(file: UploadFile = File(...)):
    ext = os.path.splitext(file.filename)[1].lower()
    file.file.seek(0)
    content = file.file.read()
    file.file.seek(0)
    try:
        if ext == '.csv':
            decoded = content.decode('utf-8')
            df = parse_ipdr_csv(io.StringIO(decoded))
        elif ext == '.json':
            df = parse_ipdr_json(io.BytesIO(content))
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"File parsing error: {e}")
    anomalies = detect_anomalies(df)
    # Enrich each anomaly with GeoIP info for a_party and b_party (if present)
    for anomaly in anomalies:
        for party in ['a_party', 'b_party', 'ip']:
            if party in anomaly:
                anomaly[f'{party}_geoip'] = geoip_lookup(anomaly[party])
    return {"anomalies": anomalies}
