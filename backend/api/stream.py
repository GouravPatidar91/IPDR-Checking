from fastapi import APIRouter, Request, HTTPException
from backend.core.parser import parse_ipdr_csv
from backend.core.anomaly import detect_anomalies
from backend.db import insert_logs
import pandas as pd
import io

router = APIRouter()

@router.post("/stream/")
async def stream_ipdr(request: Request):
    try:
        data = await request.json()
        # Accept single dict or list of dicts
        if isinstance(data, dict):
            records = [data]
        elif isinstance(data, list):
            records = data
        else:
            raise HTTPException(status_code=400, detail="Invalid JSON format")
        df = pd.DataFrame(records)
        # Normalize and validate columns
        df.columns = [c.strip().lower() for c in df.columns]
        required = {'a_party','b_party','port','protocol','timestamp'}
        if not required.issubset(df.columns):
            raise HTTPException(status_code=400, detail=f"Missing columns: {required - set(df.columns)}")
        insert_logs(df)
        anomalies = detect_anomalies(df)
        return {"rows": len(df), "anomalies": anomalies}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Stream error: {e}")
