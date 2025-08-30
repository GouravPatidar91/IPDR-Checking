from fastapi import APIRouter, Query
from backend.enrichment.geoip import geoip_lookup, abuseipdb_lookup

router = APIRouter()

@router.get("/geoip/")
def geoip(ip: str = Query(...)):
    return geoip_lookup(ip)

@router.get("/abuseipdb/")
def abuseipdb(ip: str = Query(...), api_key: str = Query(...)):
    return abuseipdb_lookup(ip, api_key)
