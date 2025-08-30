import requests

def geoip_lookup(ip: str) -> dict:
    # Use free API for demo (ip-api.com)
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}")
        if resp.status_code == 200:
            data = resp.json()
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "org": data.get("org"),
                "as": data.get("as"),
                "query": ip
            }
    except Exception:
        pass
    return {"query": ip, "error": "GeoIP lookup failed"}

def abuseipdb_lookup(ip: str, api_key: str) -> dict:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "ip": ip,
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "countryCode": data.get("countryCode"),
                "usageType": data.get("usageType"),
                "domain": data.get("domain"),
                "isp": data.get("isp"),
                "totalReports": data.get("totalReports"),
                "lastReportedAt": data.get("lastReportedAt"),
            }
    except Exception:
        pass
    return {"ip": ip, "error": "AbuseIPDB lookup failed"}
