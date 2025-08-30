import requests

BASE_URL = "http://127.0.0.1:8000"

# 1. Upload sample log
def test_upload():
    with open("data/sample_ipdr.csv", "rb") as f:
        files = {"file": ("sample_ipdr.csv", f, "text/csv")}
        r = requests.post(f"{BASE_URL}/upload/", files=files)
        print("Upload:", r.status_code, r.json())

# 2. Get connections
def test_connections():
    r = requests.get(f"{BASE_URL}/connections/")
    print("Connections:", r.status_code)
    print(r.json())

# 3. Get anomalies
def test_anomalies():
    r = requests.get(f"{BASE_URL}/anomalies/")
    print("Anomalies:", r.status_code)
    print(r.json())

if __name__ == "__main__":
    test_upload()
    test_connections()
    test_anomalies()
