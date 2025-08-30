

import streamlit as st
import requests
import pandas as pd
from pyvis.network import Network
import streamlit.components.v1 as components

st.set_page_config(page_title="IPDR Cyber Analytics Dashboard", page_icon="🕵️‍♂️", layout="wide")

BACKEND_URL = "http://127.0.0.1:8000"

# --- Sidebar ---
with st.sidebar:
    st.title("🕵️‍♂️ IPDR Cyber Analytics")
    st.info("Upload IPDR logs, visualize connections, detect anomalies, and enrich with threat intelligence.")
    st.markdown("---")
    st.markdown("**Links:**")
    st.markdown("- [GitHub](#)")
    st.markdown("- [Tech Stack SVG](./TECH_STACK_FLOW.svg)")
    st.caption("Developed for hackathons and rapid prototyping.")

# --- File Upload ---
log_file = st.file_uploader("Upload IPDR log (CSV or JSON)", type=["csv", "json"])

# --- Real-Time Log Streaming ---
st.markdown("## 🟢 Real-Time Log Stream")
st.caption("Paste new IPDR log lines (CSV/JSON) or upload a file. They will be ingested in real time and the graph/anomaly table will update.")
with st.expander("Required Columns & Example", expanded=False):
    st.markdown("**Required columns:** `a_party`, `b_party`, `port`, `protocol`, `timestamp`", help="These columns are needed for analysis.")
    st.code('{"a_party": "1.2.3.4", "b_party": "5.6.7.8", "port": 443, "protocol": "TCP", "timestamp": "2025-08-27T12:34:56"}', language="json")
    st.code('a_party,b_party,port,protocol,timestamp\n1.2.3.4,5.6.7.8,443,TCP,2025-08-27T12:34:56', language="csv")
    col1, col2 = st.columns(2)
    with col1:
        new_log_text = st.text_area("Paste new log entries (CSV/JSON, one per line)")
    with col2:
        new_log_file = st.file_uploader("Or upload new log file for streaming", type=["csv", "json"], key="stream_upload")
    if st.button("Ingest New Logs (Real-Time)"):
        logs = []
        required_cols = {"a_party", "b_party", "port", "protocol", "timestamp"}
        def valid_json_log(entry):
            return isinstance(entry, dict) and required_cols.issubset(entry.keys())
        if new_log_text:
            for line in new_log_text.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = eval(line) if line.startswith('{') else line
                    if isinstance(entry, dict) and not valid_json_log(entry):
                        st.error(f"Missing required columns in: {entry}")
                    logs.append(entry)
                except Exception:
                    st.error(f"Invalid log format: {line}")
        else:
            st.info("No connections found.")

# Show connections

def fetch_connections():
    r = requests.get(f"{BACKEND_URL}/connections/")
    if r.status_code == 200:
        return r.json()["edges"]
    return []


st.markdown("---")
st.markdown("## 🔗 A ↔ B Connections Map")
if st.button("Show Connections"):
    edges = fetch_connections()
    if edges:
        df = pd.DataFrame(edges)
        st.dataframe(df, use_container_width=True, hide_index=True)
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download Connections as CSV",
            data=csv,
            file_name="connections.csv",
            mime="text/csv"
        )
        net = Network(height="600px", width="100%", bgcolor="#ffffff", font_color="#222")
        a_parties = set(df['a_party'])
        b_parties = set(df['b_party'])
        if 'anomaly' in df.columns:
            anomaly_edges = set(zip(df['a_party'], df['b_party'], df['anomaly']))
        else:
            anomaly_edges = set()
        for node in a_parties.union(b_parties):
            if node in a_parties and node in b_parties:
                color = '#f39c12'
            elif node in a_parties:
                color = '#2980b9'
            else:
                color = '#27ae60'
            net.add_node(node, label=node, color=color, title=f"IP: {node}")
        for _, row in df.iterrows():
            color = "#97c2fc"
            width = 2
            title = f"{row['a_party']} → {row['b_party']}<br>Port: {row.get('port','')}<br>Protocol: {row.get('protocol','')}<br>Timestamp: {row.get('timestamp','')}"
            if 'anomaly' in row and row['anomaly']:
                color = "#ff4b4b"
                width = 4
                title += f"<br><b>Anomaly:</b> {row['anomaly']}"
            net.add_edge(row['a_party'], row['b_party'], color=color, width=width, title=title)
        net.set_options('''var options = {"edges": {"color": {"inherit": false}}, "nodes": {"shape": "dot", "size": 16}}''')
        net.save_graph("network.html")
        with open("network.html", "r", encoding="utf-8") as f:
            html = f.read()
            components.html(html, height=650)
        st.download_button(
            label="Download Network Graph as HTML",
            data=html,
            file_name="network_graph.html",
            mime="text/html"
        )
    else:
        st.info("No connections found.")




st.markdown("---")
st.markdown("## 🚨 Anomaly Detection Results (Uploaded File)")
abuseipdb_api_key = "6c8bf8a8b58f776183db51fae249dc57c3a3dbb3dce0dd5e03bff3159fb2b11597e5f4ad7419d51e"
if log_file is not None and st.button("Analyze Uploaded File for Anomalies"):
    log_file.seek(0)
    files = {"file": (log_file.name, log_file, log_file.type)}
    r = requests.post(f"{BACKEND_URL}/analyze/", files=files)
    if r.status_code == 200:
        anomalies = r.json().get("anomalies", [])
        if anomalies:
            df = pd.DataFrame(anomalies)
            st.dataframe(df, use_container_width=True, hide_index=True)
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Anomalies as CSV",
                data=csv,
                file_name="anomalies.csv",
                mime="text/csv"
            )
            geo_points = []
            for idx, anomaly in enumerate(anomalies):
                with st.expander(f"Anomaly {idx+1}: {anomaly.get('type','')} {anomaly.get('a_party','')} → {anomaly.get('b_party','')}"):
                    st.write(anomaly)
                    for party in ['a_party', 'b_party', 'ip']:
                        geo = anomaly.get(f"{party}_geoip")
                        if geo:
                            st.caption(f"GeoIP for {party} ({anomaly.get(party)}):")
                            st.json(geo)
                            lat = geo.get('lat') or geo.get('latitude')
                            lon = geo.get('lon') or geo.get('longitude')
                            if lat and lon:
                                geo_points.append({'ip': anomaly.get(party), 'lat': lat, 'lon': lon, 'type': party, 'anomaly': anomaly.get('type','')})
                    for party in ['a_party', 'b_party']:
                        ip = anomaly.get(party)
                        if ip:
                            if st.button(f"Threat Intelligence for {party} ({ip})", key=f"threat_{idx}_{party}"):
                                r = requests.get(f"{BACKEND_URL}/enrich/abuseipdb/{ip}", params={"api_key": abuseipdb_api_key})
                                if r.status_code == 200:
                                    st.caption(f"AbuseIPDB Threat Intelligence for {ip}:")
                                    st.json(r.json())
                                else:
                                    st.error(f"Threat intelligence lookup failed: {r.text}")
            if geo_points:
                st.markdown("### 🌍 Geo-Location Map of IP Addresses (from Anomalies)")
                map_df = pd.DataFrame([{ 'lat': p['lat'], 'lon': p['lon'] } for p in geo_points])
                st.map(map_df)
                with st.expander("Show Geo-located IPs Table"):
                    st.dataframe(pd.DataFrame(geo_points), use_container_width=True, hide_index=True)
        else:
            st.info("No anomalies detected in uploaded file.")
    else:
        st.error(f"Analysis failed: {r.text}")
