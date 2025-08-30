import pandas as pd
import networkx as nx
from typing import List, Dict, Any
from collections import Counter
import datetime

BLACKLISTED_IPS = {"10.0.0.66", "192.168.1.100"}
MAX_CONNECTIONS_PER_MIN = 5
MAX_CONNECTIONS_PER_10MIN = 10
MAX_TOTAL_CONNECTIONS = 50

def detect_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    anomalies = []
    seen = set()
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    grouped = df.groupby(['a_party', 'b_party'])
    suspicious_ips = set()
    for (a, b), group in grouped:
        group = group.sort_values('timestamp')
        times = group['timestamp'].tolist()
        total_count = len(times)
        if total_count > MAX_TOTAL_CONNECTIONS:
            key = (a, b, 'high_total_connections')
            if key not in seen:
                anomalies.append({
                    'type': 'high_total_connections',
                    'a_party': a,
                    'b_party': b,
                    'count': total_count,
                })
                seen.add(key)
                suspicious_ips.update([a, b])
        for i in range(len(times)):
            window = [t for t in times if 0 <= (t - times[i]).total_seconds() < 60]
            if len(window) > MAX_CONNECTIONS_PER_MIN:
                key = (a, b, 'too_many_connections')
                if key not in seen:
                    anomalies.append({
                        'type': 'too_many_connections',
                        'a_party': a,
                        'b_party': b,
                        'count': len(window),
                        'window_start': times[i],
                    })
                    seen.add(key)
                    suspicious_ips.update([a, b])
                break
        for i in range(len(times)):
            window = [t for t in times if 0 <= (t - times[i]).total_seconds() < 600]
            if len(window) > MAX_CONNECTIONS_PER_10MIN:
                key = (a, b, 'repeated_connections')
                if key not in seen:
                    anomalies.append({
                        'type': 'repeated_connections',
                        'a_party': a,
                        'b_party': b,
                        'count': len(window),
                        'window_start': times[i],
                    })
                    seen.add(key)
                    suspicious_ips.update([a, b])
                break
        if a in BLACKLISTED_IPS or b in BLACKLISTED_IPS:
            key = (a, b, 'blacklisted_ip')
            if key not in seen:
                anomalies.append({
                    'type': 'blacklisted_ip',
                    'a_party': a,
                    'b_party': b,
                })
                seen.add(key)
                suspicious_ips.update([a, b])
        if not df[(df['a_party'] == b) & (df['b_party'] == a)].empty:
            key = (a, b, 'bidirectional_loop')
            if key not in seen:
                anomalies.append({
                    'type': 'bidirectional_loop',
                    'a_party': a,
                    'b_party': b,
                })
                seen.add(key)
                suspicious_ips.update([a, b])
        if a == b:
            key = (a, b, 'self_communication')
            if key not in seen:
                anomalies.append({
                    'type': 'self_communication',
                    'a_party': a,
                    'b_party': b,
                    'count': total_count,
                })
                seen.add(key)
                suspicious_ips.add(a)
    if not anomalies and len(suspicious_ips) > 0:
        for ip in suspicious_ips:
            anomalies.append({
                'type': 'suspicious_ip',
                'ip': ip,
                'note': 'This IP is involved in suspicious activity.'
            })
    if not anomalies and not df.empty:
        ip_counts = pd.concat([df['a_party'], df['b_party']]).value_counts()
        top_ip = ip_counts.index[0]
        anomalies.append({
            'type': 'most_frequent_ip',
            'ip': top_ip,
            'count': int(ip_counts.iloc[0]),
            'note': 'Most frequent IP in this file.'
        })
    return anomalies
