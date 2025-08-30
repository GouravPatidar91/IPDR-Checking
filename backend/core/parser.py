import pandas as pd
import networkx as nx
from typing import List, Dict, Any

REQUIRED_FIELDS = ['a_party', 'b_party', 'port', 'protocol', 'timestamp']

def parse_ipdr_csv(file_obj) -> pd.DataFrame:
    import io, csv
    sample = file_obj.read(2048)
    file_obj.seek(0)
    try:
        dialect = csv.Sniffer().sniff(sample.decode(errors='ignore'))
        delimiter = dialect.delimiter
    except Exception:
        delimiter = ','
    try:
        df = pd.read_csv(file_obj, delimiter=delimiter, encoding='utf-8')
    except Exception as e:
        file_obj.seek(0)
        df = pd.read_csv(file_obj, delimiter=delimiter, encoding='latin1')
    if df.empty or len(df.columns) < 2:
        raise ValueError("CSV file is empty or has no valid columns.")
    df.columns = [c.strip().lower() for c in df.columns]
    col_map = {}
    for col in df.columns:
        if 'a_party' in col: col_map[col] = 'a_party'
        if 'b_party' in col: col_map[col] = 'b_party'
        if 'port' in col: col_map[col] = 'port'
        if 'protocol' in col: col_map[col] = 'protocol'
        if 'time' in col: col_map[col] = 'timestamp'
    df = df.rename(columns=col_map)
    missing = [f for f in REQUIRED_FIELDS if f not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")
    return df[REQUIRED_FIELDS]

def parse_ipdr_json(file_obj) -> pd.DataFrame:
    df = pd.read_json(file_obj)
    df.columns = [c.strip().lower() for c in df.columns]
    col_map = {}
    for col in df.columns:
        if 'a_party' in col: col_map[col] = 'a_party'
        if 'b_party' in col: col_map[col] = 'b_party'
        if 'port' in col: col_map[col] = 'port'
        if 'protocol' in col: col_map[col] = 'protocol'
        if 'time' in col: col_map[col] = 'timestamp'
    df = df.rename(columns=col_map)
    missing = [f for f in REQUIRED_FIELDS if f not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")
    return df[REQUIRED_FIELDS]

def build_connection_graph(df: pd.DataFrame) -> nx.MultiDiGraph:
    G = nx.MultiDiGraph()
    for _, row in df.iterrows():
        G.add_edge(
            row['a_party'],
            row['b_party'],
            port=row['port'],
            protocol=row['protocol'],
            timestamp=row['timestamp']
        )
    return G
