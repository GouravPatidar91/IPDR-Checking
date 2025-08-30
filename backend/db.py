import sqlite3
import pandas as pd
from typing import Optional

def init_db(db_path: str = 'ipdr_logs.db'):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        a_party TEXT,
        b_party TEXT,
        port TEXT,
        protocol TEXT,
        timestamp TEXT
    )''')
    conn.commit()
    conn.close()

def insert_logs(df: pd.DataFrame, db_path: str = 'ipdr_logs.db'):
    conn = sqlite3.connect(db_path)
    df.to_sql('logs', conn, if_exists='append', index=False)
    conn.close()

def fetch_logs(db_path: str = 'ipdr_logs.db', limit: Optional[int] = 1000) -> pd.DataFrame:
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query(f'SELECT * FROM logs LIMIT {limit}', conn)
    conn.close()
    return df
