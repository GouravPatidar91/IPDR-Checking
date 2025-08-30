from fastapi import APIRouter
from backend.core.parser import build_connection_graph
from backend.db import fetch_logs

router = APIRouter()

@router.get("/connections/")
def get_connections():
    df = fetch_logs()
    G = build_connection_graph(df)
    edges = [
        {"a_party": u, "b_party": v, **d}
        for u, v, d in G.edges(data=True)
    ]
    return {"edges": edges}
