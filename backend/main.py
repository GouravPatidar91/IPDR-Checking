
from fastapi import FastAPI
from backend.api import upload, connections, stream, enrich

app = FastAPI()
app.include_router(upload.router)
app.include_router(connections.router)
app.include_router(stream.router)
app.include_router(enrich.router, prefix="/enrich")
