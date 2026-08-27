from fastapi import FastAPI
from parser import parse_all
from database import init_db, save_artifacts, get_all_artifacts

app = FastAPI()

@app.on_event("startup")
def startup_event():
    init_db()

@app.get("/")
def read_root():
    return {"message": "ForensiX backend is running"}

@app.post("/upload")
def upload_evidence():
    """For now, re-parses the fixed sample_data folder and saves to DB."""
    artifacts = parse_all()
    save_artifacts(artifacts)
    return {"message": "Parsed and stored artifacts", "count": len(artifacts)}

@app.get("/artifacts")
def get_artifacts():
    artifacts = get_all_artifacts()
    return {"count": len(artifacts), "artifacts": artifacts}