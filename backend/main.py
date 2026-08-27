import os
import json
from fastapi.responses import JSONResponse, StreamingResponse
import csv
import io
import shutil
from fastapi import FastAPI, UploadFile, File
from parser import parse_all
from database import init_db, save_artifacts, get_all_artifacts

app = FastAPI()

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.on_event("startup")
def startup_event():
    init_db()

@app.get("/")
def read_root():
    return {"message": "ForensiX backend is running"}

@app.post("/upload")
def upload_evidence(file: UploadFile = File(...)):
    dest_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(dest_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    saved_paths = [file.filename]

    # Parse both the fixed sample_data AND newly uploaded files
    artifacts = parse_all(sample_data_dir="sample_data")
    artifacts += parse_all(sample_data_dir=UPLOAD_DIR)

    save_artifacts(artifacts)
    return {
        "message": "Files uploaded, parsed, and stored",
        "uploaded_files": saved_paths,
        "artifact_count": len(artifacts)
    }

@app.get("/artifacts")
def get_artifacts():
    artifacts = get_all_artifacts()
    return {"count": len(artifacts), "artifacts": artifacts}

@app.get("/report")
def generate_report(format: str = "json"):
    """Exports all stored artifacts as JSON or CSV."""
    artifacts = get_all_artifacts()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "source_file", "type", "src_ip", "iocs", "suspicion_score", "anomaly_flag"])
        for a in artifacts:
            writer.writerow([
                a["id"], a["source_file"], a["type"], a.get("src_ip"),
                "; ".join(a["iocs"]), a.get("suspicion_score"), a.get("anomaly_flag")
            ])
        output.seek(0)
        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=forensix_report.csv"}
        )

    # default: JSON
    return JSONResponse(content={"report_type": "json", "artifact_count": len(artifacts), "artifacts": artifacts})