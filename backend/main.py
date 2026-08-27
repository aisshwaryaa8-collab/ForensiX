from fastapi import FastAPI
from parser import parse_all

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "ForensiX backend is running"}

@app.get("/artifacts")
def get_artifacts():
    artifacts = parse_all()
    return {"count": len(artifacts), "artifacts": artifacts}