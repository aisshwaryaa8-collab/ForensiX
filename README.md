# ForensiX

An AI-powered digital forensics and incident response tool with an intuitive interface for investigators — built for the SIH internal hackathon.

## Problem Statement
Investigators need a tool that streamlines the process of importing evidence, running automated analysis, and generating detailed reports — with clear navigation, real-time data visualization, and AI-assisted anomaly detection.

## Features
- Automated data collection from forensic images / evidence files
- Automated scanning and analysis of files, system logs, registry entries, and network activity
- Identification of Indicators of Compromise (IOCs) and suspicious activity
- AI/ML-based anomaly detection and pattern recognition with a suspicion scoring system
- Recommendation engine to help investigators focus on high-priority artifacts
- Interactive timelines and graphical summaries
- Report export in PDF, JSON, and CSV formats

## Tech Stack
- **Backend:** FastAPI, Python
- **AI/ML:** Isolation Forest (anomaly detection), rule-based scoring
- **Frontend:** React, Recharts / D3 for visualizations
- **Database:** SQLite / PostgreSQL


## Getting Started

### Backend
```
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm start
```
