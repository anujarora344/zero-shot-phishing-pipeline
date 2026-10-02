# api.py
from fastapi import FastAPI, HTTPException
from track_2_agentic.schemas import Track1Input, AgenticThreatAnalysis
from track_2_agentic.reasoning_engine import analyze_url_threat

app = FastAPI(title="Zero-Shot Phishing API", version="1.0")

@app.post("/api/v1/analyze", response_model=AgenticThreatAnalysis)
async def analyze_endpoint(payload: Track1Input):
    try:
        # Pass the incoming API data directly into your LLM engine
        result = analyze_url_threat(payload)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "active", "track": 2}