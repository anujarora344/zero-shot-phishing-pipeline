import asyncio
from typing import List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from track_2_agentic.schemas import Track1Input, AgenticThreatAnalysis
from track_2_agentic.reasoning_engine import analyze_url_threat

app = FastAPI(title="Zero-Shot Phishing API", version="1.0")

# Enable CORS for future React dashboard communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Concurrency lock to prevent Groq API rate-limit saturation
SEMAPHORE = asyncio.Semaphore(5)

async def _process_single_url(payload: Track1Input) -> AgenticThreatAnalysis:
    async with SEMAPHORE:
        # Offload synchronous/blocking LLM call to a worker thread
        return await asyncio.to_thread(analyze_url_threat, payload)

@app.get("/health")
async def health_check():
    return {"status": "active", "track": 2}

@app.post("/api/v1/analyze", response_model=AgenticThreatAnalysis)
async def analyze_endpoint(payload: Track1Input):
    try:
        return await _process_single_url(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/analyze/batch", response_model=List[AgenticThreatAnalysis])
async def analyze_batch_endpoint(payloads: List[Track1Input]):
    try:
        tasks = [_process_single_url(item) for item in payloads]
        results = await asyncio.gather(*tasks)
        return list(results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))