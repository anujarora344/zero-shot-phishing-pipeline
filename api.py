import asyncio
import logging
import time
from typing import List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from track_2_agentic.schemas import Track1Input, AgenticThreatAnalysis
from track_2_agentic.reasoning_engine import analyze_url_threat

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("Track2-Engine")

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
        start_time = time.perf_counter()
        
        logger.info(f"Initiating zero-shot reasoning for URL: {payload.raw_url}")
        
        try:
            # Offload synchronous LLM call
            result = await asyncio.to_thread(analyze_url_threat, payload)
            
            elapsed_time = time.perf_counter() - start_time
            logger.info(f"Success: {payload.domain} | Verdict: {result.verdict} | Latency: {elapsed_time:.2f}s")
            
            return result
        except Exception as e:
            elapsed_time = time.perf_counter() - start_time
            logger.error(f"Failed: {payload.domain} | Latency: {elapsed_time:.2f}s | Error: {str(e)}")
            raise e

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