from fastapi.testclient import TestClient
from api import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "active", "track": 2}

def test_analyze_invalid_payload():
    # Missing required raw_url and domain fields
    response = client.post("/api/v1/analyze", json={"anomaly_score": 0.89})
    assert response.status_code == 422

def test_batch_invalid_payload():
    response = client.post("/api/v1/analyze/batch", json=[{"anomaly_score": 0.89}])
    assert response.status_code == 422