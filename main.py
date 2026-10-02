from track_2_agentic.schemas import Track1Input
from track_2_agentic.reasoning_engine import analyze_url_threat

def test_track_2():
    # 1. Mock the data that Member 1 will eventually send you
    mock_track_1_data = Track1Input(
        raw_url="http://paypal-login.security-verify.com/auth",
        domain="security-verify.com",
        subdomains=["paypal-login"],
        features={"length": 45, "special_chars": 3},
        knn_distance=0.89,
        anomaly_score=0.89,
        is_anomaly=True
    )

    print("Sending data to LLM...")
    
    # 2. Run your engine
    result = analyze_url_threat(mock_track_1_data)
    
    # 3. Print the perfectly structured Pydantic object
    print("\n--- AI THREAT ANALYSIS ---")
    print(result.model_dump_json(indent=2))

if __name__ == "__main__":
    test_track_2()