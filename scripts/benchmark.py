import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import asyncio
import pandas as pd
import time
from sklearn.metrics import classification_report, confusion_matrix
from track_2_agentic.schemas import Track1Input
from track_2_agentic.reasoning_engine import analyze_url_threat

async def run_evaluation():
    print("Loading benchmark dataset...")
    df = pd.read_csv("track_3_secops/track3_test_bank.csv")
    
    true_labels = []
    predicted_labels = []
    
    print(f"Running sequential evaluation on {len(df)} URLs to respect API rate limits...")
    
    for index, row in df.iterrows():
        print(f"[{index + 1}/{len(df)}] Analyzing: {row['url']}")
        
        # Build the payload
        payload = Track1Input(
            raw_url=row['url'], 
            domain=row.get('domain', 'unknown.com'), 
            subdomains=[], 
            features={}, 
            knn_distance=row.get('knn_distance', 0.0), 
            anomaly_score=row.get('anomaly_score', 0.0), 
            is_anomaly=bool(row.get('is_anomaly', False))
        )
        
        # Determine Ground Truth
        is_phishing = str(row['actual_classification']).strip().upper() == "PHISHING"
        true_labels.append(1 if is_phishing else 0)

        try:
            # Call the engine directly instead of the batch endpoint
            # We use asyncio.to_thread because the Groq client in reasoning_engine is likely synchronous
            result = await asyncio.to_thread(analyze_url_threat, payload)
            predicted_labels.append(1 if result.verdict == "PHISHING" else 0)
        except Exception as e:
            print(f"Failed on {row['url']}: {e}")
            predicted_labels.append(0) # Default to benign on failure
            
        # Throttle: Wait 3 seconds between requests to avoid the 429 Too Many Requests error
        time.sleep(2)

    print("\n--- PERFORMANCE METRICS ---")
    print(classification_report(true_labels, predicted_labels, target_names=["BENIGN", "PHISHING"]))
    
    print("\n--- CONFUSION MATRIX ---")
    cm = confusion_matrix(true_labels, predicted_labels)
    print(f"True Negatives: {cm[0][0]} | False Positives: {cm[0][1]}")
    print(f"False Negatives: {cm[1][0]} | True Positives: {cm[1][1]}")

if __name__ == "__main__":
    asyncio.run(run_evaluation())