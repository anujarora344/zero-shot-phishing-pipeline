import asyncio
from sklearn.metrics import classification_report, confusion_matrix
from track_2_agentic.schemas import Track1Input
from api import analyze_batch_endpoint

# Mock Ground Truth Dataset (In reality, load this from a CSV)
test_dataset = [
    Track1Input(raw_url="http://paypal-login.security-verify.com", domain="security-verify.com", subdomains=["paypal-login"], features={}, knn_distance=0.89, anomaly_score=0.89, is_anomaly=True),
    Track1Input(raw_url="https://github.com/login", domain="github.com", subdomains=[], features={}, knn_distance=0.12, anomaly_score=0.12, is_anomaly=False),
    Track1Input(raw_url="http://amazon-support-refund.net", domain="amazon-support-refund.net", subdomains=[], features={}, knn_distance=0.75, anomaly_score=0.75, is_anomaly=True)
]

# 1 = PHISHING, 0 = BENIGN
true_labels = [1, 0, 1] 

async def run_evaluation():
    print("Running batch evaluation on testing dataset...")
    
    # Run the batch endpoint
    results = await analyze_batch_endpoint(test_dataset)
    
    # Convert string verdicts to binary labels
    predicted_labels = [1 if r.verdict == "PHISHING" else 0 for r in results]
    
    print("\n--- PERFORMANCE METRICS ---")
    print(classification_report(true_labels, predicted_labels, target_names=["BENIGN", "PHISHING"]))
    
    print("\n--- CONFUSION MATRIX ---")
    cm = confusion_matrix(true_labels, predicted_labels)
    print(f"True Negatives: {cm[0][0]} | False Positives: {cm[0][1]}")
    print(f"False Negatives: {cm[1][0]} | True Positives: {cm[1][1]}")

if __name__ == "__main__":
    asyncio.run(run_evaluation())