import csv
from guardrail_engine import scan_for_base64_injection

total_tests = 0
caught_direct = 0
caught_base64 = 0
false_positives = 0
missed_attacks = 0

with open("track3_test_bank.csv", mode="r", encoding="utf-8") as file:
    reader = csv.DictReader(file)
    
    print("--- RUNNING COMPREHENSIVE BATCH SECURITY AUDIT ---")
    for row in reader:
        url = row["url"]
        actual_class = row["actual_classification"]
        injection_type = row["injection_type"]
        
        total_tests += 1
        
        
        result = scan_for_base64_injection(url)
        is_detected = result["indirect_prompt_injection_detected"]
        
        
        if injection_type == "direct_injection":
            if is_detected:
                caught_direct += 1
                print(f"[PASS] Caught direct URL-encoded injection.")
            else:
                missed_attacks += 1
                print(f"[FAIL] Missed direct injection: {url}")
                
        elif injection_type == "base64_obfuscation":
            if is_detected:
                caught_base64 += 1
                print(f"[PASS] Caught Base64 obfuscated injection.")
            else:
                missed_attacks += 1
                print(f"[FAIL] Missed Base64 attack: {url}")
        
        elif actual_class == "benign":
            if is_detected:
                false_positives += 1
                print(f"[FALSE ALARM] Blocked a safe benign URL: {url}")

print("\n--- BATCH AUDIT COMPLETE ---")
print(f"Total URLs Tested       : {total_tests}")
print(f"Direct Injections Caught: {caught_direct} / 3")
print(f"Base64 Attacks Caught   : {caught_base64} / 3")
print(f"False Positives         : {false_positives}")
print(f"Missed Attacks          : {missed_attacks}")