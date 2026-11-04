import sys
import os
import streamlit as st

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from run_pipeline import run_full_pipeline_programmatic

st.set_page_config(page_title="Zero-Shot Phishing Intelligence", layout="wide")

st.title("🛡️ Zero-Shot & Unsupervised Phishing URL Intelligence Pipeline")
st.markdown("Enter any target URL below to run it live through Track 1 (Vector Anomaly Detection) and Track 2 (Agentic LLM Reasoning).")

# Input text box for custom URL
target_url = st.text_input("Target URL to Inspect", "http://paypal-login.security-verify.com/auth")
from track_3_secops.guardrail_engine import scan_for_base64_injection

if st.button("Run Full Pipeline Analysis"):
    with st.spinner(f"Analyzing {target_url} through the multi-track pipeline..."):
        try:
            # STEP 1: Track 3 - Guardrail & Prompt Injection Scan
            guardrail_res = scan_for_base64_injection(target_url)
            sanitized_url = guardrail_res["sanitized_payload"]
            
            # STEP 2: Run Track 1 & 2 using the sanitized URL
            t1_res, t2_res = run_full_pipeline_programmatic(sanitized_url)
            
            st.success("Pipeline Execution Complete!")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.subheader("🛡️ Track 3: SecOps")
                st.write(f"**Injection Detected:** `{guardrail_res['indirect_prompt_injection_detected']}`")
                st.write(f"**Sanitized Payload:** `{sanitized_url}`")
                
            with col2:
                st.subheader("📊 Track 1: Vector Anomaly")
                st.metric("Anomaly Score", f"{t1_res.anomaly_score:.4f}")
                st.write(f"**Is Anomaly:** {t1_res.is_anomaly}")
                
            with col3:
                st.subheader("🤖 Track 2: Agentic LLM")
                if guardrail_res['indirect_prompt_injection_detected']:
                    st.error("**Verdict:** THREAT (Prompt Injection Intercepted)")
                else:
                    verdict = t2_res.verdict
                    if verdict in ["PHISHING", "SUSPICIOUS"]:
                        st.error(f"**Verdict:** {verdict}")
                    else:
                        st.success(f"**Verdict:** {verdict}")
                    st.metric("Confidence", f"{t2_res.confidence * 100:.0f}%")
                    
            st.markdown("**Chain-of-Thought Reasoning:**")
            for step in t2_res.reasoning_chain:
                st.markdown(f"- {step}")
                    
        except Exception as e:
            st.error(f"Pipeline Execution Failed: {str(e)}")