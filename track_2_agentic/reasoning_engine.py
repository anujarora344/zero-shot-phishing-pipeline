import os
import instructor
from groq import Groq
from dotenv import load_dotenv
from track_2_agentic.schemas import Track1Input, AgenticThreatAnalysis

load_dotenv()

FALLBACK_MODELS = [
    "openai/gpt-oss-20b",
    "openai/gpt-oss-120b"
]

client = instructor.from_groq(Groq(api_key=os.getenv("GROQ_API_KEY")), mode=instructor.Mode.JSON)

def analyze_url_threat(input_data: Track1Input) -> AgenticThreatAnalysis:
    prompt = prompt = f"""
    Analyze the following URL for zero-shot phishing threats using strict Chain-of-Thought reasoning.
    
    URL: {input_data.raw_url}
    Apex Domain: {input_data.domain}
    Subdomains: {input_data.subdomains}
    Vector Anomaly Score: {input_data.anomaly_score} (Is Anomaly: {input_data.is_anomaly})
    Extracted Features: {input_data.features}

    CRITICAL EVALUATION GUIDELINES:
    1. Do not only look for famous consumer brands. Phishers frequently use generic trust-evoking terms combined with random numbers or hyphenation (e.g., 'support-ticket', 'auth-portal', 'security-verify', 'account-update') hosted on cheap TLDs (.net, .tk, .xyz, .info) to trick victims into entering enterprise credentials.
    2. If a generic domain uses high-risk keywords like 'auth', 'login', 'portal', or 'verify' coupled with random numbers or suspicious suffixes, evaluate it as SUSPICIOUS or PHISHING due to credential harvesting risk.
    """

    last_exception = None

    for model_id in FALLBACK_MODELS:
        try:
            response = client.chat.completions.create(
                model=model_id,
                response_model=AgenticThreatAnalysis,
                messages=[
                    {"role": "system", "content": "You are an expert AI Cybersecurity Threat Analyst."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.0
            )
            return response
        except Exception as e:
            last_exception = e
            print(f"Warning: Model '{model_id}' failed with error: {e}. Trying fallback...")
            continue

    raise RuntimeError(f"All LLM fallback models failed. Last error: {last_exception}")