# track_2_agentic/reasoning_engine.py
import os
import instructor
from groq import Groq
from dotenv import load_dotenv
from track_2_agentic.schemas import Track1Input, AgenticThreatAnalysis

load_dotenv()

# Initialize Instructor-wrapped client
client = instructor.from_groq(Groq(api_key=os.getenv("GROQ_API_KEY")), mode=instructor.Mode.JSON)

def analyze_url_threat(input_data: Track1Input) -> AgenticThreatAnalysis:
    prompt = f"""
    Analyze the following URL for potential phishing threats using Chain-of-Thought reasoning.
    
    URL: {input_data.raw_url}
    Apex Domain: {input_data.domain}
    Subdomains: {input_data.subdomains}
    Vector Anomaly Score: {input_data.anomaly_score} (Is Anomaly: {input_data.is_anomaly})
    
    Examine the subdomain structure for brand impersonation, homoglyphs, or misleading apex domains.
    Provide step-by-step reasoning before arriving at a final verdict.
    """

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        response_model=AgenticThreatAnalysis,
        messages=[
            {"role": "system", "content": "You are an expert AI Cybersecurity Threat Analyst."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.0
    )
    return response