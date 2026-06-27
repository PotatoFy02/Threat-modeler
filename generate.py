import os
from enum import Enum
from typing import List
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError
from google import genai
from google.genai import types

# ---------- Setup ----------
load_dotenv()

# Initialize the client (Picks up GEMINI_API_KEY from your .env file)
client = genai.Client()

# ---------- Pydantic Schema ----------
class StrideCategory(str, Enum):
    spoofing = "Spoofing"
    tampering = "Tampering"
    repudiation = "Repudiation"
    info_disclosure = "Information Disclosure"
    denial_of_service = "Denial of Service"
    elevation_of_privilege = "Elevation of Privilege"

# Fix 2: Constrained severity to a strict Enum for easier DB filtering/sorting
class Severity(str, Enum):
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"

class Mitigation(BaseModel):
    description: str = Field(..., description="A concrete, actionable mitigation step")

class Threat(BaseModel):
    category: StrideCategory
    title: str = Field(..., description="Short title of the threat")
    description: str = Field(..., description="What the threat is and how it could occur")
    affected_component: str = Field(..., description="Which part of the system is affected")
    severity: Severity  # Fix 2: Applied the Enum here
    mitigations: List[Mitigation]

class ThreatModel(BaseModel):
    system_summary: str = Field(..., description="One-paragraph summary of the analyzed system")
    threats: List[Threat]

# ---------- Optimized System Prompt ----------
SYSTEM_PROMPT = """You are a senior application security engineer performing STRIDE threat modeling.

Given a system architecture description, identify realistic, specific security threats using the STRIDE framework:
- Spoofing (identity)
- Tampering (data/code integrity)
- Repudiation (denying actions)
- Information Disclosure (data leaks)
- Denial of Service (availability)
- Elevation of Privilege (unauthorized access escalation)

Rules:
- Be SPECIFIC to the described system. No generic filler.
- Reference the actual components mentioned.
- Each threat must have at least one concrete, actionable mitigation.
- Assign severity strictly as defined in the schema options.
"""

# ---------- Main Generation Function ----------
def generate_threat_model(architecture_description: str) -> ThreatModel:
    """
    Sends the architecture payload to Gemini and returns a fully validated
    Pydantic ThreatModel instance directly.
    """
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=f"System architecture to analyze:\n\n{architecture_description}",
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.4,
            response_mime_type="application/json",
            response_schema=ThreatModel, 
        ),
    )
    
    # Fix 1: Guard clause to catch safety blocks or token depletion without cryptic crashes
    if response.parsed is None:
        raise ValueError(
            f"Model returned no valid structured output. "
            f"Raw text: {getattr(response, 'text', 'N/A')}"
        )
        
    return response.parsed

# ---------- Pretty Printer ----------
def print_model(model: ThreatModel):
    print("\n" + "=" * 70)
    print("SYSTEM SUMMARY")
    print("=" * 70)
    print(model.system_summary)
    print(f"\nTotal threats identified: {len(model.threats)}\n")

    for i, t in enumerate(model.threats, 1):
        print("-" * 70)
        # Note: Added .value to t.severity for clean string extraction in terminal logs
        print(f"[{i}] {t.title}  ({t.category.value} | {t.severity.value})")
        print(f"    Component: {t.affected_component}")
        print(f"    {t.description}")
        print("    Mitigations:")
        for m in t.mitigations:
            print(f"      - {m.description}")
    print("=" * 70 + "\n")

# ---------- Execution Entry Point ----------
if __name__ == "__main__":
    test_input = """
    A web application for managing customer invoices.
    - FastAPI backend hosted on Render
    - PostgreSQL database (Supabase) storing customers, invoices, payments
    - Google OAuth for user login
    - Users can upload PDF receipts which are stored in cloud storage
    - An admin dashboard shows all customer data
    - REST API used by a JavaScript frontend
    """

    try:
        print("🚀 Compiling architecture guidelines and contacting Gemini API...")
        model = generate_threat_model(test_input)
        print_model(model)
    except ValidationError as e:
        print("⚠️ Structure validation failed. Details:")
        print(e)
    except ValueError as e:
        print(f"⚠️ Guard active: {e}")
    except Exception as e:
        print(f"❌ An unexpected engine error occurred: {e}")