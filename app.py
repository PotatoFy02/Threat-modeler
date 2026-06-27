from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError
# Import your existing, hardened engine
from generate import generate_threat_model, ThreatModel

app = FastAPI(title="Threat Modeler API", version="0.1.0")

# ---------- Request body schema ----------
class GenerateRequest(BaseModel):
    architecture_description: str

# ---------- Health check ----------
@app.get("/")
def health():
    return {"status": "ok", "service": "threat-modeler"}

# ---------- The core endpoint ----------
@app.post("/generate", response_model=ThreatModel)
def generate(req: GenerateRequest):
    # Basic input guard rails
    if not req.architecture_description.strip():
        raise HTTPException(status_code=400, detail="Architecture description is empty.")
    if len(req.architecture_description) > 8000:
        raise HTTPException(status_code=400, detail="Description too long (max 8000 chars).")

    try:
        # Fire the engine we built and verified in Step 1
        model = generate_threat_model(req.architecture_description)
        return model
    except ValidationError as e:
        raise HTTPException(status_code=502, detail=f"Model output failed validation: {e}")
    except ValueError as e:
        raise HTTPException(status_code=502, detail=f"Model returned no usable output: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")