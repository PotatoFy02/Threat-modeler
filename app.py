<<<<<<< HEAD
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
=======
import io
import os
from functools import wraps

from flask import (Flask, request, jsonify, render_template,
                   send_file, session)
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from models import Component
from stride_engine import analyze
from database import (init_db, save_scan, get_all_scans, get_scan_threats)
from report_generator import generate_pdf_bytes  # see report_generator change below
from auth import auth, init_oauth, init_users_db

app = Flask(__name__)

# --- Secret key: fail loud in production ---
app.secret_key = os.environ.get("SECRET_KEY")
IS_PROD = os.environ.get("FLASK_ENV") == "production"
if not app.secret_key:
    if IS_PROD:
        raise RuntimeError("SECRET_KEY must be set in production")
    app.secret_key = "dev-secret-key-change-in-production"

app.config["GOOGLE_CLIENT_ID"] = os.environ.get("GOOGLE_CLIENT_ID")
app.config["GOOGLE_CLIENT_SECRET"] = os.environ.get("GOOGLE_CLIENT_SECRET")

# --- Secure session cookies ---
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PROD,      # HTTPS-only cookies in prod
    MAX_CONTENT_LENGTH=1 * 1024 * 1024, # 1 MB max request body
)

# --- Behind Render's proxy: trust X-Forwarded-* so HTTPS URLs build correctly ---
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# --- Rate limiting ---
limiter = Limiter(get_remote_address, app=app,
                  default_limits=["200 per day", "50 per hour"])

init_oauth(app)
init_db()
init_users_db()
app.register_blueprint(auth)

ALLOWED_COMPONENT_TYPES = {"process", "datastore", "dataflow", "external_entity"}
MAX_COMPONENTS = 100


# --- Security headers on every response ---
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if IS_PROD:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def index():
    return render_template("index.html", user=session.get("user_name"))


@app.route("/analyze", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def analyze_system():
    data = request.get_json(silent=True)
    if not data or "system_name" not in data or "components" not in data:
        return jsonify({"error": "Invalid input."}), 400

    system_name = str(data["system_name"]).strip()
    if not system_name or len(system_name) > 200:
        return jsonify({"error": "Invalid system name."}), 400

    raw_components = data["components"]
    if not isinstance(raw_components, list) or not raw_components:
        return jsonify({"error": "components must be a non-empty list."}), 400
    if len(raw_components) > MAX_COMPONENTS:
        return jsonify({"error": f"Too many components (max {MAX_COMPONENTS})."}), 400

    try:
        components = []
        for c in raw_components:
            if not isinstance(c, dict):
                raise ValueError("each component must be an object")
            comp = Component(**c)
            if comp.component_type not in ALLOWED_COMPONENT_TYPES:
                raise ValueError(f"invalid component_type '{comp.component_type}'")
            components.append(comp)
    except (TypeError, ValueError) as e:
        return jsonify({"error": f"Component error: {str(e)}"}), 400

    threats = analyze(components)
    scan_id = save_scan(system_name, threats, session["user_id"])

    return jsonify({
        "scan_id": scan_id,
        "system_name": system_name,
        "total_threats": len(threats),
        "high": sum(1 for t in threats if t.risk_level == "HIGH"),
        "medium": sum(1 for t in threats if t.risk_level == "MEDIUM"),
        "low": sum(1 for t in threats if t.risk_level == "LOW"),
        "threats": [{
            "stride_category": t.stride_category,
            "title": t.title,
            "affected_component": t.affected_component,
            "description": t.description,
            "risk_level": t.risk_level,
            "mitigation": t.mitigation,
        } for t in threats],
    })


@app.route("/scans", methods=["GET"])
@login_required
def list_scans():
    scans = get_all_scans(session["user_id"])
    return jsonify([{
        "scan_id": r[0], "system_name": r[1], "scanned_at": r[2],
        "total_threats": r[3], "high": r[4], "medium": r[5], "low": r[6],
    } for r in scans])


@app.route("/scans/<int:scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id):
    threats = get_scan_threats(scan_id, session["user_id"])  # ownership-checked
    if not threats:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify([{
        "id": r[0], "scan_id": r[1], "stride_category": r[2], "title": r[3],
        "affected_component": r[4], "description": r[5],
        "risk_level": r[6], "mitigation": r[7],
    } for r in threats])


@app.route("/report/<int:scan_id>")
@login_required
def download_report(scan_id):
    rows = get_scan_threats(scan_id, session["user_id"])  # ownership-checked
    if not rows:
        return jsonify({"error": "Report not found"}), 404

    # Rebuild lightweight threat dicts for the PDF generator
    threats = [{
        "stride_category": r[2], "title": r[3], "affected_component": r[4],
        "description": r[5], "risk_level": r[6], "mitigation": r[7],
    } for r in rows]

    pdf_bytes = generate_pdf_bytes(threats, f"Scan #{scan_id}")
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"report_{scan_id}.pdf",
    )


if __name__ == "__main__":
    app.run(debug=False, port=5000)  # debug OFF — never True in committed code
>>>>>>> 538a6eea2916976afe2f71d77afe90aa5dfc09c8
