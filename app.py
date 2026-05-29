from flask import Flask, request, jsonify, render_template, send_file, session
from models import Component
from stride_engine import analyze
from database import init_db, save_scan, get_all_scans, get_scan_threats
from report_generator import generate_pdf_report
from auth import auth, init_oauth, init_users_db
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

init_oauth(app)
init_db()
init_users_db()

app.register_blueprint(auth)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def index():
    return render_template("index.html", user=session.get('user_name'))

@app.route("/analyze", methods=["POST"])
@login_required
def analyze_system():
    data = request.get_json()
    if not data or "system_name" not in data or "components" not in data:
        return jsonify({"error": "Invalid input."}), 400
    system_name = data["system_name"]
    try:
        components = [Component(**c) for c in data["components"]]
    except Exception as e:
        return jsonify({"error": f"Component error: {str(e)}"}), 400
    threats = analyze(components)
    scan_id = save_scan(system_name, threats, session['user_id'])
    generate_pdf_report(threats, system_name, f"report_{scan_id}.pdf")
    return jsonify({
        "scan_id": scan_id,
        "system_name": system_name,
        "total_threats": len(threats),
        "high": sum(1 for t in threats if t.risk_level == "HIGH"),
        "medium": sum(1 for t in threats if t.risk_level == "MEDIUM"),
        "low": sum(1 for t in threats if t.risk_level == "LOW"),
        "threats": [
            {
                "stride_category": t.stride_category,
                "title": t.title,
                "affected_component": t.affected_component,
                "description": t.description,
                "risk_level": t.risk_level,
                "mitigation": t.mitigation
            } for t in threats
        ]
    })

@app.route("/scans", methods=["GET"])
@login_required
def list_scans():
    scans = get_all_scans(session['user_id'])
    return jsonify([
        {
            "scan_id": row[0],
            "system_name": row[1],
            "scanned_at": row[2],
            "total_threats": row[3],
            "high": row[4],
            "medium": row[5],
            "low": row[6]
        } for row in scans
    ])

@app.route("/scans/<int:scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id):
    threats = get_scan_threats(scan_id)
    if not threats:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify([
        {
            "id": row[0],
            "scan_id": row[1],
            "stride_category": row[2],
            "title": row[3],
            "affected_component": row[4],
            "description": row[5],
            "risk_level": row[6],
            "mitigation": row[7]
        } for row in threats
    ])

@app.route("/report/<int:scan_id>")
@login_required
def download_report(scan_id):
    path = os.path.join(os.getcwd(), f"report_{scan_id}.pdf")
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return jsonify({"error": "Report not found"}), 404

if __name__ == "__main__":
    app.run(debug=True, port=5000)