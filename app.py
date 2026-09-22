"""Flask web UI for Prototype Safety Check. Run: python app.py"""
import json
import os
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template

from scanner import scan_url

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(BASE, "history.json")


def load_history():
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_history(entry, limit=20):
    hist = load_history()
    hist.insert(0, entry)
    hist = hist[:limit]
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(hist, f, indent=2)
    except Exception:
        pass
    return hist


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", history=load_history(), report=None, error=None)


@app.route("/scan", methods=["POST"])
def scan():
    url = (request.form.get("url") or "").strip()
    consent = request.form.get("consent")
    if not url:
        return render_template("index.html", history=load_history(), report=None,
                               error="Paste a deployed link first (e.g. https://my-app.vercel.app).")
    if not consent:
        return render_template("index.html", history=load_history(), report=None,
                               error="Please confirm you own the prototype or have permission to scan it.")
    try:
        report = scan_url(url)
    except ValueError as e:
        return render_template("index.html", history=load_history(), report=None, error=str(e))
    entry = {
        "target": report.get("target"),
        "verdict": report.get("verdict"),
        "fails": report.get("fails"),
        "warnings": report.get("warnings"),
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
    hist = save_history(entry)
    return render_template("index.html", history=hist, report=report, error=None)


@app.route("/api/scan", methods=["GET"])
def api_scan():
    url = (request.args.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Missing ?url=https://..."}), 400
    try:
        return jsonify(scan_url(url))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/history", methods=["GET"])
def history():
    return jsonify(load_history())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
