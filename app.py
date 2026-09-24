"""Flask web UI for Prototype Safety Check. Run: python app.py"""
import json
import os
import uuid
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template, abort

from scanner import scan_url
from fast_scanner import fast_scan_url, scan_urls

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(BASE, "history.json")
REPORTS_DIR = os.path.join(BASE, "reports")


def load_history():
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_report(report):
    """Persist a full report to disk. Returns its id."""
    rid = uuid.uuid4().hex[:12]
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(os.path.join(REPORTS_DIR, rid + ".json"), "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
    except Exception:
        pass
    return rid


def load_report(rid):
    """Load a persisted full report. Returns None if missing/invalid."""
    if not rid or not rid.isalnum():
        return None
    try:
        with open(os.path.join(REPORTS_DIR, rid + ".json"), "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else None
    except Exception:
        return None


def prune_reports(hist):
    """Delete stored reports no longer referenced by the register."""
    try:
        keep = {h.get("id") for h in hist if h.get("id")}
        for name in os.listdir(REPORTS_DIR):
            if name.endswith(".json") and name[:-5] not in keep:
                os.remove(os.path.join(REPORTS_DIR, name))
    except Exception:
        pass


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
def landing():
    return render_template("landing.html", history=load_history())


@app.route("/scanner", methods=["GET"])
def index():
    return render_template("scanner.html", history=load_history(),
                           error=None, engine="standard", prefill="",
                           active="scanner")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    hist = load_history()
    counts = {"Safe": 0, "Risky": 0, "Critical": 0, "Error": 0}
    fails = warnings = 0
    for h in hist:
        v = h.get("verdict", "Error")
        if v in counts:
            counts[v] += 1
        else:
            counts["Error"] += 1
        fails += h.get("fails", 0) or 0
        warnings += h.get("warnings", 0) or 0
    total = sum(counts.values())
    palette = [("Safe", "#22c55e"), ("Risky", "#f59e0b"),
               ("Critical", "#ef4444"), ("Error", "#64748b")]
    segments = [{"label": k, "count": counts[k], "color": c} for k, c in palette]
    if total:
        stops, acc = [], 0.0
        for s in segments:
            pct = 100.0 * s["count"] / total
            stops.append(f"{s['color']} {acc:.1f}% {acc + pct:.1f}%")
            acc += pct
        donut = "conic-gradient(" + ", ".join(stops) + ")"
    else:
        donut = "var(--line)"
    coverage = [
        {"icon": "💉", "name": "SQL Injection", "pct": 100},
        {"icon": "✨", "name": "Cross-Site Scripting", "pct": 100},
        {"icon": "🦠", "name": "Malware", "pct": 100},
        {"icon": "🎣", "name": "Phishing", "pct": 100},
        {"icon": "🌊", "name": "DoS Exposure", "pct": 100},
        {"icon": "🔒", "name": "Man-in-the-Middle", "pct": 100},
    ]
    return render_template("dashboard.html", active="dashboard",
                           stats={"total": total, "counts": counts,
                                  "fails": fails, "warnings": warnings},
                           segments=segments, donut=donut,
                           coverage=coverage, recent=hist[:6])


@app.route("/history", methods=["GET"])
def history_page():
    return render_template("history.html", history=load_history(), active="history")


@app.route("/api", methods=["GET"])
def api_page():
    return render_template("api.html", active="api")


def _parse_urls(raw):
    """Split merged scan-bar input into a clean URL list (one per line, commas OK)."""
    return [line.strip() for line in (raw or "").replace(",", "\n").splitlines()
            if line.strip()][:21]


def _render(error=None, engine="standard", prefill=""):
    return render_template("scanner.html", history=load_history(),
                           error=error, engine=engine, prefill=prefill,
                           active="scanner")


def _run_scan(raw, consent, engine):
    """Shared logic for the merged scan bar: 1 URL -> report page, N URLs -> bulk page."""
    if not raw:
        return _render(error="Paste a deployed link first (e.g. https://my-app.vercel.app).",
                       engine=engine, prefill=raw)
    if not consent:
        return _render(error="Please confirm you own the prototype(s) or have permission to scan them.",
                       engine=engine, prefill=raw)
    urls = _parse_urls(raw)
    if not urls:
        return _render(error="Paste at least one URL (one per line for bulk).",
                       engine=engine, prefill=raw)
    if len(urls) > 20:
        return _render(error="Bulk scan is capped at 20 links per batch.",
                       engine=engine, prefill=raw)
    if len(urls) == 1:
        try:
            report = fast_scan_url(urls[0]) if engine == "fast" else scan_url(urls[0])
        except ValueError as e:
            return _render(error=str(e), engine=engine, prefill=raw)
        rid = save_report(report)
        hist = save_history({
            "id": rid,
            "target": report.get("target"),
            "verdict": report.get("verdict"),
            "fails": report.get("fails"),
            "warnings": report.get("warnings"),
            "engine": report.get("engine", "standard"),
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        })
        prune_reports(hist)
        return render_template("report.html", report=report, active="scanner",
                               crumb="Examination Report")
    try:
        batch = scan_urls(urls, max_workers=8)
    except ValueError as e:
        return _render(error=str(e), engine=engine, prefill=raw)
    for r in batch["results"]:
        rid = save_report(r)
        r["id"] = rid
        save_history({
            "id": rid,
            "target": r.get("target"),
            "verdict": r.get("verdict"),
            "fails": r.get("fails"),
            "warnings": r.get("warnings"),
            "engine": r.get("engine", "fast"),
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        })
    prune_reports(load_history())
    return render_template("bulk.html", bulk=batch, active="scanner",
                           crumb="Bulk Outcome")


@app.route("/report/<rid>", methods=["GET"])
def saved_report(rid):
    """Open the full saved result of a past examination from the register."""
    report = load_report(rid)
    if report is None:
        abort(404, description="Saved report not found. It may have been pruned from the register.")
    return render_template("report.html", report=report, active="scanner",
                           crumb="Examination Report")


@app.route("/scan", methods=["POST"])
def scan():
    raw = (request.form.get("urls") or request.form.get("url") or "").strip()
    consent = request.form.get("consent")
    engine = (request.form.get("engine") or "standard").strip().lower()
    return _run_scan(raw, consent, engine)


@app.route("/bulk", methods=["POST"])
def bulk():
    # Kept for backward compatibility (old form/bookmarks) — same merged logic.
    raw = (request.form.get("urls") or request.form.get("url") or "").strip()
    consent = request.form.get("consent") or request.form.get("consent_bulk")
    engine = (request.form.get("engine") or "fast").strip().lower()
    return _run_scan(raw, consent, engine)


@app.route("/api/scan", methods=["GET"])
def api_scan():
    url = (request.args.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Missing ?url=https://..."}), 400
    try:
        return jsonify(scan_url(url))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/scan_fast", methods=["GET"])
def api_scan_fast():
    """High-efficiency single-URL scan (parallel probes + pooled connections)."""
    url = (request.args.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Missing ?url=https://..."}), 400
    try:
        return jsonify(fast_scan_url(url))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/scan_bulk", methods=["POST"])
def api_scan_bulk():
    """High-efficiency bulk scan. JSON body: {"urls": ["https://...", ...]} (max 20)."""
    data = request.get_json(silent=True) or {}
    urls = data.get("urls") or []
    if isinstance(urls, str):
        urls = [urls]
    if not urls:
        return jsonify({"error": 'Missing JSON body like {"urls": ["https://..."]}.'}), 400
    try:
        return jsonify(scan_urls(urls, max_workers=8))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/history", methods=["GET"])
def api_history():
    return jsonify(load_history())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
