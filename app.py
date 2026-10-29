import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB demo limit
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["AUDIT_FILE"] = os.path.join(app.root_path, "data", "audit_log.json")
ALLOWED_EXTENSIONS = {".bin", ".img", ".rom", ".fw", ".hex", ".zip", ".tar", ".gz", ".elf", ".dat"}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(os.path.dirname(app.config["AUDIT_FILE"]), exist_ok=True)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_audit():
    try:
        with open(app.config["AUDIT_FILE"], "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def append_audit(record):
    # Demo tamper-evident hash chain. This is NOT a public blockchain.
    entries = read_audit()
    previous_hash = entries[-1]["record_hash"] if entries else "GENESIS"
    payload = {**record, "previous_record_hash": previous_hash}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["record_hash"] = hashlib.sha256(canonical).hexdigest()
    entries.append(payload)
    with open(app.config["AUDIT_FILE"], "w", encoding="utf-8") as f:
        json.dump(entries[-500:], f, indent=2)
    return payload


def extract_strings(path, max_bytes=8 * 1024 * 1024):
    """Basic printable-string extraction for a demo; not a full firmware unpacker."""
    results = []
    pattern = re.compile(rb"[\x20-\x7e]{6,}")
    with open(path, "rb") as f:
        data = f.read(max_bytes)
    for match in pattern.finditer(data):
        value = match.group(0).decode("ascii", errors="ignore").strip()
        if value and value not in results:
            results.append(value[:180])
        if len(results) >= 250:
            break
    return results


def find_component_hints(strings):
    joined = "\n".join(strings).lower()
    hints = []
    patterns = [
        ("OpenSSL", r"openssl[\s/_-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)?"),
        ("BusyBox", r"busybox[\s/_-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)?"),
        ("Linux kernel", r"linux version[\s:]*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?)"),
        ("Dropbear", r"dropbear[\s/_-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)?"),
        ("uClibc", r"uclibc[\s/_-]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)?"),
    ]
    for name, pattern in patterns:
        match = re.search(pattern, joined, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex and match.group(1) else "version not confirmed"
            hints.append({"name": name, "version": version, "confidence": "low", "source": "printable-string hint"})
    return hints


def build_demo_agents(components, strings):
    component_names = ", ".join(c["name"] for c in components) if components else "No components confidently identified"
    return [
        {
            "name": "Emerging Threat Intelligence Agent",
            "status": "Needs live source integration",
            "summary": f"Prepared {len(components)} component hint(s) for threat-source lookup: {component_names}. This starter does not claim live NVD matches."
        },
        {
            "name": "Patch Verification Agent",
            "status": "Needs comparison firmware",
            "summary": "Upload a previous and updated firmware build and connect vendor advisories to compare patch evidence. This single-file demo cannot confirm a patch is fixed."
        },
        {
            "name": "Firmware Risk Analysis Agent",
            "status": "Heuristic review",
            "summary": f"Collected {len(strings)} printable strings for analyst review. String extraction alone cannot prove a vulnerability or device behavior."
        }
    ]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def health():
    return jsonify({"ok": True, "service": "FRIS demo backend", "mode": "prototype"})


@app.route("/api/audit")
def audit():
    entries = read_audit()
    return jsonify({"entries": list(reversed(entries[-20:])), "count": len(entries),
                    "notice": "Local hash-chain demo only; not a deployed blockchain."})


@app.route("/api/scan", methods=["POST"])
def scan():
    uploaded = request.files.get("firmware")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "Choose a firmware file first."}), 400
    filename = secure_filename(uploaded.filename)
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "Unsupported extension. Try .bin, .img, .rom, .fw, .hex, .zip, .tar, .gz, .elf, or .dat."}), 400

    scan_id = "FRIS-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + str(int(time.time() * 1000) % 100000)
    stored_name = scan_id + "-" + filename
    target = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    uploaded.save(target)

    try:
        size = os.path.getsize(target)
        digest = sha256_file(target)
        strings = extract_strings(target)
        components = find_component_hints(strings)
        agents = build_demo_agents(components, strings)

        # This is deliberately an illustrative heuristic score, not CVSS and not a verified risk rating.
        score = min(95, 18 + len(components) * 12 + (12 if size > 10 * 1024 * 1024 else 0))
        level = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW"

        record = append_audit({
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "filename": filename,
            "firmware_sha256": digest,
            "file_size": size,
            "status": "completed",
            "record_type": "FRIS prototype assessment"
        })

        return jsonify({
            "scan_id": scan_id,
            "filename": filename,
            "size": size,
            "sha256": digest,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": components,
            "strings": strings[:30],
            "string_count": len(strings),
            "agents": agents,
            "score": score,
            "risk_level": level,
            "audit_record_hash": record["record_hash"],
            "previous_record_hash": record["previous_record_hash"],
            "limitations": [
                "This prototype performs basic printable-string extraction only; it is not a full firmware unpacker.",
                "Component hints have low confidence and must be manually verified.",
                "No live NVD matching or AI-model inference is implemented in this starter.",
                "The audit log is a local hash chain, not a deployed blockchain.",
                "The displayed score is illustrative and must not be treated as a security verdict."
            ]
        })
    finally:
        # Keep files only temporarily for this demo; remove uploaded bytes after processing.
        try:
            os.remove(target)
        except OSError:
            pass


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "File is too large. Maximum upload size is 50 MB."}), 413


if __name__ == "__main__":
    app.run(debug=True, port=5000)
