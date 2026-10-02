import os
import json
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from dotenv import load_dotenv

from analyzer import detect_threats, summarize_with_ai

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "soc.db"

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)

app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

ALLOWED_EXTENSIONS = {".txt", ".log"}

AI_RUNNING_MESSAGE = "AI analysis is running..."


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                severity TEXT NOT NULL,
                finding_count INTEGER NOT NULL,
                findings TEXT NOT NULL,
                ai_summary TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def get_severity(findings):
    levels = {
        "Low": 1,
        "Medium": 2,
        "High": 3
    }

    if not findings:
        return "Low"

    return max(
        (item["severity"] for item in findings),
        key=lambda level: levels.get(level, 0)
    )


def run_ai_analysis(incident_id, log_text, findings):
    """
    Run Ollama analysis in the background so the incident page
    can load immediately.
    """

    try:
        app.logger.info(
            "Starting background AI analysis for incident %s",
            incident_id
        )

        ai_summary = summarize_with_ai(
            log_text,
            findings
        )

        with get_db() as db:
            db.execute(
                """
                UPDATE incidents
                SET ai_summary = ?
                WHERE id = ?
                """,
                (ai_summary, incident_id)
            )

        app.logger.info(
            "Background AI analysis completed for incident %s",
            incident_id
        )

    except Exception:
        app.logger.exception(
            "Background AI analysis failed for incident %s",
            incident_id
        )

        with get_db() as db:
            db.execute(
                """
                UPDATE incidents
                SET ai_summary = ?
                WHERE id = ?
                """,
                (
                    "AI analysis could not be completed. "
                    "The rule-based findings are still available.",
                    incident_id
                )
            )


@app.route("/")
def dashboard():
    with get_db() as db:
        incidents = db.execute("""
            SELECT id, filename, severity, finding_count, created_at
            FROM incidents
            ORDER BY id DESC
            LIMIT 20
        """).fetchall()

        total = db.execute(
            "SELECT COUNT(*) FROM incidents"
        ).fetchone()[0]

        high = db.execute(
            "SELECT COUNT(*) FROM incidents WHERE severity = 'High'"
        ).fetchone()[0]

        medium = db.execute(
            "SELECT COUNT(*) FROM incidents WHERE severity = 'Medium'"
        ).fetchone()[0]

    return render_template(
        "dashboard.html",
        incidents=incidents,
        total=total,
        high=high,
        medium=medium
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded = request.files.get("logfile")

    if not uploaded or not uploaded.filename:
        flash("Please select a log file.", "error")
        return redirect(url_for("dashboard"))

    filename = Path(uploaded.filename).name

    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        flash("Only .txt and .log files are accepted.", "error")
        return redirect(url_for("dashboard"))

    try:
        raw_bytes = uploaded.stream.read(
            1 * 1024 * 1024 + 1
        )

        if len(raw_bytes) > 1 * 1024 * 1024:
            flash(
                "The file is too large. Maximum size is 1 MB.",
                "error"
            )
            return redirect(url_for("dashboard"))

        log_text = raw_bytes.decode(
            "utf-8",
            errors="replace"
        )

        if not log_text.strip():
            flash(
                "The uploaded file is empty.",
                "error"
            )
            return redirect(url_for("dashboard"))

        # -----------------------------------------
        # STEP 1: Fast rule-based analysis
        # -----------------------------------------

        findings = detect_threats(log_text)

        severity = get_severity(findings)

        # -----------------------------------------
        # STEP 2: Save incident immediately
        # -----------------------------------------

        created_at = datetime.now(
            timezone.utc
        ).isoformat(
            timespec="seconds"
        )

        with get_db() as db:
            cursor = db.execute(
                """
                INSERT INTO incidents
                (
                    filename,
                    severity,
                    finding_count,
                    findings,
                    ai_summary,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    filename,
                    severity,
                    len(findings),
                    json.dumps(findings),
                    AI_RUNNING_MESSAGE,
                    created_at
                )
            )

            incident_id = cursor.lastrowid

        # -----------------------------------------
        # STEP 3: Start Ollama in background
        # -----------------------------------------

        ai_thread = threading.Thread(
            target=run_ai_analysis,
            args=(
                incident_id,
                log_text,
                findings
            ),
            daemon=True
        )

        ai_thread.start()

        # -----------------------------------------
        # STEP 4: Show incident immediately
        # -----------------------------------------

        return redirect(
            url_for(
                "incident",
                incident_id=incident_id
            )
        )

    except Exception as exc:
        app.logger.exception(
            "Incident analysis failed"
        )

        flash(
            f"Could not analyze this file "
            f"({type(exc).__name__}). "
            "Please check the application logs.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )


@app.route("/incident/<int:incident_id>")
def incident(incident_id):
    with get_db() as db:
        record = db.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

    if record is None:
        flash(
            "Incident not found.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    findings = json.loads(
        record["findings"]
    )

    return render_template(
        "incident.html",
        incident=record,
        findings=findings
    )


@app.route("/api/incident/<int:incident_id>/ai-status")
def ai_status(incident_id):
    """
    Endpoint used by the incident page to check
    whether the background Ollama analysis is finished.
    """

    with get_db() as db:
        record = db.execute(
            """
            SELECT ai_summary
            FROM incidents
            WHERE id = ?
            """,
            (incident_id,)
        ).fetchone()

    if record is None:
        return jsonify({
            "ready": False,
            "error": "Incident not found."
        }), 404

    ai_summary = record["ai_summary"]

    if ai_summary == AI_RUNNING_MESSAGE:
        return jsonify({
            "ready": False,
            "ai_summary": ai_summary
        })

    return jsonify({
        "ready": True,
        "ai_summary": ai_summary
    })


@app.errorhandler(413)
def too_large(_error):
    flash(
        "The upload exceeds the 1 MB limit.",
        "error"
    )

    return redirect(
        url_for("dashboard")
    )


init_db()


if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )