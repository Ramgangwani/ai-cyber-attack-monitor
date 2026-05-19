from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from datetime import datetime, timezone
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from flask import Flask, Response, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from werkzeug.security import check_password_hash, generate_password_hash


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "ids_model.joblib"
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "ids_logs.sqlite3"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "rg@123"


class User(UserMixin):
    def __init__(self, user_id: str) -> None:
        self.id = user_id


def create_app(
    model_path: str | Path = DEFAULT_MODEL_PATH,
    database_path: str | Path = DEFAULT_DB_PATH,
) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(PROJECT_ROOT / "templates"),
        static_folder=str(PROJECT_ROOT / "static"),
    )
    app.config["MODEL_PATH"] = Path(model_path)
    app.config["DATABASE_PATH"] = Path(database_path)
    app.config["IDS_MODEL"] = None
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = "dev-ids-secret-key"
    app.config.setdefault("IDS_USERNAME", DEFAULT_USERNAME)
    app.config.setdefault(
        "IDS_PASSWORD_HASH",
        generate_password_hash(DEFAULT_PASSWORD),
    )
    init_db(app.config["DATABASE_PATH"])

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str):
        if user_id == app.config["IDS_USERNAME"]:
            return User(user_id)
        return None

    @app.route("/")
    def home():
        return render_template("home.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if username == app.config["IDS_USERNAME"] and check_password_hash(
                app.config["IDS_PASSWORD_HASH"],
                password,
            ):
                login_user(User(username))
                next_url = request.args.get("next")
                return redirect(next_url or url_for("dashboard"))
            error = "Invalid username or password."

        return render_template("login.html", error=error)

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html",
            model_path=app.config["MODEL_PATH"],
            model_ready=app.config["MODEL_PATH"].exists(),
        )

    @app.get("/api/model")
    @login_required
    def model_status():
        model_path = app.config["MODEL_PATH"]
        response: dict[str, Any] = {
            "model_path": str(model_path),
            "ready": model_path.exists(),
        }

        if model_path.exists():
            model = get_model(app)
            response["features"] = get_expected_columns(model)
            response["classes"] = list(getattr(model, "classes_", []))

        return jsonify(response)

    @app.post("/api/predict")
    @login_required
    def predict_attack():
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify({"error": "Request body must be valid JSON."}), 400

        records = payload.get("records", payload) if isinstance(payload, dict) else payload
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list) or not records:
            return jsonify({"error": "Send one record object or a non-empty records list."}), 400

        try:
            model = get_model(app)
            response = predict_records(model, records, app.config["MODEL_PATH"])
            saved_logs = save_prediction_logs(
                app.config["DATABASE_PATH"],
                records,
                response["predictions"],
                response["model_path"],
            )
            response["history"] = saved_logs
            return jsonify(response)
        except FileNotFoundError as exc:
            return jsonify({"error": str(exc)}), 503
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/history")
    @login_required
    def attack_history():
        limit = request.args.get("limit", default=25, type=int)
        return jsonify(
            {
                "logs": fetch_prediction_logs(
                    app.config["DATABASE_PATH"],
                    limit=max(1, min(limit, 100)),
                )
            }
        )

    @app.get("/reports/attack-logs.csv")
    @login_required
    def download_attack_logs_csv():
        logs = fetch_prediction_logs(app.config["DATABASE_PATH"], limit=1000)
        csv_data = build_csv_report(logs)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=attack_logs_report.csv"
            },
        )

    @app.get("/reports/attack-logs.pdf")
    @login_required
    def download_attack_logs_pdf():
        logs = fetch_prediction_logs(app.config["DATABASE_PATH"], limit=1000)
        pdf_data = build_pdf_report(logs)
        return send_file(
            BytesIO(pdf_data),
            mimetype="application/pdf",
            as_attachment=True,
            download_name="attack_logs_report.pdf",
        )

    return app


REPORT_COLUMNS = [
    "id",
    "created_at",
    "prediction",
    "attack_probability",
    "threat_level",
    "protocol",
    "packets",
    "src_bytes",
    "dst_bytes",
    "model_path",
]


def build_csv_report(logs: list[dict[str, Any]]) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=REPORT_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(logs)
    return output.getvalue()


def build_pdf_report(logs: list[dict[str, Any]]) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=28,
        leftMargin=28,
        topMargin=32,
        bottomMargin=32,
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph("AI-Based IDS Attack Detection Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(
            f"Generated at {datetime.now(timezone.utc).isoformat()}",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph(f"Total log entries: {len(logs)}", styles["Normal"]),
        Spacer(1, 18),
    ]

    table_rows = [
        ["ID", "Timestamp", "Prediction", "Probability", "Threat", "Protocol", "Packets"]
    ]
    for log in logs[:60]:
        probability = log.get("attack_probability")
        table_rows.append(
            [
                log.get("id", ""),
                log.get("created_at", ""),
                log.get("prediction", ""),
                "" if probability is None else f"{float(probability) * 100:.1f}%",
                log.get("threat_level", ""),
                log.get("protocol", ""),
                log.get("packets", ""),
            ]
        )

    if len(table_rows) == 1:
        table_rows.append(["-", "No logs available", "-", "-", "-", "-", "-"])

    table = Table(table_rows, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12355b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]
        )
    )
    story.append(table)

    if len(logs) > 60:
        story.extend(
            [
                Spacer(1, 12),
                Paragraph(
                    f"Showing first 60 of {len(logs)} logs. Download CSV for full details.",
                    styles["Italic"],
                ),
            ]
        )

    document.build(story)
    return buffer.getvalue()


def init_db(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                prediction TEXT NOT NULL,
                attack_probability REAL,
                threat_level TEXT NOT NULL,
                protocol TEXT,
                packets TEXT,
                src_bytes REAL,
                dst_bytes REAL,
                payload_json TEXT NOT NULL,
                model_path TEXT NOT NULL
            )
            """
        )


def save_prediction_logs(
    database_path: Path,
    records: list[dict[str, Any]],
    predictions: list[dict[str, Any]],
    model_path: str,
) -> list[dict[str, Any]]:
    saved_logs = []
    now = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        for record, prediction in zip(records, predictions):
            protocol = record.get("protocol", record.get("protocol_type"))
            packets = record.get("packets", record.get("count"))
            src_bytes = numeric_or_none(record.get("src_bytes"))
            dst_bytes = numeric_or_none(record.get("dst_bytes"))
            cursor = connection.execute(
                """
                INSERT INTO attack_logs (
                    created_at,
                    prediction,
                    attack_probability,
                    threat_level,
                    protocol,
                    packets,
                    src_bytes,
                    dst_bytes,
                    payload_json,
                    model_path
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    prediction["prediction"],
                    prediction.get("attack_probability"),
                    prediction["threat_level"],
                    protocol,
                    None if packets is None else str(packets),
                    src_bytes,
                    dst_bytes,
                    json.dumps(record, sort_keys=True),
                    model_path,
                ),
            )
            saved_logs.append(
                {
                    "id": cursor.lastrowid,
                    "created_at": now,
                    "prediction": prediction["prediction"],
                    "attack_probability": prediction.get("attack_probability"),
                    "threat_level": prediction["threat_level"],
                    "protocol": protocol,
                    "packets": packets,
                    "src_bytes": src_bytes,
                    "dst_bytes": dst_bytes,
                    "model_path": model_path,
                }
            )

    return saved_logs


def fetch_prediction_logs(database_path: Path, limit: int = 25) -> list[dict[str, Any]]:
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                id,
                created_at,
                prediction,
                attack_probability,
                threat_level,
                protocol,
                packets,
                src_bytes,
                dst_bytes,
                payload_json,
                model_path
            FROM attack_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def numeric_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def predict_records(model, records: list[dict[str, Any]], model_path: Path) -> dict[str, Any]:
    frame = pd.DataFrame(records)
    expected_columns = get_expected_columns(model)
    if expected_columns:
        missing = sorted(set(expected_columns).difference(frame.columns))
        if missing:
            raise ValueError(f"Missing required feature column(s): {', '.join(missing)}")
        frame = frame[expected_columns]

    predictions = model.predict(frame)
    prediction_values = (
        predictions.tolist() if hasattr(predictions, "tolist") else list(predictions)
    )
    response: dict[str, Any] = {
        "model_path": str(model_path),
        "features_used": list(frame.columns),
        "predictions": [
            {
                "row": index,
                "prediction": prediction,
                "threat_level": threat_level_for(prediction, 0),
            }
            for index, prediction in enumerate(prediction_values)
        ],
    }

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(frame)
        classes = list(model.classes_)
        if "attack" in classes:
            attack_index = classes.index("attack")
            attack_probabilities = [
                row[attack_index] for row in probabilities
            ]
            for item, probability in zip(
                response["predictions"],
                attack_probabilities,
            ):
                score = round(float(probability), 6)
                item["attack_probability"] = score
                item["threat_level"] = threat_level_for(item["prediction"], score)

    return response


def threat_level_for(prediction: str, attack_probability: float) -> str:
    if prediction != "attack":
        return "low"
    if attack_probability >= 0.75:
        return "critical"
    if attack_probability >= 0.4:
        return "high"
    return "elevated"


def get_model(app: Flask):
    if app.config["IDS_MODEL"] is None:
        model_path = app.config["MODEL_PATH"]
        if not model_path.exists():
            raise FileNotFoundError(
                f"Model file not found at {model_path}. Train the IDS model first."
            )
        app.config["IDS_MODEL"] = joblib.load(model_path)

    return app.config["IDS_MODEL"]


def get_expected_columns(model) -> list[str]:
    if hasattr(model, "feature_names_in_"):
        return list(model.feature_names_in_)

    preprocess = getattr(model, "named_steps", {}).get("preprocess")
    if preprocess is not None and hasattr(preprocess, "feature_names_in_"):
        return list(preprocess.feature_names_in_)

    return []


app = create_app()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Flask IDS dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    app.run(host=args.host, port=args.port, debug=args.debug)
