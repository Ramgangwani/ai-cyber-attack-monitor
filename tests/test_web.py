import pytest
import joblib

from src.ids.web import DEFAULT_PASSWORD, create_app


class FakeIdsModel:
    classes_ = ["attack", "normal"]
    feature_names_in_ = ["duration", "protocol", "src_bytes"]

    def predict(self, frame):
        return ["attack"] * len(frame)

    def predict_proba(self, frame):
        return [[0.92, 0.08] for _ in range(len(frame))]


def login(client):
    return client.post(
        "/login",
        data={"username": "admin", "password": DEFAULT_PASSWORD},
        follow_redirects=True,
    )


def test_homepage_loads():
    app = create_app(database_path=":memory:")
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"Network Attack Detection" in response.data


def test_dashboard_requires_login():
    app = create_app(database_path=":memory:")
    client = app.test_client()

    response = client.get("/dashboard")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_allows_dashboard_access():
    app = create_app(database_path=":memory:")
    client = app.test_client()

    response = login(client)

    assert response.status_code == 200
    assert b"IDS Dashboard" in response.data
    assert b"Waiting for dashboard or Android traffic simulations" in response.data


def test_logout_ends_dashboard_session():
    app = create_app(database_path=":memory:")
    client = app.test_client()
    login(client)

    logout_response = client.post("/logout", follow_redirects=True)
    dashboard_response = client.get("/dashboard")

    assert logout_response.status_code == 200
    assert b"IDS Login" in logout_response.data
    assert dashboard_response.status_code == 302


def test_predict_returns_error_when_model_is_missing(tmp_path):
    app = create_app(
        model_path=tmp_path / "missing.joblib",
        database_path=tmp_path / "ids.sqlite3",
    )
    client = app.test_client()
    login(client)

    response = client.post("/api/predict", json={"duration": 1})

    assert response.status_code == 503
    assert "Model file not found" in response.get_json()["error"]


def test_model_status_reports_saved_model(tmp_path):
    model_path = tmp_path / "ids_model.joblib"
    joblib.dump(FakeIdsModel(), model_path)
    app = create_app(model_path=model_path, database_path=tmp_path / "ids.sqlite3")
    client = app.test_client()
    login(client)

    response = client.get("/api/model")
    body = response.get_json()

    assert response.status_code == 200
    assert body["ready"] is True
    assert body["features"] == ["duration", "protocol", "src_bytes"]
    assert body["classes"] == ["attack", "normal"]


def test_predict_api_uses_saved_model_and_returns_dashboard_fields(tmp_path):
    model_path = tmp_path / "ids_model.joblib"
    joblib.dump(FakeIdsModel(), model_path)
    app = create_app(model_path=model_path, database_path=tmp_path / "ids.sqlite3")
    client = app.test_client()
    login(client)

    response = client.post(
        "/api/predict",
        json={"duration": 0.1, "protocol": "tcp", "src_bytes": 20},
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["model_path"] == str(model_path)
    assert body["features_used"] == ["duration", "protocol", "src_bytes"]
    assert body["predictions"][0]["prediction"] == "attack"
    assert body["predictions"][0]["attack_probability"] == 0.92
    assert body["predictions"][0]["threat_level"] == "critical"
    assert body["history"][0]["prediction"] == "attack"


def test_prediction_is_stored_in_sqlite_history(tmp_path):
    model_path = tmp_path / "ids_model.joblib"
    database_path = tmp_path / "ids.sqlite3"
    joblib.dump(FakeIdsModel(), model_path)
    app = create_app(model_path=model_path, database_path=database_path)
    client = app.test_client()
    login(client)

    client.post(
        "/api/predict",
        json={"duration": 0.1, "protocol": "tcp", "src_bytes": 20},
    )
    response = client.get("/api/history")
    body = response.get_json()

    assert response.status_code == 200
    assert body["logs"][0]["prediction"] == "attack"
    assert body["logs"][0]["attack_probability"] == 0.92
    assert body["logs"][0]["threat_level"] == "critical"
    assert body["logs"][0]["protocol"] == "tcp"


def test_attack_logs_csv_report_download(tmp_path):
    model_path = tmp_path / "ids_model.joblib"
    database_path = tmp_path / "ids.sqlite3"
    joblib.dump(FakeIdsModel(), model_path)
    app = create_app(model_path=model_path, database_path=database_path)
    client = app.test_client()
    login(client)
    client.post(
        "/api/predict",
        json={"duration": 0.1, "protocol": "tcp", "src_bytes": 20},
    )

    response = client.get("/reports/attack-logs.csv")
    csv_text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "attachment; filename=attack_logs_report.csv" in response.headers["Content-Disposition"]
    assert "created_at,prediction,attack_probability" in csv_text
    assert "attack,0.92,critical,tcp" in csv_text


def test_attack_logs_pdf_report_download(tmp_path):
    model_path = tmp_path / "ids_model.joblib"
    database_path = tmp_path / "ids.sqlite3"
    joblib.dump(FakeIdsModel(), model_path)
    app = create_app(model_path=model_path, database_path=database_path)
    client = app.test_client()
    login(client)
    client.post(
        "/api/predict",
        json={"duration": 0.1, "protocol": "tcp", "src_bytes": 20},
    )

    response = client.get("/reports/attack-logs.pdf")

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert "attachment; filename=attack_logs_report.pdf" in response.headers["Content-Disposition"]
    assert response.data.startswith(b"%PDF")
