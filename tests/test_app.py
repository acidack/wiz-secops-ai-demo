"""Basic smoke tests for Cymbal Bank AI Security Demo."""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_healthz():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_index_loads():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Cymbal Bank AI Security Demo" in resp.text


def test_kb_normal_doc():
    resp = client.get("/api/kb/document?name=welcome.txt")
    assert resp.status_code == 200
    assert "Model Armor" in resp.json()["content"]


def test_ticket_search_normal():
    resp = client.get("/api/tickets/search?q=MFA")
    assert resp.status_code == 200
    assert len(resp.json()["results"]) >= 1
