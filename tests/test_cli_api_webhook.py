import httpx
from fastapi.testclient import TestClient

from phishir.api import app
from phishir.cli import main
from phishir.pipeline import analyze_file
from phishir.webhook import post_webhook

HOOK = "https://hooks.example.com/x"


def test_cli_runs_and_fail_on(sample, tmp_path, capsys):
    rc = main(["analyze", str(sample("01_benign_newsletter.eml")), "-o", str(tmp_path), "--fail-on", "high"])
    assert rc == 0
    rc = main(["analyze", str(sample("02_phish_credential_harvest.eml")), "-o", str(tmp_path), "--fail-on", "high"])
    assert rc == 2
    assert "CRITICAL" in capsys.readouterr().out
    assert len(list(tmp_path.glob("*.md"))) == 2


def test_api_requires_key(monkeypatch, sample):
    monkeypatch.setenv("PHISHIR_API_KEY", "s3cret")
    c = TestClient(app)
    data = sample("02_phish_credential_harvest.eml").read_bytes()
    assert c.post("/analyze", files={"file": ("a.eml", data)}).status_code == 401
    assert c.post("/analyze", files={"file": ("a.eml", data)}, headers={"X-API-Key": "nope"}).status_code == 401
    r = c.post("/analyze", files={"file": ("a.eml", data)}, headers={"X-API-Key": "s3cret"})
    assert r.status_code == 200
    assert r.json()["case"]["severity"] == "critical"


def test_api_unconfigured_key(monkeypatch):
    monkeypatch.delenv("PHISHIR_API_KEY", raising=False)
    r = TestClient(app).post("/analyze", files={"file": ("a.eml", b"x")}, headers={"X-API-Key": "a"})
    assert r.status_code == 503


def test_health():
    assert TestClient(app).get("/health").json()["status"] == "ok"


def test_webhook_disabled_by_default(sample):
    case = analyze_file(sample("02_phish_credential_harvest.eml"))
    assert post_webhook(case, url=HOOK) is False


def test_webhook_posts_when_enabled(monkeypatch, sample):
    monkeypatch.setenv("PHISHIR_WEBHOOK_ENABLED", "1")
    seen = {}

    def h(req):
        seen["body"] = req.content
        return httpx.Response(200)
    client = httpx.Client(transport=httpx.MockTransport(h))
    ok = post_webhook(analyze_file(sample("02_phish_credential_harvest.eml")), url=HOOK, client=client)
    assert ok and b"CRITICAL" in seen["body"]


def test_webhook_rejects_http(monkeypatch, sample):
    monkeypatch.setenv("PHISHIR_WEBHOOK_ENABLED", "1")
    assert post_webhook(analyze_file(sample("01_benign_newsletter.eml")), url="http://hooks.example.com/x") is False
