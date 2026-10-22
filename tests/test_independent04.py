import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def request(host="example.org", url="https://example.org/", tool="http"):
    return {
        "policy": {
            "allowed_tools": ["http"],
            "allowed_domains": [host],
            "confirmation_required": True,
        },
        "events": [
            {"event_id": "a", "action": "approve", "call_id": "one"},
            {
                "event_id": "b",
                "action": "call",
                "call_id": "one",
                "tool": tool,
                "url": url,
            },
            {
                "event_id": "c",
                "action": "call",
                "call_id": "two",
                "tool": "http",
                "url": url,
            },
        ],
    }


@pytest.mark.parametrize(
    "domain,url",
    [
        ("bücher.example", "https://xn--bcher-kva.example/"),
        ("127.0.0.1", "http://127.0.0.1/"),
        ("::1", "http://[::1]/"),
    ],
)
def test_idna_ip_hosts_and_approval_is_not_reusable(domain, url):
    response = client.post("/trace/audit", json=request(domain, url))
    assert response.status_code == 200
    assert response.json()["calls"][0]["violation_codes"] == []
    assert response.json()["calls"][1]["violation_codes"] == ["MISSING_PRIOR_APPROVAL"]


@pytest.mark.parametrize(
    "url",
    [
        "https://example.org@evil.test/",
        "https://example.org:65536/",
        "https://example.org:0/",
        "https://example.org/\nsecret",
        "file:///example.org",
    ],
)
def test_ambiguous_or_nonweb_targets_rejected(url):
    assert client.post("/trace/audit", json=request(url=url)).status_code == 422


def test_host_allowlist_is_exact_and_tool_case_is_exact():
    response = client.post(
        "/trace/audit", json=request(url="https://sub.example.org/", tool="HTTP")
    )
    assert response.status_code == 200
    assert response.json()["calls"][0]["violation_codes"] == [
        "TOOL_NOT_ALLOWED",
        "DOMAIN_NOT_ALLOWED",
    ]
