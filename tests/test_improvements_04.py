from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def trace():
    return {
        "policy": {
            "allowed_tools": ["http"],
            "allowed_domains": ["example.org"],
            "confirmation_required": True,
        },
        "events": [
            {"event_id": "e1", "action": "approve", "call_id": "c1"},
            {
                "event_id": "e2",
                "action": "call",
                "call_id": "c1",
                "tool": "http",
                "url": "https://EXAMPLE.org.:443/report",
            },
            {
                "event_id": "e3",
                "action": "call",
                "call_id": "c2",
                "tool": "http",
                "url": "https://example.org.evil.test/",
            },
            {"event_id": "e4", "action": "approve", "call_id": "c2"},
        ],
    }


def test_exact_call_approval_order_and_exact_normalized_host():
    response = client.post("/trace/audit", json=trace())
    assert response.status_code == 200
    result = response.json()
    assert result["call_count"] == 2 and result["approval_count"] == 2
    assert (
        result["calls_without_violations"] == 1 and result["calls_with_violations"] == 1
    )
    assert (
        result["calls"][0]["host"] == "example.org"
        and result["calls"][0]["prior_approval"]
    )
    assert result["calls"][1]["violation_codes"] == [
        "MISSING_PRIOR_APPROVAL",
        "DOMAIN_NOT_ALLOWED",
    ]
    assert result["violation_count"] == 2 and not result["passed"]


def test_duplicate_call_ids_unknown_approval_actions_and_self_confirmation_rejected():
    value = trace()
    value["events"][2]["call_id"] = "c1"
    assert client.post("/trace/audit", json=value).status_code == 422
    value = trace()
    value["events"][0]["call_id"] = "unknown"
    assert client.post("/trace/audit", json=value).status_code == 422
    value = trace()
    value["events"][0]["action"] = "execute"
    assert client.post("/trace/audit", json=value).status_code == 422
    value = trace()
    value["events"][1]["confirmed"] = True
    assert client.post("/trace/audit", json=value).status_code == 422
    value = trace()
    value["events"][0]["call_id"] = "bad call id"
    assert client.post("/trace/audit", json=value).status_code == 422


def test_policy_violation_tools_missing_target_and_credential_urls():
    value = {
        "policy": {
            "allowed_tools": [],
            "allowed_domains": [],
            "confirmation_required": False,
        },
        "events": [
            {"event_id": "e1", "action": "call", "call_id": "c1", "tool": "http"}
        ],
    }
    result = client.post("/trace/audit", json=value).json()
    assert result["calls"][0]["violation_codes"] == [
        "TOOL_NOT_ALLOWED",
        "MISSING_NETWORK_TARGET",
    ]
    value["events"][0]["url"] = "https://user:password@example.org/"
    assert client.post("/trace/audit", json=value).status_code == 422
    value["events"][0]["url"] = "https://example.org/"
    value["policy"]["allowed_domains"] = ["*.example.org"]
    assert client.post("/trace/audit", json=value).status_code == 422


def test_bounded_trace_outputs_and_event_cap():
    value = {
        "policy": {
            "allowed_tools": [],
            "allowed_domains": [],
            "confirmation_required": True,
        },
        "events": [
            {
                "event_id": f"e{i}",
                "action": "call",
                "call_id": f"c{i}",
                "tool": "http",
                "url": "https://example.org/",
            }
            for i in range(500)
        ],
    }
    response = client.post("/trace/audit", json=value)
    assert response.status_code == 200
    assert response.json()["violation_count"] == 1500
    assert len(response.json()["calls"]) == 500
    value["events"].append(
        {"event_id": "extra", "action": "call", "call_id": "extra", "tool": "shell"}
    )
    assert client.post("/trace/audit", json=value).status_code == 422


def test_trace_confirmation_policy_requires_an_explicit_json_boolean():
    value = trace()
    value["policy"]["confirmation_required"] = "false"
    assert client.post("/trace/audit", json=value).status_code == 422
