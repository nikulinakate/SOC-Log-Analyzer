def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analysis_endpoint_returns_and_persists_report(client):
    content = "\n".join(
        (
            f"2026-07-11T10:00:0{i}Z sshd[10{i}]: "
            f"Failed password for admin from 203.0.113.10 port 5000{i} ssh2"
        )
        for i in range(5)
    )
    response = client.post(
        "/api/v1/analyze/text",
        json={"source_type": "linux_auth", "content": content, "persist": True},
    )

    assert response.status_code == 200
    report = response.json()
    assert report["highest_severity"] == "high"
    assert report["findings"][0]["rule_id"] == "SOC-AUTH-001"

    stored = client.get(f"/api/v1/reports/{report['id']}")
    assert stored.status_code == 200
    assert stored.json()["id"] == report["id"]


def test_file_analysis_and_report_listing(client):
    payload = (
        b'[{"EventID":4720,"TimeCreated":"2026-07-11T10:00:00Z",'
        b'"Computer":"WIN-01","EventData":{"TargetUserName":"backup-admin"}}]'
    )
    response = client.post(
        "/api/v1/analyze/file?source_type=windows_json&persist=true",
        files={"file": ("events.json", payload, "application/json")},
    )

    assert response.status_code == 200
    assert response.json()["findings"][0]["rule_id"] == "SOC-ACCOUNT-001"

    listed = client.get("/api/v1/reports?limit=10")
    assert listed.status_code == 200
    assert len(listed.json()) == 1


def test_rejects_evtx_in_text_endpoint(client):
    response = client.post(
        "/api/v1/analyze/text",
        json={"source_type": "windows_evtx", "content": "not-binary", "persist": False},
    )
    assert response.status_code == 422
