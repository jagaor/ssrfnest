import json
import sys
from pathlib import Path

import pytest

# Permite importar src/ssrf_detector.py sin instalar el paquete
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ssrf_detector import (  # noqa: E402
    load_events,
    filter_ssrf_alerts,
    enrich_alert,
    compute_summary,
    generate_report,
    SEVERITY_MAP,
)


@pytest.fixture
def sample_events():
    """Simula 5 lineas de eve.json: 3 alertas SSRF, 1 http y 1 flow."""
    return [
        {
            "timestamp": "2024-05-01T10:00:01.000000+0000",
            "event_type": "alert",
            "src_ip": "10.10.10.50",
            "dest_ip": "172.20.0.10",
            "dest_port": 9000,
            "proto": "TCP",
            "alert": {
                "signature": "SSRF Attempt to Metadata Endpoint",
                "signature_id": 1000001,
                "severity": 1,
                "category": "attempted-recon",
            },
            "http": {
                "hostname": "169.254.169.254",
                "url": "/latest/meta-data/iam/security-credentials/",
                "http_method": "GET",
                "status": 200,
            },
        },
        {
            "timestamp": "2024-05-01T10:00:02.000000+0000",
            "event_type": "alert",
            "src_ip": "10.10.10.50",
            "dest_ip": "172.20.0.11",
            "dest_port": 9001,
            "proto": "TCP",
            "alert": {
                "signature": "SSRF Attempt to Internal Admin Panel",
                "signature_id": 1000002,
                "severity": 2,
                "category": "attempted-recon",
            },
            "http": {
                "hostname": "adminpanel",
                "url": "/admin/users",
                "http_method": "GET",
                "status": 200,
            },
        },
        {
            "timestamp": "2024-05-01T10:00:03.000000+0000",
            "event_type": "alert",
            "src_ip": "10.10.10.77",
            "dest_ip": "127.0.0.1",
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "signature": "SSRF Attempt to Loopback Range",
                "signature_id": 1000003,
                "severity": 3,
                "category": "attempted-recon",
            },
            "http": {
                "hostname": "127.0.0.1",
                "url": "/",
                "http_method": "GET",
                "status": 0,
            },
        },
        {
            "timestamp": "2024-05-01T10:00:04.000000+0000",
            "event_type": "http",
            "src_ip": "10.10.10.50",
            "dest_ip": "172.20.0.10",
            "dest_port": 8080,
            "proto": "TCP",
            "http": {
                "hostname": "vulnapp",
                "url": "/fetch?url=http://example.com",
                "http_method": "GET",
                "status": 200,
            },
        },
        {
            "timestamp": "2024-05-01T10:00:05.000000+0000",
            "event_type": "flow",
            "src_ip": "10.10.10.50",
            "dest_ip": "172.20.0.10",
            "dest_port": 8080,
            "proto": "TCP",
            "flow": {
                "pkts_toserver": 12,
                "pkts_toclient": 10,
                "bytes_toserver": 980,
                "bytes_toclient": 1450,
            },
        },
    ]


def _write_ndjson(path: Path, events):
    with path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event) + "\n")


def test_load_events_from_file(tmp_path, sample_events):
    eve_file = tmp_path / "eve.json"
    _write_ndjson(eve_file, sample_events)

    loaded = load_events(str(eve_file))

    assert isinstance(loaded, list)
    assert len(loaded) == len(sample_events)
    assert loaded[0]["event_type"] == "alert"
    assert loaded[-1]["event_type"] == "flow"


def test_filter_ssrf_alerts(sample_events):
    alerts = filter_ssrf_alerts(sample_events)

    assert len(alerts) == 3
    for alert in alerts:
        assert alert["event_type"] == "alert"
        assert "SSRF" in alert["alert"]["signature"]


def test_enrich_alert_severity_mapping(sample_events):
    alerts = filter_ssrf_alerts(sample_events)
    enriched = [enrich_alert(a) for a in alerts]

    by_sev = {e["severity"]: e["severity_label"] for e in enriched}

    assert by_sev[1] == "CRITICAL"
    assert by_sev[2] == "HIGH"
    assert by_sev[3] == "MEDIUM"
    assert SEVERITY_MAP[1] == "CRITICAL"
    assert SEVERITY_MAP[2] == "HIGH"
    assert SEVERITY_MAP[3] == "MEDIUM"


def test_compute_summary_unique_hosts(sample_events):
    alerts = filter_ssrf_alerts(sample_events)
    enriched = [enrich_alert(a) for a in alerts]

    summary = compute_summary(enriched)

    # Los src_ip presentes son 10.10.10.50 y 10.10.10.77 -> 2 atacantes unicos
    assert summary["total_alerts"] == 3
    assert summary["unique_attackers"] == 2
    assert summary["unique_targets"] >= 2


def test_generate_report_creates_file(tmp_path, sample_events):
    alerts = filter_ssrf_alerts(sample_events)
    enriched = [enrich_alert(a) for a in alerts]
    summary = compute_summary(enriched)

    out_file = tmp_path / "report.json"
    generate_report(enriched, summary, str(out_file))

    assert out_file.exists()
    with out_file.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    assert "ssrf_alerts" in data
    assert "summary" in data
    assert len(data["ssrf_alerts"]) == 3


def test_filter_excludes_non_ssrf():
    events = [
        {
            "event_type": "alert",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "alert": {
                "signature": "ET SCAN Potential SSH Brute Force",
                "signature_id": 2000001,
                "severity": 2,
            },
        },
        {
            "event_type": "alert",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.3",
            "alert": {
                "signature": "GPL ICMP PING UNIX",
                "signature_id": 2000002,
                "severity": 3,
            },
        },
        {
            "event_type": "http",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.4",
            "http": {"hostname": "example.com", "url": "/", "http_method": "GET"},
        },
    ]

    alerts = filter_ssrf_alerts(events)

    assert alerts == []
