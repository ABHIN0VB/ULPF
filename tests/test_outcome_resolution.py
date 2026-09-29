import os
import sys
import json
import pytest
from fastapi.testclient import TestClient

backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
sys.path.insert(0, backend_path)

from main import app
from event_store.sqlite_store import SQLiteEventStore
from parser_engine.plugin_registry import PluginRegistry
from normalization.normalizer import normalize
from normalization.outcome_resolver import OutcomeResolver

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_test_env():
    test_db = os.path.join(backend_path, "test_outcome.db")
    if os.path.exists(test_db):
        try: os.remove(test_db)
        except: pass
    app.state.event_store = SQLiteEventStore(test_db)
    app.state.plugin_registry = PluginRegistry()
    app.state.start_time = 0
    yield
    if os.path.exists(test_db):
        try: os.remove(test_db)
        except: pass

# 1. JSON with nested event.outcome
def test_json_with_event_outcome():
    raw = json.dumps({"event": {"outcome": "failure", "action": "deny"}, "source_ip": "10.0.0.1"})
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "test-json"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_outcome"] == "failure"
    assert data["event_action"] == "deny"

# 2. JSON with event.action
def test_json_with_event_action():
    raw = json.dumps({"event": {"action": "blocked"}, "source_ip": "10.0.0.2"})
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "test-json"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_outcome"] == "failure"
    assert data["event_action"] == "blocked"

# 3. JSON with semantic action "blocked" (flat)
def test_json_flat_action_blocked():
    raw = json.dumps({"action": "blocked", "reason": "policy violation", "source_ip": "192.168.1.50"})
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "test-json"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_outcome"] == "failure"
    assert data["event_action"] == "blocked"

# 4. JSON with semantic status "allowed" (flat)
def test_json_flat_status_allowed():
    raw = json.dumps({"status": "allowed", "client_ip": "192.168.1.20"})
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "test-json"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_outcome"] == "success"

# 5. Syslog firewall deny
def test_syslog_firewall_deny():
    raw = "%ASA-4-106023: Deny tcp src outside:203.0.113.50/1234 dst inside:10.0.0.1/443 by access-group \"OUTSIDE_IN\""
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "cisco-asa"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_outcome"] == "failure"
    assert data["event_action"].lower() == "deny"

# 6. Syslog firewall allow / built
def test_syslog_firewall_allow():
    raw = "%ASA-6-302013: Built outbound TCP connection 12345 for outside:203.0.113.5/80 to inside:10.0.0.100/54321"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "cisco-asa"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_outcome"] == "success"
    assert data["event_action"].lower() == "built"

# 7. CEF with action Deny
def test_cef_with_action_deny():
    raw = "CEF:0|Vendor|Firewall|1.0|100|Packet Filter|5|src=10.0.0.1 dst=8.8.8.8 act=Deny"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "cef-dev"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_outcome"] == "failure"
    assert data["event_action"] == "Deny"

# 8. CEF with action Permit
def test_cef_with_action_permit():
    raw = "CEF:0|Vendor|Firewall|1.0|101|Packet Filter|3|src=10.0.0.1 dst=8.8.8.8 act=Permit"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "cef-dev"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_outcome"] == "success"
    assert data["event_action"] == "Permit"

# 9. LEEF with action field
def test_leef_with_action_field():
    raw = "LEEF:1.0|Vendor|Product|1.0|AuthEvent|\tsrc=10.0.0.1\taction=reject"
    resp = client.post("/api/ingest", json={"raw_log": raw, "source_id": "leef-dev"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_outcome"] == "failure"
    assert data["event_action"] == "reject"

# 10. Vendor specific: FortiGate accept & deny
def test_fortigate_actions():
    raw_accept = "date=2024-01-15 time=10:30:00 devname=FGT devid=FGT123 logid=0000000013 type=traffic subtype=forward srcip=10.0.0.1 dstip=8.8.8.8 action=accept"
    r1 = client.post("/api/ingest", json={"raw_log": raw_accept, "source_id": "fortinet"})
    assert r1.status_code == 200
    assert r1.json()["event_outcome"] == "success"

    raw_deny = "date=2024-01-15 time=10:30:00 devname=FGT devid=FGT123 logid=0000000014 type=traffic subtype=forward srcip=10.0.0.1 dstip=8.8.8.8 action=deny"
    r2 = client.post("/api/ingest", json={"raw_log": raw_deny, "source_id": "fortinet"})
    assert r2.status_code == 200
    assert r2.json()["event_outcome"] == "failure"

# 11. Vendor specific: Palo Alto allow & drop
def test_palo_alto_actions():
    raw_allow = "1705310200,002201234567,TRAFFIC,end,2049,2024/01/15 10:30:00,10.0.0.1,8.8.8.8,0.0.0.0,0.0.0.0,Rule,user,,,ssl,vsys1,trust,untrust,ae1,ae2,Log,2024/01/15,1,1,54321,443,0,0,0x400000,tcp,allow,100,50,50,5,2024/01/15,60,any,0,12345,0x0,US,US,0,3,2,tcp-fin,CORP,user,0,1,2,N/A,0,0,0,0,GP"
    r1 = client.post("/api/ingest", json={"raw_log": raw_allow, "source_id": "palo_alto"})
    assert r1.status_code == 200
    assert r1.json()["event_outcome"] == "success"

    raw_drop = "1705310200,002201234567,TRAFFIC,end,2049,2024/01/15 10:30:00,10.0.0.1,8.8.8.8,0.0.0.0,0.0.0.0,Rule,user,,,ssl,vsys1,trust,untrust,ae1,ae2,Log,2024/01/15,1,1,54321,443,0,0,0x400000,tcp,drop,100,50,50,5,2024/01/15,60,any,0,12345,0x0,US,US,0,3,2,tcp-fin,CORP,user,0,1,2,N/A,0,0,0,0,GP"
    r2 = client.post("/api/ingest", json={"raw_log": raw_drop, "source_id": "palo_alto"})
    assert r2.status_code == 200
    assert r2.json()["event_outcome"] == "failure"

# 12. Explicit success & failure
def test_explicit_success_and_failure():
    ues_succ = normalize({"result": "successful", "user": "alice"}, "src", "raw", "Parser", 0.9)
    assert ues_succ["event"]["outcome"] == "success"

    ues_fail = normalize({"status": "failed", "error_code": "500"}, "src", "raw", "Parser", 0.9)
    assert ues_fail["event"]["outcome"] == "failure"

# 13. Missing outcome defaults to unknown
def test_missing_outcome():
    ues_missing = normalize({"info": "routine heart beat"}, "src", "raw", "Parser", 0.9)
    assert ues_missing["event"]["outcome"] == "unknown"

# 14. Conflicting outcome vs action (Explicit outcome takes precedence)
def test_conflicting_outcome_and_action():
    # outcome: success, action: deny
    ues_conflict = normalize({"outcome": "success", "action": "deny"}, "src", "raw", "Parser", 0.9)
    assert ues_conflict["event"]["outcome"] == "success"
    assert ues_conflict["event"]["action"] == "deny"
    # Lossless preservation of both
    assert ues_conflict["event"]["original_outcome"] == "success"

# 15. Ambiguous / informational values
def test_ambiguous_values():
    for val in ["informational", "notice", "n/a", "unknown"]:
        ues = normalize({"status": val}, "src", "raw", "Parser", 0.9)
        assert ues["event"]["outcome"] == "unknown"

# 16. Batch ingestion preserves outcomes across diverse formats
def test_batch_ingestion_outcomes():
    batch_logs = [
        {"raw_log": "%ASA-6-302013: Built outbound TCP connection 1 for outside:1.1.1.1/80 to inside:10.0.0.1/1234", "source_id": "cisco"},
        {"raw_log": "CEF:0|Vendor|Dev|1.0|1|Drop|5|src=1.2.3.4 dst=5.6.7.8 act=Deny", "source_id": "cef"},
        {"raw_log": json.dumps({"action": "blocked", "user": "badactor"}), "source_id": "json"},
        {"raw_log": json.dumps({"status": "ok", "user": "goodactor"}), "source_id": "json"},
        {"raw_log": "<134>Jan 15 10:30:00 router01 kernel: eth0: 1000Mbps link up", "source_id": "syslog"}
    ]
    resp = client.post("/api/ingest/batch", json=batch_logs)
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 5
    assert results[0]["event_outcome"] == "success"
    assert results[1]["event_outcome"] == "failure"
    assert results[2]["event_outcome"] == "failure"
    assert results[3]["event_outcome"] == "success"
    assert results[4]["event_outcome"] == "unknown"

# 17. Lossless raw preservation check
def test_lossless_raw_preservation():
    raw_str = "{\"action\": \"denied\", \"custom_attr\": \"special_val_123\"}"
    resp = client.post("/api/ingest", json={"raw_log": raw_str, "source_id": "lossless-check"})
    evt_id = resp.json()["id"]
    stored_evt = client.get(f"/api/events/{evt_id}").json()
    assert stored_evt["ulpf"]["raw"] == raw_str
    assert stored_evt["event"]["outcome"] == "failure"
    assert stored_evt["event"]["action"] == "denied"
