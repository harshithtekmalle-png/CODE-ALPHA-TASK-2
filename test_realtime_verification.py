"""
PhishGuard - Real-Time Verification Test Suite
Automated end-to-end verification of the full pipeline:
Frontend Input -> Flask REST API -> detector.py -> SQLite -> JSON Response -> Telemetry Update
"""

import sys
import json
import database
import detector
from app import app


def run_verification():
    print("=" * 70)
    print("  PHISHGUARD REAL-TIME PIPELINE VERIFICATION")
    print("  Full End-to-End Dynamic Evaluation Check")
    print("=" * 70)

    client = app.test_client()

    # Step 0: Clear any existing test history to establish a known baseline
    print("\n[STEP 0] Resetting SQLite scan history baseline...")
    del_resp = client.delete("/api/history")
    assert del_resp.status_code == 200, f"Baseline reset failed: {del_resp.status_code}"
    stats0 = del_resp.get_json()["stats"]
    assert stats0["total_scans"] == 0, f"Expected 0 total scans, got {stats0['total_scans']}"
    print("  -> Baseline confirmed: 0 records in SQLite database (phishguard.db).")

    # Step 1: Web UI Entry Point Verification
    print("\n[STEP 1] Validating GET / dashboard application page...")
    resp_index = client.get("/")
    assert resp_index.status_code == 200, f"GET / returned {resp_index.status_code}"
    html = resp_index.data.decode("utf-8")
    assert "PHISHGUARD" in html, "Brand title PHISHGUARD not found in HTML"
    assert "Real-Time Phishing Detection" in html, "Subtitle not found in HTML"
    assert "CodeAlpha" not in html, "Forbidden branding 'CodeAlpha' found in HTML!"
    assert "Task 2" not in html, "Forbidden branding 'Task 2' found in HTML!"
    print("  -> Web UI template successfully rendered with compliant SOC branding.")

    # Step 2: URL Scanner Flow (POST /api/scan-url)
    target_url = "https://example.com"
    print(f"\n[STEP 2] Submitting safe URL to POST /api/scan-url: '{target_url}'...")
    resp_url = client.post(
        "/api/scan-url",
        data=json.dumps({"url": target_url}),
        content_type="application/json"
    )
    assert resp_url.status_code == 200, f"POST /api/scan-url failed with status {resp_url.status_code}"
    res_url_data = resp_url.get_json()
    assert res_url_data["success"] is True, "API returned success: false"
    
    # Verify EXACT target match
    returned_target = res_url_data["data"]["target"]
    assert returned_target == target_url, f"Target mismatch! Expected '{target_url}', got '{returned_target}'"
    print(f"  -> Returned target EXACT match verified: '{returned_target}'")

    # Verify risk scoring
    score = res_url_data["data"]["score"]
    risk_level = res_url_data["data"]["risk_level"]
    assert 0 <= score <= 100, f"Score out of bounds: {score}"
    assert risk_level in ["Low Risk", "Suspicious", "High Risk", "Critical"]
    print(f"  -> Dynamic heuristic score calculated: {score}/100 [{risk_level}]")
    print(f"  -> Explanation: {res_url_data['data']['explanation']}")

    # Verify SQLite persistence
    stats1 = res_url_data["stats"]
    assert stats1["total_scans"] == 1, f"Expected total_scans=1, got {stats1['total_scans']}"
    assert stats1["url_scans"] == 1, f"Expected url_scans=1, got {stats1['url_scans']}"
    print(f"  -> Real-time SQLite statistics updated: Total={stats1['total_scans']}, URLs={stats1['url_scans']}")

    # Step 3: Message Analyzer Flow (POST /api/analyze-message)
    test_msg = "URGENT ACTION REQUIRED: Your account has been suspended. Please confirm your password within 24 hours."
    print(f"\n[STEP 3] Submitting text lure to POST /api/analyze-message...")
    resp_msg = client.post(
        "/api/analyze-message",
        data=json.dumps({"message": test_msg}),
        content_type="application/json"
    )
    assert resp_msg.status_code == 200, f"POST /api/analyze-message failed: {resp_msg.status_code}"
    res_msg_data = resp_msg.get_json()
    assert res_msg_data["success"] is True
    
    # Verify target exactness
    assert res_msg_data["data"]["target"] == test_msg
    print(f"  -> Message target EXACT match verified.")
    print(f"  -> Calculated score: {res_msg_data['data']['score']}/100 [{res_msg_data['data']['risk_level']}]")
    print(f"  -> Indicators detected: {len(res_msg_data['data']['indicators'])}")

    stats2 = res_msg_data["stats"]
    assert stats2["total_scans"] == 2, f"Expected total_scans=2, got {stats2['total_scans']}"
    assert stats2["message_scans"] == 1, f"Expected message_scans=1, got {stats2['message_scans']}"
    print(f"  -> Real-time SQLite stats updated: Total={stats2['total_scans']}, Messages={stats2['message_scans']}")

    # Step 4: Scan History Verification (GET /api/history)
    print("\n[STEP 4] Fetching audit log from GET /api/history...")
    resp_hist = client.get("/api/history")
    assert resp_hist.status_code == 200
    hist_data = resp_hist.get_json()
    assert hist_data["success"] is True
    history_items = hist_data["history"]
    assert len(history_items) == 2, f"Expected 2 historical records, found {len(history_items)}"
    assert history_items[0]["scan_type"] == "message", "Latest record should be message scan"
    assert history_items[1]["scan_type"] == "url", "Prior record should be URL scan"
    print(f"  -> Retrieved {len(history_items)} chronological records from SQLite.")

    # Step 5: Input Validation & Edge Case Handling
    print("\n[STEP 5] Verifying API error handling on malformed/invalid inputs...")
    
    # Empty URL
    bad_url_resp = client.post("/api/scan-url", data=json.dumps({"url": ""}), content_type="application/json")
    assert bad_url_resp.status_code == 400
    assert bad_url_resp.get_json()["success"] is False
    print("  -> Rejected empty URL with 400 Bad Request.")

    # Non-JSON payload
    bad_type_resp = client.post("/api/scan-url", data="text", content_type="text/plain")
    assert bad_type_resp.status_code == 400
    print("  -> Rejected non-JSON payload with 400 Bad Request.")

    # Empty Message
    bad_msg_resp = client.post("/api/analyze-message", data=json.dumps({"message": "   "}), content_type="application/json")
    assert bad_msg_resp.status_code == 400
    assert bad_msg_resp.get_json()["success"] is False
    print("  -> Rejected empty message with 400 Bad Request.")

    # Step 6: Clear History (DELETE /api/history)
    print("\n[STEP 6] Testing DELETE /api/history endpoint...")
    resp_clear = client.delete("/api/history")
    assert resp_clear.status_code == 200
    clear_data = resp_clear.get_json()
    assert clear_data["success"] is True
    assert clear_data["deleted_count"] == 2
    assert clear_data["stats"]["total_scans"] == 0
    print(f"  -> Cleared {clear_data['deleted_count']} records. Database metrics reset to 0.")

    # Step 7: Verify Database Is Empty
    resp_hist_empty = client.get("/api/history")
    assert len(resp_hist_empty.get_json()["history"]) == 0
    print("  -> Verified history query returns empty list [] after deletion.")

    print("\n" + "=" * 70)
    print("  ALL REAL-TIME VERIFICATION TESTS COMPLETED SUCCESSFULLY!")
    print("  Architecture Verified: Frontend <-> Flask <-> detector.py <-> SQLite")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
