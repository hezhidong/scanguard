import os, sys, tempfile
os.environ["SCANGUARD_API_TOKEN"] = "testtoken"
d = tempfile.mkdtemp()
os.environ["SCANGUARD_DB"] = d + "/t.db"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from fastapi.testclient import TestClient
from app.main import app

with TestClient(app) as c:
    H = {"Authorization": "Bearer testtoken"}
    # report one
    r = c.post("/api/report", headers=H, json={
        "ip": "91.92.40.18", "rule": "php-scanner", "severity": "high",
        "hit_count": 60, "evidence": ["GET /wp-login.php"],
        "node_id": "node-a", "node_name": "A",
        "geo": {"country": "Bulgaria", "city": "Sofia", "isp": "BULLETGROUP"}
    })
    assert r.status_code == 200, r.text
    # duplicate from another node -> dedup + distinct_nodes
    c.post("/api/report", headers=H, json={
        "ip": "91.92.40.18", "rule": "path-traversal", "severity": "critical",
        "hit_count": 5, "evidence": ["/etc/passwd"], "node_id": "node-b", "node_name": "B",
        "geo": {"country": "Bulgaria"}
    })
    c.post("/api/report", headers=H, json={
        "ip": "203.0.113.7", "rule": "ssh-bruteforce", "severity": "medium",
        "hit_count": 12, "node_id": "node-a", "node_name": "A",
        "geo": {"country": "China", "isp": "CHINANET"}
    })
    # auth check
    assert c.post("/api/report", json={"ip":"x"}).status_code == 401
    # list
    lst = c.get("/api/threats").json()
    ips = {t["ip"] for t in lst}
    assert "91.92.40.18" in ips and "203.0.113.7" in ips, ips
    # detail + aggregation
    det = c.get("/api/threats/91.92.40.18").json()
    assert det["distinct_nodes"] == 2, det["distinct_nodes"]
    assert det["max_severity"] == "critical", det["max_severity"]
    assert "php-scanner" in det["rules"] and "path-traversal" in det["rules"]
    assert len(det["nodes"]) == 2 and len(det["events"]) == 2
    print("aggregate OK:", det["distinct_nodes"], "nodes,", det["total_hits"], "hits,", det["rules"])
    # stats
    s = c.get("/api/stats").json()
    assert s["total_ips"] == 2 and s["nodes"] == 2, s
    print("stats:", s)
    # blocklist formats
    bt = c.get("/blocklist.txt?min_severity=high").text
    assert "91.92.40.18" in bt and "203.0.113.7" not in bt  # medium excluded
    assert "91.92.40.18" in c.get("/blocklist.iptables").text
    nft = c.get("/blocklist.nftables").text
    assert "91.92.40.18" in nft and "table inet scanguard" in nft
    print("blocklists OK")
    # web ui
    assert "<title>ScanGuard" in c.get("/").text
    print("web UI OK")
print("ALL E2E TESTS PASSED")
