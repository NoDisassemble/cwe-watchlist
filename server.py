"""Serve the dashboard and proxy MITRE CWE API requests on the same origin.

Run: python server.py
Then open: http://localhost:8000
"""

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

MITRE_API = "https://cwe-api.mitre.org"
KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
EPSS_API = "https://api.first.org/data/v1/epss"
CACHE_FILE = Path(__file__).with_name(".watchlist-cache.json")
CACHE_MAX_AGE = timedelta(hours=24)


class DashboardHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/watchlist":
            self.send_json(get_threat_watchlist())
            return
        if self.path.startswith("/api/v1/"):
            self.proxy_request()
            return
        super().do_GET()

    def proxy_request(self):
        target_url = f"{MITRE_API}{self.path}"
        request = Request(target_url, headers={"Accept": "application/json", "User-Agent": "CWE-Watch/1.0"})

        try:
            with urlopen(request, timeout=20) as response:
                body = response.read()
                self.send_response(response.status)
                self.send_header("Content-Type", response.headers.get_content_type())
                self.send_header("Cache-Control", "public, max-age=300")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except HTTPError as error:
            body = error.read()
            self.send_response(error.code)
            self.send_header("Content-Type", error.headers.get_content_type() if error.headers else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except URLError:
            body = b'{"error":"Unable to reach the MITRE CWE API."}'
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def send_json(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def fetch_json(url):
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "CWE-Watch/1.0"})
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def epss_scores(cve_ids):
    """Return EPSS percentile values in batches to avoid oversized request URLs."""
    scores = {}
    for start in range(0, len(cve_ids), 100):
        query = urlencode({"cve": ",".join(cve_ids[start:start + 100])})
        try:
            data = fetch_json(f"{EPSS_API}?{query}")
            scores.update({item["cve"]: float(item["percentile"]) for item in data.get("data", [])})
        except (HTTPError, URLError, KeyError, ValueError):
            # KEV evidence still produces a useful ranking if EPSS is temporarily unavailable.
            continue
    return scores


def get_threat_watchlist():
    """Rank CWEs using CISA active-exploitation evidence plus EPSS likelihood."""
    if CACHE_FILE.exists():
        cached = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        created = datetime.fromisoformat(cached["created_at"])
        if datetime.now(timezone.utc) - created < CACHE_MAX_AGE:
            return cached["data"]

    catalog = None
    for url in KEV_URLS:
        try:
            catalog = fetch_json(url)
            break
        except (HTTPError, URLError):
            continue
    if catalog is None:
        return {"items": [], "error": "Unable to load the CISA KEV catalog."}

    cutoff = datetime.now(timezone.utc).date() - timedelta(days=365)
    groups = defaultdict(lambda: {"cves": [], "ransomware": 0, "recent": 0})
    for vulnerability in catalog.get("vulnerabilities", []):
        cve_id = vulnerability.get("cveID")
        if not cve_id:
            continue
        is_recent = vulnerability.get("dateAdded", "") >= cutoff.isoformat()
        is_ransomware = vulnerability.get("knownRansomwareCampaignUse") == "Known"
        for cwe in vulnerability.get("cwes", []):
            if not cwe.startswith("CWE-"):
                continue
            group = groups[cwe]
            group["cves"].append(cve_id)
            group["ransomware"] += int(is_ransomware)
            group["recent"] += int(is_recent)

    # CISA KEV is the primary signal: every count represents a CVE exploited in the wild.
    ranked = sorted(groups.items(), key=lambda pair: len(pair[1]["cves"]) * 10 + pair[1]["ransomware"] * 20 + pair[1]["recent"] * 25, reverse=True)[:5]
    cve_ids = list({cve for _, group in ranked for cve in group["cves"]})
    epss = epss_scores(cve_ids)
    items = []
    for cwe, group in ranked:
        percentiles = [epss[cve] for cve in group["cves"] if cve in epss]
        average_epss = sum(percentiles) / len(percentiles) if percentiles else 0
        kev_count = len(group["cves"])
        score = kev_count * 10 + group["ransomware"] * 20 + group["recent"] * 25 + round(average_epss * 10, 1)
        items.append({
            "id": cwe.replace("CWE-", "", 1), "kev_count": kev_count,
            "ransomware_count": group["ransomware"], "recent_count": group["recent"],
            "epss_percentile": round(average_epss * 100, 1), "threat_score": round(score, 1),
        })

    data = {"items": items, "catalog_date": catalog.get("dateReleased"), "method": "CISA KEV + EPSS"}
    CACHE_FILE.write_text(json.dumps({"created_at": datetime.now(timezone.utc).isoformat(), "data": data}), encoding="utf-8")
    return data


if __name__ == "__main__":
    server = ThreadingHTTPServer(("", 8000), DashboardHandler)
    print("CWE Watch is available at http://localhost:8000")
    server.serve_forever()
