import os
import time
import requests
from typing import List, Dict, Optional


def cpe_to_23(cpe: str) -> str:
    """Nmap gives 'cpe:/a:apache:http_server:2.4.49'; NVD wants CPE 2.3 format."""
    if not cpe or not cpe.startswith("cpe:/"):
        return ""
    parts = cpe[5:].split(":")
    if len(parts) < 4:  # need part, vendor, product, version
        return ""
    parts += ["*"] * (11 - len(parts))
    return "cpe:2.3:" + ":".join(parts[:11])


class NVDLookup:
    def __init__(self):
        self.api_key = os.getenv("NVD_API_KEY")
        self.base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
        # No key: 5 requests / 30s -> one every 6s. With key: 50 / 30s.
        self.delay = 6.5 if not self.api_key else 0.7
        self._cache: Dict[str, List[Dict]] = {}

    def _get(self, params: Dict) -> Optional[Dict]:
        for attempt in range(5):
            r = self.session.get(self.base, params=params, timeout=30)
            if r.status_code in (403, 429, 503):
                try:
                    wait = int(r.headers.get("Retry-After", ""))
                except ValueError:
                    wait = 10 * (attempt + 1)
                print(f"  NVD rate limit hit, waiting {wait}s (attempt {attempt + 1}/5)...")
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        print("  NVD still refusing after retries, skipping this lookup.")
        return None

    def search(self, keyword: str, max_results: int = 10, cpe: str = "") -> List[Dict]:
        cpe23 = cpe_to_23(cpe)
        cache_key = cpe23 or keyword
        if not cache_key:
            return []
        if cache_key in self._cache:
            return self._cache[cache_key]

        items = []
        if cpe23:
            items = self._query({"cpeName": cpe23, "resultsPerPage": 100})
        if not items and keyword:
            items = self._query({"keywordSearch": keyword, "resultsPerPage": 20})

        # keep the worst CVEs, not just the first ones NVD returned
        items.sort(key=lambda c: c["score"], reverse=True)
        items = items[:max_results]
        self._cache[cache_key] = items
        return items

    def _query(self, params: Dict) -> List[Dict]:
        try:
            data = self._get(params)
        except requests.HTTPError as e:
            print(f"  NVD lookup failed ({e.response.status_code}), skipping.")
            data = None
        time.sleep(self.delay)
        if data is None:
            return []

        items = []
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            metrics = cve.get("metrics", {})
            severity = "UNKNOWN"
            score = 0.0
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {})
                    severity = cvss.get("baseSeverity") or metrics[key][0].get("baseSeverity", severity)
                    score = float(cvss.get("baseScore", 0.0))
                    break
            items.append({
                "id": cve_id,
                "description": desc,
                "severity": severity,
                "score": score,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return items