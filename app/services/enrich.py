import requests
from typing import Dict, List

class Enricher:
    def __init__(self):
        self.kev_url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
        self.epss_url = "https://api.first.org/data/v1/epss"
        self._kev_ids = None
        self._epss_cache = {}

    def kev_ids(self) -> set:
        if self._kev_ids is not None:
            return self._kev_ids
        r = requests.get(self.kev_url, timeout=30)
        r.raise_for_status()
        lines = r.text.splitlines()
        ids = set()
        for line in lines[1:]:
            parts = line.split(",")
            if parts:
                ids.add(parts[0].strip().upper())
        self._kev_ids = ids
        return ids

    def epss_scores(self, cve_ids: List[str]) -> Dict[str, float]:
        if not cve_ids:
            return {}
        missing = [c for c in cve_ids if c not in self._epss_cache]
        for i in range(0, len(missing), 100):
            chunk = missing[i:i+100]
            r = requests.get(self.epss_url, params={"cve": ",".join(chunk)}, timeout=30)
            r.raise_for_status()
            for item in r.json().get("data", []):
                self._epss_cache[item["cve"]] = float(item.get("epss", 0.0))
        return {c: self._epss_cache.get(c, 0.0) for c in cve_ids}

    def priority(self, severity: str, score: float, epss: float, kev: bool, internet_facing: bool = False) -> str:
        value = score + (epss * 10) + (5 if kev else 0) + (2 if internet_facing else 0)
        if value >= 12:
            return "fix_now"
        if value >= 7:
            return "fix_soon"
        return "later"
