import os
import time
import re
import json
import requests
from typing import List, Dict


class AIExplainer:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent"
        )

    def available(self) -> bool:
        return bool(self.api_key)

    def explain(self, service: Dict, cves: List[Dict]) -> Dict:
        if not self.available():
            return {"summary": "", "fix": "", "cves": [], "verified": False}

        prompt = f"""
You are a security remediation assistant.
Use ONLY the CVEs provided below. Do not invent CVE IDs.
Service: {service.get('service')} {service.get('product')} {service.get('version')} on port {service.get('port')}
CVEs:
{json.dumps(cves, indent=2)}

Return strict JSON with keys:
- summary: one plain-English sentence explaining the risk
- fix: exact practical remediation steps
- cves: array of CVE IDs you used from the provided list
"""
        headers = {
            "x-goog-api-key": self.api_key,
            "Content-Type": "application/json",
        }
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0,
                "responseMimeType": "application/json",
            },
        }

        r = None
        for attempt in range(4):
            r = requests.post(self.endpoint, headers=headers, json=payload, timeout=60)
            if r.status_code in (429, 500, 502, 503, 504):
                wait = 5 * (attempt + 1)
                print(f"  Gemini busy ({r.status_code}), retrying in {wait}s...")
                time.sleep(wait)
                continue
            break
        r.raise_for_status()

        # Safety net in case the model wraps the JSON in code fences anyway
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?", "", text).strip()
            text = re.sub(r"```$", "", text).strip()

        data = json.loads(text)
        mentioned = set(re.findall(r"CVE-\d{4}-\d{4,7}", json.dumps(data)))
        allowed = {c["id"] for c in cves}
        verified = mentioned.issubset(allowed)
        return {
            "summary": data.get("summary", ""),
            "fix": data.get("fix", ""),
            "cves": sorted(mentioned & allowed),  # drops any invented CVE IDs
            "verified": verified,
        }