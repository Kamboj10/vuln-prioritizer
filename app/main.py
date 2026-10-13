import os
import json
import argparse
from dotenv import load_dotenv
from app.models import ServiceFinding
from app.services.nmap_scanner import NmapScanner
from app.services.nvd_lookup import NVDLookup
from app.services.enrich import Enricher
from app.services.ai_explainer import AIExplainer
from app.services.report import write_report

load_dotenv()

SAMPLE = [
    {"host":"127.0.0.1","port":21,"protocol":"tcp","service":"ftp","product":"vsftpd","version":"2.3.4","cpe":"cpe:/a:vsftpd:vsftpd:2.3.4"},
    {"host":"127.0.0.1","port":22,"protocol":"tcp","service":"ssh","product":"OpenSSH","version":"7.4","cpe":"cpe:/a:openbsd:openssh:7.4"},
    {"host":"127.0.0.1","port":80,"protocol":"tcp","service":"http","product":"Apache httpd","version":"2.4.49","cpe":"cpe:/a:apache:http_server:2.4.49"}
]

def keyword_for(item):
     product = item.get("product")
     version = item.get("version")
     if not product:
        return ""          # no identified software -> nothing meaningful to search
     return f"{product} {version}".strip()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", help="Target host you own/are authorized to scan")
    parser.add_argument("--sample", action="store_true", help="Use sample scan data")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI explanations")
    args = parser.parse_args()

    if args.sample:
        raw = SAMPLE
    elif args.target:
        raw = NmapScanner(args.target).scan()
    else:
        raise SystemExit("Provide --target or --sample")

    nvd = NVDLookup()
    enrich = Enricher()
    ai = AIExplainer()
    findings = []

    for item in raw:
        cves = nvd.search(keyword_for(item), max_results=5, cpe=item.get("cpe", ""))
        cve_ids = [c["id"] for c in cves]
        epss_map = enrich.epss_scores(cve_ids)
        kev_ids = enrich.kev_ids()
        kev_hit = any(cid in kev_ids for cid in cve_ids)
        max_epss = max(epss_map.values()) if epss_map else 0.0
        max_cvss = max([c["score"] for c in cves], default=0.0)
        priority = enrich.priority(
            severity="",
            score=max_cvss,
            epss=max_epss,
            kev=kev_hit,
            internet_facing=item["port"] in [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8080,8443]
        )
        score = max_cvss + (max_epss * 10) + (5 if kev_hit else 0)
        finding = ServiceFinding(
            host=item["host"],
            port=item["port"],
            protocol=item["protocol"],
            service=item["service"],
            product=item.get("product",""),
            version=item.get("version",""),
            cpe=item.get("cpe",""),
            cves=cves,
            kev=kev_hit,
            epss_score=max_epss,
            priority=priority,
            score=score
        )
        label = f"{item['service']} {item.get('product', '')} {item.get('version', '')} (port {item['port']})".strip()
        if args.no_ai:
            print(f"[AI] skipped (--no-ai): {label}")
        elif not ai.available():
            print(f"[AI] skipped (GEMINI_API_KEY not found): {label}")
        elif not cves:
            print(f"[AI] skipped (no CVEs found): {label}")
        else:
            try:
                explanation = ai.explain(item, cves)
                finding.ai_summary = explanation["summary"]
                finding.ai_fix = explanation["fix"]
                finding.ai_cves = explanation["cves"]
                finding.verified = explanation["verified"]
                print(f"[AI] explained OK, verified={explanation['verified']}: {label}")
            except Exception as e:
                print(f"[AI] FAILED for {label}: {e}")
        findings.append(finding)

    findings.sort(key=lambda x: x.score, reverse=True)
    os.makedirs("data", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    with open("data/results.json", "w") as f:
        json.dump([x.to_dict() for x in findings], f, indent=2)
    write_report([x.to_dict() for x in findings], "reports/vuln_report.html")
    print("Wrote data/results.json")
    print("Wrote reports/vuln_report.html")

if __name__ == "__main__":
    main()
