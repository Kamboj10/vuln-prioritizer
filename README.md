# Vuln Prioritizer

A working local security tool that:

1. scans a machine you own with Nmap
2. extracts open ports, services, and versions
3. looks up real CVEs from NVD
4. enriches results with CISA KEV and EPSS
5. ranks what to fix first
6. optionally uses AI to explain each confirmed CVE in plain English
7. verifies that the AI only used real CVE IDs from the lookup
8. writes an HTML report

## Why this is useful
A normal scanner says:
- port 21 GEMINI_API_KEY
- vsftpd 2.3.4

This tool turns that into:
- confirmed CVEs
- exploit likelihood
- whether attackers are already exploiting it
- what to fix first
- exact patch guidance

## Important
Use this only on machines you own or are authorized to test.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

### Scan localhost
```bash
python -m app.main --target 127.0.0.1
```

### Scan another authorized host
```bash
python -m app.main --target 192.168.1.20
```

### Skip AI explanation
```bash
python -m app.main --target 127.0.0.1 --no-ai
```

### Use sample data without scanning
```bash
python -m app.main --sample
```

## Output
- JSON results: `data/results.json`
- HTML report: `reports/vuln_report.html`

## How ranking works
Each finding gets a score from:
- CVE severity
- EPSS exploit probability
- CISA KEV presence
- internet-facing exposure heuristics

Priority bands:
- `fix_now`
- `fix_soon`
- `later`

## AI safety design
The AI is not used to invent vulnerabilities.
It only explains CVEs already returned by NVD.
After generation, the app checks every CVE mentioned by the AI against the confirmed CVE list and removes hallucinated IDs.

## Project structure
```text
app/
  main.py
  models.py
  services/
    nmap_scanner.py
    nvd_lookup.py
    enrich.py
    ai_explainer.py
    report.py
data/
reports/
```

## Notes
- Nmap must be installed on your system.
- NVD works without an API key, but a key is better for rate limits.
- If no AI key is provided, the tool still works and generates a technical report without AI explanations.
