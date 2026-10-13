from pathlib import Path
from jinja2 import Template
from datetime import datetime

HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Vuln Prioritizer Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 30px; background: #f7f7f7; color: #222; }
    h1 { margin-bottom: 5px; }
    .meta { color: #666; margin-bottom: 20px; }
    .card { background: white; padding: 18px; margin-bottom: 16px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
    .fix_now { border-left: 6px solid #d9534f; }
    .fix_soon { border-left: 6px solid #f0ad4e; }
    .later { border-left: 6px solid #5bc0de; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 6px; color: white; font-size: 12px; margin-right: 6px; }
    .kev { background: #b30000; }
    .epss { background: #555; }
    .cve { background: #337ab7; }
    pre { white-space: pre-wrap; background: #f4f4f4; padding: 10px; border-radius: 6px; }
    .ok { color: green; font-weight: bold; }
    .bad { color: red; font-weight: bold; }
  </style>
</head>
<body>
  <h1>Vuln Prioritizer Report</h1>
  <div class="meta">Generated: {{ generated_at }}</div>
  {% for item in findings %}
  <div class="card {{ item.priority }}">
    <h2>{{ item.service }} {{ item.product }} {{ item.version }} — port {{ item.port }}/{{ item.protocol }}</h2>
    <p>
      <span class="badge {{ item.priority }}">{{ item.priority.replace('_', ' ').upper() }}</span>
      {% if item.kev %}<span class="badge kev">CISA KEV</span>{% endif %}
      <span class="badge epss">EPSS {{ '%.2f'|format(item.epss_score) }}</span>
    </p>
    <p><strong>Host:</strong> {{ item.host }}</p>
    <p><strong>Score:</strong> {{ '%.1f'|format(item.score) }}</p>
    {% if item.ai_summary %}
      <p><strong>AI Summary:</strong> {{ item.ai_summary }}</p>
      <p><strong>Fix:</strong></p>
      <pre>{{ item.ai_fix }}</pre>
      <p><strong>AI CVE verification:</strong>
        {% if item.verified %}<span class="ok">passed</span>{% else %}<span class="bad">failed / hallucination removed</span>{% endif %}
      </p>
    {% endif %}
    <h3>Confirmed CVEs</h3>
    <ul>
      {% for cve in item.cves %}
        <li>
          <span class="badge cve">{{ cve.id }}</span>
          {{ cve.severity }} / {{ cve.score }} — {{ cve.description }}
          <br><a href="{{ cve.url }}">{{ cve.url }}</a>
        </li>
      {% endfor %}
    </ul>
  </div>
  {% endfor %}
</body>
</html>
"""

def write_report(findings: list, output_path: str):
    template = Template(HTML)
    html = template.render(findings=findings, generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(html)
