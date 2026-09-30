import csv
from datetime import datetime, timezone

import db

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#65a30d",
}


def generate_csv(scan_id, output_path="compliance_report.csv"):
    findings = db.get_findings(scan_id=scan_id)
    fieldnames = ["resource_type", "resource_id", "check_name",
                  "severity", "status", "description", "detected_at"]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in findings:
            writer.writerow({k: row[k] for k in fieldnames})
    return output_path


def generate_html(scan_id, output_path="compliance_report.html"):
    findings = db.get_findings(scan_id=scan_id)
    total = len(findings)
    failures = [f for f in findings if f["status"] == "FAIL"]

    rows_html = ""
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "#374151")
        status_badge = "FAIL" if f["status"] == "FAIL" else "PASS"
        badge_color = "#dc2626" if f["status"] == "FAIL" else "#16a34a"
        rows_html += f"""
        <tr>
            <td>{f['resource_type']}</td>
            <td>{f['resource_id']}</td>
            <td>{f['check_name']}</td>
            <td><span style="color:{color}; font-weight:bold">{f['severity']}</span></td>
            <td><span style="color:{badge_color}; font-weight:bold">{status_badge}</span></td>
            <td>{f['description']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Cloud Security Compliance Report</title>
<style>
  body {{ font-family: -apple-system, Arial, sans-serif; margin: 2rem; color: #111827; }}
  h1 {{ margin-bottom: 0; }}
  .subtitle {{ color: #6b7280; margin-top: 0.25rem; }}
  .summary {{ display: flex; gap: 1.5rem; margin: 1.5rem 0; }}
  .card {{ background: #f3f4f6; border-radius: 8px; padding: 1rem 1.5rem; }}
  .card .num {{ font-size: 1.75rem; font-weight: bold; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #e5e7eb; font-size: 0.9rem; }}
  th {{ background: #111827; color: white; }}
</style>
</head>
<body>
  <h1>Cloud Security Compliance Report</h1>
  <p class="subtitle">Scan ID: {scan_id} &middot; Generated {datetime.now(timezone.utc).isoformat()}</p>
  <div class="summary">
    <div class="card"><div class="num">{total}</div>Total checks</div>
    <div class="card"><div class="num" style="color:#dc2626">{len(failures)}</div>Failures</div>
    <div class="card"><div class="num" style="color:#16a34a">{total - len(failures)}</div>Passed</div>
  </div>
  <table>
    <tr>
      <th>Resource Type</th><th>Resource ID</th><th>Check</th>
      <th>Severity</th><th>Status</th><th>Details</th>
    </tr>
    {rows_html}
  </table>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    return output_path
