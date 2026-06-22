```python
import json
from pathlib import Path
from openpyxl import Workbook

REPORT_DIR = "/var/jenkins_home/reports/raw"

files = [
    "trivy-fs.json",
    "trivy-image.json"
]

summary = {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0
}

summary_json = {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
}

for report in files:
    path = f"{REPORT_DIR}/{report}"

    try:
        with open(path, "r") as f:
            data = json.load(f)

        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "").upper()

                if sev in summary:
                    summary[sev] += 1

    except Exception as e:
        print(f"Error reading {report}: {e}")

summary_json["critical"] = summary["CRITICAL"]
summary_json["high"] = summary["HIGH"]
summary_json["medium"] = summary["MEDIUM"]
summary_json["low"] = summary["LOW"]

Path("/var/jenkins_home/reports/final").mkdir(
    parents=True,
    exist_ok=True
)

# Generate JSON report

json_output = "/var/jenkins_home/reports/final/security-summary.json"

with open(json_output, "w") as f:
    json.dump(summary_json, f, indent=4)

print("JSON Summary generated:")
print(json_output)

# Generate Excel report

wb = Workbook()

ws = wb.active
ws.title = "Security Summary"

ws.append(["Severity", "Count"])

ws.append(["CRITICAL", summary["CRITICAL"]])
ws.append(["HIGH", summary["HIGH"]])
ws.append(["MEDIUM", summary["MEDIUM"]])
ws.append(["LOW", summary["LOW"]])

excel_output = "/var/jenkins_home/reports/final/security-report.xlsx"

wb.save(excel_output)

print("Excel Report generated:")
print(excel_output)

# Generate HTML report

html = f"""
<html>
<head>
<title>DevSecOps Security Report</title>
</head>
<body>

<h1>Security Summary</h1>

<table border="1" cellpadding="5" cellspacing="0">
<tr>
<th>Severity</th>
<th>Count</th>
</tr>

<tr><td>CRITICAL</td><td>{summary['CRITICAL']}</td></tr>
<tr><td>HIGH</td><td>{summary['HIGH']}</td></tr>
<tr><td>MEDIUM</td><td>{summary['MEDIUM']}</td></tr>
<tr><td>LOW</td><td>{summary['LOW']}</td></tr>

</table>

</body>
</html>
"""

html_output = "/var/jenkins_home/reports/final/security-report.html"

with open(html_output, "w") as f:
    f.write(html)

print("HTML Report generated:")
print(html_output)
```

