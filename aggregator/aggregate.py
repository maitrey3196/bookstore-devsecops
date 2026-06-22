import json
from pathlib import Path

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

html = f"""
<html>
<head>
<title>DevSecOps Security Report</title>
</head>
<body>
<h1>Security Summary</h1>

<table border="1">
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

output = "/var/jenkins_home/reports/final/security-report.html"

Path("/var/jenkins_home/reports/final").mkdir(
    parents=True,
    exist_ok=True
)

with open(output, "w") as f:
    f.write(html)

print("Report generated:")
print(output)
