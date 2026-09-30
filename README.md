# Cloud Security Auditor

A Python tool that audits an AWS account for common cloud security misconfigurations, stores findings in SQLite, generates compliance reports, and sends real-time alerts on policy violations.

## Features

- **S3 auditing** — flags public buckets, missing encryption, disabled versioning/logging
- **IAM analysis** — detects overly permissive policies (wildcard `Action`/`Resource`) and unused policies
- **Findings history** — every scan's results are stored in SQLite for tracking over time
- **Compliance reports** — auto-generated CSV and styled HTML reports per scan
- **Real-time alerting** — console output plus optional Slack/email notifications for HIGH/CRITICAL findings

## Setup

```bash
pip install -r requirements.txt
```

Configure AWS credentials via `aws configure` (or environment variables / an IAM role if running on AWS infrastructure).

## Usage

```bash
# Try it with built-in fake data, no AWS account required
python main.py --mock

# Run against your real AWS account
python main.py
```

Each run prints a summary, writes `compliance_report.csv` and `compliance_report.html`, and stores results in `audit_findings.db`.

### Least-privilege IAM policy

`auditor_iam_policy.json` contains a read-only policy — attach it to whatever IAM user/role runs this tool so it can only read configuration, never modify anything.

### Alerting setup (optional)

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."

export SMTP_HOST="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USER="you@gmail.com"
export SMTP_PASSWORD="your-app-password"
export SMTP_FROM="you@gmail.com"
export SMTP_TO="you@gmail.com"
```

## Project structure

```
main.py                       entry point / CLI
db.py                         SQLite storage layer
s3_auditor.py                 S3 bucket checks
iam_analyzer.py               IAM policy checks
alerting.py                   console / Slack / email alerts
report_generator.py           CSV + HTML report generation
mock_data.py                  fake AWS responses for --mock mode
auditor_iam_policy.json       least-privilege policy for a real run
```

## Possible extensions

- Trigger via AWS Lambda on a schedule (EventBridge)
- React to AWS Config/CloudTrail events for true event-driven alerting
- Swap SQLite for DynamoDB/RDS at multi-account scale
- Add checks for security groups, EBS encryption, unused access keys, MFA enforcement
