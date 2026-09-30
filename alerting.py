import os
import smtplib
from email.message import EmailMessage

import requests

import db

# Only page/notify on the findings that actually need action -
# LOW/MEDIUM go in the report but shouldn't trigger an alert.
ALERT_SEVERITIES = {"HIGH", "CRITICAL"}


def get_actionable_findings(scan_id):
    findings = db.get_findings(scan_id=scan_id, status="FAIL")
    return [f for f in findings if f["severity"] in ALERT_SEVERITIES]


def format_alert_text(findings):
    lines = [f"{len(findings)} high-priority cloud security finding(s):"]
    for f in findings:
        lines.append(
            f"- [{f['severity']}] {f['resource_type']} '{f['resource_id']}' "
            f"failed check '{f['check_name']}': {f['description']}"
        )
    return "\n".join(lines)


def send_console_alert(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60 + "\n")


def send_slack_alert(text):
    # Slack alerting is optional - skip silently if not configured
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        return False
    resp = requests.post(webhook_url, json={"text": text}, timeout=10)
    return resp.status_code == 200


def send_email_alert(text):
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False

    msg = EmailMessage()
    msg["Subject"] = "Cloud Security Auditor - Policy Violation Alert"
    msg["From"] = os.environ["SMTP_FROM"]
    msg["To"] = os.environ["SMTP_TO"]
    msg.set_content(text)

    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587))) as server:
        server.starttls()
        server.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        server.send_message(msg)
    return True


def alert_on_scan(scan_id):
    findings = get_actionable_findings(scan_id)
    if not findings:
        print("No HIGH/CRITICAL findings this scan - nothing to alert on.")
        return

    text = format_alert_text(findings)
    send_console_alert(text)

    if send_slack_alert(text):
        print("Slack alert sent.")
    if send_email_alert(text):
        print("Email alert sent.")
