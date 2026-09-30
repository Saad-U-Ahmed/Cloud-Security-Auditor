import argparse
import uuid

import boto3

import db
import s3_auditor
import iam_analyzer
import alerting
import report_generator


def get_session(use_mock: bool):
    # Only import mock_data when actually needed, so the real-AWS path
    # never depends on the test fixtures.
    if use_mock:
        import mock_data
        return mock_data.MockSession()
    return boto3.Session()


def print_summary(scan_id):
    findings = db.get_findings(scan_id=scan_id)
    failed = [f for f in findings if f["status"] == "FAIL"]
    print(f"\nScan {scan_id}: {len(findings)} checks run, {len(failed)} failed.\n")
    for f in failed:
        print(f"  [{f['severity']:8}] {f['resource_type']:10} {f['resource_id']:30} {f['check_name']}")


def main():
    parser = argparse.ArgumentParser(
        description="Audit AWS S3 and IAM for security misconfigurations."
    )
    parser.add_argument("--mock", action="store_true",
                         help="Run against built-in fake data (no AWS account needed).")
    args = parser.parse_args()

    db.init_db()
    scan_id = str(uuid.uuid4())[:8]  # short, readable ID for this run
    db.start_scan(scan_id)
    print(f"Starting scan {scan_id} ({'MOCK' if args.mock else 'LIVE'} mode)...")

    session = get_session(args.mock)

    print("\nAuditing S3 buckets...")
    s3_auditor.run_s3_audit(scan_id, session)

    print("Auditing IAM policies...")
    iam_analyzer.run_iam_audit(scan_id, session)

    all_findings = db.get_findings(scan_id=scan_id)
    failed = [f for f in all_findings if f["status"] == "FAIL"]
    db.finish_scan(scan_id, len(all_findings), len(failed))

    print_summary(scan_id)

    csv_path = report_generator.generate_csv(scan_id)
    html_path = report_generator.generate_html(scan_id)
    print(f"\nReports written: {csv_path}, {html_path}")

    alerting.alert_on_scan(scan_id)


if __name__ == "__main__":
    main()
