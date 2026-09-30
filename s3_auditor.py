import json

import boto3
from botocore.exceptions import ClientError

import db


def get_s3_client(session=None):
    # Accepting a session lets tests/mocks inject a fake session;
    # defaults to real AWS credentials otherwise.
    session = session or boto3.Session()
    return session.client("s3")


def list_buckets(s3_client):
    response = s3_client.list_buckets()
    return [b["Name"] for b in response.get("Buckets", [])]


def check_public_access_block(s3_client, bucket_name):
    try:
        resp = s3_client.get_public_access_block(Bucket=bucket_name)
        config = resp["PublicAccessBlockConfiguration"]
        all_blocked = all(config.values())
        return all_blocked, config
    except ClientError as e:
        # AWS throws this specific error when no config exists at all,
        # which means nothing is being blocked -> treat as a failure.
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False, {}
        raise


def check_bucket_policy_public(s3_client, bucket_name):
    try:
        resp = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(resp["Policy"])
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return False, None
        raise

    for statement in policy.get("Statement", []):
        principal = statement.get("Principal")
        effect = statement.get("Effect")
        # "*" or {"AWS": "*"} both mean "anyone on the internet"
        is_wildcard_principal = principal == "*" or principal == {"AWS": "*"}
        if effect == "Allow" and is_wildcard_principal:
            return True, policy
    return False, policy


def check_encryption(s3_client, bucket_name):
    try:
        resp = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = resp["ServerSideEncryptionConfiguration"]["Rules"]
        return True, rules
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return False, []
        raise


def check_versioning(s3_client, bucket_name):
    resp = s3_client.get_bucket_versioning(Bucket=bucket_name)
    status = resp.get("Status", "Disabled")
    return status == "Enabled", status


def check_logging(s3_client, bucket_name):
    resp = s3_client.get_bucket_logging(Bucket=bucket_name)
    enabled = "LoggingEnabled" in resp
    return enabled, resp.get("LoggingEnabled", {})


def audit_bucket(s3_client, bucket_name, scan_id):
    checks = []

    blocked, pab_config = check_public_access_block(s3_client, bucket_name)
    checks.append(("public_access_block", "CRITICAL", blocked,
                    f"Public Access Block fully enabled: {blocked}. Config: {pab_config}"))

    is_public, _policy = check_bucket_policy_public(s3_client, bucket_name)
    checks.append(("bucket_policy_public", "CRITICAL", not is_public,
                    "Bucket policy allows public (wildcard) access" if is_public
                    else "No public wildcard principal found in bucket policy"))

    encrypted, _enc_rules = check_encryption(s3_client, bucket_name)
    checks.append(("default_encryption", "HIGH", encrypted,
                    f"Default encryption enabled: {encrypted}"))

    versioned, v_status = check_versioning(s3_client, bucket_name)
    checks.append(("versioning", "MEDIUM", versioned,
                    f"Versioning status: {v_status}"))

    logged, _log_config = check_logging(s3_client, bucket_name)
    checks.append(("access_logging", "LOW", logged,
                    f"Access logging enabled: {logged}"))

    for check_name, severity, passed, description in checks:
        db.record_finding(
            scan_id=scan_id,
            resource_type="s3_bucket",
            resource_id=bucket_name,
            check_name=check_name,
            severity=severity,
            status="PASS" if passed else "FAIL",
            description=description,
        )

    return checks


def run_s3_audit(scan_id, session=None):
    s3 = get_s3_client(session)
    results = {}
    for bucket in list_buckets(s3):
        try:
            results[bucket] = audit_bucket(s3, bucket, scan_id)
        except ClientError as e:
            # Don't let one bad/inaccessible bucket kill the whole scan
            print(f"  ! Skipped {bucket}: {e.response['Error']['Message']}")
    return results
