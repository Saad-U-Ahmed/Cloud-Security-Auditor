import boto3

import db

# "*" = every action on every service. "iam:*" = full control over
# permissions themselves, which is effectively the same as full admin.
HIGH_RISK_ACTIONS = {"*", "iam:*"}


def get_iam_client(session=None):
    session = session or boto3.Session()
    return session.client("iam")


def list_customer_managed_policies(iam_client):
    # Scope="Local" = policies this account created, excluding AWS's
    # own built-in managed policies. Paginator loops through all pages
    # automatically since IAM caps results per call.
    paginator = iam_client.get_paginator("list_policies")
    policies = []
    for page in paginator.paginate(Scope="Local"):
        policies.extend(page["Policies"])
    return policies


def get_policy_document(iam_client, policy_arn, version_id):
    resp = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    return resp["PolicyVersion"]["Document"]


def _as_list(value):
    # IAM allows a single string or a list of strings for Action/Resource
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def find_wildcard_statements(policy_document):
    problems = []
    for statement in _as_list(policy_document.get("Statement")):
        # Deny statements aren't a risk, only Allow statements are
        if statement.get("Effect") != "Allow":
            continue
        actions = _as_list(statement.get("Action"))
        resources = _as_list(statement.get("Resource"))
        wildcard_action = any(a in HIGH_RISK_ACTIONS for a in actions)
        wildcard_resource = "*" in resources
        if wildcard_action or wildcard_resource:
            problems.append({
                "sid": statement.get("Sid", "(no Sid)"),
                "actions": actions,
                "resources": resources,
                "wildcard_action": wildcard_action,
                "wildcard_resource": wildcard_resource,
            })
    return problems


def audit_policy(iam_client, policy_meta, scan_id):
    policy_arn = policy_meta["Arn"]
    policy_name = policy_meta["PolicyName"]
    version_id = policy_meta["DefaultVersionId"]

    document = get_policy_document(iam_client, policy_arn, version_id)
    problems = find_wildcard_statements(document)

    passed = len(problems) == 0
    if passed:
        description = "No wildcard Action/Resource combinations found."
    else:
        summary = "; ".join(
            f"[{p['sid']}] action*={p['wildcard_action']} resource*={p['wildcard_resource']}"
            for p in problems
        )
        description = f"Overly permissive statement(s) in '{policy_name}': {summary}"

    db.record_finding(
        scan_id=scan_id,
        resource_type="iam_policy",
        resource_id=policy_arn,
        check_name="wildcard_permissions",
        severity="CRITICAL" if not passed else "LOW",
        status="PASS" if passed else "FAIL",
        description=description,
    )

    attached = policy_meta.get("AttachmentCount", 0) > 0
    db.record_finding(
        scan_id=scan_id,
        resource_type="iam_policy",
        resource_id=policy_arn,
        check_name="policy_in_use",
        severity="LOW",
        status="PASS" if attached else "FAIL",
        description=f"Policy '{policy_name}' attachment count: {policy_meta.get('AttachmentCount', 0)}",
    )

    return problems


def run_iam_audit(scan_id, session=None):
    iam = get_iam_client(session)
    results = {}
    for policy in list_customer_managed_policies(iam):
        results[policy["PolicyName"]] = audit_policy(iam, policy, scan_id)
    return results
