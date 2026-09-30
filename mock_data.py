# Fake boto3-compatible clients so main.py --mock can run without real
# AWS credentials. Each method mirrors the real boto3 method it replaces.

from botocore.exceptions import ClientError


class MockS3Client:
    # Three fake buckets, each deliberately built to exercise a
    # different path: one well-configured, one public, one neglected.
    def list_buckets(self):
        return {"Buckets": [
            {"Name": "company-secure-backups"},
            {"Name": "public-website-assets"},
            {"Name": "legacy-data-dump"},
        ]}

    def get_public_access_block(self, Bucket):
        if Bucket == "public-website-assets":
            raise ClientError(
                {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "not found"}},
                "GetPublicAccessBlock",
            )
        return {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        }}

    def get_bucket_policy(self, Bucket):
        if Bucket == "public-website-assets":
            import json
            policy = {"Statement": [{
                "Sid": "PublicReadGetObject", "Effect": "Allow",
                "Principal": "*", "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-website-assets/*",
            }]}
            return {"Policy": json.dumps(policy)}
        raise ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": "not found"}},
            "GetBucketPolicy",
        )

    def get_bucket_encryption(self, Bucket):
        if Bucket == "legacy-data-dump":
            raise ClientError(
                {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "not found"}},
                "GetBucketEncryption",
            )
        return {"ServerSideEncryptionConfiguration": {"Rules": [
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
        ]}}

    def get_bucket_versioning(self, Bucket):
        status = "Disabled" if Bucket == "legacy-data-dump" else "Enabled"
        return {"Status": status}

    def get_bucket_logging(self, Bucket):
        if Bucket == "company-secure-backups":
            return {"LoggingEnabled": {"TargetBucket": "audit-logs", "TargetPrefix": "s3/"}}
        return {}


class MockPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class MockIAMClient:
    def get_paginator(self, operation_name):
        if operation_name == "list_policies":
            return MockPaginator([{"Policies": [
                {"PolicyName": "AdminFullAccess",
                 "Arn": "arn:aws:iam::111111111111:policy/AdminFullAccess",
                 "DefaultVersionId": "v1", "AttachmentCount": 2},
                {"PolicyName": "ReadOnlyS3",
                 "Arn": "arn:aws:iam::111111111111:policy/ReadOnlyS3",
                 "DefaultVersionId": "v1", "AttachmentCount": 1},
                {"PolicyName": "UnusedLegacyPolicy",
                 "Arn": "arn:aws:iam::111111111111:policy/UnusedLegacyPolicy",
                 "DefaultVersionId": "v1", "AttachmentCount": 0},
            ]}])
        raise NotImplementedError(operation_name)

    def get_policy_version(self, PolicyArn, VersionId):
        documents = {
            "arn:aws:iam::111111111111:policy/AdminFullAccess": {
                "Statement": [{"Sid": "FullAdmin", "Effect": "Allow",
                                "Action": "*", "Resource": "*"}]
            },
            "arn:aws:iam::111111111111:policy/ReadOnlyS3": {
                "Statement": [{"Sid": "S3Read", "Effect": "Allow",
                                "Action": ["s3:GetObject", "s3:ListBucket"],
                                "Resource": "arn:aws:s3:::company-secure-backups/*"}]
            },
            "arn:aws:iam::111111111111:policy/UnusedLegacyPolicy": {
                "Statement": [{"Sid": "OldFullAccess", "Effect": "Allow",
                                "Action": "s3:*", "Resource": "*"}]
            },
        }
        return {"PolicyVersion": {"Document": documents[PolicyArn]}}


class MockSession:
    def client(self, service_name):
        if service_name == "s3":
            return MockS3Client()
        if service_name == "iam":
            return MockIAMClient()
        raise NotImplementedError(service_name)
