"""
Security Agent Lambda — Full Capabilities
Uses Vertex AI REST API for intelligent analysis.

CHECKS PERFORMED:
1.  CloudTrail Error Events (failed/denied API calls)
2.  CloudTrail SCP Denied Events
3.  Security Hub Active Findings
4.  GuardDuty Findings
5.  Unusual API Activity (new regions, unusual hours)
6.  Root Account Usage Detection
7.  IAM Changes (policy modifications, new users/roles)
8.  Public Resource Exposure (S3, SG, RDS, EC2)
9.  Access Key Usage Anomalies
10. AssumeRole Chain Investigation
11. Failed Login Attempts (Console sign-in failures)
12. Resource Deletion Events

ENV VARS:
    GCP_PROJECT_ID, GCP_LOCATION, GCP_MODEL_ID, GCP_SA_KEY
    CROSS_ACCOUNT_ROLE_NAME, DEFAULT_TARGET_ACCOUNT_ID
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from collections import Counter

import boto3
import requests
from google.oauth2 import service_account
from google.auth.transport.requests import Request

# ── LOGGING ───────────────────────────────────────────────────
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── ENV VARS ──────────────────────────────────────────────────
PROJECT_ID              = os.environ['GCP_PROJECT_ID']
LOCATION                = os.environ['GCP_LOCATION']
MODEL_ID                = os.environ['GCP_MODEL_ID']
SERVICE_ACCOUNT_JSON    = json.loads(os.environ['GCP_SA_KEY'])
CROSS_ACCOUNT_ROLE_NAME = os.environ['CROSS_ACCOUNT_ROLE_NAME']
DEFAULT_ACCOUNT_ID      = os.environ['DEFAULT_TARGET_ACCOUNT_ID']

# ── SERVICE TO RESOURCE TYPE MAPPING ──────────────────────────
_SERVICE_TO_RESOURCE_TYPE = {
    "ec2":    "AwsEc2Instance",
    "s3":     "AwsS3Bucket",
    "iam":    "AwsIamRole",
    "rds":    "AwsRdsDbInstance",
    "lambda": "AwsLambdaFunction",
}

# ── SENSITIVE IAM ACTIONS ─────────────────────────────────────
SENSITIVE_IAM_ACTIONS = [
    "CreateUser", "DeleteUser", "CreateRole", "DeleteRole",
    "AttachUserPolicy", "DetachUserPolicy", "AttachRolePolicy", "DetachRolePolicy",
    "PutUserPolicy", "PutRolePolicy", "DeleteUserPolicy", "DeleteRolePolicy",
    "CreateAccessKey", "DeleteAccessKey",
    "CreateLoginProfile", "UpdateLoginProfile", "DeleteLoginProfile",
    "AddUserToGroup", "RemoveUserFromGroup",
    "UpdateAssumeRolePolicy",
    "CreatePolicy", "DeletePolicy", "CreatePolicyVersion",
]

# ── DANGEROUS DELETION ACTIONS ────────────────────────────────
DELETION_ACTIONS = [
    "TerminateInstances", "DeleteBucket", "DeleteDBInstance",
    "DeleteFunction", "DeleteTable", "DeleteStack",
    "DeleteVolume", "DeleteSnapshot", "DeleteSecurityGroup",
    "DeleteVpc", "DeleteSubnet", "DeleteCluster",
    "DeregisterImage", "ReleaseAddress",
]

# ── VERTEX AI AUTH ────────────────────────────────────────────
def get_access_token():
    credentials = service_account.Credentials.from_service_account_info(
        SERVICE_ACCOUNT_JSON,
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    credentials.refresh(Request())
    return credentials.token

# ── VERTEX AI CALL ────────────────────────────────────────────
def call_vertex(prompt: str) -> dict:
    token = get_access_token()

    url = (
        f"https://{LOCATION}-aiplatform.googleapis.com/v1/"
        f"projects/{PROJECT_ID}/locations/{LOCATION}/"
        f"publishers/google/models/{MODEL_ID}:generateContent"
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json"
    }

    payload = {
        "contents": [
            {
                "role":  "user",
                "parts": [{"text": prompt}]
            }
        ],
        "generationConfig": {
            "temperature":      0.1,
            "responseMimeType": "application/json"
        }
    }

    response = requests.post(url, headers=headers, json=payload, timeout=120)

    if not response.ok:
        raise ValueError(f"Vertex AI error {response.status_code}: {response.text}")

    data = response.json()

    try:
        raw_text = data['candidates'][0]['content']['parts'][0]['text']
        logger.info(f"[DEBUG] Vertex raw response: {raw_text[:500]}")
    except (KeyError, IndexError):
        raise ValueError(f"Unexpected Vertex response: {json.dumps(data)}")

    raw_text = raw_text.strip()
    if raw_text.startswith("```"):
        raw_text = raw_text.strip("`").strip()
        if raw_text.startswith("json"):
            raw_text = raw_text[4:].strip()

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        raise ValueError(f"Model returned invalid JSON: {raw_text}")

# ── QUERY INTENT CLASSIFICATION ───────────────────────────────
def classify_query_intent(query: str) -> dict:
    prompt = f"""You are a security query analyzer for AWS infrastructure.

The user asked: "{query}"

Decide which security checks are RELEVANT to answer this query.

Available checks:
- "cloudtrail_errors": Failed/denied API calls in CloudTrail
- "scp_denials": Service Control Policy denied events in CloudTrail
- "security_hub": Active Security Hub findings and vulnerabilities
- "guardduty": GuardDuty threat detection findings
- "unusual_activity": API calls from unusual regions or at unusual hours
- "root_usage": Root account API activity detection
- "iam_changes": Recent IAM modifications (new users, policy changes, role changes)
- "public_exposure": Publicly accessible resources (S3, Security Groups, RDS, EC2)
- "access_key_anomalies": Access key usage from unusual IPs or regions
- "assume_role_chains": AssumeRole events and cross-account access patterns
- "failed_logins": Failed console sign-in attempts
- "resource_deletions": Recent resource deletion events

Rules:
- Only include checks DIRECTLY relevant to the user's query
- If query is GENERAL ("any threats?", "security status", "full audit") include ALL checks
- "SCP" or "blocked" or "denied" → include "scp_denials" and "cloudtrail_errors"
- "who accessed" or "who did" → include "cloudtrail_errors" and "assume_role_chains"
- "public" or "exposed" → include "public_exposure"

Return ONLY this JSON:
{{
  "checks_to_run": ["cloudtrail_errors", "security_hub"],
  "query_summary": "one line summary",
  "service_focus": "ec2 or s3 or iam or all",
  "lookback_hours": 24
}}
"""
    try:
        result = call_vertex(prompt)
        logger.info(f"[INFO] Query intent: {result}")
        return result
    except Exception as e:
        logger.warning(f"[WARN] Intent classification failed: {str(e)} — running all checks")
        return {
            "checks_to_run": ["cloudtrail_errors", "scp_denials", "security_hub", "guardduty",
                              "unusual_activity", "root_usage", "iam_changes", "public_exposure",
                              "access_key_anomalies", "assume_role_chains", "failed_logins",
                              "resource_deletions"],
            "query_summary": query,
            "service_focus": "all",
            "lookback_hours": 24
        }

# ── SERVICE EXTRACTION ────────────────────────────────────────
def extract_service_from_query(query: str) -> str:
    query_lower = query.lower()
    service_keywords = {
        "ec2":    ["ec2", "instance", "server", "compute"],
        "s3":     ["s3", "bucket", "storage", "object"],
        "iam":    ["iam", "role", "user", "permission", "credential", "access key"],
        "rds":    ["rds", "database", "db", "mysql", "postgres"],
        "lambda": ["lambda", "function", "serverless"],
        "vpc":    ["vpc", "subnet", "security group", "network"],
    }
    for service, keywords in service_keywords.items():
        if any(kw in query_lower for kw in keywords):
            return service
    return "all"

# ── CROSS ACCOUNT ROLE ASSUMPTION ─────────────────────────────
def assume_role_session(account_id: str) -> boto3.Session:
    try:
        sts  = boto3.client("sts")
        resp = sts.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}",
            RoleSessionName="aegis-security-investigation",
        )
        creds = resp["Credentials"]
        logger.info(f"[INFO] Assumed role in account {account_id}")
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except Exception as e:
        logger.error(f"[ERROR] Failed to assume role: {str(e)}")
        raise

# ══════════════════════════════════════════════════════════════
# HELPER: FETCH CLOUDTRAIL EVENTS
# ══════════════════════════════════════════════════════════════
def fetch_cloudtrail_events(session: boto3.Session, lookback_hours: int, lookup_attributes: list = None, max_results: int = 50) -> list:
    """
    Generic CloudTrail event fetcher.
    Returns list of parsed event dicts.
    """
    try:
        ct       = session.client("cloudtrail")
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=lookback_hours)

        kwargs = {
            "StartTime":  start_time,
            "EndTime":    end_time,
            "MaxResults": max_results,
        }
        if lookup_attributes:
            kwargs["LookupAttributes"] = lookup_attributes

        raw_events = ct.lookup_events(**kwargs).get("Events", [])

        parsed = []
        for e in raw_events:
            detail = json.loads(e.get("CloudTrailEvent", "{}"))
            parsed.append({
                "event_name":    e.get("EventName"),
                "event_time":    str(e.get("EventTime")),
                "username":      e.get("Username", "unknown"),
                "event_source":  detail.get("eventSource", ""),
                "source_ip":     detail.get("sourceIPAddress", ""),
                "aws_region":    detail.get("awsRegion", ""),
                "user_agent":    detail.get("userAgent", ""),
                "error_code":    detail.get("errorCode"),
                "error_message": detail.get("errorMessage"),
                "request_params": detail.get("requestParameters"),
                "user_identity": detail.get("userIdentity", {}),
            })

        return parsed
    except Exception as e:
        logger.error(f"[ERROR] CloudTrail fetch failed: {str(e)}")
        return []

# ══════════════════════════════════════════════════════════════
# CHECK 1: CLOUDTRAIL ERROR EVENTS
# ══════════════════════════════════════════════════════════════
def check_cloudtrail_errors(session: boto3.Session, service: str, lookback_hours: int) -> dict:
    try:
        lookup = []
        if service != "all":
            lookup = [{"AttributeKey": "EventSource", "AttributeValue": f"{service.lower()}.amazonaws.com"}]

        all_events = fetch_cloudtrail_events(session, lookback_hours, lookup, max_results=100)
        error_events = [e for e in all_events if e.get("error_code")]

        # Group by error code
        error_summary = Counter(e["error_code"] for e in error_events)

        logger.info(f"[INFO] CloudTrail errors: {len(error_events)} error events")
        return {
            "check":           "cloudtrail_errors",
            "violations":      error_events[:20],
            "violation_count": len(error_events),
            "error_summary":   dict(error_summary),
            "total_events":    len(all_events),
            "lookback_hours":  lookback_hours,
        }
    except Exception as e:
        logger.error(f"[ERROR] CloudTrail errors check failed: {str(e)}")
        return {"check": "cloudtrail_errors", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 2: SCP DENIED EVENTS
# ══════════════════════════════════════════════════════════════
def check_scp_denials(session: boto3.Session, lookback_hours: int) -> dict:
    try:
        all_events = fetch_cloudtrail_events(session, lookback_hours, max_results=200)

        scp_denied = []
        for e in all_events:
            error_code = e.get("error_code", "")
            error_msg  = e.get("error_message", "") or ""

            # SCP denials show as AccessDenied with specific messages
            is_scp = (
                error_code in ("AccessDenied", "Client.UnauthorizedAccess", "UnauthorizedAccess")
                and any(kw in error_msg.lower() for kw in
                        ["service control policy", "scp", "organization", "explicit deny"])
            )

            # Also catch general AccessDenied that could be SCP
            is_access_denied = error_code in ("AccessDenied", "Client.UnauthorizedAccess")

            if is_scp or is_access_denied:
                scp_denied.append({
                    "event_name":    e.get("event_name"),
                    "event_time":    e.get("event_time"),
                    "username":      e.get("username"),
                    "source_ip":     e.get("source_ip"),
                    "aws_region":    e.get("aws_region"),
                    "error_code":    error_code,
                    "error_message": error_msg[:200],
                    "event_source":  e.get("event_source"),
                    "is_likely_scp": is_scp,
                })

        logger.info(f"[INFO] SCP denials: {len(scp_denied)} denied events")
        return {
            "check":           "scp_denials",
            "violations":      scp_denied[:20],
            "violation_count": len(scp_denied),
            "lookback_hours":  lookback_hours,
        }
    except Exception as e:
        logger.error(f"[ERROR] SCP denials check failed: {str(e)}")
        return {"check": "scp_denials", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 3: SECURITY HUB FINDINGS
# ══════════════════════════════════════════════════════════════
def check_security_hub(session: boto3.Session, account_id: str, service: str, lookback_hours: int) -> dict:
    try:
        sh = session.client("securityhub")
        updated_after = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        now_str       = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        filters = {
            "AwsAccountId":   [{"Value": account_id, "Comparison": "EQUALS"}],
            "RecordState":    [{"Value": "ACTIVE",    "Comparison": "EQUALS"}],
            "WorkflowStatus": [
                {"Value": "NEW",      "Comparison": "EQUALS"},
                {"Value": "NOTIFIED", "Comparison": "EQUALS"},
            ],
            "UpdatedAt": [{"Start": updated_after, "End": now_str}],
        }

        if service != "all":
            resource_type = _SERVICE_TO_RESOURCE_TYPE.get(service.lower())
            if resource_type:
                filters["ResourceType"] = [{"Value": resource_type, "Comparison": "EQUALS"}]

        findings  = []
        paginator = sh.get_paginator("get_findings")
        for page in paginator.paginate(
            Filters=filters,
            SortCriteria=[{"Field": "SeverityLabel", "SortOrder": "desc"}],
            PaginationConfig={"MaxItems": 50},
        ):
            findings.extend(page.get("Findings", []))

        # Group by severity
        severity_counts = Counter(f.get("Severity", {}).get("Label", "UNKNOWN") for f in findings)

        parsed = [
            {
                "title":           f.get("Title"),
                "severity":        f.get("Severity", {}).get("Label"),
                "resource_type":   [r.get("Type") for r in f.get("Resources", [])],
                "resource_id":     [r.get("Id") for r in f.get("Resources", [])],
                "description":     f.get("Description", "")[:200],
                "workflow_status": f.get("Workflow", {}).get("Status"),
                "generator_id":   f.get("GeneratorId", ""),
            }
            for f in findings
        ]

        logger.info(f"[INFO] Security Hub: {len(findings)} findings | Severities: {dict(severity_counts)}")
        return {
            "check":            "security_hub",
            "violations":       parsed[:20],
            "violation_count":  len(findings),
            "severity_summary": dict(severity_counts),
            "lookback_hours":   lookback_hours,
        }
    except Exception as e:
        logger.error(f"[ERROR] Security Hub check failed: {str(e)}")
        return {"check": "security_hub", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 4: GUARDDUTY FINDINGS
# ══════════════════════════════════════════════════════════════
def check_guardduty(session: boto3.Session) -> dict:
    try:
        gd = session.client("guardduty")

        # Get detector ID
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            return {
                "check":           "guardduty",
                "violations":      [{"issue": "GuardDuty is not enabled", "severity": "HIGH"}],
                "violation_count": 1,
                "error":           "No GuardDuty detector found"
            }

        detector_id = detectors[0]

        # Get findings
        criteria = {
            "FindingCriteria": {
                "Criterion": {
                    "service.archived": {
                        "Eq": ["false"]
                    }
                }
            },
            "SortCriteria": {
                "AttributeName": "severity",
                "OrderBy": "DESC"
            },
            "MaxResults": 50
        }

        finding_ids = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria=criteria.get("FindingCriteria", {}),
            SortCriteria=criteria.get("SortCriteria", {}),
            MaxResults=50,
        ).get("FindingIds", [])

        if not finding_ids:
            return {
                "check":           "guardduty",
                "violations":      [],
                "violation_count": 0,
                "detector_enabled": True,
            }

        findings = gd.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids,
        ).get("Findings", [])

        severity_counts = Counter()
        parsed = []
        for f in findings:
            severity = f.get("Severity", 0)
            if severity >= 7:
                sev_label = "HIGH"
            elif severity >= 4:
                sev_label = "MEDIUM"
            else:
                sev_label = "LOW"

            severity_counts[sev_label] += 1

            parsed.append({
                "title":         f.get("Title"),
                "type":          f.get("Type"),
                "severity":      sev_label,
                "severity_score": severity,
                "description":   f.get("Description", "")[:200],
                "resource_type": f.get("Resource", {}).get("ResourceType"),
                "region":        f.get("Region"),
                "updated_at":    str(f.get("UpdatedAt", "")),
            })

        logger.info(f"[INFO] GuardDuty: {len(findings)} findings | Severities: {dict(severity_counts)}")
        return {
            "check":            "guardduty",
            "violations":       parsed[:20],
            "violation_count":  len(findings),
            "severity_summary": dict(severity_counts),
            "detector_enabled": True,
        }
    except Exception as e:
        logger.error(f"[ERROR] GuardDuty check failed: {str(e)}")
        return {"check": "guardduty", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 5: UNUSUAL API ACTIVITY
# ══════════════════════════════════════════════════════════════
def check_unusual_activity(session: boto3.Session, lookback_hours: int) -> dict:
    try:
        all_events = fetch_cloudtrail_events(session, lookback_hours, max_results=200)

        unusual = []

        # Check for unusual regions
        region_counts = Counter(e.get("aws_region", "") for e in all_events)
        common_regions = {"ap-south-1", "us-east-1"}  # Add your normal regions

        for e in all_events:
            region = e.get("aws_region", "")
            source_ip = e.get("source_ip", "")

            # Flag unusual regions
            if region and region not in common_regions:
                unusual.append({
                    "type":        "unusual_region",
                    "event_name":  e.get("event_name"),
                    "username":    e.get("username"),
                    "region":      region,
                    "source_ip":   source_ip,
                    "event_time":  e.get("event_time"),
                    "severity":    "MEDIUM",
                })

            # Flag unusual hours (UTC 00:00 - 05:00 or 18:00 - 23:59)
            try:
                event_time_str = e.get("event_time", "")
                if event_time_str:
                    event_dt = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
                    hour = event_dt.hour
                    if hour < 5 or hour > 22:
                        unusual.append({
                            "type":        "unusual_hours",
                            "event_name":  e.get("event_name"),
                            "username":    e.get("username"),
                            "event_hour":  hour,
                            "source_ip":   source_ip,
                            "event_time":  event_time_str,
                            "severity":    "LOW",
                        })
            except Exception:
                pass

        # Deduplicate by username + type
        seen = set()
        deduplicated = []
        for u in unusual:
            key = f"{u.get('username')}_{u.get('type')}_{u.get('region', '')}"
            if key not in seen:
                seen.add(key)
                deduplicated.append(u)

        logger.info(f"[INFO] Unusual activity: {len(deduplicated)} events")
        return {
            "check":           "unusual_activity",
            "violations":      deduplicated[:20],
            "violation_count": len(deduplicated),
            "region_summary":  dict(region_counts),
            "lookback_hours":  lookback_hours,
        }
    except Exception as e:
        logger.error(f"[ERROR] Unusual activity check failed: {str(e)}")
        return {"check": "unusual_activity", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 6: ROOT ACCOUNT USAGE
# ══════════════════════════════════════════════════════════════
def check_root_usage(session: boto3.Session, lookback_hours: int) -> dict:
    try:
        all_events = fetch_cloudtrail_events(session, lookback_hours, max_results=200)

        root_events = []
        for e in all_events:
            user_identity = e.get("user_identity", {})
            is_root = (
                user_identity.get("type") == "Root"
                or user_identity.get("arn", "").endswith(":root")
                or e.get("username", "").lower() in ("root", "aws account root user")
            )
            if is_root:
                root_events.append({
                    "event_name":  e.get("event_name"),
                    "event_time":  e.get("event_time"),
                    "source_ip":   e.get("source_ip"),
                    "aws_region":  e.get("aws_region"),
                    "user_agent":  e.get("user_agent", "")[:100],
                    "error_code":  e.get("error_code"),
                    "severity":    "CRITICAL",
                })

        logger.info(f"[INFO] Root usage: {len(root_events)} root events")
        return {
            "check":           "root_usage",
            "violations":      root_events[:20],
            "violation_count": len(root_events),
            "lookback_hours":  lookback_hours,
            "policy":          "Root account should not be used for daily operations"
        }
    except Exception as e:
        logger.error(f"[ERROR] Root usage check failed: {str(e)}")
        return {"check": "root_usage", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 7: IAM CHANGES
# ══════════════════════════════════════════════════════════════
def check_iam_changes(session: boto3.Session, lookback_hours: int) -> dict:
    try:
        lookup = [{"AttributeKey": "EventSource", "AttributeValue": "iam.amazonaws.com"}]
        all_events = fetch_cloudtrail_events(session, lookback_hours, lookup, max_results=200)

        iam_changes = []
        for e in all_events:
            event_name = e.get("event_name", "")
            if event_name in SENSITIVE_IAM_ACTIONS:
                severity = "CRITICAL" if event_name in (
                    "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy",
                    "UpdateAssumeRolePolicy", "CreateLoginProfile"
                ) else "HIGH"

                iam_changes.append({
                    "event_name":   event_name,
                    "username":     e.get("username"),
                    "event_time":   e.get("event_time"),
                    "source_ip":    e.get("source_ip"),
                    "aws_region":   e.get("aws_region"),
                    "error_code":   e.get("error_code"),
                    "request_params": str(e.get("request_params", ""))[:200],
                    "severity":     severity,
                })

        # Group by action type
        action_summary = Counter(e["event_name"] for e in iam_changes)

        logger.info(f"[INFO] IAM changes: {len(iam_changes)} sensitive changes")
        return {
            "check":           "iam_changes",
            "violations":      iam_changes[:20],
            "violation_count": len(iam_changes),
            "action_summary":  dict(action_summary),
            "lookback_hours":  lookback_hours,
        }
    except Exception as e:
        logger.error(f"[ERROR] IAM changes check failed: {str(e)}")
        return {"check": "iam_changes", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 8: PUBLIC RESOURCE EXPOSURE
# ══════════════════════════════════════════════════════════════
def check_public_exposure(session: boto3.Session) -> dict:
    violations = []

    # ── Public Security Groups ────────────────────────────────
    try:
        ec2 = session.client("ec2")
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])

        dangerous_ports = [22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 8080, 8443]

        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        from_port = perm.get("FromPort", 0)
                        to_port   = perm.get("ToPort", 65535)
                        is_all    = perm.get("IpProtocol") == "-1"
                        is_dangerous = any(from_port <= p <= to_port for p in dangerous_ports)

                        if is_dangerous or is_all:
                            violations.append({
                                "resource_id":   sg["GroupId"],
                                "resource_name": sg.get("GroupName"),
                                "type":          "security_group",
                                "issue":         f"Open to internet (0.0.0.0/0) ports {from_port}-{to_port}",
                                "severity":      "CRITICAL" if is_all else "HIGH",
                            })
    except Exception as e:
        logger.warning(f"[WARN] Security group exposure check failed: {str(e)}")

    # ── Public S3 Buckets ─────────────────────────────────────
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                public_access = s3.get_public_access_block(Bucket=bucket_name)
                config = public_access.get("PublicAccessBlockConfiguration", {})
                if not all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ]):
                    violations.append({
                        "resource_id": bucket_name,
                        "type":        "s3_bucket",
                        "issue":       "Public access block not fully configured",
                        "severity":    "HIGH",
                    })
            except Exception:
                violations.append({
                    "resource_id": bucket_name,
                    "type":        "s3_bucket",
                    "issue":       "No public access block configured",
                    "severity":    "HIGH",
                })
    except Exception as e:
        logger.warning(f"[WARN] S3 public access check failed: {str(e)}")

    # ── Public RDS ────────────────────────────────────────────
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                if db.get("PubliclyAccessible", False):
                    violations.append({
                        "resource_id": db["DBInstanceIdentifier"],
                        "type":        "rds_instance",
                        "issue":       "RDS instance is publicly accessible",
                        "severity":    "CRITICAL",
                    })
    except Exception as e:
        logger.warning(f"[WARN] Public RDS check failed: {str(e)}")

    # ── EC2 Instances with Public IPs ─────────────────────────
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    public_ip = inst.get("PublicIpAddress")
                    if public_ip:
                        name = ""
                        for tag in inst.get("Tags", []):
                            if tag["Key"] == "Name":
                                name = tag["Value"]
                        violations.append({
                            "resource_id":   inst["InstanceId"],
                            "resource_name": name,
                            "type":          "ec2_instance",
                            "issue":         f"EC2 instance has public IP: {public_ip}",
                            "severity":      "MEDIUM",
                        })
    except Exception as e:
        logger.warning(f"[WARN] EC2 public IP check failed: {str(e)}")

    logger.info(f"[INFO] Public exposure: {len(violations)} exposed resources")
    return {
        "check":           "public_exposure",
        "violations":      violations[:20],
        "violation_count": len(violations),
    }

# ══════════════════════════════════════════════════════════════
# CHECK 9: ACCESS KEY USAGE ANOMALIES
# ══════════════════════════════════════════════════════════════
def check_access_key_anomalies(session: boto3.Session, lookback_hours: int) -> dict:
    try:
        all_events = fetch_cloudtrail_events(session, lookback_hours, max_results=200)

        # Track IPs and regions per user
        user_activity = {}
        for e in all_events:
            username  = e.get("username", "unknown")
            source_ip = e.get("source_ip", "")
            region    = e.get("aws_region", "")

            if username not in user_activity:
                user_activity[username] = {"ips": set(), "regions": set(), "events": []}

            user_activity[username]["ips"].add(source_ip)
            user_activity[username]["regions"].add(region)
            user_activity[username]["events"].append(e)

        anomalies = []
        for username, activity in user_activity.items():
            # Multiple IPs for same user
            if len(activity["ips"]) > 3:
                anomalies.append({
                    "username":     username,
                    "type":         "multiple_ips",
                    "unique_ips":   list(activity["ips"])[:5],
                    "ip_count":     len(activity["ips"]),
                    "severity":     "MEDIUM",
                })

            # Multiple regions for same user
            if len(activity["regions"]) > 2:
                anomalies.append({
                    "username":      username,
                    "type":          "multiple_regions",
                    "regions":       list(activity["regions"]),
                    "region_count":  len(activity["regions"]),
                    "severity":      "HIGH",
                })

        logger.info(f"[INFO] Access key anomalies: {len(anomalies)}")
        return {
            "check":           "access_key_anomalies",
            "violations":      anomalies[:20],
            "violation_count": len(anomalies),
            "lookback_hours":  lookback_hours,
        }
    except Exception as e:
        logger.error(f"[ERROR] Access key anomalies check failed: {str(e)}")
        return {"check": "access_key_anomalies", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 10: ASSUME ROLE CHAINS
# ══════════════════════════════════════════════════════════════
def check_assume_role_chains(session: boto3.Session, lookback_hours: int) -> dict:
    try:
        lookup = [{"AttributeKey": "EventName", "AttributeValue": "AssumeRole"}]
        events = fetch_cloudtrail_events(session, lookback_hours, lookup, max_results=100)

        assume_events = []
        for e in events:
            user_identity = e.get("user_identity", {})
            request_params = e.get("request_params") or {}

            assume_events.append({
                "event_time":    e.get("event_time"),
                "caller":        e.get("username"),
                "caller_type":   user_identity.get("type"),
                "role_assumed":  request_params.get("roleArn", "unknown") if isinstance(request_params, dict) else "unknown",
                "source_ip":     e.get("source_ip"),
                "aws_region":    e.get("aws_region"),
                "error_code":    e.get("error_code"),
            })

        # Flag cross-account assumptions
        cross_account = [e for e in assume_events if ":iam::" in str(e.get("role_assumed", ""))]

        logger.info(f"[INFO] AssumeRole: {len(assume_events)} events, {len(cross_account)} cross-account")
        return {
            "check":               "assume_role_chains",
            "violations":          assume_events[:20],
            "violation_count":     len(assume_events),
            "cross_account_count": len(cross_account),
            "lookback_hours":      lookback_hours,
        }
    except Exception as e:
        logger.error(f"[ERROR] AssumeRole check failed: {str(e)}")
        return {"check": "assume_role_chains", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 11: FAILED LOGIN ATTEMPTS
# ══════════════════════════════════════════════════════════════
def check_failed_logins(session: boto3.Session, lookback_hours: int) -> dict:
    try:
        lookup = [{"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}]
        events = fetch_cloudtrail_events(session, lookback_hours, lookup, max_results=100)

        failed = []
        for e in events:
            error_code = e.get("error_code")
            if error_code:
                failed.append({
                    "event_time":  e.get("event_time"),
                    "username":    e.get("username"),
                    "source_ip":   e.get("source_ip"),
                    "aws_region":  e.get("aws_region"),
                    "error_code":  error_code,
                    "user_agent":  e.get("user_agent", "")[:100],
                    "severity":    "HIGH",
                })

        # Group by username
        user_failures = Counter(e["username"] for e in failed)

        # Flag users with > 3 failures (possible brute force)
        brute_force_suspects = {u: c for u, c in user_failures.items() if c >= 3}

        logger.info(f"[INFO] Failed logins: {len(failed)} | Brute force suspects: {brute_force_suspects}")
        return {
            "check":                "failed_logins",
            "violations":           failed[:20],
            "violation_count":      len(failed),
            "failures_per_user":    dict(user_failures),
            "brute_force_suspects": brute_force_suspects,
            "lookback_hours":       lookback_hours,
        }
    except Exception as e:
        logger.error(f"[ERROR] Failed logins check failed: {str(e)}")
        return {"check": "failed_logins", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 12: RESOURCE DELETION EVENTS
# ══════════════════════════════════════════════════════════════
def check_resource_deletions(session: boto3.Session, lookback_hours: int) -> dict:
    try:
        all_events = fetch_cloudtrail_events(session, lookback_hours, max_results=200)

        deletions = []
        for e in all_events:
            event_name = e.get("event_name", "")
            if event_name in DELETION_ACTIONS:
                deletions.append({
                    "event_name":     event_name,
                    "username":       e.get("username"),
                    "event_time":     e.get("event_time"),
                    "source_ip":      e.get("source_ip"),
                    "aws_region":     e.get("aws_region"),
                    "error_code":     e.get("error_code"),
                    "request_params": str(e.get("request_params", ""))[:200],
                    "severity":       "HIGH",
                })

        # Group by action
        action_summary = Counter(e["event_name"] for e in deletions)

        logger.info(f"[INFO] Resource deletions: {len(deletions)} events")
        return {
            "check":           "resource_deletions",
            "violations":      deletions[:20],
            "violation_count": len(deletions),
            "action_summary":  dict(action_summary),
            "lookback_hours":  lookback_hours,
        }
    except Exception as e:
        logger.error(f"[ERROR] Resource deletions check failed: {str(e)}")
        return {"check": "resource_deletions", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# BUILD SECURITY ANALYSIS PROMPT
# ══════════════════════════════════════════════════════════════
def build_security_prompt(query: str, account_id: str, service: str, evidence: dict, checks_run: list) -> str:

    evidence_sections = []

    for check_name, check_data in evidence.items():
        count = check_data.get("violation_count", 0)
        violations = check_data.get("violations", [])
        error = check_data.get("error", "")

        section = f"--- {check_name.upper()} ({count} findings) ---\n"

        # Add summaries if available
        if check_data.get("severity_summary"):
            section += f"Severity breakdown: {check_data['severity_summary']}\n"
        if check_data.get("error_summary"):
            section += f"Error types: {check_data['error_summary']}\n"
        if check_data.get("action_summary"):
            section += f"Actions: {check_data['action_summary']}\n"
        if check_data.get("brute_force_suspects"):
            section += f"Brute force suspects: {check_data['brute_force_suspects']}\n"
        if error:
            section += f"Error: {error}\n"

        section += f"Details:\n{json.dumps(violations[:10], indent=2, default=str)}\n"
        evidence_sections.append(section)

    evidence_text = "\n\n".join(evidence_sections) if evidence_sections else "No security findings."

    total_findings = sum(v.get("violation_count", 0) for v in evidence.values())

    return f"""You are a cloud security investigator for AWS infrastructure.

The user asked: "{query}"

Your job is to answer the user's SPECIFIC question using the security evidence below.

AWS Account: {account_id}
Service Focus: {service}
Checks Performed: {', '.join(checks_run)}
Total Findings: {total_findings}

Security Evidence:
{evidence_text}

Rules:
- Answer ONLY what the user asked — be direct and specific
- Prioritize by severity: CRITICAL > HIGH > MEDIUM > LOW
- Cite specific events, resources, IPs, usernames
- If something looks like an active threat, say so clearly
- Provide actionable recommendations
- If data was insufficient, say so clearly

Return ONLY this JSON:
{{
  "is_incident": true or false,
  "confidence": 0.0 to 1.0,
  "severity": "CRITICAL or HIGH or MEDIUM or LOW or NONE",
  "reasoning": "direct answer to user's question",
  "evidence": ["specific finding 1", "specific finding 2"],
  "recommendations": ["actionable recommendation 1", "actionable recommendation 2"]
}}
"""

# ══════════════════════════════════════════════════════════════
# MAIN INVESTIGATION LOGIC
# ══════════════════════════════════════════════════════════════
def investigate(payload: dict) -> dict:
    query          = payload.get("query", "General security check")
    job_id         = payload.get("job_id", "unknown")
    user_id        = payload.get("user_id", "anonymous")
    account_id     = payload.get("account_id", DEFAULT_ACCOUNT_ID)
    service        = payload.get("service") or extract_service_from_query(query)

    logger.info(f"[INFO] Starting security investigation: job_id={job_id} account={account_id}")

    # ── 1. Understand query intent ────────────────────────────
    intent = classify_query_intent(query)
    checks_to_run  = intent.get("checks_to_run", [])
    service_focus   = intent.get("service_focus", service)
    lookback_hours  = int(intent.get("lookback_hours", 24))

    if service_focus and service_focus != "all":
        service = service_focus

    logger.info(f"[INFO] Checks: {checks_to_run} | Service: {service} | Lookback: {lookback_hours}h")

    # ── 2. Assume role ────────────────────────────────────────
    try:
        session = assume_role_session(account_id)
    except Exception as e:
        return {
            "agent":       "security",
            "status":      "error",
            "is_incident": False,
            "confidence":  0.0,
            "reasoning":   f"Failed to assume role in account {account_id}: {str(e)}",
            "evidence":    [],
            "job_id":      job_id,
            "query":       query,
        }

    # ── 3. Run relevant checks ────────────────────────────────
    check_functions = {
        "cloudtrail_errors":     lambda: check_cloudtrail_errors(session, service, lookback_hours),
        "scp_denials":           lambda: check_scp_denials(session, lookback_hours),
        "security_hub":          lambda: check_security_hub(session, account_id, service, lookback_hours),
        "guardduty":             lambda: check_guardduty(session),
        "unusual_activity":      lambda: check_unusual_activity(session, lookback_hours),
        "root_usage":            lambda: check_root_usage(session, lookback_hours),
        "iam_changes":           lambda: check_iam_changes(session, lookback_hours),
        "public_exposure":       lambda: check_public_exposure(session),
        "access_key_anomalies":  lambda: check_access_key_anomalies(session, lookback_hours),
        "assume_role_chains":    lambda: check_assume_role_chains(session, lookback_hours),
        "failed_logins":         lambda: check_failed_logins(session, lookback_hours),
        "resource_deletions":    lambda: check_resource_deletions(session, lookback_hours),
    }

    evidence = {}
    for check_name in checks_to_run:
        if check_name in check_functions:
            try:
                evidence[check_name] = check_functions[check_name]()
            except Exception as e:
                logger.error(f"[ERROR] Check {check_name} failed: {str(e)}")
                evidence[check_name] = {
                    "check": check_name,
                    "violations": [],
                    "violation_count": 0,
                    "error": str(e)
                }

    # ── 4. Calculate totals ───────────────────────────────────
    total_findings = sum(v.get("violation_count", 0) for v in evidence.values())
    logger.info(f"[INFO] Total findings: {total_findings}")

    # ── 5. No findings ────────────────────────────────────────
    if total_findings == 0:
        return {
            "agent":            "security",
            "status":           "success",
            "is_incident":      False,
            "confidence":       0.95,
            "severity":         "NONE",
            "reasoning":        f"No security findings for the query: '{query}'. Checks performed: {', '.join(checks_to_run)}.",
            "evidence":         [],
            "recommendations":  [],
            "job_id":           job_id,
            "query":            query,
            "account_id":       account_id,
            "service":          service,
            "checks_run":       checks_to_run,
            "lookback_hours":   lookback_hours,
            "total_findings":   0,
            "summary":          {c: evidence.get(c, {}).get("violation_count", 0) for c in checks_to_run},
        }

    # ── 6. Send to Vertex AI ──────────────────────────────────
    try:
        prompt    = build_security_prompt(query, account_id, service, evidence, checks_to_run)
        ai_result = call_vertex(prompt)

        result = {
            "agent":            "security",
            "status":           "success",
            "is_incident":      ai_result.get("is_incident", False),
            "confidence":       ai_result.get("confidence", 0.0),
            "severity":         ai_result.get("severity", "UNKNOWN"),
            "reasoning":        ai_result.get("reasoning", "No reasoning provided"),
            "evidence":         ai_result.get("evidence", []),
            "recommendations":  ai_result.get("recommendations", []),
            "job_id":           job_id,
            "query":            query,
            "account_id":       account_id,
            "service":          service,
            "checks_run":       checks_to_run,
            "lookback_hours":   lookback_hours,
            "total_findings":   total_findings,
            "summary":          {c: evidence.get(c, {}).get("violation_count", 0) for c in checks_to_run},
        }

        logger.info(f"[INFO] Done: is_incident={result['is_incident']} severity={result['severity']}")
        return result

    except Exception as e:
        logger.error(f"[ERROR] Vertex AI failed: {str(e)}")
        return {
            "agent":            "security",
            "status":           "error",
            "is_incident":      False,
            "confidence":       0.5,
            "severity":         "UNKNOWN",
            "reasoning":        f"AI analysis failed: {str(e)}. Raw findings available.",
            "evidence":         [],
            "recommendations":  [],
            "job_id":           job_id,
            "query":            query,
            "account_id":       account_id,
            "service":          service,
            "checks_run":       checks_to_run,
            "lookback_hours":   lookback_hours,
            "total_findings":   total_findings,
            "summary":          {c: evidence.get(c, {}).get("violation_count", 0) for c in checks_to_run},
            "raw_evidence":     {k: v.get("violations", [])[:3] for k, v in evidence.items()},
        }

# ── LAMBDA HANDLER ────────────────────────────────────────────
def lambda_handler(event, context):
    logger.info(f"[INFO] Incoming event: {json.dumps(event, default=str)}")

    if "requestContext" in event and "http" in event.get("requestContext", {}):
        try:
            payload = json.loads(event.get("body") or "{}")
            result  = investigate(payload)
            return {
                "statusCode": 200,
                "headers":    {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body":       json.dumps(result, default=str)
            }
        except Exception as e:
            logger.exception("Security investigation failed")
            return {
                "statusCode": 500,
                "headers":    {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body":       json.dumps({"agent": "security", "status": "error", "message": str(e)})
            }

    try:
        return investigate(event)
    except Exception as e:
        logger.exception("Security investigation failed")
        return {"agent": "security", "status": "error", "message": str(e)}
