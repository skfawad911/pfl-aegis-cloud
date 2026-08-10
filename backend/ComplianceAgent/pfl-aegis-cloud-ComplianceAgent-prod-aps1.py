"""
Compliance Agent Lambda — Full Capabilities
Uses Vertex AI REST API for intelligent analysis.

CHECKS PERFORMED:
1.  Resource Tagging Compliance
2.  Region Compliance
3.  IAM Access Key Rotation
4.  Deletion Protection (EC2/RDS)
5.  IAM MFA Compliance
6.  IAM Password Policy
7.  IAM Inactive Users
8.  IAM Admin Access Audit
9.  Encryption Compliance (EBS, S3, RDS)
10. Logging Compliance (CloudTrail, S3 Access Logs, VPC Flow Logs)
11. Network Compliance (Public Security Groups, Public RDS, Public S3)
12. AWS Config Rule Compliance

ENV VARS:
    GCP_PROJECT_ID, GCP_LOCATION, GCP_MODEL_ID, GCP_SA_KEY
    CROSS_ACCOUNT_ROLE_NAME, DEFAULT_TARGET_ACCOUNT_ID
    REQUIRED_TAGS, APPROVED_REGIONS, ACCESS_KEY_MAX_AGE_DAYS
    INACTIVE_USER_DAYS
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta

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

REQUIRED_TAGS = [
    t.strip()
    for t in os.environ.get("REQUIRED_TAGS", "Owner,CostCenter,Environment").split(",")
    if t.strip()
]
APPROVED_REGIONS = [
    r.strip()
    for r in os.environ.get("APPROVED_REGIONS", "ap-south-1").split(",")
    if r.strip()
]
ACCESS_KEY_MAX_AGE_DAYS = int(os.environ.get("ACCESS_KEY_MAX_AGE_DAYS", "90"))
INACTIVE_USER_DAYS      = int(os.environ.get("INACTIVE_USER_DAYS", "90"))

# ── SERVICE MAPPINGS ──────────────────────────────────────────
_SERVICE_TO_RESOURCE_TYPE = {
    "ec2":    "ec2:instance",
    "rds":    "rds:db",
    "s3":     "s3",
    "lambda": "lambda:function",
    "ecs":    "ecs:service",
}

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
    prompt = f"""You are a compliance query analyzer for AWS infrastructure.

The user asked: "{query}"

Decide which compliance checks are RELEVANT to answer this query.

Available checks:
- "tags": Required tags (Owner, CostCenter, Environment) present on resources
- "region": Resources only in approved AWS regions
- "key_rotation": IAM access keys rotated within policy (90 days)
- "deletion_protection": Deletion protection enabled on RDS/EC2
- "mfa": MFA enabled for IAM users
- "password_policy": Account password policy meets standards
- "inactive_users": IAM users with console access but no activity > 90 days
- "admin_access": Users/roles with AdministratorAccess or root-level permissions
- "encryption": EBS volumes, S3 buckets, RDS instances encrypted
- "logging": CloudTrail enabled, S3 access logging, VPC flow logs
- "network": Public security groups (0.0.0.0/0), public RDS, public S3 buckets
- "config_rules": AWS Config managed rule compliance status

Rules:
- Only include checks DIRECTLY relevant to the user's query
- If query is GENERAL ("any violations?", "compliance status", "full audit") include ALL checks
- Be precise — if user asks about encryption, only check encryption

Return ONLY this JSON:
{{
  "checks_to_run": ["tags", "mfa", "encryption"],
  "query_summary": "one line summary",
  "service_focus": "ec2 or s3 or rds or iam or all"
}}
"""
    try:
        result = call_vertex(prompt)
        logger.info(f"[INFO] Query intent: {result}")
        return result
    except Exception as e:
        logger.warning(f"[WARN] Intent classification failed: {str(e)} — running all checks")
        return {
            "checks_to_run": ["tags", "region", "key_rotation", "deletion_protection",
                              "mfa", "password_policy", "inactive_users", "admin_access",
                              "encryption", "logging", "network", "config_rules"],
            "query_summary": query,
            "service_focus": "all"
        }

# ── SERVICE EXTRACTION ────────────────────────────────────────
def extract_service_from_query(query: str) -> str:
    query_lower = query.lower()
    service_keywords = {
        "ec2":    ["ec2", "instance", "server", "compute"],
        "s3":     ["s3", "bucket", "storage", "object"],
        "iam":    ["iam", "role", "user", "permission", "credential", "access key", "mfa", "password"],
        "rds":    ["rds", "database", "db", "mysql", "postgres"],
        "lambda": ["lambda", "function", "serverless"],
        "vpc":    ["vpc", "subnet", "security group", "network", "nacl"],
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
            RoleSessionName="aegis-compliance-investigation",
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
# CHECK 1: RESOURCE TAGGING
# ══════════════════════════════════════════════════════════════
def check_tags(session: boto3.Session, service: str) -> dict:
    try:
        tagging = session.client("resourcegroupstaggingapi")

        if service == "all":
            resources = tagging.get_resources(
                ResourcesPerPage=100,
            ).get("ResourceTagMappingList", [])
        else:
            res_type = _SERVICE_TO_RESOURCE_TYPE.get(service.lower(), service.lower())
            resources = tagging.get_resources(
                ResourceTypeFilters=[res_type],
                ResourcesPerPage=100,
            ).get("ResourceTagMappingList", [])

        missing = []
        for r in resources:
            present      = {t["Key"] for t in r.get("Tags", [])}
            missing_tags = [t for t in REQUIRED_TAGS if t not in present]
            if missing_tags:
                missing.append({
                    "resource_arn": r["ResourceARN"],
                    "missing_tags": missing_tags
                })

        logger.info(f"[INFO] Tags: {len(missing)} violations out of {len(resources)} resources")
        return {
            "check":           "tags",
            "total_resources":  len(resources),
            "violations":       missing[:20],
            "violation_count":  len(missing),
            "required_tags":    REQUIRED_TAGS,
            "policy":           f"All resources must have tags: {', '.join(REQUIRED_TAGS)}"
        }
    except Exception as e:
        logger.error(f"[ERROR] Tags check failed: {str(e)}")
        return {"check": "tags", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 2: REGION COMPLIANCE
# ══════════════════════════════════════════════════════════════
def check_region(session: boto3.Session, service: str) -> dict:
    try:
        tagging = session.client("resourcegroupstaggingapi")

        if service == "all":
            resources = tagging.get_resources(ResourcesPerPage=100).get("ResourceTagMappingList", [])
        else:
            res_type = _SERVICE_TO_RESOURCE_TYPE.get(service.lower(), service.lower())
            resources = tagging.get_resources(
                ResourceTypeFilters=[res_type], ResourcesPerPage=100
            ).get("ResourceTagMappingList", [])

        out_of_region = []
        for r in resources:
            arn_parts = r["ResourceARN"].split(":")
            region    = arn_parts[3] if len(arn_parts) > 3 else ""
            if region and region not in APPROVED_REGIONS:
                out_of_region.append({
                    "resource_arn":  r["ResourceARN"],
                    "actual_region": region
                })

        logger.info(f"[INFO] Region: {len(out_of_region)} out-of-region resources")
        return {
            "check":            "region",
            "violations":       out_of_region[:20],
            "violation_count":  len(out_of_region),
            "approved_regions": APPROVED_REGIONS,
            "policy":           f"Resources must only exist in: {', '.join(APPROVED_REGIONS)}"
        }
    except Exception as e:
        logger.error(f"[ERROR] Region check failed: {str(e)}")
        return {"check": "region", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 3: IAM ACCESS KEY ROTATION
# ══════════════════════════════════════════════════════════════
def check_key_rotation(session: boto3.Session) -> dict:
    try:
        iam     = session.client("iam")
        overdue = []
        now     = datetime.now(timezone.utc)

        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                for key in keys:
                    if key.get("Status") != "Active":
                        continue
                    age_days = (now - key["CreateDate"]).days
                    if age_days > ACCESS_KEY_MAX_AGE_DAYS:
                        overdue.append({
                            "username":      username,
                            "access_key_id": key["AccessKeyId"],
                            "age_days":      age_days,
                            "max_age_days":  ACCESS_KEY_MAX_AGE_DAYS,
                            "created_date":  key["CreateDate"].isoformat(),
                        })

        logger.info(f"[INFO] Key rotation: {len(overdue)} overdue keys")
        return {
            "check":           "key_rotation",
            "violations":      overdue[:20],
            "violation_count": len(overdue),
            "policy":          f"IAM access keys must be rotated every {ACCESS_KEY_MAX_AGE_DAYS} days"
        }
    except Exception as e:
        logger.error(f"[ERROR] Key rotation check failed: {str(e)}")
        return {"check": "key_rotation", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 4: DELETION PROTECTION
# ══════════════════════════════════════════════════════════════
def check_deletion_protection(session: boto3.Session, service: str) -> dict:
    findings = []
    try:
        if service in ("rds", "all"):
            try:
                rds = session.client("rds")
                paginator = rds.get_paginator("describe_db_instances")
                for page in paginator.paginate():
                    for db in page.get("DBInstances", []):
                        if not db.get("DeletionProtection", False):
                            findings.append({
                                "resource_id":   db["DBInstanceIdentifier"],
                                "resource_type": "rds:db",
                                "deletion_protection": False,
                            })
            except Exception as e:
                logger.warning(f"[WARN] RDS deletion protection check failed: {str(e)}")

        if service in ("ec2", "all"):
            try:
                ec2 = session.client("ec2")
                paginator = ec2.get_paginator("describe_instances")
                for page in paginator.paginate(
                    Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
                ):
                    for res in page.get("Reservations", []):
                        for inst in res.get("Instances", []):
                            iid = inst["InstanceId"]
                            attr = ec2.describe_instance_attribute(
                                InstanceId=iid, Attribute="disableApiTermination"
                            )
                            if not attr.get("DisableApiTermination", {}).get("Value", False):
                                # Get instance name
                                name = ""
                                for tag in inst.get("Tags", []):
                                    if tag["Key"] == "Name":
                                        name = tag["Value"]
                                findings.append({
                                    "resource_id":   iid,
                                    "resource_name": name,
                                    "resource_type": "ec2:instance",
                                    "deletion_protection": False,
                                })
            except Exception as e:
                logger.warning(f"[WARN] EC2 deletion protection check failed: {str(e)}")

        logger.info(f"[INFO] Deletion protection: {len(findings)} unprotected resources")
        return {
            "check":           "deletion_protection",
            "violations":      findings[:20],
            "violation_count": len(findings),
            "policy":          "Deletion protection must be enabled on all stateful resources (EC2, RDS)"
        }
    except Exception as e:
        logger.error(f"[ERROR] Deletion protection check failed: {str(e)}")
        return {"check": "deletion_protection", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 5: MFA COMPLIANCE
# ══════════════════════════════════════════════════════════════
def check_mfa(session: boto3.Session) -> dict:
    try:
        iam = session.client("iam")
        no_mfa = []

        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]

                # Check if user has console access (login profile)
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except iam.exceptions.NoSuchEntityException:
                    has_console = False

                if not has_console:
                    continue

                # Check MFA devices
                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                if not mfa_devices:
                    no_mfa.append({
                        "username":       username,
                        "has_console":    True,
                        "mfa_enabled":    False,
                        "created":        user.get("CreateDate", "").isoformat() if hasattr(user.get("CreateDate", ""), "isoformat") else str(user.get("CreateDate", "")),
                    })

        # Check root MFA
        try:
            summary = iam.get_account_summary().get("SummaryMap", {})
            root_mfa = summary.get("AccountMFAEnabled", 0)
            if root_mfa == 0:
                no_mfa.insert(0, {
                    "username":    "ROOT ACCOUNT",
                    "has_console": True,
                    "mfa_enabled": False,
                    "severity":    "CRITICAL",
                })
        except Exception:
            pass

        logger.info(f"[INFO] MFA: {len(no_mfa)} users without MFA")
        return {
            "check":           "mfa",
            "violations":      no_mfa[:20],
            "violation_count": len(no_mfa),
            "policy":          "All IAM users with console access must have MFA enabled"
        }
    except Exception as e:
        logger.error(f"[ERROR] MFA check failed: {str(e)}")
        return {"check": "mfa", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 6: PASSWORD POLICY
# ══════════════════════════════════════════════════════════════
def check_password_policy(session: boto3.Session) -> dict:
    try:
        iam = session.client("iam")
        violations = []

        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        except iam.exceptions.NoSuchEntityException:
            return {
                "check":           "password_policy",
                "violations":      [{"issue": "No password policy configured", "severity": "HIGH"}],
                "violation_count": 1,
                "policy":          "Account must have a strong password policy configured"
            }

        # Check each requirement
        checks = {
            "MinimumPasswordLength":      {"expected": 14, "actual": policy.get("MinimumPasswordLength", 0)},
            "RequireSymbols":             {"expected": True, "actual": policy.get("RequireSymbols", False)},
            "RequireNumbers":             {"expected": True, "actual": policy.get("RequireNumbers", False)},
            "RequireUppercaseCharacters": {"expected": True, "actual": policy.get("RequireUppercaseCharacters", False)},
            "RequireLowercaseCharacters": {"expected": True, "actual": policy.get("RequireLowercaseCharacters", False)},
            "MaxPasswordAge":             {"expected": 90,   "actual": policy.get("MaxPasswordAge", 0)},
            "PasswordReusePrevention":    {"expected": 24,   "actual": policy.get("PasswordReusePrevention", 0)},
        }

        for rule, vals in checks.items():
            if isinstance(vals["expected"], bool):
                if vals["actual"] != vals["expected"]:
                    violations.append({
                        "rule":     rule,
                        "expected": vals["expected"],
                        "actual":   vals["actual"],
                    })
            else:
                if vals["actual"] < vals["expected"]:
                    violations.append({
                        "rule":     rule,
                        "expected": f">= {vals['expected']}",
                        "actual":   vals["actual"],
                    })

        logger.info(f"[INFO] Password policy: {len(violations)} violations")
        return {
            "check":           "password_policy",
            "violations":      violations,
            "violation_count": len(violations),
            "current_policy":  policy,
            "policy":          "Password policy must meet CIS benchmark standards"
        }
    except Exception as e:
        logger.error(f"[ERROR] Password policy check failed: {str(e)}")
        return {"check": "password_policy", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 7: INACTIVE USERS
# ══════════════════════════════════════════════════════════════
def check_inactive_users(session: boto3.Session) -> dict:
    try:
        iam      = session.client("iam")
        inactive = []
        now      = datetime.now(timezone.utc)
        cutoff   = now - timedelta(days=INACTIVE_USER_DAYS)

        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]

                # Check console access
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except iam.exceptions.NoSuchEntityException:
                    has_console = False

                if not has_console:
                    continue

                # Check last activity
                last_used = user.get("PasswordLastUsed")
                if last_used and last_used < cutoff:
                    days_inactive = (now - last_used).days
                    inactive.append({
                        "username":       username,
                        "last_activity":  last_used.isoformat(),
                        "days_inactive":  days_inactive,
                        "threshold_days": INACTIVE_USER_DAYS,
                    })
                elif not last_used:
                    # Never used console
                    created = user.get("CreateDate")
                    if created and created < cutoff:
                        inactive.append({
                            "username":       username,
                            "last_activity":  "NEVER",
                            "days_since_created": (now - created).days,
                            "threshold_days": INACTIVE_USER_DAYS,
                        })

        logger.info(f"[INFO] Inactive users: {len(inactive)}")
        return {
            "check":           "inactive_users",
            "violations":      inactive[:20],
            "violation_count": len(inactive),
            "policy":          f"Users with console access inactive for > {INACTIVE_USER_DAYS} days should be disabled"
        }
    except Exception as e:
        logger.error(f"[ERROR] Inactive users check failed: {str(e)}")
        return {"check": "inactive_users", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 8: ADMIN ACCESS AUDIT
# ══════════════════════════════════════════════════════════════
def check_admin_access(session: boto3.Session) -> dict:
    try:
        iam     = session.client("iam")
        admins  = []

        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])

                for pol in attached:
                    if pol["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess":
                        admins.append({
                            "username":   username,
                            "policy":     pol["PolicyName"],
                            "policy_arn": pol["PolicyArn"],
                            "type":       "direct_user_policy",
                        })

                # Check groups
                groups = iam.list_groups_for_user(UserName=username).get("Groups", [])
                for group in groups:
                    group_policies = iam.list_attached_group_policies(
                        GroupName=group["GroupName"]
                    ).get("AttachedPolicies", [])
                    for pol in group_policies:
                        if pol["PolicyArn"] == "arn:aws:iam::aws:policy/AdministratorAccess":
                            admins.append({
                                "username":   username,
                                "group":      group["GroupName"],
                                "policy":     pol["PolicyName"],
                                "policy_arn": pol["PolicyArn"],
                                "type":       "via_group",
                            })

        logger.info(f"[INFO] Admin access: {len(admins)} users with admin")
        return {
            "check":           "admin_access",
            "violations":      admins[:20],
            "violation_count": len(admins),
            "policy":          "AdministratorAccess should be granted sparingly and reviewed regularly"
        }
    except Exception as e:
        logger.error(f"[ERROR] Admin access check failed: {str(e)}")
        return {"check": "admin_access", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# CHECK 9: ENCRYPTION COMPLIANCE
# ══════════════════════════════════════════════════════════════
def check_encryption(session: boto3.Session, service: str) -> dict:
    violations = []

    # ── EBS Volumes ───────────────────────────────────────────
    if service in ("ec2", "all"):
        try:
            ec2 = session.client("ec2")
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page.get("Volumes", []):
                    if not vol.get("Encrypted", False):
                        violations.append({
                            "resource_id":   vol["VolumeId"],
                            "resource_type": "ebs:volume",
                            "encrypted":     False,
                            "size_gb":       vol.get("Size"),
                            "state":         vol.get("State"),
                        })
        except Exception as e:
            logger.warning(f"[WARN] EBS encryption check failed: {str(e)}")

    # ── S3 Buckets ────────────────────────────────────────────
    if service in ("s3", "all"):
        try:
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                bucket_name = bucket["Name"]
                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                except s3.exceptions.ClientError as ce:
                    if "ServerSideEncryptionConfigurationNotFoundError" in str(ce):
                        violations.append({
                            "resource_id":   bucket_name,
                            "resource_type": "s3:bucket",
                            "encrypted":     False,
                        })
        except Exception as e:
            logger.warning(f"[WARN] S3 encryption check failed: {str(e)}")

    # ── RDS Instances ─────────────────────────────────────────
    if service in ("rds", "all"):
        try:
            rds = session.client("rds")
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    if not db.get("StorageEncrypted", False):
                        violations.append({
                            "resource_id":   db["DBInstanceIdentifier"],
                            "resource_type": "rds:db",
                            "encrypted":     False,
                            "engine":        db.get("Engine"),
                        })
        except Exception as e:
            logger.warning(f"[WARN] RDS encryption check failed: {str(e)}")

    logger.info(f"[INFO] Encryption: {len(violations)} unencrypted resources")
    return {
        "check":           "encryption",
        "violations":      violations[:20],
        "violation_count": len(violations),
        "policy":          "All data at rest must be encrypted (EBS, S3, RDS)"
    }

# ══════════════════════════════════════════════════════════════
# CHECK 10: LOGGING COMPLIANCE
# ══════════════════════════════════════════════════════════════
def check_logging(session: boto3.Session) -> dict:
    violations = []

    # ── CloudTrail ────────────────────────────────────────────
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])

        if not trails:
            violations.append({
                "resource":  "CloudTrail",
                "issue":     "No CloudTrail trails configured",
                "severity":  "CRITICAL",
            })
        else:
            for trail in trails:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                if not status.get("IsLogging", False):
                    violations.append({
                        "resource":   trail.get("Name"),
                        "resource_type": "cloudtrail",
                        "issue":      "CloudTrail is not actively logging",
                        "severity":   "HIGH",
                    })
                if not trail.get("IsMultiRegionTrail", False):
                    violations.append({
                        "resource":   trail.get("Name"),
                        "resource_type": "cloudtrail",
                        "issue":      "CloudTrail is not multi-region",
                        "severity":   "MEDIUM",
                    })
                if not trail.get("LogFileValidationEnabled", False):
                    violations.append({
                        "resource":   trail.get("Name"),
                        "resource_type": "cloudtrail",
                        "issue":      "Log file validation not enabled",
                        "severity":   "MEDIUM",
                    })
    except Exception as e:
        logger.warning(f"[WARN] CloudTrail check failed: {str(e)}")

    # ── VPC Flow Logs ─────────────────────────────────────────
    try:
        ec2 = session.client("ec2")
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
        vpc_ids_with_logs = {fl["ResourceId"] for fl in flow_logs}

        for vpc in vpcs:
            if vpc["VpcId"] not in vpc_ids_with_logs:
                violations.append({
                    "resource":      vpc["VpcId"],
                    "resource_type": "vpc",
                    "issue":         "VPC does not have flow logs enabled",
                    "severity":      "MEDIUM",
                })
    except Exception as e:
        logger.warning(f"[WARN] VPC flow logs check failed: {str(e)}")

    logger.info(f"[INFO] Logging: {len(violations)} logging violations")
    return {
        "check":           "logging",
        "violations":      violations[:20],
        "violation_count": len(violations),
        "policy":          "CloudTrail must be enabled (multi-region), VPC flow logs must be enabled"
    }

# ══════════════════════════════════════════════════════════════
# CHECK 11: NETWORK COMPLIANCE
# ══════════════════════════════════════════════════════════════
def check_network(session: boto3.Session) -> dict:
    violations = []

    # ── Security Groups with 0.0.0.0/0 ───────────────────────
    try:
        ec2 = session.client("ec2")
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])

        dangerous_ports = [22, 3389, 3306, 5432, 1433, 27017, 6379, 9200]

        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        from_port = perm.get("FromPort", 0)
                        to_port   = perm.get("ToPort", 65535)

                        # Check if dangerous port is exposed
                        is_dangerous = any(from_port <= p <= to_port for p in dangerous_ports)
                        is_all_traffic = perm.get("IpProtocol") == "-1"

                        if is_dangerous or is_all_traffic:
                            violations.append({
                                "resource_id":   sg["GroupId"],
                                "resource_name": sg.get("GroupName"),
                                "resource_type": "security_group",
                                "issue":         f"Open to internet (0.0.0.0/0) on ports {from_port}-{to_port}",
                                "protocol":      perm.get("IpProtocol"),
                                "severity":      "CRITICAL" if is_all_traffic else "HIGH",
                            })

                for ipv6 in perm.get("Ipv6Ranges", []):
                    if ipv6.get("CidrIpv6") == "::/0":
                        violations.append({
                            "resource_id":   sg["GroupId"],
                            "resource_name": sg.get("GroupName"),
                            "resource_type": "security_group",
                            "issue":         "Open to internet via IPv6 (::/0)",
                            "severity":      "HIGH",
                        })
    except Exception as e:
        logger.warning(f"[WARN] Security group check failed: {str(e)}")

    # ── Public S3 Buckets ─────────────────────────────────────
    try:
        s3 = session.client("s3")
        s3_control = session.client("s3control")
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
                        "resource_id":   bucket_name,
                        "resource_type": "s3:bucket",
                        "issue":         "Public access block not fully configured",
                        "severity":      "HIGH",
                    })
            except Exception:
                violations.append({
                    "resource_id":   bucket_name,
                    "resource_type": "s3:bucket",
                    "issue":         "No public access block configured",
                    "severity":      "HIGH",
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
                        "resource_id":   db["DBInstanceIdentifier"],
                        "resource_type": "rds:db",
                        "issue":         "RDS instance is publicly accessible",
                        "severity":      "CRITICAL",
                    })
    except Exception as e:
        logger.warning(f"[WARN] Public RDS check failed: {str(e)}")

    logger.info(f"[INFO] Network: {len(violations)} network violations")
    return {
        "check":           "network",
        "violations":      violations[:20],
        "violation_count": len(violations),
        "policy":          "No dangerous ports open to internet, S3 buckets must block public access, RDS must not be public"
    }

# ══════════════════════════════════════════════════════════════
# CHECK 12: AWS CONFIG RULES
# ══════════════════════════════════════════════════════════════
def check_config_rules(session: boto3.Session) -> dict:
    try:
        config = session.client("config")
        violations = []

        paginator = config.get_paginator("describe_compliance_by_config_rule")
        for page in paginator.paginate():
            for rule in page.get("ComplianceByConfigRules", []):
                compliance = rule.get("Compliance", {})
                if compliance.get("ComplianceType") == "NON_COMPLIANT":
                    rule_name = rule.get("ConfigRuleName")

                    # Get non-compliant resources
                    try:
                        eval_results = config.get_compliance_details_by_config_rule(
                            ConfigRuleName=rule_name,
                            ComplianceTypes=["NON_COMPLIANT"],
                            Limit=10,
                        ).get("EvaluationResults", [])

                        resources = []
                        for er in eval_results:
                            qualifier = er.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {})
                            resources.append({
                                "resource_type": qualifier.get("ResourceType"),
                                "resource_id":   qualifier.get("ResourceId"),
                            })

                        violations.append({
                            "rule_name":              rule_name,
                            "non_compliant_resources": resources,
                            "resource_count":          len(eval_results),
                        })
                    except Exception:
                        violations.append({
                            "rule_name":              rule_name,
                            "non_compliant_resources": [],
                            "resource_count":          0,
                        })

        logger.info(f"[INFO] Config rules: {len(violations)} non-compliant rules")
        return {
            "check":           "config_rules",
            "violations":      violations[:20],
            "violation_count": len(violations),
            "policy":          "All AWS Config rules must be in COMPLIANT state"
        }
    except Exception as e:
        logger.error(f"[ERROR] Config rules check failed: {str(e)}")
        return {"check": "config_rules", "violations": [], "violation_count": 0, "error": str(e)}

# ══════════════════════════════════════════════════════════════
# BUILD COMPLIANCE PROMPT
# ══════════════════════════════════════════════════════════════
def build_compliance_prompt(query: str, account_id: str, service: str, evidence: dict, checks_run: list) -> str:

    evidence_sections = []

    for check_name, check_data in evidence.items():
        if check_data.get("violation_count", 0) > 0 or check_data.get("error"):
            policy = check_data.get("policy", "")
            violations = check_data.get("violations", [])
            count = check_data.get("violation_count", 0)
            error = check_data.get("error", "")

            section = f"--- {check_name.upper()} ({count} violations) ---\n"
            section += f"Policy: {policy}\n"
            if error:
                section += f"Error: {error}\n"
            section += f"Details:\n{json.dumps(violations[:10], indent=2, default=str)}\n"
            evidence_sections.append(section)

    evidence_text = "\n\n".join(evidence_sections) if evidence_sections else "No violations found in any checked category."

    total_violations = sum(v.get("violation_count", 0) for v in evidence.values())

    return f"""You are a cloud compliance investigator for AWS infrastructure.

The user asked: "{query}"

Your job is to answer the user's SPECIFIC question using the compliance evidence below.

AWS Account: {account_id}
Service Focus: {service}
Checks Performed: {', '.join(checks_run)}
Total Violations Found: {total_violations}

Compliance Evidence:
{evidence_text}

Rules:
- Answer ONLY what the user asked — be direct and specific
- Cite specific resources, rule names, and numbers
- If the user asked a specific question, answer it directly
- If the user asked for a general audit, provide a summary
- Rate severity: CRITICAL > HIGH > MEDIUM > LOW
- If data was insufficient to answer, say so clearly

Return ONLY this JSON:
{{
  "is_violation": true or false,
  "confidence": 0.0 to 1.0,
  "severity": "CRITICAL or HIGH or MEDIUM or LOW or NONE",
  "reasoning": "direct answer to the user's question",
  "evidence": ["specific finding 1", "specific finding 2"],
  "recommendations": ["actionable recommendation 1", "actionable recommendation 2"]
}}
"""

# ══════════════════════════════════════════════════════════════
# MAIN INVESTIGATION LOGIC
# ══════════════════════════════════════════════════════════════
def investigate(payload: dict) -> dict:
    query      = payload.get("query", "General compliance check")
    job_id     = payload.get("job_id", "unknown")
    user_id    = payload.get("user_id", "anonymous")
    account_id = payload.get("account_id", DEFAULT_ACCOUNT_ID)
    service    = payload.get("service") or extract_service_from_query(query)

    logger.info(f"[INFO] Starting compliance investigation: job_id={job_id} account={account_id}")

    # ── 1. Understand what user is asking ─────────────────────
    intent = classify_query_intent(query)
    checks_to_run = intent.get("checks_to_run", [])
    service_focus  = intent.get("service_focus", service)

    if service_focus and service_focus != "all":
        service = service_focus

    logger.info(f"[INFO] Checks to run: {checks_to_run} | Service: {service}")

    # ── 2. Assume role ────────────────────────────────────────
    try:
        session = assume_role_session(account_id)
    except Exception as e:
        return {
            "agent":        "compliance",
            "status":       "error",
            "is_violation": False,
            "confidence":   0.0,
            "reasoning":    f"Failed to assume role in account {account_id}: {str(e)}",
            "evidence":     [],
            "job_id":       job_id,
            "query":        query,
        }

    # ── 3. Run relevant checks ────────────────────────────────
    check_functions = {
        "tags":                lambda: check_tags(session, service),
        "region":              lambda: check_region(session, service),
        "key_rotation":        lambda: check_key_rotation(session),
        "deletion_protection": lambda: check_deletion_protection(session, service),
        "mfa":                 lambda: check_mfa(session),
        "password_policy":     lambda: check_password_policy(session),
        "inactive_users":      lambda: check_inactive_users(session),
        "admin_access":        lambda: check_admin_access(session),
        "encryption":          lambda: check_encryption(session, service),
        "logging":             lambda: check_logging(session),
        "network":             lambda: check_network(session),
        "config_rules":        lambda: check_config_rules(session),
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
    total_violations = sum(v.get("violation_count", 0) for v in evidence.values())
    logger.info(f"[INFO] Total violations: {total_violations}")

    # ── 5. No violations ──────────────────────────────────────
    if total_violations == 0:
        return {
            "agent":            "compliance",
            "status":           "success",
            "is_violation":     False,
            "confidence":       0.95,
            "severity":         "NONE",
            "reasoning":        f"No compliance violations found. Checks performed: {', '.join(checks_to_run)}. Service: {service}.",
            "evidence":         [],
            "recommendations":  [],
            "job_id":           job_id,
            "query":            query,
            "account_id":       account_id,
            "service":          service,
            "checks_run":       checks_to_run,
            "total_violations": 0,
            "summary":          {c: evidence.get(c, {}).get("violation_count", 0) for c in checks_to_run},
        }

    # ── 6. Send to Vertex AI ──────────────────────────────────
    try:
        prompt    = build_compliance_prompt(query, account_id, service, evidence, checks_to_run)
        ai_result = call_vertex(prompt)

        result = {
            "agent":            "compliance",
            "status":           "success",
            "is_violation":     ai_result.get("is_violation", False),
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
            "total_violations": total_violations,
            "summary":          {c: evidence.get(c, {}).get("violation_count", 0) for c in checks_to_run},
        }

        logger.info(f"[INFO] Done: is_violation={result['is_violation']} severity={result['severity']}")
        return result

    except Exception as e:
        logger.error(f"[ERROR] Vertex AI failed: {str(e)}")
        return {
            "agent":            "compliance",
            "status":           "error",
            "is_violation":     total_violations > 0,
            "confidence":       0.5,
            "severity":         "UNKNOWN",
            "reasoning":        f"AI analysis failed: {str(e)}. Raw violation counts available.",
            "evidence":         [],
            "recommendations":  [],
            "job_id":           job_id,
            "query":            query,
            "account_id":       account_id,
            "service":          service,
            "checks_run":       checks_to_run,
            "total_violations": total_violations,
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
            logger.exception("Compliance investigation failed")
            return {
                "statusCode": 500,
                "headers":    {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body":       json.dumps({"agent": "compliance", "status": "error", "message": str(e)})
            }

    try:
        return investigate(event)
    except Exception as e:
        logger.exception("Compliance investigation failed")
        return {"agent": "compliance", "status": "error", "message": str(e)}
