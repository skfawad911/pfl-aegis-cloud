"""
FinOps Agent Lambda — Full Capabilities
Uses Vertex AI REST API for intelligent cost analysis and Usage vs. Rate Math.
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta

import boto3
import requests
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from boto3.dynamodb.conditions import Key

# ── LOGGING ───────────────────────────────────────────────────
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── ENV ────────────────────────────────────────────────────────
PROJECT_ID           = os.environ.get('GCP_PROJECT_ID')
LOCATION             = os.environ.get('GCP_LOCATION')
MODEL_ID             = os.environ.get('GCP_MODEL_ID')
SERVICE_ACCOUNT_JSON = json.loads(os.environ.get('GCP_SA_KEY', '{}'))

TABLE_GLOBAL  = os.environ.get('TABLE_GLOBAL', 'pfl-aegis-account-summary').strip()
TABLE_SERVICE = os.environ.get('TABLE_SERVICE', 'pfl-aegis-account-daily-summary').strip()
TABLE_ANOMALY = os.environ.get('TABLE_ANOMALIES', 'pfl-aegis-anomalies').strip() 

CROSS_ACCOUNT_ROLE = os.environ.get('CROSS_ACCOUNT_ROLE_NAME', 'AegisCrossAccountRole').strip()
DEFAULT_ACCOUNT_ID = os.environ.get('DEFAULT_TARGET_ACCOUNT_ID', '644130540803').strip()

# ── DYNAMODB ──────────────────────────────────────────────────
dynamodb = boto3.resource('dynamodb')
table_global     = dynamodb.Table(TABLE_GLOBAL)
table_service    = dynamodb.Table(TABLE_SERVICE)
table_anomalies  = dynamodb.Table(TABLE_ANOMALY)

# ── VERTEX AI ──────────────────────────────────────────────────
def get_access_token():
    creds = service_account.Credentials.from_service_account_info(
        SERVICE_ACCOUNT_JSON, scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    creds.refresh(Request())
    return creds.token

def call_vertex(prompt: str) -> dict:
    token = get_access_token()
    url = (f"https://{LOCATION}-aiplatform.googleapis.com/v1/"
           f"projects/{PROJECT_ID}/locations/{LOCATION}/"
           f"publishers/google/models/{MODEL_ID}:generateContent")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"}
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=120)
    if not resp.ok:
        raise ValueError(f"Vertex error {resp.status_code}: {resp.text}")
    data = resp.json()
    raw = data['candidates'][0]['content']['parts'][0]['text']
    raw = raw.strip().strip("`").strip()
    if raw.startswith("json"):
        raw = raw[4:].strip()
    return json.loads(raw)

def cors_headers():
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
    }

# ══════════════════════════════════════════════════════════════
# DATA READERS
# ══════════════════════════════════════════════════════════════

def get_target_dates(provided_date=None):
    if provided_date:
        try:
            target_dt = datetime.strptime(provided_date, '%Y-%m-%d')
            return provided_date, (target_dt - timedelta(days=1)).strftime('%Y-%m-%d')
        except ValueError:
            logger.warning(f"Invalid date {provided_date}. Defaulting.")
    current_date = (datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d')
    previous_date = (datetime.utcnow() - timedelta(days=2)).strftime('%Y-%m-%d')
    return current_date, previous_date

def read_global_overview(provided_date=None):
    try:
        current_date, _ = get_target_dates(provided_date)
        response = table_global.scan(FilterExpression=Key('date').eq(current_date))
        items = response.get('Items', [])
        total_cost = sum(float(item.get('cost', 0)) for item in items)
        return {"date": current_date, "total_accounts_scanned": len(items), "cost": total_cost, "accounts_data": items}
    except Exception as e:
        logger.error(f"[ERROR] Global overview read failed: {str(e)}")
        return {}

def get_account_summary(account_id: str, fetch_previous: bool = False, provided_date: str = None) -> dict:
    try:
        current_date, previous_date = get_target_dates(provided_date)
        target_date = previous_date if fetch_previous else current_date
        resp = table_global.get_item(Key={"account_id": str(account_id), "date": target_date})
        return resp.get("Item", {})
    except Exception as e:
        logger.error(f"[ERROR] Account summary read failed: {str(e)}")
        return {}

def read_case_file(id_val: str, account_id: str):
    try:
        resp = table_anomalies.get_item(Key={"account_id": str(account_id), "id": str(id_val)})
        return resp.get("Item", {})
    except Exception as e:
        return {}

def read_service_costs(account_id: str, date_str: str, target_service: str) -> list:
    """Queries service table dynamically for ANY requested AWS service."""
    try:
        current_date, _ = get_target_dates(date_str)
        items = []
        last_evaluated_key = None

        while True:
            kwargs = {
                "KeyConditionExpression": Key('account_id').eq(str(account_id)),
                "FilterExpression": Key('date').eq(current_date)
            }
            if last_evaluated_key:
                kwargs["ExclusiveStartKey"] = last_evaluated_key

            resp = table_service.query(**kwargs)
            items.extend(resp.get("Items", []))

            last_evaluated_key = resp.get("LastEvaluatedKey")
            if not last_evaluated_key:
                break

        filtered = []
        for item in items:
            resource = item.get("resource_name", "")
            cost = float(item.get("cost", 0) or 0)

            # Match the requested service string (e.g. "email", "s3", "ec2")
            if target_service in str(resource).lower():
                filtered.append({
                    "resource_name": resource,
                    "resource_id": item.get("id"),
                    "cost": cost,
                    "usage": item.get("usage", 0),
                    "date": item.get("date"),
                    "Risk": item.get("Risk", "N/A"),
                    "L1": item.get("L1"), "L2": item.get("L2")
                })
        return filtered
    except Exception as e:
        logger.error(f"[ERROR] Service query failed: {e}")
        return []

# ══════════════════════════════════════════════════════════════
# USAGE VS RATE ENGINE
# ══════════════════════════════════════════════════════════════

def calculate_usage_vs_rate(current: dict, previous: dict) -> dict:
    result = {"driver": "none", "usage_delta_pct": 0.0, "rate_delta_pct": 0.0, "usage_change": "stable"}
    try:
        cur_cost = float(current.get("cost", 0) or 0)
        prev_cost = float(previous.get("cost", 0) or 0)
    except:
        cur_cost, prev_cost = 0.0, 0.0

    if prev_cost == 0: return result

    delta = ((cur_cost - prev_cost) / prev_cost) * 100
    result["cost_delta_pct"] = round(delta, 2)
    result["rate_delta_pct"] = round(delta, 2)

    try:
        cur_use = float(current.get("usage", 1) or 1)
        prev_use = float(previous.get("usage", 1) or 1)
    except:
        cur_use, prev_use = 1.0, 1.0

    use_delta = ((cur_use - prev_use) / prev_use) * 100 if prev_use else 0
    result["usage_delta_pct"] = round(use_delta, 2)
    result["usage_change"] = "up" if use_delta > 5 else ("down" if use_delta < -5 else "stable")

    if abs(use_delta) < 5 and abs(delta) > 10:
        result["driver"] = "rate"
    elif abs(use_delta) > 10:
        result["driver"] = "usage"
    elif abs(delta) > 10:
        result["driver"] = "mixed"
    return result

# ══════════════════════════════════════════════════════════════
# PROMPT BUILDER
# ══════════════════════════════════════════════════════════════

def build_finops_prompt(query: str, account_id: str, case_data: dict, analysis_context: dict, usage_rate_result: dict) -> str:
    risk_ctx = f"Risk: {case_data.get('Risk', 'N/A')}" if case_data else "N/A"
    resource_ctx = case_data.get("resource_name", "Account aggregate") if case_data else "Account aggregate"

    svc_items = analysis_context.get("current", {}).get("service_items", [])
    svc_items_str = f"Filtered Service Instances:\n{json.dumps(svc_items, indent=2, default=str)}\n" if svc_items else ""

    evidence_json = json.dumps({
        "target_date_queried": analysis_context.get("date_str"),
        "case_file_active": bool(case_data),
        "service_filter_applied": analysis_context.get("filtered_service") != "all",
        "cost_comparison": {
            "current_cost": analysis_context.get("current_cost", 0),
            "previous_cost": analysis_context.get("previous_cost", 0),
            "current_usage": analysis_context.get("current_usage", 0),
            "previous_usage": analysis_context.get("previous_usage", 0)
        },
        "usage_vs_rate_analysis": usage_rate_result
    }, indent=2, default=str)

    return f"""You are a Cloud Financial Analyst (FinOps).

User Query: "{query}"
AWS Account: {account_id}
Resource Focus: {resource_ctx}
Risk: {risk_ctx}

Cost Evidence & Math:
{evidence_json}
{svc_items_str}

CRITICAL INSTRUCTIONS:
1. READ THE USER'S QUERY CAREFULLY. Decide if it is a SIMPLE DATA PULL (e.g., "cost of SES") OR an ANOMALY INVESTIGATION (e.g., "why did costs spike?").
2. IF IT IS A SIMPLE DATA PULL:
   - Answer directly using the evidence provided.
   - Match the user's date to the 'target_date_queried' in the evidence.
   - Set "is_anomaly" to false.
   - Put the direct answer in "financial_root_cause" (e.g., "The resource cost on YYYY-MM-DD was $23.52").
   - Ignore the rate/usage delta math unless it helps answer the query.
3. IF IT IS AN ANOMALY INVESTIGATION:
   - Set "is_anomaly" to true.
   - Explain if the driver is "usage" or "rate".

Return ONLY this JSON:
{{
  "agent": "finops",
  "status": "success",
  "is_anomaly": true or false,
  "confidence": 0.9,
  "driver": "usage | rate | mixed | none",
  "usage_delta_pct": 0.0,
  "cost_delta_pct": 0.0,
  "financial_root_cause": "Direct answer to the user's query OR the anomaly explanation.",
  "resource_focus": "Specific resource or account aggregate",
  "usage_details": "Explanation of usage changes.",
  "rate_details": "Explanation of rate changes.",
  "recommendations": ["action 1"],
  "evidence_points": ["Point 1 referencing exact cost numbers"],
  "correlation_hint": "null"
}}
"""

# ══════════════════════════════════════════════════════════════
# MAIN LOGIC
# ══════════════════════════════════════════════════════════════

def investigate(payload: dict) -> dict:
    query = payload.get("query", "Analyze cost")
    job_id = payload.get("job_id", "unknown")
    account_id = payload.get("account_id", DEFAULT_ACCOUNT_ID).strip()
    service = payload.get("service", "all").strip()
    investigation_id = payload.get("investigation_id")
    source = payload.get("source", "api")
    date_input = payload.get("date")

    query_lower = query.lower()

    if "yesterday" in query_lower or "yesterdays" in query_lower:
        date_str = (datetime.now(timezone.utc) - timedelta(days=1)).strftime('%Y-%m-%d')
    else:
        date_str, _ = get_target_dates(date_input)

    # ── UNIVERSAL SERVICE CATCHER ──
    aws_services = {
        "ec2": "ec2", "s3": "s3", "rds": "rds", "lambda": "lambda",
        "email": "email", "ses": "ses", "dynamo": "dynamo", "cloudfront": "cloudfront",
        "cloudwatch": "cloudwatch", "config": "config", "vpc": "vpc", "security hub": "security hub"
    }

    target_service = None
    for kw, search_term in aws_services.items():
        if kw in query_lower:
            target_service = search_term
            break

    logger.info(f"[INFO] FinOps: job={job_id} acct={account_id} date={date_str} service_target={target_service}")

    case_data = None
    current_summary = {}
    previous_summary = {}

    if investigation_id:
        case_data = read_case_file(str(investigation_id), account_id)
        if case_data:
            current_summary = case_data
            previous_summary = get_account_summary(account_id, fetch_previous=True, provided_date=case_data.get("date", date_str))
        else:
            current_summary = get_account_summary(account_id, provided_date=date_str)
            previous_summary = get_account_summary(account_id, fetch_previous=True, provided_date=date_str)

    elif account_id.lower() == "all" or "all accounts" in query_lower:
        current_summary = read_global_overview(provided_date=date_str)
        previous_summary = {} 

    else:
        if target_service:
            svc_items = read_service_costs(account_id, date_str, target_service) 
            if svc_items:
                total_svc_cost = sum(float(i.get("cost", 0)) for i in svc_items)
                current_summary = {
                    "cost": total_svc_cost,
                    "usage": sum(float(i.get("usage", 0)) for i in svc_items),
                    "date": date_str,
                    "service_items": svc_items,
                    "filtered_service": target_service
                }
                _, prev_date = get_target_dates(date_str)
                prev_svc_items = read_service_costs(account_id, prev_date, target_service)
                previous_summary = {
                    "cost": sum(float(i.get("cost", 0)) for i in prev_svc_items) if prev_svc_items else 0,
                    "usage": sum(float(i.get("usage", 0)) for i in prev_svc_items) if prev_svc_items else 0,
                    "date": prev_date
                }
            else:
                current_summary = {
                    "cost": 0, "usage": 0, "date": date_str,
                    "service_items": [], "filtered_service": target_service
                }
                previous_summary = {}
            service = target_service
        else:
            current_summary = get_account_summary(account_id, provided_date=date_str)
            previous_summary = get_account_summary(account_id, fetch_previous=True, provided_date=date_str)

    analysis_context = {
        "investigation_id": investigation_id,
        "account_id": account_id,
        "service": service,
        "date_str": date_str,
        "filtered_service": target_service if target_service else "all",
        "current": current_summary,
        "previous": previous_summary,
        "current_cost": current_summary.get("cost", 0),
        "current_usage": current_summary.get("usage", 0),
        "previous_cost": previous_summary.get("cost", 0),
        "previous_usage": previous_summary.get("usage", 0),
    }

    usage_rate_result = calculate_usage_vs_rate(current_summary, previous_summary)

    try:
        prompt = build_finops_prompt(query, account_id, case_data, analysis_context, usage_rate_result)
        ai_result = call_vertex(prompt)

        result = {
            "agent": "finops",
            "status": "success",
            "job_id": job_id,
            "query": query,
            "account_id": account_id,
            "service": service,
            "investigation_id": investigation_id,
            "source": source,
            "date_queried": date_str,
            "is_anomaly": ai_result.get("is_anomaly", False),
            "confidence": ai_result.get("confidence", 0.9),
            "severity": ai_result.get("severity", "LOW"),
            "driver": usage_rate_result.get("driver", "none"),
            "usage_delta_pct": usage_rate_result.get("usage_delta_pct", 0),
            "cost_delta_pct": usage_rate_result.get("cost_delta_pct", 0),
            "financial_root_cause": ai_result.get("financial_root_cause", "Analysis complete."),
            "usage_details": ai_result.get("usage_details", "N/A"),
            "rate_details": ai_result.get("rate_details", "N/A"),
            "resource_focus": case_data.get("resource_name") if case_data else (current_summary.get("service_items", [{}])[0].get("resource_name") if current_summary.get("service_items") else "Account aggregate"),
            "recommendations": ai_result.get("recommendations", []),
            "evidence_points": ai_result.get("evidence_points", []),
            "analysis_summary": {
                "date_queried": date_str,
                "current_spend": current_summary.get("cost", 0),
                "previous_spend": previous_summary.get("cost", 0),
                "resource_name": target_service
            }
        }
        return result

    except Exception as e:
        logger.error(f"[ERROR] Vertex AI synthesis failed: {str(e)}")
        return {"agent": "finops", "status": "error", "error": str(e)}

# ── HANDLER ───────────────────────────────────────────────────
def lambda_handler(event, context):
    if "requestContext" in event and "http" in event.get("requestContext", {}):
        method = event.get("requestContext", {}).get("http", {}).get("method", "POST")
        raw_path = event.get("rawPath", event.get("path", ""))

        if method == "OPTIONS":
            return {"statusCode": 200, "headers": cors_headers(), "body": ""}

        if method == "GET" and "/finops/anomalies" in raw_path:
            try:
                summary = read_global_overview()
                return {"statusCode": 200, "headers": cors_headers(), "body": json.dumps({"status": "success", "dashboard": summary}, default=str)}
            except Exception as e:
                return {"statusCode": 500, "headers": cors_headers(), "body": json.dumps({"status": "error", "message": str(e)})}

        try:
            body_str = event.get("body") or "{}"
            body = json.loads(body_str) if body_str and body_str != "null" else {}

            payload = {
                "query": body.get("message") or body.get("query", "Analyze cost"),
                "user_id": body.get("user_id", "anonymous"),
                "job_id": body.get("job_id", event.get("requestContext", {}).get("requestId", "unknown")),
                "account_id": body.get("account_id", DEFAULT_ACCOUNT_ID).strip(),
                "service": body.get("service", "all").strip(),
                "investigation_id": body.get("investigation_id"),
                "source": "api",
                "date": body.get("date")
            }

            result = investigate(payload)
            return {"statusCode": 200, "headers": cors_headers(), "body": json.dumps(result, default=str)}
        except Exception as e:
            return {"statusCode": 500, "headers": cors_headers(), "body": json.dumps({"agent": "finops", "status": "error", "message": str(e)})}

    try:
        if "date" not in event and isinstance(event, dict):
            event["date"] = event.get("date")
        return investigate(event)
    except Exception as e:
        return {"agent": "finops", "status": "error", "message": str(e)}
