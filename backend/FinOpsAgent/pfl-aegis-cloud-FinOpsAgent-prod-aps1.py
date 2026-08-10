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

# ── ENV ────────────────────────────────────────────────────────
PROJECT_ID           = os.environ.get('GCP_PROJECT_ID')
LOCATION             = os.environ.get('GCP_LOCATION')
MODEL_ID             = os.environ.get('GCP_MODEL_ID')
SERVICE_ACCOUNT_JSON = json.loads(os.environ.get('GCP_SA_KEY', '{}'))

TABLE_GLOBAL  = os.environ.get('TABLE_GLOBAL', 'pfl-aegis-account-summary').strip()
TABLE_SERVICE = os.environ.get('TABLE_SERVICE', 'pfl-aegis-account-daily-summary').strip()
TABLE_ANOMALY  = os.environ.get('TABLE_ANOMALIES', 'pfl-aegis-anomalies').strip()
JOB_TABLE     = os.environ.get('JOB_TABLE_NAME', 'pfl-aegis-agent-jobs').strip()

CROSS_ACCOUNT_ROLE = os.environ.get('CROSS_ACCOUNT_ROLE_NAME', 'AegisCrossAccountRole').strip()
DEFAULT_ACCOUNT_ID = os.environ.get('DEFAULT_TARGET_ACCOUNT_ID', '644130540803').strip()

# ── DYNAMODB ──────────────────────────────────────────────────
dynamodb = boto3.resource('dynamodb')
table_global     = dynamodb.Table(TABLE_GLOBAL)
table_service    = dynamodb.Table(TABLE_SERVICE)
table_anomalies  = dynamodb.Table(TABLE_ANOMALY)
table_job        = dynamodb.Table(JOB_TABLE)

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

def get_account_summary(account_id: str, date_str: str = None) -> dict:
    try:
        date_str = date_str or datetime.now(timezone.utc).strftime('%Y-%m-%d')
        # FIX: Read from global/account summary table
        resp = table_global.get_item(Key={"account_id": account_id, "date": date_str})
        return resp.get("Item", {})
    except Exception as e:
        logger.error(f"[ERROR] Global/account summary read failed table={TABLE_GLOBAL}: {e}")
        return {}

def get_previous_account_summary(account_id: str, date_str: str) -> dict:
    try:
        prev = (datetime.fromisoformat(date_str) - timedelta(days=1)).strftime('%Y-%m-%d')
        resp = table_global.get_item(Key={"account_id": account_id, "date": prev})
        return resp.get("Item", {})
    except Exception as e:
        return {}

def read_case_file(id_val: str) -> dict:
    try:
        resp = table_anomalies.get_item(Key={"id": id_val})
        return resp.get("Item", {})
    except Exception as e:
        logger.error(f"[ERROR] Case file read failed: {e}")
        return {}

def read_ec2_high_cost(account_id: str, date_str: str = None, threshold: float = 10.0) -> list:
    try:
        date_str = date_str or datetime.now(timezone.utc).strftime('%Y-%m-%d')
        dates_to_try = [date_str]
        base = datetime.fromisoformat(date_str) if date_str else datetime.now(timezone.utc)
        for i in range(1, 4):
            prev_day = (base - timedelta(days=i)).strftime('%Y-%m-%d')
            if prev_day not in dates_to_try:
                dates_to_try.append(prev_day)
        
        all_items = []
        for d in dates_to_try:
            resp = table_anomalies.query(
                KeyConditionExpression=boto3.dynamodb.conditions.Key('account_id').eq(account_id) &
                                      boto3.dynamodb.conditions.Key('date').eq(d)
            )
            items = resp.get("Items", [])
            for item in items:
                resource = item.get("resource_name", "")
                cost = float(item.get("cost", 0) or 0)
                if ("ec2" in str(resource).lower() or "EC2" in str(resource)) and cost > threshold:
                    all_items.append({
                        "resource_name": resource,
                        "resource_id": item.get("id"),
                        "cost": cost,
                        "usage": item.get("usage", 0),
                        "date": item.get("date"),
                        "Risk": item.get("Risk", "N/A"),
                        "L1": item.get("L1"), "L2": item.get("L2"),
                        "L3": item.get("L3"), "L4": item.get("L4"), "L5": item.get("L5")
                    })
        seen = set()
        unique_items = []
        for i in all_items:
            if i["resource_id"] not in seen:
                seen.add(i["resource_id"])
                unique_items.append(i)
        logger.info(f"[INFO] EC2 filter: found {len(unique_items)} resources > ${threshold} (tried dates: {dates_to_try})")
        return unique_items
    except Exception as e:
        logger.error(f"[ERROR] EC2 high cost query failed: {e}")
        return []

# ══════════════════════════════════════════════════════════════
# USAGE VS RATE ENGINE
# ══════════════════════════════════════════════════════════════

def calculate_usage_vs_rate(current: dict, previous: dict) -> dict:
    result = {
        "driver": "unknown",
        "usage_delta_pct": 0.0,
        "rate_delta_pct": 0.0,
        "usage_change": "stable",
        "cost_delta_pct": 0.0
    }
    cur_cost = float(current.get("cost", 0) or 0)
    prev_cost = float(previous.get("cost", 0) or 0)
    if prev_cost == 0:
        result["driver"] = "none"
        return result
    delta = ((cur_cost - prev_cost) / prev_cost) * 100
    result["cost_delta_pct"] = round(delta, 2)

    cur_use = float(current.get("usage", 1) or 1)
    prev_use = float(previous.get("usage", 1) or 1)
    use_delta = ((cur_use - prev_use) / prev_use) * 100 if prev_use else 0
    result["usage_delta_pct"] = round(use_delta, 2)
    result["usage_change"] = "up" if use_delta > 5 else ("down" if use_delta < -5 else "stable")

    if abs(use_delta) < 5 and abs(delta) > 10:
        result["driver"] = "rate"
        result["rate_delta_pct"] = round(delta, 2)
    elif abs(use_delta) > 10:
        result["driver"] = "usage"
    elif abs(delta) > 10:
        result["driver"] = "mixed"
    else:
        result["driver"] = "none"
    return result

# ══════════════════════════════════════════════════════════════
# PROMPT BUILDER
# ══════════════════════════════════════════════════════════════

def build_finops_prompt(query: str, account_id: str, case_data: dict, analysis: dict, evidence: dict) -> str:
    filters = f"L1={case_data.get('L1')}, L2={case_data.get('L2')}, L3={case_data.get('L3')}, L4={case_data.get('L4')}, L5={case_data.get('L5')}" if case_data else "N/A"
    risk_ctx = f"Risk: {case_data.get('Risk', 'N/A')}" if case_data else "N/A"
    resource_ctx = case_data.get("resource_name", "Account aggregate") if case_data else "Account aggregate"

    ec2_items_str = ""
    ec2_items = analysis.get("current", {}).get("ec2_high_cost_items", [])
    if ec2_items:
        ec2_items_str = f"Filtered EC2 Instances (cost > $10):\n{json.dumps(ec2_items, indent=2, default=str)}\n"

    evidence_json = json.dumps({
        "case_file": {
            "id": case_data.get("id") if case_data else None,
            "resource_name": case_data.get("resource_name") if case_data else None,
            "date": case_data.get("date") if case_data else None,
            "Risk": case_data.get("Risk") if case_data else None,
            "filters": filters
        },
        "date_range": analysis.get("date_range"),
        "ec2_filter_applied": analysis.get("filtered_service") == "ec2",
        "ec2_high_cost_items": ec2_items,
        "cost_comparison": {
            "current_cost": analysis.get("current_cost", 0),
            "previous_cost": analysis.get("previous_cost", 0),
            "current_usage": analysis.get("current_usage", 0),
            "previous_usage": analysis.get("previous_usage", 0)
        },
        "usage_vs_rate_analysis": analysis,
        "evidence_sources": list(evidence.keys())
    }, indent=2, default=str)

    return f"""You are a Senior Cloud Financial Analyst (FinOps) investigating AWS costs.

Query: "{query}"
Account: {account_id}
Resource Focus: {resource_ctx}
Risk: {risk_ctx}
Filters: {filters}

FINANCIAL EVIDENCE:
{evidence_json}
{ec2_items_str}

USAGE VS RATE:
- Driver: {analysis.get('driver', 'unknown')}
- Cost Delta: {analysis.get('cost_delta_pct', 0)}%
- Usage Delta: {analysis.get('usage_delta_pct', 0)}%

INSTRUCTIONS:
- If user asks for "ec2" or "instance" with cost thresholds (e.g., "> $10"), use the "ec2_high_cost_items" list specifically.
- If the list shows resources above the threshold, quote their exact cost, usage, and risk.
- Provide financial root cause (usage vs rate) and specific recommendations.
- Include correlation hint for Security/Compliance if risk is present.

Return ONLY this JSON:
{{
  "agent": "finops",
  "status": "success",
  "is_anomaly": true,
  "confidence": 0.9,
  "driver": "usage | rate | mixed | none",
  "usage_delta_pct": 0.0,
  "cost_delta_pct": 0.0,
  "financial_root_cause": "Concise explanation referencing actual costs and resources.",
  "resource_focus": "Specific EC2 resource or account aggregate",
  "usage_details": "Usage metric details for queried resource(s).",
  "rate_details": "Rate/pricing explanation if applicable.",
  "recommendations": ["Specific AWS action 1", "Specific AWS action 2"],
  "evidence_points": ["Point 1 referencing data", "Point 2 referencing data"],
  "correlation_hint": "Suggest Security/Compliance correlation if high risk present."
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

    # FIX: Handle "yesterday" in query text
    date_input = payload.get("date")
    date_range_start = None
    query_lower = query.lower()
    if "yesterday" in query_lower or "yesterdays" in query_lower:
        date_str = (datetime.now(timezone.utc) - timedelta(days=1)).strftime('%Y-%m-%d')
    elif date_input and " to " in str(date_input):
        parts = str(date_input).split(" to ")
        date_range_start = parts[0].strip()
        date_str = parts[1].strip()
    else:
        date_str = date_input if date_input else datetime.now(timezone.utc).strftime('%Y-%m-%d')

    logger.info(f"[INFO] FinOps: job={job_id} acct={account_id} date={date_str} range_start={date_range_start} case={investigation_id}")

    # FIX: Detect EC2 filter query (includes "give", "spend", "last", "days", etc.)
    is_ec2_filter = ("ec2" in query_lower) and (any(x in query_lower for x in ["spend", "cost", "price", "higher", ">", "above", "last", "days", "instance", "bill", "amount", "give", "10"]))

    case_data = None
    current_summary = {}
    previous_summary = {}

    # ── CASE MODE ──────────────────────────────────────────────
    if investigation_id:
        case_data = read_case_file(str(investigation_id))
        if case_data:
            account_id = case_data.get("account_id", account_id)
            current_summary = {
                "cost": case_data.get("cost", 0),
                "usage": case_data.get("usage", 0),
                "date": case_data.get("date") or date_str
            }
            case_date = case_data.get("date") or date_str
            previous_summary = get_previous_account_summary(account_id, case_date)
        else:
            current_summary = get_account_summary(account_id, date_str)
            previous_summary = get_previous_account_summary(account_id, date_str)
    else:
        # ── DIRECT MODE ────────────────────────────────────────
        if is_ec2_filter:
            ec2_items = read_ec2_high_cost(account_id, date_str, threshold=10.0)
            # If range implied ("last 2 days") and no results on "to" date, try "from" date
            if not ec2_items and date_range_start:
                ec2_items = read_ec2_high_cost(account_id, date_range_start, threshold=10.0)
            
            if ec2_items:
                total_ec2_cost = sum(float(i.get("cost", 0)) for i in ec2_items)
                current_summary = {
                    "cost": total_ec2_cost,
                    "usage": sum(float(i.get("usage", 0)) for i in ec2_items),
                    "date": date_str,
                    "ec2_high_cost_items": ec2_items,
                    "filtered_service": "ec2"
                }
                prev_ec2_items = read_ec2_high_cost(account_id, (datetime.fromisoformat(date_str) - timedelta(days=1)).strftime('%Y-%m-%d'), threshold=10.0)
                prev_cost = sum(float(i.get("cost", 0)) for i in prev_ec2_items) if prev_ec2_items else 0
                previous_summary = {
                    "cost": prev_cost,
                    "usage": sum(float(i.get("usage", 0)) for i in prev_ec2_items) if prev_ec2_items else 0,
                    "date": (datetime.fromisoformat(date_str) - timedelta(days=1)).strftime('%Y-%m-%d')
                }
            else:
                current_summary = {
                    "cost": 0,
                    "usage": 0,
                    "date": date_str,
                    "ec2_high_cost_items": [],
                    "filtered_service": "ec2",
                    "filter_note": f"No EC2 instances found with cost > $10 for date {date_str}."
                }
                previous_summary = {}
            # Force service focus
            service = "ec2"
        else:
            # FIX: Read from global/account summary (not service table)
            current_summary = get_account_summary(account_id, date_str)
            previous_summary = get_previous_account_summary(account_id, date_str)
            # If range and empty, try start date
            if (not current_summary) and date_range_start:
                current_summary = get_account_summary(account_id, date_range_start)
                previous_summary = get_previous_account_summary(account_id, date_range_start)

    # Build analysis context
    analysis_context = {
        "investigation_id": investigation_id,
        "account_id": account_id,
        "service": service,
        "date_str": date_str,
        "date_range": {"from": date_range_start, "to": date_str} if date_range_start else None,
        "filtered_service": "ec2" if is_ec2_filter else service,
        "current": current_summary,
        "previous": previous_summary,
        "current_cost": current_summary.get("cost", 0),
        "current_usage": current_summary.get("usage", 0),
        "previous_cost": previous_summary.get("cost", 0),
        "previous_usage": previous_summary.get("usage", 0),
    }

    usage_rate_result = calculate_usage_vs_rate(current_summary, previous_summary)

    # Correlation hint
    correlation_hint = ""
    case_risk = case_data.get("Risk", "N/A") if case_data else "N/A"
    case_resource = case_data.get("resource_name", "N/A") if case_data else "N/A"

    if is_ec2_filter and current_summary.get("ec2_high_cost_items"):
        ec2_names = ", ".join([i.get("resource_name", "EC2") for i in current_summary["ec2_high_cost_items"][:3]])
        correlation_hint = f"EC2 instances with cost > $10 found: {ec2_names}. Recommend Security and Compliance investigation for these resources."
    elif investigation_id and usage_rate_result.get("driver") != "none":
        correlation_hint = f"Cost spike during investigation (Risk: {case_risk}, Resource: {case_resource}). Recommend Manager Agent to correlate with Security and Compliance findings."
    elif usage_rate_result.get("driver") == "usage" and usage_rate_result.get("usage_delta_pct", 0) > 20:
        correlation_hint = "Usage spike detected. Recommend Security/Compliance check."

    # Evidence package
    evidence = {
        "source": "Case Mode" if investigation_id else ("EC2 Filter" if is_ec2_filter else "Direct Mode / Yesterday"),
        "date_queried": date_str,
        "date_range_start": date_range_start,
        "case_file_read": bool(case_data),
        "current_record": current_summary,
        "previous_record": previous_summary,
        "usage_vs_rate_raw": usage_rate_result,
        "ec2_filter_applied": is_ec2_filter,
        "ec2_items_found": len(current_summary.get("ec2_high_cost_items", []))
    }

    # Vertex AI synthesis
    try:
        prompt = build_finops_prompt(query, account_id, case_data, usage_rate_result, evidence)
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
            "date_range_start": date_range_start,
            "is_anomaly": (usage_rate_result.get("driver") != "none") if not is_ec2_filter else (len(current_summary.get("ec2_high_cost_items", [])) > 0),
            "confidence": ai_result.get("confidence", 0.9),
            "severity": ai_result.get("severity", "LOW") if ai_result.get("severity") else ("HIGH" if usage_rate_result.get("cost_delta_pct", 0) > 50 else "MEDIUM"),
            "driver": usage_rate_result.get("driver", ai_result.get("driver", "unknown")),
            "usage_delta_pct": usage_rate_result.get("usage_delta_pct", 0),
            "cost_delta_pct": usage_rate_result.get("cost_delta_pct", 0),
            "financial_root_cause": ai_result.get("financial_root_cause", f"Driver: {usage_rate_result.get('driver')}. Cost delta: {usage_rate_result.get('cost_delta_pct')}%. Usage delta: {usage_rate_result.get('usage_delta_pct')}%."),
            "usage_details": ai_result.get("usage_details", f"Usage delta: {usage_rate_result.get('usage_delta_pct')}%."),
            "rate_details": ai_result.get("rate_details", "No rate change detected."),
            "resource_focus": case_data.get("resource_name") if case_data else (current_summary.get("ec2_high_cost_items", [{}])[0].get("resource_name") if current_summary.get("ec2_high_cost_items") else "Account aggregate"),
            "risk_assessment": f"Risk: {case_risk}" + (f" | EC2 items > $10: {len(current_summary.get('ec2_high_cost_items', []))}" if is_ec2_filter else ""),
            "recommendations": ai_result.get("recommendations", []),
            "evidence_points": ai_result.get("evidence_points", []),
            "correlation_hint": ai_result.get("correlation_hint", correlation_hint),
            "filtered_service": "ec2" if is_ec2_filter else service,
            "ec2_high_cost_items": current_summary.get("ec2_high_cost_items", []),
            "filter_applied": "cost > $10 and resource contains EC2" if is_ec2_filter else "none",
            "analysis_summary": {
                "date_queried": date_str,
                "date_range_start": date_range_start,
                "current_spend": current_summary.get("cost", 0),
                "previous_spend": previous_summary.get("cost", 0),
                "current_usage": current_summary.get("usage", 0),
                "previous_usage": previous_summary.get("usage", 0),
                "investigation_mode": bool(investigation_id),
                "resource_name": case_data.get("resource_name") if case_data else (current_summary.get("ec2_high_cost_items", [{}])[0].get("resource_name") if current_summary.get("ec2_high_cost_items") else None),
                "ec2_items_found": len(current_summary.get("ec2_high_cost_items", [])),
                "case_risk": case_risk,
                "case_filters": {
                    "L1": case_data.get("L1") if case_data else None,
                    "L2": case_data.get("L2") if case_data else None,
                    "L3": case_data.get("L3") if case_data else None,
                    "L4": case_data.get("L4") if case_data else None,
                    "L5": case_data.get("L5") if case_data else None
                },
                "correlation_target": correlation_hint
            }
        }

        logger.info(f"[INFO] FinOps done: filter={is_ec2_filter} ec2_items={len(current_summary.get('ec2_high_cost_items', []))} driver={result['driver']}")
        return result

    except Exception as e:
        logger.error(f"[ERROR] Vertex AI synthesis failed: {str(e)}")
        return {
            "agent": "finops",
            "status": "error",
            "job_id": job_id,
            "query": query,
            "account_id": account_id,
            "service": service,
            "investigation_id": investigation_id,
            "source": source,
            "date_queried": date_str,
            "is_anomaly": len(current_summary.get("ec2_high_cost_items", [])) > 0,
            "driver": usage_rate_result.get("driver"),
            "usage_delta_pct": usage_rate_result.get("usage_delta_pct", 0),
            "cost_delta_pct": usage_rate_result.get("cost_delta_pct", 0),
            "financial_root_cause": f"Vertex AI unavailable. Filter: ec2 > $10 found: {len(current_summary.get('ec2_high_cost_items', []))} items.",
            "resource_focus": current_summary.get("ec2_high_cost_items", [{}])[0].get("resource_name") if current_summary.get("ec2_high_cost_items") else "None",
            "ec2_high_cost_items": current_summary.get("ec2_high_cost_items", []),
            "filtered_service": "ec2" if is_ec2_filter else service,
            "filter_applied": "cost > $10 and resource contains EC2" if is_ec2_filter else "none",
            "recommendations": ["Check DynamoDB table directly.", "Review billing console for EC2 costs."],
            "analysis_summary": {
                "date_queried": date_str,
                "date_range_start": date_range_start,
                "current_spend": current_summary.get("cost", 0),
                "previous_spend": previous_summary.get("cost", 0),
                "ec2_items_found": len(current_summary.get("ec2_high_cost_items", [])),
                "ec2_items": current_summary.get("ec2_high_cost_items", []),
                "investigation_mode": bool(investigation_id),
                "case_risk": case_risk,
                "case_filters": {
                    "L1": case_data.get("L1") if case_data else None,
                    "L2": case_data.get("L2") if case_data else None,
                    "L3": case_data.get("L3") if case_data else None,
                    "L4": case_data.get("L4") if case_data else None,
                    "L5": case_data.get("L5") if case_data else None
                },
                "correlation_target": correlation_hint
            },
            "raw_evidence": {
                "current_summary": current_summary,
                "previous_summary": previous_summary,
                "usage_vs_rate_raw": usage_rate_result
            },
            "error": str(e)
        }

# ── HANDLER ───────────────────────────────────────────────────
def lambda_handler(event, context):
    logger.info(f"[INFO] Incoming event keys: {list(event.keys())}")
    print("Incoming body:", event.get("body"))

    logger.info(f"[DEBUG] TABLES -> GLOBAL={TABLE_GLOBAL} SERVICE={TABLE_SERVICE} ANOMALY={TABLE_ANOMALY} JOB={JOB_TABLE}")

    # Handle API Gateway
    if "requestContext" in event and "http" in event.get("requestContext", {}):
        method = event.get("requestContext", {}).get("http", {}).get("method", "POST")
        raw_path = event.get("rawPath", event.get("path", ""))

        if method == "OPTIONS":
            return {"statusCode": 200, "headers": cors_headers(), "body": ""}

        # GET /cases/{id}
        if method == "GET" and "/cases/" in raw_path:
            try:
                case_id = raw_path.split("/")[-1] if raw_path.split("/")[-1] else raw_path.split("/")[-2]
                resp = table_job.get_item(Key={"job_id": case_id})
                item = resp.get("Item", {})
                if not item:
                    return {
                        "statusCode": 404,
                        "headers": cors_headers(),
                        "body": json.dumps({
                            "status": "not_found",
                            "message": f"Job/Case {case_id} not found",
                            "case_id": case_id,
                            "table_checked": JOB_TABLE
                        })
                    }
                result_data = item.get("result")
                if isinstance(result_data, str):
                    try:
                        result_data = json.loads(result_data)
                    except:
                        result_data = {}
                return {
                    "statusCode": 200,
                    "headers": cors_headers(),
                    "body": json.dumps({
                        "status": item.get("status", "unknown"),
                        "job_id": case_id,
                        "agent_used": item.get("agent_used"),
                        "investigation_id": case_id,
                        "result": result_data,
                        "case_summary": {
                            "query": item.get("query"),
                            "date_queried": result_data.get("date_queried") if isinstance(result_data, dict) else None
                        }
                    }, default=str)
                }
            except Exception as e:
                logger.error(f"[ERROR] GET case failed: {e}")
                return {
                    "statusCode": 500,
                    "headers": cors_headers(),
                    "body": json.dumps({
                        "status": "error",
                        "message": str(e),
                        "route": "GET /cases/{id}"
                    })
                }

        # GET /dashboard
        if method == "GET" and ("/dashboard" in raw_path or raw_path.endswith("/dashboard")):
            try:
                resp = table_global.get_item(Key={"summary_id": "latest"})
                item = resp.get("Item", {})
                return {
                    "statusCode": 200,
                    "headers": cors_headers(),
                    "body": json.dumps({
                        "agent": "finops",
                        "status": "success",
                        "global_summary": item
                    }, default=str)
                }
            except Exception as e:
                return {
                    "statusCode": 500,
                    "headers": cors_headers(),
                    "body": json.dumps({"status": "error", "message": str(e)})
                }

        # POST routes
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

            if "/finops/scan" in raw_path:
                payload["query"] = "Full cost scan and anomaly detection"
            elif "/finops/anomalies" in raw_path:
                payload["query"] = "Retrieve cost anomalies"

            result = investigate(payload)
            return {
                "statusCode": 200,
                "headers": cors_headers(),
                "body": json.dumps(result, default=str)
            }

        except json.JSONDecodeError:
            return {"statusCode": 400, "headers": cors_headers(), "body": json.dumps({"agent": "finops", "status": "error", "message": "Invalid JSON"})}
        except Exception as e:
            logger.exception("API error")
            return {"statusCode": 500, "headers": cors_headers(), "body": json.dumps({"agent": "finops", "status": "error", "message": str(e)})}

    # Direct Lambda invoke
    try:
        if "date" not in event and isinstance(event, dict):
            event["date"] = event.get("date")
        return investigate(event)
    except Exception as e:
        logger.exception("Direct invoke error")
        return {"agent": "finops", "status": "error", "message": str(e)}
