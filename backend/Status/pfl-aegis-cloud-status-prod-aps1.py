import json
import os
import boto3

# ── AWS DynamoDB ──────────────────────────────────────────────
dynamodb = boto3.resource('dynamodb')
table    = dynamodb.Table(os.environ['JOB_TABLE_NAME'])

# ── CORS ──────────────────────────────────────────────────────
def cors_headers():
    return {
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,GET"
    }

# ── PARSE ALL AGENTS RESULT ───────────────────────────────────
def parse_all_agents_result(result: list) -> dict:
    combined = {
        "finops":     None,
        "security":   None,
        "compliance": None,
    }

    for agent_result in result:
        if isinstance(agent_result, dict):
            agent_name = agent_result.get("agent", "unknown")
            if agent_name in combined:
                combined[agent_name] = agent_result

    finops_data     = combined.get("finops") or {}
    security_data   = combined.get("security") or {}
    compliance_data = combined.get("compliance") or {}

    agents_success = sum(
        1 for d in [finops_data, security_data, compliance_data]
        if d.get("status") == "success"
    )
    agents_error = sum(
        1 for d in [finops_data, security_data, compliance_data]
        if d.get("status") == "error"
    )

    severity_rank    = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}
    severities       = [security_data.get("severity", "NONE"), compliance_data.get("severity", "NONE")]
    overall_severity = max(severities, key=lambda s: severity_rank.get(s, 0))

    summary = {
        "agents_responded": 3,
        "agents_success":   agents_success,
        "agents_error":     agents_error,
        "overall_severity": overall_severity,
        "finops": {
            "status": finops_data.get("status", "no response"),
            "error":  finops_data.get("message") if finops_data.get("status") == "error" else None,
        },
        "security": {
            "status":      security_data.get("status", "no response"),
            "is_incident": security_data.get("is_incident", False),
            "severity":    security_data.get("severity", "NONE"),
            "error":       security_data.get("message") if security_data.get("status") == "error" else None,
        },
        "compliance": {
            "status":       compliance_data.get("status", "no response"),
            "is_violation": compliance_data.get("is_violation", False),
            "severity":     compliance_data.get("severity", "NONE"),
            "error":        compliance_data.get("message") if compliance_data.get("status") == "error" else None,
        },
    }

    return {
        "agent_used": "all",
        "summary":    summary,
        "results": {
            "finops":     finops_data     or None,
            "security":   security_data   or None,
            "compliance": compliance_data or None,
        }
    }

# ── PARSE CORRELATION RESULT ──────────────────────────────────
def parse_correlation_result(result: dict) -> dict:
    finops_data     = result.get("finops_result", {})
    security_data   = result.get("security_result", {})
    compliance_data = result.get("compliance_result", {})

    severity_rank    = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}
    severities       = [
        security_data.get("severity", "NONE"),
        compliance_data.get("severity", "NONE"),
        "HIGH" if finops_data.get("is_anomaly") else "NONE"
    ]
    overall_severity = max(severities, key=lambda s: severity_rank.get(s, 0))

    return {
        "agent_used":       "finops_with_correlation",
        "triggered_by":     "cost_anomaly_auto_investigation",
        "overall_severity": overall_severity,
        "summary": {
            "finops": {
                "status":           finops_data.get("status", "unknown"),
                "is_anomaly":       finops_data.get("is_anomaly", False),
                "cost_delta":       finops_data.get("cost_delta_pct", 0),
                "driver":           finops_data.get("driver", "unknown"),
                "correlation_hint": finops_data.get("correlation_hint", ""),
            },
            "security": {
                "status":      security_data.get("status", "unknown"),
                "is_incident": security_data.get("is_incident", False),
                "severity":    security_data.get("severity", "NONE"),
            },
            "compliance": {
                "status":       compliance_data.get("status", "unknown"),
                "is_violation": compliance_data.get("is_violation", False),
                "severity":     compliance_data.get("severity", "NONE"),
            }
        },
        "results": {
            "finops":     finops_data,
            "security":   security_data,
            "compliance": compliance_data,
        }
    }

# ── LAMBDA HANDLER ────────────────────────────────────────────
def lambda_handler(event, context):
    print("Incoming event:", json.dumps(event))

    # ── OPTIONS preflight ─────────────────────────────────────
    if event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS":
        return {"statusCode": 200, "headers": cors_headers(), "body": ""}

    try:
        # ── 1. Get job_id ──────────────────────────────────────
        path_params = event.get('pathParameters') or {}
        job_id      = path_params.get('job_id', '').strip()

        if not job_id:
            query_params = event.get('queryStringParameters') or {}
            job_id = query_params.get('job_id', '').strip()

        if not job_id:
            body   = json.loads(event.get('body', '{}')) if event.get('body') else {}
            job_id = body.get('job_id', '').strip()

        if not job_id:
            return {
                "statusCode": 400,
                "headers":    cors_headers(),
                "body":       json.dumps({"status": "error", "message": "job_id is required"})
            }

        print(f"[INFO] Checking status for job_id: {job_id}")

        # ── 2. Read DynamoDB ───────────────────────────────────
        response = table.get_item(Key={"job_id": job_id})
        item     = response.get('Item')

        if not item:
            return {
                "statusCode": 404,
                "headers":    cors_headers(),
                "body":       json.dumps({"status": "error", "message": "Job not found"})
            }

        job_status  = item.get('status', 'unknown')
        agent_used  = item.get('agent_used', 'unknown')

        # ── 3. PENDING ─────────────────────────────────────────
        if job_status == 'pending':
            return {
                "statusCode": 200,
                "headers":    cors_headers(),
                "body":       json.dumps({
                    "status":     "pending",
                    "job_id":     job_id,
                    "agent_used": agent_used,
                    "query":      item.get('query', ''),
                    "message":    "Still processing... Please poll again in a few seconds."
                })
            }

        # ── 4. COMPLETED ───────────────────────────────────────
        elif job_status == 'completed':

            result_raw = item.get('result', '{}')
            try:
                result = json.loads(result_raw) if isinstance(result_raw, str) else result_raw
            except json.JSONDecodeError:
                result = result_raw

            result_type = item.get('result_type', '')

            # ── Correlation result ─────────────────────────────
            if result_type == 'finops_with_correlation' or (
                isinstance(result, dict) and "finops_result" in result
            ):
                parsed = parse_correlation_result(result)
                return {
                    "statusCode": 200,
                    "headers":    cors_headers(),
                    "body":       json.dumps({
                        "status":           "completed",
                        "job_id":           job_id,
                        "query":            item.get('query', ''),
                        "agent_used":       parsed["agent_used"],
                        "triggered_by":     parsed["triggered_by"],
                        "overall_severity": parsed["overall_severity"],
                        "summary":          parsed["summary"],
                        "results":          parsed["results"],
                        "created_at":       item.get('created_at', ''),
                        "completed_at":     item.get('completed_at', ''),
                    }, default=str)
                }

            # ── All agents result ──────────────────────────────
            elif agent_used == 'all':
                parsed = (
                    parse_all_agents_result(result)
                    if isinstance(result, list)
                    else {
                        "agent_used": "all",
                        "summary":    {"error": "Unexpected result format"},
                        "results":    result
                    }
                )
                return {
                    "statusCode": 200,
                    "headers":    cors_headers(),
                    "body":       json.dumps({
                        "status":        "completed",
                        "job_id":        job_id,
                        "query":         item.get('query', ''),
                        "agent_used":    "all",
                        "summary":       parsed["summary"],
                        "results":       parsed["results"],
                        "ai_reason":     item.get('ai_reason', ''),
                        "ai_confidence": item.get('ai_confidence', ''),
                        "created_at":    item.get('created_at', ''),
                        "completed_at":  item.get('completed_at', ''),
                    }, default=str)
                }

            # ── Single agent result ────────────────────────────
            else:
                return {
                    "statusCode": 200,
                    "headers":    cors_headers(),
                    "body":       json.dumps({
                        "status":        "completed",
                        "job_id":        job_id,
                        "query":         item.get('query', ''),
                        "agent_used":    agent_used,
                        "ai_reason":     item.get('ai_reason', ''),
                        "ai_confidence": item.get('ai_confidence', ''),
                        "result":        result,
                        "created_at":    item.get('created_at', ''),
                        "completed_at":  item.get('completed_at', ''),
                    }, default=str)
                }

        # ── 5. ERROR ───────────────────────────────────────────
        elif job_status == 'error':
            return {
                "statusCode": 200,
                "headers":    cors_headers(),
                "body":       json.dumps({
                    "status":        "error",
                    "job_id":        job_id,
                    "agent_used":    agent_used,
                    "query":         item.get('query', ''),
                    "error_message": item.get('error_message', 'Unknown error occurred'),
                    "created_at":    item.get('created_at', ''),
                    "completed_at":  item.get('completed_at', ''),
                })
            }

        # ── 6. UNKNOWN ─────────────────────────────────────────
        else:
            return {
                "statusCode": 200,
                "headers":    cors_headers(),
                "body":       json.dumps({
                    "status":  job_status,
                    "job_id":  job_id,
                    "message": f"Unknown job status: {job_status}"
                })
            }

    except json.JSONDecodeError:
        return {
            "statusCode": 400,
            "headers":    cors_headers(),
            "body":       json.dumps({"status": "error", "message": "Invalid request format"})
        }

    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return {
            "statusCode": 500,
            "headers":    cors_headers(),
            "body":       json.dumps({"status": "error", "message": str(e)})
        }
