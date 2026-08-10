import json
import os
import uuid
import boto3
import requests
from datetime import datetime, timedelta
from google.oauth2 import service_account
from google.auth.transport.requests import Request

# ── AWS Clients ───────────────────────────────────────────────
dynamodb  = boto3.resource('dynamodb')
sf_client = boto3.client('stepfunctions')
table     = dynamodb.Table(os.environ['JOB_TABLE_NAME'])

# ── ENV VARS ──────────────────────────────────────────────────
STEP_FUNCTION_ARN    = os.environ['STEP_FUNCTION_ARN']
PROJECT_ID           = os.environ['GCP_PROJECT_ID']
LOCATION             = os.environ['GCP_LOCATION']
MODEL_ID             = os.environ['GCP_MODEL_ID']
SERVICE_ACCOUNT_JSON = json.loads(os.environ['GCP_SA_KEY'])

# ── VALID AGENTS ──────────────────────────────────────────────
VALID_AGENTS = ['finops', 'security', 'compliance', 'all']

# ── CORS ──────────────────────────────────────────────────────
def cors_headers():
    return {
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Access-Control-Allow-Methods": "OPTIONS,POST,GET" # Added GET here
    }

# ── AUTH : Vertex AI ──────────────────────────────────────────
def get_access_token():
    credentials = service_account.Credentials.from_service_account_info(
        SERVICE_ACCOUNT_JSON,
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    credentials.refresh(Request())
    return credentials.token

# ── PROMPT BUILDER (Your original, detailed prompt) ───────────
def build_classification_prompt(user_query: str) -> str:
    return f"""You are an AI Cloud Operations Manager for AWS infrastructure.
Your ONLY job is to classify the user's query and route it to exactly ONE specialist agent
OR to "all" if the query requires multiple domains.

Available Agents and their EXACT responsibilities:

1. "finops"
   HANDLES: Cost analysis, billing, spend tracking, budget alerts, pricing,
   expense reports, savings plans, reserved instances, cost optimization,
   cost breakdown by service/account, cost anomalies, cost forecasting,
   idle resource detection, rightsizing recommendations, unattached volumes,
   unused Elastic IPs, NAT Gateway costs.
   
   EXAMPLE QUERIES:
   - "What is my AWS cost this month?"
   - "Why did my bill spike?"
   - "How can I reduce EC2 costs?"
   - "Show me cost breakdown by service"
   - "Which service is most expensive?"
   - "Compare this month's spend to last month"
   - "Show me idle EC2 instances"
   - "Any unattached EBS volumes?"
   - "What is my projected spend?"

2. "security"
   HANDLES: Active security threats, incident investigation, CloudTrail
   event analysis (who did what, when, from where), Security Hub findings,
   GuardDuty threat detection, unauthorized access, suspicious API activity,
   SCP denied events, root account usage, IAM permission changes,
   failed login attempts, brute force detection, resource deletion tracking,
   public resource exposure (open security groups, public S3/RDS/EC2),
   access key usage anomalies, AssumeRole chain investigation,
   unusual API patterns (new regions, odd hours).
   
   KEY DISTINCTION: Security agent investigates EVENTS and ACTIVITIES —
   things that happened or are happening. It reads CloudTrail events,
   Security Hub findings, and GuardDuty alerts.
   
   QUESTIONS ABOUT "WHO DID WHAT" → SECURITY
   QUESTIONS ABOUT "WHAT HAPPENED" → SECURITY
   QUESTIONS ABOUT "IS SOMETHING BAD HAPPENING" → SECURITY
   
   EXAMPLE QUERIES:
   - "Any unauthorized access detected?"
   - "Show me SCP denied events from today"
   - "Who made API calls from unusual regions?"
   - "Has root account been used recently?"
   - "Any failed login attempts?"
   - "Show me IAM changes in last 24 hours"
   - "Who deleted resources today?"
   - "Any GuardDuty findings?"
   - "Are any resources publicly exposed?"
   - "Show me suspicious API calls"
   - "Who accessed my S3 bucket?"
   - "Check for compromised credentials"
   - "Any brute force attempts?"
   - "What got blocked by SCP?"
   - "Show me AssumeRole events"
   - "Who created this EC2 instance?"
   - "Any unusual activity today?"

3. "compliance"
   HANDLES: Policy adherence, configuration audits, governance rules,
   resource tagging compliance, region restrictions, IAM access key
   rotation policy, deletion protection checks, MFA compliance,
   password policy compliance, inactive user detection, admin access audit,
   encryption compliance (EBS/S3/RDS), logging compliance (CloudTrail
   enabled, VPC flow logs), network compliance (security group rules),
   AWS Config rule violations, regulatory requirements (CIS, SOC2, HIPAA).
   
   KEY DISTINCTION: Compliance agent checks CONFIGURATION and POLICY —
   whether resources ARE SET UP correctly, not what events happened.
   
   QUESTIONS ABOUT "IS IT CONFIGURED RIGHT" → COMPLIANCE
   QUESTIONS ABOUT "DOES IT MEET POLICY" → COMPLIANCE
   QUESTIONS ABOUT "IS SOMETHING ENABLED/DISABLED" → COMPLIANCE
   
   EXAMPLE QUERIES:
   - "Any policy violations?"
   - "Are all resources tagged properly?"
   - "List users whose access keys have not been rotated"
   - "Which users don't have MFA enabled?"
   - "Is deletion protection enabled on all RDS instances?"
   - "Are there unencrypted EBS volumes?"
   - "Is CloudTrail enabled in all regions?"
   - "Are VPC flow logs enabled?"
   - "Does our password policy meet CIS benchmarks?"
   - "Show me inactive IAM users"
   - "Who has AdministratorAccess?"
   - "Are S3 buckets encrypted?"
   - "Show me AWS Config rule violations"
   - "Are we SOC2 compliant?"
   - "Any resources outside approved regions?"
   - "Show me non-compliant resources"

4. "all" — Use ONLY when the query EXPLICITLY needs MULTIPLE domains combined.

WHEN TO USE "all":
- User asks for a "full audit" or "complete review"
- User asks for an "executive summary" or "monthly report"
- User asks for "overall health" or "full investigation"
- User asks a question that spans BOTH security AND compliance AND/OR cost
- User says "investigate everything" or "check everything"

CRITICAL CLASSIFICATION RULES:
- "SCP denied/blocked events" → SECURITY 
- "who accessed/created/deleted" → SECURITY 
- "unauthorized access" → SECURITY 
- "missing tags" → COMPLIANCE
- "MFA enabled/disabled" → COMPLIANCE
- "cost/bill/spend/budget" → FINOPS
- "idle resources" → FINOPS 

User Query: "{user_query}"

Return ONLY this JSON, nothing else:
{{"agent": "<finops|security|compliance|all>", "reason": "<why>", "confidence": "<high|medium|low>"}}
"""

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
            "temperature":       0.1,
            "responseMimeType":  "application/json"
        }
    }

    response = requests.post(url, headers=headers, json=payload, timeout=30)

    if not response.ok:
        raise ValueError(f"Vertex AI error {response.status_code}: {response.text}")

    data = response.json()

    try:
        raw_text = data['candidates'][0]['content']['parts'][0]['text']
    except (KeyError, IndexError):
        raise ValueError(f"Unexpected Vertex response: {json.dumps(data)}")

    try:
        return json.loads(raw_text.strip())
    except json.JSONDecodeError:
        raise ValueError(f"Model returned invalid JSON: {raw_text}")

# ── CLASSIFY WITH RETRY (Your original robust logic) ─────────
def classify_query(user_query: str, max_retries: int = 2) -> dict:
    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            print(f"[INFO] Classification attempt {attempt}/{max_retries}")
            prompt = build_classification_prompt(user_query)
            result = call_vertex(prompt)

            agent = result.get('agent', '').lower().strip()
            reason = result.get('reason', '')
            confidence = result.get('confidence', 'low')

            if agent not in VALID_AGENTS:
                raise ValueError(f"LLM returned invalid agent: '{agent}'. Expected one of {VALID_AGENTS}")

            print(f"[INFO] Classification success → agent: {agent} | reason: {reason} | confidence: {confidence}")
            return {"agent": agent, "reason": reason, "confidence": confidence}

        except Exception as e:
            last_error = str(e)
            print(f"[WARN] Attempt {attempt} failed: {last_error}")

    raise ValueError(f"Classification failed after {max_retries} attempts. Last error: {last_error}")

# ── LAMBDA HANDLER ────────────────────────────────────────────
def lambda_handler(event, context):
    print("Incoming event:", json.dumps(event))

    # ── OPTIONS preflight ─────────────────────────────────────
    if event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS":
        return {"statusCode": 200, "headers": cors_headers(), "body": ""}

    http_method = event.get("requestContext", {}).get("http", {}).get("method", "POST")

    try:
        # ── NEW LOGIC: HANDLE GET (POLLING FOR RESULTS) ────────
        if http_method == "GET":
            # Extract ID from path parameters (e.g., /anomalies/{investigation_id})
            path_params = event.get("pathParameters") or {}
            job_id = path_params.get("investigation_id")
            
            if not job_id:
                return {
                    "statusCode": 400, 
                    "headers": cors_headers(), 
                    "body": json.dumps({"status": "error", "message": "Missing investigation_id"})
                }
                
            resp = table.get_item(Key={"job_id": job_id})
            item = resp.get("Item")
            
            if not item:
                return {
                    "statusCode": 404, 
                    "headers": cors_headers(), 
                    "body": json.dumps({"status": "error", "message": "Job not found"})
                }
                
            return {
                "statusCode": 200,
                "headers": cors_headers(),
                "body": json.dumps(item, default=str)
            }

        # ── ORIGINAL LOGIC: HANDLE POST (START JOB) ─────────────
        body       = json.loads(event.get('body', '{}'))
        user_query = body.get('message', '').strip()
        user_id    = body.get('user_id', 'anonymous')

        if not user_query:
            return {
                "statusCode": 400,
                "headers":    cors_headers(),
                "body": json.dumps({"status": "error", "message": "message field is required"})
            }

        print(f"[INFO] User query: {user_query}")

        try:
            classification = classify_query(user_query)
            agent_type     = classification['agent']
            ai_reason      = classification['reason']
            ai_confidence  = classification['confidence']
        except Exception as classify_err:
            print(f"[ERROR] Classification failed: {str(classify_err)}")
            return {
                "statusCode": 503,
                "headers":    cors_headers(),
                "body": json.dumps({"status": "error", "message": "AI service unavailable", "detail": str(classify_err)})
            }

        print(f"[INFO] Final routing → agent: {agent_type} | reason: {ai_reason} | confidence: {ai_confidence}")

        job_id = str(uuid.uuid4())

        table.put_item(Item={
            "job_id":         job_id,
            "status":         "pending",
            "agent_used":     agent_type,
            "ai_reason":      ai_reason,
            "ai_confidence":  ai_confidence,
            "query":          user_query,
            "user_id":        user_id,
            "created_at":     datetime.utcnow().isoformat(),
            "expires_at":     int((datetime.utcnow() + timedelta(hours=24)).timestamp()),
            "result":         None
        })

        sf_client.start_execution(
            stateMachineArn=STEP_FUNCTION_ARN,
            name=job_id,
            input=json.dumps({
                "agent":   agent_type,
                "query":   user_query,
                "user_id": user_id,
                "job_id":  job_id
            })
        )

        return {
            "statusCode": 202,
            "headers":    cors_headers(),
            "body": json.dumps({
                "status":        "pending",
                "job_id":        job_id,
                "agent_used":    agent_type,
                "ai_reason":     ai_reason,
                "ai_confidence": ai_confidence,
                "message":       "Request accepted. Poll /anomalies/{job_id} for result."
            })
        }

    except json.JSONDecodeError:
        return {"statusCode": 400, "headers": cors_headers(), "body": json.dumps({"status": "error", "message": "Invalid JSON"})}
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return {"statusCode": 500, "headers": cors_headers(), "body": json.dumps({"status": "error", "message": str(e)})}
