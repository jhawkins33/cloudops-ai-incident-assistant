import json
import boto3
import re
import os
from urllib.parse import unquote_plus
from datetime import datetime, timezone

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

TABLE_NAME = os.environ.get("TABLE_NAME", "incident-findings")
table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    print("Received event:")
    print(json.dumps(event))

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])

        print(f"Processing file: s3://{bucket}/{key}")

        response = s3.get_object(Bucket=bucket, Key=key)
        log_text = response["Body"].read().decode("utf-8")

        event_id_match = re.search(r"Event ID:\s*(\d+)", log_text)
        service_match = re.search(r"Service:\s*(.+)", log_text)
        source_match = re.search(r"Source:\s*(.+)", log_text)

        detected_event_id = event_id_match.group(1) if event_id_match else "unknown"
        detected_service = service_match.group(1).strip() if service_match else "unknown"
        detected_source = source_match.group(1).strip() if source_match else "unknown"

        log_lower = log_text.lower()

        if "500.19" in log_text or "http error 500.19" in log_lower:
            detected_issue = "IIS configuration error"
            incident_type = "iis"
            incident_category = "application"
            severity = "error"
            confidence_score = "0.95"
            alert_required = "yes"
            resolution_recommendation = "Review IIS configuration and permissions"
            recommended_action = (
                "Verify web.config permissions, "
                "application pool identity access, "
                "and IIS configuration validity."
            )

        elif "terminated unexpectedly" in log_lower:
            detected_issue = "Windows service terminated unexpectedly"
            incident_type = "windows_service"
            incident_category = "infrastructure"
            severity = "error"
            confidence_score = "0.95"
            alert_required = "yes"
            resolution_recommendation = "Investigate service stability and restart conditions"
            recommended_action = (
                "Check service logs, recent deployments, "
                "service account permissions, "
                "and dependency failures."
            )

        else:
            detected_issue = "unknown"
            incident_type = "unknown"
            incident_category = "unknown"
            severity = "info"
            confidence_score = "0.20"
            alert_required = "no"
            resolution_recommendation = "Manual analysis required"
            recommended_action = (
                "Review the raw log manually for further investigation."
            )

        if severity == "error" and alert_required == "yes" and float(confidence_score) >= 0.90:
            remediation_priority = "high"
        elif severity == "error":
            remediation_priority = "medium"
        else:
            remediation_priority = "low"

        status = "new"

        item = {
            "log_id": key.replace("/", "_").replace(".txt", ""),
            "source_bucket": bucket,
            "source_key": key,
            "event_id": detected_event_id,
            "service": detected_service,
            "issue": detected_issue,
            "severity": severity,
            "recommended_action": recommended_action,
            "resolution_recommendation": resolution_recommendation,
            "confidence_score": confidence_score,
            "alert_required": alert_required,
            "remediation_priority": remediation_priority,
            "status": status,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "log_preview": log_text[:500],
            "source": detected_source,
            "incident_type": incident_type,
            "incident_category": incident_category,
        }

        table.put_item(Item=item)

        print("Saved finding to DynamoDB:")
        print(json.dumps(item, indent=2))

    return {
        "statusCode": 200,
        "body": json.dumps("Processed log file and saved finding")
    }

