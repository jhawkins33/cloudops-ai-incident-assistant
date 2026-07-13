
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

import boto3


s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

TABLE_NAME = os.environ.get("TABLE_NAME", "incident-findings")
table = dynamodb.Table(TABLE_NAME)


def parse_log_fields(log_text):
    event_id_match = re.search(r"Event ID:\s*(\d+)", log_text)
    service_match = re.search(r"Service:\s*(.+)", log_text)
    source_match = re.search(r"Source:\s*(.+)", log_text)

    return {
        "event_id": event_id_match.group(1) if event_id_match else "unknown",
        "service": service_match.group(1).strip() if service_match else "unknown",
        "source": source_match.group(1).strip() if source_match else "unknown",
    }


def classify_incident(log_text, detected_service):
    log_lower = log_text.lower()

    if "500.19" in log_text or "http error 500.19" in log_lower:
        return {
            "issue": "IIS configuration error",
            "incident_type": "iis",
            "incident_category": "application",
            "severity": "error",
            "confidence_score": "0.95",
            "alert_required": "yes",
            "assigned_team": "web_operations",
            "incident_source_system": "windows_iis",
            "incident_summary": "IIS configuration error detected",
            "status_reason": (
                "Awaiting investigation by web operations team"
            ),
            "business_impact": (
                "Customer-facing application may be unavailable"
            ),
            "resolution_recommendation": (
                "Review IIS configuration and permissions"
            ),
            "estimated_resolution_time": "30 minutes",
            "incident_tags": [
                "iis",
                "application",
                "web",
                "configuration",
                "high_priority",
            ],
            "recommended_action": (
                "Verify web.config permissions, "
                "application pool identity access, "
                "and IIS configuration validity."
            ),
        }

    if "terminated unexpectedly" in log_lower:
        return {
            "issue": "Windows service terminated unexpectedly",
            "incident_type": "windows_service",
            "incident_category": "infrastructure",
            "severity": "error",
            "confidence_score": "0.95",
            "alert_required": "yes",
            "assigned_team": "infrastructure_operations",
            "incident_source_system": "windows_os",
            "incident_summary": (
                f"Service {detected_service} terminated unexpectedly"
            ),
            "status_reason": (
                "Awaiting investigation by infrastructure operations team"
            ),
            "business_impact": (
                "Infrastructure service interruption may affect "
                "application operations"
            ),
            "resolution_recommendation": (
                "Investigate service stability and restart conditions"
            ),
            "estimated_resolution_time": "15 minutes",
            "incident_tags": [
                "windows",
                "service",
                "infrastructure",
                "7031",
                "high_priority",
            ],
            "recommended_action": (
                "Check service logs, recent deployments, "
                "service account permissions, "
                "and dependency failures."
            ),
        }

    return {
        "issue": "unknown",
        "incident_type": "unknown",
        "incident_category": "unknown",
        "severity": "info",
        "confidence_score": "0.20",
        "alert_required": "no",
        "assigned_team": "triage",
        "incident_source_system": "unknown",
        "incident_summary": "Unknown incident detected",
        "status_reason": "Awaiting triage and classification",
        "business_impact": "Business impact currently unknown",
        "resolution_recommendation": "Manual analysis required",
        "estimated_resolution_time": "To be determined",
        "incident_tags": ["unknown", "triage"],
        "recommended_action": (
            "Review the raw log manually for further investigation."
        ),
    }


def lambda_handler(event, context):
    print("Received event:")
    print(json.dumps(event))

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])

        print(f"Processing file: s3://{bucket}/{key}")

        response = s3.get_object(Bucket=bucket, Key=key)
        log_text = response["Body"].read().decode("utf-8")

        # -----------------------------
        # Parse log fields
        # -----------------------------

        parsed_fields = parse_log_fields(log_text)

        detected_event_id = parsed_fields["event_id"]
        detected_service = parsed_fields["service"]
        detected_source = parsed_fields["source"]

        # -----------------------------
        # Classify incident
        # -----------------------------

        incident = classify_incident(log_text, detected_service)

        detected_issue = incident["issue"]
        incident_type = incident["incident_type"]
        incident_category = incident["incident_category"]
        severity = incident["severity"]
        confidence_score = incident["confidence_score"]
        alert_required = incident["alert_required"]
        assigned_team = incident["assigned_team"]
        incident_source_system = incident["incident_source_system"]
        incident_summary = incident["incident_summary"]
        status_reason = incident["status_reason"]
        business_impact = incident["business_impact"]
        resolution_recommendation = incident[
            "resolution_recommendation"
        ]
        estimated_resolution_time = incident[
            "estimated_resolution_time"
        ]
        incident_tags = incident["incident_tags"]
        recommended_action = incident["recommended_action"]

        # -----------------------------
        # Calculate base score
        # -----------------------------

        if (
            severity == "error"
            and alert_required == "yes"
            and float(confidence_score) >= 0.90
        ):
            remediation_priority = "high"
            incident_score = 95
        elif severity == "error":
            remediation_priority = "medium"
            incident_score = 70
        else:
            remediation_priority = "low"
            incident_score = 30

        incident_detected_at = datetime.now(timezone.utc).isoformat()
        incident_age_minutes = 0

        # -----------------------------
        # Analyze incident history
        # -----------------------------

        repeat_incident = "no"
        incident_occurrence = 1

        history_response = table.scan()

        for existing_item in history_response.get("Items", []):
            if (
                existing_item.get("service") == detected_service
                and existing_item.get("incident_type") == incident_type
            ):
                repeat_incident = "yes"
                incident_occurrence += 1

        # -----------------------------
        # Determine trend and final score
        # -----------------------------

        if incident_occurrence >= 20:
            incident_trend = "chronic"
        elif incident_occurrence >= 10:
            incident_trend = "frequent"
        elif incident_occurrence >= 2:
            incident_trend = "recurring"
        else:
            incident_trend = "new"

        if incident_trend == "recurring":
            incident_score += 2
        elif incident_trend == "frequent":
            incident_score += 5
        elif incident_trend == "chronic":
            incident_score += 10

        incident_score = min(incident_score, 100)

        # -----------------------------
        # Determine escalation
        # -----------------------------

        if incident_score >= 90:
            escalation_level = "critical"
        elif incident_score >= 70:
            escalation_level = "high"
        elif incident_score >= 40:
            escalation_level = "medium"
        else:
            escalation_level = "low"

        if (
            escalation_level == "critical"
            or incident_trend == "chronic"
        ):
            requires_escalation = "yes"
        else:
            requires_escalation = "no"

        # -----------------------------
        # Determine priority, lifecycle, and risk
        # -----------------------------

        if incident_score >= 90:
            incident_priority = "P1"
        elif incident_score >= 70:
            incident_priority = "P2"
        elif incident_score >= 40:
            incident_priority = "P3"
        else:
            incident_priority = "P4"

        status = "new"

        if incident_priority == "P1":
            incident_lifecycle = "Immediate Response"
        elif incident_priority == "P2":
            incident_lifecycle = "Active Investigation"
        else:
            incident_lifecycle = "Monitoring"

        if (
            incident_priority == "P1"
            and incident_trend == "chronic"
        ):
            incident_risk = "critical"
        elif incident_priority == "P1":
            incident_risk = "high"
        elif incident_priority == "P2":
            incident_risk = "medium"
        else:
            incident_risk = "low"

        # -----------------------------
        # Recommend incident status
        # -----------------------------

        if incident_priority == "P1":
            recommended_status = "Open"
        elif incident_priority == "P2":
            recommended_status = "Investigating"
        else:
            recommended_status = "Monitoring"

        # -----------------------------
        # Generate executive summary
        # -----------------------------

        executive_summary = (
            f"{incident_priority} {incident_risk.upper()} incident "
            f"affecting {detected_service}. "
            f"This is occurrence #{incident_occurrence} "
            f"and is classified as {incident_trend}."
        )

        # -----------------------------
        # Build and save DynamoDB item
        # -----------------------------

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
            "incident_score": incident_score,
            "incident_priority": incident_priority,
            "incident_risk": incident_risk,
            "escalation_level": escalation_level,
            "requires_escalation": requires_escalation,
            "repeat_incident": repeat_incident,
            "incident_occurrence": incident_occurrence,
            "incident_trend": incident_trend,
            "alert_required": alert_required,
            "remediation_priority": remediation_priority,
            "status": status,
            "recommended_status": recommended_status,
            "status_reason": status_reason,
            "incident_lifecycle": incident_lifecycle,
            "estimated_resolution_time": estimated_resolution_time,
            "business_impact": business_impact,
            "incident_tags": incident_tags,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "incident_detected_at": incident_detected_at,
            "incident_age_minutes": incident_age_minutes,
            "log_preview": log_text[:500],
            "source": detected_source,
            "incident_type": incident_type,
            "incident_category": incident_category,
            "assigned_team": assigned_team,
            "incident_source_system": incident_source_system,
            "incident_summary": incident_summary,
            "executive_summary": executive_summary,
        }

        table.put_item(Item=item)

        print("Saved finding to DynamoDB:")
        print(json.dumps(item, indent=2))

    return {
        "statusCode": 200,
        "body": json.dumps(
            "Processed log file and saved finding"
        ),
    }

