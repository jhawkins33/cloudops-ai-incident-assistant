import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

import boto3
import logging

from incident_rules import INCIDENT_RULES

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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

def resolve_service(parsed_fields):
    service = parsed_fields["service"]
    source = parsed_fields["source"]

    if service != "unknown":
        return service

    if source == "MSSQLSERVER":
        return "SQL Server"

    if source == "IIS":
        return "IIS"

    return "unknown"

def classify_incident(log_text, detected_service):
    log_lower = log_text.lower()

    for rule in INCIDENT_RULES:
        if all(
            term.lower() in log_lower
            for term in rule["match"]
        ):
            return {
                "issue": rule["issue"],
                "incident_type": rule["incident_type"],
                "incident_category": rule["incident_category"],
                "severity": rule["severity"],
                "alert_required": rule["alert_required"],
                "confidence_score": rule["confidence_score"],
                "assigned_team": rule["assigned_team"],
                "status_reason": (
                    "Awaiting investigation by infrastructure operations team"
                ),
                "business_impact": rule["business_impact"],
                "estimated_resolution_time": rule[
                    "estimated_resolution_time"
                ],
                "incident_tags": rule["incident_tags"],
                "recommended_action": rule["recommended_action"],
                "resolution_recommendation": rule[
                    "resolution_recommendation"
                ],
                "incident_source_system": rule[
                    "incident_source_system"
                ],
                "incident_summary": rule["incident_summary"].format(
                    service=detected_service
                ),
            }

    return {
        "issue": "Unknown incident",
        "incident_type": "unknown",
        "incident_category": "unknown",
        "severity": "info",
        "alert_required": "no",
        "confidence_score": 0.25,
        "assigned_team": "operations",
        "status_reason": "Incident could not be automatically classified",
        "business_impact": "Impact has not yet been determined",
        "estimated_resolution_time": "Unknown",
        "incident_tags": [
            "unknown",
            "manual_review"
        ],
        "recommended_action": "Review the raw log manually.",
        "resolution_recommendation": "Perform manual incident analysis",
        "incident_source_system": "unknown",
        "incident_summary": "Unclassified operational incident",
    }

def analyze_incident_history(table, detected_service, incident_type):
    repeat_incident = "no"
    incident_occurrence = 1

    response = table.scan()

    for existing_item in response.get("Items", []):
        if (
            existing_item.get("service") == detected_service
            and existing_item.get("incident_type") == incident_type
        ):
            repeat_incident = "yes"
            incident_occurrence += 1

    if incident_occurrence >= 20:
        incident_trend = "chronic"
    elif incident_occurrence >= 10:
        incident_trend = "frequent"
    elif incident_occurrence >= 2:
        incident_trend = "recurring"
    else:
        incident_trend = "new"

    return {
        "repeat_incident": repeat_incident,
        "incident_occurrence": incident_occurrence,
        "incident_trend": incident_trend,
    }

def calculate_incident_score(severity, alert_required, confidence_score, incident_trend):
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

    if incident_trend == "recurring":
        incident_score += 2
    elif incident_trend == "frequent":
        incident_score += 5
    elif incident_trend == "chronic":
        incident_score += 10

    incident_score = min(incident_score, 100)

    return {
        "incident_score": incident_score,
        "remediation_priority": remediation_priority,
    }

def determine_incident_response(incident_score, incident_trend):
    # Determine escalation level
    if incident_score >= 90:
        escalation_level = "critical"
    elif incident_score >= 70:
        escalation_level = "high"
    elif incident_score >= 40:
        escalation_level = "medium"
    else:
        escalation_level = "low"

    # Determine whether escalation is required
    if escalation_level == "critical" or incident_trend == "chronic":
        requires_escalation = "yes"
    else:
        requires_escalation = "no"

    # Determine incident priority
    if incident_score >= 90:
        incident_priority = "P1"
    elif incident_score >= 70:
        incident_priority = "P2"
    elif incident_score >= 40:
        incident_priority = "P3"
    else:
        incident_priority = "P4"

    # Determine lifecycle
    if incident_priority == "P1":
        incident_lifecycle = "Immediate Response"
    elif incident_priority == "P2":
        incident_lifecycle = "Active Investigation"
    else:
        incident_lifecycle = "Monitoring"

    # Determine risk
    if incident_priority == "P1" and incident_trend == "chronic":
        incident_risk = "critical"
    elif incident_priority == "P1":
        incident_risk = "high"
    elif incident_priority == "P2":
        incident_risk = "medium"
    else:
        incident_risk = "low"

    # Determine incident health
    if incident_trend == "new":
        incident_health = "Healthy"
    elif incident_trend == "recurring":
        incident_health = "Watch"
    elif incident_trend == "chronic":
        incident_health = "Chronic"
    else:
        incident_health = "Unknown"

    # Recommend incident status
    if incident_priority == "P1":
        recommended_status = "Open"
    elif incident_priority == "P2":
        recommended_status = "Investigating"
    else:
        recommended_status = "Monitoring"

    return {
        "escalation_level": escalation_level,
        "requires_escalation": requires_escalation,
        "incident_priority": incident_priority,
        "incident_lifecycle": incident_lifecycle,
        "incident_risk": incident_risk,
        "incident_health": incident_health,
        "recommended_status": recommended_status,
    }

def build_incident_record(
    bucket,
    key,
    parsed_fields,
    incident,
    history,
    scoring,
    response_logic,
    timestamps,
    status,
    executive_summary,
    log_text,
):
    return {
        "log_id": key.replace("/", "_").replace(".txt", ""),
        "source_bucket": bucket,
        "source_key": key,

        # Parsed log information
        "event_id": parsed_fields["event_id"],
        "service": parsed_fields["service"],
        "source": parsed_fields["source"],

        # Classification information
        "issue": incident["issue"],
        "severity": incident["severity"],
        "recommended_action": incident["recommended_action"],
        "resolution_recommendation": incident[
            "resolution_recommendation"
        ],
        "confidence_score": str(incident["confidence_score"]),
        "alert_required": incident["alert_required"],
        "status_reason": incident["status_reason"],
        "estimated_resolution_time": incident[
            "estimated_resolution_time"
        ],
        "business_impact": incident["business_impact"],
        "incident_tags": incident["incident_tags"],
        "incident_type": incident["incident_type"],
        "incident_category": incident["incident_category"],
        "assigned_team": incident["assigned_team"],
        "incident_source_system": incident[
            "incident_source_system"
        ],
        "incident_summary": incident["incident_summary"],

        # Historical analysis
        "repeat_incident": history["repeat_incident"],
        "incident_occurrence": history["incident_occurrence"],
        "incident_trend": history["incident_trend"],

        # Scoring
        "incident_score": scoring["incident_score"],
        "remediation_priority": scoring[
            "remediation_priority"
        ],

        # Response logic
        "incident_priority": response_logic[
            "incident_priority"
        ],
        "incident_risk": response_logic["incident_risk"],
        "incident_health": response_logic["incident_health"],
        "escalation_level": response_logic[
            "escalation_level"
        ],
        "requires_escalation": response_logic[
            "requires_escalation"
        ],
        "recommended_status": response_logic[
            "recommended_status"
        ],
        "incident_lifecycle": response_logic[
            "incident_lifecycle"
        ],

        # General status and timing
        "status": status,
        "processed_at": timestamps["processed_at"],
        "incident_detected_at": timestamps[
            "incident_detected_at"
        ],
        "incident_age_minutes": timestamps[
            "incident_age_minutes"
        ],

        # Original log and summary
        "log_preview": log_text[:500],
        "executive_summary": executive_summary,
    }


def lambda_handler(event, context):
    logger.info("Received event:")
    logger.info(json.dumps(event))

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])

        logger.info(f"Processing file: s3://{bucket}/{key}")

        response = s3.get_object(Bucket=bucket, Key=key)
        log_text = response["Body"].read().decode("utf-8")

        # -----------------------------
        # Parse log fields
        # -----------------------------

        parsed_fields = parse_log_fields(log_text)

        detected_service = resolve_service(parsed_fields)
        parsed_fields["service"] = detected_service

        # -----------------------------
        # Classify incident
        # -----------------------------

        incident = classify_incident(log_text, detected_service)

        incident_type = incident["incident_type"]
        severity = incident["severity"]
        confidence_score = incident["confidence_score"]
        alert_required = incident["alert_required"]

        # -----------------------------
        # Set incident timestamps
        # -----------------------------

        timestamps = {
            "incident_detected_at": datetime.now(timezone.utc).isoformat(),
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "incident_age_minutes": 0,
        }

        # -----------------------------
        # Analyze incident history
        # -----------------------------

        history = analyze_incident_history(
            table,
            detected_service,
            incident_type,
        )

        incident_occurrence = history["incident_occurrence"]
        incident_trend = history["incident_trend"]

        # -----------------------------
        # Calculate incident score
        # -----------------------------

        scoring = calculate_incident_score(
            severity,
            alert_required,
            confidence_score,
            incident_trend,
        )

        incident_score = scoring["incident_score"]

        # -----------------------------
        # Determine incident response
        # -----------------------------

        response_logic = determine_incident_response(
            incident_score,
            incident_trend,
        )

        incident_priority = response_logic["incident_priority"]
        incident_risk = response_logic["incident_risk"]
        incident_health = response_logic["incident_health"]

        status = "new"

        # -----------------------------
        # Generate executive summary
        # -----------------------------

        executive_summary = (
            f"{incident_priority} {incident_risk.upper()} incident "
            f"affecting {detected_service}. "
            f"This is occurrence #{incident_occurrence}, "
            f"classified as {incident_trend}, "
            f"with incident health rated as {incident_health}."
        )

        # -----------------------------
        # Build and save DynamoDB item
        # -----------------------------

        item = build_incident_record(
            bucket=bucket,
            key=key,
            parsed_fields=parsed_fields,
            incident=incident,
            history=history,
            scoring=scoring,
            response_logic=response_logic,
            timestamps=timestamps,
            status=status,
            executive_summary=executive_summary,
            log_text=log_text,
        )

        table.put_item(Item=item)

        logger.info("Saved finding to DynamoDB:")
        logger.info(json.dumps(item, indent=2))

    return {
        "statusCode": 200,
        "body": json.dumps(
            "Processed log file and saved finding"
        ),
    }