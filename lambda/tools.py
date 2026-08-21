import os

import boto3
from boto3.dynamodb.conditions import Attr


TABLE_NAME = os.environ.get("TABLE_NAME", "incident-findings")

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(TABLE_NAME)


def lookup_incident_history(
    event_id=None,
    service=None,
    incident_type=None,
    limit=5,
):
    """
    Look up previous incidents that are similar to the current incident.
    """

    filter_expression = None

    if event_id:
        filter_expression = Attr("event_id").eq(str(event_id))

    if service:
        service_filter = Attr("service").eq(service)

        filter_expression = (
            service_filter
            if filter_expression is None
            else filter_expression & service_filter
        )

    if incident_type:
        type_filter = Attr("incident_type").eq(incident_type)

        filter_expression = (
            type_filter
            if filter_expression is None
            else filter_expression & type_filter
        )

    scan_args = {
        "Limit": limit,
    }

    if filter_expression is not None:
        scan_args["FilterExpression"] = filter_expression

    response = table.scan(**scan_args)

    incidents = []

    for item in response.get("Items", []):
        incidents.append(
            {
                "log_id": item.get("log_id"),
                "event_id": item.get("event_id"),
                "service": item.get("service"),
                "incident_type": item.get("incident_type"),
                "severity": item.get("severity"),
                "issue": item.get("issue"),
                "recommended_action": item.get("recommended_action"),
                "processed_at": item.get("processed_at"),
            }
        )

    return incidents