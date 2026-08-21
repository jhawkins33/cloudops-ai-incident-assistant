import json
import os
import logging

import boto3

from agent import run_agent

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")

TABLE_NAME = os.environ.get("TABLE_NAME", "incident-findings")
table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    logger.info("Received SQS event:")
    logger.info(json.dumps(event))

    for record in event.get("Records", []):
        body = json.loads(record["body"])

        log_id = body["log_id"]
        agent_input = body["agent_input"]

        logger.info(
            "Processing AI analysis: log_id=%s",
            log_id,
        )
        
        agent_recommendation = run_agent(agent_input)

        table.update_item(
            Key={
                "log_id": log_id
            },
            UpdateExpression="SET agent_recommendation = :recommendation",
            ExpressionAttributeValues={
                ":recommendation": agent_recommendation
            },
        )
        
        logger.info(
            "AI analysis completed: log_id=%s",
            log_id,
        )