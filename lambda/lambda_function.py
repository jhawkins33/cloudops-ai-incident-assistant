import json
import boto3
from urllib.parse import unquote_plus

s3 = boto3.client("s3")

def lambda_handler(event, context):
    print("Received event:")
    print(json.dumps(event))

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])

        print(f"Processing file: s3://{bucket}/{key}")

        response = s3.get_object(Bucket=bucket, Key=key)
        log_text = response["Body"].read().decode("utf-8")

        result = {
            "bucket": bucket,
            "key": key,
            "log_preview": log_text[:500],
            "basic_analysis": {
                "detected_event_id": "7031" if "7031" in log_text else "unknown",
                "detected_issue": "Windows service terminated unexpectedly"
                if "terminated unexpectedly" in log_text.lower()
                else "unknown",
                "next_step": "Check service logs, recent deployments, service account permissions, and dependency failures."
            }
        }

        print("Analysis result:")
        print(json.dumps(result, indent=2))

    return {
        "statusCode": 200,
        "body": json.dumps("Processed log file successfully")
    }