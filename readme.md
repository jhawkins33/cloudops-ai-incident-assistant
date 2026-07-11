## Incident Processing Workflow

```text
             S3 Log Upload
                   │
                   ▼
           AWS Lambda Processor
                   │
    ┌──────────────┼──────────────┐
    │              │              │
 Parse Log     Classify      Score Incident
                   │
                   ▼
        Analyze Historical Data
                   │
                   ▼
      Determine Trend & Priority
                   │
                   ▼
    Risk • Escalation • Lifecycle
                   │
                   ▼
       Executive Summary Created
                   │
                   ▼
        DynamoDB Incident Store
                   │
                   ▼
          CloudWatch Monitoring
