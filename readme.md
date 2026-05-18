# CloudOps AI Incident Assistant

A serverless AWS portfolio project that ingests sample operational logs, classifies incident types, stores structured findings, and lays the foundation for AI-powered incident analysis.

## Current Architecture

```text
S3 sample log upload
        ↓
S3 ObjectCreated event
        ↓
AWS Lambda
        ↓
Parse incident metadata
        ↓
DynamoDB incident-findings table
        ↓
CloudWatch logs