# CloudOps AI Incident Assistant

> **An AWS serverless platform for automated infrastructure incident detection, analysis, and operational intelligence.**

A serverless AWS project that automatically analyzes infrastructure logs, classifies incidents, evaluates historical trends, prioritizes operational issues, and stores enriched incident records in Amazon DynamoDB.

The project demonstrates practical cloud engineering, serverless architecture, automation, and operational incident analysis using AWS services while following production-style software engineering practices.

---

## Table of Contents

- [Current Status](#current-status)
- [Project Goal](#project-goal)
- [Features](#features)
- [Design Principles](#design-principles)
- [Architecture](#architecture)
- [AWS Services](#aws-services)
- [Project Structure](#project-structure)
- [Building](#building)
- [Current Incident Types](#current-incident-types)
- [Technologies](#technologies)
- [Sample Output](#sample-output)
- [Example Workflow](#example-workflow)
- [Example Incident Record](#example-incident-record)
- [Future Enhancements](#future-enhancements)
- [Why This Project?](#why-this-project)
- [Roadmap](#roadmap)
- [About](#about)

---

## Current Status

🚧 **Actively Developed**

Current capabilities include:

- ✅ IIS HTTP 500.19 incident detection
- ✅ Windows Service Event ID 7031 detection
- ✅ Historical incident analysis
- ✅ Dynamic incident scoring
- ✅ Executive summary generation
- ✅ Production logging with Amazon CloudWatch
- ✅ Automated build and deployment packaging

---

## Project Goal

The long-term objective is to build an intelligent CloudOps assistant capable of:

- Automatically ingesting infrastructure logs
- Detecting operational incidents
- Identifying recurring issues
- Prioritizing incidents based on historical patterns
- Recommending remediation actions
- Generating executive-level summaries
- Providing operational dashboards
- Serving as a foundation for future AI-assisted incident analysis

---

## Features

- Event-driven processing using Amazon S3 and AWS Lambda
- Rule-based incident classification engine
- Historical incident analysis
- Dynamic incident scoring
- Trend detection (New vs. Recurring)
- Risk assessment
- Escalation recommendations
- Executive summary generation
- Structured incident records stored in Amazon DynamoDB
- Production logging with Amazon CloudWatch
- Automated deployment package creation
- ZIP verification before deployment

---

## Design Principles

This project is designed around a few core principles:

- Keep the detection engine modular.
- Prefer automation over manual processes.
- Build incrementally with small, testable improvements.
- Favor clear operational data over unnecessary complexity.
- Treat logging and observability as first-class features.

---

## Architecture

```text
                    Infrastructure Log
                            │
                            ▼
                     Amazon S3 Bucket
                            │
                            ▼
                   AWS Lambda Processor
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
      Parse Log       Classify Incident   Score Incident
                            │
                            ▼
               Analyze Historical Incidents
                            │
                            ▼
             Determine Trend, Risk & Priority
                            │
                            ▼
             Generate Executive Summary
                            │
                            ▼
              Amazon DynamoDB Incident Store
                            │
                            ▼
                 Amazon CloudWatch Logs
```

---

## AWS Services

| Service | Purpose |
|----------|---------|
| Amazon S3 | Stores uploaded infrastructure logs |
| AWS Lambda | Processes uploaded logs automatically |
| Amazon DynamoDB | Stores enriched incident records |
| Amazon CloudWatch | Captures execution logs and operational monitoring |

---

## Project Structure

```text
cloudops-ai-incident-assistant/
│
├── lambda/
│   ├── lambda_function.py      # Main Lambda processor
│   ├── incident_rules.py       # Rule-based detection engine
│   └── lambda_function.zip     # Deployment package
│
├── samples/                    # Sample log files
│
├── build.ps1                   # Automated build script
│
├── README.md
│
└── .gitignore
```

---

## Building

Build the Lambda deployment package locally:

```powershell
.\build.ps1
```

The build script automatically:

- Validates Python syntax
- Creates a new deployment package
- Verifies ZIP integrity
- Confirms expected files exist
- Displays packaged files and sizes
- Cleans up temporary build artifacts
- Reports the final package size

---

## Current Incident Types

Currently supported:

- IIS HTTP 500.19 Configuration Errors
- Windows Service Unexpected Termination (Event ID 7031)

The incident detection engine is intentionally modular, allowing additional rule sets to be added with minimal code changes.

---

## Technologies

### Languages

- Python 3.12
- PowerShell

### AWS Services

- AWS Lambda
- Amazon S3
- Amazon DynamoDB
- Amazon CloudWatch

### Development Tools

- Git
- GitHub
- Visual Studio Code

---

## Sample Output

```json
{
  "incident_type": "iis",
  "severity": "error",
  "incident_priority": "P1",
  "incident_risk": "high",
  "incident_occurrence": 8,
  "incident_trend": "recurring",
  "assigned_team": "infrastructure_operations",
  "executive_summary": "P1 HIGH incident affecting unknown. This is occurrence #8 and is classified as recurring."
}
```

---

## Example Workflow

1. An infrastructure log is uploaded to Amazon S3.
2. AWS Lambda is triggered automatically.
3. The log is parsed and classified.
4. Historical incidents are analyzed.
5. Trend, priority, and risk are calculated.
6. An executive summary is generated.
7. The enriched incident record is stored in Amazon DynamoDB.
8. Execution details are written to Amazon CloudWatch Logs.

---

## Example Incident Record

Each processed incident includes enriched operational metadata such as:

- Incident Type
- Severity
- Confidence Score
- Historical Occurrence Count
- Trend Analysis
- Incident Priority
- Risk Level
- Escalation Recommendation
- Assigned Team
- Executive Summary
- Recommended Resolution
- Business Impact
- Processing Timestamp

---

## Future Enhancements

### Incident Detection

- SQL Server incident detection
- Disk space monitoring
- Windows Update failures
- IIS Application Pool failures
- Redis connectivity issues
- Linux service monitoring

### Notifications

- Email notifications
- Slack integration
- Microsoft Teams integration

### Visualization

- Incident dashboard
- Historical reporting
- Trend analytics
- Executive reporting

### Intelligence

- AI-assisted incident summarization
- Confidence score improvements
- Similar incident recommendations
- Root cause suggestions
- Intelligent remediation recommendations

### Engineering

- Automated unit testing
- GitHub Actions CI/CD
- Infrastructure as Code deployment
- Docker-based local testing
- Automated deployment pipeline

---

## Why This Project?

This project is being developed incrementally to mirror how production software evolves.

Rather than building a simple proof of concept, each enhancement focuses on improving:

- Maintainability
- Automation
- Observability
- Operational value
- Code quality
- Deployment reliability

The goal is to create a portfolio-quality cloud engineering project that demonstrates practical AWS architecture, automation, serverless development, and operational engineering practices.

---

## Roadmap

### Completed

- ✅ Automated incident processing pipeline
- ✅ Rule-based incident classification
- ✅ Historical incident analysis
- ✅ Dynamic incident scoring
- ✅ Executive summary generation
- ✅ Production logging with Amazon CloudWatch
- ✅ Automated build pipeline

### In Progress

- ⏳ Expand the incident detection library
- ⏳ Build an operational dashboard
- ⏳ Add automated notifications

### Planned

- 🔮 AI-assisted incident analysis
- 🔮 Similar incident recommendations
- 🔮 Root cause suggestions
- 🔮 Infrastructure as Code deployment
- 🔮 CI/CD automation

---

## About

This project is actively developed as both a personal engineering portfolio and a continuous learning platform.

Each enhancement is intentionally implemented as an incremental improvement, reflecting how production software evolves while exploring cloud engineering, serverless architecture, automation, observability, and AI-assisted operations.