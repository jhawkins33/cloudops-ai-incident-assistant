INCIDENT_RULES = [
    {
    "name": "Windows Service 7031",
    "match": [
        "7031",
        "terminated unexpectedly"
    ],
    "issue": "Windows service terminated unexpectedly",
    "incident_type": "windows_service",
    "severity": "error",
    "alert_required": "yes",
    "assigned_team": "infrastructure_operations",
    "recommended_action": (
        "Check service logs, recent deployments, service account permissions, "
        "and dependency failures."
    ),
    "resolution_recommendation": (
        "Investigate service stability and restart conditions"
    ),
    "confidence_score": 0.95,
    "incident_category": "infrastructure",
    "incident_source_system": "windows_os",
    "incident_summary": "Service {service} terminated unexpectedly",
    "business_impact": (
        "Infrastructure service interruption may affect application operations"
    ),
    "estimated_resolution_time": "15 minutes",
    "incident_tags": [
        "windows",
        "service",
        "infrastructure",
        "7031",
        "high_priority"
    ]
},
    {
        "name": "IIS HTTP 500.19",
        "match": [
            "500.19"
        ],
        "issue": "IIS configuration error",
        "incident_type": "iis",
        "severity": "error",
        "alert_required": "yes",
        "assigned_team": "infrastructure_operations",
        "recommended_action": (
            "Verify web.config permissions, application pool identity, "
            "and IIS configuration validity."
        ),
        "resolution_recommendation": (
            "Correct the IIS configuration or permissions causing the failure"
        ),
        "confidence_score": 0.95,
        "incident_category": "application_hosting",
        "incident_source_system": "iis",
        "incident_summary": "IIS configuration error detected",
        "business_impact": (
            "The affected web application may be unavailable or unable to load"
        ),
        "estimated_resolution_time": "30 minutes",
        "incident_tags": [
            "iis",
            "web",
            "configuration",
            "500.19",
            "high_priority"
        ]
    }
]