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
    },
    {
    "name": "SQL Server Login Failure 18456",
    "match": [
        "18456",
        "login failed"
    ],
    "issue": "SQL Server login failure",
    "incident_type": "sql_login_failure",
    "severity": "error",
    "alert_required": "yes",
    "assigned_team": "database_operations",
    "recommended_action": (
        "Review the SQL Server error log, login status, authentication mode, "
        "database access, and the failure state associated with error 18456."
    ),
    "resolution_recommendation": (
        "Correct the login, authentication, or database access issue "
        "identified by the SQL Server failure state"
    ),
    "confidence_score": 0.95,
    "incident_category": "database",
    "incident_source_system": "sql_server",
    "incident_summary": "SQL Server login failure detected",
    "business_impact": (
        "Applications or users may be unable to connect to the SQL Server instance"
    ),
    "estimated_resolution_time": "30 minutes",
    "incident_tags": [
        "sql_server",
        "database",
        "authentication",
        "18456",
        "high_priority"
    ]
},
]