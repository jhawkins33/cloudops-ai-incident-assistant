import json
import os

import boto3

from tools import lookup_incident_history


MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-sonnet-5",
)

bedrock = boto3.client("bedrock-runtime")


TOOL_CONFIG = {
    "tools": [
        {
            "toolSpec": {
                "name": "lookup_incident_history",
                "description": (
                    "Look up previous CloudOps incidents similar to "
                    "the current incident."
                ),
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "event_id": {
                                "type": "string",
                                "description": "Event ID for the incident",
                            },
                            "service": {
                                "type": "string",
                                "description": "Affected service name",
                            },
                            "incident_type": {
                                "type": "string",
                                "description": "Incident category",
                            },
                        },
                    }
                },
            }
        }
    ]
}


def run_agent(incident):
    messages = [
        {
            "role": "user",
            "content": [
                {
                    "text": (
                        "Analyze this CloudOps incident. "
                        "Use incident history when it would help produce "
                        "a better recommendation.\n\n"
                        f"{json.dumps(incident, indent=2)}"
                    )
                }
            ],
        }
    ]

    response = bedrock.converse(
        modelId=MODEL_ID,
        messages=messages,
        toolConfig=TOOL_CONFIG,
    )

    while response.get("stopReason") == "tool_use":
        assistant_message = response["output"]["message"]
        messages.append(assistant_message)

        tool_results = []

        for content in assistant_message.get("content", []):
            if "toolUse" not in content:
                continue

            tool_use = content["toolUse"]
            tool_name = tool_use["name"]
            tool_input = tool_use.get("input", {})

        if tool_name == "lookup_incident_history":
            result = lookup_incident_history(
                event_id=tool_input.get("event_id"),
                service=tool_input.get("service"),
                incident_type=tool_input.get("incident_type"),
            )
        else:
            result = {
                "error": f"Unknown tool requested: {tool_name}"
            }

        print(
            f"Tool called: {tool_name} "
            f"with input={tool_input} "
            f"results={len(result) if isinstance(result, list) else 1}"
        )

        tool_results.append(
            {
                "toolResult": {
                    "toolUseId": tool_use["toolUseId"],
                    "content": [
                        {
                            "json": {
                                "incidents": result
                            }
                        }
                    ],
                }
            }
        )

        messages.append(
            {
                "role": "user",
                "content": tool_results,
            }
        )

        response = bedrock.converse(
            modelId=MODEL_ID,
            messages=messages,
            toolConfig=TOOL_CONFIG,
        )

    final_message = response["output"]["message"]

    text_parts = []

    for content in final_message.get("content", []):
        if "text" in content:
            text_parts.append(content["text"])

    return "\n".join(text_parts)