variable "lambda_function_name" {
  description = "Existing CloudOps Incident Assistant Lambda function name"
  type        = string
}

variable "lambda_execution_role_name" {
  description = "Existing IAM execution role used by the Lambda function"
  type        = string
}

variable "bedrock_model_id" {
  description = "Amazon Bedrock model used by the incident agent"
  type        = string
  default     = "anthropic.claude-sonnet-5"
}