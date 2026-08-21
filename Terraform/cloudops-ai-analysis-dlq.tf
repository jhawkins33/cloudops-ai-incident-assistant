resource "aws_sqs_queue" "ai_analysis_dlq" {
  name = "cloudops-ai-analysis-dlq"
}