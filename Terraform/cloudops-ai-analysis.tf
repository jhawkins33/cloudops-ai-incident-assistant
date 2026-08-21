resource "aws_sqs_queue" "ai_analysis" {
  name                       = "cloudops-ai-analysis"
  visibility_timeout_seconds = 90
}

resource "aws_sqs_queue_redrive_policy" "ai_analysis" {
  queue_url = aws_sqs_queue.ai_analysis.id

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.ai_analysis_dlq.arn
    maxReceiveCount     = 3
  })
}