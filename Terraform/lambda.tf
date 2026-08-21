resource "aws_lambda_function" "ai_worker" {
  function_name = "cloudops-ai-worker"

  filename         = "${path.module}/../lambda/ai_worker.zip"
  source_code_hash = filebase64sha256("${path.module}/../lambda/ai_worker.zip")

  role    = aws_iam_role.ai_worker.arn
  handler = "ai_worker.lambda_handler"
  runtime = "python3.12"

  timeout     = 60
  memory_size = 128

  environment {
    variables = {
      TABLE_NAME       = "incident-findings"
      BEDROCK_MODEL_ID = "us.anthropic.claude-sonnet-4-6"
    }
  }
}

resource "aws_lambda_event_source_mapping" "ai_worker_sqs" {
  event_source_arn = aws_sqs_queue.ai_analysis.arn
  function_name    = aws_lambda_function.ai_worker.arn

  batch_size = 1
  enabled    = true
}