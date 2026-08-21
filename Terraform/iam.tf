data "aws_iam_role" "lambda_execution_role" {
  name = var.lambda_execution_role_name
}

resource "aws_iam_role_policy" "bedrock_invoke" {
  name = "incident-assistant-bedrock-invoke"
  role = data.aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "bedrock:InvokeModel"
        ]

        Resource = "*"
      },
      {
        Effect = "Allow"

        Action = [
          "aws-marketplace:Subscribe",
          "aws-marketplace:ViewSubscriptions",
          "aws-marketplace:Unsubscribe"
        ]

        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "sns_publish" {
  name = "incident-assistant-sns-publish"
  role = data.aws_iam_role.lambda_execution_role.name

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = "arn:aws:sns:us-east-1:759982476405:cloudops-incident-alerts"
      }
    ]
  })
}

resource "aws_iam_role_policy" "sqs_send" {
  name = "incident-assistant-sqs-send"
  role = data.aws_iam_role.lambda_execution_role.name

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.ai_analysis.arn
      }
    ]
  })
}

resource "aws_iam_role" "ai_worker" {
  name = "cloudops-ai-worker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "lambda.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ai_worker_basic_execution" {
  role       = aws_iam_role.ai_worker.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "ai_worker_sqs_consume" {
  name = "cloudops-ai-worker-sqs-consume"
  role = aws_iam_role.ai_worker.name

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]

        Resource = aws_sqs_queue.ai_analysis.arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "ai_worker_dynamodb_update" {
  name = "cloudops-ai-worker-dynamodb-update"
  role = aws_iam_role.ai_worker.name

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "dynamodb:UpdateItem",
          "dynamodb:Scan"
        ]

        Resource = "arn:aws:dynamodb:us-east-1:759982476405:table/incident-findings"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ai_worker_bedrock_invoke" {
  name = "cloudops-ai-worker-bedrock-invoke"
  role = aws_iam_role.ai_worker.name

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = "*"
      }
    ]
  })
}