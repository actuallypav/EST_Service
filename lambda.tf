resource "aws_iam_policy" "est_server_policy" {
  name        = "est-server-policy"
  description = "Policy for the est lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:*:${var.region}:${data.aws_caller_identity.current.account_id}:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "arn:aws:*:${var.region}:${data.aws_caller_identity.current.account_id}:secret:*"
      },
      {
        Effect   = "Allow"
        Action   = ["acm:CreateCertificateFromCsr"]
        Resource = "arn:aws:*:${var.region}:${data.aws_caller_identity.current.account_id}:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "iot:DescribeThing",
          "iot:CreateThing",
          "iot:GetPolicy",
          "iot:CreatePolicy",
          "iot:AttachThingPrincipal",
          "iot:AttachPolicy"
        ]
        Resource = "arn:aws:*:${var.region}:${data.aws_caller_identity.current.account_id}:*:*"
      },
      {
        Effect = "Allow"
        Action = "lambda:InvokeFunction"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_role_est" {
  role       = aws_iam_role.assume_role.name
  policy_arn = aws_iam_policy.est_server_policy.arn
}

resource "aws_iam_role" "assume_role" {
  name = "assume-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "null_resource" "install_dependencies" {
  provisioner "local-exec" {
    command = "pop install -r src/requirements.txt -t src/"
  }
}

data "archive_file" "python_zip" {
  type        = "zip"
  source_file = "src"
  output_path = "payload.zip"

  depends_on = [null_resource.install_dependencies]
}

resource "aws_lambda_function" "est_server" {
  filename      = "payload.zip"
  function_name = var.function_name
  role          = aws_iam_role.assume_role.arn

  source_code_hash = data.archive_file.python_zip.output_base64sha256

  runtime = "python3.10"
  handler = "server.lambda_handler"

  depends_on = [
    aws_cloudwatch_log_group.lambda_outputs
  ]

  environment {
    variables = {
      KV_NAME     = var.kv_name
      REGION      = var.region
      ROOT_CA_URL = var.root_ca_url
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda_outputs" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = 3
}
