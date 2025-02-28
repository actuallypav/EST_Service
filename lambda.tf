data "aws_iam_policy_document" "permissions" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"] #update with permissions found in .txt
  }
}

resource "aws_iam_role" "assume_role" {
  name               = "assume-role"
  assume_role_policy = data.aws_iam_policy_document.permissions.json
}

data "archive_file" "python_zip" {
  type        = "zip"
  source_file = "server.py"
  output_path = "payload.zip"
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
      KV_NAME = var.kv_name
      REGION = var.region
      ROOT_CA_URL = var.root_ca_url
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda_outputs" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = 3
}
