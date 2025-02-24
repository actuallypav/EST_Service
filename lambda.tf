data "aws_iam_policy_document" "permissions" {
  statement {
    effect = "Allow"

    principals {
      type		= "Service"
      identifiers	= ["lambda.amazonaws.com"]
    }
    
    actions = ["sts:AssumeRole"] #update with permissions found in .txt
  }
}

resource "aws_iam_role" "assume_role" {
  name			= "assume-role"
  assume_role_policy 	= data.aws_iam_policy_document.permissions.json
}

data "archive_file" "python_zip" {
  type		= "zip"
  source_file	= "server.py"
  output_path	= "payload.zip"
}

resource "aws_lambda_function" "est" {
  filename 	= "payload.zip"
  function_name = "var.lambda_function_name"
  role 		= aws_iam_role.assume_role.arn
  
  source_code_hash  = data.archive_file.python_zip.output_base64sha256

  runtime = "python3.10"
  handler = "lambda_handler"

  logging_config {
    log_format = "Text"
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_outputs
  ]
}

resource "aws_cloudwatch_log_group" "lambda_outputs" {
  name 			= "/aws/lambda/${var.lambda_function_name}"
  retention_in_days 	= 3
}
