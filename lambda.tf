data "aws_iam_policy_document" "permissions" {
  statement {
    effect = "Allow"

    principals {
      type		= "Service"
      identifiers	= ["lambda.amazonaws.com"]
    }
    
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "assume_role" {
  name			= "assume-role"
  assume_role_policy 	= data.aws_iam_policy_document.permissions.json
}

data "archive_file" "lambda" {
  type		= "zip"
  source_file	= "server.py"
  output_path	= "payload.zip"
}

resource "aws_lambda_function" "test_lambda" {
  filename 	= "payload.zip"
  function_name = "main"
  role 		= aws_iam_role.assume_role.arn
  
  source_code_hash  = data.archive_file.lambda.output_base64sha256

  runtime = "python3.10"
  handler = "lambda_handler"
}
