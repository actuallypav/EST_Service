terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.20.0"
    }
  }
}

provider "aws" {
  region = var.region
}

#get aws account id
data "aws_caller_identity" "current" {}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

#create API Gateway HTTP API
resource "aws_apigatewayv2_api" "est_api" {
  name          = "est-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id           = aws_apigatewayv2_api.est_api.id
  integration_type = "AWS_PROXY"
  integration_uri  = aws_lambda_function.est_server.invoke_arn
}

resource "aws_apigatewayv2_route" "lambda_root" {
  api_id    = aws_apigatewayv2_api.est_api.id
  route_key = "ANY /"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

resource "aws_cloudwatch_log_group" "est_gw_logs" {
  name              = "/aws/apigatewayv2/gateway-logs"
  retention_in_days = 7
}

#give permission to api gateway to write logs
resource "aws_iam_role" "est_gw_role" {
  name = "est-gw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "apigateway.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "est_gw_policy" {
  name        = "est-gw-policy"
  description = "Allows the EST API Gateway to write logs to Cloudwatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents",
        "logs:GetLogEvents",
        "logs:FilterLogEvents"
      ]
      Resource = [aws_cloudwatch_log_group.est_gw_logs.arn]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "est_gw" {
  role       = aws_iam_role.est_gw_role.name
  policy_arn = aws_iam_policy.est_gw_policy.arn
}

resource "aws_apigatewayv2_stage" "est_gw_stage" {
  api_id      = aws_apigatewayv2_api.est_api.id
  name        = "prod"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.est_gw_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId",
      ip             = "$context.identity.sourceIp",
      httpMethod     = "$context.httpMethod",
      routeKey       = "$context.routeKey",
      status         = "$context.status",
      protocol       = "$context.protocol",
      responseLength = "$context.responseLength"
    })
  }
}

resource "aws_lambda_permission" "apigw_lambda" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.est_server.function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_apigatewayv2_api.est_api.execution_arn}/*"
}

output "est_service_url" {
  value = aws_apigatewayv2_stage.est_gw_stage.invoke_url
}

#generate a 32-byte AES Key (b64 encoded)
resource "random_bytes" "aes_key" {
  length = 32
}

#generate a 16-byte IV (b64 encoded)
resource "random_bytes" "aes_iv" {
  length = 16
}

#the shit below can defo break tbh
#create a secret for AES decryption/encryption
resource "aws_secretsmanager_secret" "kv_encryptor" {
  name        = var.kv_name
  description = "AES 256 Key and IV"
}

#store KV in Secrets Manager (IF previous secret does not exist)
resource "aws_secretsmanager_secret_version" "kv_value" {
  secret_id = aws_secretsmanager_secret.kv_encryptor.id
  secret_string = jsonencode({
    aes_key = random_bytes.aes_key.base64
    aes_iv  = random_bytes.aes_iv.base64
  })
}