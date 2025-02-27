terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.67.0"
    }
  }
}

provider "aws" {
  region = "eu-west-2"
}


#create vpc for ALB
resource "aws_vpc" "est_lb_cloud" {
  cidr_block = "10.0.0.0/16"
}

#create a public subnet for ALB
resource "aws_subnet" "est_lb_public_1" {
  vpc_id                  = aws_vpc.est_lb_cloud.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "euw2-az1"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "est_lb_public_2" {
  vpc_id                  = aws_vpc.est_lb_cloud.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "euw2-az2"
  map_public_ip_on_launch = true
}

resource "aws_internet_gateway" "alb_est_edge" {
  vpc_id = aws_vpc.est_lb_cloud.id
}

#allows alb to access internet and outbound to respond to clients
resource "aws_route_table" "lb_est_public" {
  vpc_id = aws_vpc.est_lb_cloud.id
}

resource "aws_route_table_association" "est_lb_public_1" {
  subnet_id      = aws_subnet.est_lb_public_1.id
  route_table_id = aws_route_table.lb_est_public.id
}

resource "aws_route_table_association" "est_lb_public_2" {
  subnet_id      = aws_subnet.est_lb_public_2.id
  route_table_id = aws_route_table.lb_est_public.id
}

#create a bucket (for logs) for NLB
resource "aws_s3_bucket" "est_logs" {
  bucket        = "est-logs"
  force_destroy = true
}

#give the bucket an expiration rule - delete data after 3 days
resource "aws_s3_bucket_lifecycle_configuration" "est_logs_lifecycle" {
  bucket = aws_s3_bucket.est_logs.id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    expiration {
      days = 3
    }
  }
}

#create an NLB
resource "aws_lb" "est_gateway" {
  name               = "est-gateway"
  internal           = false
  load_balancer_type = "network"
  subnets            = [aws_subnet.est_lb_public_1.id, aws_subnet.est_lb_public_2.id]

  #will prevent tf from deleting the load balancer
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.est_logs.id
    prefix  = "EST-alb"
    enabled = true
  }

  tags = {
    Project = "est_service"
  }
}

#point the ALB at the EST Server Lambda
resource "aws_lb_target_group" "est_server" {
  name = "est-server"
  target_type = "lambda"
  vpc_id = aws_vpc.est_lb_cloud.id
}

resource "aws_lb_target_group_attachment" "est_pointer" {
  target_group_arn = aws_lb_target_group.est_server.arn
  target_id = aws_lambda_function.est_server.arn
}

resource "aws_lb_listener" "est_gateway_endpoint" {
  load_balancer_arn = aws_lb.est_gateway.arn
  port              = "80"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.est_server.arn
  }

  tags = {
    Project = "est_service"
  }
}

#give permission to nlb to call lambda
resource "aws_lambda_permission" "nlb_invocation" {
  statement_id = "AllowNLBInvocation"
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.est_server.function_name
  principal = "elasticloadbalancing.amazonaws.com"
  source_arn = aws_lb_target_group.est_server.arn
}