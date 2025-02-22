terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-2"
}

#create a security group for ALB
resource "aws_security_group" "est_alb_sg" {
  name        = "est-alb-security-group"
  description = "Allow inbound traffic from clients and outbound to EC2"
  vpc_id      = aws_vpc.main.id

  #ingress = accept client traffic on HTTPS (443)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #egress - allow ALB to communicate with EC2 and clients
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] #add in details for ec2_est_sg 
  }
  eggress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # allow ALB to send back to clients
  }
}

#create vpc for ALB
resource "aws_vpc" "est_alb_vpc" {
  cidr_block = "10.0.0.0/16"
}

#create a public subnet for ALB
resource "aws_subnet" "est_alb_public_1" {
  vpc_id                  = aws_vpc.est_alb_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "euw2-az1"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "est_alb_public_2" {
  vpc_id                  = aws_vpc.est_alb_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "euw2-az2"
  map_public_ip_on_launch = true
}

resource "aws_internet_gateway" "alb_est_igw" {
  vpc_id = aws_vpc.est_alb_vpc.id
}

#allows alb to access internet and outbound to respond to clients
resource "aws_route_table" "alb_est_public_rt" {
  vpc_id = aws_vpc.est_alb_vpc.id
}

resource "aws_route_table_assosciation" "est_alb_public_1" {
  subnet_id      = aws_subnet.est_alb_public_1.id
  route_table_id = aws_route_table.alb_est_public_rt.id
}

resource "aws_route_table_assosciation" "est_alb_public_2" {
  subnet_id      = aws_subnet.est_alb_public_2.id
  route_table_id = aws_route_table.alb_est_public_rt.id
}

#create a bucket (for logs) for ALB
resource "aws_s3_bucket" "est_alb_logs" {
  bucket        = "est-alb-logs-bucket"
  force_destroy = true
}

#give the bucket an expiration rule - delete data after 3 days
resource "aws_s3_bucket_lifecycle_configuration" "est_alb_logs_lifecycle" {
  bucket = aws_s3_bucket.est_alb_logs.id

  rule {
    id     = "expire-alb-logs"
    status = "Enabled"

    expiration {
      days = 3
    }
  }
}



#create a ACM cert for ALB
resource "aws_acm_certificate" "est_cert" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  tags = {
    Project = "est_service"
  }

  lifecycle {
    create_before_destroy = true
  }
}

#create an ALB
resource "aws_alb" "EST_alb" {
  name               = "EST-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.est_alb_sg.id]
  subnets            = [aws_subnet.est_alb_public_1.id, aws_subnet.est_alb_public_2.id]

  #will prevent tf from deleting the load balancer
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.est_alb_logs.id
    prefix  = "EST-alb"
    enabled = true
  }

  tags = {
    Project = "est_service"
  }
}

resource "aws_lb_target_group" "EST_Server" {
  #point the ALB at the EST Service EC2
}

resource "aws_lb_listener" "alb_est_listener" {
  load_balancer_arn = aws_alb.EST_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.est_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.EST_Server.arn
  }

  tags = {
    Project = "est_service"
  }
}

