# Create an ACM Cert for HTTPS on API GW
resource "aws_acm_certificate" "api_est_cert" {
  domain_name       = var.est_domain
  subject_alternative_names = ["api.${var.est_domain}"]
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

data "aws_route53_zone" "est_zone" {
  name         = var.est_domain
  private_zone = false
}

resource "aws_route53_record" "api_route" {
  zone_id = data.aws_route53_zone.est_zone.zone_id
  name    = "api.${var.est_domain}"
  type    = "A"
  alias {
    evaluate_target_health = true
    name                   = aws_api_gateway_domain_name.est_domain.regional_domain_name
    zone_id                = aws_api_gateway_domain_name.est_domain.regional_zone_id
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.api_est_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  }

  zone_id = data.aws_route53_zone.est_zone.zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 80
}

resource "aws_acm_certificate_validation" "cert_val" {
  certificate_arn         = aws_acm_certificate.api_est_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# Register a custom domain name for the AWS API Gateway
resource "aws_api_gateway_domain_name" "est_domain" {
  domain_name              = "api.${var.est_domain}"
  regional_certificate_arn = aws_acm_certificate.api_est_cert.arn

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_apigatewayv2_api_mapping" "api_map" {
  api_id      = aws_apigatewayv2_api.est_api.id
  domain_name = aws_api_gateway_domain_name.est_domain.domain_name
  stage       = aws_apigatewayv2_stage.est_gw_stage.id
}


