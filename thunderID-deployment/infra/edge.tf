data "aws_route53_zone" "main" {
  zone_id = var.route53_zone_id
}

resource "aws_acm_certificate" "auth" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = var.domain_name }
}

resource "aws_route53_record" "certificate" {
  for_each = {
    for option in aws_acm_certificate.auth.domain_validation_options : option.domain_name => {
      name   = option.resource_record_name
      record = option.resource_record_value
      type   = option.resource_record_type
    }
  }

  allow_overwrite = true
  zone_id         = data.aws_route53_zone.main.zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
}

resource "aws_acm_certificate_validation" "auth" {
  certificate_arn         = aws_acm_certificate.auth.arn
  validation_record_fqdns = [for record in aws_route53_record.certificate : record.fqdn]
}

resource "aws_lb" "auth" {
  name               = "${var.name_prefix}-auth"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = { Name = "${var.name_prefix}-auth" }
}

resource "aws_lb_target_group" "auth" {
  name        = "${var.name_prefix}-auth"
  port        = 30080
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.main.id

  deregistration_delay = 30

  health_check {
    enabled             = true
    path                = "/health/readiness"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group_attachment" "auth" {
  for_each = toset(local.worker_names)

  target_group_arn = aws_lb_target_group.auth.arn
  target_id        = aws_instance.node[each.value].id
  port             = 30080
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.auth.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.auth.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.auth.arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.auth.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_wafv2_web_acl" "auth" {
  name  = "${var.name_prefix}-auth"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-auth"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "auth" {
  resource_arn = aws_lb.auth.arn
  web_acl_arn  = aws_wafv2_web_acl.auth.arn
}

resource "aws_route53_record" "auth" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.auth.dns_name
    zone_id                = aws_lb.auth.zone_id
    evaluate_target_health = true
  }
}
