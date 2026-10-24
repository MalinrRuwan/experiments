data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "node" {
  for_each = local.nodes

  ami                         = data.aws_ami.ubuntu.id
  instance_type               = each.value.type
  subnet_id                   = each.value.tier == "data" ? aws_subnet.data[each.value.subnet].id : aws_subnet.app[each.value.subnet].id
  vpc_security_group_ids      = [each.value.tier == "data" ? aws_security_group.data.id : aws_security_group.nodes.id]
  iam_instance_profile        = aws_iam_instance_profile.node.name
  associate_public_ip_address = false

  user_data = templatefile("${path.module}/templates/node-userdata.sh.tftpl", {
    hostname         = each.key
    kubernetes_minor = var.kubernetes_minor
    bootstrap        = file("${path.module}/../scripts/bootstrap-node.sh")
  })

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = each.value.role == "data" ? 40 : 20
    encrypted             = true
    kms_key_id            = aws_kms_key.main.arn
    delete_on_termination = true
  }

  tags = {
    Name = each.key
    Role = each.value.role
    Tier = each.value.tier
  }
}

# Internal API endpoint used by kubeadm (control-plane-endpoint).
resource "aws_lb" "api" {
  name                             = "${var.name_prefix}-api"
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = aws_subnet.app[*].id
  security_groups                  = [aws_security_group.nlb.id]
  enable_cross_zone_load_balancing = true

  tags = { Name = "${var.name_prefix}-api" }
}

resource "aws_lb_target_group" "api" {
  name        = "${var.name_prefix}-api"
  port        = 6443
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = aws_vpc.main.id

  health_check {
    protocol            = "TCP"
    port                = "6443"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "api" {
  load_balancer_arn = aws_lb.api.arn
  port              = 6443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_target_group_attachment" "api" {
  for_each = toset(local.control_plane_names)

  target_group_arn = aws_lb_target_group.api.arn
  target_id        = aws_instance.node[each.value].id
  port             = 6443
}
