resource "aws_vpc" "main" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  count = length(local.public_subnets)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_subnets[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name_prefix}-public-${count.index + 1}"
    Tier = "public"
  }
}

resource "aws_subnet" "app" {
  count = length(local.app_subnets)

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.app_subnets[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${var.name_prefix}-app-${count.index + 1}"
    Tier = "app"
  }
}

resource "aws_subnet" "data" {
  count = length(local.data_subnets)

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.data_subnets[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${var.name_prefix}-data-${count.index + 1}"
    Tier = "data"
  }
}

# One NAT gateway keeps the lab affordable. Add one per AZ for production HA.
resource "aws_eip" "nat" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.main]

  tags = { Name = "${var.name_prefix}-nat" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  depends_on    = [aws_internet_gateway.main]

  tags = { Name = "${var.name_prefix}-nat" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.name_prefix}-public" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = { Name = "${var.name_prefix}-private" }
}

resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "app" {
  count = length(aws_subnet.app)

  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "data" {
  count = length(aws_subnet.data)

  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.private.id
}

# Public edge: HTTPS (and HTTP redirect) from the internet.
resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb"
  description = "Public ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "To worker NodePort"
    from_port   = 30080
    to_port     = 30080
    protocol    = "tcp"
    cidr_blocks = local.app_subnets
  }

  tags = { Name = "${var.name_prefix}-alb" }
}

# Kubernetes nodes have no public IP. Use SSM Session Manager to access them.
resource "aws_security_group" "nodes" {
  name        = "${var.name_prefix}-nodes"
  description = "Kubernetes control-plane and worker nodes"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Control-plane and worker node-to-node"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  ingress {
    description = "Data nodes to cluster services"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = local.data_subnets
  }

  ingress {
    description     = "ALB to Istio NodePort"
    from_port       = 30080
    to_port         = 30080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description     = "Internal NLB to API"
    from_port       = 6443
    to_port         = 6443
    protocol        = "tcp"
    security_groups = [aws_security_group.nlb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-nodes" }
}

# PostgreSQL nodes accept cluster traffic (pods, kubelet, VXLAN) and replication.
resource "aws_security_group" "data" {
  name        = "${var.name_prefix}-data"
  description = "PostgreSQL data nodes"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Node-to-node replication"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  ingress {
    description = "App nodes (kubelet, VXLAN, pod traffic)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = local.app_subnets
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-data" }
}

resource "aws_security_group" "nlb" {
  name        = "${var.name_prefix}-nlb"
  description = "Internal Kubernetes API load balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "API from inside the VPC"
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  egress {
    description = "To control-plane nodes"
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = local.app_subnets
  }

  tags = { Name = "${var.name_prefix}-nlb" }
}
