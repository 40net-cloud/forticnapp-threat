##############################################################################################################
#
# Ubuntu / Debian instance (OS image selectable via terraform.tfvars) with Node.js and Brotli pinned to affected builds (CVE-2026-111497, Node2Shell)
# Terraform deployment template for AWS
#
##############################################################################################################

##############################################################################################################
# General
##############################################################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# Credentials are taken from the standard AWS mechanisms (environment variables, shared config, SSO, ...)
provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}

# Prefix for all resources created for this deployment in AWS
variable "prefix" {
  description = "Added name to each deployed resource"
}

variable "region" {
  description = "AWS region"
}

variable "key_name" {
  description = "Name of an existing EC2 key pair used for SSH access (login user: ubuntu or admin, depending on the selected OS image)"
}

variable "admin_source_cidr" {
  description = "Source CIDR allowed to reach SSH (22). Restrict this to your own public IP/CIDR."
  default     = "0.0.0.0/0"
}

##############################################################################################################
# OS image selection
##############################################################################################################

variable "os_images" {
  description = "Available OS images. Pick one with os_image. Add entries to support more images."
  type = list(object({
    name               = string # key used in os_image
    family             = string # "ubuntu" or "debian"
    ami_owner          = string # AWS account that publishes the AMI
    ami_name           = string # AMI name pattern; %s is replaced by amd64 or arm64
    ssh_user           = string # default login user of the AMI
    node_version       = string # default exact nodejs/libnode build to pin for this image
    libnode_pkg        = string # libnode package name matching the nodejs build
    brotli_version     = string # default exact libbrotli1/brotli build to pin for this image (vulnerable)
    snapshot_url       = string # APT line (without "deb [..]") of the snapshot archive that still carries the pinned builds, %s = timestamp
    snapshot_timestamp = string
  }))
  default = [
    {
      name      = "ubuntu-26.04"
      family    = "ubuntu"
      ami_owner = "099720109477" # Canonical
      ami_name  = "ubuntu/images/hvm-ssd-gp3/ubuntu-*-26.04-%s-server-*"
      ssh_user  = "ubuntu"
      # Ubuntu uses the system Brotli: 1.2.0-3build1 is the release build, fixed in 1.2.0-3ubuntu0.1
      node_version       = "22.22.1+dfsg+~cs22.19.15-1ubuntu1"
      libnode_pkg        = "libnode109"
      brotli_version     = "1.2.0-3build1"
      snapshot_url       = "https://snapshot.ubuntu.com/ubuntu/%s resolute main universe"
      snapshot_timestamp = "20261020T000000Z"
    },
    {
      name               = "debian-13"
      family             = "debian"
      ami_owner          = "136693071363" # Debian
      ami_name           = "debian-13-%s-*"
      ssh_user           = "admin"
      node_version       = "20.19.2+dfsg-1+deb13u2"
      libnode_pkg        = "libnode115"
      brotli_version     = "1.1.0-2+b7"
      snapshot_url       = "http://snapshot.debian.org/archive/debian/%s trixie main"
      snapshot_timestamp = "20261101T000000Z"
    },
  ]

  validation {
    condition     = alltrue([for i in var.os_images : contains(["ubuntu", "debian"], i.family)])
    error_message = "Each os_images entry must have family \"ubuntu\" or \"debian\"."
  }
}

variable "os_image" {
  description = "Name of the entry in os_images to deploy (e.g. ubuntu-26.04 or debian-13)"
  type        = string
  default     = "debian-13"
}

##############################################################################################################
# Node.js / Brotli settings
##############################################################################################################

variable "node_version" {
  description = "Exact nodejs/libnode build to install and hold. Leave null to use the node_version of the selected OS image (Debian trixie: every build is affected by CVE-2026-111497, no fixed version is published)."
  type        = string
  default     = null
}

variable "brotli_version" {
  description = "Exact libbrotli1/brotli build to install and hold. Leave null to use the brotli_version of the selected OS image (must be below the distribution fix: Debian 1.1.0-2+deb13u1, Ubuntu 26.04 1.2.0-3ubuntu0.1)."
  type        = string
  default     = null
}

variable "node_snapshot_timestamp" {
  description = "Snapshot archive timestamp (snapshot.debian.org / snapshot.ubuntu.com) that still carries the pinned builds. Leave null to use the snapshot_timestamp of the selected OS image."
  type        = string
  default     = null
}

variable "demo_port" {
  description = "TCP port of the Brotli demo service, reachable from admin_source_cidr"
  type        = number
  default     = 3000
}

##############################################################################################################
# Network and instance
##############################################################################################################

variable "vpc" {
  default = "172.16.140.0/24"
}

variable "subnet" {
  default = "172.16.140.0/25"
}

# t3.small is x86_64; use a Graviton type (e.g. t4g.small) together with arch = "arm64" for lower cost
variable "instance_type" {
  default = "t3.small"
}

variable "arch" {
  description = "Either x86_64 or arm64, must match the instance type"
  default     = "x86_64"
}

variable "tags" {
  type = map(string)
  default = {
    project = "node-vm"
  }
}

##############################################################################################################
# FortiCNAPP agent settings
##############################################################################################################

variable "install_forticnapp_agent" {
  description = "Install the FortiCNAPP Linux agent from the packages.lacework.net APT repository (amd64/arm64 only)"
  type        = bool
  default     = false
}

variable "forticnapp_access_token" {
  description = "FortiCNAPP agent access token (required when install_forticnapp_agent is true)"
  type        = string
  sensitive   = true
  default     = ""

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]*$", var.forticnapp_access_token))
    error_message = "The FortiCNAPP access token may only contain letters, digits, '-' and '_'."
  }
}

variable "forticnapp_server_url" {
  description = "Optional FortiCNAPP agent server URL for your region (e.g. https://api.fra.lacework.net for EU). Leave empty to let the agent auto-discover it."
  default     = "https://api.fra.lacework.net"
}

# Official images are published by Canonical (Ubuntu) and the Debian project
data "aws_ami" "lnx_ami" {
  most_recent = true
  owners      = [local.image.ami_owner]

  filter {
    name   = "name"
    values = [format(local.image.ami_name, var.arch == "x86_64" ? "amd64" : "arm64")]
  }

  filter {
    name   = "architecture"
    values = [var.arch]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  az1 = data.aws_availability_zones.available.names[0]
}

##############################################################################################################
# Cloud-init
##############################################################################################################

locals {
  image = one([for i in var.os_images : i if i.name == var.os_image])

  node_version       = coalesce(var.node_version, local.image.node_version)
  brotli_version     = coalesce(var.brotli_version, local.image.brotli_version)
  snapshot_timestamp = coalesce(var.node_snapshot_timestamp, local.image.snapshot_timestamp)
  snapshot_line      = format(local.image.snapshot_url, local.snapshot_timestamp)

  node_packages = ["nodejs", local.image.libnode_pkg, "libbrotli1", "brotli"]
  node_pinned = [
    "nodejs=${local.node_version}",
    "${local.image.libnode_pkg}=${local.node_version}",
    "libbrotli1=${local.brotli_version}",
    "brotli=${local.brotli_version}",
  ]

  forticnapp_config = jsonencode(merge(
    { tokens = { accesstoken = var.forticnapp_access_token } },
    var.forticnapp_server_url != "" ? { serverurl = var.forticnapp_server_url } : {}
  ))

  customdata = <<-EOT
    #cloud-config
    fqdn: ${lower(var.prefix)}-node-vm
    package_update: false
    package_upgrade: false
    write_files:
      %{~if var.install_forticnapp_agent~}
      - owner: root:root
        permissions: "0600"
        path: /var/lib/lacework/config/config.json
        content: '${replace(local.forticnapp_config, "'", "''")}'
      %{~endif~}
      - owner: root:root
        permissions: "0755"
        path: /usr/local/sbin/install-node.sh
        content: |
          #!/bin/bash
          set -euo pipefail
          export DEBIAN_FRONTEND=noninteractive
          APT="apt-get -y -o DPkg::Lock::Timeout=300"

          # Avoid dpkg lock contention with the automatic updater
          systemctl stop unattended-upgrades.service || true

          # Everything current first
          $APT update
          $APT full-upgrade

          # Pinned builds (variables, see terraform.tfvars)
          NODE_VER="${local.node_version}"
          BROTLI_VER="${local.brotli_version}"

          # Temporary snapshot repository that still carries the pinned builds
          echo "deb [check-valid-until=no trusted=yes] ${local.snapshot_line}" \
            > /etc/apt/sources.list.d/snapshot-node.list
          $APT update
          # nodejs needs ${local.image.libnode_pkg} at the same version, and it links the system libbrotli1
          $APT --allow-downgrades install ${join(" ", local.node_pinned)}

          # Remove the snapshot repository again and keep the pinned versions
          rm -f /etc/apt/sources.list.d/snapshot-node.list
          $APT update
          apt-mark hold ${join(" ", local.node_packages)}

          # Demo service: an endpoint that Brotli-decompresses request bodies (the CVE-2026-111497 code path)
          id -u node2shell >/dev/null 2>&1 || useradd --system --home /opt/node2shell --shell /usr/sbin/nologin node2shell
          install -d -o node2shell -g node2shell /opt/node2shell

          cat > /opt/node2shell/server.js <<'JSEOF'
          const http = require('http');
          const zlib = require('zlib');

          const port = Number(process.env.PORT || ${var.demo_port});

          const server = http.createServer((req, res) => {
            if (req.method === 'GET') {
              res.writeHead(200, { 'Content-Type': 'text/plain' });
              res.end(
                'Node2Shell demo host\n' +
                'node:   ' + process.version + '\n' +
                'brotli: ' + (process.versions.brotli || 'unknown') + '\n' +
                'usage:  curl -X POST --data-binary @payload.br -H "Content-Encoding: br" http://<host>:' + port + '/inflate\n'
              );
              return;
            }

            if (req.method === 'POST' && req.url === '/inflate') {
              const chunks = [];
              req.on('data', (c) => chunks.push(c));
              req.on('end', () => {
                try {
                  const out = zlib.brotliDecompressSync(Buffer.concat(chunks));
                  res.writeHead(200, { 'Content-Type': 'text/plain' });
                  res.end('inflated ' + out.length + ' bytes\n');
                } catch (err) {
                  res.writeHead(400, { 'Content-Type': 'text/plain' });
                  res.end('error: ' + err.message + '\n');
                }
              });
              return;
            }

            res.writeHead(404);
            res.end();
          });

          server.listen(port, '0.0.0.0', () => console.log('listening on ' + port));
          JSEOF

          cat > /etc/systemd/system/node2shell.service <<'UNITEOF'
          [Unit]
          Description=Node2Shell demo service (CVE-2026-111497 test target)
          After=network-online.target

          [Service]
          Type=simple
          User=node2shell
          Group=node2shell
          WorkingDirectory=/opt/node2shell
          Environment=PORT=${var.demo_port}
          ExecStart=/usr/bin/node /opt/node2shell/server.js
          Restart=always
          RestartSec=2

          [Install]
          WantedBy=multi-user.target
          UNITEOF

          systemctl daemon-reload
          systemctl enable --now node2shell.service

          %{~if var.install_forticnapp_agent~}
          # FortiCNAPP agent from the packages.lacework.net APT repository (config.json is written by cloud-init).
          # A failure here is logged but does not abort the rest of the build.
          ( set -e
            ARCH=$(dpkg --print-architecture)
            if [ "$ARCH" != "amd64" ] && [ "$ARCH" != "arm64" ]; then
              echo "FortiCNAPP agent is not available for architecture $ARCH, skipping"
              exit 0
            fi

            $APT install gpg curl ca-certificates lsb-release
            install -d -m 0755 /etc/apt/keyrings
            curl -fsS https://packages.lacework.net/keys/RPM-GPG-KEY-lacework | gpg --dearmor --yes -o /etc/apt/keyrings/lacework-agent.gpg
            printf 'Package: lacework*\nPin: origin "packages.lacework.net"\nPin-Priority: 999\n' > /etc/apt/preferences.d/lacework

            # Repository layout: https://packages.lacework.net/<channel>/DEB/<distro>  suite = release codename
            DISTRO=$(lsb_release -i -s | tr '[:upper:]' '[:lower:]')
            CODENAME=$(lsb_release -c -s)
            REPO="https://packages.lacework.net/latest/DEB/$DISTRO"
            # Not every new release has a suite yet (e.g. Debian trixie): fall back to the newest published Debian suite
            if ! curl -fsSI "$REPO/dists/$CODENAME/InRelease" > /dev/null; then
              if [ "$DISTRO" = "debian" ]; then
                echo "No FortiCNAPP suite for $DISTRO $CODENAME, falling back to bookworm"
                CODENAME=bookworm
              else
                echo "No FortiCNAPP suite for $DISTRO $CODENAME" >&2
                exit 1
              fi
            fi
            echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/lacework-agent.gpg] $REPO $CODENAME main" \
              > /etc/apt/sources.list.d/lacework.list

            $APT update
            $APT install lacework
            systemctl enable --now datacollector.service
          ) || echo "FortiCNAPP agent installation FAILED, see above"
          %{~endif~}

          # Build report: cat /var/log/node-report.txt
          {
            echo "== dpkg"
            dpkg -l | grep -E '^(ii|hi)\s+(nodejs|libnode|libbrotli|brotli)' || true
            echo
            echo "== node"
            node --version || true
            echo
            echo "== linked brotli"
            node -p 'process.versions.brotli' || true
            echo
            echo "== pins (vulnerable builds per distribution security tracker)"
            echo "nodejs      pin: $NODE_VER"
            echo "libbrotli1  pin: $BROTLI_VER (Debian fix 1.1.0-2+deb13u1, Ubuntu 26.04 fix 1.2.0-3ubuntu0.1)"
            echo
            echo "== holds"
            apt-mark showhold
          } > /var/log/node-report.txt
    runcmd:
      - [ bash, -c, "/usr/local/sbin/install-node.sh > /var/log/install-node.log 2>&1" ]
    final_message: "The system is finally up, after $UPTIME seconds"
  EOT
}

##############################################################################################################
# Network
##############################################################################################################

resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc
  enable_dns_support   = true
  enable_dns_hostnames = true
  instance_tenancy     = "default"
  tags = {
    Name = "${var.prefix}-vpc"
  }
}

resource "aws_subnet" "subnet" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.subnet
  availability_zone = local.az1
  tags = {
    Name = "${var.prefix}-subnet"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "${var.prefix}-igw"
  }
}

resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "${var.prefix}-rt"
  }
}

resource "aws_route" "internetroute" {
  route_table_id         = aws_route_table.rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "rtassociate" {
  subnet_id      = aws_subnet.subnet.id
  route_table_id = aws_route_table.rt.id
}

##############################################################################################################
# Linux VM
##############################################################################################################

resource "aws_security_group" "lnxsg" {
  name        = "${var.prefix}-lnx-sg"
  description = "SSH and demo port inbound"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_source_cidr]
  }

  ingress {
    description = "Brotli demo service"
    from_port   = var.demo_port
    to_port     = var.demo_port
    protocol    = "tcp"
    cidr_blocks = [var.admin_source_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.prefix}-lnx-sg"
  }
}

resource "aws_network_interface" "lnxnic" {
  description     = "${var.prefix}-lnx-nic"
  subnet_id       = aws_subnet.subnet.id
  security_groups = [aws_security_group.lnxsg.id]
  tags = {
    Name = "${var.prefix}-lnx-nic"
  }
}

resource "aws_instance" "lnxvm" {
  ami               = data.aws_ami.lnx_ami.id
  instance_type     = var.instance_type
  availability_zone = local.az1
  key_name          = var.key_name
  user_data         = local.customdata

  # IMDSv2 only
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }

  network_interface {
    network_interface_id = aws_network_interface.lnxnic.id
    device_index         = 0
  }

  tags = {
    Name = "${var.prefix}-lnx-vm"
  }

  lifecycle {
    precondition {
      condition     = local.image != null
      error_message = "os_image must match the name of exactly one entry in os_images."
    }

    precondition {
      condition     = !var.install_forticnapp_agent || var.forticnapp_access_token != ""
      error_message = "forticnapp_access_token must be set when install_forticnapp_agent is true."
    }
  }
}

resource "aws_eip" "lnxpip" {
  depends_on        = [aws_internet_gateway.igw]
  domain            = "vpc"
  network_interface = aws_network_interface.lnxnic.id
  tags = {
    Name = "${var.prefix}-lnx-pip"
  }
}

##############################################################################################################
# Output
##############################################################################################################

output "lnx_public_ip_address" {
  value = aws_eip.lnxpip.public_ip
}

output "lnx_private_ip_address" {
  value = aws_network_interface.lnxnic.private_ip
}

output "lnx_ssh" {
  value = "ssh -i <private key> ${local.image.ssh_user}@${aws_eip.lnxpip.public_ip}"
}

output "demo_url" {
  description = "Version page of the Brotli demo service"
  value       = "http://${aws_eip.lnxpip.public_ip}:${var.demo_port}/"
}

output "verify_command" {
  description = "Read the build report left by the cloud-init script (available once cloud-init has finished)"
  value       = "ssh -i <private key> ${local.image.ssh_user}@${aws_eip.lnxpip.public_ip} 'cat /var/log/node-report.txt'"
}

output "forticnapp_agent_installed" {
  value = var.install_forticnapp_agent
}
