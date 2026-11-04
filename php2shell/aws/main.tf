##############################################################################################################
#
# Ubuntu / Debian instance with a pinned PHP version (OS image selectable via terraform.tfvars)
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
  description = "Available OS images (AMI lookups). Pick one with os_image. Add entries to support more images."
  type = list(object({
    name         = string # key used in os_image
    family       = string # "ubuntu" or "debian"
    ami_owner    = string # AWS account that publishes the AMI
    ami_name     = string # AMI name pattern; %s is replaced by amd64 or arm64
    ssh_user     = string # default login user of the AMI
    php_series   = string # PHP major.minor shipped by this image, e.g. "8.5"
    php_version  = string # default exact package version to pin for this image
  }))
  default = [
    {
      name        = "ubuntu-26.04"
      family      = "ubuntu"
      ami_owner   = "099720109477" # Canonical
      ami_name    = "ubuntu/images/hvm-ssd-gp3/ubuntu-*-26.04-%s-server-*"
      ssh_user    = "ubuntu"
      php_series  = "8.5"
      php_version = "8.5.4-0ubuntu1.5" # Must be 8.5.11 or below
    },
    {
      name        = "debian-13"
      family      = "debian"
      ami_owner   = "136693071363" # Debian
      ami_name    = "debian-13-%s-*"
      ssh_user    = "admin"
      php_series  = "8.4"
      php_version = "8.4.26-1~deb13u1"
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
# PHP / Apache settings (Apache and mod_php are always installed)
##############################################################################################################

variable "php_version" {
  description = "Exact package version of PHP to install and hold. Leave null to use the php_version of the selected OS image."
  type        = string
  default     = null
}

variable "php_snapshot_timestamp" {
  description = "Debian only: snapshot.debian.org timestamp used to fetch the pinned PHP packages from trixie-proposed-updates"
  default     = "20261010T000000Z"
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
    project = "php-vm"
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

  is_debian   = local.image.family == "debian"
  php_series  = local.image.php_series
  php_version = coalesce(var.php_version, local.image.php_version)

  # opcache is built into php8.5 on Ubuntu, there is no separate php8.5-opcache package
  php_packages = concat(
    ["php${local.php_series}", "php${local.php_series}-cli", "php${local.php_series}-common", "php${local.php_series}-readline"],
    local.is_debian ? ["php${local.php_series}-opcache"] : [],
    ["libapache2-mod-php${local.php_series}"]
  )
  php_pinned = [for p in local.php_packages : "${p}=${local.php_version}"]

  forticnapp_config = jsonencode(merge(
    { tokens = { accesstoken = var.forticnapp_access_token } },
    var.forticnapp_server_url != "" ? { serverurl = var.forticnapp_server_url } : {}
  ))

  customdata = <<-EOT
    #cloud-config
    fqdn: ${lower(var.prefix)}-php-vm
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
        path: /usr/local/sbin/install-php.sh
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

          $APT install apache2

          %{~if local.is_debian~}
          # Temporary snapshot repository providing the pinned PHP build
          echo "deb [check-valid-until=no trusted=yes] http://snapshot.debian.org/archive/debian/${var.php_snapshot_timestamp} trixie-proposed-updates main" \
            > /etc/apt/sources.list.d/snapshot-php.list
          $APT update
          $APT --allow-downgrades install ${join(" ", local.php_pinned)}

          # Remove the snapshot repository again and keep the pinned versions
          rm -f /etc/apt/sources.list.d/snapshot-php.list
          $APT update
          apt-mark hold ${join(" ", local.php_packages)}
          %{~else~}
          # PHP ${local.php_series} comes from the Ubuntu archive
          $APT --allow-downgrades install ${join(" ", local.php_pinned)}

          # Refuse anything newer than 8.5.11 and keep the pinned versions
          dpkg --compare-versions "$(dpkg-query -W -f='$${Version}' php${local.php_series}-cli)" le 8.5.11
          apt-mark hold ${join(" ", local.php_packages)}
          %{~endif~}

          # Serve PHP and expose the running version for quick checks
          a2enmod php${local.php_series} || true
          systemctl restart apache2
          cat > /var/www/html/index.php <<'PHPEOF'
          <?php
          header('Content-Type: text/plain');
          printf("PHP2Shell test host\nPHP version: %s\n", PHP_VERSION);
          PHPEOF

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

          # Build report: cat /var/log/php-report.txt
          {
            echo "== dpkg"
            dpkg -l | grep -E 'php${replace(local.php_series, ".", "\\.")}|libapache2-mod-php' || true
            echo
            echo "== php -v"
            php -v || true
            echo
            echo "== holds"
            apt-mark showhold
          } > /var/log/php-report.txt
    runcmd:
      - [ bash, -c, "/usr/local/sbin/install-php.sh > /var/log/install-php.log 2>&1" ]
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
  description = "SSH, HTTP and HTTPS inbound"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_source_cidr]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
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

output "http_url" {
  description = "URL of the version-reporting page"
  value       = "http://${aws_eip.lnxpip.public_ip}/index.php"
}

output "verify_command" {
  description = "Read the build report left by the cloud-init script (available once cloud-init has finished)"
  value       = "ssh -i <private key> ${local.image.ssh_user}@${aws_eip.lnxpip.public_ip} 'cat /var/log/php-report.txt'"
}

output "forticnapp_agent_installed" {
  value = var.install_forticnapp_agent
}
