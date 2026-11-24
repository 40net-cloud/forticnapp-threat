##############################################################################################################
#
# Ubuntu / Debian instance combining all demo vulnerabilities selectable via `scenarios` (OS image selectable
# via terraform.tfvars): PHP2Shell, Node2Shell (Brotli) and mod_http2 RCE — one host, one agent, every CVE.
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

# The three state_* variables are read by scripts/configure-state-backend.sh, not by Terraform:
# a backend block cannot use variables.
variable "state_backend" {
  description = "Where Terraform state lives: \"local\" or \"s3\". Applied by scripts/configure-state-backend.sh."
  type        = string
  default     = "local"
}

variable "state_bucket" {
  description = "S3 bucket for state when state_backend = \"s3\". Empty = forticnapp-threat-tfstate-<account>-<region>."
  type        = string
  default     = ""
}

variable "state_key" {
  description = "Object key of the state file in the bucket."
  type        = string
  default     = "vulnerable-vm/terraform.tfstate"
}

variable "key_name" {
  description = "Name of an existing EC2 key pair used for SSH access (login user: ubuntu or admin, depending on the selected OS image)"
}

variable "admin_source_cidr" {
  description = "Source CIDR allowed to reach SSH (22) and the Brotli demo port. Restrict this to your own public IP/CIDR."
  default     = "0.0.0.0/0"
}

##############################################################################################################
# Scenario selection
##############################################################################################################

variable "scenarios" {
  description = "Which vulnerabilities to install on the one host. \"php2shell\" (PHP2Shell), \"broccoli2shell\" (Node2Shell/Brotli) and \"cve-2026-119618\" (mod_http2 RCE). All three by default: a single host carrying every vulnerability."
  type        = list(string)
  default     = ["php2shell", "broccoli2shell", "cve-2026-119618"]

  validation {
    condition = (
      length(var.scenarios) > 0 &&
      alltrue([for s in var.scenarios : contains(["php2shell", "broccoli2shell", "cve-2026-119618"], s)])
    )
    error_message = "scenarios must be a non-empty list of: \"php2shell\", \"broccoli2shell\", \"cve-2026-119618\"."
  }
}

##############################################################################################################
# OS image selection
##############################################################################################################

variable "os_images" {
  description = "Available OS images. Pick one with os_image. Add entries to support more images."
  type = list(object({
    name                      = string # key used in os_image
    family                    = string # "ubuntu" or "debian"
    ami_owner                 = string # AWS account that publishes the AMI
    ami_name                  = string # AMI name pattern; %s is replaced by amd64 or arm64
    ssh_user                  = string # default login user of the AMI
    php_series                = string # PHP major.minor shipped by this image, e.g. "8.5"
    php_version               = string # exact php build to pin (vulnerable)
    php_snapshot_url          = string # APT line with %s = timestamp (unused on Ubuntu, where php comes from the live archive)
    php_snapshot_timestamp    = string
    node_version              = string # exact nodejs/libnode build to pin (vulnerable)
    libnode_pkg               = string # libnode package name matching the nodejs build
    brotli_version            = string # exact libbrotli1/brotli build to pin (vulnerable)
    node_snapshot_url         = string # APT line with %s = timestamp
    node_snapshot_timestamp   = string
    apache_version            = string # exact apache2 build to pin (vulnerable)
    apache_snapshot_url       = string # APT line with %s = timestamp
    apache_snapshot_timestamp = string
  }))
  default = [
    {
      name      = "ubuntu-26.04"
      family    = "ubuntu"
      ami_owner = "099720109477" # Canonical
      ami_name  = "ubuntu/images/hvm-ssd-gp3/ubuntu-*-26.04-%s-server-*"
      ssh_user  = "ubuntu"
      # PHP comes from the live archive (resolute-updates/-security still carry 8.5.4-0ubuntu1.5);
      # the snapshot fields are unused on Ubuntu (the entry only has to satisfy coalesce()).
      php_series             = "8.5"
      php_version            = "8.5.4-0ubuntu1.5"                                            # Must be 8.5.11 or below
      php_snapshot_url       = "https://snapshot.ubuntu.com/ubuntu/%s resolute-updates main" # unused: php comes from the live archive
      php_snapshot_timestamp = "20261111T000000Z"
      # Release-pocket builds: 1.2.0-3build1 is the release Brotli, fixed in 1.2.0-3ubuntu0.1
      node_version            = "22.22.1+dfsg+~cs22.19.15-1ubuntu1"
      libnode_pkg             = "libnode109"
      brotli_version          = "1.2.0-3build1"
      node_snapshot_url       = "https://snapshot.ubuntu.com/ubuntu/%s resolute main universe"
      node_snapshot_timestamp = "20261020T000000Z"
      # Last resolute-security build before USN-9090-1 (2026-11-12); fixed in 2.4.66-2ubuntu2.8
      apache_version            = "2.4.66-2ubuntu2.7"
      apache_snapshot_url       = "https://snapshot.ubuntu.com/ubuntu/%s resolute-security main"
      apache_snapshot_timestamp = "20261111T000000Z"
    },
    {
      name                      = "debian-13"
      family                    = "debian"
      ami_owner                 = "136693071363" # Debian
      ami_name                  = "debian-13-%s-*"
      ssh_user                  = "admin"
      php_series                = "8.4"
      php_version               = "8.4.26-1~deb13u1" # Debian fix: 8.4.26-1~deb13u2
      php_snapshot_url          = "http://snapshot.debian.org/archive/debian/%s trixie-proposed-updates main"
      php_snapshot_timestamp    = "20261010T000000Z"
      node_version              = "20.19.2+dfsg-1+deb13u2"
      libnode_pkg               = "libnode115"
      brotli_version            = "1.1.0-2+b7" # Debian fix: 1.1.0-2+deb13u1
      node_snapshot_url         = "http://snapshot.debian.org/archive/debian/%s trixie main"
      node_snapshot_timestamp   = "20261101T000000Z"
      apache_version            = "2.4.69-1~deb13u1" # Fixed in 2.4.71-1~deb13u1 (DSA-6620-1)
      apache_snapshot_url       = "http://snapshot.debian.org/archive/debian-security/%s trixie-security main"
      apache_snapshot_timestamp = "20261111T000312Z"
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
# Vulnerable-build pins (defaults come from os_images)
##############################################################################################################

variable "php_version" {
  description = "Exact php build to install and hold (php packages incl. libapache2-mod-php). Leave null for the OS image default; must be vulnerable for CVE-2026-109618/109619."
  type        = string
  default     = null
}

variable "php_snapshot_timestamp" {
  description = "Debian only: snapshot.debian.org timestamp of the trixie-proposed-updates archive carrying the pinned PHP build."
  type        = string
  default     = null
}

variable "node_version" {
  description = "Exact nodejs/libnode build to install and hold (with libbrotli1/brotli). Leave null for the OS image default; affected by CVE-2026-111497."
  type        = string
  default     = null
}

variable "brotli_version" {
  description = "Exact libbrotli1/brotli build to install and hold. Leave null for the OS image default (must be below the distribution fix: Debian 1.1.0-2+deb13u1, Ubuntu 26.04 1.2.0-3ubuntu0.1)."
  type        = string
  default     = null
}

variable "node_snapshot_timestamp" {
  description = "Snapshot archive timestamp carrying the pinned node/brotli builds. Leave null for the OS image default."
  type        = string
  default     = null
}

variable "apache_version" {
  description = "Exact apache2 build to install and hold (apache2, apache2-bin, apache2-data, apache2-utils). Leave null for the OS image default; must lie in the CVE-2026-119618 range 2.4.55 through 2.4.70."
  type        = string
  default     = null
}

variable "apache_snapshot_timestamp" {
  description = "Snapshot archive timestamp carrying the pinned apache2 build. Leave null for the OS image default."
  type        = string
  default     = null
}

variable "demo_port" {
  description = "TCP port of the Brotli demo service, reachable from admin_source_cidr"
  type        = number
  default     = 3000
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
    project = "forticnapp-threat"
  }
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

locals {
  image = one([for i in var.os_images : i if i.name == var.os_image])

  # Scenario selection (drives the shell flags in the install script and the firewall rules)
  do_php    = contains(var.scenarios, "php2shell")
  do_brotli = contains(var.scenarios, "broccoli2shell")
  do_http2  = contains(var.scenarios, "cve-2026-119618")
  do_apache = local.do_php || local.do_http2

  is_debian = local.image.family == "debian"

  # Ternaries are rendered as shell variables inside the script, so the script body itself stays
  # directive-free: identical text works in cloud-init (Azure/AWS) and the GCP startup script.
  f_php    = tostring(local.do_php)
  f_brotli = tostring(local.do_brotli)
  f_http2  = tostring(local.do_http2)
  f_apache = tostring(local.do_apache)
  f_debian = tostring(local.is_debian)

  # --- Pins ---
  php_series           = local.image.php_series
  php_version          = coalesce(var.php_version, local.image.php_version)
  php_snapshot_ts      = coalesce(var.php_snapshot_timestamp, local.image.php_snapshot_timestamp)
  php_snapshot_line    = format(local.image.php_snapshot_url, local.php_snapshot_ts)
  node_version         = coalesce(var.node_version, local.image.node_version)
  brotli_version       = coalesce(var.brotli_version, local.image.brotli_version)
  node_snapshot_ts     = coalesce(var.node_snapshot_timestamp, local.image.node_snapshot_timestamp)
  node_snapshot_line   = format(local.image.node_snapshot_url, local.node_snapshot_ts)
  apache_version       = coalesce(var.apache_version, local.image.apache_version)
  apache_snapshot_ts   = coalesce(var.apache_snapshot_timestamp, local.image.apache_snapshot_timestamp)
  apache_snapshot_line = format(local.image.apache_snapshot_url, local.apache_snapshot_ts)

  php_packages = concat(
    ["php${local.image.php_series}", "php${local.image.php_series}-cli", "php${local.image.php_series}-common", "php${local.image.php_series}-readline"],
    local.is_debian ? ["php${local.image.php_series}-opcache"] : [],
    ["libapache2-mod-php${local.image.php_series}"]
  )
  php_pinned = [for p in local.php_packages : "${p}=${local.php_version}"]
  # apache2 depends on apache2-bin, apache2-data and apache2-utils at the exact same version
  apache_packages = ["apache2", "apache2-bin", "apache2-data", "apache2-utils"]
  apache_pinned   = [for p in local.apache_packages : "${p}=${local.apache_version}"]
  node_packages   = [local.image.libnode_pkg, "nodejs", "libbrotli1", "brotli"]
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
    fqdn: ${lower(var.prefix)}-forticnapp-threat-vm
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
        path: /usr/local/sbin/install-vulns.sh
        content: |
          #!/bin/bash
          set -euo pipefail
          export DEBIAN_FRONTEND=noninteractive
          APT="apt-get -y -o DPkg::Lock::Timeout=300"

          # Which scenarios and pins this deployment uses (rendered by Terraform)
          SCENARIOS="${join(" ", var.scenarios)}"
          IS_DEBIAN="${local.f_debian}"
          DO_PHP="${local.f_php}"
          DO_BROTLI="${local.f_brotli}"
          DO_HTTP2="${local.f_http2}"
          DO_APACHE="${local.f_apache}"
          PHP_SERIES="${local.php_series}"
          PHP_VER="${local.php_version}"
          NODE_VER="${local.node_version}"
          BROTLI_VER="${local.brotli_version}"
          APACHE_VER="${local.apache_version}"
          DEMO_PORT="${var.demo_port}"

          # Avoid dpkg lock contention with the automatic updater
          systemctl stop unattended-upgrades.service || true

          # Everything current first — pins below are applied afterwards and protected by holds
          $APT update
          $APT full-upgrade

          # --- Scenario: cve-2026-119618 (mod_http2 RCE, fixed in 2.4.71) ---
          # Debian keeps security fixes in archive/debian-security (trixie-security), not the main archive.
          if [ "$DO_HTTP2" = "true" ]; then
            echo "deb [check-valid-until=no trusted=yes] ${local.apache_snapshot_line}" \
              > /etc/apt/sources.list.d/snapshot-apache.list
            $APT update
            $APT --allow-downgrades install ${join(" ", local.apache_pinned)}
            rm -f /etc/apt/sources.list.d/snapshot-apache.list
            $APT update
            apt-mark hold ${join(" ", local.apache_packages)}

            # Anything newer than the last affected upstream release (2.4.70) means the pin failed
            dpkg --compare-versions "$(dpkg-query -W -f='$${Version}' apache2-bin)" le 2.4.70

            a2enmod http2
          cat > /etc/apache2/conf-available/cve-2026-119618.conf <<'CFGEOF'
          # CVE-2026-119618 test host: cleartext HTTP/2 and a revealing Server header
          Protocols h2c http/1.1
          ServerTokens Full
          ServerSignature On
          CFGEOF
            a2enconf cve-2026-119618
          fi

          # --- Scenario: php2shell (PHP2Shell RCE, PHP <= 8.5.11 / <= 8.4.26-deb) ---
          if [ "$DO_PHP" = "true" ]; then
            dpkg -s apache2 > /dev/null 2>&1 || $APT install apache2
            if [ "$IS_DEBIAN" = "true" ]; then
              # Temporary snapshot archive still carrying the pinned PHP build (trixie-proposed-updates)
              echo "deb [check-valid-until=no trusted=yes] ${local.php_snapshot_line}" \
                > /etc/apt/sources.list.d/snapshot-php.list
              $APT update
            fi
            $APT --allow-downgrades install ${join(" ", local.php_pinned)}
            rm -f /etc/apt/sources.list.d/snapshot-php.list
            $APT update

            # Refuse anything newer than 8.5.11 and keep the pinned versions
            dpkg --compare-versions "$(dpkg-query -W -f='$${Version}' php$PHP_SERIES-cli)" le 8.5.11
            apt-mark hold ${join(" ", local.php_packages)}

            a2enmod "php$PHP_SERIES" || true
          fi

          # --- Scenario: broccoli2shell (Node2Shell / Brotli, libbrotli1 affected build) ---
          if [ "$DO_BROTLI" = "true" ]; then
            echo "deb [check-valid-until=no trusted=yes] ${local.node_snapshot_line}" \
              > /etc/apt/sources.list.d/snapshot-node.list
            $APT update
            # nodejs needs ${local.image.libnode_pkg} at the same version, and it links the system libbrotli1
            $APT --allow-downgrades install ${join(" ", local.node_pinned)}
            rm -f /etc/apt/sources.list.d/snapshot-node.list
            $APT update
            apt-mark hold ${join(" ", local.node_packages)}

            # Demo service: an endpoint that Brotli-decompresses request bodies (the CVE-2026-111497 code path)
            id -u node2shell > /dev/null 2>&1 || useradd --system --home /opt/node2shell --shell /usr/sbin/nologin node2shell
            install -d -o node2shell -g node2shell /opt/node2shell

          cat > /opt/node2shell/server.js <<'JSEOF'
          const http = require('http');
          const zlib = require('zlib');

          const port = Number(process.env.PORT || 3000);

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
          fi

          # --- Version-reporting page + Apache restart (Apache only exists when php or http2 is on) ---
          if [ "$DO_APACHE" = "true" ]; then
            APACHE_PKG_VER=$(dpkg-query -W -f='$${Version}' apache2-bin 2>/dev/null 2>&1 || echo n/a)
            MOD_H2=$(a2query -m http2 2>/dev/null || echo "not enabled")
            NODE_V=$(node --version 2>/dev/null || echo "not installed")
            BROTLI_V=$(dpkg-query -W -f='$${Version}' libbrotli1 2>/dev/null 2>&1 || echo "not installed")
            if [ "$DO_PHP" = "true" ]; then
          cat > /var/www/html/index.php <<'PHPEOF'
          <?php
          header('Content-Type: text/plain');
          printf("FortiCNAPP multi-CVE test host\n");
          printf("scenarios:     SCENPLACEHOLDER\n");
          printf("PHP version:   %s (pin: PHPPINPLACEHOLDER)\n", PHP_VERSION);
          printf("Apache (dpkg): APKGVPLACEHOLDER\n");
          printf("mod_http2:     MODH2PLACEHOLDER\n");
          printf("node:          NODEVPLACEHOLDER\n");
          printf("libbrotli1:    BROTLIVPLACEHOLDER\n");
          printf("\nHTTP/2:      curl --http2-prior-knowledge -I http://<host>/\n");
          printf("Brotli demo: POST http://<host>:${var.demo_port}/inflate with Content-Encoding: br\n");
          PHPEOF
              sed -i "s|SCENPLACEHOLDER|$SCENARIOS|" /var/www/html/index.php
              sed -i "s|PHPPINPLACEHOLDER|$PHP_VER|" /var/www/html/index.php
              sed -i "s|APKGVPLACEHOLDER|$APACHE_PKG_VER|" /var/www/html/index.php
              sed -i "s|MODH2PLACEHOLDER|$MOD_H2|" /var/www/html/index.php
              sed -i "s|NODEVPLACEHOLDER|$NODE_V|" /var/www/html/index.php
              sed -i "s|BROTLIVPLACEHOLDER|$BROTLI_V|" /var/www/html/index.php
            else
          cat > /var/www/html/index.html <<'HTMLEOF'
          <!doctype html>
          <html lang="en">
          <head>
          <meta charset="utf-8">
          <title>CVE-2026-119618 test host</title>
          </head>
          <body>
          <h1>CVE-2026-119618 test host</h1>
          <p>
            Apache HTTP Server with <code>mod_http2</code> held at a build affected by CVE-2026-119618
            (improper synchronization in <code>assign_headers()</code>, remote code execution; fixed in 2.4.71).
          </p>
          <ul>
            <li>scenarios: SCENPLACEHOLDER</li>
            <li>dpkg <code>apache2-bin</code>: APKGVPLACEHOLDER</li>
            <li>httpd: HTTPDPLACEHOLDER</li>
            <li><code>mod_http2</code>: MODH2PLACEHOLDER</li>
            <li>Protocols: h2c http/1.1 (cleartext HTTP/2 on port 80)</li>
          </ul>
          <p>
            Check it: <code>curl --http2-prior-knowledge -I http://this-host/</code>
            (the <code>Server</code> header and HTTP/2 response confirm the module is in the path).
          </p>
          </body>
          </html>
          HTMLEOF
              HTTPD_V=$(apache2 -v 2>/dev/null | sed -n 's/^Server version: //p' | head -1)
              sed -i "s|SCENPLACEHOLDER|$SCENARIOS|" /var/www/html/index.html
              sed -i "s|APKGVPLACEHOLDER|$APACHE_PKG_VER|" /var/www/html/index.html
              sed -i "s|HTTPDPLACEHOLDER|$HTTPD_V|" /var/www/html/index.html
              sed -i "s|MODH2PLACEHOLDER|$MOD_H2|" /var/www/html/index.html
            fi
            systemctl restart apache2
          fi

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

          # Build report: cat /var/log/vuln-report.txt (sections for scenarios that are not enabled stay empty)
          {
            echo "== scenarios enabled: $SCENARIOS"
            echo
            echo "== dpkg"
            dpkg -l | grep -E '^(ii|hi)\s+(apache2|php8|nodejs|libnode|libbrotli|brotli)' || true
            echo
            echo "== httpd"
            apache2 -v 2>/dev/null || true
            echo
            echo "== mod_http2"
            a2query -m http2 2>/dev/null || true
            echo
            echo "== php"
            php -v 2>/dev/null | head -1 || true
            echo
            echo "== node / brotli"
            node --version 2>/dev/null || true
            dpkg-query -W -f='$${Version}\n' libbrotli1 2>/dev/null || true
            echo
            echo "== pins (vulnerable builds)"
            echo "apache2-bin  $APACHE_VER   (CVE-2026-119618 range 2.4.55-2.4.70; fixes: Debian 2.4.71-1~deb13u1 / DSA-6620-1, Ubuntu 2.4.66-2ubuntu2.8 / USN-9090-1)"
            echo "php          $PHP_VER       (CVE-2026-109618/109619; PHP must be <= 8.5.11)"
            echo "node/brotli  nodejs=$NODE_VER libbrotli1/brotli=$BROTLI_VER   (CVE-2026-111497; Debian fix 1.1.0-2+deb13u1, Ubuntu fix 1.2.0-3ubuntu0.1)"
            echo
            echo "== holds"
            apt-mark showhold
            echo
            echo "== checks"
            echo "curl --http2-prior-knowledge -I http://<host>/          (when cve-2026-119618 is enabled)"
            echo "curl -X POST --data-binary @payload.br -H 'Content-Encoding: br' http://<host>:$DEMO_PORT/inflate   (when broccoli2shell is enabled)"
          } > /var/log/vuln-report.txt
    runcmd:
      - [ bash, -c, "/usr/local/sbin/install-vulns.sh > /var/log/install-vulns.log 2>&1" ]
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
  description = "SSH, HTTP and Brotli demo port inbound"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_source_cidr]
  }

  # Port 80 only when Apache is part of the deployment (php2shell and/or cve-2026-119618)
  dynamic "ingress" {
    for_each = local.do_apache ? [1] : []
    content {
      description = "HTTP (PHP / mod_http2 h2c)"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  # Demo port only when the broccoli2shell scenario is enabled (node2shell does not listen otherwise)
  dynamic "ingress" {
    for_each = local.do_brotli ? [1] : []
    content {
      description = "Brotli demo service"
      from_port   = var.demo_port
      to_port     = var.demo_port
      protocol    = "tcp"
      cidr_blocks = [var.admin_source_cidr]
    }
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

  primary_network_interface {
    network_interface_id = aws_network_interface.lnxnic.id
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

output "scenarios" {
  description = "Vulnerabilities installed on this host"
  value       = var.scenarios
}

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
  description = "Version-reporting page (needs a php or cve-2026-119618 scenario). HTTP/2 with: curl --http2-prior-knowledge -I <url>"
  value       = local.do_apache ? "http://${aws_eip.lnxpip.public_ip}/${local.do_php ? "index.php" : "index.html"}" : ""
}

output "demo_url" {
  description = "Version page of the Brotli demo service (needs the broccoli2shell scenario)"
  value       = local.do_brotli ? "http://${aws_eip.lnxpip.public_ip}:${var.demo_port}/" : ""
}

output "verify_command" {
  description = "Read the build report left by the cloud-init script (available once cloud-init has finished)"
  value       = "ssh -i <private key> ${local.image.ssh_user}@${aws_eip.lnxpip.public_ip} 'cat /var/log/vuln-report.txt'"
}

output "forticnapp_agent_installed" {
  value = var.install_forticnapp_agent
}
