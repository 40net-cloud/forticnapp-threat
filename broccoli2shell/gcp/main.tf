##############################################################################################################
#
# Ubuntu / Debian instance (OS image selectable via terraform.tfvars) with Node.js and Brotli pinned to affected builds (CVE-2026-111497, Node2Shell)
# Terraform deployment template for Google Cloud
#
##############################################################################################################

##############################################################################################################
# General
##############################################################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

# Credentials are taken from Application Default Credentials (gcloud auth application-default login)
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# Prefix for all resources created for this deployment in Google Cloud
variable "prefix" {
  description = "Added name to each deployed resource (lowercase letters, digits and hyphens)"
}

variable "project_id" {
  description = "Google Cloud project ID"
}

variable "region" {
  description = "Google Cloud region"
  default     = "europe-west1"
}

variable "zone" {
  description = "Google Cloud zone"
  default     = "europe-west1-b"
}

variable "username" {
  description = "Administrator username created from the SSH public key"
  default     = "admin"
}

variable "ssh_public_key_file" {
  description = "Path to the SSH public key used for the administrator account"
  default     = "~/.ssh/id_rsa.pub"
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
    image              = string # image or image family, e.g. ubuntu-os-cloud/ubuntu-2604-lts-amd64
    node_version       = string # default exact nodejs/libnode build to pin for this image
    libnode_pkg        = string # libnode package name matching the nodejs build
    brotli_version     = string # default exact libbrotli1/brotli build to pin for this image (vulnerable)
    snapshot_url       = string # APT line (without "deb [..]") of the snapshot archive that still carries the pinned builds, %s = timestamp
    snapshot_timestamp = string
  }))
  default = [
    {
      name   = "ubuntu-26.04"
      family = "ubuntu"
      image  = "ubuntu-os-cloud/ubuntu-2604-lts-amd64"
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
      image              = "debian-cloud/debian-13"
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

variable "subnet" {
  default = "172.16.140.0/25"
}

variable "machine_type" {
  default = "e2-small"
}

variable "labels" {
  type = map(string)
  default = {
    project = "node-vm"
  }
}

##############################################################################################################
# Startup script
# The startup script metadata is used instead of cloud-init so that Debian and Ubuntu images are handled the same way.
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

  # Agent install snippet. Kept in its own heredoc without template directives: a %{if} inside the startup
  # script heredoc would disable the <<- indentation stripping and break the shell heredoc terminators.
  forticnapp_install_snippet = <<-EOT
    # Agent config (no cloud-init on Google Cloud images, so it is written here before the package is installed)
    install -d -m 0755 /var/lib/lacework/config
    install -m 0600 /dev/null /var/lib/lacework/config/config.json
    cat > /var/lib/lacework/config/config.json <<'LWEOF'
    ${local.forticnapp_config}
    LWEOF

    # FortiCNAPP agent from the packages.lacework.net APT repository (config.json is written above).
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
  EOT

  forticnapp_install_script = var.install_forticnapp_agent ? local.forticnapp_install_snippet : ""

  startup_script = <<-EOT
    #!/bin/bash
    set -euo pipefail
    exec > /var/log/install-node.log 2>&1

    # The startup script runs at every boot, only install once
    [ -f /var/lib/install-node.done ] && exit 0

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

    ${local.forticnapp_install_script}

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

    touch /var/lib/install-node.done
  EOT
}

##############################################################################################################
# Network
##############################################################################################################

resource "google_compute_network" "vpc" {
  name                    = "${var.prefix}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${var.prefix}-subnet"
  region        = var.region
  network       = google_compute_network.vpc.id
  ip_cidr_range = var.subnet
}

resource "google_compute_firewall" "lnxsshin" {
  name          = "${var.prefix}-allow-ssh"
  network       = google_compute_network.vpc.name
  direction     = "INGRESS"
  source_ranges = [var.admin_source_cidr]
  target_tags   = ["${var.prefix}-lnx"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "lnxdemoin" {
  name          = "${var.prefix}-allow-demo"
  network       = google_compute_network.vpc.name
  direction     = "INGRESS"
  source_ranges = [var.admin_source_cidr]
  target_tags   = ["${var.prefix}-lnx"]

  allow {
    protocol = "tcp"
    ports    = [tostring(var.demo_port)]
  }
}

##############################################################################################################
# Linux VM
##############################################################################################################

resource "google_compute_address" "lnxpip" {
  name   = "${var.prefix}-lnx-pip"
  region = var.region
}

resource "google_compute_instance" "lnxvm" {
  name         = "${var.prefix}-lnx-vm"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["${var.prefix}-lnx"]
  labels       = var.labels

  boot_disk {
    initialize_params {
      image = local.image.image
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet.id

    access_config {
      nat_ip = google_compute_address.lnxpip.address
    }
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    ssh-keys               = "${var.username}:${trimspace(file(pathexpand(var.ssh_public_key_file)))}"
    block-project-ssh-keys = "true"
    # The instance setting overrides a project-wide enable-oslogin=TRUE, so the ssh-keys above are honoured
    enable-oslogin = "FALSE"
  }

  metadata_startup_script = local.startup_script

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

##############################################################################################################
# Output
##############################################################################################################

output "lnx_public_ip_address" {
  value = google_compute_address.lnxpip.address
}

output "lnx_private_ip_address" {
  value = google_compute_instance.lnxvm.network_interface[0].network_ip
}

output "lnx_ssh" {
  value = "ssh ${var.username}@${google_compute_address.lnxpip.address}"
}

output "demo_url" {
  description = "Version page of the Brotli demo service"
  value       = "http://${google_compute_address.lnxpip.address}:${var.demo_port}/"
}

output "verify_command" {
  description = "Read the build report left by the startup script (available once it has finished)"
  value       = "ssh ${var.username}@${google_compute_address.lnxpip.address} 'cat /var/log/node-report.txt'"
}

output "forticnapp_agent_installed" {
  value = var.install_forticnapp_agent
}
