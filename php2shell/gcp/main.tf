##############################################################################################################
#
# Ubuntu / Debian instance with a pinned PHP version (OS image selectable via terraform.tfvars)
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
  description = "Available OS images (Compute Engine image families). Pick one with os_image. Add entries to support more images."
  type = list(object({
    name        = string # key used in os_image
    family      = string # "ubuntu" or "debian"
    image       = string # image or image family, e.g. ubuntu-os-cloud/ubuntu-2604-lts-amd64
    php_series  = string # PHP major.minor shipped by this image, e.g. "8.5"
    php_version = string # default exact package version to pin for this image
  }))
  default = [
    {
      name        = "ubuntu-26.04"
      family      = "ubuntu"
      image       = "ubuntu-os-cloud/ubuntu-2604-lts-amd64"
      php_series  = "8.5"
      php_version = "8.5.4-0ubuntu1.5" # Must be 8.5.11 or below
    },
    {
      name        = "debian-13"
      family      = "debian"
      image       = "debian-cloud/debian-13"
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
    project = "php-vm"
  }
}

##############################################################################################################
# Startup script
# The startup script metadata is used instead of cloud-init so that Debian and Ubuntu images are handled the same way.
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
    exec > /var/log/install-php.log 2>&1

    # The startup script runs at every boot, only install once
    [ -f /var/lib/install-php.done ] && exit 0

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

    ${local.forticnapp_install_script}

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

    touch /var/lib/install-php.done
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

resource "google_compute_firewall" "lnxwebin" {
  name          = "${var.prefix}-allow-web"
  network       = google_compute_network.vpc.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["${var.prefix}-lnx"]

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
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

output "http_url" {
  description = "URL of the version-reporting page"
  value       = "http://${google_compute_address.lnxpip.address}/index.php"
}

output "verify_command" {
  description = "Read the build report left by the startup script (available once it has finished)"
  value       = "ssh ${var.username}@${google_compute_address.lnxpip.address} 'cat /var/log/php-report.txt'"
}

output "forticnapp_agent_installed" {
  value = var.install_forticnapp_agent
}
