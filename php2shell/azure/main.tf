##############################################################################################################
#
# Ubuntu / Debian VM with a pinned PHP version (OS image selectable via terraform.tfvars)
# Terraform deployment template for Microsoft Azure
#
##############################################################################################################

##############################################################################################################
# General
##############################################################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# Prefix for all resources created for this deployment in Microsoft Azure
variable "prefix" {
  description = "Added name to each deployed resource"
}

variable "location" {
  description = "Azure region"
  default     = "westeurope"
}

variable "subscription_id" {
  description = "Azure subscription ID"
}

variable "username" {
  description = "Administrator username of the VM"
  default     = "azureuser"
}

variable "ssh_public_key_file" {
  description = "Path to the SSH public key used for the administrator account"
  default     = "~/.ssh/id_rsa.pub"
}

variable "admin_source_cidr" {
  description = "Source address prefix allowed to reach SSH (22). Restrict this to your own public IP/CIDR."
  default     = "*"
}

##############################################################################################################
# OS image selection
##############################################################################################################

variable "os_images" {
  description = "Available OS images (Azure marketplace SKUs). Pick one with os_image. Add entries to support more images."
  type = list(object({
    name        = string # key used in os_image
    family      = string # "ubuntu" or "debian"
    publisher   = string
    offer       = string
    sku         = string
    php_series  = string # PHP major.minor shipped by this image, e.g. "8.5"
    php_version = string # default exact package version to pin for this image
  }))
  default = [
    {
      name        = "ubuntu-26.04"
      family      = "ubuntu"
      publisher   = "Canonical"
      offer       = "ubuntu-26_04-lts"
      sku         = "server"
      php_series  = "8.5"
      php_version = "8.5.4-0ubuntu1.5" # Must be 8.5.11 or below
    },
    {
      name        = "debian-13"
      family      = "debian"
      publisher   = "debian"
      offer       = "debian-13"
      sku         = "13-gen2"
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
# PHP / Apache settings
##############################################################################################################

variable "install_apache" {
  description = "Install Apache and the Apache PHP module (libapache2-mod-phpX.Y)"
  type        = bool
  default     = true
}

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
# Network and VM
##############################################################################################################

variable "vnet" {
  default = "172.16.140.0/24"
}

variable "subnet" {
  default = "172.16.140.0/25"
}

variable "vm_size" {
  default = "Standard_B2s"
}

variable "tags" {
  type = map(string)
  default = {
    project = "php-vm"
  }
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
    var.install_apache ? ["libapache2-mod-php${local.php_series}"] : []
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

          %{~if var.install_apache~}
          $APT install apache2
          %{~endif~}

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

          %{~if var.install_apache~}
          # Serve PHP and expose the running version for quick checks
          a2enmod php${local.php_series} || true
          systemctl restart apache2
          cat > /var/www/html/index.php <<'PHPEOF'
          <?php
          header('Content-Type: text/plain');
          printf("PHP2Shell test host\nPHP version: %s\n", PHP_VERSION);
          PHPEOF
          %{~endif~}

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
            dpkg -l | grep -E 'php${replace(local.php_series, ".", "\\.")}|libapache2-mod-php'  || true
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
# Resource Group
##############################################################################################################

resource "azurerm_resource_group" "resourcegroup" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags     = var.tags
}

resource "azurerm_virtual_network" "vnet" {
  name                = "${var.prefix}-vnet"
  address_space       = [var.vnet]
  location            = azurerm_resource_group.resourcegroup.location
  resource_group_name = azurerm_resource_group.resourcegroup.name
  tags                = var.tags
}

resource "azurerm_subnet" "subnet" {
  name                 = "${var.prefix}-subnet"
  resource_group_name  = azurerm_resource_group.resourcegroup.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.subnet]
}

##############################################################################################################
# Linux VM
##############################################################################################################

resource "azurerm_network_security_group" "lnxnsg" {
  name                = "${var.prefix}-lnx-nsg"
  location            = var.location
  resource_group_name = azurerm_resource_group.resourcegroup.name
  tags                = var.tags
}

resource "azurerm_network_security_rule" "lnxnsgallowsshin" {
  name                        = "AllowSSHInbound"
  resource_group_name         = azurerm_resource_group.resourcegroup.name
  network_security_group_name = azurerm_network_security_group.lnxnsg.name
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.admin_source_cidr
  destination_address_prefix  = "*"
}

resource "azurerm_network_security_rule" "lnxnsgallowhttpin" {
  name                        = "AllowHTTPInbound"
  resource_group_name         = azurerm_resource_group.resourcegroup.name
  network_security_group_name = azurerm_network_security_group.lnxnsg.name
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "80"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
}

resource "azurerm_network_security_rule" "lnxnsgallowhttpsin" {
  name                        = "AllowHTTPSInbound"
  resource_group_name         = azurerm_resource_group.resourcegroup.name
  network_security_group_name = azurerm_network_security_group.lnxnsg.name
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
}

resource "azurerm_public_ip" "lnxpip" {
  name                = "${var.prefix}-lnx-pip"
  location            = var.location
  resource_group_name = azurerm_resource_group.resourcegroup.name
  allocation_method   = "Static"
  sku                 = "Standard"
  domain_name_label   = format("%s-%s", lower(var.prefix), "lnx-pip")
  tags                = var.tags
}

resource "azurerm_network_interface" "lnxifc" {
  name                           = "${var.prefix}-lnx-nic"
  location                       = azurerm_resource_group.resourcegroup.location
  resource_group_name            = azurerm_resource_group.resourcegroup.name
  accelerated_networking_enabled = false
  tags                           = var.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.lnxpip.id
  }
}

resource "azurerm_network_interface_security_group_association" "lnxnsg" {
  network_interface_id      = azurerm_network_interface.lnxifc.id
  network_security_group_id = azurerm_network_security_group.lnxnsg.id
}

resource "azurerm_linux_virtual_machine" "lnxvm" {
  name                  = "${var.prefix}-lnx-vm"
  location              = azurerm_resource_group.resourcegroup.location
  resource_group_name   = azurerm_resource_group.resourcegroup.name
  network_interface_ids = [azurerm_network_interface.lnxifc.id]
  size                  = var.vm_size

  identity {
    type = "SystemAssigned"
  }

  source_image_reference {
    publisher = local.image.publisher
    offer     = local.image.offer
    sku       = local.image.sku
    version   = "latest"
  }

  os_disk {
    name                 = "${var.prefix}-lnx-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  admin_username                  = var.username
  disable_password_authentication = true
  custom_data                     = base64encode(local.customdata)

  admin_ssh_key {
    username   = var.username
    public_key = file(pathexpand(var.ssh_public_key_file))
  }

  tags = var.tags

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

output "resource_group_name" {
  description = "Resource group holding the test host. Delete it to remove everything."
  value       = azurerm_resource_group.resourcegroup.name
}

output "lnx_public_ip_address" {
  value = azurerm_public_ip.lnxpip.ip_address
}

output "lnx_fqdn" {
  value = azurerm_public_ip.lnxpip.fqdn
}

output "lnx_private_ip_address" {
  value = azurerm_network_interface.lnxifc.private_ip_address
}

output "forticnapp_agent_installed" {
  value = var.install_forticnapp_agent
}

output "lnx_ssh" {
  value = "ssh ${var.username}@${azurerm_public_ip.lnxpip.fqdn}"
}

output "http_url" {
  description = "URL of the version-reporting page"
  value       = "http://${azurerm_public_ip.lnxpip.fqdn}/index.php"
}

output "verify_command" {
  description = "Read the build report left by the cloud-init script (available once cloud-init has finished)"
  value       = "ssh ${var.username}@${azurerm_public_ip.lnxpip.fqdn} 'cat /var/log/php-report.txt'"
}
