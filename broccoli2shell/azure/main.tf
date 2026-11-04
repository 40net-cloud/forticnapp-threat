##############################################################################################################
#
# Ubuntu / Debian VM (OS image selectable via terraform.tfvars) with Node.js and Brotli pinned to affected builds (CVE-2026-111497, Node2Shell)
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
  description = "Available OS images. Pick one with os_image. Add entries to support more images."
  type = list(object({
    name               = string # key used in os_image
    family             = string # "ubuntu" or "debian"
    publisher          = string
    offer              = string
    sku                = string
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
      publisher = "Canonical"
      offer     = "ubuntu-26_04-lts"
      sku       = "server"
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
      publisher          = "debian"
      offer              = "debian-13"
      sku                = "13-gen2"
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
    project = "node-vm"
  }
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

resource "azurerm_network_security_rule" "lnxnsgallowdemoin" {
  name                        = "AllowDemoInbound"
  resource_group_name         = azurerm_resource_group.resourcegroup.name
  network_security_group_name = azurerm_network_security_group.lnxnsg.name
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = tostring(var.demo_port)
  source_address_prefix       = var.admin_source_cidr
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

output "demo_url" {
  description = "Version page of the Brotli demo service"
  value       = "http://${azurerm_public_ip.lnxpip.fqdn}:${var.demo_port}/"
}

output "verify_command" {
  description = "Read the build report left by the cloud-init script (available once cloud-init has finished)"
  value       = "ssh ${var.username}@${azurerm_public_ip.lnxpip.fqdn} 'cat /var/log/node-report.txt'"
}
