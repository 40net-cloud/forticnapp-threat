# FortiCNAPP threat demo

Terraform deployment templates that build intentionally vulnerable Linux hosts in AWS, Microsoft Azure and Google Cloud, plus helper scripts to find them again in FortiCNAPP. They are meant for demos and detection testing of the [FortiCNAPP](https://www.fortinet.com/products/cloud-native-application-protection-platform) Linux agent and its vulnerability management.

**WARNING:** These templates deploy software with known, exploitable vulnerabilities and expose it to the internet. Only use them in a dedicated, disposable account, subscription or project, restrict access with `admin_source_cidr`, and destroy the environment when you are done.

## Deployment

Each scenario is available as a separate Terraform template per cloud. All of them deploy a single Linux VM in a new network, selectable between Ubuntu 26.04 and Debian 13 (`os_image`), and can optionally install the FortiCNAPP Linux agent (`install_forticnapp_agent`).

| Scenario | Vulnerability | AWS | Azure | Google Cloud |
|----------|---------------|:---:|:-----:|:------------:|
| [php2shell](php2shell) | PHP2Shell, CVE-2026-109618 / CVE-2026-109619 | YES | YES | YES |
| [broccoli2shell](broccoli2shell) | Node2Shell (Brotli), CVE-2026-111497 | YES | YES | YES |

### Vulnerabilities

- **[php2shell](php2shell)**

  A VM with Apache and `mod_php` where PHP is installed and held at a vulnerable build. The version is pinned per OS image (PHP 8.5 on Ubuntu 26.04, PHP 8.4 on Debian 13) and can be overridden with `php_version`. On Debian the pinned build is fetched from `snapshot.debian.org`. A small `index.php` reports the running PHP version. A build report is written to `/var/log/php-report.txt`.

- **[broccoli2shell](broccoli2shell)**

  A VM with Node.js and Brotli (`libbrotli1`, `brotli`) held at affected builds, plus a small systemd service (`node2shell`) that Brotli-decompresses request bodies on `demo_port` (default 3000). Access to SSH and the demo port is limited to `admin_source_cidr`. A build report is written to `/var/log/node-report.txt`.

### Select your cloud

Every template folder is organized as `<scenario>/<cloud>`, with `aws`, `azure` and `gcp` as cloud names. Each of these contains:

| File | Purpose |
|------|---------|
| `main.tf` | The complete Terraform template (network, VM and cloud-init) |
| `terraform.tfvars.example` | Annotated example variables, copy it to `terraform.tfvars` |

### Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) 1.5 or later
- Credentials for the target cloud, using its standard mechanism (AWS environment variables, shared config or SSO; `az login`; `gcloud auth`)
- AWS only: an existing EC2 key pair (`key_name`)
- Azure only: a subscription ID (`subscription_id`) and an SSH public key (`ssh_public_key_file`, default `~/.ssh/id_rsa.pub`)
- Optional: a FortiCNAPP agent access token to install the agent

### Deployment

```bash
cd php2shell/aws        # or any <scenario>/<cloud> folder
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars
terraform init
terraform apply
```

The outputs show the public IP address, the SSH command, the URL of the test page and a `verify_command` that prints the build report. The report is only available once cloud-init has finished, which can take a few minutes.

To remove everything:

```bash
terraform destroy
```

### Common variables

| Variable | Description |
|----------|-------------|
| `prefix` | Name added to every deployed resource |
| `admin_source_cidr` | Source address allowed to reach SSH and the exposed service. Restrict it to your own public IP, for example `203.0.113.10/32` |
| `os_image` | `ubuntu-26.04` or `debian-13` (default `debian-13`). More images can be added to `os_images` in `main.tf` |
| `install_forticnapp_agent` | Install the FortiCNAPP Linux agent from the `packages.lacework.net` APT repository (amd64 and arm64 only) |
| `forticnapp_access_token` | Agent access token, required when the agent is installed. Prefer `export TF_VAR_forticnapp_access_token=<token>` over writing it to a file |
| `forticnapp_server_url` | FortiCNAPP server URL for your region (default `https://api.fra.lacework.net`). Empty means auto-discover |

Network ranges, VM sizes, tags and the pinned package versions have defaults and are documented in `terraform.tfvars.example`.

## Support

Fortinet-provided scripts and templates in this repository are not officially supported by Fortinet Technical Support. They are provided as-is, without any warranty. Use the [issue tracker](https://github.com/40net-cloud/forticnapp-threat/issues) to report problems or request improvements.

---

*Intentionally vulnerable. Deploy responsibly.*
