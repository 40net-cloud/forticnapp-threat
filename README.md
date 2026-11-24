# FortiCNAPP threat demo

Terraform deployment templates that build intentionally vulnerable Linux hosts in AWS, Microsoft Azure and Google Cloud, plus helper scripts to find them again in FortiCNAPP. They are meant for demos and detection testing of the [FortiCNAPP](https://www.fortinet.com/products/cloud-native-application-protection-platform) Linux agent and its vulnerability management.

**WARNING:** These templates deploy software with known, exploitable vulnerabilities and expose it to the internet. Only use them in a dedicated, disposable account, subscription or project, restrict access with `admin_source_cidr`, and destroy the environment when you are done.

## Deployment

Each scenario is available as a separate Terraform template per cloud. All of them deploy a single Linux VM in a new network, selectable between Ubuntu 26.04 and Debian 13 (`os_image`), and can optionally install the FortiCNAPP Linux agent (`install_forticnapp_agent`).

| Scenario | Vulnerability | AWS | Azure | Google Cloud |
|----------|---------------|:---:|:-----:|:------------:|
| [php2shell](php2shell) | PHP2Shell, CVE-2026-109618 / CVE-2026-109619 | YES | YES | YES |
| [broccoli2shell](broccoli2shell) | Node2Shell (Brotli), CVE-2026-111497 | YES | YES | YES |
| [cve-2026-119618](cve-2026-119618) | Apache HTTP/2 RCE (mod_http2), CVE-2026-119618 | YES | YES | YES |
| [vulnerable-vm](vulnerable-vm) | All scenarios on one host: CVE-2026-109618/109619, CVE-2026-111497, CVE-2026-119618 | YES | YES | YES |

### Vulnerabilities

- **[php2shell](php2shell)**

  A VM with Apache and `mod_php` where PHP is installed and held at a vulnerable build. The version is pinned per OS image (PHP 8.5 on Ubuntu 26.04, PHP 8.4 on Debian 13) and can be overridden with `php_version`. On Debian the pinned build is fetched from `snapshot.debian.org`. A small `index.php` reports the running PHP version. A build report is written to `/var/log/php-report.txt`.

- **[broccoli2shell](broccoli2shell)**

  A VM with Node.js and Brotli (`libbrotli1`, `brotli`) held at affected builds, plus a small systemd service (`node2shell`) that Brotli-decompresses request bodies on `demo_port` (default 3000). Access to SSH and the demo port is limited to `admin_source_cidr`. A build report is written to `/var/log/node-report.txt`.

- **[cve-2026-119618](cve-2026-119618)**

  A VM with Apache HTTP Server held at a build affected by CVE-2026-119618 (race condition in `mod_http2`'s `assign_headers()`, remote code execution; affects 2.4.55 through 2.4.70, fixed in 2.4.71). The version is pinned per OS image (Apache 2.4.69 on Debian 13, Apache 2.4.66 on Ubuntu 26.04) and can be overridden with `apache_version`; the pinned build is fetched from a pre-fix snapshot of the distribution archive (`snapshot.debian.org/archive/debian-security` on Debian, `snapshot.ubuntu.com` on Ubuntu), because both distributions shipped fixes on 2026-11-12 (DSA-6620-1 and USN-9090-1). `mod_http2` is enabled and the default site serves cleartext HTTP/2 (`h2c`) on port 80, so demo requests actually traverse the vulnerable module: `curl --http2-prior-knowledge -I http://<host>/`. A small `index.html` reports the running version. A build report is written to `/var/log/apache-report.txt`.

- **[vulnerable-vm](vulnerable-vm)**

  One host carrying every vulnerability: the combined form of the three scenarios above, chosen with the `scenarios` list variable (`["php2shell", "broccoli2shell", "cve-2026-119618"]`, all enabled by default; remove entries to isolate a single vulnerability — the matching firewall ports are only opened then). The install script runs the scenario steps sequentially: Apache once (held at the mod_http2-vulnerable build) with pinned `mod_php` on top, then Node.js and Brotli at the affected builds with the demo service on `demo_port`, then `mod_http2` enabled with `h2c` on port 80. All pins and snapshot sources are identical to the per-CVE templates. One version page reports everything (`index.php` when `php2shell` is enabled, otherwise `index.html`) and one build report is written to `/var/log/vuln-report.txt`.

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
| `state_backend` | `local` (default) or `s3`. Terraform cannot use variables in a backend block, so run `scripts/configure-state-backend.sh` after changing it, then `terraform init -reconfigure` (or `-migrate-state`). `state_bucket` and `state_key` are optional |
| `scenarios` | vulnerable-vm only: which vulnerabilities to install on the one host (default: all three). Remove entries to isolate |
| `install_forticnapp_agent` | Install the FortiCNAPP Linux agent from the `packages.lacework.net` APT repository (amd64 and arm64 only) |
| `forticnapp_access_token` | Agent access token, required when the agent is installed. Prefer `export TF_VAR_forticnapp_access_token=<token>` over writing it to a file |
| `forticnapp_server_url` | FortiCNAPP server URL for your region (default `https://api.fra.lacework.net`). Empty means auto-discover |

Network ranges, VM sizes, tags and the pinned package versions have defaults and are documented in `terraform.tfvars.example`.

## Deploy with GitHub Actions (AWS)

The workflow [`deploy-vulnerable-vm-aws.yml`](.github/workflows/deploy-vulnerable-vm-aws.yml) deploys `vulnerable-vm/aws` and is started manually (Actions tab, *Run workflow*). Choose `plan`, `apply` or `destroy`, the resource name prefix (default `multi-cve`), the OS image, the allowed source CIDR and whether to install the FortiCNAPP agent.

The workflow authenticates to AWS with OpenID Connect (OIDC): GitHub issues a short-lived token per run and AWS exchanges it for temporary credentials, so no access keys are stored in GitHub.

### Setup

**In AWS** (once per account; replace `<ACCOUNT_ID>`, `<ORG>/<REPO>` and `<REGION>`):

1. Create the state bucket: `scripts/create-tfstate-bucket.sh <REGION>`.
2. Create the GitHub OIDC identity provider (skip if the account already has one for `token.actions.githubusercontent.com`):

   ```sh
   aws iam create-open-id-connect-provider \
     --url https://token.actions.githubusercontent.com \
     --client-id-list sts.amazonaws.com
   ```

3. Create the IAM role the workflow assumes. The trust policy only accepts runs of this repository that use the `aws-vulnerable-vm` environment:

   ```sh
   cat > trust.json <<'JSON'
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {"Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"},
       "Action": "sts:AssumeRoleWithWebIdentity",
       "Condition": {
         "StringEquals": {
           "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
           "token.actions.githubusercontent.com:sub": "repo:<ORG>/<REPO>:environment:aws-vulnerable-vm"
         }
       }
     }]
   }
   JSON
   aws iam create-role --role-name github-actions-vulnerable-vm \
     --assume-role-policy-document file://trust.json
   ```

4. Give the role permission to manage the EC2/VPC resources and to use the state bucket:

   ```sh
   cat > permissions.json <<'JSON'
   {
     "Version": "2012-10-17",
     "Statement": [
       {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"},
       {"Effect": "Allow", "Action": "s3:ListBucket",
        "Resource": "arn:aws:s3:::multi-cve-tfstate-<ACCOUNT_ID>-<REGION>"},
       {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        "Resource": "arn:aws:s3:::multi-cve-tfstate-<ACCOUNT_ID>-<REGION>/*"}
     ]
   }
   JSON
   aws iam put-role-policy --role-name github-actions-vulnerable-vm \
     --policy-name vulnerable-vm --policy-document file://permissions.json
   ```

5. Make sure an EC2 key pair exists in the target region (`aws ec2 create-key-pair` or import your public key) and note its name.

**In GitHub** (repository Settings):

1. Environments: create `aws-vulnerable-vm`. Optionally add required reviewers so `apply` and `destroy` need approval. The environment name must match the `sub` condition in the trust policy.
2. Secrets and variables, Actions: add these repository secrets:

| Secret | Description |
|--------|-------------|
| `AWS_ROLE_ARN` | ARN of the role from step 3, for example `arn:aws:iam::<ACCOUNT_ID>:role/github-actions-vulnerable-vm` |
| `AWS_REGION` | Region to deploy into, for example `eu-west-1` |
| `AWS_ACCOUNT_ID` | Target account ID, used for the state bucket name. The run aborts if the role belongs to another account |
| `AWS_KEY_NAME` | Name of the EC2 key pair from step 5 |
| `FORTICNAPP_ACCESS_TOKEN` | Optional, only when installing the agent |

3. Actions tab, *Deploy vulnerable-vm (AWS)*, *Run workflow*: start with `plan`, then `apply`.

Terraform state is kept in an S3 bucket named `multi-cve-tfstate-<account>-<region>`, so `destroy` works from a later run. The bucket is created in AWS setup step 1 by `scripts/create-tfstate-bucket.sh`, which enables versioning, encryption and blocks public access, and is safe to re-run. The workflow's `state_backend` input selects `s3` (default) or `local`; local state is lost when the runner ends. 

## Support

Fortinet-provided scripts and templates in this repository are not officially supported by Fortinet Technical Support. They are provided as-is, without any warranty. Use the [issue tracker](https://github.com/40net-cloud/forticnapp-threat/issues) to report problems or request improvements.

---

*Intentionally vulnerable. Deploy responsibly.*
