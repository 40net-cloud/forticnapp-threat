# FortiCNAPP threat demo

A Terraform deployment template that builds one intentionally vulnerable Linux host in AWS, Microsoft Azure or Google Cloud, plus helper scripts to find it again in FortiCNAPP. It is meant for demos and detection testing of the [FortiCNAPP](https://www.fortinet.com/products/cloud-native-application-protection-platform) Linux agent and its vulnerability management.

**WARNING:** This template deploys software with known, exploitable vulnerabilities and exposes it to the internet. Only use it in a dedicated, disposable account, subscription or project, restrict access with `admin_source_cidr`, and destroy the environment when you are done.

## Deployment

The single template [`vulnerable-vm`](vulnerable-vm) deploys one Linux VM in a new network on AWS, Microsoft Azure or Google Cloud. The VM is selectable between Ubuntu 26.04 and Debian 13 (`os_image`) and can optionally install the FortiCNAPP Linux agent (`install_forticnapp_agent`). It carries every vulnerability below; the `scenarios` list variable chooses which ones are installed (all enabled by default; remove entries to isolate a single vulnerability, the matching firewall ports are only opened then).

| Scenario | Vulnerability | AWS | Azure | Google Cloud |
|----------|---------------|:---:|:-----:|:------------:|
| `php2shell` | PHP2Shell, CVE-2026-109618 / CVE-2026-109619 | YES | YES | YES |
| `broccoli2shell` | Node2Shell (Brotli), CVE-2026-111497 | YES | YES | YES |
| `cve-2026-119618` | Apache HTTP/2 RCE (mod_http2), CVE-2026-119618 | YES | YES | YES |
| `cve-2026-114938` | Java4Shell (OpenJDK Base64 decoder), CVE-2026-114938 | YES | YES | YES |

The install script runs the scenario steps sequentially: Apache once (held at the mod_http2-vulnerable build) with pinned `mod_php` on top, then Node.js and Brotli at the affected builds with the demo service on `demo_port`, then `mod_http2` enabled with `h2c` on port 80, then OpenJDK 21 at the affected build with the demo service on `java_port`. One version page reports PHP/Apache/Node (`index.php` when `php2shell` is enabled, otherwise `index.html`), the Java service has its own version page, and one build report is written to `/var/log/vuln-report.txt`.

### Vulnerabilities

- **`php2shell`**

  Apache with `mod_php` where PHP is installed and held at a vulnerable build. The version is pinned per OS image (PHP 8.5 on Ubuntu 26.04, PHP 8.4 on Debian 13) and can be overridden with `php_version`. On Debian the pinned build is fetched from `snapshot.debian.org`. When this scenario is enabled, a small `index.php` reports the running versions.

- **`broccoli2shell`**

  Node.js and Brotli (`libbrotli1`, `brotli`) held at affected builds, plus a small systemd service (`node2shell`) that Brotli-decompresses request bodies on `demo_port` (default 3000). Access to SSH and the demo port is limited to `admin_source_cidr`.

- **`cve-2026-119618`**

  Apache HTTP Server held at a build affected by CVE-2026-119618 (race condition in `mod_http2`'s `assign_headers()`, remote code execution; affects 2.4.55 through 2.4.70, fixed in 2.4.71). The version is pinned per OS image (Apache 2.4.69 on Debian 13, Apache 2.4.66 on Ubuntu 26.04) and can be overridden with `apache_version`; the pinned build is fetched from a pre-fix snapshot of the distribution archive (`snapshot.debian.org/archive/debian-security` on Debian, `snapshot.ubuntu.com` on Ubuntu), because both distributions shipped fixes on 2026-11-12 (DSA-6620-1 and USN-9090-1). `mod_http2` is enabled and the default site serves cleartext HTTP/2 (`h2c`) on port 80, so demo requests actually traverse the vulnerable module: `curl --http2-prior-knowledge -I http://<host>/`. Without `php2shell`, a small `index.html` reports the running version.

- **`cve-2026-114938`: Java4Shell**

  A heap out-of-bounds write in the HotSpot AVX-512 VBMI intrinsic behind `java.util.Base64`'s basic and URL decoders (OpenJDK 17.0.6 and later, also 21, 25 and 27; fixed in 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1). It is reachable by anything that Base64-decodes untrusted input, such as HTTP Basic authentication headers or JWTs. Severity is disputed: Oracle scores it 8.1 (CVSS 3.1), the reporting researcher 9.2 (CVSS 4.0); unauthenticated code execution was demonstrated by the reporter in several Java applications, while other labs have only reproduced crashes and memory reads. The scenario installs `openjdk-21-jre-headless` and `openjdk-21-jdk-headless` held at a pre-fix build (Debian 13: `21.0.13+9-1~deb13u2`, fixed in `21.0.13.1+2-1~deb13u1` / DSA-6639-1; Ubuntu 26.04: `21.0.13.0.3+1-1~26.04.1`, fixed in `21.0.13.1+2-1~26.04.1` / USN-9155-1), fetched from a pre-fix snapshot of the distribution security archive. Override with `java_version` and `java_snapshot_timestamp`. A small systemd service (`java4shell`) listens on `java_port` (default 8081, limited to `admin_source_cidr`) and decodes request bodies (`POST /decode`) and Basic-auth headers (`GET /auth`) with `java.util.Base64`; `GET /` reports the Java version and whether the CPU has AVX-512 VBMI. The pinned version is checked against the first fixed release at deploy time and held with `apt-mark hold`.

  **CPU requirement:** the bug is only reachable on x86-64 CPUs with AVX-512 VBMI (Intel Ice Lake / Sapphire Rapids or newer, AMD Zen 4 or newer). The default VM sizes (`t3.small`, `Standard_B2s`, `e2-small`) do not have it: FortiCNAPP still reports the vulnerable package there, but the bug cannot be triggered. For an exploitable host, choose a size with `avx512_vbmi` (for example AWS `m6i`/`c6i`/`m7i`, Azure `Dv5`/`Ev5`/`Dv6`, GCP `C3` or N2 on Ice Lake; the cloud vendors' size lists differ, so confirm with `grep avx512_vbmi /proc/cpuinfo` — the build report prints the result). ARM instances are not affected. Check the demo with `curl http://<host>:8081/`. Only trigger the flaw against a host you own and in an isolated account.

  Mitigation to demonstrate remediation: `-XX:-UseBASE64Intrinsics`, or upgrade to a fixed build. References: [Rapid7](https://www.rapid7.com/blog/post/etr-cve-2026-114938-reported-critical-pre-authentication-remote-code-execution-java-17/), [Censys](https://censys.com/advisory/cve-2026-114938/), [Equixly](https://equixly.com/blog/2026/11/17/cve-2026-114938-pre-auth-heap-overflow-in-java-17-21-and-25/).

### Select your cloud

The template folder is organized as `vulnerable-vm/<cloud>`, with `aws`, `azure` and `gcp` as cloud names. Each of these contains:

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
cd vulnerable-vm/aws    # or vulnerable-vm/azure, vulnerable-vm/gcp
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
| `scenarios` | Which vulnerabilities to install on the one host (default: all four). Remove entries to isolate |
| `install_forticnapp_agent` | Install the FortiCNAPP Linux agent from the `packages.lacework.net` APT repository (amd64 and arm64 only) |
| `forticnapp_access_token` | Agent access token, required when the agent is installed. Prefer `export TF_VAR_forticnapp_access_token=<token>` over writing it to a file |
| `forticnapp_server_url` | FortiCNAPP server URL for your region (default `https://api.fra.lacework.net`). Empty means auto-discover |

Network ranges, VM sizes, tags and the pinned package versions have defaults and are documented in `terraform.tfvars.example`.

## Deploy with GitHub Actions (AWS)

The workflow [`deploy-vulnerable-vm-aws.yml`](.github/workflows/deploy-vulnerable-vm-aws.yml) deploys `vulnerable-vm/aws` and is started manually (Actions tab, *Run workflow*). Choose `plan`, `apply` or `destroy`, the resource name prefix (default `forticnapp-threat`), the OS image, the allowed source CIDR and whether to install the FortiCNAPP agent.

The workflow authenticates to AWS with OpenID Connect (OIDC): GitHub issues a short-lived token per run and AWS exchanges it for temporary credentials, so no access keys are stored in GitHub.

### Setup

**In AWS** (once per account; replace `<ACCOUNT_ID>`, `<ORG>/<REPO>`, `<SUB_PREFIX>` and `<REGION>`):

1. Create the state bucket: `scripts/create-tfstate-bucket.sh <REGION>`.
2. Create the GitHub OIDC identity provider (skip if the account already has one for `token.actions.githubusercontent.com`):

   ```sh
   aws iam create-open-id-connect-provider \
     --url https://token.actions.githubusercontent.com \
     --client-id-list sts.amazonaws.com
   ```

3. Find the `sub` claim prefix GitHub uses for this repository. By default it is `repo:<ORG>/<REPO>`, but if the organisation or repository enforces immutable subject claims it contains numeric IDs (for example `repo:<ORG>@<ORG_ID>/<REPO>@<REPO_ID>`), and a trust policy using the plain name is refused with "Not authorized to perform sts:AssumeRoleWithWebIdentity":

   ```sh
   gh api repos/<ORG>/<REPO>/actions/oidc/customization/sub
   ```

   If `use_immutable_subject` is `true`, use the returned `sub_claim_prefix` as `<SUB_PREFIX>` below. Otherwise use `repo:<ORG>/<REPO>`.

4. Create the IAM role the workflow assumes. The trust policy only accepts runs of this repository that use the `forticnapp-threat-aws` environment:

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
           "token.actions.githubusercontent.com:sub": "<SUB_PREFIX>:environment:forticnapp-threat-aws"
         }
       }
     }]
   }
   JSON
   aws iam create-role --role-name github-actions-forticnapp-threat \
     --assume-role-policy-document file://trust.json
   ```

5. Give the role permission to manage the EC2/VPC resources and to use the state bucket:

   ```sh
   cat > permissions.json <<'JSON'
   {
     "Version": "2012-10-17",
     "Statement": [
       {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"},
       {"Effect": "Allow", "Action": "s3:ListBucket",
        "Resource": "arn:aws:s3:::forticnapp-threat-tfstate-<ACCOUNT_ID>-<REGION>"},
       {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        "Resource": "arn:aws:s3:::forticnapp-threat-tfstate-<ACCOUNT_ID>-<REGION>/*"}
     ]
   }
   JSON
   aws iam put-role-policy --role-name github-actions-forticnapp-threat \
     --policy-name github-actions-forticnapp-threat --policy-document file://permissions.json
   ```

6. Make sure an EC2 key pair exists in the target region (`aws ec2 create-key-pair` or import your public key) and note its name.

**In GitHub** (repository Settings):

1. Environments: create `forticnapp-threat-aws`. Optionally add required reviewers so `apply` and `destroy` need approval. The environment name must match the `sub` condition in the trust policy.
2. Secrets and variables, Actions: add these repository secrets:

| Secret | Description |
|--------|-------------|
| `AWS_ROLE_ARN` | ARN of the role from step 4, for example `arn:aws:iam::<ACCOUNT_ID>:role/github-actions-forticnapp-threat` |
| `AWS_REGION` | Region to deploy into, for example `eu-west-1` |
| `AWS_ACCOUNT_ID` | Target account ID, used for the state bucket name. The run aborts if the role belongs to another account |
| `AWS_KEY_NAME` | Name of the EC2 key pair from step 6 |
| `FORTICNAPP_ACCESS_TOKEN` | Optional, only when installing the agent |

3. Actions tab, *Deploy vulnerable-vm (AWS)*, *Run workflow*: start with `plan`, then `apply`.

Terraform state is kept in an S3 bucket named `forticnapp-threat-tfstate-<account>-<region>`, so `destroy` works from a later run. The bucket is created in AWS setup step 1 by `scripts/create-tfstate-bucket.sh`, which enables versioning, encryption and blocks public access, and is safe to re-run. The workflow's `state_backend` input selects `s3` (default) or `local`; local state is lost when the runner ends. 

## Support

Fortinet-provided scripts and templates in this repository are not officially supported by Fortinet Technical Support. They are provided as-is, without any warranty. Use the [issue tracker](https://github.com/40net-cloud/forticnapp-threat/issues) to report problems or request improvements.

---

*Intentionally vulnerable. Deploy responsibly.*
