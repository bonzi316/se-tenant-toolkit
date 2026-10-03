# Zscaler POV Toolkit

> **Automate your Zscaler Proof of Value tenant setup in minutes, not hours.**

A Python CLI tool built for Zscaler Admins to automate the full configuration of a ZCC, ZIA, and ZPA tenant from a single declarative YAML file — using the **Zscaler OneAPI** (OAuth 2.0).

---

## ✨ Key Features

- **ZCC Automation** — Configure Forwarding Profiles (Tunnel 2.0, TLS/DTLS, PAC), App Profiles, and Trusted Networks
- **ZIA Automation** — Deploy URL Categories, SSL Inspection, URL Filtering, Cloud App Control, Firewall, and DNS policies; manage PAC files
- **ZPA Automation** — Create Connector Groups, Server Groups, Segment Groups, and wildcard App Segments with Access Policies
- **Idempotent** — Safe to run repeatedly; existing resources are updated, not duplicated
- **Dry-Run Mode** — Preview all changes before touching any tenant
- **Scoped Execution** — Target a specific section (e.g. `--scope zcc.forwarding_profiles`) without running the full playbook
- **Multi-Tenant** — Switch between tenants with a single `--env` flag
- **Portable YAML Config** — Human-readable, diffable, reusable across any Zscaler tenant

---

## 📁 Project Structure

```
zscaler-pov-toolkit/
├── pov_toolkit.py           # Main CLI — tenant preparation & configuration
├── tenant-cleanup.py        # Companion CLI — remove POV resources from a tenant
├── requirements.txt         # Python dependencies
├── .env-example             # Credential template (copy to .env.<tenant>)
├── configs/
│   └── POV_ZIA_NO_AI_GUARD/ # Example POV configuration preset
│       └── POV-ZIA_NO_AI_GUARD.yaml
└── src/
    ├── config.py            # Pydantic schema validation
    ├── zcc.py               # ZCC handlers (Forwarding & App Profiles)
    ├── zia.py               # ZIA handlers (Policies, PAC, Categories)
    ├── zpa.py               # ZPA handlers (App Segments, Groups, Policies)
    └── exporter.py          # Export live tenant config to YAML
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.10+
- Zscaler OneAPI credentials (Client ID, Client Secret, Vanity Domain) configured in **ZIdentity**

### 1. Clone & create virtual environment

**Windows (PowerShell):**
```powershell
git clone https://github.com/<your-username>/zscaler-pov-toolkit.git
cd zscaler-pov-toolkit
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS / Linux:**
```bash
git clone https://github.com/<your-username>/zscaler-pov-toolkit.git
cd zscaler-pov-toolkit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure credentials

Copy the example file and fill in your tenant credentials:
```bash
cp .env-example .env.mytenant
```

```ini
ZSCALER_CLIENT_ID="your_client_id"
ZSCALER_CLIENT_SECRET="your_client_secret"
ZSCALER_VANITY_DOMAIN="yourcompany.zslogin.net"
# ZSCALER_CLOUD="zscaler"                    # Optional: e.g. zscaler, zscalertwo (defaults to production)
ZSCALER_CUSTOMER_ID="your_zpa_id"            # Required for ZPA
PRIMARY_DOMAIN="yourcompany.com"             # Used for PAC file registration
INTERNAL_DOMAINS="corp.local,internal.local" # Comma-separated domains for ZPA
ENV_NAME="mytenant"                          # Short label for this environment
```

> 💡 You can maintain multiple `.env.<tenant>` files and switch between them with `--env`.

---

## 🛠️ Usage

### Basic syntax
```bash
python pov_toolkit.py -c <config.yaml> -e <.env.tenant> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `-c / --config` | Path to the POV preset configuration YAML file |
| `-e / --env-file` | Path to the `.env.<tenant>` credentials file **(Required - By design, there is no default value to prevent accidental modifications on the wrong tenant)** |
| `-p / --prefix` | Prefix dynamically added to the names of created/updated objects (default: `POV-TOOL`). Set to empty string `''` to deploy without prefix. |
| `--rule-label` | Rule label to automatically tag on all created ZIA rules (creates the label if it does not exist) |
| `--scope` | Scope specific configuration sections to apply (e.g., `zcc.forwarding_profiles`). Can be specified multiple times. |
| `-a / --activate` | Activate ZIA configuration changes after applying (Does nothing in dry-run mode) |
| `-d / --dry-run` | Perform a dry run without making actual API changes |
| `-v / --verbose` | Enable verbose debug logging |
| `--export-zcc` | Export ZCC configuration (Profiles, Networks, Privacy, Cleanup) from the tenant to a YAML file |
| `--export-zia` | Export ZIA configuration (URL Categories, Settings, Profile, Security) from the tenant to a YAML file |
| `--export-zpa` | Export ZPA configuration (Connector Groups, Server Groups, Segment Groups, App Segments, Policies) from the tenant to a YAML file |
| `--search` | Search query to filter forwarding and application profiles by name when exporting |
| `--export-out` | Output file path for the exported YAML configuration |

---

### Examples

**Full POV setup — dry run first:**
```bash
python pov_toolkit.py -c configs/POV_ZIA_NO_AI_GUARD/POV-ZIA_NO_AI_GUARD.yaml \
                      -e .env.myclient \
                      -p "POV" \
                      --dry-run
```

**Apply full configuration:**
```bash
python pov_toolkit.py -c configs/POV_ZIA_NO_AI_GUARD/POV-ZIA_NO_AI_GUARD.yaml \
                      -e .env.myclient \
                      -p "POV"
```

**Apply only ZCC Forwarding Profiles:**
```bash
python pov_toolkit.py -c configs/POV_ZIA_NO_AI_GUARD/POV-ZIA_NO_AI_GUARD.yaml \
                      -e .env.myclient \
                      --scope zcc.forwarding_profiles
```

**Apply multiple specific scopes:**
```bash
python pov_toolkit.py -c configs/POV_ZIA_NO_AI_GUARD/POV-ZIA_NO_AI_GUARD.yaml \
                      -e .env.myclient \
                      --scope zcc.forwarding_profiles \
                      --scope zcc.app_profiles
```

---

## 📋 YAML Configuration

The toolkit is driven by a single YAML file that describes all resources to create or update. Example structure:

```yaml
version: '1.0'

zcc:
  forwarding_profiles:
    - search_name: POV - WIN T2.0 - TLS
      update:
        name: POV - WIN T2.0 - TLS
        forwarding_profile_actions:
          - network_type: 0
            action_type: 1
            enable_packet_tunnel: 1
            primary_transport: 0   # 0 = TLS, 1 = DTLS

  app_profiles:
    windows:
      - search_name: POV - T2.0 TLS
        update:
          name: POV - T2.0 TLS
          forwarding_profile_name: POV - WIN T2.0 - TLS
          pac_url_name: POV_PAC

zia:
  rule_labels:
    - name: "POV - Created Rules"
      description: "Rules managed by POV Toolkit"

  url_categories:
    - name: POV - Allowed Apps
      super_category: USER_DEFINED
      urls:
        - example.com
        - allowed-app.io

  url_filtering_rules:
    - name: POV - Allow Rule
      action: ALLOW
      labels:
        - "POV - Created Rules"
      url_categories:
        - POV - Allowed Apps
```

See [`configs/POV_ZIA_NO_AI_GUARD/`](configs/POV_ZIA_NO_AI_GUARD/) for a full working example.

---

## 🔒 Security Notes

- **Never commit `.env.*` files** — they contain API credentials. The `.gitignore` is pre-configured to exclude them.
- Use `.env-example` as the credential template (safe to commit — contains no real values).
- Each tenant should have its own `.env.<tenant>` file kept locally.

---

## 📦 Available Scopes

| Scope | Description |
|---|---|
| `zcc.trusted_networks` | Trusted Network definitions |
| `zcc.forwarding_profiles` | ZCC Forwarding Profiles (Tunnel 2.0, PAC, transport) |
| `zcc.app_profiles` | ZCC App Profiles (Windows, macOS) |
| `zia.pac_files` | PAC file deployment |
| `zia.rule_labels` | ZIA Rule Labels |
| `zia.url_categories` | Custom URL categories |
| `zia.ssl_inspection_rules` | SSL Inspection policies |
| `zia.url_filtering_rules` | URL Filtering rules |
| `zia.cloud_app_rules` | Cloud App Control rules |
| `zia.firewall_rules` | Firewall Filtering rules |
| `zia.dns_rules` | DNS Control rules |
| `zpa.app_segments` | ZPA App Segments |
| `zpa.server_groups` | ZPA Server Groups |
| `zpa.segment_groups` | ZPA Segment Groups |
| `zpa.access_policies` | ZPA Access Policy rules |

---

## 🧹 Cleanup Tool — `tenant-cleanup.py`

Remove POV resources from a tenant after the engagement is complete. Safely deletes ZIA rules, Rule Labels, URL categories, ZCC profiles, and ZPA objects matching a given prefix, regex pattern, or rule label. It respects strict deletion order to avoid dependency errors.

```bash
python tenant-cleanup.py -e .env.myclient --prefix "POV"
# Or delete rules tagged with a specific Rule Label:
python tenant-cleanup.py -e .env.myclient --rule-label "POV - Created Rules"
```

### Options

| Argument | Description |
|---|---|
| `-e / --env-file` | Path to the `.env.<tenant>` credentials file **(Required - Forces explicit tenant selection to prevent accidental deletions on the wrong environment)** |
| `-p / --prefix` | Delete all resources whose name starts with this prefix (e.g. `POV`) |
| `--pattern` | Delete all resources matching this regex pattern |
| `-d / --dry-run` | List matching items without deleting them |
| `-l / --list` | List matching items and exit without deleting (alias for `--dry-run`) |
| `-f / --force` | Bypass interactive confirmation prompt when deleting |
| `-m / --modules` | Comma-separated list of specific modules to clean (Default: all modules) |
| `--rule-label` | Delete all rules tagged with this Rule Label, as well as the Rule Label itself |
| `--zia` | Scan all ZIA modules |
| `--zcc` | Scan all ZCC modules |
| `--zpa` | Scan all ZPA modules |
| `-a / --activate` | Activate ZIA configuration changes after cleanup completes (Does nothing in dry-run mode) |

**Available Modules for `-m`:**
- **ZIA**: `url-cat`, `url-rules`, `casb-rules`, `ssl-rules`, `file-rules`, `ip-dest-groups`, `ip-src-groups`, `firewall-rules`, `dns-rules`, `proxies`, `proxy-gws`, `fwd-rules`, `pac-files`, `rule-labels`
- **ZCC**: `app-profiles`, `fwd-profiles`, `trusted-networks`, `root-certs`
- **ZPA**: `zpa-access-rules`, `zpa-timeout-rules`, `zpa-fwd-rules`, `zpa-app-segments`, `zpa-segment-groups`, `zpa-server-groups`, `zpa-conn-groups`, `zpa-dns-domains`

> ⚠️ **Use `-l / --list` first.** This tool permanently deletes resources matching the criteria. Default policies (e.g., `Default_Rule` in ZPA) are safely ignored and will never be deleted.

---

## 🤖 AI Guard App Extractor — `zia_ai_guard_extract.py`

A utility script that scrapes the official Zscaler help portal to dynamically extract the list of supported AI Guard applications. 

```bash
# Requires playwright
pip install playwright pyyaml
playwright install

# Extract to YAML
python zia_ai_guard_extract.py --format yaml > ai-guard.yaml

# Extract to Terraform locals
python zia_ai_guard_extract.py --format terraform > locals.tf
```

### Options

| Argument | Description |
|---|---|
| `--format` | **Required**. Output format (`yaml` or `terraform`) |
| `--cert-url` | URL to download the proxy chain certificate |
| `-p / --prefix` | Prefix for naming generated objects (default: `AI Guard`) |
| `--out` | Path to write the output file directly (overwrite mode) |
| `--append` | Path to write the output file directly (append mode) |
| `--update-yaml` | Path to an existing YAML configuration file to intelligently update in-place |

---

## ⚠️ Known Limitations

- **ZCC App Profiles:** Automated creation of ZCC App Profiles is currently not recommended. There are API limitations around the installation of SSL certificates and the WFP (Windows Filtering Platform) driver that are not actionable programmatically. It is highly recommended to configure App Profiles **manually** for now.
- **ZIA AI Guard:** ZIA Proxy Gateways (required for AI Guard policies) cannot be created manually or via the standard API endpoints. Because of this restriction, **AI Guard cannot be fully automated** from end to end.

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first.

---

## 📄 License

MIT
