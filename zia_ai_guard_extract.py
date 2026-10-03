#!/usr/bin/env python3

# scrape_ai_guard_apps.py
# Usage:
#   pip install playwright pyyaml
#   playwright install
#   python scrape_ai_guard_apps.py --format yaml   > ai-guard.yaml
#   python scrape_ai_guard_apps.py --format terraform > locals.tf

import argparse
import json
import re
import sys
import urllib.request
import os
from collections import OrderedDict
from playwright.sync_api import sync_playwright

URL = "https://help.zscaler.com/secure-ai-users/integrating-zia-ai-guard"

def normalize_name(app: str) -> str:
    # "Anthropic (Claude)" -> "Anthropic Claude"
    # "OpenAI ChatGPT, Codex" -> "OpenAI ChatGPT Codex"
    name = re.sub(r"[()]", "", app).strip()
    return name.replace(",", "")

def uniq_preserve(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def scrape():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(URL, wait_until="networkidle")
        page.wait_for_selector(".ag-root")

        rows_all = []
        while True:
            rows = page.locator(".ag-center-cols-container [role='row']").all()
            for r in rows:
                app = r.locator("[col-id='application'] .ag-cell-value").inner_text().strip()
                if not app:
                    continue

                ct_cell = r.locator("[col-id='clienttypes']")
                ct_items = [li.inner_text().strip() for li in ct_cell.locator("li").all()]
                if not ct_items:
                    ct_text = ct_cell.inner_text().strip()
                    ct_items = [ct_text] if ct_text else []

                dom_cell = r.locator("[col-id='domainsrequired']")
                spans = dom_cell.locator("code").all()
                addresses = []
                for span in spans:
                    text = span.inner_text().strip()
                    if text:
                        addresses.append(text)
                
                domains = addresses
                if not domains:
                    txt = dom_cell.inner_text().strip()
                    domains = [ln.strip() for ln in txt.splitlines() if ln.strip()]

                if domains:
                    rows_all.append({
                        "application": app,
                        "client_types": ct_items,
                        "domains": domains,
                    })

            next_btn = page.locator("[data-ref='btNext']")
            if (next_btn.count() == 0) or (next_btn.get_attribute("aria-disabled") == "true"):
                break
            next_btn.click()
            page.wait_for_selector(".ag-center-cols-container [role='row']")

        browser.close()
        return rows_all

def build_groups(records, prefix="AI Guard"):
    groups = []
    for rec in records:
        name_base = f"{prefix} - {normalize_name(rec['application'])}"
        desc_lines = [s for s in rec["client_types"] if s]
        desc_lines.append(f"\nExtracted from: {URL}")
        desc = "\n".join(desc_lines)
        
        fqdns = []
        wildcards = []
        
        seen = set()
        for d in rec["domains"]:
            d_clean = d.strip()
            if not d_clean:
                continue
                
            is_wildcard = d_clean.startswith("*.") or d_clean.startswith(".")
            bare = re.sub(r'^\*?\.+', '', d_clean)
            if not bare:
                continue
                
            # If ZIA needs bare domain for both, we store bare but use DSTN_DOMAIN type for wildcards
            # Some platforms prefer .domain for wildcards. ZIA accepts bare domain for DSTN_DOMAIN
            # We will use bare domain.
            if is_wildcard:
                if bare not in seen:
                    wildcards.append(bare)
                    seen.add(bare)
            else:
                if bare not in seen:
                    fqdns.append(bare)
                    seen.add(bare)

        if fqdns:
            groups.append({
                "name": name_base if not wildcards else f"{name_base} - FQDN",
                "description": desc,
                "type": "DSTN_FQDN",
                "addresses": fqdns,
            })
            
        if wildcards:
            groups.append({
                "name": name_base if not fqdns else f"{name_base} - Wildcard",
                "description": desc,
                "type": "DSTN_DOMAIN",
                "addresses": wildcards,
            })

    return groups

class LiteralString(str):
    pass

def to_yaml(groups, cert_content=None, prefix="AI Guard"):
    import yaml
    yaml.SafeDumper.add_representer(LiteralString, lambda dumper, data: dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|'))
    
    payload = {
        "version": "1.0",
        "zia": {}
    }
    
    payload["zia"]["proxies"] = [{
        "name": f"{prefix} - TO_BE_DEFINED",
        "type": "PROXYCHAIN",
        "address": "TO_BE_DEFINED",
        "port": "TO_BE_DEFINED",
        "cert": {
            "name": f"{prefix} Root Cert"
        },
        "description": f"{prefix} Proxy",
        "insert_xau_header": True,
        "base64_encode_xau_header": False
    }]
    
    payload["zia"]["proxy_gateways"] = [{
        "name": f"{prefix} - TO_BE_DEFINED",
        "type": "PROXYCHAIN",
        "primary_proxy": {
            "name": f"{prefix} - TO_BE_DEFINED"
        },
        "description": f"{prefix} Proxy Gateway",
        "fail_closed": True
    }]
    
    payload["zia"]["ip_destination_groups"] = groups
    
    if cert_content:
        payload["zia"]["root_certificates"] = [{
            "name": f"{prefix} Root Cert.pem",
            "displayName": f"{prefix} Root Cert",
            "certTypes": ["PROXY_CHAINING"],
            "cert": LiteralString(cert_content.strip())
        }]
        
    payload["zia"]["ssl_policy"] = [{
        "name": f"{prefix} - TO_BE_DEFINED",
        "order": 1,
        "rank": 7,
        "road_warrior_for_kerberos": False,
        "action": {
            "type": "DECRYPT",
            "showEUN": False,
            "showEUNATP": False,
            "overrideDefaultCertificate": False,
            "decryptSubActions": {
                "serverCertificates": "BLOCK",
                "ocspCheck": True,
                "blockSslTrafficWithNoSniEnabled": False,
                "minClientTLSVersion": "CLIENT_TLS_1_2",
                "minServerTLSVersion": "SERVER_TLS_1_2",
                "blockUndecrypt": False,
                "http2Enabled": False
            }
        },
        "state": "ENABLED",
        "description": f"{prefix} SSL Inspection",
        "dest_ip_groups": [{"name": g["name"]} for g in groups]
    }]
    
    payload["zia"]["forwarding_rules"] = [{
        "name": f"{prefix} - TO_BE_DEFINED",
        "type": "FORWARDING",
        "order": 1,
        "rank": 7,
        "state": "ENABLED",
        "forward_method": "PROXYCHAIN",
        "description": f"{prefix} Forwarding",
        "proxy_gateway": {
            "name": f"{prefix} - TO_BE_DEFINED"
        },
        "dest_ip_groups": [{"name": g["name"]} for g in groups]
    }]
        
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)

def hcl_escape(s: str) -> str:
    return (
        s.replace("\\", "\\\\")
         .replace("\n", "\\n")
         .replace('"', '\\"')
    )



def to_hcl(groups, cert_content=None, prefix="AI Guard"):
    lines = []
    lines.append("locals {")
    lines.append("  zia = {")
    
    if cert_content:
        lines.append("    root_certificates = [")
        lines.append("      {")
        lines.append(f'        name        = "{hcl_escape(prefix)} Root Cert.pem"')
        lines.append(f'        displayName = "{hcl_escape(prefix)} Root Cert"')
        lines.append('        certTypes   = ["PROXY_CHAINING"]')
        lines.append(f'        cert        = <<EOF\n{cert_content.strip()}\nEOF')
        lines.append("      }")
        lines.append("    ]")
        
    lines.append("    ip_destination_groups = [")
    for i, g in enumerate(groups):
        lines.append("      {")
        lines.append(f'        name        = "{hcl_escape(g["name"])}"')
        lines.append(f'        description = "{hcl_escape(g["description"])}"')
        lines.append(f'        type        = "{g["type"]}"')
        addrs = ", ".join(f'"{hcl_escape(a)}"' for a in g["addresses"])
        lines.append(f"        addresses   = [{addrs}]")
        lines.append("      }" + ("," if i < len(groups) - 1 else ""))
    lines.append("    ]")
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines)

def update_existing_yaml(filepath, groups, cert_content=None, prefix="AI Guard"):
    import yaml
    
    with open(filepath, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
        
    if "zia" not in config:
        config["zia"] = {}
        
    config["zia"]["ip_destination_groups"] = groups
    
    if cert_content:
        config["zia"]["root_certificates"] = [{
            "name": f"{prefix} Root Cert.pem",
            "displayName": f"{prefix} Root Cert",
            "certTypes": ["PROXY_CHAINING"],
            "cert": LiteralString(cert_content.strip())
        }]

    # Update ssl_policy dest_ip_groups if it exists
    if "ssl_policy" in config["zia"]:
        for rule in config["zia"]["ssl_policy"]:
            if "dest_ip_groups" in rule:
                rule["dest_ip_groups"] = [{"name": g["name"]} for g in groups]
                
    # Update forwarding_rules dest_ip_groups if it exists
    if "forwarding_rules" in config["zia"]:
        for rule in config["zia"]["forwarding_rules"]:
            if "dest_ip_groups" in rule:
                rule["dest_ip_groups"] = [{"name": g["name"]} for g in groups]
                
    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.safe_dump(config, f, sort_keys=False, allow_unicode=True)
    
    print(f"Successfully updated configuration file in-place: {filepath}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--format", choices=["yaml", "terraform"], required=True)
    ap.add_argument("--cert-url", default="https://public-cert-proxychaining.s3-us-west-2.amazonaws.com/prod_root_cert.pem", help="URL to download the proxy chain certificate")
    ap.add_argument("--prefix", "-p", default="AI Guard", help="Prefix for naming generated objects")
    
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--out", help="Path to write the output file directly (overwrite mode)")
    group.add_argument("--append", help="Path to write the output file directly (append mode)")
    group.add_argument("--update-yaml", help="Path to an existing YAML configuration file to intelligently update in-place")
    
    args = ap.parse_args()

    cert_content = None
    if args.cert_url:
        try:
            with urllib.request.urlopen(args.cert_url) as response:
                cert_content = response.read().decode('utf-8').replace('\r\n', '\n')
        except Exception as e:
            print(f"Error downloading certificate from {args.cert_url}: {e}", file=sys.stderr)
            sys.exit(1)

    records = scrape()
    
    active_prefix = args.prefix
    if args.update_yaml:
        if not os.path.exists(args.update_yaml):
            print(f"Error: Target update file {args.update_yaml} does not exist.", file=sys.stderr)
            sys.exit(1)
            
        import yaml
        with open(args.update_yaml, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            if config and "zia" in config and config["zia"].get("ip_destination_groups"):
                first_name = config["zia"]["ip_destination_groups"][0].get("name", "")
                if " - " in first_name:
                    active_prefix = first_name.split(" - ")[0]

    groups = build_groups(records, prefix=active_prefix)

    if args.format == "yaml":
        output = to_yaml(groups, cert_content, prefix=active_prefix)
    else:
        output = to_hcl(groups, cert_content, prefix=active_prefix)
        
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Successfully wrote output to {args.out}")
    elif args.append:
        with open(args.append, "a", encoding="utf-8") as f:
            f.write("\n" + output)
        print(f"Successfully appended output to {args.append}")
    elif args.update_yaml:
        if not os.path.exists(args.update_yaml):
            print(f"Error: Target update file {args.update_yaml} does not exist.", file=sys.stderr)
            sys.exit(1)
        update_existing_yaml(args.update_yaml, groups, cert_content, prefix=active_prefix)
    else:
        print(output)

if __name__ == "__main__":
    main()
