#!/usr/bin/env python3
import os
import sys
import re
import argparse
from src.client import get_zscaler_client, load_env_file

# Define categories of CASB / Cloud App Control rules
CASB_CATEGORIES = [
    "AI_ML", "BUSINESS_PRODUCTIVITY", "CONSUMER", "DNS_OVER_HTTPS",
    "ENTERPRISE_COLLABORATION", "FILE_SHARE", "FINANCE", "HEALTH_CARE",
    "HOSTING_PROVIDER", "HUMAN_RESOURCES", "INSTANT_MESSAGING", "IT_SERVICES",
    "LEGAL", "SALES_AND_MARKETING", "STREAMING_MEDIA", "SOCIAL_NETWORKING",
    "SYSTEM_AND_DEVELOPMENT", "WEBMAIL"
]

def should_delete(name, prefix=None, pattern_re=None):
    if not name:
        return False
    if prefix:
        if name.lower().startswith(prefix.lower()):
            return True
    if pattern_re:
        if pattern_re.search(name):
            return True
    return False

def rule_has_label(rule, rule_label_filter):
    if not rule_label_filter:
        return False
    labels = getattr(rule, "labels", None)
    if labels is None and isinstance(rule, dict):
        labels = rule.get("labels")
    if not labels:
        return False
    for lb in labels:
        lb_name = getattr(lb, "name", None) if not isinstance(lb, dict) else lb.get("name")
        if lb_name and (rule_label_filter.lower() in lb_name.lower() or rule_label_filter.lower() == lb_name.lower()):
            return True
    return False


def get_all_paginated(client_func, *args, **kwargs):
    all_items = []
    page = 1
    query_params = kwargs.pop('query_params', {})
    while True:
        q = dict(query_params)
        q['page'] = page
        q['pagesize'] = 500
        q['page_size'] = 500
        try:
            res = client_func(*args, query_params=q, **kwargs)
            items = res[0] if isinstance(res, tuple) and len(res) >= 1 else res
            if items is None:
                break
            all_items.extend(items)
            if len(items) < 500:
                break
            page += 1
        except Exception:
            # Fallback for APIs that don't support pagination
            if page == 1:
                try:
                    res = client_func(*args, query_params=query_params, **kwargs)
                    items = res[0] if isinstance(res, tuple) and len(res) >= 1 else res
                    if items:
                        all_items.extend(items)
                except Exception:
                    try:
                        res = client_func(*args, **kwargs)
                        items = res[0] if isinstance(res, tuple) and len(res) >= 1 else res
                        if items:
                            all_items.extend(items)
                    except Exception:
                        pass
            break
    return all_items

def scan_url_categories(client, prefix, pattern_re):
    print("Scanning ZIA URL Categories...")
    categories = []
    try:
        raw_cats = get_all_paginated(client.zia.url_categories.list_categories)
        for c in raw_cats:
            c_dict = c.as_dict() if hasattr(c, "as_dict") else dict(c)
            c_name = c_dict.get("configured_name", "") or c_dict.get("name", "") or ""
            c_id = c_dict.get("id")
            is_custom = c_dict.get("custom_category", False)
            if not is_custom:
                continue
            if should_delete(c_name, prefix, pattern_re):
                categories.append({"id": c_id, "name": c_name, "type": "ZIA URL Category"})
    except Exception as e:
        print(f"  [EXCEPTION] URL Category scan failed: {e}")
    return categories

def scan_ip_destination_groups(client, prefix, pattern_re):
    print("Scanning ZIA IP Destination Groups...")
    groups = []
    try:
        raw_groups = get_all_paginated(client.zia.cloud_firewall.list_ip_destination_groups)
        for g in raw_groups:
            g_dict = g.as_dict() if hasattr(g, "as_dict") else dict(g)
            g_name = g_dict.get("name", "")
            g_id = g_dict.get("id")
            is_custom = not g_dict.get("is_non_editable", False)
            if not is_custom:
                continue
            if should_delete(g_name, prefix, pattern_re):
                groups.append({"id": g_id, "name": g_name, "type": "IP Destination Group"})
    except Exception as e:
        print(f"  [EXCEPTION] IP Destination Group scan failed: {e}")
    return groups

def scan_ip_source_groups(client, prefix, pattern_re):
    print("Scanning ZIA IP Source Groups...")
    groups = []
    try:
        raw_groups = get_all_paginated(client.zia.cloud_firewall.list_ip_source_groups)
        for g in raw_groups:
            g_dict = g.as_dict() if hasattr(g, "as_dict") else dict(g)
            g_name = g_dict.get("name", "")
            g_id = g_dict.get("id")
            is_custom = not g_dict.get("is_non_editable", False)
            if not is_custom:
                continue
            if should_delete(g_name, prefix, pattern_re):
                groups.append({"id": g_id, "name": g_name, "type": "IP Source Group"})
    except Exception as e:
        print(f"  [EXCEPTION] IP Source Group scan failed: {e}")
    return groups

def scan_url_filtering(client, prefix, pattern_re, rule_label=None):
    print("Scanning ZIA URL Filtering rules...")
    rules = []
    try:
        raw_rules = get_all_paginated(client.zia.url_filtering.list_rules)
        for r in raw_rules:
            r_name = getattr(r, 'name', '') or ''
            r_id = getattr(r, 'id', None)
            if should_delete(r_name, prefix, pattern_re) or rule_has_label(r, rule_label):
                rules.append({"id": r_id, "name": r_name, "type": "URL Filtering Rule"})
    except Exception as e:
        print(f"  [EXCEPTION] URL Filtering scan failed: {e}")
    return rules

def scan_casb_rules(client, prefix, pattern_re, rule_label=None):
    print("Scanning ZIA CASB Cloud App Control rules...")
    rules = []
    for cat in CASB_CATEGORIES:
        try:
            raw_rules = get_all_paginated(client.zia.cloudappcontrol.list_rules, cat)
            if not raw_rules:
                continue
            for r in raw_rules:
                r_name = getattr(r, 'name', '') or ''
                r_id = getattr(r, 'id', None)
                if should_delete(r_name, prefix, pattern_re) or rule_has_label(r, rule_label):
                    rules.append({"id": r_id, "name": r_name, "type": f"CASB Rule ({cat})", "category": cat})
        except Exception:
            pass
    return rules

def scan_ssl_inspection(client, prefix, pattern_re, rule_label=None):
    print("Scanning ZIA SSL Inspection rules...")
    rules = []
    try:
        raw_rules = get_all_paginated(client.zia.ssl_inspection_rules.list_rules)
        for r in raw_rules:
            r_name = getattr(r, 'name', '') or ''
            r_id = getattr(r, 'id', None)
            if should_delete(r_name, prefix, pattern_re) or rule_has_label(r, rule_label):
                rules.append({"id": r_id, "name": r_name, "type": "SSL Inspection Rule"})
    except Exception as e:
        print(f"  [EXCEPTION] SSL Inspection scan failed: {e}")
    return rules

def scan_file_type_rules(client, prefix, pattern_re, rule_label=None):
    print("Scanning ZIA File Type Control rules...")
    rules = []
    try:
        raw_rules = get_all_paginated(client.zia.file_type_control_rule.list_rules)
        for r in raw_rules:
            r_name = getattr(r, 'name', '') or ''
            r_id = getattr(r, 'id', None)
            if should_delete(r_name, prefix, pattern_re) or rule_has_label(r, rule_label):
                rules.append({"id": r_id, "name": r_name, "type": "File Type Control Rule"})
    except Exception as e:
        print(f"  [EXCEPTION] File Type Control scan failed: {e}")
    return rules

def scan_app_profiles(client, prefix, pattern_re):
    print("Scanning ZCC App Profiles...")
    profiles = []
    platforms = ["windows", "macos", "linux", "android", "ios"]
    for plat in platforms:
        try:
            raw_profiles = get_all_paginated(client.zcc.web_policy.list_by_company, query_params={"device_type": plat})
            if not raw_profiles:
                continue
            for p in raw_profiles:
                p_dict = p.as_dict() if hasattr(p, "as_dict") else dict(p)
                p_name = p_dict.get("name", "")
                p_id = p_dict.get("id")
                if p_name.lower() == "default":
                    continue
                if should_delete(p_name, prefix, pattern_re):
                    profiles.append({"id": p_id, "name": p_name, "type": f"ZCC App Profile ({plat.upper()})", "platform": plat})
        except Exception as e:
            print(f"  [EXCEPTION] ZCC App Profile ({plat}) scan failed: {e}")
    return profiles

def scan_forwarding_profiles(client, prefix, pattern_re):
    print("Scanning ZCC Forwarding Profiles...")
    profiles = []
    try:
        raw_profiles = get_all_paginated(client.zcc.forwarding_profile.list_by_company)
        for p in raw_profiles:
            p_name = getattr(p, 'name', '') or ''
            p_id = getattr(p, 'id', None)
            if p_name.lower() == "default" or str(p_id) == "0":
                continue
            if should_delete(p_name, prefix, pattern_re):
                profiles.append({"id": p_id, "name": p_name, "type": "ZCC Forwarding Profile"})
    except Exception as e:
        print(f"  [EXCEPTION] Forwarding Profile scan failed: {e}")
    return profiles

def scan_firewall_rules(client, prefix, pattern_re, rule_label=None):
    print("Scanning ZIA Cloud Firewall rules...")
    rules = []
    try:
        raw_rules = get_all_paginated(client.zia.cloud_firewall_rules.list_rules)
        for r in raw_rules:
            r_name = getattr(r, 'name', '') or ''
            r_id = getattr(r, 'id', None)
            if should_delete(r_name, prefix, pattern_re) or rule_has_label(r, rule_label):
                rules.append({"id": r_id, "name": r_name, "type": "Cloud Firewall Rule"})
    except Exception as e:
        print(f"  [EXCEPTION] Cloud Firewall scan failed: {e}")
    return rules

def scan_dns_rules(client, prefix, pattern_re, rule_label=None):
    print("Scanning ZIA DNS Filtering rules...")
    rules = []
    try:
        raw_rules = get_all_paginated(client.zia.cloud_firewall_dns.list_rules)
        for r in raw_rules:
            r_name = getattr(r, 'name', '') or ''
            r_id = getattr(r, 'id', None)
            if should_delete(r_name, prefix, pattern_re) or rule_has_label(r, rule_label):
                rules.append({"id": r_id, "name": r_name, "type": "DNS Filtering Rule"})
    except Exception as e:
        print(f"  [EXCEPTION] DNS Filtering scan failed: {e}")
    return rules

def scan_trusted_networks(client, prefix, pattern_re):
    print("Scanning ZCC Trusted Networks...")
    networks = []
    try:
        raw_networks = get_all_paginated(client.zcc.trusted_networks.list_by_company)
        for net in raw_networks:
            net_dict = net.as_dict() if hasattr(net, "as_dict") else dict(net)
            net_name = net_dict.get("network_name", "")
            net_id = net_dict.get("id")
            if should_delete(net_name, prefix, pattern_re):
                networks.append({"id": net_id, "name": net_name, "type": "ZCC Trusted Network"})
    except Exception as e:
        print(f"  [EXCEPTION] ZCC Trusted Networks scan failed: {e}")
    return networks

def scan_root_certificates(client, prefix, pattern_re):
    print("Scanning ZIA Root Certificates...")
    certs = []
    try:
        url = "/zia/api/v1/rootCertificates"
        request, error = client._request_executor.create_request("GET", url, {}, {})
        if not error:
            response, error = client._request_executor.execute(request)
            if not error and response:
                body = response.get_body()
                for c in body:
                    if c.get("isDefault") or "Zscaler Root" in c.get("displayName", ""):
                        continue
                    c_name = c.get("displayName", "")
                    c_id = c.get("id")
                    if should_delete(c_name, prefix, pattern_re):
                        certs.append({"id": c_id, "name": c_name, "type": "ZIA Root Certificate"})
    except Exception as e:
        print(f"  [EXCEPTION] Root Certificate scan failed: {e}")
    return certs

def scan_proxies(client, prefix, pattern_re):
    print("Scanning ZIA Proxies...")
    proxies = []
    try:
        raw_proxies = get_all_paginated(client.zia.proxies.list_proxies)
        for p in raw_proxies:
            p_dict = p.as_dict() if hasattr(p, "as_dict") else dict(p)
            p_name = p_dict.get("name", "")
            p_id = p_dict.get("id")
            if should_delete(p_name, prefix, pattern_re):
                proxies.append({"id": p_id, "name": p_name, "type": "ZIA Proxy"})
    except Exception as e:
        print(f"  [EXCEPTION] Proxy scan failed: {e}")
    return proxies

def scan_proxy_gateways(client, prefix, pattern_re):
    print("Scanning ZIA Proxy Gateways...")
    gateways = []
    try:
        res = client.zia.proxies.list_proxy_gateways()
        raw_gws = res[0] if isinstance(res, tuple) and len(res) >= 1 else res
        for g in raw_gws or []:
            g_dict = g.as_dict() if hasattr(g, "as_dict") else dict(g)
            g_name = g_dict.get("name", "")
            g_id = g_dict.get("id")
            if should_delete(g_name, prefix, pattern_re):
                gateways.append({"id": g_id, "name": g_name, "type": "ZIA Proxy Gateway"})
    except Exception as e:
        print(f"  [EXCEPTION] Proxy Gateway scan failed: {e}")
    return gateways

def get_proxy_gateway_associations(client, proxy_id, proxy_name):
    """
    Checks all existing Proxy Gateways to see if proxy_id or proxy_name
    is referenced as primary_proxy or secondary_proxy.
    Returns list of dicts: [{'id': gw_id, 'name': gw_name, 'role': role}, ...]
    """
    associations = []
    try:
        res = client.zia.proxies.list_proxy_gateways()
        gateways = res[0] if isinstance(res, tuple) and len(res) >= 1 else res
        for gw in gateways or []:
            gw_dict = gw.as_dict() if hasattr(gw, "as_dict") else dict(gw)
            gw_name = gw_dict.get("name", "")
            gw_id = gw_dict.get("id")
            
            # Check primary_proxy
            primary = gw_dict.get("primary_proxy") or gw_dict.get("primaryProxy")
            if primary and isinstance(primary, dict):
                p_id = primary.get("id")
                p_name = primary.get("name", "")
                if (proxy_id is not None and str(p_id) == str(proxy_id)) or (proxy_name and str(p_name).lower() == str(proxy_name).lower()):
                    associations.append({"id": gw_id, "name": gw_name, "role": "Primary Proxy"})
                    continue
            
            # Check secondary_proxy
            secondary = gw_dict.get("secondary_proxy") or gw_dict.get("secondaryProxy")
            if secondary and isinstance(secondary, dict):
                s_id = secondary.get("id")
                s_name = secondary.get("name", "")
                if (proxy_id is not None and str(s_id) == str(proxy_id)) or (proxy_name and str(s_name).lower() == str(proxy_name).lower()):
                    associations.append({"id": gw_id, "name": gw_name, "role": "Secondary Proxy"})
    except Exception as e:
        print(f"  [WARNING] Could not check Proxy Gateway associations: {e}")
    return associations

def scan_forwarding_rules(client, prefix, pattern_re, rule_label=None):
    print("Scanning ZIA Forwarding Control rules...")
    rules = []
    try:
        raw_rules = get_all_paginated(client.zia.forwarding_control.list_rules)
        for r in raw_rules:
            r_name = getattr(r, 'name', '') or ''
            r_id = getattr(r, 'id', None)
            r_order = getattr(r, 'order', 0)
            if r_order < 0:
                continue
            if should_delete(r_name, prefix, pattern_re) or rule_has_label(r, rule_label):
                rules.append({"id": r_id, "name": r_name, "type": "Forwarding Control Rule"})
    except Exception as e:
        print(f"  [EXCEPTION] Forwarding Control scan failed: {e}")
    return rules

def scan_zpa_access_rules(client, prefix, pattern_re):
    print("Scanning ZPA Access Rules...")
    items = []
    try:
        rules = get_all_paginated(client.zpa.policies.list_rules, policy_type='access')
        for r in rules or []:
            if should_delete(r.name, prefix, pattern_re):
                items.append({'type': 'ZPA Access Rule', 'id': r.id, 'name': r.name})
    except Exception as e:
        print(f'Error scanning ZPA Access Rules: {e}')
    return items

def scan_zpa_timeout_rules(client, prefix, pattern_re):
    print("Scanning ZPA Timeout Rules...")
    items = []
    try:
        rules = get_all_paginated(client.zpa.policies.list_rules, policy_type='timeout')
        for r in rules or []:
            if r.name != 'Default_Rule' and should_delete(r.name, prefix, pattern_re):
                items.append({'type': 'ZPA Timeout Rule', 'id': r.id, 'name': r.name})
    except Exception as e:
        print(f'Error scanning ZPA Timeout Rules: {e}')
    return items

def scan_zpa_fwd_rules(client, prefix, pattern_re):
    print("Scanning ZPA Client Forwarding Rules...")
    items = []
    try:
        rules = get_all_paginated(client.zpa.policies.list_rules, policy_type='client_forwarding')
        for r in rules or []:
            if r.name != 'Default_Rule' and r.name != 'Zscaler Deception' and should_delete(r.name, prefix, pattern_re):
                items.append({'type': 'ZPA CF Rule', 'id': r.id, 'name': r.name})
    except Exception as e:
        print(f'Error scanning ZPA Client Forwarding Rules: {e}')
    return items

def scan_zpa_app_segments(client, prefix, pattern_re):
    print("Scanning ZPA App Segments...")
    items = []
    try:
        segs = get_all_paginated(client.zpa.application_segment.list_segments)
        for s in segs or []:
            if should_delete(s.name, prefix, pattern_re):
                items.append({'type': 'ZPA App Segment', 'id': s.id, 'name': s.name})
    except Exception as e:
        print(f'Error scanning ZPA App Segments: {e}')
    return items

def scan_zpa_segment_groups(client, prefix, pattern_re):
    print("Scanning ZPA Segment Groups...")
    items = []
    try:
        segs = get_all_paginated(client.zpa.segment_groups.list_groups)
        for s in segs or []:
            if should_delete(s.name, prefix, pattern_re):
                items.append({'type': 'ZPA Segment Group', 'id': s.id, 'name': s.name})
    except Exception as e:
        print(f'Error scanning ZPA Segment Groups: {e}')
    return items

def scan_zpa_server_groups(client, prefix, pattern_re):
    print("Scanning ZPA Server Groups...")
    items = []
    try:
        grps = get_all_paginated(client.zpa.server_groups.list_groups)
        for g in grps or []:
            if should_delete(g.name, prefix, pattern_re):
                items.append({'type': 'ZPA Server Group', 'id': g.id, 'name': g.name})
    except Exception as e:
        print(f'Error scanning ZPA Server Groups: {e}')
    return items

def scan_zpa_conn_groups(client, prefix, pattern_re):
    print("Scanning ZPA Connector Groups...")
    items = []
    try:
        cgs = get_all_paginated(client.zpa.app_connector_groups.list_connector_groups)
        for c in cgs or []:
            if should_delete(c.name, prefix, pattern_re):
                items.append({'type': 'ZPA Conn Group', 'id': c.id, 'name': c.name})
    except Exception as e:
        print(f'Error scanning ZPA Connector Groups: {e}')
    return items

def scan_zpa_dns_domains(client, prefix, pattern_re):
    print("Scanning ZPA DNS Domains...")
    items = []
    try:
        _, resp, _ = client.zpa.customer_domain.list_domains(type='SEARCH_SUFFIX')
        if resp:
            body = resp.get_body() or []
            if isinstance(body, list):
                for d in body:
                    domain_name = d.get('domain')
                    if domain_name and should_delete(domain_name, prefix, pattern_re):
                        items.append({'type': 'ZPA DNS Domain', 'id': domain_name, 'name': domain_name})
    except Exception as e:
        print(f'Error scanning ZPA DNS Domains: {e}')
    return items

def scan_pac_files(client, prefix, pattern_re):
    print("Scanning ZIA Hosted PAC files...")
    pac_files = []
    try:
        raw_pacs = get_all_paginated(client.zia.pac_files.list_pac_files)
        for p in raw_pacs:
            p_dict = p.as_dict() if hasattr(p, "as_dict") else dict(p)
            p_name = p_dict.get("name", "")
            p_id = p_dict.get("id")
            if should_delete(p_name, prefix, pattern_re):
                pac_files.append({"id": p_id, "name": p_name, "type": "ZIA PAC File"})
    except Exception as e:
        print(f"  [EXCEPTION] PAC file scan failed: {e}")
    return pac_files

def scan_rule_labels(client, prefix, pattern_re, rule_label=None):
    print("Scanning ZIA Rule Labels...")
    labels = []
    try:
        raw_labels = get_all_paginated(client.zia.rule_labels.list_labels)
        for lbl in raw_labels:
            lbl_name = getattr(lbl, 'name', '') or ''
            lbl_id = getattr(lbl, 'id', None)
            matches = should_delete(lbl_name, prefix, pattern_re)
            if not matches and rule_label:
                if rule_label.lower() in lbl_name.lower():
                    matches = True
            if matches:
                labels.append({"id": lbl_id, "name": lbl_name, "type": "ZIA Rule Label"})
    except Exception as e:
        print(f"  [EXCEPTION] Rule Labels scan failed: {e}")
    return labels

def main():
    parser = argparse.ArgumentParser(
        description="Tenant Policy Cleanup Script - Deletes test profiles and rules from ZIA/ZCC based on prefix or regex pattern."
    )
    parser.add_argument(
        "-e", "--env-file",
        required=True,
        help="Path to environment file (e.g. .env.tenant)"
    )
    parser.add_argument(
        "-p", "--prefix",
        help="Case-insensitive name prefix to match (e.g. 'TT')"
    )
    parser.add_argument(
        "--pattern",
        help="Regex pattern to match names against (e.g. '^TT - POV.*')"
    )
    parser.add_argument(
        "-d", "--dry-run",
        action="store_true",
        help="List matching items without deleting them"
    )
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List matching items and exit without deleting (alias for --dry-run)"
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Bypass interactive confirmation prompt when deleting"
    )
    parser.add_argument(
        "-m", "--modules",
        help="Comma-separated list of modules to clean (choices: app-profiles, fwd-profiles, url-rules, casb-rules, ssl-rules, file-rules, url-cat, ip-dest-groups, ip-src-groups, firewall-rules, dns-rules, trusted-networks, root-certs, proxies, proxy-gws, fwd-rules, pac-files, rule-labels, zpa-access-rules, zpa-timeout-rules, zpa-fwd-rules, zpa-app-segments, zpa-segment-groups, zpa-server-groups, zpa-conn-groups, zpa-dns-domains)"
    )
    parser.add_argument(
        "--rule-label",
        default=None,
        help="Delete rules tagged with this Rule Label, as well as the Rule Label itself."
    )
    parser.add_argument(
        "--zia",
        action="store_true",
        help="Scan all ZIA modules"
    )
    parser.add_argument(
        "--zcc",
        action="store_true",
        help="Scan all ZCC modules"
    )
    parser.add_argument(
        "--zpa",
        action="store_true",
        help="Scan all ZPA modules"
    )
    parser.add_argument(
        "-a", "--activate",
        action="store_true",
        help="Activate ZIA configuration changes after applying"
    )

    args = parser.parse_args()

    # Validate filters
    if not args.prefix and not args.pattern and not args.rule_label:
        parser.error("You must specify either a --prefix (-p), --pattern, or --rule-label to filter objects for deletion.")

    pattern_re = None
    if args.pattern:
        try:
            pattern_re = re.compile(args.pattern, re.IGNORECASE)
        except re.error as e:
            parser.error(f"Invalid regex pattern: {e}")

    # Load environment variables
    load_env_file(args.env_file)

    # Determine modules to clean
    ZIA_MODULES = ["url-rules", "casb-rules", "ssl-rules", "file-rules", "url-cat", "ip-dest-groups", "ip-src-groups", "firewall-rules", "dns-rules", "root-certs", "proxies", "proxy-gws", "fwd-rules", "pac-files", "rule-labels"]
    ZCC_MODULES = ["app-profiles", "fwd-profiles", "trusted-networks"]
    ZPA_MODULES = ["zpa-access-rules", "zpa-timeout-rules", "zpa-fwd-rules", "zpa-app-segments", "zpa-segment-groups", "zpa-server-groups", "zpa-conn-groups", "zpa-dns-domains"]
    all_valid_modules = ZIA_MODULES + ZCC_MODULES + ZPA_MODULES

    modules = set()
    if args.modules:
        for m in args.modules.split(","):
            m = m.strip().lower()
            if m not in all_valid_modules:
                parser.error(f"Invalid module: {m}. Valid modules are: " + ", ".join(all_valid_modules))
            modules.add(m)

    if args.zia:
        modules.update(ZIA_MODULES)
    if args.zcc:
        modules.update(ZCC_MODULES)
    if args.zpa:
        modules.update(ZPA_MODULES)

    if not modules:
        modules = set(all_valid_modules)

    modules = list(modules)

    # Authenticate Client
    # Set ZPA Customer ID default if not present
    if os.getenv("ZSCALER_CUSTOMER_ID") and not os.getenv("ZPA_CUSTOMER_ID"):
        os.environ["ZPA_CUSTOMER_ID"] = os.getenv("ZSCALER_CUSTOMER_ID")

    print("Authenticating Zscaler client...")
    try:
        client = get_zscaler_client()
    except Exception as e:
        print(f"[ERROR] Failed to authenticate client: {e}")
        sys.exit(1)

    print("\n--- Scanning for Matching Policies ---")
    items_to_delete = []

    if "app-profiles" in modules:
        items_to_delete.extend(scan_app_profiles(client, args.prefix, pattern_re))
    if "fwd-profiles" in modules:
        items_to_delete.extend(scan_forwarding_profiles(client, args.prefix, pattern_re))
    if "url-rules" in modules:
        items_to_delete.extend(scan_url_filtering(client, args.prefix, pattern_re, args.rule_label))
    if "casb-rules" in modules:
        items_to_delete.extend(scan_casb_rules(client, args.prefix, pattern_re, args.rule_label))
    if "ssl-rules" in modules:
        items_to_delete.extend(scan_ssl_inspection(client, args.prefix, pattern_re, args.rule_label))
    if "file-rules" in modules:
        items_to_delete.extend(scan_file_type_rules(client, args.prefix, pattern_re, args.rule_label))
    if "url-cat" in modules:
        items_to_delete.extend(scan_url_categories(client, args.prefix, pattern_re))
    if "ip-dest-groups" in modules:
        items_to_delete.extend(scan_ip_destination_groups(client, args.prefix, pattern_re))
    if "ip-src-groups" in modules:
        items_to_delete.extend(scan_ip_source_groups(client, args.prefix, pattern_re))
    if "firewall-rules" in modules:
        items_to_delete.extend(scan_firewall_rules(client, args.prefix, pattern_re, args.rule_label))
    if "dns-rules" in modules:
        items_to_delete.extend(scan_dns_rules(client, args.prefix, pattern_re, args.rule_label))
    if "trusted-networks" in modules:
        items_to_delete.extend(scan_trusted_networks(client, args.prefix, pattern_re))
    if "root-certs" in modules:
        items_to_delete.extend(scan_root_certificates(client, args.prefix, pattern_re))
    if "proxies" in modules:
        items_to_delete.extend(scan_proxies(client, args.prefix, pattern_re))
    if "proxy-gws" in modules:
        items_to_delete.extend(scan_proxy_gateways(client, args.prefix, pattern_re))

    if "fwd-rules" in modules:
        items_to_delete.extend(scan_forwarding_rules(client, args.prefix, pattern_re, args.rule_label))
    if "pac-files" in modules:
        items_to_delete.extend(scan_pac_files(client, args.prefix, pattern_re))
    if "rule-labels" in modules:
        items_to_delete.extend(scan_rule_labels(client, args.prefix, pattern_re, args.rule_label))
    if "zpa-access-rules" in modules:
        items_to_delete.extend(scan_zpa_access_rules(client, args.prefix, pattern_re))
    if "zpa-timeout-rules" in modules:
        items_to_delete.extend(scan_zpa_timeout_rules(client, args.prefix, pattern_re))
    if "zpa-fwd-rules" in modules:
        items_to_delete.extend(scan_zpa_fwd_rules(client, args.prefix, pattern_re))
    if "zpa-app-segments" in modules:
        items_to_delete.extend(scan_zpa_app_segments(client, args.prefix, pattern_re))
    if "zpa-segment-groups" in modules:
        items_to_delete.extend(scan_zpa_segment_groups(client, args.prefix, pattern_re))
    if "zpa-server-groups" in modules:
        items_to_delete.extend(scan_zpa_server_groups(client, args.prefix, pattern_re))
    if "zpa-conn-groups" in modules:
        items_to_delete.extend(scan_zpa_conn_groups(client, args.prefix, pattern_re))
    if "zpa-dns-domains" in modules:
        items_to_delete.extend(scan_zpa_dns_domains(client, args.prefix, pattern_re))

    # Define strict deletion order (lowest index = deleted first)
    order_map = {
        "ZPA Access Rule": 1,
        "ZPA Timeout Rule": 1,
        "ZPA CF Rule": 1,
        "ZPA App Segment": 2,
        "ZPA Segment Group": 3,
        "ZPA Server Group": 4,
        "ZPA Conn Group": 5,
        "ZPA DNS Domain": 1,
        
        "ZIA URL Category": 30,
        "IP Destination Group": 30,
        "IP Source Group": 30,
        "ZIA Proxy Gateway": 30,
        "ZIA Proxy": 31,
        "ZIA Root Certificate": 30,
        "ZIA Trusted Network": 30,
        "ZIA PAC File": 30,
        "ZIA Rule Label": 40
    }
    items_to_delete.sort(key=lambda x: order_map.get(x["type"], 10))

    print(f"\n--- Scan Summary ({len(items_to_delete)} items found) ---")
    if not items_to_delete:
        print("No matching items found.")
        sys.exit(0)

    # Print matching items
    print(f"{'TYPE':<30} | {'ID':<15} | {'NAME':<50}")
    print("-" * 102)
    for item in items_to_delete:
        print(f"{item['type']:<30} | {str(item['id']):<15} | {item['name']:<50}")

    if args.dry_run or args.list:
        mode_str = "LIST-ONLY" if args.list else "DRY-RUN"
        print(f"\n[{mode_str}] Script completed. No changes made.")
        sys.exit(0)

    # Ask for confirmation
    if not args.force:
        confirm = input(f"\nWARNING: You are about to permanently delete these {len(items_to_delete)} items. Proceed? (y/N): ")
        if confirm.strip().lower() not in ["y", "yes"]:
            print("Operation aborted. No changes made.")
            sys.exit(0)

    print("\n--- Deleting Matching Policies ---")
    for item in items_to_delete:
        item_id = item["id"]
        item_name = item["name"]
        item_type = item["type"]
        
        try:
            print(f"Deleting {item_type} '{item_name}' (ID: {item_id})...")
            err = None
            if "URL Filtering Rule" in item_type:
                _, _, err = client.zia.url_filtering.delete_rule(int(item_id))
            elif "CASB Rule" in item_type:
                _, _, err = client.zia.cloudappcontrol.delete_rule(item["category"], int(item_id))
            elif "SSL Inspection Rule" in item_type:
                _, _, err = client.zia.ssl_inspection_rules.delete_rule(int(item_id))
            elif "File Type Control Rule" in item_type:
                _, _, err = client.zia.file_type_control_rule.delete_rule(int(item_id))
            elif "Cloud Firewall Rule" in item_type:
                _, _, err = client.zia.cloud_firewall_rules.delete_rule(int(item_id))
            elif "DNS Filtering Rule" in item_type:
                _, _, err = client.zia.cloud_firewall_dns.delete_rule(int(item_id))
            elif "ZIA URL Category" in item_type:
                _, _, err = client.zia.url_categories.delete_category(category_id=item_id)
            elif "IP Destination Group" in item_type:
                _, _, err = client.zia.cloud_firewall.delete_ip_destination_group(int(item_id))
            elif "IP Source Group" in item_type:
                _, _, err = client.zia.cloud_firewall.delete_ip_source_group(int(item_id))
            elif "ZCC App Profile" in item_type:
                _, _, err = client.zcc.web_policy.delete_web_policy(int(item_id))
            elif "ZCC Forwarding Profile" in item_type:
                _, _, err = client.zcc.forwarding_profile.delete_forwarding_profile(int(item_id))
            elif "ZCC Trusted Network" in item_type:
                _, _, err = client.zcc.trusted_networks.delete_trusted_network(int(item_id))
            elif "Forwarding Control Rule" in item_type:
                _, _, err = client.zia.forwarding_control.delete_rule(int(item_id))
            elif "ZIA Proxy Gateway" in item_type:
                print(f"  [SKIPPED] Proxy Gateways cannot be deleted via the API. Please delete '{item_name}' manually in the ZIA Admin UI.")
                continue
            elif "ZIA Proxy" in item_type:
                assocs = get_proxy_gateway_associations(client, item_id, item_name)
                if assocs:
                    print("\n" + "=" * 80)
                    print(f"[MANUAL ACTION REQUIRED] Proxy Association Detected")
                    print("=" * 80)
                    print(f"Proxy '{item_name}' (ID: {item_id}) cannot be deleted via the API because")
                    print(f"it is currently referenced by the following Proxy Gateway(s):")
                    for a in assocs:
                        print(f"  - Gateway: '{a['name']}' (ID: {a['id']}, Role: {a['role']})")
                    print("\nIMPORTANT:")
                    print("Proxy Gateways cannot be modified or deleted via the Zscaler API.")
                    print("PRIOR to answering the question below, you must log in to the ZIA Admin Portal")
                    print("and manually perform one of the following actions:")
                    print(f"  Option 1: Remove the reference to proxy '{item_name}' from the Proxy Gateway(s).")
                    print(f"  Option 2: Delete the Proxy Gateway(s) entirely.")
                    print("=" * 80)
                    
                    skip_proxy = False
                    while True:
                        print("\nHave you completed the manual cleanup in the ZIA Admin Portal?")
                        print("  [1 / yes] Yes, I've done the cleanup manually (verify and proceed with deletion)")
                        print("  [2 / no]  No, I don't want to proceed and skip the proxy cleanup")
                        choice = input("Choice (1/yes or 2/no): ").strip().lower()
                        
                        if choice in ["1", "yes", "y"]:
                            print("Verifying proxy gateway associations...")
                            assocs_remaining = get_proxy_gateway_associations(client, item_id, item_name)
                            if assocs_remaining:
                                print(f"\n[WARNING] Proxy '{item_name}' is still referenced by {len(assocs_remaining)} gateway(s):")
                                for a in assocs_remaining:
                                    print(f"  - Gateway: '{a['name']}' (ID: {a['id']}, Role: {a['role']})")
                                print("Please ensure you have saved/activated the changes in the ZIA Admin Portal.")
                                retry_choice = input("Would you like to try verification again? (y/N to skip proxy): ").strip().lower()
                                if retry_choice in ["y", "yes"]:
                                    continue
                                else:
                                    skip_proxy = True
                                    break
                            else:
                                print("  [SUCCESS] Verified: Proxy is no longer referenced by any Proxy Gateway.")
                                break
                        elif choice in ["2", "no", "n", "skip"]:
                            skip_proxy = True
                            break
                        else:
                            print("Invalid input. Please enter 'yes' (or 1) or 'no' (or 2).")

                    if skip_proxy:
                        print(f"  [SKIPPED] Skipped deletion of Proxy '{item_name}'.")
                        continue

                _, _, err = client.zia.proxies.delete_proxy(int(item_id))
            elif "ZIA PAC File" in item_type:
                _, _, err = client.zia.pac_files.delete_pac_file(int(item_id))
            elif "ZIA Rule Label" in item_type:
                _, _, err = client.zia.rule_labels.delete_label(str(item_id))
            elif "ZIA Root Certificate" in item_type:
                # ZIA API limitation: DELETE /rootCertificates/{id} is a no-op returning HTTP 204.
                # Clearing certTypes via PUT disassociates and removes the certificate from the tenant.
                put_url = f"/zia/api/v1/rootCertificates/{item_id}"
                request, error = client._request_executor.create_request("PUT", put_url, {"certTypes": []}, {})
                if not error:
                    _, err = client._request_executor.execute(request)
                else:
                    err = error

                del_url = f"/zia/api/v1/rootCertificates/{item_id}"
                del_req, del_err = client._request_executor.create_request("DELETE", del_url, {}, {})
                if not del_err:
                    _, _ = client._request_executor.execute(del_req)
            elif item_type == "ZPA Access Rule":
                _, _, err = client.zpa.policies.delete_rule(rule_id=item_id, policy_type='access')
            elif item_type == "ZPA Timeout Rule":
                _, _, err = client.zpa.policies.delete_rule(rule_id=item_id, policy_type='timeout')
            elif item_type == "ZPA CF Rule":
                _, _, err = client.zpa.policies.delete_rule(rule_id=item_id, policy_type='client_forwarding')
            elif item_type == "ZPA App Segment":
                _, _, err = client.zpa.application_segment.delete_segment(segment_id=item_id)
            elif item_type == "ZPA Segment Group":
                _, _, err = client.zpa.segment_groups.delete_group(group_id=item_id)
            elif item_type == "ZPA Server Group":
                _, _, err = client.zpa.server_groups.delete_group(group_id=item_id)
            elif item_type == "ZPA Conn Group":
                _, _, err = client.zpa.app_connector_groups.delete_connector_group(group_id=item_id)
            elif item_type == "ZPA DNS Domain":
                _, resp, _ = client.zpa.customer_domain.list_domains(type="SEARCH_SUFFIX")
                if resp:
                    body = resp.get_body() or []
                    if isinstance(body, list):
                        new_domains = [{"domain": d.get("domain")} for d in body if d.get("domain") != item_id]
                        _, _, err = client.zpa.customer_domain.add_update_domain(type="SEARCH_SUFFIX", domain_list=new_domains)
            
            if err:
                print(f"  [ERROR] Deletion failed: {err}")
            else:
                print(f"  [SUCCESS] Deleted '{item_name}'.")
        except Exception as e:
            print(f"  [EXCEPTION] Error deleting '{item_name}': {e}")

    if args.activate and args.zia and not args.dry_run and not args.list:
        print("\n--- Activating ZIA Configuration ---")
        try:
            _, _, err = client.zia.activate.activate()
            if err:
                print(f"  [ERROR] Activation failed: {err}")
            else:
                print("  [SUCCESS] ZIA configuration activated.")
        except Exception as e:
            print(f"  [EXCEPTION] Error activating configuration: {e}")
    elif args.activate and (args.dry_run or args.list):
        print("\n--- Activating ZIA Configuration (SKIPPED - Dry Run) ---")

    print("\nCleanup completed.")

if __name__ == "__main__":
    main()
