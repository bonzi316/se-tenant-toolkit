import yaml
import logging
import click
import sys
import os
from typing import Dict, Any, List
from zscaler import ZscalerClient

logger = logging.getLogger("src")

# ==============================================================================
# Helper functions
# ==============================================================================
def seconds_to_human(seconds_val):
    if seconds_val is None or seconds_val == "":
        return None
    try:
        sec = int(seconds_val)
    except ValueError:
        return str(seconds_val)
        
    if sec == -1:
        return "never"
    if sec == 0:
        return "0"
        
    if sec % 86400 == 0:
        return f"{sec // 86400}d"
    elif sec % 3600 == 0:
        return f"{sec // 3600}h"
    elif sec % 60 == 0:
        return f"{sec // 60}m"
    else:
        return f"{sec}s"

def clean_zcc_dict(d: Any) -> Any:
    """Recursively cleans ZCC dict from as_dict() output for clean YAML output."""
    if isinstance(d, str):
        if (d.startswith("https://pac.") or "/pac." in d) and "/" in d:
            import urllib.parse
            raw_pac = urllib.parse.unquote(d.split("/")[-1])
            return raw_pac.replace(" ", "_")
        return d
    if isinstance(d, list):
        return [clean_zcc_dict(x) for x in d]
    if isinstance(d, dict):
        new_d = {}
        key_normalize = {
            "enable_l_w_f_driver": "enable_lwf_driver",
            "enable_split_vpn_t_n": "enable_split_vpn_tn",
            "enable_all_default_adapters_t_n": "enable_all_default_adapters_tn",
            "d_t_l_s_timeout": "dtls_timeout",
            "t_l_s_timeout": "tls_timeout",
            "u_d_p_timeout": "udp_timeout",
            "allow_t_l_s_fallback": "allow_tls_fallback",
            "action_type_z_i_a": "action_type_zia",
            "action_type_z_p_a": "action_type_zpa",
            "bypass_proxy_for_private_i_p": "bypass_proxy_for_private_ip",
            "enable_p_a_c": "enable_pac",
            "perform_g_p_update": "perform_gp_update",
            "latency_based_server_m_t_enablement": "latency_based_server_mt_enablement",
            "is_same_as_on_trusted_network": "same_as_on_trusted",
            "send_trusted_network_result_to_zpa": "send_trusted_network_result_to_zpa"
        }
        for k, v in d.items():
            if v is None or v == "" or v == []:
                continue
            if k in ["id", "last_modified_time", "last_modified_by", "access_control", "policy_id", "company_id", "created_by", "edited_by", "guid"]:
                continue
            
            k_clean = key_normalize.get(k, k)
            v_clean = v
            if k_clean == "device_type" and isinstance(v, str):
                v_clean = v.replace("DEVICE_TYPE_", "").lower()

            new_d[k_clean] = clean_zcc_dict(v_clean)
        return new_d
    return d

# ==============================================================================
# Load / Save Combined YAML Wrapper
# ==============================================================================
def load_existing_yaml(path: str) -> Dict[str, Any]:
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            logger.warning(f"Could not load existing YAML file {path}: {e}")
    return {"version": "1.0"}

def reorder_keys_make_name_first(d: Any) -> Any:
    if isinstance(d, dict):
        new_d = {}
        if "name" in d:
            new_d["name"] = reorder_keys_make_name_first(d["name"])
        for k, v in d.items():
            if k != "name":
                new_d[k] = reorder_keys_make_name_first(v)
        return new_d
    elif isinstance(d, list):
        return [reorder_keys_make_name_first(x) for x in d]
    return d

def save_yaml(path: str, data: Dict[str, Any]):
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        # Reorder keys to make 'name' first
        ordered_data = reorder_keys_make_name_first(data)
        with open(path, "w") as f:
            yaml.safe_dump(ordered_data, f, default_flow_style=False, sort_keys=False)
        logger.info(f"Configurations exported successfully to: {path}")
        click.echo(f"YAML config updated at: {path}")
    except Exception as e:
        logger.error(f"Failed to write exported YAML configuration: {e}")
        sys.exit(1)

# ==============================================================================
# Exporter Modules
# ==============================================================================
def export_zcc_presets(client: ZscalerClient, search_query: str = None, out_path: str = "pov_preset_exported.yaml"):
    """Fetches, filters, and exports ZCC configuration settings."""
    logger.info("Starting complete ZCC configurations exporter...")
    
    # 1. Forwarding Profiles
    profiles_fp, _, err = client.zcc.forwarding_profile.list_by_company()
    if err:
        logger.error(f"Failed to list forwarding profiles: {err}")
        sys.exit(1)
        
    # 2. Application Profiles (Web Policies)
    profiles_ap, _, err = client.zcc.application_profiles.get_application_profiles()
    if err:
        logger.error(f"Failed to list application profiles: {err}")
        sys.exit(1)

    def matches(name: str) -> bool:
        if not name:
            return False
        if search_query is not None:
            return search_query.lower() in name.lower()
        return True

    filtered_fp = [p for p in profiles_fp if matches(p.name)]
    filtered_ap = [p for p in profiles_ap if matches(p.name)]

    logger.info(f"Found {len(filtered_fp)} forwarding profiles and {len(filtered_ap)} application profiles to export.")

    zcc_config = {
        "forwarding_profiles": [],
        "app_profiles": {},
        "trusted_networks": [],
        "web_privacy": {},
        "device_cleanup": {},
        "notification_templates": [],
        "custom_ip_bypasses": [],
        "custom_process_bypasses": [],
        "posture_check": [],
        "posture_profile": {
            "windows": [],
            "macos": [],
            "linux": [],
            "ios": [],
            "android": []
        },
        "company_info": {}
    }

    # Process Forwarding Profiles
    for fp in filtered_fp:
        fp_dict = clean_zcc_dict(fp.as_dict())
        zcc_config["forwarding_profiles"].append({
            "search_name": fp.name,
            "update": fp_dict
        })
        logger.info(f"Exported Forwarding Profile: '{fp.name}'")

    # Sort Forwarding Profiles alphabetically by update name
    zcc_config["forwarding_profiles"].sort(key=lambda x: x["update"].get("name", "").lower())

    # Collect notification templates from App Profiles to create a clean reference section
    seen_templates = set()

    # Process Application Profiles
    for ap in filtered_ap:
        ap_dict = clean_zcc_dict(ap.as_dict())
        device_type = ap_dict.get("device_type", "windows")
        
        # Link to Forwarding Profile by name rather than ID
        on_net_policy = ap_dict.pop("on_net_policy", None)
        if on_net_policy and isinstance(on_net_policy, dict):
            fwd_ref_name = on_net_policy.get("name")
            if fwd_ref_name:
                ap_dict["forwarding_profile_name"] = fwd_ref_name
                logger.info(f"Linked Application Profile '{ap.name}' to Forwarding Profile name: '{fwd_ref_name}'")

        # Extract ZIA posture config to global posture_profile and link by name
        ap_dict.pop("zia_posture_config_id", None)
        zia_posture = ap_dict.pop("zia_posture_config", None)
        if zia_posture and isinstance(zia_posture, dict):
            profile_name = zia_posture.get("name")
            if profile_name:
                ap_dict["posture_profile_name"] = profile_name
                logger.info(f"Linked Application Profile '{ap.name}' to Posture Profile: '{profile_name}'")
                
                # Add to global list if not already present
                existing_profiles = zcc_config["posture_profile"].get(device_type, [])
                if not any(ep.get("name") == profile_name for ep in existing_profiles):
                    zcc_config["posture_profile"][device_type].append(zia_posture)

        # Extract notification templates contract for reference
        notif_contract = ap_dict.get("notification_template_contract")
        if notif_contract and isinstance(notif_contract, dict):
            t_id = notif_contract.get("id")
            t_name = notif_contract.get("name")
            if t_id and t_id not in seen_templates:
                seen_templates.add(t_id)
                zcc_config["notification_templates"].append({
                    "id": t_id,
                    "name": t_name
                })

        ap_entry = {
            "search_name": ap.name,
            "update": ap_dict
        }

        if device_type not in zcc_config["app_profiles"]:
            zcc_config["app_profiles"][device_type] = []
        zcc_config["app_profiles"][device_type].append(ap_entry)
        logger.info(f"Exported Application Profile: '{ap.name}' ({device_type})")

    # Sort Application Profiles alphabetically by update name for each platform
    for platform_key in zcc_config["app_profiles"]:
        zcc_config["app_profiles"][platform_key].sort(key=lambda x: x["update"].get("name", "").lower())

    # 3. Trusted Networks
    logger.info("Fetching Trusted Networks...")
    networks, _, err = client.zcc.trusted_networks.list_by_company()
    if not err and networks:
        for net in networks:
            net_dict = clean_zcc_dict(net.as_dict())
            zcc_config["trusted_networks"].append(net_dict)
            logger.info(f"Exported Trusted Network: '{net.network_name}'")
        # Sort Trusted Networks alphabetically by network_name
        zcc_config["trusted_networks"].sort(key=lambda x: x.get("network_name", "").lower())
    else:
        logger.warning(f"Could not retrieve trusted networks or none configured. Error: {err}")

    # 4. Web Privacy Settings (Global)
    logger.info("Fetching Web Privacy settings...")
    privacy_info = client.zcc.web_privacy.get_web_privacy()
    if isinstance(privacy_info, dict):
        zcc_config["web_privacy"] = clean_zcc_dict(privacy_info)
        logger.info("Exported Web Privacy settings.")
    else:
        logger.warning("Could not retrieve Web Privacy settings.")

    # 5. Device Cleanup Settings (Global)
    logger.info("Fetching Device Cleanup settings...")
    cleanup_info, _, err = client.zcc.devices.get_device_cleanup_info()
    if not err and cleanup_info:
        # cleanup_info is returned as a list of dict/objects, grab the first one
        target_cleanup = cleanup_info[0]
        if hasattr(target_cleanup, "as_dict"):
            target_cleanup = target_cleanup.as_dict()
        zcc_config["device_cleanup"] = clean_zcc_dict(target_cleanup)
        logger.info("Exported Device Cleanup settings.")
    else:
        logger.warning(f"Could not retrieve Device Cleanup settings. Error: {err}")

    # 6. Custom IP-Based Application Bypasses (Read-only reference)
    logger.info("Fetching Custom IP-based bypass apps...")
    try:
        ip_apps, _, err = client.zcc.custom_ip_base_apps.get_custom_ip_base_apps()
        if not err and ip_apps:
            for item in ip_apps:
                # The response structure has customAppContracts
                contracts = item.get("customAppContracts") or item.get("custom_app_contracts") or [] if isinstance(item, dict) else []
                if not contracts and hasattr(item, "as_dict"):
                    contracts = item.as_dict().get("custom_app_contracts", [])
                for contract in contracts:
                    zcc_config["custom_ip_bypasses"].append(clean_zcc_dict(contract))
            logger.info(f"Exported {len(zcc_config['custom_ip_bypasses'])} Custom IP-based bypass apps.")
    except Exception as ex:
        logger.warning(f"Could not retrieve Custom IP-based apps: {ex}")

    # 7. Custom Process-Based Application Bypasses (Read-only reference)
    logger.info("Fetching Process-based bypass apps...")
    try:
        process_apps, _, err = client.zcc.process_based_apps.get_process_based_apps()
        if not err and process_apps:
            for item in process_apps:
                contracts = item.get("processAppContracts") or item.get("process_app_contracts") or [] if isinstance(item, dict) else []
                if not contracts and hasattr(item, "as_dict"):
                    contracts = item.as_dict().get("process_app_contracts", [])
                for contract in contracts:
                    zcc_config["custom_process_bypasses"].append(clean_zcc_dict(contract))
            logger.info(f"Exported {len(zcc_config['custom_process_bypasses'])} Custom Process-based bypass apps.")
    except Exception as ex:
        logger.warning(f"Could not retrieve Process-based apps: {ex}")

    # 8. Company Info & Global Update settings (Read-only reference)
    logger.info("Fetching Company Info settings...")
    try:
        comp_info, _, err = client.zcc.company.get_company_info()
        if not err and comp_info:
            target_comp = comp_info[0]
            if hasattr(target_comp, "as_dict"):
                target_comp = target_comp.as_dict()
            zcc_config["company_info"] = clean_zcc_dict(target_comp)
            logger.info("Exported Company Info settings.")
    except Exception as ex:
        logger.warning(f"Could not retrieve Company Info: {ex}")

    # 9. ZPA Posture Profiles (renamed to posture_check)
    logger.info("Fetching ZPA Posture Profiles (Posture Checks)...")
    try:
        postures, _, err = client.zpa.posture_profiles.list_posture_profiles()
        if not err and postures:
            for p in postures:
                p_dict = p.as_dict() if hasattr(p, "as_dict") else p
                p_clean = clean_zcc_dict(p_dict)
                
                # Remove ZPA specific metadata keys
                for key in ["id", "creation_time", "modified_time", "modified_by", "zscaler_cloud"]:
                    p_clean.pop(key, None)
                
                # Strip cloud domain suffix from name if present
                name = p_clean.get("name")
                if name:
                    p_clean["name"] = name.split(" (")[0] if " (" in name else name
                
                zcc_config["posture_check"].append(p_clean)
            logger.info(f"Exported {len(zcc_config['posture_check'])} Posture Checks (cleaned).")
    except Exception as ex:
        logger.warning(f"Could not retrieve Posture Checks: {ex}")

    yaml_data = load_existing_yaml(out_path)
    yaml_data["zcc"] = zcc_config
    save_yaml(out_path, yaml_data)

# ==============================================================================
# ZIA Exporter Methods
# ==============================================================================
def clean_zia_dict(d: Any) -> Any:
    """Recursively cleans ZIA dict from as_dict() output for clean YAML output."""
    if isinstance(d, list):
        return [clean_zia_dict(x) for x in d]
    if isinstance(d, dict):
        new_d = {}
        for k, v in d.items():
            if v is None or v == "" or v == []:
                continue
            # Remove read-only / metadata keys
            if k in ["last_modified_by", "last_modified_time", "access_control", "org_id", "pdomain"]:
                continue
            # Strip logo_base64_data since it is huge binary data
            if k == "logo_base64_data":
                continue
            # Normalize labels to portable name-based representation
            if k == "labels" and isinstance(v, list):
                cleaned_labels = []
                for item in v:
                    if isinstance(item, dict) and item.get("name"):
                        cleaned_labels.append({"name": item["name"]})
                    elif isinstance(item, str):
                        cleaned_labels.append({"name": item})
                if cleaned_labels:
                    new_d[k] = cleaned_labels
                continue
            new_d[k] = clean_zia_dict(v)
        return new_d
    return d

def export_zia_presets(client: ZscalerClient, out_path: str = "pov_preset_exported.yaml"):
    """Fetches, cleans, and exports ZIA configuration settings."""
    logger.info("Starting complete ZIA configurations exporter...")
    
    zia_config = {
        "rule_labels": [],
        "url_categories": [],
        "advanced_settings": {},
        "url_filtering_settings": {},
        "company_profile": {},
        "threat_protection": {},
        "malware_policy": {},
        "atp_policy": {},
        "ssl_policy": [],
        "pac_files": [],
        "ip_destination_groups": [],
        "ip_source_groups": [],
        "file_type_rules": [],
        "firewall_rules": [],
        "dns_rules": [],
        "root_certificates": [],
        "proxies": [],
        "proxy_gateways": [],
        "forwarding_rules": []
    }
    
    # Build lookup map for CUSTOM categories mapping (ID -> configured_name)
    custom_cat_id_to_name = {}
    
    # 1. URL Categories (Only user-defined/custom categories)
    logger.info("Fetching ZIA URL Categories...")
    try:
        cats, _, err = client.zia.url_categories.list_categories()
        if not err and cats:
            # First, populate lookup mapping
            for cat in cats:
                cat_dict = cat.as_dict() if hasattr(cat, "as_dict") else cat
                cat_id = cat_dict.get("id")
                if cat_id and cat_dict.get("custom_category") is True:
                    cfg_name = cat_dict.get("configured_name") or cat_dict.get("name")
                    if cfg_name:
                        custom_cat_id_to_name[cat_id] = cfg_name

            # Next, clean and filter custom categories
            custom_cats = []
            for cat in cats:
                cat_dict = cat.as_dict() if hasattr(cat, "as_dict") else cat
                if cat_dict.get("custom_category") is True:
                    cleaned_cat = clean_zia_dict(cat_dict)
                    # Remove internal ID to avoid redundancy
                    cleaned_cat.pop("id", None)
                    custom_cats.append(cleaned_cat)
            
            # Sort URL Categories alphabetically by configured_name
            custom_cats.sort(key=lambda x: (x.get("configured_name") or x.get("name") or "").lower())
            zia_config["url_categories"] = custom_cats
            logger.info(f"Exported {len(custom_cats)} custom URL categories.")
        else:
            logger.warning(f"Could not retrieve URL Categories or none configured. Error: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA URL Categories: {e}")

    # 2. ZIA Settings & Advanced Settings
    logger.info("Fetching ZIA Advanced Settings...")
    try:
        adv, _, err = client.zia.advanced_settings.get_advanced_settings()
        if not err and adv:
            adv_dict = adv.as_dict() if hasattr(adv, "as_dict") else adv
            zia_config["advanced_settings"] = clean_zia_dict(adv_dict)
            logger.info("Exported ZIA Advanced Settings.")
        else:
            logger.warning(f"Could not retrieve ZIA Advanced Settings. Error: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA Advanced Settings: {e}")

    # 2.5 ZIA URL & Cloud App Advanced Settings
    logger.info("Fetching ZIA URL & Cloud App Advanced Settings...")
    try:
        url_app, response, err = client.zia.url_filtering.get_url_and_app_settings()
        if not err and response:
            # Use raw dictionary to capture all undocumented AI Prompt / settings fields
            url_app_dict = response.get_body()
            zia_config["url_filtering_settings"] = clean_zia_dict(url_app_dict)
            logger.info("Exported ZIA URL & Cloud App Advanced Settings.")
        else:
            logger.warning(f"Could not retrieve ZIA URL & Cloud App Advanced Settings. Error: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA URL & Cloud App Advanced Settings: {e}")

    # 3. Company Profile
    logger.info("Fetching ZIA Company Profile (Org Info)...")
    try:
        org, _, err = client.zia.organization_information.get_organization_information()
        if not err and org:
            org_dict = org.as_dict() if hasattr(org, "as_dict") else org
            zia_config["company_profile"] = clean_zia_dict(org_dict)
            logger.info("Exported ZIA Company Profile.")
        else:
            logger.warning(f"Could not retrieve ZIA Company Profile. Error: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA Company Profile: {e}")

    # 4. Threat Protection Configuration (Policy - Malware Policy, Protocols, Inspection)
    logger.info("Fetching ZIA Threat Protection Configuration...")
    try:
        # Policy
        pol, _, err_pol = client.zia.malware_protection_policy.get_atp_malware_policy()
        pol_dict = (pol.as_dict() if hasattr(pol, "as_dict") else pol) if not err_pol else {}
        
        # Protocols
        proto, _, err_proto = client.zia.malware_protection_policy.get_atp_malware_protocols()
        proto_dict = (proto.as_dict() if hasattr(proto, "as_dict") else proto) if not err_proto else {}
        
        # Inspection
        insp, _, err_insp = client.zia.malware_protection_policy.get_atp_malware_inspection()
        insp_dict = (insp.as_dict() if hasattr(insp, "as_dict") else insp) if not err_insp else {}
        
        threat_prot = {}
        if pol_dict:
            threat_prot["policy"] = clean_zia_dict(pol_dict)
        if proto_dict:
            threat_prot["protocols"] = clean_zia_dict(proto_dict)
        if insp_dict:
            threat_prot["inspection"] = clean_zia_dict(insp_dict)
            
        if threat_prot:
            zia_config["threat_protection"] = threat_prot
            logger.info("Exported ZIA Threat Protection configuration.")
        else:
            logger.warning("Could not retrieve any ZIA Threat Protection configurations.")
    except Exception as e:
        logger.error(f"Error fetching ZIA Threat Protection: {e}")

    # 5. Policy - Malware Settings
    logger.info("Fetching ZIA Malware Settings...")
    try:
        mal, _, err = client.zia.malware_protection_policy.get_malware_settings()
        if not err and mal:
            mal_dict = mal.as_dict() if hasattr(mal, "as_dict") else mal
            zia_config["malware_policy"] = clean_zia_dict(mal_dict)
            logger.info("Exported ZIA Malware Settings.")
        else:
            logger.warning(f"Could not retrieve ZIA Malware Settings. Error: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA Malware Settings: {e}")

    # 6. Policy - ATP Settings
    logger.info("Fetching ZIA ATP Settings...")
    try:
        atp, _, err = client.zia.atp_policy.get_atp_settings()
        if not err and atp:
            atp_dict = atp.as_dict() if hasattr(atp, "as_dict") else atp
            zia_config["atp_policy"] = clean_zia_dict(atp_dict)
            logger.info("Exported ZIA ATP Settings.")
        else:
            logger.warning(f"Could not retrieve ZIA ATP Settings. Error: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA ATP Settings: {e}")

    # 7. Policy - SSL Advanced Policy Settings
    logger.info("Fetching ZIA SSL Inspection Rules...")
    try:
        rules, _, err = client.zia.ssl_inspection_rules.list_rules()
        if not err and rules:
            ssl_rules = []
            for rule in rules:
                rule_dict = rule.as_dict() if hasattr(rule, "as_dict") else rule
                cleaned_rule = clean_zia_dict(rule_dict)
                # Remove rule ID to avoid read-only fields
                cleaned_rule.pop("id", None)
                
                # Translate CUSTOM_xx references in url_categories to configured names
                if "url_categories" in cleaned_rule and isinstance(cleaned_rule["url_categories"], list):
                    cleaned_rule["url_categories"] = [
                        custom_cat_id_to_name.get(cid, cid) for cid in cleaned_rule["url_categories"]
                    ]

                ssl_rules.append(cleaned_rule)
            # Sort SSL rules alphabetically by name
            ssl_rules.sort(key=lambda x: x.get("name", "").lower())
            zia_config["ssl_policy"] = ssl_rules
            logger.info(f"Exported {len(ssl_rules)} ZIA SSL Inspection Rules (sorted, IDs clean).")
        else:
            logger.warning(f"Could not retrieve ZIA SSL Inspection Rules. Error: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA SSL Rules: {e}")

    # 8. Cloud App Control Rules (CASB)
    logger.info("Fetching ZIA Cloud App Control Rules (CASB)...")
    CASB_RULE_TYPES = [
        'WEBMAIL', 'SOCIAL_NETWORKING', 'FINANCE', 'LEGAL', 'AI_ML',
        'HUMAN_RESOURCES', 'DNS_OVER_HTTPS', 'SYSTEM_AND_DEVELOPMENT',
        'INSTANT_MESSAGING', 'STREAMING_MEDIA', 'HEALTH_CARE', 'FILE_SHARE',
        'CONSUMER', 'HOSTING_PROVIDER', 'ENTERPRISE_COLLABORATION',
        'CUSTOM_CAPP', 'SALES_AND_MARKETING', 'IT_SERVICES', 'BUSINESS_PRODUCTIVITY'
    ]
    casb_rules = {}
    for rtype in CASB_RULE_TYPES:
        try:
            rules, _, err = client.zia.cloudappcontrol.list_rules(rule_type=rtype)
            if not err and rules:
                cleaned_rules = []
                for rule in rules:
                    rule_dict = rule.as_dict() if hasattr(rule, "as_dict") else rule
                    cleaned_rule = clean_zia_dict(rule_dict)
                    # Remove rule ID to avoid read-only fields
                    cleaned_rule.pop("id", None)
                    cleaned_rules.append(cleaned_rule)
                if cleaned_rules:
                    # Sort the rules alphabetically by name within this category
                    cleaned_rules.sort(key=lambda x: x.get("name", "").lower())
                    casb_rules[rtype.lower()] = cleaned_rules
                    logger.info(f"Exported {len(cleaned_rules)} Cloud App Control rules for type: {rtype}")
        except Exception as e:
            logger.warning(f"Could not retrieve Cloud App Control rules for type {rtype}: {e}")
            
    if casb_rules:
        zia_config["cloud_app_control_rules"] = casb_rules

    # 9. URL Filtering Rules
    logger.info("Fetching ZIA URL Filtering Rules...")
    try:
        rules, _, err = client.zia.url_filtering.list_rules()
        if not err and rules:
            url_rules = []
            for rule in rules:
                rule_dict = rule.as_dict() if hasattr(rule, "as_dict") else rule
                cleaned_rule = clean_zia_dict(rule_dict)
                # Remove rule ID to avoid read-only fields
                cleaned_rule.pop("id", None)
                
                # Translate CUSTOM_xx references in url_categories to configured names
                if "url_categories" in cleaned_rule and isinstance(cleaned_rule["url_categories"], list):
                    cleaned_rule["url_categories"] = [
                        custom_cat_id_to_name.get(cid, cid) for cid in cleaned_rule["url_categories"]
                    ]

                url_rules.append(cleaned_rule)
            # Sort URL Filtering Rules alphabetically by name
            url_rules.sort(key=lambda x: x.get("name", "").lower())
            zia_config["url_filtering_rules"] = url_rules
            logger.info(f"Exported {len(url_rules)} URL Filtering Rules (sorted, IDs clean).")
        else:
            logger.warning(f"Could not retrieve URL Filtering Rules. Error: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA URL Filtering Rules: {e}")

    # 10. PAC Files
    logger.info("Fetching ZIA PAC Files...")
    try:
        pacs, _, err = client.zia.pac_files.list_pac_files()
        if not err and pacs:
            # Create pac_files subdirectory partitioned by environment name / vanity domain
            env_name = os.getenv("ENV_NAME") or os.getenv("ZSCALER_VANITY_DOMAIN") or "default"
            import re
            # Clean env_name for file system compatibility
            env_name_clean = re.sub(r'[^a-zA-Z0-9._-]', '_', env_name)
            
            out_dir = os.path.dirname(os.path.abspath(out_path))
            pac_dir = os.path.join(out_dir, "pac_files", env_name_clean)
            os.makedirs(pac_dir, exist_ok=True)

            cleaned_pacs = []
            for pac in pacs:
                pac_dict = pac.as_dict() if hasattr(pac, "as_dict") else pac
                cleaned_pac = clean_zia_dict(pac_dict)
                # Remove internal ID and domain to avoid environment dependency
                cleaned_pac.pop("id", None)
                cleaned_pac.pop("domain", None)

                # Ensure PAC name replaces spaces with underscores
                pac_name = cleaned_pac.get("name")
                if pac_name:
                    pac_name_clean = pac_name.replace(" ", "_")
                    if pac_name_clean != pac_name:
                        logger.info(f"Replacing spaces with underscores in exported PAC name: '{pac_name}' -> '{pac_name_clean}'")
                        cleaned_pac["name"] = pac_name_clean
                    pac_name = pac_name_clean

                # Write pac_content to external file
                if pac_name and "pac_content" in cleaned_pac:
                    # Keep alphanumeric, dots, dashes, underscores
                    safe_fn = re.sub(r'[^a-zA-Z0-9._-]', '_', pac_name)
                    if not safe_fn.endswith('.pac'):
                        safe_fn += '.pac'
                    
                    pac_file_path_relative = f"pac_files/{env_name_clean}/{safe_fn}"
                    pac_file_path_absolute = os.path.join(pac_dir, safe_fn)
                    
                    try:
                        pac_content = cleaned_pac.pop("pac_content", "")
                        with open(pac_file_path_absolute, "w", encoding="utf-8") as pf:
                            pf.write(pac_content)
                        # Save reference path in YAML
                        cleaned_pac["pac_file_path"] = pac_file_path_relative
                        logger.info(f"Exported PAC file content for '{pac_name}' to: {pac_file_path_relative}")
                    except Exception as e:
                        logger.error(f"Failed to write external PAC file for '{pac_name}': {e}")
                        
                cleaned_pacs.append(cleaned_pac)
            # Sort PAC Files alphabetically by name
            cleaned_pacs.sort(key=lambda x: x.get("name", "").lower())
            zia_config["pac_files"] = cleaned_pacs
            logger.info(f"Exported {len(cleaned_pacs)} ZIA PAC Files.")
        else:
            logger.warning(f"Could not retrieve ZIA PAC Files. Error: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA PAC Files: {e}")

    # Fetch custom IP Destination Groups
    logger.info("Fetching ZIA IP Destination Groups...")
    try:
        groups, _, err = client.zia.cloud_firewall.list_ip_destination_groups()
        if not err and groups:
            dest_groups = []
            for group in groups:
                g_dict = group.as_dict() if hasattr(group, "as_dict") else group
                if not g_dict.get("is_non_editable", False):
                    cleaned_group = clean_zia_dict(g_dict)
                    cleaned_group.pop("id", None)
                    dest_groups.append(cleaned_group)
            dest_groups.sort(key=lambda x: x.get("name", "").lower())
            zia_config["ip_destination_groups"] = dest_groups
            logger.info(f"Exported {len(dest_groups)} custom ZIA IP Destination Groups.")
        else:
            logger.warning(f"Could not retrieve IP Destination Groups: {err}")
    except Exception as e:
        logger.error(f"Error fetching IP Destination Groups: {e}")

    # Fetch custom IP Source Groups
    logger.info("Fetching ZIA IP Source Groups...")
    try:
        groups, _, err = client.zia.cloud_firewall.list_ip_source_groups()
        if not err and groups:
            src_groups = []
            for group in groups:
                g_dict = group.as_dict() if hasattr(group, "as_dict") else group
                if not g_dict.get("is_non_editable", False):
                    cleaned_group = clean_zia_dict(g_dict)
                    cleaned_group.pop("id", None)
                    src_groups.append(cleaned_group)
            src_groups.sort(key=lambda x: x.get("name", "").lower())
            zia_config["ip_source_groups"] = src_groups
            logger.info(f"Exported {len(src_groups)} custom ZIA IP Source Groups.")
        else:
            logger.warning(f"Could not retrieve ZIA IP Source Groups: {err}")
    except Exception as e:
        logger.error(f"Error fetching IP Source Groups: {e}")

    # Fetch File Type Control Rules
    logger.info("Fetching ZIA File Type Control Rules...")
    try:
        rules, _, err = client.zia.file_type_control_rule.list_rules()
        if not err and rules:
            file_rules = []
            for rule in rules:
                rule_dict = rule.as_dict() if hasattr(rule, "as_dict") else rule
                cleaned_rule = clean_zia_dict(rule_dict)
                cleaned_rule.pop("id", None)
                file_rules.append(cleaned_rule)
            file_rules.sort(key=lambda x: x.get("name", "").lower())
            zia_config["file_type_rules"] = file_rules
            logger.info(f"Exported {len(file_rules)} File Type Control Rules.")
        else:
            logger.warning(f"Could not retrieve File Type Control Rules: {err}")
    except Exception as e:
        logger.error(f"Error fetching File Type Control Rules: {e}")

    # Fetch Cloud Firewall Rules
    logger.info("Fetching ZIA Cloud Firewall Rules...")
    try:
        rules, _, err = client.zia.cloud_firewall_rules.list_rules()
        if not err and rules:
            fw_rules = []
            for rule in rules:
                rule_dict = rule.as_dict() if hasattr(rule, "as_dict") else rule
                cleaned_rule = clean_zia_dict(rule_dict)
                cleaned_rule.pop("id", None)
                # Strip nested reference IDs (e.g. nw_services, nw_service_groups) to make export portable across tenants
                for ref_key in ["nw_services", "nw_service_groups", "nw_application_groups", "app_service_groups", "dest_ip_groups", "src_ip_groups"]:
                    if ref_key in cleaned_rule and isinstance(cleaned_rule[ref_key], list):
                        cleaned_rule[ref_key] = [{k: v for k, v in item.items() if k != "id"} if isinstance(item, dict) else item for item in cleaned_rule[ref_key]]
                fw_rules.append(cleaned_rule)
            fw_rules.sort(key=lambda x: x.get("name", "").lower())
            zia_config["firewall_rules"] = fw_rules
            logger.info(f"Exported {len(fw_rules)} Cloud Firewall Rules.")
        else:
            logger.warning(f"Could not retrieve Cloud Firewall Rules: {err}")
    except Exception as e:
        logger.error(f"Error fetching Cloud Firewall Rules: {e}")

    # Fetch DNS Filtering Rules
    logger.info("Fetching ZIA DNS Filtering Rules...")
    try:
        rules, _, err = client.zia.cloud_firewall_dns.list_rules()
        if not err and rules:
            dns_rules = []
            for rule in rules:
                rule_dict = rule.as_dict() if hasattr(rule, "as_dict") else rule
                cleaned_rule = clean_zia_dict(rule_dict)
                cleaned_rule.pop("id", None)
                for ref_key in ["nw_services", "nw_service_groups", "nw_application_groups", "app_service_groups", "dest_ip_groups", "src_ip_groups"]:
                    if ref_key in cleaned_rule and isinstance(cleaned_rule[ref_key], list):
                        cleaned_rule[ref_key] = [{k: v for k, v in item.items() if k != "id"} if isinstance(item, dict) else item for item in cleaned_rule[ref_key]]
                dns_rules.append(cleaned_rule)
            dns_rules.sort(key=lambda x: x.get("name", "").lower())
            zia_config["dns_rules"] = dns_rules
            logger.info(f"Exported {len(dns_rules)} DNS Filtering Rules.")
        else:
            logger.warning(f"Could not retrieve ZIA DNS Filtering Rules: {err}")
    except Exception as e:
        logger.error(f"Error fetching DNS Filtering Rules: {e}")

    # Fetch custom ZIA Root Certificates
    logger.info("Fetching ZIA Root Certificates...")
    try:
        url = "/zia/api/v1/rootCertificates"
        request, error = client._request_executor.create_request("GET", url, {}, {})
        if not error:
            response, error = client._request_executor.execute(request)
            if not error and response:
                certs = response.get_body()
                custom_certs = []
                for cert in certs:
                    if cert.get("isDefault") or "Zscaler Root" in cert.get("displayName", ""):
                        continue
                    cleaned_cert = clean_zia_dict(cert)
                    cleaned_cert.pop("id", None)
                    # Use a placeholder for the PEM cert content since API GET doesn't return it
                    cleaned_cert["cert"] = "PLACEHOLDER_PLEASE_REPLACE_WITH_PEM_CONTENT"
                    custom_certs.append(cleaned_cert)
                custom_certs.sort(key=lambda x: x.get("displayName", "").lower())
                zia_config["root_certificates"] = custom_certs
                logger.info(f"Exported {len(custom_certs)} custom ZIA Root Certificates.")
            else:
                logger.warning(f"Could not retrieve ZIA Root Certificates: {error}")
        else:
            logger.warning(f"Could not create request for ZIA Root Certificates: {error}")
    except Exception as e:
        logger.error(f"Error fetching ZIA Root Certificates: {e}")

    # Fetch custom ZIA Proxies
    logger.info("Fetching ZIA Proxies...")
    try:
        proxies, _, err = client.zia.proxies.list_proxies()
        if not err and proxies:
            custom_proxies = []
            for proxy in proxies:
                p_dict = proxy.as_dict() if hasattr(proxy, "as_dict") else proxy
                cleaned_proxy = clean_zia_dict(p_dict)
                cleaned_proxy.pop("id", None)
                if "cert" in cleaned_proxy and isinstance(cleaned_proxy["cert"], dict):
                    cert_name = cleaned_proxy["cert"].get("name")
                    cleaned_proxy["cert"] = {"name": cert_name} if cert_name else {}
                custom_proxies.append(cleaned_proxy)
            custom_proxies.sort(key=lambda x: x.get("name", "").lower())
            zia_config["proxies"] = custom_proxies
            logger.info(f"Exported {len(custom_proxies)} ZIA Proxies.")
        else:
            logger.warning(f"Could not retrieve ZIA Proxies: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA Proxies: {e}")

    # Fetch custom ZIA Proxy Gateways (Read-only on API, but we export for policy linkage reference)
    logger.info("Fetching ZIA Proxy Gateways...")
    try:
        gateways, _, err = client.zia.proxies.list_proxy_gateways()
        if not err and gateways:
            custom_gws = []
            for gw in gateways:
                gw_dict = gw.as_dict() if hasattr(gw, "as_dict") else gw
                cleaned_gw = clean_zia_dict(gw_dict)
                cleaned_gw.pop("id", None)
                if "primary_proxy" in cleaned_gw and isinstance(cleaned_gw["primary_proxy"], dict):
                    proxy_name = cleaned_gw["primary_proxy"].get("name")
                    cleaned_gw["primary_proxy"] = {"name": proxy_name} if proxy_name else {}
                custom_gws.append(cleaned_gw)
            custom_gws.sort(key=lambda x: x.get("name", "").lower())
            zia_config["proxy_gateways"] = custom_gws
            logger.info(f"Exported {len(custom_gws)} ZIA Proxy Gateways.")
        else:
            logger.warning(f"Could not retrieve ZIA Proxy Gateways: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA Proxy Gateways: {e}")

    # Fetch custom ZIA Forwarding Control Rules
    logger.info("Fetching ZIA Forwarding Control Rules...")
    try:
        rules, _, err = client.zia.forwarding_control.list_rules()
        if not err and rules:
            fwd_rules = []
            for rule in rules:
                rule_dict = rule.as_dict() if hasattr(rule, "as_dict") else rule
                cleaned_rule = clean_zia_dict(rule_dict)
                # Skip Zscaler system default / read-only rules (typically order < 0 or default_rule=True)
                if cleaned_rule.get("order", 0) < 0 or cleaned_rule.get("default_rule"):
                    continue
                cleaned_rule.pop("id", None)
                
                if "proxy_gateway" in cleaned_rule and isinstance(cleaned_rule["proxy_gateway"], dict):
                    gw_name = cleaned_rule["proxy_gateway"].get("name")
                    cleaned_rule["proxy_gateway"] = {"name": gw_name} if gw_name else {}
                
                if "dest_ip_groups" in cleaned_rule and isinstance(cleaned_rule["dest_ip_groups"], list):
                    cleaned_rule["dest_ip_groups"] = [
                        {"name": g.get("name")} for g in cleaned_rule["dest_ip_groups"] if isinstance(g, dict) and g.get("name")
                    ]
                
                fwd_rules.append(cleaned_rule)
            fwd_rules.sort(key=lambda x: x.get("order", 999))
            zia_config["forwarding_rules"] = fwd_rules
            logger.info(f"Exported {len(fwd_rules)} custom ZIA Forwarding Control Rules.")
        else:
            logger.warning(f"Could not retrieve ZIA Forwarding Control Rules: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA Forwarding Control Rules: {e}")

    # Fetch Rule Labels
    logger.info("Fetching ZIA Rule Labels...")
    try:
        labels, _, err = client.zia.rule_labels.list_labels()
        if not err and labels:
            custom_labels = []
            for lbl in labels:
                lbl_dict = lbl.as_dict() if hasattr(lbl, "as_dict") else lbl
                cleaned = clean_zia_dict(lbl_dict)
                cleaned.pop("id", None)
                cleaned.pop("referenced_rule_count", None)
                if cleaned.get("name"):
                    custom_labels.append(cleaned)
            custom_labels.sort(key=lambda x: x.get("name", "").lower())
            zia_config["rule_labels"] = custom_labels
            logger.info(f"Exported {len(custom_labels)} Rule Labels.")
        else:
            if err:
                logger.warning(f"Could not retrieve Rule Labels: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZIA Rule Labels: {e}")

    # Save to file under 'zia' key
    yaml_data = load_existing_yaml(out_path)
    yaml_data["zia"] = zia_config
    save_yaml(out_path, yaml_data)


# ==============================================================================
# ZPA Exporter
# ==============================================================================
def export_zpa_presets(client: ZscalerClient, out_path: str = "pov_preset_exported.yaml") -> None:
    """Exports ZPA configuration (Connector Groups, Server Groups, Segment Groups,
    App Segments, and Access Policy rules) to a YAML file compatible with zpa.py."""

    logger.info("Starting complete ZPA configurations exporter...")
    zpa_config = {}

    # --- Connector Groups ---
    try:
        groups, _, err = client.zpa.app_connector_groups.list_connector_groups()
        if not err and groups:
            exported = []
            for g in groups:
                d = g.as_dict() if hasattr(g, "as_dict") else dict(g)
                clean = {
                    "name": d.get("name"),
                    "description": d.get("description") or "",
                    "enabled": d.get("enabled", True),
                    "latitude": str(d.get("latitude") or "0"),
                    "longitude": str(d.get("longitude") or "0"),
                    "location": d.get("location") or "",
                }
                exported.append(clean)
            zpa_config["connector_groups"] = exported
            logger.info(f"Exported {len(exported)} ZPA Connector Groups.")
        else:
            logger.warning(f"Could not retrieve ZPA Connector Groups: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZPA Connector Groups: {e}")

    # --- Server Groups ---
    try:
        groups, _, err = client.zpa.server_groups.list_groups()
        if not err and groups:
            exported = []
            for g in groups:
                d = g.as_dict() if hasattr(g, "as_dict") else dict(g)
                # Resolve app_connector_group name from nested object
                cg_name = None
                cg_list = d.get("app_connector_groups") or []
                if cg_list and isinstance(cg_list, list):
                    cg_name = cg_list[0].get("name") if isinstance(cg_list[0], dict) else None
                clean = {
                    "name": d.get("name"),
                    "description": d.get("description") or "",
                    "enabled": d.get("enabled", True),
                    "dynamic_discovery": d.get("dynamic_discovery", True),
                }
                if cg_name:
                    clean["app_connector_group_name"] = cg_name
                exported.append(clean)
            zpa_config["server_groups"] = exported
            logger.info(f"Exported {len(exported)} ZPA Server Groups.")
        else:
            logger.warning(f"Could not retrieve ZPA Server Groups: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZPA Server Groups: {e}")

    # --- Segment Groups ---
    try:
        groups, _, err = client.zpa.segment_groups.list_groups()
        if not err and groups:
            exported = []
            for g in groups:
                d = g.as_dict() if hasattr(g, "as_dict") else dict(g)
                clean = {
                    "name": d.get("name"),
                    "description": d.get("description") or "",
                    "enabled": d.get("enabled", True),
                }
                exported.append(clean)
            zpa_config["segment_groups"] = exported
            logger.info(f"Exported {len(exported)} ZPA Segment Groups.")
        else:
            logger.warning(f"Could not retrieve ZPA Segment Groups: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZPA Segment Groups: {e}")

    # --- App Segments ---
    try:
        segments, _, err = client.zpa.application_segment.list_segments()
        if not err and segments:
            exported = []
            for s in segments:
                d = s.as_dict() if hasattr(s, "as_dict") else dict(s)
                # Resolve server_group name
                sg_name = None
                sg_list = d.get("server_groups") or []
                if sg_list and isinstance(sg_list, list):
                    sg_name = sg_list[0].get("name") if isinstance(sg_list[0], dict) else None
                # Resolve segment_group name
                segg_name = None
                segg = d.get("segment_group") or {}
                if isinstance(segg, dict):
                    segg_name = segg.get("name")

                # TCP port ranges
                tcp_ranges = []
                for pr in (d.get("tcp_port_ranges") or []):
                    if isinstance(pr, dict):
                        tcp_ranges.append({"from": str(pr.get("from") or pr.get("from_port", "")),
                                           "to": str(pr.get("to") or pr.get("to_port", ""))})

                # UDP port ranges
                udp_ranges = []
                for pr in (d.get("udp_port_ranges") or []):
                    if isinstance(pr, dict):
                        udp_ranges.append({"from": str(pr.get("from") or pr.get("from_port", "")),
                                           "to": str(pr.get("to") or pr.get("to_port", ""))})

                clean = {
                    "name": d.get("name"),
                    "description": d.get("description") or "",
                    "enabled": d.get("enabled", True),
                    "domain_names": d.get("domain_names") or [],
                    "bypass_type": d.get("bypass_type") or "NEVER",
                    "icmp_access_type": d.get("icmp_access_type") or "PING",
                    "fqdn_dns_check": d.get("fqdn_dns_check"),
                    "match_style": d.get("match_style"),
                    "is_cname_enabled": d.get("is_cname_enabled"),
                }
                if sg_name:
                    clean["server_group_name"] = sg_name
                if segg_name:
                    clean["segment_group_name"] = segg_name
                if tcp_ranges:
                    clean["tcp_port_range"] = tcp_ranges
                if udp_ranges:
                    clean["udp_port_range"] = udp_ranges
                exported.append(clean)
            exported.sort(key=lambda x: x.get("name", ""))
            zpa_config["app_segments"] = exported
            logger.info(f"Exported {len(exported)} ZPA App Segments.")
        else:
            logger.warning(f"Could not retrieve ZPA App Segments: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZPA App Segments: {e}")
    app_segment_map = {}
    if 'segments' in locals() and segments:
        for s in segments:
            app_segment_map[str(s.id)] = s.name

    # --- Access Policy Rules ---
    try:
        rules, _, err = client.zpa.policies.list_rules(policy_type="access")
        if not err and rules:
            exported = []
            for r in rules:
                d = r.as_dict() if hasattr(r, "as_dict") else dict(r)
                # Skip system default rules (order <= 0 or default_rule flag)
                if d.get("default_rule") or int(d.get("rule_order") or 0) <= 0:
                    continue
                # Resolve app segment names from conditions
                app_seg_names = []
                for cond in (d.get("conditions") or []):
                    for op in (cond.get("operands") or []):
                        if isinstance(op, dict) and op.get("object_type") == "APP":
                            lhs_by_id = op.get("lhs") == "id"
                            rhs = op.get("rhs_val") or op.get("rhs") or ""
                            if isinstance(rhs, dict):
                                seg_name = rhs.get("name")
                            else:
                                seg_name = app_segment_map.get(str(rhs), str(rhs))
                            if seg_name:
                                app_seg_names.append(seg_name)

                clean = {
                    "name": d.get("name"),
                    "description": d.get("description") or "",
                    "action": d.get("action") or "ALLOW",
                    "rule_order": str(d.get("rule_order") or "1"),
                    "app_segments": app_seg_names,
                }
                exported.append(clean)
            exported.sort(key=lambda x: int(x.get("rule_order") or 999))
            zpa_config["policies"] = exported
            logger.info(f"Exported {len(exported)} ZPA Access Policy rules.")
        else:
            logger.warning(f"Could not retrieve ZPA Access Policy rules: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZPA Access Policy rules: {e}")

    # --- Timeout Policy Rules ---
    try:
        rules, _, err = client.zpa.policies.list_rules(policy_type="timeout")
        if not err and rules:
            exported = []
            for r in rules:
                d = r.as_dict() if hasattr(r, "as_dict") else dict(r)
                
                # Resolve app segment names from conditions
                app_seg_names = []
                for cond in (d.get("conditions") or []):
                    for op in (cond.get("operands") or []):
                        if isinstance(op, dict) and op.get("object_type") == "APP":
                            rhs = op.get("rhs_val") or op.get("rhs") or ""
                            if isinstance(rhs, dict):
                                seg_name = rhs.get("name")
                            else:
                                seg_name = app_segment_map.get(str(rhs), str(rhs))
                            if seg_name:
                                app_seg_names.append(seg_name)
                                
                clean = {
                    "name": d.get("name"),
                    "description": d.get("description") or "",
                    "action": d.get("action") or "RE_AUTH",
                    "rule_order": str(d.get("rule_order") or "1"),
                    "app_segments": app_seg_names,
                    "reauth_idle_timeout": seconds_to_human(d.get("reauth_idle_timeout")),
                    "reauth_timeout": seconds_to_human(d.get("reauth_timeout")),
                    "custom_msg": d.get("custom_msg"),
                }
                exported.append(clean)
            exported.sort(key=lambda x: int(x.get("rule_order") or 999))
            zpa_config["timeout_policies"] = exported
            logger.info(f"Exported {len(exported)} ZPA Timeout Policy rules.")
        else:
            logger.warning(f"Could not retrieve ZPA Timeout Policy rules: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZPA Timeout Policy rules: {e}")

    # --- Client Forwarding Policy Rules ---
    try:
        rules, _, err = client.zpa.policies.list_rules(policy_type="client_forwarding")
        if not err and rules:
            exported = []
            for r in rules:
                d = r.as_dict() if hasattr(r, "as_dict") else dict(r)
                    
                # Resolve app segment names from conditions
                app_seg_names = []
                for cond in (d.get("conditions") or []):
                    for op in (cond.get("operands") or []):
                        if isinstance(op, dict) and op.get("object_type") == "APP":
                            rhs = op.get("rhs_val") or op.get("rhs") or ""
                            if isinstance(rhs, dict):
                                seg_name = rhs.get("name")
                            else:
                                seg_name = app_segment_map.get(str(rhs), str(rhs))
                            if seg_name:
                                app_seg_names.append(seg_name)
                                
                clean = {
                    "name": d.get("name"),
                    "description": d.get("description") or "",
                    "action": d.get("action") or "ALLOW",
                    "rule_order": str(d.get("rule_order") or "1"),
                    "app_segments": app_seg_names,
                }
                exported.append(clean)
            exported.sort(key=lambda x: int(x.get("rule_order") or 999))
            zpa_config["client_forwarding_policies"] = exported
            logger.info(f"Exported {len(exported)} ZPA Client Forwarding Policy rules.")
        else:
            logger.warning(f"Could not retrieve ZPA Client Forwarding Policy rules: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZPA Client Forwarding Policy rules: {e}")

    # --- DNS Search Domains (Customer Domains) ---
    try:
        _, resp, err = client.zpa.customer_domain.list_domains(type="SEARCH_SUFFIX")
        if not err and resp:
            body = resp.get_body() or []
            if isinstance(body, list):
                exported = []
                for d in body:
                    clean = {
                        "domain": d.get("domain"),
                    }
                    if clean["domain"]:
                        exported.append(clean)
                zpa_config["dns_search_domains"] = exported
                logger.info(f"Exported {len(exported)} ZPA DNS Search Domains.")
        else:
            logger.warning(f"Could not retrieve ZPA DNS Search Domains: {err}")
    except Exception as e:
        logger.error(f"Error fetching ZPA DNS Search Domains: {e}")

    # Save to file under 'zpa' key
    yaml_data = load_existing_yaml(out_path)
    yaml_data["zpa"] = zpa_config
    save_yaml(out_path, yaml_data)
    logger.info(f"ZPA configurations exported successfully to: {out_path}")
