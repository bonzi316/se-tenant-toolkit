import logging
from typing import Dict, Any, List
from zscaler import ZscalerClient
from src.config import ZIAConfig
from src.zcc import remove_none_recursive

logger = logging.getLogger("src")

APP_TO_RULE_TYPE = {
    "GMAIL": "WEBMAIL",
    "YAHOO_MAIL": "WEBMAIL",
    "OUTLOOK": "WEBMAIL",
    "FACEBOOK": "SOCIAL_NETWORKING",
    "LINKEDIN": "SOCIAL_NETWORKING",
    "TWITTER": "SOCIAL_NETWORKING",
    "YOUTUBE": "STREAMING_MEDIA",
    "NETFLIX": "STREAMING_MEDIA",
    "BOX": "FILE_SHARE",
    "DROPBOX": "FILE_SHARE",
    "GOOGLE_DRIVE": "FILE_SHARE",
    "ONEDRIVE": "FILE_SHARE",
    "SLACK": "ENTERPRISE_COLLABORATION",
    "ZOOM": "ENTERPRISE_COLLABORATION",
    "TEAMS": "ENTERPRISE_COLLABORATION",
}

CASB_RULE_TYPES = [
    'WEBMAIL', 'SOCIAL_NETWORKING', 'FINANCE', 'LEGAL', 'AI_ML',
    'HUMAN_RESOURCES', 'DNS_OVER_HTTPS', 'SYSTEM_AND_DEVELOPMENT',
    'INSTANT_MESSAGING', 'STREAMING_MEDIA', 'HEALTH_CARE', 'FILE_SHARE',
    'CONSUMER', 'HOSTING_PROVIDER', 'ENTERPRISE_COLLABORATION',
    'CUSTOM_CAPP', 'SALES_AND_MARKETING', 'IT_SERVICES', 'BUSINESS_PRODUCTIVITY'
]

def camel_to_snake(s: str) -> str:
    import re
    return re.sub(r'(?<!^)(?=[A-Z])', '_', s).lower()

def count_active_rules(rules_list) -> int:
    """Helper to count only regular active rules, excluding default rules (with order -1 or default_rule=True)."""
    count = 0
    for r in rules_list:
        r_order = getattr(r, 'order', None)
        if r_order is None and hasattr(r, 'get'):
            r_order = r.get('order')
        
        r_default = getattr(r, 'default_rule', None) or getattr(r, 'default_rule_obj', None)
        if r_default is None and hasattr(r, 'get'):
            r_default = r.get('default_rule') or r.get('defaultRule')
            
        if r_order == -1 or r_order == '-1' or r_default:
            continue
        count += 1
    return count

def apply_prefix(name: str, prefix: str) -> str:
    """Prepends the prefix to the name case-insensitively if not already prefixed."""
    if not prefix:
        return name
    prefix_clean = prefix.strip()
    if not prefix_clean:
        return name
    # Strip any trailing dash or space to find the base prefix (e.g. "POV - " -> "POV")
    if prefix_clean.endswith("-"):
        prefix_clean = prefix_clean[:-1].strip()
        
    # Check if name already starts with clean prefix (case-insensitive)
    if name.strip().lower().startswith(prefix_clean.lower()):
        return name
        
    return f"{prefix_clean} - {name}"

def apply_prefix_and_truncate_31(name: str, prefix: str) -> str:
    """Prepends the prefix and truncates to 31 characters with a unique stable hash suffix if too long."""
    if not prefix:
        if len(name) > 31:
            import hashlib
            h = hashlib.md5(name.encode('utf-8')).hexdigest()[:3]
            return f"{name[:27].strip()}-{h}"
        return name
        
    prefix_clean = prefix.strip()
    if prefix_clean.endswith("-"):
        prefix_clean = prefix_clean[:-1].strip()
        
    prefixed_name = name
    if not name.strip().lower().startswith(prefix_clean.lower()):
        prefixed_name = f"{prefix_clean} - {name}"
        
    if len(prefixed_name) > 31:
        import hashlib
        prefix_part = f"{prefix_clean} - "
        # Generate a stable 3-char hash of the original name
        h = hashlib.md5(name.encode('utf-8')).hexdigest()[:3]
        suffix = f"-{h}"
        
        # Max length of original name part we can keep
        max_name_len = 31 - len(prefix_part) - len(suffix)
        name_part = name
        # If the original name was already prefixed, use the part after the prefix
        if name.strip().lower().startswith(prefix_clean.lower()):
            # Find where the base name starts
            raw_part = name[len(prefix_clean):].strip()
            if raw_part.startswith("-"):
                raw_part = raw_part[1:].strip()
            name_part = raw_part
        name_part = name_part[:max_name_len].strip()
        
        prefixed_name = f"{prefix_part}{name_part}{suffix}"
        if len(prefixed_name) > 31:
            prefixed_name = prefixed_name[:31]
        logger.info(f"ZIA rule/object name '{name}' with prefix was too long. Truncated uniquely to '{prefixed_name}' (31 chars).")
        
    return prefixed_name

def normalize_pem(pem_str: str) -> str:
    if not pem_str:
        return pem_str
    header = "-----BEGIN CERTIFICATE-----"
    footer = "-----END CERTIFICATE-----"
    
    if header in pem_str and footer in pem_str:
        parts = pem_str.split(header)
        base64_part = parts[1].split(footer)[0]
    else:
        base64_part = pem_str
        
    # Strip all whitespace, newlines, and quotes
    clean_b64 = "".join(base64_part.split()).replace('"', '').replace("'", "")
    
    # Chunk base64 into 64-char lines
    lines = [clean_b64[i:i+64] for i in range(0, len(clean_b64), 64)]
    
    # Reassemble PEM with unix newlines
    return f"{header}\n" + "\n".join(lines) + f"\n{footer}\n"


def setup_zia(client: ZscalerClient, config: ZIAConfig, dry_run: bool = False, prefix: str = "", config_dir: str = "", rule_label: str = None) -> Dict[str, Any]:
    """Sets up ZIA settings, URL categories, threat protection, malware policy, ATP settings, rule labels, and policy rules."""
    results = {}
    if not config:
        return results

    target_locations = {}
    target_groups = {}
    target_departments = {}
    target_zpa_segments = {}
    target_dest_ip_groups = {}
    target_rule_labels = {}
    refs_fetched = [False]

    def ensure_refs_fetched():
        if refs_fetched[0]:
            return
        # 1. Fetch locations
        try:
            locs, _, _ = client.zia.locations.list_locations()
            if locs:
                for l in locs:
                    l_dict = l.as_dict() if hasattr(l, "as_dict") else l
                    if l_dict.get("name") and l_dict.get("id") is not None:
                        target_locations[l_dict["name"].lower()] = l_dict["id"]
        except Exception as e:
            logger.warning(f"Could not fetch ZIA locations: {e}")

        # 2. Fetch groups
        try:
            grps, _, _ = client.zia.user_management.list_groups()
            if grps:
                for g in grps:
                    g_dict = g.as_dict() if hasattr(g, "as_dict") else g
                    if g_dict.get("name") and g_dict.get("id") is not None:
                        target_groups[g_dict["name"].lower()] = g_dict["id"]
        except Exception as e:
            logger.warning(f"Could not fetch ZIA groups: {e}")

        # 3. Fetch departments
        try:
            depts, _, _ = client.zia.user_management.list_departments()
            if depts:
                for d in depts:
                    d_dict = d.as_dict() if hasattr(d, "as_dict") else d
                    if d_dict.get("name") and d_dict.get("id") is not None:
                        target_departments[d_dict["name"].lower()] = d_dict["id"]
        except Exception as e:
            logger.warning(f"Could not fetch ZIA departments: {e}")

        # 4. Fetch ZPA app segments
        try:
            segs, _, _ = client.zpa.application_segment.list_segments()
            if segs:
                for s in segs:
                    s_dict = s.as_dict() if hasattr(s, "as_dict") else s
                    if s_dict.get("name") and s_dict.get("id") is not None:
                        target_zpa_segments[s_dict["name"].lower()] = s_dict["id"]
        except Exception as e:
            logger.warning(f"Could not fetch ZPA app segments: {e}")
            
        # 5. Fetch dest IP groups
        try:
            ip_groups, _, _ = client.zia.cloud_firewall.list_ip_destination_groups()
            if ip_groups:
                for ig in ip_groups:
                    ig_dict = ig.as_dict() if hasattr(ig, "as_dict") else ig
                    if ig_dict.get("name") and ig_dict.get("id") is not None:
                        target_dest_ip_groups[ig_dict["name"].lower()] = ig_dict["id"]
        except Exception as e:
            logger.warning(f"Could not fetch ZIA IP destination groups: {e}")

        # 6. Fetch rule labels
        try:
            lbls, _, _ = client.zia.rule_labels.list_labels()
            if lbls:
                for lb in lbls:
                    lb_dict = lb.as_dict() if hasattr(lb, "as_dict") else lb
                    if lb_dict.get("name") and lb_dict.get("id") is not None:
                        target_rule_labels[lb_dict["name"].lower()] = lb_dict["id"]
        except Exception as e:
            logger.warning(f"Could not fetch ZIA rule labels: {e}")
            
        refs_fetched[0] = True

    def resolve_ref_list(items, target_map):
        resolved = []
        if not items:
            return resolved
        for item in items:
            name = None
            if isinstance(item, dict):
                name = item.get("name")
            elif isinstance(item, str):
                name = item
                
            if not name:
                continue
            
            tid = target_map.get(name.lower())
            if not tid and prefix:
                prefixed_name = name if name.startswith(prefix) else f"{prefix} - {name}"
                tid = target_map.get(prefixed_name.lower())
            
            if tid is not None:
                resolved.append({"id": tid, "name": name})
            else:
                logger.warning(f"Reference '{name}' could not be resolved in target tenant. Skipping reference.")
        return resolved

    def resolve_labels(rule_labels_attr) -> List[Dict[str, Any]]:
        ensure_refs_fetched()
        names = []
        if rule_labels_attr:
            for item in rule_labels_attr:
                if isinstance(item, str):
                    names.append(item)
                elif isinstance(item, dict):
                    if item.get("name"):
                        names.append(item["name"])
        if rule_label:
            if rule_label not in names:
                names.append(rule_label)
        
        resolved = []
        seen_ids = set()
        for name in names:
            lid = target_rule_labels.get(name.lower())
            if not lid and prefix:
                prefixed = name if name.startswith(prefix) else f"{prefix} - {name}"
                lid = target_rule_labels.get(prefixed.lower())
            if lid is not None:
                if lid not in seen_ids:
                    resolved.append({"id": lid})
                    seen_ids.add(lid)
            else:
                logger.warning(f"Rule Label '{name}' not found on target tenant. Skipping label.")
        
        # In case raw IDs were supplied without names:
        if rule_labels_attr:
            for item in rule_labels_attr:
                if isinstance(item, dict) and item.get("id") and not item.get("name"):
                    if item["id"] not in seen_ids:
                        resolved.append({"id": item["id"]})
                        seen_ids.add(item["id"])
        return resolved

    # 1. Advanced Settings
    if config.advanced_settings:
        logger.info("Processing ZIA Advanced Settings...")
        adv, _, err = client.zia.advanced_settings.get_advanced_settings()
        if err:
            logger.error(f"Failed to fetch ZIA advanced settings: {err}")
            raise Exception(f"Failed to fetch ZIA advanced settings: {err}")
        
        adv_dict = adv.as_dict() if hasattr(adv, "as_dict") else adv
        adv_dict.pop("id", None)
        
        valid_keys = set(adv_dict.keys())
        updated_settings = {}
        
        for k, v in config.advanced_settings.items():
            snake_k = camel_to_snake(k)
            if snake_k in valid_keys:
                if adv_dict[snake_k] != v:
                    updated_settings[snake_k] = v
            else:
                logger.warning(f"Skipping ZIA advanced setting '{k}' ('{snake_k}') - not a valid setting on this tenant.")
                
        if updated_settings:
            if dry_run:
                logger.info("[DRY-RUN] Would update ZIA Advanced Settings")
            else:
                adv_dict.update(updated_settings)
                _, _, err = client.zia.advanced_settings.update_advanced_settings(**adv_dict)
                if err:
                    logger.error(f"Failed to update ZIA advanced settings: {err}")
                    raise Exception(f"Failed to update ZIA advanced settings: {err}")
                logger.info("ZIA Advanced Settings updated successfully.")
            results["advanced_settings"] = "Updated"
        else:
            logger.info("ZIA Advanced Settings already up-to-date.")
            results["advanced_settings"] = "NoChange"

    # 1.5 URL & Cloud App Advanced Settings
    if hasattr(config, "url_filtering_settings") and config.url_filtering_settings:
        logger.info("Processing ZIA URL & Cloud App Advanced Settings...")
        url_settings, response, err = client.zia.url_filtering.get_url_and_app_settings()
        if err:
            logger.error(f"Failed to fetch ZIA URL & Cloud App advanced settings: {err}")
            raise Exception(f"Failed to fetch ZIA URL & Cloud App advanced settings: {err}")

        # Use the raw GET response body so we don't lose any undocumented/new AI prompt fields
        raw_settings_dict = response.get_body()

        # Helper to convert snake_case keys to camelCase keys
        def to_camel(s: str) -> str:
            parts = s.split('_')
            return parts[0] + ''.join(x.title() for x in parts[1:])

        updated_settings = {}
        for k, v in config.url_filtering_settings.items():
            camel_k = to_camel(k) if "_" in k else k
            
            # Map input key to the exact casing returned by Zscaler
            matched_key = None
            for rk in raw_settings_dict.keys():
                if rk.lower() == camel_k.lower() or rk.lower() == k.lower():
                    matched_key = rk
                    break
            
            if matched_key:
                if raw_settings_dict[matched_key] != v:
                    updated_settings[matched_key] = v
            else:
                updated_settings[camel_k] = v

        if updated_settings:
            if dry_run:
                logger.info("[DRY-RUN] Would update ZIA URL & Cloud App Advanced Settings")
            else:
                raw_settings_dict.update(updated_settings)
                # Pass the complete raw dictionary back to update_url_and_app_settings
                _, _, err = client.zia.url_filtering.update_url_and_app_settings(**raw_settings_dict)
                if err:
                    logger.error(f"Failed to update ZIA URL & Cloud App advanced settings: {err}")
                    raise Exception(f"Failed to update ZIA URL & Cloud App advanced settings: {err}")
                logger.info("ZIA URL & Cloud App Advanced Settings updated successfully.")
            results["url_filtering_settings"] = "Updated"
        else:
            logger.info("ZIA URL & Cloud App Advanced Settings already up-to-date.")
            results["url_filtering_settings"] = "NoChange"

    # 2. URL Categories
    cat_map = {} # name -> id
    cats, _, err = client.zia.url_categories.list_categories()
    if err:
        logger.error(f"Failed to list URL categories: {err}")
        raise Exception(f"Failed to list URL categories: {err}")
        
    for c in cats:
        c_dict = c.as_dict() if hasattr(c, "as_dict") else c
        cat_id = c_dict.get("id")
        cfg_name = c_dict.get("configured_name")
        if c_dict.get("custom_category"):
            if cfg_name:
                cat_map[cfg_name.lower()] = cat_id
        else:
            cat_map[cat_id.lower()] = cat_id

    if config.url_categories:
        results["url_categories"] = []
        for cat_cfg in config.url_categories:
            orig_name = cat_cfg.get("configured_name") or cat_cfg.get("name")
            if not orig_name:
                continue
                
            prefixed_name = apply_prefix(orig_name, prefix)

                
            cat_id = cat_map.get(prefixed_name.lower())
            urls = cat_cfg.get("urls", [])
            db_categorized_urls = cat_cfg.get("db_categorized_urls", [])
            
            payload = {
                "configured_name": prefixed_name,
                "urls": urls,
                "db_categorized_urls": db_categorized_urls,
                "description": cat_cfg.get("description", ""),
            }
            # Remove any None values
            payload = {k: v for k, v in payload.items() if v is not None}
            
            if cat_id:
                logger.info(f"URL Category '{prefixed_name}' already exists (ID: {cat_id}). Updating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would update URL category '{prefixed_name}' (ID: {cat_id}) with urls: {urls}")
                else:
                    import time
                    max_retries = 5
                    for attempt in range(max_retries):
                        _, _, err = client.zia.url_categories.update_url_category(
                            category_id=cat_id,
                            **payload
                        )
                        if err:
                            err_msg = str(getattr(err, "message", err))
                            is_lock_error = "operation is in progress" in err_msg.lower() or "enter org barrier" in err_msg.lower()
                            if is_lock_error and attempt < max_retries - 1:
                                logger.info(f"ZIA is processing another URL operation or holding barrier lock. Retrying in 5 seconds... (Attempt {attempt+1}/{max_retries})")
                                time.sleep(5)
                                continue
                            logger.error(f"Failed to update URL category '{prefixed_name}': {err}")
                            raise Exception(f"Failed to update URL category '{prefixed_name}': {err}")
                        break
                    logger.info(f"URL Category '{prefixed_name}' updated successfully.")
                results["url_categories"].append({"name": prefixed_name, "id": cat_id, "status": "Updated"})
            else:
                logger.info(f"URL Category '{prefixed_name}' does not exist. Creating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create URL category '{prefixed_name}' with urls: {urls}")
                    cat_map[prefixed_name.lower()] = "TEMP_CUSTOM_ID"
                else:
                    super_cat = cat_cfg.get("super_category") or "USER_DEFINED"
                    import time
                    max_retries = 5
                    new_cat = None
                    for attempt in range(max_retries):
                        new_cat, _, err = client.zia.url_categories.add_url_category(
                            super_category=super_cat,
                            **payload
                        )
                        if err:
                            err_msg = str(getattr(err, "message", err))
                            is_lock_error = "operation is in progress" in err_msg.lower() or "enter org barrier" in err_msg.lower()
                            if is_lock_error and attempt < max_retries - 1:
                                logger.info(f"ZIA is processing another URL operation or holding barrier lock. Retrying in 5 seconds... (Attempt {attempt+1}/{max_retries})")
                                time.sleep(5)
                                continue
                            logger.error(f"Failed to create URL category '{prefixed_name}': {err}")
                            raise Exception(f"Failed to create URL category '{prefixed_name}': {err}")
                        break
                    logger.info(f"URL Category '{prefixed_name}' created successfully with ID: {new_cat.id}")
                    cat_map[prefixed_name.lower()] = new_cat.id
                results["url_categories"].append({"name": prefixed_name, "status": "Created"})

    # 3. Threat Protection Configuration
    if config.threat_protection:
        logger.info("Processing Threat Protection settings...")
        tp_cfg = config.threat_protection
        
        # Policy
        tp_policy = tp_cfg.get("policy")
        if tp_policy:
            unscannable = tp_policy.get("block_unscannable_files", False)
            pwd_protected = tp_policy.get("block_password_protected_archive_files", False)
            if dry_run:
                logger.info(f"[DRY-RUN] Would update ATP Malware Policy: block_unscannable_files={unscannable}, block_password_protected_archive_files={pwd_protected}")
            else:
                _, _, err = client.zia.malware_protection_policy.update_atp_malware_policy(
                    block_unscannable_files=unscannable,
                    block_password_protected_archive_files=pwd_protected
                )
                if err:
                    logger.error(f"Failed to update ATP Malware Policy: {err}")
                    raise Exception(f"Failed to update ATP Malware Policy: {err}")
                logger.info("ATP Malware Policy updated successfully.")
                
        # Protocols
        tp_protocols = tp_cfg.get("protocols")
        if tp_protocols:
            inspect_http = tp_protocols.get("inspect_http", True)
            inspect_ftp_over_http = tp_protocols.get("inspect_ftp_over_http", True)
            inspect_ftp = tp_protocols.get("inspect_ftp", True)
            if dry_run:
                logger.info(f"[DRY-RUN] Would update ATP Malware Protocols: inspect_http={inspect_http}, inspect_ftp_over_http={inspect_ftp_over_http}, inspect_ftp={inspect_ftp}")
            else:
                _, _, err = client.zia.malware_protection_policy.update_atp_malware_protocols(
                    inspect_http=inspect_http,
                    inspect_ftp_over_http=inspect_ftp_over_http,
                    inspect_ftp=inspect_ftp
                )
                if err:
                    logger.error(f"Failed to update ATP Malware Protocols: {err}")
                    raise Exception(f"Failed to update ATP Malware Protocols: {err}")
                logger.info("ATP Malware Protocols updated successfully.")
                
        # Inspection
        tp_inspection = tp_cfg.get("inspection")
        if tp_inspection:
            inbound = tp_inspection.get("inspect_inbound", True)
            outbound = tp_inspection.get("inspect_outbound", True)
            if dry_run:
                logger.info(f"[DRY-RUN] Would update ATP Malware Inspection: inspect_inbound={inbound}, inspect_outbound={outbound}")
            else:
                _, _, err = client.zia.malware_protection_policy.update_atp_malware_inspection(
                    inspect_inbound=inbound,
                    inspect_outbound=outbound
                )
                if err:
                    logger.error(f"Failed to update ATP Malware Inspection: {err}")
                    raise Exception(f"Failed to update ATP Malware Inspection: {err}")
                logger.info("ATP Malware Inspection updated successfully.")
        results["threat_protection"] = "Updated"

    # 4. Policy - Malware Settings
    if config.malware_policy:
        logger.info("Processing ZIA Malware Settings...")
        if dry_run:
            logger.info("[DRY-RUN] Would update Malware settings")
        else:
            try:
                from zscaler.zia.models.malware_protection_settings import MalwareSettings
                settings_obj = MalwareSettings()
                for k, v in config.malware_policy.items():
                    if hasattr(settings_obj, k):
                        setattr(settings_obj, k, v)
                _, _, err = client.zia.malware_protection_policy.update_malware_settings(settings=settings_obj)
            except Exception as e:
                logger.error(f"Error preparing MalwareSettings object: {e}")
                raise e
            if err:
                logger.error(f"Failed to update Malware Settings: {err}")
                raise Exception(f"Failed to update Malware Settings: {err}")
            logger.info("ZIA Malware Settings updated successfully.")
        results["malware_policy"] = "Updated"

    # 5. Policy - ATP Settings
    if config.atp_policy:
        logger.info("Processing ZIA ATP Settings...")
        if dry_run:
            logger.info("[DRY-RUN] Would update ZIA ATP Settings")
        else:
            _, _, err = client.zia.atp_policy.update_atp_settings(**config.atp_policy)
            if err:
                logger.error(f"Failed to update ATP Settings: {err}")
                raise Exception(f"Failed to update ATP Settings: {err}")
            logger.info("ZIA ATP Settings updated successfully.")
        results["atp_policy"] = "Updated"

    # 5.5 PAC Files
    if hasattr(config, "pac_files") and config.pac_files:
        import os
        logger.info("Processing ZIA PAC Files...")
        pacs_list, _, err = client.zia.pac_files.list_pac_files()
        if err:
            logger.error(f"Failed to list PAC files: {err}")
            raise Exception(f"Failed to list PAC files: {err}")
            
        target_pacs = {p.name.lower().replace(" ", "_"): p for p in pacs_list}
        
        # Enforce mandatory PRIMARY_DOMAIN
        target_domain = os.getenv("PRIMARY_DOMAIN")
        if not target_domain:
            logger.error("PRIMARY_DOMAIN environment variable is mandatory for PAC file deployment but was not set.")
            raise Exception("PRIMARY_DOMAIN environment variable is mandatory for PAC file deployment but was not set.")
        logger.info(f"Using PRIMARY_DOMAIN for PAC files: {target_domain}")
            
        for pac_cfg in config.pac_files:
            orig_name = pac_cfg.get("name")
            if not orig_name:
                continue
                
            # Replace spaces with underscores for ZIA PAC name constraints
            if " " in orig_name:
                orig_name = orig_name.replace(" ", "_")
                pac_cfg["name"] = orig_name
                
            prefixed_name = apply_prefix_and_truncate_31(orig_name, prefix).replace(" ", "_")
            orig_name_clean = orig_name.replace(" ", "_")
            found_pac = target_pacs.get(prefixed_name.lower()) or target_pacs.get(orig_name_clean.lower())

            
            # Resolve PAC content from external file if pac_file_path is provided
            pac_content = pac_cfg.get("pac_content")
            pac_file_path = pac_cfg.get("pac_file_path")
            if pac_file_path:
                resolved_path = pac_file_path
                if config_dir and not os.path.isabs(resolved_path):
                    resolved_path = os.path.join(config_dir, resolved_path)
                try:
                    with open(resolved_path, "r", encoding="utf-8") as pf:
                        pac_content = pf.read()
                    logger.info(f"Loaded PAC content for '{prefixed_name}' from file: {pac_file_path}")
                except Exception as e:
                    logger.error(f"Failed to read PAC file from path '{pac_file_path}': {e}")
                    raise Exception(f"Failed to read PAC file from path '{pac_file_path}': {e}")
            
            # Substitute template variables in PAC content
            if pac_content:
                vanity_domain = os.getenv("ZSCALER_VANITY_DOMAIN") or ""
                vanity_prefix = vanity_domain.split(".")[0] if vanity_domain else ""
                cloud_name = os.getenv("ZSCALER_CLOUD") or "production"
                
                pac_content = pac_content.replace("${PRIMARY_DOMAIN}", target_domain)
                pac_content = pac_content.replace("${ZSCALER_ORGANIZATION_DOMAIN}", target_domain)
                pac_content = pac_content.replace("${ORGANIZATION_DOMAIN}", target_domain)
                
                if vanity_domain:
                    pac_content = pac_content.replace("${ZSCALER_VANITY_DOMAIN}", vanity_domain)
                if vanity_prefix:
                    pac_content = pac_content.replace("${ZSCALER_VANITY_PREFIX}", vanity_prefix)
                if cloud_name:
                    pac_content = pac_content.replace("${ZSCALER_CLOUD}", cloud_name)
                
                logger.info(f"Substituted template variables in PAC content for '{prefixed_name}'")

            
            # Prepare payload
            payload = {
                "name": prefixed_name,
                "description": pac_cfg.get("description", prefixed_name),
                "domain": target_domain,
                "pac_content": pac_content,
                "pac_commit_message": pac_cfg.get("pac_commit_message") or "Deployed via SE Toolkit",
                "pac_verification_status": "VERIFY_NOERR",
                "pac_version_status": "DEPLOYED"
            }
            
            if found_pac:
                logger.info(f"PAC File '{prefixed_name}' already exists (ID: {found_pac.id}, Version: {found_pac.pac_version}). Updating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would update PAC file '{prefixed_name}' (ID: {found_pac.id})")
                else:
                    _, _, err = client.zia.pac_files.update_pac_file(
                        pac_id=found_pac.id,
                        pac_version=found_pac.pac_version,
                        pac_version_action="DEPLOY",
                        **payload
                    )
                    if err:
                        err_msg = str(getattr(err, "message", err))
                        if "already deployed" in err_msg.lower():
                            logger.info(f"PAC File '{prefixed_name}' is already deployed. Skipping deployment update.")
                        else:
                            logger.error(f"Failed to update PAC file '{prefixed_name}': {err}")
                            raise Exception(f"Failed to update PAC file '{prefixed_name}': {err}")
                    else:
                        logger.info(f"PAC File '{prefixed_name}' updated successfully.")
            else:
                logger.info(f"PAC File '{prefixed_name}' does not exist. Creating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create PAC file '{prefixed_name}' with domain: {target_domain}")
                else:
                    _, _, err = client.zia.pac_files.add_pac_file(**payload)
                    if err:
                        logger.error(f"Failed to create PAC file '{prefixed_name}': {err}")
                        raise Exception(f"Failed to create PAC file '{prefixed_name}': {err}")
                    logger.info(f"PAC File '{prefixed_name}' created successfully.")

    # 12. IP Destination Groups
    if hasattr(config, "ip_destination_groups") and config.ip_destination_groups:
        results["ip_destination_groups"] = []
        logger.info("Processing ZIA IP Destination Groups...")
        groups, _, err = client.zia.cloud_firewall.list_ip_destination_groups()
        if err:
            logger.error(f"Failed to list IP Destination Groups: {err}")
            raise Exception(f"Failed to list IP Destination Groups: {err}")
            
        target_groups = {g.name.lower(): g for g in groups}

        for g_cfg in config.ip_destination_groups:
            orig_name = g_cfg.get("name")
            if not orig_name:
                continue
            prefixed_name = apply_prefix(orig_name, prefix)
            found_group = target_groups.get(prefixed_name.lower())
            
            payload = dict(g_cfg)
            payload["name"] = prefixed_name
            
            # Remove read-only/metadata fields
            for k in ["id", "is_non_editable", "isNonEditable"]:
                payload.pop(k, None)

            if found_group:
                logger.info(f"IP Destination Group '{prefixed_name}' already exists. Updating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would update IP Destination Group '{prefixed_name}' (ID: {found_group.id})")
                else:
                    _, _, err = client.zia.cloud_firewall.update_ip_destination_group(group_id=found_group.id, **payload)
                    if err:
                        logger.error(f"Failed to update IP Destination Group '{prefixed_name}': {err}")
                        raise Exception(f"Failed to update IP Destination Group '{prefixed_name}': {err}")
                    logger.info(f"IP Destination Group '{prefixed_name}' updated successfully.")
                results["ip_destination_groups"].append({"name": prefixed_name, "status": "Updated"})
            else:
                logger.info(f"IP Destination Group '{prefixed_name}' does not exist. Creating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create IP Destination Group '{prefixed_name}'")
                else:
                    _, _, err = client.zia.cloud_firewall.add_ip_destination_group(**payload)
                    if err:
                        logger.error(f"Failed to create IP Destination Group '{prefixed_name}': {err}")
                        raise Exception(f"Failed to create IP Destination Group '{prefixed_name}': {err}")
                    logger.info(f"IP Destination Group '{prefixed_name}' created successfully.")
                results["ip_destination_groups"].append({"name": prefixed_name, "status": "Created"})

    # 13. IP Source Groups
    if hasattr(config, "ip_source_groups") and config.ip_source_groups:
        results["ip_source_groups"] = []
        logger.info("Processing ZIA IP Source Groups...")
        groups, _, err = client.zia.cloud_firewall.list_ip_source_groups()
        if err:
            logger.error(f"Failed to list IP Source Groups: {err}")
            raise Exception(f"Failed to list IP Source Groups: {err}")
            
        target_groups = {g.name.lower(): g for g in groups}

        for g_cfg in config.ip_source_groups:
            orig_name = g_cfg.get("name")
            if not orig_name:
                continue
            prefixed_name = apply_prefix(orig_name, prefix)
            found_group = target_groups.get(prefixed_name.lower())
            
            payload = dict(g_cfg)
            payload["name"] = prefixed_name
            
            # Remove read-only/metadata fields
            for k in ["id", "is_non_editable", "isNonEditable"]:
                payload.pop(k, None)

            if found_group:
                logger.info(f"IP Source Group '{prefixed_name}' already exists. Updating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would update IP Source Group '{prefixed_name}' (ID: {found_group.id})")
                else:
                    _, _, err = client.zia.cloud_firewall.update_ip_source_group(group_id=found_group.id, **payload)
                    if err:
                        logger.error(f"Failed to update IP Source Group '{prefixed_name}': {err}")
                        raise Exception(f"Failed to update IP Source Group '{prefixed_name}': {err}")
                    logger.info(f"IP Source Group '{prefixed_name}' updated successfully.")
                results["ip_source_groups"].append({"name": prefixed_name, "status": "Updated"})
            else:
                logger.info(f"IP Source Group '{prefixed_name}' does not exist. Creating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create IP Source Group '{prefixed_name}'")
                else:
                    _, _, err = client.zia.cloud_firewall.add_ip_source_group(**payload)
                    if err:
                        logger.error(f"Failed to create IP Source Group '{prefixed_name}': {err}")
                        raise Exception(f"Failed to create IP Source Group '{prefixed_name}': {err}")
                    logger.info(f"IP Source Group '{prefixed_name}' created successfully.")
                results["ip_source_groups"].append({"name": prefixed_name, "status": "Created"})

    # 14. Root Certificates
    if hasattr(config, "root_certificates") and config.root_certificates:
        results["root_certificates"] = []
        logger.info("Processing ZIA Root Certificates...")
        
        # Get existing root certificates on target tenant
        url = "/zia/api/v1/rootCertificates"
        request, error = client._request_executor.create_request("GET", url, {}, {})
        if error:
            logger.error(f"Failed to create request for target root certificates: {error}")
            raise Exception(f"Failed to list target root certificates: {error}")
        response, error = client._request_executor.execute(request)
        if error:
            logger.error(f"Failed to fetch target root certificates: {error}")
            raise Exception(f"Failed to fetch target root certificates: {error}")
            
        target_certs = {c.get("displayName").lower(): c for c in response.get_body() if c.get("displayName")}

        for cert_cfg in config.root_certificates:
            orig_name = cert_cfg.get("displayName")
            if not orig_name:
                continue
            prefixed_name = apply_prefix(orig_name, prefix)
            found_cert = target_certs.get(prefixed_name.lower())

            if found_cert:
                logger.info(f"Root Certificate '{prefixed_name}' already exists. Skipping upload.")
                results["root_certificates"].append({"name": prefixed_name, "id": found_cert.get("id"), "status": "Skipped"})
            else:
                logger.info(f"Root Certificate '{prefixed_name}' does not exist. Preparing upload...")
                cert_pem = cert_cfg.get("cert")
                
                # Check if it is a placeholder or not provided
                if not cert_pem or "PLACEHOLDER" in cert_pem:
                    # Look for file at configs/certificates/{displayName}.pem or configs/certificates/{name}
                    potential_paths = [
                        os.path.join("configs", "certificates", f"{orig_name}.pem"),
                        os.path.join("configs", "certificates", cert_cfg.get("name", "")),
                        os.path.join("configs", "certificates", f"{prefixed_name}.pem")
                    ]
                    for path in potential_paths:
                        if os.path.exists(path):
                            try:
                                with open(path, "r", encoding="utf-8") as f:
                                    cert_pem = f.read()
                                logger.info(f"Found root certificate file locally at: {path}")
                                break
                            except Exception as e:
                                logger.warning(f"Could not read root certificate file at {path}: {e}")

                if not cert_pem or "PLACEHOLDER" in cert_pem:
                    logger.warning(f"Cannot upload Root Certificate '{prefixed_name}': PEM cert content not found. Please place the file in 'configs/certificates/{orig_name}.pem' or upload it manually in ZIA UI.")
                    results["root_certificates"].append({"name": prefixed_name, "status": "Failed (Missing PEM)"})
                else:
                    normalized_cert = normalize_pem(cert_pem)
                    payload = {
                        "name": cert_cfg.get("name", f"{prefixed_name}.pem"),
                        "displayName": prefixed_name,
                        "cert": normalized_cert,
                        "certTypes": cert_cfg.get("certTypes", ["PROXY_CHAINING"])
                    }
                    if dry_run:
                        logger.info(f"[DRY-RUN] Would upload ZIA Root Certificate '{prefixed_name}'")
                    else:
                        request, error = client._request_executor.create_request("POST", url, payload, {})
                        if error:
                            logger.error(f"Failed to create upload request for Root Certificate '{prefixed_name}': {error}")
                            raise Exception(f"Failed to upload Root Certificate '{prefixed_name}': {error}")
                        res, error = client._request_executor.execute(request)
                        if error:
                            if "already exists" in str(error).lower():
                                logger.warning(f"Root Certificate '{prefixed_name}' already exists in backend. Treating as successfully created.")
                            else:
                                logger.error(f"Failed to upload Root Certificate '{prefixed_name}': {error}")
                                raise Exception(f"Failed to upload Root Certificate '{prefixed_name}': {error}")
                        else:
                            logger.info(f"Root Certificate '{prefixed_name}' uploaded successfully.")
                    results["root_certificates"].append({"name": prefixed_name, "status": "Created/Exists"})

    # 15. Proxies
    if hasattr(config, "proxies") and config.proxies:
        results["proxies"] = []
        logger.info("Processing ZIA Proxies...")
        
        # Get existing proxies on target tenant
        existing_proxies, _, err = client.zia.proxies.list_proxies()
        if err:
            logger.error(f"Failed to list target proxies: {err}")
            raise Exception(f"Failed to list target proxies: {err}")
            
        target_proxies = {p.name.lower(): p for p in existing_proxies}
        
        # Get existing root certificates to map cert name -> ID
        url = "/zia/api/v1/rootCertificates"
        request, error = client._request_executor.create_request("GET", url, {}, {})
        if error:
            logger.error(f"Failed to create request for target root certificates: {error}")
            raise Exception(f"Failed to list target root certificates: {error}")
        response, error = client._request_executor.execute(request)
        if error:
            logger.error(f"Failed to fetch target root certificates: {error}")
            raise Exception(f"Failed to fetch target root certificates: {error}")
        cert_map = {c.get("displayName").lower(): c.get("id") for c in response.get_body() if c.get("displayName")}

        for proxy_cfg in config.proxies:
            orig_name = proxy_cfg.get("name")
            if not orig_name:
                continue
            prefixed_name = apply_prefix(orig_name, prefix)
            found_proxy = target_proxies.get(prefixed_name.lower())
            
            payload = dict(proxy_cfg)
            payload["name"] = prefixed_name
            payload.pop("id", None)
            
            # Resolve cert reference
            if "cert" in payload and isinstance(payload["cert"], dict):
                cert_name = payload["cert"].get("name")
                cert_id = None
                if cert_name:
                    prefixed_cert_name = apply_prefix(cert_name, prefix)
                    cert_id = cert_map.get(prefixed_cert_name.lower()) or cert_map.get(cert_name.lower())
                if cert_id:
                    payload["cert"] = {"id": cert_id}
                else:
                    logger.warning(f"Could not resolve Root Certificate reference '{cert_name}' for Proxy '{prefixed_name}'")

            if found_proxy:
                logger.info(f"Proxy '{prefixed_name}' already exists. Updating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would update Proxy '{prefixed_name}' (ID: {found_proxy.id})")
                else:
                    _, _, err = client.zia.proxies.update_proxy(proxy_id=found_proxy.id, **payload)
                    if err:
                        logger.error(f"Failed to update Proxy '{prefixed_name}': {err}")
                        raise Exception(f"Failed to update Proxy '{prefixed_name}': {err}")
                    logger.info(f"Proxy '{prefixed_name}' updated successfully.")
                results["proxies"].append({"name": prefixed_name, "status": "Updated"})
            else:
                logger.info(f"Proxy '{prefixed_name}' does not exist. Creating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create Proxy '{prefixed_name}'")
                else:
                    _, _, err = client.zia.proxies.add_proxy(**payload)
                    if err:
                        logger.error(f"Failed to create Proxy '{prefixed_name}': {err}")
                        raise Exception(f"Failed to create Proxy '{prefixed_name}': {err}")
                    logger.info(f"Proxy '{prefixed_name}' created successfully.")
                results["proxies"].append({"name": prefixed_name, "status": "Created"})

    # 16. Proxy Gateways
    if hasattr(config, "proxy_gateways") and config.proxy_gateways:
        results["proxy_gateways"] = []
        logger.info("Processing ZIA Proxy Gateways...")
        
        # Get existing gateways
        existing_gws, _, err = client.zia.proxies.list_proxy_gateways()
        if err:
            logger.error(f"Failed to list target proxy gateways: {err}")
            raise Exception(f"Failed to list target proxy gateways: {err}")
            
        target_gws = {g.name.lower(): g for g in existing_gws}
        
        # Ensure target_proxies exists for reference resolution
        if "target_proxies" not in locals():
            existing_proxies, _, err = client.zia.proxies.list_proxies()
            if err:
                logger.error(f"Failed to list target proxies for gateway resolution: {err}")
                raise Exception(f"Failed to list target proxies for gateway resolution: {err}")
            target_proxies = {p.name.lower(): p for p in existing_proxies}
        
        for gw_cfg in config.proxy_gateways:
            orig_name = gw_cfg.get("name")
            if not orig_name:
                continue
            prefixed_name = apply_prefix(orig_name, prefix)
            found_gw = target_gws.get(prefixed_name.lower())
            
            payload = dict(gw_cfg)
            payload["name"] = prefixed_name
            payload.pop("id", None)
            
            # Resolve primary proxy
            if "primary_proxy" in payload and isinstance(payload["primary_proxy"], dict):
                p_name = payload["primary_proxy"].get("name")
                if p_name:
                    pref_p_name = apply_prefix(p_name, prefix)
                    p_proxy = target_proxies.get(pref_p_name.lower()) or target_proxies.get(p_name.lower())
                    if p_proxy:
                        payload["primary_proxy"] = {"id": p_proxy.id}
                    else:
                        logger.warning(f"Could not resolve primary proxy '{p_name}' for Gateway '{prefixed_name}'")
                
            # Resolve secondary proxy
            if "secondary_proxy" in payload and isinstance(payload["secondary_proxy"], dict):
                s_name = payload["secondary_proxy"].get("name")
                if s_name:
                    pref_s_name = apply_prefix(s_name, prefix)
                    s_proxy = target_proxies.get(pref_s_name.lower()) or target_proxies.get(s_name.lower())
                    if s_proxy:
                        payload["secondary_proxy"] = {"id": s_proxy.id}
                    else:
                        logger.warning(f"Could not resolve secondary proxy '{s_name}' for Gateway '{prefixed_name}'")
            
            if found_gw:
                logger.info(f"Proxy Gateway '{prefixed_name}' exists. Skipping update (API is read-only).")
                results["proxy_gateways"].append({"name": prefixed_name, "status": "Skipped (Read-only API)"})
            else:
                logger.info(f"Proxy Gateway '{prefixed_name}' does not exist. Creating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create Proxy Gateway '{prefixed_name}'")
                else:
                    url = "/zia/api/v1/proxyGateways"
                    req, err = client._request_executor.create_request("POST", url, payload, {})
                    if err:
                        raise Exception(f"Failed to construct create request for Gateway '{prefixed_name}': {err}")
                    _, err = client._request_executor.execute(req)
                    if err:
                        if (isinstance(err, dict) and err.get("status") == 405) or ("405" in str(err)):
                            if dry_run:
                                logger.warning(f"[DRY-RUN] Proxy Gateway '{prefixed_name}' must be created manually.")
                                results["proxy_gateways"].append({"name": prefixed_name, "status": "Manual Creation Required"})
                            else:
                                logger.warning(f"\n[ACTION REQUIRED] Proxy Gateways cannot be created via the API.")
                                print(f"\nPlease log in to the ZIA Admin UI and manually create a Proxy Gateway with the EXACT name:")
                                print(f"   Name: {prefixed_name}")
                                if "primary_proxy" in payload and payload["primary_proxy"].get("id"):
                                    p_name = gw_cfg.get("primary_proxy", {}).get("name", "Unknown Proxy")
                                    print(f"   Primary Proxy: {apply_prefix(p_name, prefix)}")
                                
                                while True:
                                    user_input = input(f"\nHave you created the Proxy Gateway '{prefixed_name}' in the UI? (y/n/exit): ").strip().lower()
                                    if user_input == 'exit':
                                        logger.error("User exited during Proxy Gateway creation step.")
                                        raise Exception("Script aborted by user.")
                                    elif user_input in ['y', 'yes']:
                                        print("Verifying Proxy Gateway exists...")
                                        verify_gws, _, v_err = client.zia.proxies.list_proxy_gateways()
                                        if not v_err and verify_gws:
                                            found_verify = next((g for g in verify_gws if g.name.lower() == prefixed_name.lower()), None)
                                            if found_verify:
                                                logger.info(f"Verified! Proxy Gateway '{prefixed_name}' found with ID {found_verify.id}.")
                                                results["proxy_gateways"].append({"name": prefixed_name, "status": "Manually Created & Verified"})
                                                break
                                            else:
                                                logger.warning(f"Could not find Proxy Gateway '{prefixed_name}'. Please ensure the name matches exactly.")
                                        else:
                                            logger.warning("Failed to fetch proxy gateways for verification. Please try again.")
                                    else:
                                        print("Waiting for you to create it...")
                        else:
                            raise Exception(f"Failed to create Proxy Gateway '{prefixed_name}': {err}")
                    else:
                        logger.info(f"Proxy Gateway '{prefixed_name}' created successfully.")
                        results["proxy_gateways"].append({"name": prefixed_name, "status": "Created"})

    # 5.6. Policy - Rule Labels
    if (hasattr(config, "rule_labels") and config.rule_labels) or rule_label:
        ensure_refs_fetched()
        results["rule_labels"] = []
        labels_to_deploy = []
        if hasattr(config, "rule_labels") and config.rule_labels:
            for l_cfg in config.rule_labels:
                l_dict = l_cfg.model_dump() if hasattr(l_cfg, "model_dump") else (l_cfg.dict() if hasattr(l_cfg, "dict") else dict(l_cfg))
                labels_to_deploy.append(l_dict)
        if rule_label:
            if not any(l.get("name") == rule_label for l in labels_to_deploy):
                labels_to_deploy.append({"name": rule_label, "description": f"Rule Label {rule_label}"})

        for lbl in labels_to_deploy:
            l_name = lbl.get("name")
            if not l_name:
                continue
            prefixed_name = apply_prefix(l_name, prefix)
            existing_id = target_rule_labels.get(prefixed_name.lower()) or target_rule_labels.get(l_name.lower())
            if existing_id:
                logger.info(f"Rule Label '{prefixed_name}' already exists (ID: {existing_id}).")
                results["rule_labels"].append({"name": prefixed_name, "status": "Exists", "id": existing_id})
            else:
                logger.info(f"Creating Rule Label '{prefixed_name}'...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create Rule Label '{prefixed_name}'")
                    results["rule_labels"].append({"name": prefixed_name, "status": "Dry-run (Would create)"})
                else:
                    new_lbl, _, err = client.zia.rule_labels.add_label(name=prefixed_name, description=lbl.get("description", ""))
                    if err:
                        logger.error(f"Failed to create Rule Label '{prefixed_name}': {err}")
                        raise Exception(f"Failed to create Rule Label '{prefixed_name}': {err}")
                    new_id = getattr(new_lbl, "id", None) or (new_lbl.get("id") if isinstance(new_lbl, dict) else None)
                    logger.info(f"Rule Label '{prefixed_name}' created successfully (ID: {new_id}).")
                    if new_id:
                        target_rule_labels[prefixed_name.lower()] = new_id
                    results["rule_labels"].append({"name": prefixed_name, "status": "Created", "id": new_id})

    # 6. Policy - SSL Advanced Policy Settings
    if config.ssl_policy:
        results["ssl_policy"] = []
        rules, _, err = client.zia.ssl_inspection_rules.list_rules()
        if err:
            logger.error(f"Failed to list SSL inspection rules: {err}")
            raise Exception(f"Failed to list SSL inspection rules: {err}")
            
        # Fetch target mappings for linkage resolution
        ensure_refs_fetched()

        current_ssl_rule_count = count_active_rules(rules)

        for rule_cfg in config.ssl_policy:
            orig_name = rule_cfg.get("name")
            if not orig_name:
                continue
                
            if rule_cfg.get("predefined") or rule_cfg.get("default_rule"):
                logger.info(f"SSL rule '{orig_name}' is predefined or default. Skipping deployment.")
                results["ssl_policy"].append({"name": orig_name, "status": "Skipped (predefined/default)"})
                continue

            prefixed_name = apply_prefix_and_truncate_31(orig_name, prefix)
            found_rule = next((r for r in rules if r.name == prefixed_name), None)
            
            params = dict(rule_cfg)
            params["name"] = prefixed_name

            # Resolve mappings
            if "locations" in params:
                params["locations"] = resolve_ref_list(params["locations"], target_locations)
                if not params["locations"]:
                    params.pop("locations")
                    
            if "groups" in params:
                params["groups"] = resolve_ref_list(params["groups"], target_groups)
                if not params["groups"]:
                    params.pop("groups")
                    
            if "departments" in params:
                params["departments"] = resolve_ref_list(params["departments"], target_departments)
                if not params["departments"]:
                    params.pop("departments")
                    
            if "zpa_app_segments" in params:
                params["zpa_app_segments"] = resolve_ref_list(params["zpa_app_segments"], target_zpa_segments)
                if not params["zpa_app_segments"]:
                    params.pop("zpa_app_segments")
                    
            if "dest_ip_groups" in params:
                params["dest_ip_groups"] = resolve_ref_list(params["dest_ip_groups"], target_dest_ip_groups)
                if not params["dest_ip_groups"]:
                    params.pop("dest_ip_groups")
            
            if "state" not in params:
                params["state"] = "ENABLED"
                
            if "url_categories" in params:
                resolved_cats = []
                for cat_ref in params["url_categories"]:
                    prefixed_ref = cat_ref
                    if prefix and not cat_ref.startswith(prefix):
                        prefixed_ref = f"{prefix} - {cat_ref}"
                        
                    resolved_id = cat_map.get(prefixed_ref.lower()) or cat_map.get(cat_ref.lower())
                    if resolved_id:
                        resolved_cats.append(resolved_id)
                    else:
                        resolved_cats.append(cat_ref)
                params["url_categories"] = resolved_cats

            # Remove fields that shouldn't be passed to CRUD operations
            for k in ["id", "predefined", "default_rule", "access_control", "last_modified_by", "last_modified_time"]:
                params.pop(k, None)

            if "action" in params and isinstance(params["action"], str):
                params["action"] = {"type": params["action"]}

            # Resolve rule labels
            resolved_lbls = resolve_labels(params.get("labels"))
            if resolved_lbls:
                params["labels"] = resolved_lbls
            elif "labels" in params:
                params.pop("labels")

            # Adjust order if out of bounds
            if "order" in params:
                configured_order = params["order"]
                max_possible_order = current_ssl_rule_count if found_rule else (current_ssl_rule_count + 1)
                if configured_order > max_possible_order:
                    logger.info(f"Adjusting order of SSL rule '{prefixed_name}' from {configured_order} to {max_possible_order} to fit current rule count ({current_ssl_rule_count}).")
                    params["order"] = max_possible_order

            if found_rule:
                logger.info(f"SSL rule '{prefixed_name}' already exists. Updating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would update SSL rule '{prefixed_name}' (ID: {found_rule.id})")
                else:
                    _, _, err = client.zia.ssl_inspection_rules.update_rule(rule_id=found_rule.id, **params)
                    if err:
                        logger.error(f"Failed to update SSL rule '{prefixed_name}': {err}")
                        raise Exception(f"Failed to update SSL rule '{prefixed_name}': {err}")
                    logger.info(f"SSL rule '{prefixed_name}' updated successfully.")
                results["ssl_policy"].append({"name": prefixed_name, "status": "Updated"})
            else:
                logger.info(f"SSL rule '{prefixed_name}' does not exist. Creating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create SSL rule '{prefixed_name}'")
                    current_ssl_rule_count += 1
                else:
                    _, _, err = client.zia.ssl_inspection_rules.add_rule(**params)
                    if err:
                        logger.error(f"Failed to create SSL rule '{prefixed_name}': {err}")
                        raise Exception(f"Failed to create SSL rule '{prefixed_name}': {err}")
                    logger.info(f"SSL rule '{prefixed_name}' created successfully.")
                    current_ssl_rule_count += 1
                results["ssl_policy"].append({"name": prefixed_name, "status": "Created"})

    # 7. URL Filtering Rules
    if config.url_filtering_rules:
        results["url_filtering_rules"] = []
        rules, _, err = client.zia.url_filtering.list_rules()
        if err:
            logger.error(f"Failed to list URL filtering rules: {err}")
            raise Exception(f"Failed to list URL filtering rules: {err}")
            
        current_url_rule_count = count_active_rules(rules)

        for rule_cfg in config.url_filtering_rules:
            orig_name = rule_cfg.name
            prefixed_name = apply_prefix_and_truncate_31(orig_name, prefix)
            found_rule = next((r for r in rules if r.name == prefixed_name), None)
            
            params = rule_cfg.model_dump(exclude_none=True)
            params["name"] = prefixed_name
            
            # Resolve URL category names
            if "url_categories" in params:
                resolved_cats = []
                for cat_ref in params["url_categories"]:
                    prefixed_ref = cat_ref
                    if prefix and not cat_ref.startswith(prefix):
                        prefixed_ref = f"{prefix} - {cat_ref}"
                    resolved_id = cat_map.get(prefixed_ref.lower()) or cat_map.get(cat_ref.lower())
                    if resolved_id:
                        resolved_cats.append(resolved_id)
                    else:
                        resolved_cats.append(cat_ref)
                params["url_categories"] = resolved_cats

            # Map state
            if "state" not in params:
                params["state"] = "ENABLED"

            # Resolve rule labels
            resolved_lbls = resolve_labels(params.get("labels"))
            if resolved_lbls:
                params["labels"] = resolved_lbls
            elif "labels" in params:
                params.pop("labels")

            if found_rule:
                logger.info(f"URL Filtering rule '{prefixed_name}' already exists. Skipping...")
                results["url_filtering_rules"].append({"name": prefixed_name, "id": found_rule.id, "status": "Skipped"})
            else:
                logger.info(f"URL Filtering rule '{prefixed_name}' does not exist. Creating...")
                # Adjust order if out of bounds
                if "order" in params:
                    configured_order = params["order"]
                    max_possible_order = current_url_rule_count + 1
                    if configured_order > max_possible_order:
                        logger.info(f"Adjusting order of URL Filtering rule '{prefixed_name}' from {configured_order} to {max_possible_order} to fit current rule count ({current_url_rule_count}).")
                        params["order"] = max_possible_order

                if dry_run:
                    logger.info(f"[DRY-RUN] Would create URL Filtering rule '{prefixed_name}'")
                    current_url_rule_count += 1
                else:
                    _, _, err = client.zia.url_filtering.add_rule(**params)
                    if err:
                        err_msg = str(getattr(err, "message", err))
                        if "duplicate name" in err_msg.lower() or "already exists" in err_msg.lower():
                            logger.info(f"URL Filtering rule '{prefixed_name}' already exists (duplicate). Skipping creation.")
                        else:
                            logger.error(f"Failed to create URL Filtering rule '{prefixed_name}': {err}")
                            raise Exception(f"Failed to create URL Filtering rule '{prefixed_name}': {err}")
                    else:
                        logger.info(f"URL Filtering rule '{prefixed_name}' created successfully.")
                        current_url_rule_count += 1
                results["url_filtering_rules"].append({"name": prefixed_name, "status": "Created"})

    # 8. Cloud App Control (CASB) Rules
    if config.cloud_app_control_rules:
        results["cloud_app_control_rules"] = []
        for category, rules_list in config.cloud_app_control_rules.items():
            rule_type = category.upper()
            
            # List rules of this type to see if it already exists
            rules, _, err = client.zia.cloudappcontrol.list_rules(rule_type=rule_type)
            if err:
                logger.warning(f"Failed to list Cloud App Control rules for type {rule_type}: {err}")
                rules = []
                
            current_casb_rule_count = count_active_rules(rules)

            for rule_cfg in rules_list:
                orig_name = rule_cfg.name
                if getattr(rule_cfg, "predefined", None) or getattr(rule_cfg, "default_rule", None) or getattr(rule_cfg, "defaultRule", None):
                    logger.info(f"Cloud App Control rule '{orig_name}' is predefined or default. Skipping deployment.")
                    results["cloud_app_control_rules"].append({"name": orig_name, "status": "Skipped (predefined/default)"})
                    continue

                prefixed_name = apply_prefix_and_truncate_31(orig_name, prefix)
                found_rule = next((r for r in rules if r.name == prefixed_name), None)
                
                params = rule_cfg.model_dump(exclude_none=True)
                params["name"] = prefixed_name
                
                # Map state
                if "state" not in params:
                    params["state"] = "ENABLED"

                # Resolve rule labels
                resolved_lbls = resolve_labels(params.get("labels"))
                if resolved_lbls:
                    params["labels"] = resolved_lbls
                elif "labels" in params:
                    params.pop("labels")
                    
                if found_rule:
                    logger.info(f"Cloud App Control rule '{prefixed_name}' already exists. Skipping...")
                    results["cloud_app_control_rules"].append({"name": prefixed_name, "id": found_rule.id, "status": "Skipped"})
                else:
                    logger.info(f"Cloud App Control rule '{prefixed_name}' does not exist. Creating...")
                    # Adjust order if out of bounds
                    if "order" in params:
                        configured_order = params["order"]
                        max_possible_order = current_casb_rule_count + 1
                        if configured_order > max_possible_order:
                            logger.info(f"Adjusting order of Cloud App Control rule '{prefixed_name}' from {configured_order} to {max_possible_order} to fit current rule count ({current_casb_rule_count}).")
                            params["order"] = max_possible_order

                    if dry_run:
                        logger.info(f"[DRY-RUN] Would create Cloud App Control rule '{prefixed_name}' for type {rule_type}")
                        current_casb_rule_count += 1
                    else:
                        _, _, err = client.zia.cloudappcontrol.add_rule(rule_type=rule_type, **params)
                        if err:
                            err_msg = str(getattr(err, "message", err))
                            if "duplicate name" in err_msg.lower() or "already exists" in err_msg.lower():
                                logger.info(f"Cloud App Control rule '{prefixed_name}' already exists (duplicate). Skipping creation.")
                            else:
                                logger.error(f"Failed to create Cloud App Control rule '{prefixed_name}': {err}")
                                raise Exception(f"Failed to create Cloud App Control rule '{prefixed_name}': {err}")
                        else:
                            logger.info(f"Cloud App Control rule '{prefixed_name}' created successfully.")
                            current_casb_rule_count += 1
                    results["cloud_app_control_rules"].append({"name": prefixed_name, "status": "Created"})

    # 9. Cloud Firewall Rules
    if config.firewall_rules:
        results["firewall_rules"] = []
        rules, _, err = client.zia.cloud_firewall_rules.list_rules()
        if err:
            logger.error(f"Failed to list Cloud Firewall rules: {err}")
            raise Exception(f"Failed to list Cloud Firewall rules: {err}")
            
        current_fw_rule_count = count_active_rules(rules)

        # Map target tenant Network Services and Network Service Groups by name
        target_nw_services = {}
        try:
            ns_list, _, err = client.zia.cloud_firewall.list_network_services()
            if not err and ns_list:
                for ns in ns_list:
                    ns_dict = ns.as_dict() if hasattr(ns, "as_dict") else dict(ns)
                    ns_id = ns_dict.get("id")
                    ns_name = ns_dict.get("name")
                    if ns_id is not None and ns_name:
                        target_nw_services[ns_name.lower()] = ns_id
                        ns_tag = ns_dict.get("tag")
                        if ns_tag:
                            target_nw_services[ns_tag.lower()] = ns_id
        except Exception as e:
            logger.warning(f"Could not load target Network Services: {e}")

        target_nw_svc_groups = {}
        try:
            nsg_list, _, err = client.zia.cloud_firewall.list_network_svc_groups()
            if not err and nsg_list:
                for nsg in nsg_list:
                    nsg_dict = nsg.as_dict() if hasattr(nsg, "as_dict") else dict(nsg)
                    nsg_id = nsg_dict.get("id")
                    nsg_name = nsg_dict.get("name")
                    if nsg_id is not None and nsg_name:
                        target_nw_svc_groups[nsg_name.lower()] = nsg_id
        except Exception as e:
            logger.warning(f"Could not load target Network Service Groups: {e}")

        for rule_cfg in config.firewall_rules:
            orig_name = rule_cfg.name
            prefixed_name = apply_prefix_and_truncate_31(orig_name, prefix)
            found_rule = next((r for r in rules if r.name == prefixed_name), None)
            
            params = rule_cfg.model_dump(exclude_none=True)
            params["name"] = prefixed_name
            
            if "state" not in params:
                params["state"] = "ENABLED"

            # Resolve rule labels
            resolved_lbls = resolve_labels(params.get("labels"))
            if resolved_lbls:
                params["labels"] = resolved_lbls
            elif "labels" in params:
                params.pop("labels")

            # Resolve Network Services by name against target tenant
            if "nw_services" in params and isinstance(params["nw_services"], list):
                resolved_nw_services = []
                for s in params["nw_services"]:
                    s_name = None
                    if isinstance(s, dict):
                        s_name = s.get("name")
                    elif isinstance(s, str):
                        s_name = s
                    
                    if s_name:
                        target_id = target_nw_services.get(s_name.lower())
                        if target_id is not None:
                            resolved_nw_services.append({"id": target_id})
                            logger.info(f"Resolved Network Service '{s_name}' -> Target ID {target_id}")
                        else:
                            logger.warning(f"Could not resolve Network Service '{s_name}' on target tenant.")
                if resolved_nw_services:
                    params["nw_services"] = resolved_nw_services
                else:
                    params.pop("nw_services", None)

            # Resolve Network Service Groups by name against target tenant
            if "nw_service_groups" in params and isinstance(params["nw_service_groups"], list):
                resolved_nw_svc_groups = []
                for sg in params["nw_service_groups"]:
                    sg_name = None
                    if isinstance(sg, dict):
                        sg_name = sg.get("name")
                    elif isinstance(sg, str):
                        sg_name = sg
                    
                    if sg_name:
                        target_id = target_nw_svc_groups.get(sg_name.lower()) or target_nw_svc_groups.get(apply_prefix_and_truncate_31(sg_name, prefix).lower())
                        if target_id is not None:
                            resolved_nw_svc_groups.append({"id": target_id})
                            logger.info(f"Resolved Network Service Group '{sg_name}' -> Target ID {target_id}")
                        else:
                            logger.warning(f"Could not resolve Network Service Group '{sg_name}' on target tenant.")
                if resolved_nw_svc_groups:
                    params["nw_service_groups"] = resolved_nw_svc_groups
                else:
                    params.pop("nw_service_groups", None)
                
            if found_rule:
                logger.info(f"Cloud Firewall rule '{prefixed_name}' already exists. Skipping...")
                results["firewall_rules"].append({"name": prefixed_name, "id": found_rule.id, "status": "Skipped"})
            else:
                logger.info(f"Cloud Firewall rule '{prefixed_name}' does not exist. Creating...")
                # Adjust order if out of bounds
                if "order" in params:
                    configured_order = params["order"]
                    max_possible_order = current_fw_rule_count + 1
                    if configured_order > max_possible_order:
                        logger.info(f"Adjusting order of Cloud Firewall rule '{prefixed_name}' from {configured_order} to {max_possible_order} to fit current rule count ({current_fw_rule_count}).")
                        params["order"] = max_possible_order

                if dry_run:
                    logger.info(f"[DRY-RUN] Would create Cloud Firewall rule '{prefixed_name}'")
                    current_fw_rule_count += 1
                else:
                    _, _, err = client.zia.cloud_firewall_rules.add_rule(**params)
                    if err:
                        err_msg = str(getattr(err, "message", err))
                        if "duplicate name" in err_msg.lower() or "already exists" in err_msg.lower():
                            logger.info(f"Cloud Firewall rule '{prefixed_name}' already exists (duplicate). Skipping creation.")
                        else:
                            logger.error(f"Failed to create Cloud Firewall rule '{prefixed_name}': {err}")
                            raise Exception(f"Failed to create Cloud Firewall rule '{prefixed_name}': {err}")
                    else:
                        logger.info(f"Cloud Firewall rule '{prefixed_name}' created successfully.")
                        current_fw_rule_count += 1
                results["firewall_rules"].append({"name": prefixed_name, "status": "Created"})

    # 10. DNS Filtering Rules
    if config.dns_rules:
        results["dns_rules"] = []
        rules, _, err = client.zia.cloud_firewall_dns.list_rules()
        if err:
            logger.error(f"Failed to list DNS Filtering rules: {err}")
            raise Exception(f"Failed to list DNS Filtering rules: {err}")
            
        current_dns_rule_count = count_active_rules(rules)

        for rule_cfg in config.dns_rules:
            orig_name = rule_cfg.name
            prefixed_name = apply_prefix_and_truncate_31(orig_name, prefix)
            found_rule = next((r for r in rules if r.name == prefixed_name), None)
            
            params = rule_cfg.model_dump(exclude_none=True)
            params["name"] = prefixed_name
            
            if "state" not in params:
                params["state"] = "ENABLED"

            # Resolve rule labels
            resolved_lbls = resolve_labels(params.get("labels"))
            if resolved_lbls:
                params["labels"] = resolved_lbls
            elif "labels" in params:
                params.pop("labels")
                
            if found_rule:
                logger.info(f"DNS Filtering rule '{prefixed_name}' already exists. Skipping...")
                results["dns_rules"].append({"name": prefixed_name, "id": found_rule.id, "status": "Skipped"})
            else:
                logger.info(f"DNS Filtering rule '{prefixed_name}' does not exist. Creating...")
                # Adjust order if out of bounds
                if "order" in params:
                    configured_order = params["order"]
                    max_possible_order = current_dns_rule_count + 1
                    if configured_order > max_possible_order:
                        logger.info(f"Adjusting order of DNS Filtering rule '{prefixed_name}' from {configured_order} to {max_possible_order} to fit current rule count ({current_dns_rule_count}).")
                        params["order"] = max_possible_order

                if dry_run:
                    logger.info(f"[DRY-RUN] Would create DNS Filtering rule '{prefixed_name}'")
                    current_dns_rule_count += 1
                else:
                    _, _, err = client.zia.cloud_firewall_dns.add_rule(**params)
                    if err:
                        err_msg = str(getattr(err, "message", err))
                        if "duplicate name" in err_msg.lower() or "already exists" in err_msg.lower():
                            logger.info(f"DNS Filtering rule '{prefixed_name}' already exists (duplicate). Skipping creation.")
                        else:
                            logger.error(f"Failed to create DNS Filtering rule '{prefixed_name}': {err}")
                            raise Exception(f"Failed to create DNS Filtering rule '{prefixed_name}': {err}")
                    else:
                        logger.info(f"DNS Filtering rule '{prefixed_name}' created successfully.")
                        current_dns_rule_count += 1
                results["dns_rules"].append({"name": prefixed_name, "status": "Created"})

    # 11. File Type Control Rules
    if config.file_type_rules:
        results["file_type_rules"] = []
        rules, _, err = client.zia.file_type_control_rule.list_rules()
        if err:
            logger.error(f"Failed to list File Type Control rules: {err}")
            raise Exception(f"Failed to list File Type Control rules: {err}")
            
        current_file_rule_count = count_active_rules(rules)

        for rule_cfg in config.file_type_rules:
            orig_name = rule_cfg.name
            prefixed_name = apply_prefix_and_truncate_31(orig_name, prefix)
            found_rule = next((r for r in rules if r.name == prefixed_name), None)
            
            params = rule_cfg.model_dump(exclude_none=True)
            params["name"] = prefixed_name

            # Resolve mappings using ensure_refs_fetched
            ensure_refs_fetched()
            if "locations" in params:
                params["locations"] = resolve_ref_list(params["locations"], target_locations)
                if not params["locations"]:
                    params.pop("locations")
            if "groups" in params:
                params["groups"] = resolve_ref_list(params["groups"], target_groups)
                if not params["groups"]:
                    params.pop("groups")
            if "departments" in params:
                params["departments"] = resolve_ref_list(params["departments"], target_departments)
                if not params["departments"]:
                    params.pop("departments")
            if "zpa_app_segments" in params:
                params["zpa_app_segments"] = resolve_ref_list(params["zpa_app_segments"], target_zpa_segments)
                if not params["zpa_app_segments"]:
                    params.pop("zpa_app_segments")
            
            if "state" not in params:
                params["state"] = "ENABLED"

            # Resolve rule labels
            resolved_lbls = resolve_labels(params.get("labels"))
            if resolved_lbls:
                params["labels"] = resolved_lbls
            elif "labels" in params:
                params.pop("labels")

            if found_rule:
                logger.info(f"File Type Control rule '{prefixed_name}' already exists. Skipping...")
                results["file_type_rules"].append({"name": prefixed_name, "id": found_rule.id, "status": "Skipped"})
            else:
                logger.info(f"File Type Control rule '{prefixed_name}' does not exist. Creating...")
                # Adjust order if out of bounds
                if "order" in params:
                    configured_order = params["order"]
                    max_possible_order = current_file_rule_count + 1
                    if configured_order > max_possible_order:
                        logger.info(f"Adjusting order of File Type Control rule '{prefixed_name}' from {configured_order} to {max_possible_order} to fit current rule count ({current_file_rule_count}).")
                        params["order"] = max_possible_order

                if dry_run:
                    logger.info(f"[DRY-RUN] Would create File Type Control rule '{prefixed_name}'")
                    current_file_rule_count += 1
                else:
                    _, _, err = client.zia.file_type_control_rule.add_rule(**params)
                    if err:
                        err_msg = str(getattr(err, "message", err))
                        if "duplicate name" in err_msg.lower() or "already exists" in err_msg.lower():
                            logger.info(f"File Type Control rule '{prefixed_name}' already exists (duplicate). Skipping creation.")
                        else:
                            logger.error(f"Failed to create File Type Control rule '{prefixed_name}': {err}")
                            raise Exception(f"Failed to create File Type Control rule '{prefixed_name}': {err}")
                    else:
                        logger.info(f"File Type Control rule '{prefixed_name}' created successfully.")
                        current_file_rule_count += 1
                results["file_type_rules"].append({"name": prefixed_name, "status": "Created"})

    # 17. Forwarding Control Rules
    if hasattr(config, "forwarding_rules") and config.forwarding_rules:
        results["forwarding_rules"] = []
        logger.info("Processing ZIA Forwarding Control Rules...")
        
        # Get existing rules
        rules, _, err = client.zia.forwarding_control.list_rules()
        if err:
            logger.error(f"Failed to list Forwarding Control rules: {err}")
            raise Exception(f"Failed to list Forwarding Control rules: {err}")
            
        current_fwd_rule_count = count_active_rules(rules)
        target_rules = {r.name.lower(): r for r in rules if r.name}
        
        # Get existing proxy gateways to map proxy_gateway name -> ID
        existing_gws, _, err = client.zia.proxies.list_proxy_gateways()
        if not err and existing_gws:
            gw_map = {g.name.lower(): g.id for g in existing_gws}
        else:
            gw_map = {}
            
        # Get existing destination IP groups to map
        ip_groups, _, err = client.zia.cloud_firewall.list_ip_destination_groups()
        if not err and ip_groups:
            ip_group_map = {g.name.lower(): g.id for g in ip_groups}
        else:
            ip_group_map = {}

        for rule_cfg in config.forwarding_rules:
            if rule_cfg.get("order", 0) < 0 or rule_cfg.get("default_rule"):
                continue
            orig_name = rule_cfg.get("name")
            if not orig_name:
                continue
            prefixed_name = apply_prefix(orig_name, prefix)
            found_rule = target_rules.get(prefixed_name.lower())
            
            payload = dict(rule_cfg)
            payload["name"] = prefixed_name
            payload.pop("id", None)
            
            # Resolve proxy_gateway reference
            if "proxy_gateway" in payload and isinstance(payload["proxy_gateway"], dict):
                gw_name = payload["proxy_gateway"].get("name")
                gw_id = None
                if gw_name:
                    prefixed_gw_name = apply_prefix(gw_name, prefix)
                    gw_id = gw_map.get(prefixed_gw_name.lower()) or gw_map.get(gw_name.lower())
                if gw_id:
                    payload["proxy_gateway"] = {"id": gw_id}
                else:
                    logger.warning(f"Could not resolve Proxy Gateway reference '{gw_name}' for Forwarding Control rule '{prefixed_name}'")
                    payload.pop("proxy_gateway", None)
            
            # Resolve dest_ip_groups reference
            if "dest_ip_groups" in payload and isinstance(payload["dest_ip_groups"], list):
                resolved_groups = []
                for g in payload["dest_ip_groups"]:
                    if isinstance(g, dict) and g.get("name"):
                        g_name = g.get("name")
                        prefixed_g_name = apply_prefix(g_name, prefix)
                        g_id = ip_group_map.get(prefixed_g_name.lower()) or ip_group_map.get(g_name.lower())
                        if g_id:
                            resolved_groups.append({"id": g_id})
                payload["dest_ip_groups"] = resolved_groups
                if not resolved_groups:
                    payload.pop("dest_ip_groups")

            # Resolve mappings using ensure_refs_fetched
            ensure_refs_fetched()
            if "locations" in payload:
                payload["locations"] = resolve_ref_list(payload["locations"], target_locations)
                if not payload["locations"]:
                    payload.pop("locations")
            if "groups" in payload:
                payload["groups"] = resolve_ref_list(payload["groups"], target_groups)
                if not payload["groups"]:
                    payload.pop("groups")
            if "departments" in payload:
                payload["departments"] = resolve_ref_list(payload["departments"], target_departments)
                if not payload["departments"]:
                    payload.pop("departments")
            if "zpa_app_segments" in payload:
                payload["zpa_app_segments"] = resolve_ref_list(payload["zpa_app_segments"], target_zpa_segments)
                if not payload["zpa_app_segments"]:
                    payload.pop("zpa_app_segments")

            if "state" not in payload:
                payload["state"] = "ENABLED"

            # Resolve rule labels
            resolved_lbls = resolve_labels(payload.get("labels"))
            if resolved_lbls:
                payload["labels"] = resolved_lbls
            elif "labels" in payload:
                payload.pop("labels")

            if found_rule:
                logger.info(f"Forwarding Control rule '{prefixed_name}' already exists. Skipping...")
                results["forwarding_rules"].append({"name": prefixed_name, "id": found_rule.id, "status": "Skipped"})
            else:
                # If rule requires PROXYCHAIN forwarding but proxy_gateway is missing, skip creation with a warning
                if payload.get("forward_method") == "PROXYCHAIN" and "proxy_gateway" not in payload:
                    gw_name_ref = rule_cfg.get("proxy_gateway", {}).get("name") if isinstance(rule_cfg.get("proxy_gateway"), dict) else "unknown"
                    logger.warning(f"Skipping Forwarding Control rule '{prefixed_name}': Proxy Gateway reference '{gw_name_ref}' could not be resolved. Please create it manually in the ZIA Admin UI.")
                    results["forwarding_rules"].append({"name": prefixed_name, "status": "Skipped (Missing Proxy GW)"})
                    continue

                logger.info(f"Forwarding Control rule '{prefixed_name}' does not exist. Creating...")
                # Adjust order if out of bounds
                if "order" in payload:
                    configured_order = payload["order"]
                    max_possible_order = current_fwd_rule_count + 1
                    if configured_order > max_possible_order:
                        logger.info(f"Adjusting order of Forwarding Control rule '{prefixed_name}' from {configured_order} to {max_possible_order} to fit current rule count ({current_fwd_rule_count}).")
                        payload["order"] = max_possible_order

                if dry_run:
                    logger.info(f"[DRY-RUN] Would create Forwarding Control rule '{prefixed_name}'")
                    current_fwd_rule_count += 1
                else:
                    url = "/zia/api/v1/forwardingRules"
                    request, error = client._request_executor.create_request("POST", url, payload, {})
                    if error:
                        logger.error(f"Failed to create request for Forwarding Control rule '{prefixed_name}': {error}")
                        raise Exception(f"Failed to create Forwarding Control rule '{prefixed_name}': {error}")
                    res, error = client._request_executor.execute(request)
                    if error:
                        err_msg = str(error)
                        if "duplicate name" in err_msg.lower() or "already exists" in err_msg.lower():
                            logger.info(f"Forwarding Control rule '{prefixed_name}' already exists (duplicate). Skipping creation.")
                        else:
                            logger.error(f"Failed to create Forwarding Control rule '{prefixed_name}': {error}")
                            raise Exception(f"Failed to create Forwarding Control rule '{prefixed_name}': {error}")
                    else:
                        logger.info(f"Forwarding Control rule '{prefixed_name}' created successfully.")
                        current_fwd_rule_count += 1
                results["forwarding_rules"].append({"name": prefixed_name, "status": "Created"})

    return results
