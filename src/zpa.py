import logging
from typing import Dict, Any, List
from zscaler import ZscalerClient
from src.config import ZPAConfig
from src.zcc import remove_none_recursive

logger = logging.getLogger("src")

def human_to_seconds(human_str: str) -> int:
    """Converts a human readable timeout string like '7d' or '2h' to seconds."""
    if human_str is None or human_str == "":
        return None
    if human_str.lower() == "never":
        return -1
    
    human_str = human_str.strip().lower()
    if human_str.endswith("d"):
        try: return int(human_str[:-1]) * 86400
        except ValueError: pass
    elif human_str.endswith("h"):
        try: return int(human_str[:-1]) * 3600
        except ValueError: pass
    elif human_str.endswith("m"):
        try: return int(human_str[:-1]) * 60
        except ValueError: pass
    elif human_str.endswith("s"):
        try: return int(human_str[:-1])
        except ValueError: pass
        
    try:
        return int(human_str)
    except ValueError:
        return None

def setup_zpa(client: ZscalerClient, config: ZPAConfig, dry_run: bool = False) -> Dict[str, Any]:
    """Sets up ZPA App Connector Groups, Server Groups, Segment Groups, App Segments, and Access Policy rules."""
    results = {}
    if not config:
        return results

    # Maps for name-to-ID lookup
    conn_groups_map = {}
    server_groups_map = {}
    segment_groups_map = {}
    app_segments_map = {}

    # 1. Process Connector Group
    if config.connector_group:
        cg_cfg = config.connector_group
        logger.info(f"Processing Connector Group: '{cg_cfg.name}'")
        groups, _, err = client.zpa.app_connector_groups.list_connector_groups()
        if err:
            logger.error(f"Failed to list connector groups: {err}")
            raise Exception(f"Failed to list connector groups: {err}")
            
        found_cg = next((g for g in groups if g.name == cg_cfg.name), None)
        
        params = cg_cfg.model_dump(exclude_none=True)
        # Ensure default profile properties for creation if missing
        if "enabled" not in params:
            params["enabled"] = True
        if "latitude" not in params:
            params["latitude"] = "0"
        if "longitude" not in params:
            params["longitude"] = "0"
        if "location" not in params:
            params["location"] = "San Jose, CA, USA"

        if found_cg:
            logger.info(f"Connector Group '{cg_cfg.name}' already exists (ID: {found_cg.id}). Updating...")
            conn_groups_map[cg_cfg.name.lower()] = found_cg.id
            if dry_run:
                logger.info(f"[DRY-RUN] Would update Connector Group '{cg_cfg.name}' (ID: {found_cg.id}) with: {params}")
            else:
                _, _, err = client.zpa.app_connector_groups.update_connector_group(group_id=found_cg.id, **params)
                if err:
                    logger.error(f"Failed to update Connector Group '{cg_cfg.name}': {err}")
                    raise Exception(f"Failed to update Connector Group '{cg_cfg.name}': {err}")
                logger.info(f"Connector Group '{cg_cfg.name}' updated successfully.")
                results["connector_group"] = {"name": cg_cfg.name, "id": found_cg.id, "status": "Updated"}
        else:
            logger.info(f"Connector Group '{cg_cfg.name}' does not exist. Creating...")
            if "enrollment_cert_id" not in params:
                certs, _, _ = client.zpa.enrollment_certificates.list_enrolment()
                cert_id = next((c.id for c in certs or [] if c.name == "Connector"), None)
                if not cert_id:
                    raise ValueError("Could not find the default 'Connector' enrollment certificate.")
                params["enrollment_cert_id"] = cert_id

            if dry_run:
                logger.info(f"[DRY-RUN] Would create Connector Group '{cg_cfg.name}' with: {params}")
                conn_groups_map[cg_cfg.name.lower()] = "TEMP_CG_ID"
            else:
                new_cg, _, err = client.zpa.app_connector_groups.add_connector_group(**params)
                if err:
                    logger.error(f"Failed to create Connector Group '{cg_cfg.name}': {err}")
                    raise Exception(f"Failed to create Connector Group '{cg_cfg.name}': {err}")
                logger.info(f"Connector Group '{cg_cfg.name}' created successfully with ID: {new_cg.id}")
                conn_groups_map[cg_cfg.name.lower()] = new_cg.id
                results["connector_group"] = {"name": cg_cfg.name, "id": new_cg.id, "status": "Created"}

        if getattr(cg_cfg, "provisioning_key", False):
            logger.info(f"Processing Provisioning Key for '{cg_cfg.name}'...")
            cg_id = found_cg.id if found_cg else new_cg.id
            if dry_run:
                logger.info(f"[DRY-RUN] Would generate provisioning key for '{cg_cfg.name}'")
                results["connector_group"]["provisioning_key"] = "TEMP_PROV_KEY"
            else:
                keys, _, err = client.zpa.provisioning.list_provisioning_keys(key_type="connector")
                if err:
                    logger.error(f"Failed to list provisioning keys: {err}")
                    raise Exception(f"Failed to list provisioning keys: {err}")
                
                existing_key = next((k for k in keys or [] if getattr(k, 'zcomponent_id', None) == cg_id), None)
                if not existing_key:
                    cert_id = params.get("enrollment_cert_id")
                    if not cert_id:
                        certs, _, _ = client.zpa.enrollment_certificates.list_enrolment()
                        cert_id = next((c.id for c in certs or [] if c.name == "Connector"), None)
                    
                    logger.info(f"Creating provisioning key for '{cg_cfg.name}'...")
                    pk, _, err = client.zpa.provisioning.add_provisioning_key(
                        key_type="connector",
                        name=f"{cg_cfg.name} Key",
                        max_usage=str(getattr(cg_cfg, 'provisioning_key_max_usage', '100')),
                        enrollment_cert_id=cert_id,
                        component_id=cg_id
                    )
                    if err:
                        logger.error(f"Failed to create provisioning key: {err}")
                        raise Exception(f"Failed to create provisioning key: {err}")
                    results["connector_group"]["provisioning_key"] = getattr(pk, 'provisioning_key', 'Created')
                    logger.info(f"Provisioning key for '{cg_cfg.name}' created successfully.")
                else:
                    logger.info(f"Provisioning key for '{cg_cfg.name}' already exists.")
                    results["connector_group"]["provisioning_key"] = getattr(existing_key, 'provisioning_key', 'Exists')

    # 2. Process Server Group
    if config.server_group:
        sg_cfg = config.server_group
        logger.info(f"Processing Server Group: '{sg_cfg.name}'")
        groups, _, err = client.zpa.server_groups.list_groups()
        if err:
            logger.error(f"Failed to list server groups: {err}")
            raise Exception(f"Failed to list server groups: {err}")
            
        found_sg = next((g for g in groups if g.name == sg_cfg.name), None)
        
        # Resolve App Connector Group ID
        conn_group_id = None
        if sg_cfg.app_connector_group_name:
            ref_name = sg_cfg.app_connector_group_name.lower()
            conn_group_id = conn_groups_map.get(ref_name)
            if not conn_group_id:
                # Lookup in Zscaler if not in current map
                cgs, _, _ = client.zpa.app_connector_groups.list_connector_groups()
                for cg in cgs or []:
                    if cg.name.lower() == ref_name:
                        conn_group_id = cg.id
                        break
            if not conn_group_id:
                logger.warning(f"Could not resolve referenced Connector Group name '{sg_cfg.app_connector_group_name}' for Server Group '{sg_cfg.name}'.")
        
        params = sg_cfg.model_dump(exclude_none=True)
        params.pop("app_connector_group_name", None)
        
        if "enabled" not in params:
            params["enabled"] = True
        if "dynamic_discovery" not in params:
            params["dynamic_discovery"] = True
            
        if conn_group_id:
            params["app_connector_groups"] = [{"id": conn_group_id}]

        if found_sg:
            logger.info(f"Server Group '{sg_cfg.name}' already exists (ID: {found_sg.id}). Updating...")
            server_groups_map[sg_cfg.name.lower()] = found_sg.id
            if dry_run:
                logger.info(f"[DRY-RUN] Would update Server Group '{sg_cfg.name}' (ID: {found_sg.id}) with: {params}")
            else:
                _, _, err = client.zpa.server_groups.update_group(group_id=found_sg.id, **params)
                if err:
                    logger.error(f"Failed to update Server Group '{sg_cfg.name}': {err}")
                    raise Exception(f"Failed to update Server Group '{sg_cfg.name}': {err}")
                logger.info(f"Server Group '{sg_cfg.name}' updated successfully.")
                results["server_group"] = {"name": sg_cfg.name, "id": found_sg.id, "status": "Updated"}
        else:
            logger.info(f"Server Group '{sg_cfg.name}' does not exist. Creating...")
            if dry_run:
                logger.info(f"[DRY-RUN] Would create Server Group '{sg_cfg.name}' with: {params}")
                server_groups_map[sg_cfg.name.lower()] = "TEMP_SG_ID"
            else:
                new_sg, _, err = client.zpa.server_groups.add_group(**params)
                if err:
                    logger.error(f"Failed to create Server Group '{sg_cfg.name}': {err}")
                    raise Exception(f"Failed to create Server Group '{sg_cfg.name}': {err}")
                logger.info(f"Server Group '{sg_cfg.name}' created successfully with ID: {new_sg['id']}")
                server_groups_map[sg_cfg.name.lower()] = new_sg["id"]
                results["server_group"] = {"name": sg_cfg.name, "id": new_sg["id"], "status": "Created"}

    # 3. Process Segment Group
    if config.segment_group:
        seg_cfg = config.segment_group
        logger.info(f"Processing Segment Group: '{seg_cfg.name}'")
        groups, _, err = client.zpa.segment_groups.list_groups()
        if err:
            logger.error(f"Failed to list segment groups: {err}")
            raise Exception(f"Failed to list segment groups: {err}")
            
        found_seg = next((g for g in groups if g.name == seg_cfg.name), None)
        
        params = seg_cfg.model_dump(exclude_none=True)
        if "enabled" not in params:
            params["enabled"] = True

        if found_seg:
            logger.info(f"Segment Group '{seg_cfg.name}' already exists (ID: {found_seg.id}). Updating...")
            segment_groups_map[seg_cfg.name.lower()] = found_seg.id
            if dry_run:
                logger.info(f"[DRY-RUN] Would update Segment Group '{seg_cfg.name}' (ID: {found_seg.id}) with: {params}")
            else:
                _, _, err = client.zpa.segment_groups.update_group(group_id=found_seg.id, **params)
                if err:
                    logger.error(f"Failed to update Segment Group '{seg_cfg.name}': {err}")
                    raise Exception(f"Failed to update Segment Group '{seg_cfg.name}': {err}")
                logger.info(f"Segment Group '{seg_cfg.name}' updated successfully.")
                results["segment_group"] = {"name": seg_cfg.name, "id": found_seg.id, "status": "Updated"}
        else:
            logger.info(f"Segment Group '{seg_cfg.name}' does not exist. Creating...")
            if dry_run:
                logger.info(f"[DRY-RUN] Would create Segment Group '{seg_cfg.name}' with: {params}")
                segment_groups_map[seg_cfg.name.lower()] = "TEMP_SEGG_ID"
            else:
                new_seg, _, err = client.zpa.segment_groups.add_group(**params)
                if err:
                    logger.error(f"Failed to create Segment Group '{seg_cfg.name}': {err}")
                    raise Exception(f"Failed to create Segment Group '{seg_cfg.name}': {err}")
                logger.info(f"Segment Group '{seg_cfg.name}' created successfully with ID: {new_seg['id']}")
                segment_groups_map[seg_cfg.name.lower()] = new_seg["id"]
                results["segment_group"] = {"name": seg_cfg.name, "id": new_seg["id"], "status": "Created"}

    # 4. Process App Segments
    if config.app_segments:
        results["app_segments"] = []
        segments, _, err = client.zpa.application_segment.list_segments()
        if err:
            logger.error(f"Failed to list app segments: {err}")
            raise Exception(f"Failed to list app segments: {err}")
            
        for app_cfg in config.app_segments:
            found_app = next((s for s in segments if s.name == app_cfg.name), None)
            
            # Resolve Server Group
            srv_grp_id = server_groups_map.get(app_cfg.server_group_name.lower())
            if not srv_grp_id:
                # lookup in client
                sgs, _, _ = client.zpa.server_groups.list_groups()
                for sg in sgs or []:
                    if sg.name.lower() == app_cfg.server_group_name.lower():
                        srv_grp_id = sg.id
                        break
            if not srv_grp_id:
                raise ValueError(f"Could not resolve Server Group '{app_cfg.server_group_name}' for App Segment '{app_cfg.name}'.")
                
            # Resolve Segment Group
            seg_grp_id = segment_groups_map.get(app_cfg.segment_group_name.lower())
            if not seg_grp_id:
                # lookup in client
                segs, _, _ = client.zpa.segment_groups.list_groups()
                for seg in segs or []:
                    if seg.name.lower() == app_cfg.segment_group_name.lower():
                        seg_grp_id = seg.id
                        break
            if not seg_grp_id:
                raise ValueError(f"Could not resolve Segment Group '{app_cfg.segment_group_name}' for App Segment '{app_cfg.name}'.")
                
            params = app_cfg.model_dump(exclude_none=True)
            params.pop("server_group_name", None)
            params.pop("segment_group_name", None)
            params.pop("passiveHealthEnabled", None)
            params.pop("passive_health_enabled", None)
            
            # Link IDs
            params["server_groups"] = [{"id": srv_grp_id}]
            params["segment_group_id"] = seg_grp_id
            
            # Map port ranges
            if app_cfg.tcp_port_range:
                flat_tcp = []
                for p in app_cfg.tcp_port_range:
                    flat_tcp.extend([p.from_port, p.to_port])
                params["tcp_port_ranges"] = flat_tcp
                params.pop("tcp_port_range", None)
                
            if app_cfg.udp_port_range:
                flat_udp = []
                for p in app_cfg.udp_port_range:
                    flat_udp.extend([p.from_port, p.to_port])
                params["udp_port_ranges"] = flat_udp
                params.pop("udp_port_range", None)

            if "bypass_type" not in params:
                params["bypass_type"] = "NEVER"
            if "icmp_access_type" not in params:
                params["icmp_access_type"] = "PING"

            if found_app:
                logger.info(f"App Segment '{app_cfg.name}' already exists (ID: {found_app.id}). Updating...")
                app_segments_map[app_cfg.name.lower()] = found_app.id
                if dry_run:
                    logger.info(f"[DRY-RUN] Would update App Segment '{app_cfg.name}' (ID: {found_app.id}) with: {params}")
                else:
                    _, _, err = client.zpa.application_segment.update_segment(segment_id=found_app.id, **params)
                    if err:
                        logger.error(f"Failed to update App Segment '{app_cfg.name}': {err}")
                        raise Exception(f"Failed to update App Segment '{app_cfg.name}': {err}")
                    logger.info(f"App Segment '{app_cfg.name}' updated successfully.")
                    results["app_segments"].append({"name": app_cfg.name, "id": found_app.id, "status": "Updated"})
            else:
                logger.info(f"App Segment '{app_cfg.name}' does not exist. Creating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create App Segment '{app_cfg.name}' with: {params}")
                    app_segments_map[app_cfg.name.lower()] = "TEMP_APP_ID"
                else:
                    new_app, _, err = client.zpa.application_segment.add_segment(**params)
                    if err:
                        logger.error(f"Failed to create App Segment '{app_cfg.name}': {err}")
                        raise Exception(f"Failed to create App Segment '{app_cfg.name}': {err}")
                    logger.info(f"App Segment '{app_cfg.name}' created successfully with ID: {new_app.id}")
                    app_segments_map[app_cfg.name.lower()] = new_app.id
                    results["app_segments"].append({"name": app_cfg.name, "id": new_app.id, "status": "Created"})

    # 5. Process Access Policies
    if config.policies:
        results["policies"] = []
        rules, _, err = client.zpa.policies.list_rules(policy_type="access")
        if err:
            logger.error(f"Failed to list ZPA access policy rules: {err}")
            raise Exception(f"Failed to list ZPA access policy rules: {err}")
            
        for rule_cfg in config.policies:
            found_rule = next((r for r in rules if r.name == rule_cfg.name), None)
            
            # Resolve App Segment references to segment IDs
            operands = []
            for app_ref in rule_cfg.app_segments:
                ref_lower = app_ref.lower()
                app_id = app_segments_map.get(ref_lower)
                if not app_id:
                    # search in client
                    apps, _, _ = client.zpa.application_segment.list_segments()
                    for app in apps or []:
                        if app.name.lower() == ref_lower:
                            app_id = app.id
                            break
                if not app_id:
                    raise ValueError(f"Could not resolve App Segment '{app_ref}' for ZPA Policy rule '{rule_cfg.name}'.")
                
                operands.append({
                    "object_type": "APP",
                    "objectType": "APP",
                    "lhs": "id",
                    "rhs": app_id
                })
                
            conditions = [{
                "operator": "OR",
                "negated": False,
                "operands": operands
            }]
            
            params = rule_cfg.model_dump(exclude_none=True)
            params.pop("app_segments", None)
            params["conditions"] = conditions
            
            if "custom_msg" not in params:
                params["custom_msg"] = "Created/managed by Antigravity POV script"

            if found_rule:
                logger.info(f"ZPA Policy rule '{rule_cfg.name}' already exists (ID: {found_rule.id}). Updating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would update ZPA Policy rule '{rule_cfg.name}' (ID: {found_rule.id}) with: {params}")
                else:
                    _, _, err = client.zpa.policies.update_access_rule(rule_id=found_rule.id, **params)
                    if err:
                        logger.error(f"Failed to update ZPA Policy rule '{rule_cfg.name}': {err}")
                        raise Exception(f"Failed to update ZPA Policy rule '{rule_cfg.name}': {err}")
                    logger.info(f"ZPA Policy rule '{rule_cfg.name}' updated successfully.")
                    results["policies"].append({"name": rule_cfg.name, "status": "Updated"})
            else:
                logger.info(f"ZPA Policy rule '{rule_cfg.name}' does not exist. Creating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create ZPA Policy rule '{rule_cfg.name}' with: {params}")
                else:
                    _, _, err = client.zpa.policies.add_access_rule(**params)
                    if err:
                        logger.error(f"Failed to create ZPA Policy rule '{rule_cfg.name}': {err}")
                        raise Exception(f"Failed to create ZPA Policy rule '{rule_cfg.name}': {err}")
                    logger.info(f"ZPA Policy rule '{rule_cfg.name}' created successfully.")
                    results["policies"].append({"name": rule_cfg.name, "status": "Created"})

    # 6. Process Timeout Policies
    if getattr(config, "timeout_policies", None):
        results["timeout_policies"] = []
        rules, _, err = client.zpa.policies.list_rules(policy_type="timeout")
        if err:
            logger.error(f"Failed to list ZPA timeout policy rules: {err}")
            raise Exception(f"Failed to list ZPA timeout policy rules: {err}")
            
        for rule_cfg in config.timeout_policies:
            found_rule = next((r for r in rules if r.name == rule_cfg.name), None)
            
            # Resolve App Segment references
            operands = []
            for app_ref in rule_cfg.app_segments:
                ref_lower = app_ref.lower()
                app_id = app_segments_map.get(ref_lower)
                if not app_id:
                    apps, _, _ = client.zpa.application_segment.list_segments()
                    for app in apps or []:
                        if app.name.lower() == ref_lower:
                            app_id = app.id
                            break
                if not app_id:
                    raise ValueError(f"Could not resolve App Segment '{app_ref}' for Timeout rule '{rule_cfg.name}'.")
                
                operands.append({
                    "object_type": "APP",
                    "objectType": "APP",
                    "lhs": "id",
                    "rhs": app_id
                })
                
            conditions = [{"operator": "OR", "negated": False, "operands": operands}] if operands else []
            
            params = rule_cfg.model_dump(exclude_none=True)
            params.pop("app_segments", None)
            params["conditions"] = conditions
            
            # Convert human timeouts to seconds
            if "reauth_idle_timeout" in params:
                val = human_to_seconds(params["reauth_idle_timeout"])
                if val is not None: params["reauth_idle_timeout"] = val
            if "reauth_timeout" in params:
                val = human_to_seconds(params["reauth_timeout"])
                if val is not None: params["reauth_timeout"] = val

            if found_rule:
                logger.info(f"ZPA Timeout Policy rule '{rule_cfg.name}' already exists (ID: {found_rule.id}). Updating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would update Timeout rule '{rule_cfg.name}' (ID: {found_rule.id}) with: {params}")
                else:
                    _, _, err = client.zpa.policies.update_timeout_rule(rule_id=found_rule.id, **params)
                    if err:
                        logger.error(f"Failed to update Timeout rule '{rule_cfg.name}': {err}")
                        raise Exception(f"Failed to update Timeout rule '{rule_cfg.name}': {err}")
                    logger.info(f"ZPA Timeout Policy rule '{rule_cfg.name}' updated successfully.")
                    results["timeout_policies"].append({"name": rule_cfg.name, "status": "Updated"})
            else:
                if rule_cfg.name == "Default_Rule":
                    logger.warning("Default_Rule not found, skipping creation as it is a default rule.")
                    continue
                logger.info(f"ZPA Timeout Policy rule '{rule_cfg.name}' does not exist. Creating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create Timeout rule '{rule_cfg.name}' with: {params}")
                else:
                    _, _, err = client.zpa.policies.add_timeout_rule(**params)
                    if err:
                        logger.error(f"Failed to create Timeout rule '{rule_cfg.name}': {err}")
                        raise Exception(f"Failed to create Timeout rule '{rule_cfg.name}': {err}")
                    logger.info(f"ZPA Timeout Policy rule '{rule_cfg.name}' created successfully.")
                    results["timeout_policies"].append({"name": rule_cfg.name, "status": "Created"})

    # 7. Process Client Forwarding Policies
    if getattr(config, "client_forwarding_policies", None):
        results["client_forwarding_policies"] = []
        rules, _, err = client.zpa.policies.list_rules(policy_type="client_forwarding")
        if err:
            logger.error(f"Failed to list ZPA Client Forwarding rules: {err}")
            raise Exception(f"Failed to list ZPA Client Forwarding rules: {err}")
            
        for rule_cfg in config.client_forwarding_policies:
            found_rule = next((r for r in rules if r.name == rule_cfg.name), None)
            
            # Resolve App Segment references
            operands = []
            for app_ref in rule_cfg.app_segments:
                ref_lower = app_ref.lower()
                app_id = app_segments_map.get(ref_lower)
                if not app_id:
                    apps, _, _ = client.zpa.application_segment.list_segments()
                    for app in apps or []:
                        if app.name.lower() == ref_lower:
                            app_id = app.id
                            break
                if not app_id:
                    raise ValueError(f"Could not resolve App Segment '{app_ref}' for Client Forwarding rule '{rule_cfg.name}'.")
                
                operands.append({
                    "object_type": "APP",
                    "objectType": "APP",
                    "lhs": "id",
                    "rhs": app_id
                })
                
            conditions = [{"operator": "OR", "negated": False, "operands": operands}] if operands else []
            
            params = rule_cfg.model_dump(exclude_none=True)
            params.pop("app_segments", None)
            params["conditions"] = conditions

            if found_rule:
                logger.info(f"ZPA Client Forwarding rule '{rule_cfg.name}' already exists (ID: {found_rule.id}). Updating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would update CF rule '{rule_cfg.name}' (ID: {found_rule.id}) with: {params}")
                else:
                    _, _, err = client.zpa.policies.update_client_forwarding_rule(rule_id=found_rule.id, **params)
                    if err:
                        logger.error(f"Failed to update CF rule '{rule_cfg.name}': {err}")
                        raise Exception(f"Failed to update CF rule '{rule_cfg.name}': {err}")
                    logger.info(f"ZPA Client Forwarding rule '{rule_cfg.name}' updated successfully.")
                    results["client_forwarding_policies"].append({"name": rule_cfg.name, "status": "Updated"})
            else:
                if rule_cfg.name == "Default_Rule" or rule_cfg.name == "Zscaler Deception":
                    logger.warning(f"'{rule_cfg.name}' not found, skipping creation as it is a default rule.")
                    continue
                logger.info(f"ZPA Client Forwarding rule '{rule_cfg.name}' does not exist. Creating...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create CF rule '{rule_cfg.name}' with: {params}")
                else:
                    _, _, err = client.zpa.policies.add_client_forwarding_rule(**params)
                    if err:
                        logger.error(f"Failed to create CF rule '{rule_cfg.name}': {err}")
                        raise Exception(f"Failed to create CF rule '{rule_cfg.name}': {err}")
                    logger.info(f"ZPA Client Forwarding rule '{rule_cfg.name}' created successfully.")
                    results["client_forwarding_policies"].append({"name": rule_cfg.name, "status": "Created"})

    # 8. Process DNS Search Domains
    if getattr(config, "dns_search_domains", None) is not None:
        logger.info("Processing ZPA DNS Search Domains (SEARCH_SUFFIX)...")
        if dry_run:
            logger.info(f"[DRY-RUN] Would update DNS Search Domains with: {config.dns_search_domains}")
            results["dns_search_domains"] = {"status": "Updated", "count": len(config.dns_search_domains)}
        else:
            _, _, err = client.zpa.customer_domain.add_update_domain(
                type="SEARCH_SUFFIX",
                domain_list=config.dns_search_domains
            )
            if err:
                logger.error(f"Failed to update ZPA DNS Search Domains: {err}")
                raise Exception(f"Failed to update ZPA DNS Search Domains: {err}")
            logger.info("ZPA DNS Search Domains updated successfully.")
            results["dns_search_domains"] = {"status": "Updated", "count": len(config.dns_search_domains)}

    return results
