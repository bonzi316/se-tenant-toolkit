import logging
import requests
from typing import Any, Dict, Optional
from zscaler import ZscalerClient

logger = logging.getLogger("src.aiguard")

def get_auth_headers(client: ZscalerClient) -> dict:
    req = client.get_request_executor()
    token = getattr(req, '_access_token', None)
    if not token:
        # Trigger an implicit fetch if it's missing
        client.aiguard.policies.list_policies()
        token = getattr(req, '_access_token', None)
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

def apply_aiguard_policies(client: ZscalerClient, policies: list, dry_run: bool = False, prefix: str = "") -> dict:
    results = {"created": [], "updated": [], "failed": [], "skipped": []}
    headers = get_auth_headers(client)
    base_url = "https://api.zsapi.net/aiguard/v1/detections/policies"
    
    for pol_def in policies:
        try:
            name = pol_def.get("name")
            if prefix and not name.startswith(prefix):
                name = f"{prefix}{name}"
                pol_def["name"] = name
                
            logger.info(f"Processing AI Guard Policy: {name}")
            
            # Check if exists
            res = requests.get(f"{base_url}/name/{name}", headers=headers)
            existing_pol = res.json() if res.status_code == 200 else None
            
            if existing_pol and existing_pol.get('id'):
                logger.info(f"Policy '{name}' already exists. Updating...")
                pol_def["id"] = existing_pol.get('id')
                if not dry_run:
                    upd_res = requests.put(f"{base_url}/{pol_def['id']}", json=pol_def, headers=headers)
                    if upd_res.status_code not in (200, 204):
                        raise Exception(f"HTTP {upd_res.status_code}: {upd_res.text}")
                results["updated"].append(name)
            else:
                logger.info(f"Policy '{name}' does not exist. Creating...")
                if not dry_run:
                    post_res = requests.post(base_url, json=pol_def, headers=headers)
                    if post_res.status_code not in (200, 201):
                        raise Exception(f"HTTP {post_res.status_code}: {post_res.text}")
                results["created"].append(name)
                
        except Exception as e:
            logger.error(f"Failed to process AI Guard Policy '{pol_def.get('name')}': {e}")
            results["failed"].append(pol_def.get("name"))
            
    return results

def apply_llm_applications(client: ZscalerClient, apps: list, dry_run: bool = False, prefix: str = "") -> dict:
    results = {"created": [], "updated": [], "failed": [], "skipped": []}
    headers = get_auth_headers(client)
    base_url = "https://api.zsapi.net/aiguard/v1/llm-applications"
    
    for app_def in apps:
        try:
            name = app_def.get("name")
            if prefix and not name.startswith(prefix):
                name = f"{prefix}{name}"
                app_def["name"] = name
                
            logger.info(f"Processing LLM Application: {name}")
            
            res = requests.get(f"{base_url}/name/{name}", headers=headers)
            existing_app = res.json() if res.status_code == 200 else None
            
            if existing_app and existing_app.get('id'):
                logger.info(f"LLM Application '{name}' already exists. Updating...")
                app_def["id"] = existing_app.get('id')
                if not dry_run:
                    upd_res = requests.put(f"{base_url}/{app_def['id']}", json=app_def, headers=headers)
                    if upd_res.status_code not in (200, 204):
                        raise Exception(f"HTTP {upd_res.status_code}: {upd_res.text}")
                results["updated"].append(name)
            else:
                logger.info(f"LLM Application '{name}' does not exist. Creating...")
                if not dry_run:
                    post_res = requests.post(base_url, json=app_def, headers=headers)
                    if post_res.status_code not in (200, 201):
                        raise Exception(f"HTTP {post_res.status_code}: {post_res.text}")
                results["created"].append(name)
                
        except Exception as e:
            logger.error(f"Failed to process LLM Application '{app_def.get('name')}': {e}")
            results["failed"].append(app_def.get("name"))
            
    return results

import os
import re

def resolve_env_vars(val: str) -> str:
    if not isinstance(val, str):
        return val
    matches = re.findall(r'\$\{([^}]+)\}', val)
    for var in matches:
        env_val = os.getenv(var)
        if env_val is not None:
            val = val.replace(f'${{{var}}}', env_val)
    return val

def apply_llm_credentials(client: ZscalerClient, creds: list, dry_run: bool = False, prefix: str = "") -> dict:
    results = {"created": [], "updated": [], "failed": [], "skipped": [], "tokens_generated": []}
    headers = get_auth_headers(client)
    base_url = "https://api.zsapi.net/aiguard/v1/llm-application-credentials"
    app_url = "https://api.zsapi.net/aiguard/v1/llm-applications"
    
    for cred_def in creds:
        try:
            name = cred_def.get("name")
            if prefix and not name.startswith(prefix):
                name = f"{prefix}{name}"
                cred_def["name"] = name
                
            logger.info(f"Processing LLM Application Credential: {name}")
            
            target_app_name = cred_def.get("target_llm_application_name")
            if target_app_name:
                if prefix and not target_app_name.startswith(prefix):
                    target_app_name = f"{prefix}{target_app_name}"
                    
                ares = requests.get(f"{app_url}/name/{target_app_name}", headers=headers)
                target_app = ares.json() if ares.status_code == 200 else None
                
                if not target_app or not target_app.get('id'):
                    logger.error(f"Target LLM App '{target_app_name}' not found for credential '{name}'. Skipping.")
                    results["skipped"].append(name)
                    continue
                cred_def["applicationId"] = target_app.get('id')
                del cred_def["target_llm_application_name"]
            
            # Resolve environment variables (e.g. ${OPENAI_API_KEY})
            for k, v in cred_def.items():
                if isinstance(v, str):
                    cred_def[k] = resolve_env_vars(v)

            res = requests.get(f"{base_url}/name/{name}", headers=headers)
            existing_cred = res.json() if res.status_code == 200 else None
            
            if existing_cred and existing_cred.get('id'):
                logger.info(f"LLM Credential '{name}' already exists. Updating...")
                cred_def["id"] = existing_cred.get('id')
                if not dry_run:
                    upd_res = requests.put(f"{base_url}/{cred_def['id']}", json=cred_def, headers=headers)
                    if upd_res.status_code not in (200, 204):
                        raise Exception(f"HTTP {upd_res.status_code}: {upd_res.text}")
                results["updated"].append(name)
            else:
                logger.info(f"LLM Credential '{name}' does not exist. Creating...")
                if not dry_run:
                    post_res = requests.post(base_url, json=cred_def, headers=headers)
                    if post_res.status_code not in (200, 201):
                        raise Exception(f"HTTP {post_res.status_code}: {post_res.text}")
                    
                    created_data = post_res.json()
                    # Capture generated tokens for PROXY mode
                    token = created_data.get("token") or created_data.get("apiKey") or created_data.get("credential")
                    if token:
                        results["tokens_generated"].append({"name": name, "token": token})

                results["created"].append(name)
                
        except Exception as e:
            logger.error(f"Failed to process LLM Credential '{cred_def.get('name')}': {e}")
            results["failed"].append(cred_def.get("name"))
            
    return results

def apply_aiguard_match_rules(client: ZscalerClient, rules: list, dry_run: bool = False, prefix: str = "") -> dict:
    results = {"created": [], "updated": [], "failed": [], "skipped": []}
    headers = get_auth_headers(client)
    base_url = "https://api.zsapi.net/aiguard/v1/detections/policy-match-rules"
    pol_url = "https://api.zsapi.net/aiguard/v1/detections/policies"
    app_url = "https://api.zsapi.net/aiguard/v1/llm-applications"
    cred_url = "https://api.zsapi.net/aiguard/v1/llm-application-credentials"
    
    for rule_def in rules:
        try:
            name = rule_def.get("name")
            if prefix and not name.startswith(prefix):
                name = f"{prefix}{name}"
                rule_def["name"] = name
                
            logger.info(f"Processing AI Guard Match Rule: {name}")
            
            target_policy_name = rule_def.get("target_policy_name")
            if target_policy_name:
                if prefix and not target_policy_name.startswith(prefix):
                    target_policy_name = f"{prefix}{target_policy_name}"
                    
                tres = requests.get(f"{pol_url}/name/{target_policy_name}", headers=headers)
                target_policy = tres.json() if tres.status_code == 200 else None
                
                if not target_policy or not target_policy.get('id'):
                    logger.error(f"Target Policy '{target_policy_name}' not found for rule '{name}'. Skipping.")
                    results["skipped"].append(name)
                    continue
                rule_def["policyId"] = target_policy.get('id')
                del rule_def["target_policy_name"]

            mc = rule_def.get('matchCriteria', {})
            if mc.get('type') == 'DAS_APPLICATION':
                for app in mc.get('llmApplications', []):
                    # Resolve App ID
                    t_app_name = app.get('target_llm_application_name')
                    if t_app_name:
                        if prefix and not t_app_name.startswith(prefix):
                            t_app_name = f"{prefix}{t_app_name}"
                        ares = requests.get(f"{app_url}/name/{t_app_name}", headers=headers)
                        target_app = ares.json() if ares.status_code == 200 else None
                        if target_app and target_app.get('id'):
                            app['applicationId'] = target_app.get('id')
                        app.pop('target_llm_application_name', None)
                        
                    # Resolve Cred IDs
                    t_cred_names = app.get('target_llm_credential_names', [])
                    if t_cred_names:
                        cids = []
                        for cname in t_cred_names:
                            real_cname = cname
                            if prefix and not real_cname.startswith(prefix) and not real_cname.isdigit():
                                real_cname = f"{prefix}{real_cname}"
                            cres = requests.get(f"{cred_url}/name/{real_cname}", headers=headers)
                            target_cred = cres.json() if cres.status_code == 200 else None
                            if target_cred and target_cred.get('id'):
                                cids.append(target_cred.get('id'))
                            elif real_cname.isdigit():
                                cids.append(int(real_cname))
                        app['applicationCredentialsIds'] = cids
                        app.pop('target_llm_credential_names', None)
            
            # Check if exists
            rres = requests.get(f"{base_url}/name/{name}", headers=headers)
            existing_rule = rres.json() if rres.status_code == 200 else None
            
            if existing_rule and existing_rule.get('id'):
                logger.info(f"Match Rule '{name}' already exists. Updating...")
                rule_def["id"] = existing_rule.get('id')
                if not dry_run:
                    upd_res = requests.put(f"{base_url}/{rule_def['id']}", json=rule_def, headers=headers)
                    if upd_res.status_code not in (200, 204):
                        raise Exception(f"HTTP {upd_res.status_code}: {upd_res.text}")
                results["updated"].append(name)
            else:
                logger.info(f"Match Rule '{name}' does not exist. Creating...")
                if not dry_run:
                    post_res = requests.post(base_url, json=rule_def, headers=headers)
                    if post_res.status_code not in (200, 201):
                        raise Exception(f"HTTP {post_res.status_code}: {post_res.text}")
                results["created"].append(name)
                
        except Exception as e:
            logger.error(f"Failed to process AI Guard Match Rule '{rule_def.get('name')}': {e}")
            results["failed"].append(rule_def.get("name"))
            
    return results

def setup_aiguard(client: ZscalerClient, aiguard_config: Any, dry_run: bool = False, prefix: str = "") -> dict:
    summary = {
        "llm_applications": {},
        "llm_application_credentials": {},
        "policies": {},
        "match_rules": {}
    }
    
    if hasattr(aiguard_config, 'llm_applications') and aiguard_config.llm_applications:
        summary["llm_applications"] = apply_llm_applications(
            client, aiguard_config.llm_applications, dry_run=dry_run, prefix=prefix
        )
        
    if hasattr(aiguard_config, 'llm_application_credentials') and aiguard_config.llm_application_credentials:
        summary["llm_application_credentials"] = apply_llm_credentials(
            client, aiguard_config.llm_application_credentials, dry_run=dry_run, prefix=prefix
        )
    
    if hasattr(aiguard_config, 'policies') and aiguard_config.policies:
        summary["policies"] = apply_aiguard_policies(
            client, aiguard_config.policies, dry_run=dry_run, prefix=prefix
        )
        
    if hasattr(aiguard_config, 'policy_match_rules') and aiguard_config.policy_match_rules:
        summary["match_rules"] = apply_aiguard_match_rules(
            client, aiguard_config.policy_match_rules, dry_run=dry_run, prefix=prefix
        )
        
    return summary
