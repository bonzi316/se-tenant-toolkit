from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator

# ==============================================================================
# ZCC Models
# ==============================================================================
class ZCCForwardingProfileUpdate(BaseModel):
    name: str
    description: Optional[str] = None
    model_config = {"extra": "allow"}

class ZCCForwardingProfile(BaseModel):
    search_name: str
    update: ZCCForwardingProfileUpdate

class ZCCAppProfileUpdate(BaseModel):
    name: str
    description: Optional[str] = None
    forwarding_profile_name: Optional[str] = None
    posture_profile_name: Optional[str] = None
    model_config = {"extra": "allow"}

class ZCCAppProfile(BaseModel):
    search_name: str
    update: ZCCAppProfileUpdate

class TrustedNetworkConfig(BaseModel):
    network_name: str
    active: Optional[bool] = True
    dns_servers: Optional[str] = ""
    dns_search_domains: Optional[str] = ""
    hostnames: Optional[str] = ""
    trusted_subnets: Optional[str] = ""
    trusted_gateways: Optional[str] = ""
    trusted_dhcp_servers: Optional[str] = ""
    ssids: Optional[str] = ""
    trusted_egress_ips: Optional[str] = ""
    condition_type: Optional[int] = 0
    model_config = {"extra": "allow"}

class WebPrivacyConfig(BaseModel):
    active: Optional[str] = "1"
    collect_user_info: Optional[str] = "1"
    collect_machine_hostname: Optional[str] = "1"
    collect_zdx_location: Optional[str] = "1"
    enable_packet_capture: Optional[str] = "1"
    disable_crashlytics: Optional[str] = "0"
    override_t2_protocol_setting: Optional[str] = "0"
    restrict_remote_packet_capture: Optional[str] = "0"
    grant_access_to_zscaler_log_folder: Optional[str] = "0"
    export_logs_for_non_admin: Optional[str] = "1"
    enable_auto_log_snippet: Optional[str] = "0"
    model_config = {"extra": "allow"}

class DeviceCleanupConfig(BaseModel):
    active: Optional[str] = "1"
    auto_purge_days: Optional[str] = "60"
    auto_removal_days: Optional[str] = "30"
    device_exceed_limit: Optional[str] = "16"
    force_remove_type: Optional[str] = "0"
    model_config = {"extra": "allow"}

class ZCCConfig(BaseModel):
    forwarding_profiles: Optional[List[ZCCForwardingProfile]] = Field(default_factory=list)
    app_profiles: Optional[Dict[str, List[ZCCAppProfile]]] = Field(default_factory=dict)
    trusted_networks: Optional[List[TrustedNetworkConfig]] = Field(default_factory=list)
    web_privacy: Optional[WebPrivacyConfig] = None
    device_cleanup: Optional[DeviceCleanupConfig] = None
    posture_check: Optional[List[Any]] = Field(default_factory=list)
    posture_profile: Optional[Dict[str, List[Any]]] = Field(default_factory=dict)
    custom_ip_bypasses: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    custom_process_bypasses: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    company_info: Optional[Dict[str, Any]] = Field(default_factory=dict)


# ==============================================================================
# ZIA Models
# ==============================================================================
class ZIAUrlRule(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    order: Optional[int] = None
    action: str = "BLOCK"
    protocols: List[str] = ["ANY_RULE"]
    url_categories: Optional[List[str]] = None
    labels: Optional[List[Any]] = None
    model_config = {"extra": "allow"}

class ZIACasbRule(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    order: Optional[int] = None
    action: str = "BLOCK"
    applications: Optional[List[str]] = Field(default_factory=list)
    labels: Optional[List[Any]] = None
    model_config = {"extra": "allow"}

class ZIAFirewallRule(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    order: Optional[int] = None
    action: str = "ALLOW"
    dest_addresses: Optional[List[str]] = None
    labels: Optional[List[Any]] = None
    model_config = {"extra": "allow"}

class ZIADnsRule(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    order: Optional[int] = None
    action: str = "BLOCK"
    protocols: List[str] = ["ANY_RULE"]
    labels: Optional[List[Any]] = None
    model_config = {"extra": "allow"}

class ZIAFileTypeRule(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    order: Optional[int] = None
    filtering_action: str = "BLOCK"
    labels: Optional[List[Any]] = None
    model_config = {"extra": "allow"}

class ZIARuleLabel(BaseModel):
    name: str
    description: Optional[str] = None
    model_config = {"extra": "allow"}

class ZIAConfig(BaseModel):
    rule_labels: Optional[List[ZIARuleLabel]] = Field(default_factory=list)
    url_categories: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    advanced_settings: Optional[Dict[str, Any]] = Field(default_factory=dict)
    url_filtering_settings: Optional[Dict[str, Any]] = Field(default_factory=dict)
    company_profile: Optional[Dict[str, Any]] = Field(default_factory=dict)
    threat_protection: Optional[Dict[str, Any]] = Field(default_factory=dict)
    malware_policy: Optional[Dict[str, Any]] = Field(default_factory=dict)
    atp_policy: Optional[Dict[str, Any]] = Field(default_factory=dict)
    ssl_policy: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    pac_files: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    # Rules
    url_filtering_rules: Optional[List[ZIAUrlRule]] = Field(default_factory=list)
    cloud_app_control_rules: Optional[Dict[str, List[ZIACasbRule]]] = Field(default_factory=dict)
    firewall_rules: Optional[List[ZIAFirewallRule]] = Field(default_factory=list)
    dns_rules: Optional[List[ZIADnsRule]] = Field(default_factory=list)
    file_type_rules: Optional[List[ZIAFileTypeRule]] = Field(default_factory=list)
    ip_destination_groups: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    ip_source_groups: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    root_certificates: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    proxies: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    proxy_gateways: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    forwarding_rules: Optional[List[Dict[str, Any]]] = Field(default_factory=list)


# ==============================================================================
# ZPA Models
# ==============================================================================
class ZPACoGroup(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: Optional[bool] = True
    latitude: Optional[str] = "0"
    longitude: Optional[str] = "0"
    location: Optional[str] = "San Jose, CA, USA"
    provisioning_key: Optional[bool] = False
    provisioning_key_max_usage: Optional[int] = 100
    model_config = {"extra": "allow"}

class ZPAServerGroup(BaseModel):
    name: str
    description: Optional[str] = None
    app_connector_group_name: Optional[str] = None
    enabled: Optional[bool] = True
    dynamic_discovery: Optional[bool] = True
    model_config = {"extra": "allow"}

class ZPASegGroup(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: Optional[bool] = True
    model_config = {"extra": "allow"}

class ZPAPortRange(BaseModel):
    from_port: str = Field(..., alias="from")
    to_port: str = Field(..., alias="to")

class ZPAAppSegment(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    domain_names: List[str]
    server_group_name: str
    segment_group_name: str
    tcp_port_range: Optional[List[ZPAPortRange]] = None
    udp_port_range: Optional[List[ZPAPortRange]] = None
    bypass_type: Optional[str] = "NEVER"
    icmp_access_type: Optional[str] = "PING"
    fqdn_dns_check: Optional[bool] = None
    match_style: Optional[str] = None
    is_cname_enabled: Optional[bool] = None
    model_config = {"extra": "allow"}

    @field_validator("domain_names", mode="before")
    @classmethod
    def parse_domain_names(cls, v):
        def _process_item(item):
            if not isinstance(item, str):
                return [item]
            prefix = ""
            if item.startswith("*."):
                prefix = "*."
                item = item[2:]
            if "," in item:
                return [f"{prefix}{d.strip()}" for d in item.split(",") if d.strip()]
            return [f"{prefix}{item.strip()}"]

        if isinstance(v, str):
            return _process_item(v)
        if isinstance(v, list):
            res = []
            for item in v:
                res.extend(_process_item(item))
            return res
        return v

class ZPAPolicy(BaseModel):
    name: str
    description: Optional[str] = None
    action: str = "ALLOW"
    rule_order: Optional[str] = "1"
    app_segments: List[str]
    reauth_idle_timeout: Optional[str] = None
    reauth_timeout: Optional[str] = None
    custom_msg: Optional[str] = None
    model_config = {"extra": "allow"}

class ZPAConfig(BaseModel):
    connector_group: Optional[ZPACoGroup] = None
    server_group: Optional[ZPAServerGroup] = None
    segment_group: Optional[ZPASegGroup] = None
    app_segments: Optional[List[ZPAAppSegment]] = None
    policies: Optional[List[ZPAPolicy]] = None
    timeout_policies: Optional[List[ZPAPolicy]] = None
    client_forwarding_policies: Optional[List[ZPAPolicy]] = None
    dns_search_domains: Optional[List[dict]] = None

    @field_validator("dns_search_domains", mode="before")
    @classmethod
    def parse_dns_search_domains(cls, v):
        if not v:
            return v
        if isinstance(v, list):
            res = []
            for item in v:
                if isinstance(item, dict) and "domain" in item:
                    domain_val = item["domain"]
                    if isinstance(domain_val, str) and "," in domain_val:
                        for d in domain_val.split(","):
                            if d.strip():
                                new_item = dict(item)
                                new_item["domain"] = d.strip()
                                res.append(new_item)
                    else:
                        res.append(item)
                else:
                    res.append(item)
            return res
        return v


# ==============================================================================
# Root Config Model
# ==============================================================================
class POVConfig(BaseModel):
    version: str
    zcc: Optional[ZCCConfig] = None
    zia: Optional[ZIAConfig] = None
    zpa: Optional[ZPAConfig] = None

def load_config(filepath: str) -> POVConfig:
    """Loads and validates a POV config file in YAML format."""
    import os
    import yaml
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Config file not found: {filepath}")
    
    with open(filepath, "r") as f:
        content = f.read()
        
    # Expand any ${VAR} references in the yaml string using os.environ
    expanded_content = os.path.expandvars(content)
    data = yaml.safe_load(expanded_content)
        
    return POVConfig.model_validate(data)
