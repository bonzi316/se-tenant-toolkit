import logging
from typing import Dict, Any
from zscaler import ZscalerClient
from src.config import ZCCConfig
from zscaler.helpers import convert_keys_to_camel_case

logger = logging.getLogger("src")

def to_camel_wire_dict(obj):
    """Recursively converts ZscalerObject models to camelCase dictionaries to preserve nested structures for API serialization."""
    if isinstance(obj, list):
        return [to_camel_wire_dict(item) for item in obj]
    if isinstance(obj, dict):
        camel_dict = convert_keys_to_camel_case(obj)
        replacements = {
            "dtlsTimeout": "DTLSTimeout",
            "tlsTimeout": "TLSTimeout",
            "udpTimeout": "UDPTimeout",
            "allowTlsFallback": "allowTLSFallback",
            "actionTypeZia": "actionTypeZIA",
            "actionTypeZpa": "actionTypeZPA",
            "bypassProxyForPrivateIp": "bypassProxyForPrivateIP",
            "latencyBasedServerMtEnablement": "latencyBasedServerMTEnablement",
            "enableLwfDriver": "enableLWFDriver",
            "enableSplitVpnTn": "enableSplitVpnTN",
            "enableAllDefaultAdaptersTn": "enableAllDefaultAdaptersTN"
        }
        camel_dict = {replacements.get(k, k): v for k, v in camel_dict.items()}
        return {k: to_camel_wire_dict(v) for k, v in camel_dict.items()}
    if hasattr(obj, "request_format"):
        return to_camel_wire_dict(obj.request_format())
    return obj

def remove_none_recursive(val):
    """Recursively removes all keys with None values from dictionaries and lists."""
    if isinstance(val, dict):
        return {k: remove_none_recursive(v) for k, v in val.items() if v is not None}
    if isinstance(val, list):
        return [remove_none_recursive(v) for v in val if v is not None]
    return val

def recursive_merge(target, source):
    """Recursively merges source dict/list into target dict/list in-place."""
    if isinstance(target, dict) and isinstance(source, dict):
        for k, v in source.items():
            target_key = k
            if k not in target:
                camel_k = convert_keys_to_camel_case({k: None})
                camel_key = list(camel_k.keys())[0]
                if camel_key in target:
                    target_key = camel_key
            
            if target_key in target:
                if isinstance(target[target_key], list) and isinstance(v, list):
                    target_list = target[target_key]
                    if len(target_list) > 0 and isinstance(target_list[0], dict) and 'networkType' in target_list[0]:
                        for s_item in v:
                            if isinstance(s_item, dict) and 'networkType' in s_item:
                                s_net = s_item['networkType']
                                found_match = False
                                for t_item in target_list:
                                    if isinstance(t_item, dict) and t_item.get('networkType') == s_net:
                                        recursive_merge(t_item, s_item)
                                        found_match = True
                                        break
                                if not found_match:
                                    target_list.append(s_item)
                    else:
                        for i in range(min(len(target_list), len(v))):
                            if isinstance(target_list[i], (dict, list)) and isinstance(v[i], (dict, list)):
                                recursive_merge(target_list[i], v[i])
                            else:
                                target_list[i] = v[i]
                        if len(v) > len(target_list):
                            target_list.extend(v[len(target_list):])
                elif isinstance(target[target_key], dict) and isinstance(v, dict):
                    recursive_merge(target[target_key], v)
                else:
                    target[target_key] = v
            else:
                target[target_key] = v

def apply_prefix(name: str, prefix: str) -> str:
    """Prepends the prefix to the name if not already prefixed."""
    if not prefix:
        return name
    prefix_clean = prefix.strip()
    if not prefix_clean:
        return name
    if name.startswith(prefix_clean):
        return name
    return f"{prefix_clean} - {name}"

def apply_prefix_and_truncate(name: str, prefix: str, max_len: int = 50) -> str:
    """Prepends the prefix and truncates to max_len if it exceeds."""
    prefixed = apply_prefix(name, prefix)
    if len(prefixed) > max_len:
        truncated = prefixed[:max_len].rstrip()
        logger.info(f"Name '{prefixed}' with prefix was too long. Truncated to '{truncated}' ({len(truncated)} chars).")
        return truncated
    return prefixed

def resolve_pac_urls_recursive(val, target_pacs):
    """Recursively replaces any string values matching target PAC names with their URLs."""
    if isinstance(val, dict):
        return {k: resolve_pac_urls_recursive(v, target_pacs) for k, v in val.items()}
    if isinstance(val, list):
        return [resolve_pac_urls_recursive(v, target_pacs) for v in val]
    if isinstance(val, str):
        val_lower = val.lower()
        val_clean = val_lower.replace(" ", "_")
        if val_clean in target_pacs:
            resolved_url = target_pacs[val_clean]
            logger.info(f"Dynamically linked PAC name '{val}' to target URL: {resolved_url}")
            return resolved_url
    return val


def _get_blank_app_profile_base(platform: str, name: str, forwarding_profile_id: int = 0, forwarding_profile_name: str = "") -> dict:
    """Returns a hardcoded blank base App Profile payload for the given platform.

    This is derived from the proven working payload used by the ZCC UI.
    No existing profile on the tenant is required — this is fully self-contained.
    The 'id' field is intentionally absent to trigger creation (not update) on the OneAPI gateway.
    """
    # Build forwardingProfile list in the exact format the ZCC UI sends (label + enableLWFDriver required)
    fwd_profile_list = [{
        "label": forwarding_profile_name or str(forwarding_profile_id),
        "value": str(forwarding_profile_id),
        "enableLWFDriver": "1",
        "disabled": None,
        "selected": None,
    }] if forwarding_profile_id else []

    # Shared base across all platforms
    base = {
        "name": name,
        "active": "0",
        "ruleOrder": 1,  # New profiles always inserted at position 1, same as ZCC UI
        "description": "",
        "groups": [],
        "users": [],
        "appServiceIds": [],
        "groupAll": 0,
        "pac_url": "",
        "logMode": -1,
        "logLevel": 0,
        "logFileSize": 100,
        "reactivateWebSecurityMinutes": 0,
        "tunnelZappTraffic": 0,
        "sendDisableServiceReason": 0,
        "highlightActiveControl": 0,
        "reauth_period": "12",
        "refreshKerberosToken": 0,
        "bypassCustomAppIds": [],
        "bypassAppIds": [],
        "deviceGroups": [],
        "enableDeviceGroups": 0,
        "forwardingProfileId": forwarding_profile_id,
        "forwardingProfile": fwd_profile_list,
        "disasterRecovery": {
            "enableZiaDR": None,
            "enableZpaDR": None,
            "ziaDRMethod": 2,
            "ziaCustomDbUrl": "",
            "useZiaGlobalDb": True,
            "ziaDomainName": "",
            "ziaRSAPubKeyName": "",
            "ziaRSAPubKey": "",
            "zpaDomainName": "",
            "zpaRSAPubKeyName": "",
            "zpaRSAPubKey": "",
            "allowZiaTest": None,
            "allowZpaTest": None,
        },
        "policyExtension": {
            "vpnGateways": "",
            "partnerDomains": "",
            "exitPassword": "",
            "followRoutingTable": "1",
            "useDefaultAdapterForDNS": "1",
            "updateDnsSearchOrder": "1",
            "useZscalerNotificationFramework": "1",
            "switchFocusToNotification": "1",
            "fallbackToGatewayDomain": "1",
            "useProxyPortForT1": "0",
            "useProxyPortForT2": "0",
            "useWsaPollForZpa": "0",
            "enableZCCRevert": "0",
            "zccRevertPassword": "",
            "zpaAuthExpOnSleep": 0,
            "zpaAuthExpOnSysRestart": 0,
            "zpaAuthExpOnNetIpChange": 0,
            "zpaAuthExpOnWinLogonSession": 0,
            "zpaAuthExpOnWinSessionLock": 0,
            "zpaAuthExpSessionLockStateMinTimeInSecond": "0",
            "enableSetProxyOnVPNAdapters": 1,
            "disableDNSRouteExclusion": 0,
            "interceptZIATrafficAllAdapters": 0,
            "enableAntiTampering": "1",
            "reactivateAntiTamperingTime": "10",
            "overrideATCmdByPolicy": "1",
            "sourcePortBasedBypasses": "3389:*",
            "enforceSplitDNS": 0,
            "dropQuicTraffic": "0",
            "useV8JsEngine": "1",
            "followGlobalForPartnerLogin": "1",
            "followGlobalForZpaReauth": "1",
            "followGlobalForPacketCapture": "1",
            "enableLocalPacketCapture": "0",
            "packetTunnelIncludeList": "0.0.0.0/0",
            "packetTunnelExcludeList": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,224.0.0.0/4,255.255.255.255,169.254.0.0/16",
            "packetTunnelExcludeListForIPv6": "[FF00::/8],[FE80::/10],[FC00::/7]",
            "packetTunnelIncludeListForIPv6": "",
            "packetTunnelDnsIncludeList": "",
            "packetTunnelDnsExcludeList": "",
            "nonce": "",
            "machineIdpAuth": None,
            "enableFlowBasedTunnel": "0",
            "zccAppFailOpenPolicy": 0,
            "zccTunnelFailPolicy": 0,
            "zccFailCloseSettingsLockdownOnTunnelProcessExit": "1",
            "zccFailCloseSettingsLockdownOnFirewallError": "0",
            "zccFailCloseSettingsLockdownOnDriverError": "0",
            "zccFailCloseSettingsExitUninstallPassword": "",
            "zccFailCloseSettingsAppByPassIds": [],
            "userAllowedToAddPartner": "1",
            "deleteDHCPOption121Routes": "{\"trusted\":1,\"offTrusted\":1,\"vpnTrusted\":1,\"splitVpnTrusted\":1}",
            "ddilConfig": "{\"ddilEnabled\":0,\"businessContinuityActivationDomain\":\"\",\"businessContinuityTestModeEnabled\":0}",
            "generateCliPasswordContract": {
                "enableCli": None,
                "allowZpaDisableWithoutPassword": True,
                "allowZiaDisableWithoutPassword": True,
                "allowZdxDisableWithoutPassword": True,
            },
            "prioritizeDnsExclusions": 1,
            "truncateLargeUDPDNSResponse": 0,
            "zdxLiteConfigObj": "{\"localMetrics\":1,\"endToEndDiagnostics\":{\"trusted\":0,\"vpnTrusted\":0,\"offTrusted\":0,\"splitVpnTrusted\":0}}",
            "enableAutomaticPacketCapture": "0",
            "enableAPCforCriticalSections": "1",
            "enableAPCforOtherSections": "1",
            "enablePCAdditionalSpace": "1",
            "pcAdditionalSpace": "512",
            "blockPrivateRelay": "0",
            "enableCrashReporting": "0",
            "advanceZpaReauthTime": "15",
            "enableCustomProxyDetection": "0",
            "oneIdMTDeviceAuthEnabled": "0",
            "preventAutoReauthDuringDeviceLock": "0",
        },
    }

    dev = platform.lower()
    if dev == "mac":
        dev = "macos"

    if dev == "windows":
        base["device_type"] = 3
        base["windowsPolicy"] = {
            "cacheSystemProxy": "0",
            "disable_password": "",
            "logout_password": "",
            "uninstall_password": "",
            "install_ssl_certs": 1,
            "disableLoopBackRestriction": "0",
            "removeExemptedContainers": "0",
            "disableParallelIpv4andIpv6": "-1",
            "flowLoggerConfig": "",
            "domainProfileDetectionConfig": "{\"trusted\":0,\"vpnTrusted\":0,\"offTrusted\":0,\"splitVpnTrusted\":0}",
            "allInboundTrafficConfig": "",
            "triggerDomainProfleDetection": 0,
            "overrideWPAD": 0,
            "pacDataPath": "",
            "pacType": 1,
            "prioritizeIPv4": 0,
            "restartWinHttpSvc": 0,
            "wfpDriver": 1,
            "captivePortalConfig": "{\"automaticCapture\":0,\"enableCaptivePortalDetection\":0,\"enableFailOpen\":0,\"captivePortalWebSecDisableMinutes\":0,\"enableEmbeddedCaptivePortal\":0}",
            "installWindowsFirewallInboundRule": "1",
            "forceLocationRefreshSccm": 0,
            "enableCustomProxyDetection": "0",
            "enableZscalerFirewall": "0",
            "captivePortalUrlId": 1,
            "sccmConfig": None,
        }
    elif dev == "macos":
        base["device_type"] = 4
        base["macPolicy"] = {
            "disable_password": "",
            "logout_password": "",
            "uninstall_password": "",
            "install_ssl_certs": 1,
            "clearArpCache": 0,
            "enableZscalerFirewall": "0",
            "persistentZscalerFirewall": 0,
            "dnsPriorityOrdering": "",
            "dnsPriorityOrderingForTrustedDnsCriteria": "",
        }
    elif dev == "linux":
        base["device_type"] = 5
    elif dev == "ios":
        base["device_type"] = 1
    elif dev == "android":
        base["device_type"] = 2

    return base

def _create_app_profile_oneapi(client, name: str, platform: str, logger, forwarding_profile_id: int = 0, forwarding_profile_name: str = ""):
    """Creates an App Profile by cloning an existing profile on the tenant via web_policy_edit.

    Cloning guarantees the payload has every required internal field the API expects.
    The blank base approach consistently returns success=false because internal fields
    vary by tenant version and the API gives no specific error.

    Strategy:
      1. Fetch all existing web policies for the target platform.
      2. Clone the first non-default (non-zero id) profile, stripping identity fields.
      3. Override: name, forwardingProfileId, forwardingProfile list.
      4. Fall back to blank base only if no existing profile to clone from.
    """
    import copy
    import time

    if not forwarding_profile_id:
        logger.warning(
            f"Cannot create App Profile '{name}': a valid forwarding_profile_id is required. "
            f"Ensure the Forwarding Profile is created and mapped before creating App Profiles. "
            f"Skipping creation."
        )
        return False

    # Map platform string to ZCC device_type int
    dev = platform.lower()
    if dev == "mac":
        dev = "macos"
    platform_to_device_type = {
        "windows": 3, "macos": 5, "ios": 1, "android": 2
    }
    device_type_int = platform_to_device_type.get(dev, 3)

    # --- Step 1: Try to clone an existing profile ---
    existing, _, err = client.zcc.web_policy.list_by_company(
        query_params={"device_type": dev}
    )
    template_dict = None
    # Profiles to skip as clone templates: placeholder/dummy names are not valid bases
    SKIP_TEMPLATE_NAMES = {"dummy"}
    if not err and existing:
        for p in existing:
            p_dict = p.as_dict() if hasattr(p, "as_dict") else dict(p)
            raw_id = p_dict.get("id") or p_dict.get("policy_id") or 0
            p_name = (p_dict.get("name") or "").strip().lower()
            if p_name not in SKIP_TEMPLATE_NAMES:
                template_dict = p_dict
                logger.info(
                    f"Using existing App Profile '{p_dict.get('name')}' (ID {raw_id}) as clone template."
                )
                break
        if not template_dict:
            logger.warning(
                f"No valid clone template found for platform '{platform}' (all existing profiles are placeholder/default). "
                f"Falling back to blank base template."
            )

    if template_dict:
        payload = copy.deepcopy(template_dict)

        # Recursively strip ALL identity fields from the payload and any nested dicts.
        # generateCliPasswordContract.policyId is the main offender — the server sees it
        # and treats the request as an update to the source profile, causing success=false.
        STRIP_KEYS = {
            "id", "policyId", "policy_id", "companyId", "company_id",
            "policyToken", "policy_token", "lastModification",
            "last_modified_by", "last_modified_time", "creation_time", "created_by",
            "deviceTypeName", "device_type_name",
            "notificationTemplateContract", "notification_template_contract",
            "ziaPostureConfig", "zia_posture_config",
            "onNetPolicy", "on_net_policy",
            "appServices", "app_services",
            "zccFailCloseSettingsThumbPrint", "zcc_fail_close_settings_thumb_print",
        }

        def _strip_identity(obj):
            if isinstance(obj, dict):
                return {k: _strip_identity(v) for k, v in obj.items() if k not in STRIP_KEYS}
            if isinstance(obj, list):
                return [_strip_identity(x) for x in obj]
            return obj

        payload = _strip_identity(payload)
        # Also clear the thumbprint — it is cryptographically tied to the source profile
        payload.pop("zccFailCloseSettingsThumbPrint", None)
        payload.pop("zcc_fail_close_settings_thumb_print", None)
        if isinstance(payload.get("policyExtension"), dict):
            payload["policyExtension"].pop("zccFailCloseSettingsThumbPrint", None)
        if isinstance(payload.get("policy_extension"), dict):
            payload["policy_extension"].pop("zcc_fail_close_settings_thumb_print", None)
    else:
        # --- Fallback: use hardcoded blank base ---
        logger.warning(
            f"No existing App Profile found on tenant for platform '{platform}' to use as template. "
            f"Falling back to blank base (may fail on some tenants)."
        )
        payload = _get_blank_app_profile_base(platform, name, forwarding_profile_id, forwarding_profile_name)

    # Override the identifying fields
    payload["name"] = name
    payload["device_type"] = device_type_int
    payload["forwardingProfileId"] = forwarding_profile_id
    payload["forwardingProfile"] = [{
        "label": forwarding_profile_name or str(forwarding_profile_id),
        "value": str(forwarding_profile_id),
        "enableLWFDriver": "1",
        "disabled": None,
        "selected": None,
    }]
    # Clear any user/group assignments from the cloned profile
    payload["groups"] = []
    payload["users"] = []
    payload["groupAll"] = 0
    payload.pop("group_ids", None)
    payload.pop("user_ids", None)

    logger.info(
        f"Creating App Profile '{name}' (platform={platform}, fwd_id={forwarding_profile_id}) "
        f"via {'clone' if template_dict else 'blank base'}..."
    )
    result, response, err = client.zcc.web_policy.web_policy_edit(**payload)
    if err:
        logger.warning(
            f"OneAPI rejected App Profile creation for '{name}'. Error: {err}"
        )
        return False

    # The SDK may not surface success=false from the body — check explicitly
    try:
        body = response._body if hasattr(response, "_body") else {}
        if isinstance(body, dict) and str(body.get("success", "true")).lower() == "false":
            err_msg = body.get("message") or body.get("error") or body.get("reason") or str(body)
            logger.warning(
                f"OneAPI returned HTTP 200 but success=false for App Profile '{name}'. Details: {err_msg}. Skipping creation."
            )
            return False
    except AttributeError:
        pass

    logger.info(f"App Profile '{name}' created successfully via OneAPI. Waiting for ZCC sync...")
    time.sleep(2)
    return True


def get_blank_fwd_profile_payload(name: str) -> dict:
    """Returns a standard default Forwarding Profile payload mapping to 'No Forwarding'."""
    return {
        "id": "-1",
        "name": name,
        "active": 0,
        "enableLWFDriver": 1,
        "enableAllDefaultAdaptersTN": 0,
        "enableSplitVpnTN": 0,
        "skipTrustedCriteriaMatch": 0,
        "addCondition": "",
        "conditionType": 1,
        "dnsServers": "",
        "dnsSearchDomains": "",
        "hostname": "",
        "resolvedIpsForHostname": "",
        "trustedSubnets": "",
        "trustedGateways": "",
        "trustedDhcpServers": "",
        "trustedEgressIps": "",
        "predefinedTrustedNetworks": False,
        "trustedNetworkIds": [],
        "predefinedTnAll": False,
        "forwardingProfileActions": [
            {
                "actionType": 0,
                "enablePacketTunnel": 0,
                "blockUnreachableDomainsTraffic": "0",
                "dropIpv6Traffic": 0,
                "primaryTransport": 1,
                "UDPTimeout": 9,
                "DTLSTimeout": 9,
                "TLSTimeout": 5,
                "mtuForZadapter": "0",
                "allowTLSFallback": 1,
                "pathMtuDiscovery": 1,
                "tunnel2FallbackType": 0,
                "useTunnel2ForProxiedWebTraffic": 0,
                "useTunnel2ForUnencryptedWebTraffic": 0,
                "redirectWebTraffic": 0,
                "dropIpv6IncludeTrafficInT2": 0,
                "customPac": "",
                "systemProxyData": {
                    "bypassProxyForPrivateIP": 0,
                    "enableAutoDetect": 0,
                    "enablePAC": 0,
                    "enableProxyServer": 0,
                    "pacURL": "",
                    "pacDataPath": "",
                    "performGPUpdate": 0,
                    "proxyAction": 0,
                    "proxyServerAddress": "",
                    "proxyServerPort": ""
                },
                "latencyBasedZenEnablement": "0",
                "zenProbeInterval": 60,
                "zenProbeSampleSize": 5,
                "zenThresholdLimit": 2,
                "latencyBasedServerEnablement": 0,
                "lbsProbeInterval": 30,
                "lbsProbeSampleSize": 5,
                "lbsThresholdLimit": 1,
                "latencyBasedServerMTEnablement": 0,
                "networkType": 0
            },
            {
                "actionType": 0,
                "enablePacketTunnel": 0,
                "blockUnreachableDomainsTraffic": "0",
                "dropIpv6Traffic": 0,
                "primaryTransport": 1,
                "UDPTimeout": 9,
                "DTLSTimeout": 9,
                "TLSTimeout": 5,
                "mtuForZadapter": "0",
                "allowTLSFallback": 1,
                "pathMtuDiscovery": 1,
                "tunnel2FallbackType": 0,
                "useTunnel2ForProxiedWebTraffic": 0,
                "useTunnel2ForUnencryptedWebTraffic": 0,
                "redirectWebTraffic": 0,
                "dropIpv6IncludeTrafficInT2": 0,
                "customPac": "",
                "systemProxyData": {
                    "bypassProxyForPrivateIP": 0,
                    "enableAutoDetect": 0,
                    "enablePAC": 0,
                    "enableProxyServer": 0,
                    "pacURL": "",
                    "pacDataPath": "",
                    "performGPUpdate": 0,
                    "proxyAction": 0,
                    "proxyServerAddress": "",
                    "proxyServerPort": ""
                },
                "latencyBasedZenEnablement": "0",
                "zenProbeInterval": 60,
                "zenProbeSampleSize": 5,
                "zenThresholdLimit": 2,
                "latencyBasedServerEnablement": 0,
                "lbsProbeInterval": 30,
                "lbsProbeSampleSize": 5,
                "lbsThresholdLimit": 1,
                "latencyBasedServerMTEnablement": 0,
                "networkType": 1,
                "isSameAsOnTrustedNetwork": None
            },
            {
                "actionType": 0,
                "enablePacketTunnel": 0,
                "blockUnreachableDomainsTraffic": "0",
                "dropIpv6Traffic": 0,
                "primaryTransport": 1,
                "UDPTimeout": 9,
                "DTLSTimeout": 9,
                "TLSTimeout": 5,
                "mtuForZadapter": "0",
                "allowTLSFallback": 1,
                "pathMtuDiscovery": 1,
                "tunnel2FallbackType": 0,
                "useTunnel2ForProxiedWebTraffic": 0,
                "useTunnel2ForUnencryptedWebTraffic": 0,
                "redirectWebTraffic": 0,
                "dropIpv6IncludeTrafficInT2": 0,
                "customPac": "",
                "systemProxyData": {
                    "bypassProxyForPrivateIP": 0,
                    "enableAutoDetect": 0,
                    "enablePAC": 0,
                    "enableProxyServer": 0,
                    "pacURL": "",
                    "pacDataPath": "",
                    "performGPUpdate": 0,
                    "proxyAction": 0,
                    "proxyServerAddress": "",
                    "proxyServerPort": ""
                },
                "latencyBasedZenEnablement": "0",
                "zenProbeInterval": 60,
                "zenProbeSampleSize": 5,
                "zenThresholdLimit": 2,
                "latencyBasedServerEnablement": 0,
                "lbsProbeInterval": 30,
                "lbsProbeSampleSize": 5,
                "lbsThresholdLimit": 1,
                "latencyBasedServerMTEnablement": 0,
                "networkType": 2,
                "isSameAsOnTrustedNetwork": None
            },
            {
                "actionType": 0,
                "enablePacketTunnel": 0,
                "blockUnreachableDomainsTraffic": "0",
                "dropIpv6Traffic": 0,
                "primaryTransport": 1,
                "UDPTimeout": 9,
                "DTLSTimeout": 9,
                "TLSTimeout": 5,
                "mtuForZadapter": "0",
                "allowTLSFallback": 1,
                "pathMtuDiscovery": 1,
                "tunnel2FallbackType": 0,
                "useTunnel2ForProxiedWebTraffic": 0,
                "useTunnel2ForUnencryptedWebTraffic": 0,
                "redirectWebTraffic": 0,
                "dropIpv6IncludeTrafficInT2": 0,
                "customPac": "",
                "systemProxyData": {
                    "bypassProxyForPrivateIP": 0,
                    "enableAutoDetect": 0,
                    "enablePAC": 0,
                    "enableProxyServer": 0,
                    "pacURL": "",
                    "pacDataPath": "",
                    "performGPUpdate": 0,
                    "proxyAction": 0,
                    "proxyServerAddress": "",
                    "proxyServerPort": ""
                },
                "latencyBasedZenEnablement": "0",
                "zenProbeInterval": 60,
                "zenProbeSampleSize": 5,
                "zenThresholdLimit": 2,
                "latencyBasedServerEnablement": 0,
                "lbsProbeInterval": 30,
                "lbsProbeSampleSize": 5,
                "lbsThresholdLimit": 1,
                "latencyBasedServerMTEnablement": 0,
                "networkType": 3,
                "isSameAsOnTrustedNetwork": None
            }
        ],
        "forwardingProfileZpaActions": [
            {
                "actionType": 0,
                "primaryTransport": 0,
                "DTLSTimeout": 9,
                "TLSTimeout": 5,
                "mtuForZadapter": "0",
                "partnerInfo": {
                    "primaryTransport": 0,
                    "mtuForZadapter": 0
                },
                "latencyBasedServerEnablement": "0",
                "lbsProbeSampleSize": 5,
                "lbsThresholdLimit": 1,
                "lbsProbeInterval": 30,
                "latencyBasedServerMTEnablement": "0",
                "networkType": 0
            },
            {
                "actionType": 0,
                "primaryTransport": 0,
                "DTLSTimeout": 9,
                "TLSTimeout": 5,
                "mtuForZadapter": "0",
                "partnerInfo": {
                    "primaryTransport": 0,
                    "mtuForZadapter": 0
                },
                "latencyBasedServerEnablement": "0",
                "lbsProbeSampleSize": 5,
                "lbsThresholdLimit": 1,
                "lbsProbeInterval": 30,
                "latencyBasedServerMTEnablement": "0",
                "networkType": 1,
                "isSameAsOnTrustedNetwork": None
            },
            {
                "actionType": 0,
                "primaryTransport": 0,
                "DTLSTimeout": 9,
                "TLSTimeout": 5,
                "mtuForZadapter": "0",
                "partnerInfo": {
                    "primaryTransport": 0,
                    "mtuForZadapter": 0
                },
                "latencyBasedServerEnablement": "0",
                "lbsProbeSampleSize": 5,
                "lbsThresholdLimit": 1,
                "lbsProbeInterval": 30,
                "latencyBasedServerMTEnablement": "0",
                "networkType": 2,
                "isSameAsOnTrustedNetwork": None
            },
            {
                "actionType": 1,
                "primaryTransport": 0,
                "DTLSTimeout": 9,
                "TLSTimeout": 5,
                "mtuForZadapter": "0",
                "partnerInfo": {
                    "primaryTransport": 0,
                    "mtuForZadapter": 0
                },
                "latencyBasedServerEnablement": "0",
                "lbsProbeSampleSize": 5,
                "lbsThresholdLimit": 1,
                "lbsProbeInterval": 30,
                "latencyBasedServerMTEnablement": "0",
                "networkType": 3,
                "isSameAsOnTrustedNetwork": False
            }
        ]
    }


def _create_forwarding_profile_oneapi(client, name: str, logger, update_data: dict = None):
    """Creates a Forwarding Profile via the OneAPI update_forwarding_profile endpoint.

    If any existing custom (non-default) profile exists, it clones its structure (stripping its id).
    Otherwise, it uses a built-in standard base payload, ensuring zero external setup requirements.

    update_data: optional dict of YAML-derived settings (snake_case) to merge into the creation
    payload so that Tunnel 2.0 / TLS / PAC settings are baked in at creation time.
    """
    import copy
    import time

    # Fetch existing profiles to check for custom templates
    profiles, _, err = client.zcc.forwarding_profile.list_by_company()
    if err:
        raise ValueError(
            f"Cannot create Forwarding Profile '{name}': failed to list existing profiles. Error: {err}"
        )

    def to_raw_api_payload(val):
        if hasattr(val, 'request_format'):
            val = val.request_format()
        if isinstance(val, dict):
            return {k: to_raw_api_payload(v) for k, v in val.items() if v is not None}
        if isinstance(val, list):
            return [to_raw_api_payload(x) for x in val]
        return val

    # Find the first non-default custom profile to use as template if available
    template = None
    if profiles:
        for p in profiles:
            p_id = str(getattr(p, 'id', '0') or '0').replace('.', '')
            if p_id not in ('0', ''):
                template = p
                break

    if template:
        logger.info(f"Cloning template structure from existing custom profile '{getattr(template, 'name', '')}'...")
        payload = to_raw_api_payload(template)
        # Strip company/read-only metadata, and set 'id' to "-1" to trigger creation
        for key in ['companyId', 'company_id', 'lastModification',
                    'last_modified_by', 'last_modified_time', 'policyToken', 'policy_token',
                    'unifiedTunnel', 'unified_tunnel']:
            payload.pop(key, None)
    else:
        logger.info("No existing custom Forwarding Profile found. Using built-in blank default payload...")
        payload = get_blank_fwd_profile_payload(name)

    payload['id'] = "-1"
    payload['name'] = name

    # Merge YAML update_data into the creation payload so Tunnel/TLS/PAC settings
    # are applied at creation time rather than requiring a follow-up update call.
    if update_data:
        wire_update = to_camel_wire_dict(copy.deepcopy(update_data))
        # Remove name/id from the merge source to avoid overwriting what we just set
        wire_update.pop('name', None)
        wire_update.pop('id', None)
        wire_update.pop('policyId', None)
        recursive_merge(payload, wire_update)
        logger.info(f"Merged {len(wire_update)} update_data keys into Forwarding Profile creation payload.")

    logger.info(f"Creating Forwarding Profile '{name}' via OneAPI...")
    result, response, err = client.zcc.forwarding_profile.update_forwarding_profile(**payload)
    if err:
        resp_body = getattr(response, "_body", getattr(response, "text", None)) if response else None
        err_detail = resp_body if resp_body else err
        logger.warning(
            f"OneAPI rejected Forwarding Profile creation for '{name}'. Details: {err_detail}"
        )
        return None

    # Check response body success flag
    try:
        body = response._body if hasattr(response, '_body') else {}
        if isinstance(body, dict) and str(body.get('success', 'true')).lower() == 'false':
            logger.warning(
                f"OneAPI returned HTTP 200 but success=false for Forwarding Profile '{name}'. "
                f"Response: {body}"
            )
            return None
    except AttributeError:
        pass

    logger.info(f"Forwarding Profile '{name}' created successfully via OneAPI. Waiting for ZCC sync...")
    time.sleep(2)
    return result


def clean_web_policy_payload_recursive(d):
    """Recursively converts whole floats to int and strips read-only fields/representation lists."""
    if isinstance(d, dict):
        cleaned = {}
        for k, v in d.items():
            # Skip read-only and representation keys
            if k in {
                "id", "policyId", "policy_id", "companyId", "company_id", "policyToken", "policy_token",
                "deviceTypeName", "groups", "users", "deviceGroups", "device_groups",
                "appServices", "app_services", "onNetPolicy", "on_net_policy",
                "notificationTemplateContract", "notification_template_contract",
                "ziaPostureConfig", "zia_posture_config"
            }:
                continue
            cleaned[k] = clean_web_policy_payload_recursive(v)
        return cleaned
    elif isinstance(d, list):
        return [clean_web_policy_payload_recursive(x) for x in d]
    elif isinstance(d, float):
        if d.is_integer():
            return int(d)
        return d
    return d


def restructure_ap_to_web_policy(ap_dict: dict, device_type_str: str) -> dict:
    """Restructures a flat ApplicationProfile dictionary to match the nested WebPolicy format."""
    import copy
    payload = copy.deepcopy(ap_dict)
    
    # Run recursive clean to strip database/read-only metadata/representation fields and convert float integers
    payload = clean_web_policy_payload_recursive(payload)
    
    dev_type = device_type_str.lower()
    if dev_type == "mac":
        dev_type = "macos"
        
    # Ensure deviceType is numeric (camelCase since input is already camelCase)
    if dev_type == "windows":
        payload["deviceType"] = 3
        payload.pop("device_type", None)
    elif dev_type == "macos":
        payload["deviceType"] = 4
        payload.pop("device_type", None)
    elif dev_type == "linux":
        payload["deviceType"] = 5
        payload.pop("device_type", None)
    elif dev_type == "ios":
        payload["deviceType"] = 1
        payload.pop("device_type", None)
    elif dev_type == "android":
        payload["deviceType"] = 2
        payload.pop("device_type", None)
        
    # Extract windows/mac specific keys from root and nest them
    if dev_type == "windows":
        windows_keys = [
            "cacheSystemProxy", "disable_password", "disablePassword",
            "disableLoopBackRestriction", "removeExemptedContainers",
            "disableParallelIpv4andIpv6", "disableParallelIpv4AndIPv6",
            "flowLoggerConfig", "domainProfileDetectionConfig",
            "allInboundTrafficConfig", "install_ssl_certs", "installSslCerts",
            "triggerDomainProfleDetection", "logout_password", "logoutPassword",
            "overrideWPAD", "pacDataPath", "pacType", "prioritizeIPv4",
            "restartWinHttpSvc", "sccmConfig", "uninstall_password",
            "uninstallPassword", "wfpDriver", "captivePortalConfig",
            "installWindowsFirewallInboundRule", "forceLocationRefreshSccm"
        ]
        windows_policy = payload.pop("windowsPolicy", {}) or {}
        if not isinstance(windows_policy, dict):
            windows_policy = {}
            
        for k in windows_keys:
            val = payload.pop(k, None)
            if val is not None:
                windows_policy[k] = val
                
        payload.pop("macPolicy", None)
        payload.pop("mac_policy", None)
        payload.pop("linuxPolicy", None)
        payload.pop("iosPolicy", None)
        payload.pop("androidPolicy", None)
        
        payload["windowsPolicy"] = windows_policy
        
    elif dev_type == "macos":
        mac_keys = [
            "addIfscopeRoute", "cacheSystemProxy", "clearArpCache",
            "disablePassword", "disable_password", "dnsPriorityOrdering",
            "dnsPriorityOrderingForTrustedDnsCriteria", "enableApplicationBasedBypass",
            "enableZscalerFirewall", "installCerts", "logoutPassword",
            "logout_password", "persistentZscalerFirewall", "uninstallPassword",
            "uninstall_password"
        ]
        mac_policy = payload.pop("macPolicy", {}) or {}
        if not isinstance(mac_policy, dict):
            mac_policy = {}
            
        for k in mac_keys:
            val = payload.pop(k, None)
            if val is not None:
                mac_policy[k] = val
                
        payload.pop("windowsPolicy", None)
        payload.pop("windows_policy", None)
        payload.pop("linuxPolicy", None)
        payload.pop("iosPolicy", None)
        payload.pop("androidPolicy", None)
        
        # Convert dnsPriorityOrdering fields from list to string if needed
        if "dnsPriorityOrdering" in mac_policy and isinstance(mac_policy["dnsPriorityOrdering"], list):
            mac_policy["dnsPriorityOrdering"] = mac_policy["dnsPriorityOrdering"][0] if mac_policy["dnsPriorityOrdering"] else ""
        if "dnsPriorityOrderingForTrustedDnsCriteria" in mac_policy and isinstance(mac_policy["dnsPriorityOrderingForTrustedDnsCriteria"], list):
            mac_policy["dnsPriorityOrderingForTrustedDnsCriteria"] = mac_policy["dnsPriorityOrderingForTrustedDnsCriteria"][0] if mac_policy["dnsPriorityOrderingForTrustedDnsCriteria"] else ""
            
        payload["macPolicy"] = mac_policy
        
    return payload


def setup_zcc(client: ZscalerClient, config: ZCCConfig, dry_run: bool = False, prefix: str = "POV-TOOL") -> Dict[str, Any]:
    """Updates ZCC configurations based on config file."""
    results = {}
    if not config:
        return results

    # Maps for resolving dependency linkages
    processed_networks = {}
    processed_fwds = {}

    # Fetch target PAC files from ZIA to resolve dynamic linking
    target_pacs = {}
    try:
        pacs_list, _, err = client.zia.pac_files.list_pac_files()
        if not err and pacs_list:
            for p in pacs_list:
                p_dict = p.as_dict() if hasattr(p, "as_dict") else p
                p_name = p_dict.get("name")
                p_url = p_dict.get("pac_url")
                if p_name and p_url:
                    p_name_lower = p_name.lower()
                    target_pacs[p_name_lower] = p_url
                    target_pacs[p_name_lower.replace(" ", "_")] = p_url
                    if " - " in p_name:
                        parts = p_name.split(" - ", 1)
                        if len(parts) > 1:
                            part_lower = parts[1].lower()
                            target_pacs[part_lower] = p_url
                            target_pacs[part_lower.replace(" ", "_")] = p_url

            logger.info(f"Loaded {len(target_pacs)} ZIA PAC file URLs for dynamic linking.")
        elif err:
            logger.warning(f"Could not retrieve ZIA PAC files: {err}")
    except Exception as e:
        logger.warning(f"Could not load ZIA PAC files: {e}")

    # 1. Process Trusted Networks
    if config.trusted_networks:
        results["trusted_networks"] = []
        logger.info("Starting Trusted Networks configuration setup...")
        
        # Get existing networks
        networks, _, err = client.zcc.trusted_networks.list_by_company()
        if err:
            logger.error(f"Failed to list trusted networks: {err}")
            raise Exception(f"Failed to list trusted networks: {err}")
            
        for net_cfg in config.trusted_networks:
            raw_name = net_cfg.network_name
            prefixed_name = apply_prefix_and_truncate(raw_name, prefix, 50)
            logger.info(f"Processing Trusted Network. Target Name: '{prefixed_name}' (Raw Name: '{raw_name}')")

            # Match against existing networks by raw or prefixed name
            found_net = None
            search_names = {raw_name.lower(), prefixed_name.lower()}
            for net in networks:
                if net.network_name and net.network_name.lower() in search_names:
                    found_net = net
                    break

            # Prepare payload
            net_data = net_cfg.model_dump(exclude_none=True)
            net_data["network_name"] = prefixed_name

            if found_net:
                net_id = found_net.id
                processed_networks[raw_name.lower()] = net_id
                processed_networks[prefixed_name.lower()] = net_id
                if found_net.network_name:
                    processed_networks[found_net.network_name.lower()] = net_id

                logger.info(f"Trusted Network '{prefixed_name}' already exists (ID: {net_id}). Updating configuration.")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would update Trusted Network '{prefixed_name}' (ID: {net_id})")
                else:
                    import copy
                    original_payload = to_camel_wire_dict(found_net)
                    net_payload = copy.deepcopy(original_payload)
                    recursive_merge(net_payload, net_data)
                    net_payload = remove_none_recursive(net_payload)
                    net_payload["id"] = net_id # Ensure ID is present

                    # Compare payload to detect actual changes
                    cleaned_original = remove_none_recursive(original_payload)
                    cleaned_new = remove_none_recursive(net_payload)

                    if cleaned_original == cleaned_new:
                        logger.info(f"Trusted Network '{prefixed_name}' is already up-to-date. Skipping API update.")
                    else:
                        _, _, err = client.zcc.trusted_networks.update_trusted_network(**net_payload)
                        if err:
                            logger.error(f"Failed to update Trusted Network: {err}")
                            raise Exception(f"Failed to update Trusted Network: {err}")
                        logger.info(f"Trusted Network '{prefixed_name}' updated successfully.")
                    results["trusted_networks"].append({"id": net_id, "name": prefixed_name, "action": "update"})
            else:
                logger.info(f"Trusted Network '{prefixed_name}' not found. Creating a new one.")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create Trusted Network '{prefixed_name}' with data: {net_data}")
                    results["trusted_networks"].append({"id": "DRY-RUN-ID", "name": prefixed_name, "action": "create"})
                else:
                    net_payload = remove_none_recursive(net_data)
                    res, _, err = client.zcc.trusted_networks.add_trusted_network(**net_payload)
                    if err:
                        logger.error(f"Failed to create Trusted Network: {err}")
                        raise Exception(f"Failed to create Trusted Network: {err}")
                    
                    new_id = res.id if hasattr(res, "id") else res.get("id")
                    processed_networks[raw_name.lower()] = new_id
                    processed_networks[prefixed_name.lower()] = new_id
                    logger.info(f"Trusted Network '{prefixed_name}' created successfully (ID: {new_id}).")
                    results["trusted_networks"].append({"id": new_id, "name": prefixed_name, "action": "create"})

    # 2. Process Web Privacy (User Privacy)
    if config.web_privacy:
        logger.info("Starting Web Privacy configuration setup...")
        privacy_data = config.web_privacy.model_dump(exclude_none=True)
        
        # Web Privacy endpoint needs 'id' from current configuration to update successfully
        existing_privacy = client.zcc.web_privacy.get_web_privacy()
        if isinstance(existing_privacy, dict) and "id" in existing_privacy:
            privacy_data["id"] = existing_privacy["id"]
        
        if dry_run:
            logger.info("[DRY-RUN] Would update Web Privacy")
            results["web_privacy"] = {"action": "update"}
        else:
            privacy_payload = remove_none_recursive(privacy_data)
            res, _, err = client.zcc.web_privacy.set_web_privacy_info(**privacy_payload)
            if err:
                logger.error(f"Failed to update Web Privacy configuration: {err}")
                raise Exception(f"Failed to update Web Privacy configuration: {err}")
            logger.info("Web Privacy configuration updated successfully.")
            results["web_privacy"] = {"action": "update", "id": privacy_payload.get("id")}

    # 3. Process Device Cleanup
    if config.device_cleanup:
        logger.info("Starting Device Cleanup configuration setup...")
        cleanup_data = config.device_cleanup.model_dump(exclude_none=True)
        
        # Device cleanup endpoint needs 'id' from current configuration to update successfully
        existing_cleanup, _, err = client.zcc.devices.get_device_cleanup_info()
        if not err and existing_cleanup:
            first_cleanup = existing_cleanup[0]
            cleanup_id = first_cleanup.id if hasattr(first_cleanup, "id") else first_cleanup.get("id")
            if cleanup_id:
                cleanup_data["id"] = cleanup_id
                
        if dry_run:
            logger.info("[DRY-RUN] Would update Device Cleanup settings")
            results["device_cleanup"] = {"action": "update"}
        else:
            cleanup_payload = remove_none_recursive(cleanup_data)
            _, _, err = client.zcc.devices.update_device_cleanup_info(**cleanup_payload)
            if err:
                # Detect if the error is a 400 Bad Request caused by a large ID (known Zscaler ZCC API limitation)
                is_400_large_id = False
                try:
                    cleanup_id_str = str(cleanup_payload.get("id", ""))
                    if "400" in str(err) and cleanup_id_str.isdigit() and int(cleanup_id_str) > 2147483647:
                        is_400_large_id = True
                except Exception:
                    pass
                
                if is_400_large_id:
                    logger.warning(
                        f"SKIPPED: Could not update Device Cleanup settings due to a known Zscaler API bug. "
                        f"The tenant's Device Cleanup ID ({cleanup_id_str}) exceeds the 32-bit integer limit (2147483647) "
                        f"accepted by the /setDeviceCleanupInfo endpoint. "
                        f"Please configure this setting manually in the Client Connector Support Portal UI."
                    )
                    results["device_cleanup"] = {"action": "skipped_due_to_large_id_api_bug", "id": cleanup_id_str}
                else:
                    logger.error(f"Failed to update Device Cleanup settings: {err}")
                    raise Exception(f"Failed to update Device Cleanup settings: {err}")
            else:
                logger.info("Device Cleanup settings updated successfully.")
                results["device_cleanup"] = {"action": "update", "id": cleanup_data.get("id")}

    # 4. Process Forwarding Profiles
    if config.forwarding_profiles:
        results["forwarding_profiles"] = []
        logger.info("Starting Forwarding Profiles configuration setup...")
        
        # Get existing forwarding profiles
        profiles, _, err = client.zcc.forwarding_profile.list_by_company()
        if err:
            logger.error(f"Failed to list forwarding profiles: {err}")
            raise Exception(f"Failed to list forwarding profiles: {err}")
        for fp_cfg in config.forwarding_profiles:
            raw_name = fp_cfg.update.name
            prefixed_name = apply_prefix_and_truncate(raw_name, prefix, 50)
            logger.info(f"Processing Forwarding Profile. Target Name: '{prefixed_name}' (Raw Name: '{raw_name}')")

            # Match against existing forwarding profiles by raw or prefixed name
            found_profile = None
            just_created = False
            search_names = {raw_name.lower(), prefixed_name.lower(), fp_cfg.search_name.lower()}
            for p in profiles:
                if p.name and p.name.lower() in search_names:
                    found_profile = p
                    break
                    
            if not found_profile:
                logger.info(f"Forwarding Profile '{prefixed_name}' not found. Creating via OneAPI...")
                if dry_run:
                    logger.info(f"[DRY-RUN] Would create Forwarding Profile '{prefixed_name}' via OneAPI.")
                    results["forwarding_profiles"].append({"id": "DRY-RUN-ID", "name": prefixed_name, "action": "create"})
                    continue
                else:
                    # Pass the full YAML update_data so settings are baked in at creation
                    creation_update_data = fp_cfg.update.model_dump(exclude_none=True) if fp_cfg.update else None
                    new_profile = _create_forwarding_profile_oneapi(client, prefixed_name, logger, update_data=creation_update_data)
                    if not new_profile:
                        raise Exception(f"Failed to create Forwarding Profile '{prefixed_name}' via OneAPI.")
                    # Add to local profiles list to prevent extra API requests
                    profiles.append(new_profile)
                    found_profile = new_profile
                    just_created = True

            if found_profile:
                fwd_id = getattr(found_profile, 'id', found_profile.get('id') if isinstance(found_profile, dict) else None)
                processed_fwds[raw_name.lower()] = fwd_id
                processed_fwds[prefixed_name.lower()] = fwd_id
                processed_fwds[fp_cfg.search_name.lower()] = fwd_id
                found_name = getattr(found_profile, 'name', found_profile.get('name') if isinstance(found_profile, dict) else None)
                if found_name:
                    processed_fwds[found_name.lower()] = fwd_id

                if str(fwd_id) == "0":
                    logger.info("Forwarding Profile with ID 0 is the read-only system default profile. Skipping update but recorded mapping.")
                    results["forwarding_profiles"].append({"id": fwd_id, "name": prefixed_name, "status": "skipped_default"})
                    continue
                    
                if just_created:
                    logger.info(f"Forwarding Profile '{prefixed_name}' was just created with settings applied. Skipping immediate update.")
                    results["forwarding_profiles"].append({"id": str(fwd_id), "name": prefixed_name})
                    continue

                # Prepare update payload
                update_data = fp_cfg.update.model_dump(exclude_none=True)
                update_data["name"] = prefixed_name
                update_data.pop("description", None)

                # Resolve Trusted Networks dependency ID mapping
                if "trusted_network_ids" in update_data:
                    # In case the source config lists names or IDs, resolve them
                    target_network_ids = []
                    for tn_ref in update_data.get("trusted_network_ids", []):
                        # Find matching ID in network map
                        net_id = processed_networks.get(tn_ref.lower())
                        if not net_id:
                            # Try with prefixed name
                            prefixed_tn_ref = apply_prefix_and_truncate(tn_ref, prefix, 50)
                            net_id = processed_networks.get(prefixed_tn_ref.lower())
                        if net_id:
                            target_network_ids.append(str(net_id))
                        else:
                            # Keep raw ID/reference if not found in mapping
                            target_network_ids.append(str(tn_ref))
                    update_data["trusted_network_ids"] = target_network_ids

                logger.info(f"Found Forwarding Profile. ID: {fwd_id}. Preparing update.")
                if dry_run:
                    update_data_resolved = resolve_pac_urls_recursive(update_data, target_pacs)
                    logger.info(f"[DRY-RUN] Would update Forwarding Profile '{prefixed_name}' (ID: {fwd_id})")
                    results["forwarding_profiles"].append({"id": fwd_id, "name": prefixed_name})
                else:
                    import copy
                    original_payload = to_camel_wire_dict(found_profile)
                    profile_payload = copy.deepcopy(original_payload)
                    recursive_merge(profile_payload, update_data)
                    profile_payload = resolve_pac_urls_recursive(profile_payload, target_pacs)
                    profile_payload = remove_none_recursive(profile_payload)
                    
                    # Strip read-only metadata and unifiedTunnel which cause HTTP 400 rejection from ZCC backend
                    STRIP_FWD_KEYS = {
                        "unifiedTunnel", "companyId", "company_id", "lastModification",
                        "last_modified_by", "last_modified_time", "creation_time", "created_by",
                        "policyToken", "policy_token"
                    }
                    for k in STRIP_FWD_KEYS:
                        profile_payload.pop(k, None)
                    
                    # Compare payload to detect actual changes
                    cleaned_original = remove_none_recursive(original_payload)
                    cleaned_new = remove_none_recursive(profile_payload)

                    if cleaned_original == cleaned_new:
                        logger.info(f"Forwarding Profile '{prefixed_name}' is already up-to-date. Skipping API update.")
                    else:
                        import json
                        logger.debug(f"Payload sent to update_forwarding_profile: {json.dumps(profile_payload)}")
                        _, response, err = client.zcc.forwarding_profile.update_forwarding_profile(**profile_payload)
                        if err:
                            resp_body = getattr(response, "_body", getattr(response, "text", None)) if response else None
                            err_detail = resp_body if resp_body else err
                            logger.warning(
                                f"Failed to update Forwarding Profile '{prefixed_name}'. Details: {err_detail}"
                            )
                        else:
                            logger.info(f"Forwarding Profile '{fp_cfg.search_name}' updated successfully to '{prefixed_name}'.")
                    results["forwarding_profiles"].append({"id": fwd_id, "name": prefixed_name})

    # 5. Process Application Profiles (Web Policies)
    if config.app_profiles:
        results["app_profiles"] = []
        logger.info("Starting Application Profiles configuration setup...")
        
        # Get existing application profiles
        profiles, _, err = client.zcc.application_profiles.get_application_profiles()
        if err:
            logger.error(f"Failed to list application profiles: {err}")
            raise Exception(f"Failed to list application profiles: {err}")

        # Build a mapping of posture profile name to ID from existing profiles
        posture_map = {}
        for p in profiles:
            zia_pc = getattr(p, "zia_posture_config", None)
            if zia_pc and isinstance(zia_pc, dict):
                pc_name = zia_pc.get("name")
                pc_id = zia_pc.get("id")
                if pc_name and pc_id:
                    posture_map[pc_name.lower()] = pc_id

        for platform, ap_list in config.app_profiles.items():
            for ap_cfg in ap_list:
                raw_name = ap_cfg.update.name
                prefixed_name = apply_prefix_and_truncate(raw_name, prefix, 50)
                logger.info(f"Processing Application Profile. Target Name: '{prefixed_name}' (Raw Name: '{raw_name}')")

                # Match against existing application profiles by raw/prefixed name AND device type (platform)
                found_ap = None
                search_names = {raw_name.lower(), prefixed_name.lower(), ap_cfg.search_name.lower()}
                
                target_plat = platform.lower()
                if target_plat == "mac":
                    target_plat = "macos"
                    
                for p in profiles:
                    p_dev = p.device_type.replace("DEVICE_TYPE_", "").lower() if isinstance(p.device_type, str) else ""
                    if p_dev == "mac":
                        p_dev = "macos"
                        
                    if p_dev == target_plat:
                        if p.name and p.name.lower() in search_names:
                            found_ap = p
                            break
                    
                if not found_ap:
                    logger.warning(f"Application Profile '{prefixed_name}' not found. Creating from blank base template.")
                    if dry_run:
                        logger.info(f"[DRY-RUN] Would create Application Profile '{prefixed_name}' via OneAPI.")
                        results["app_profiles"].append({"name": prefixed_name, "device_type": platform, "action": "create"})
                        continue
                    else:
                        # Dynamically resolve the forwarding profile ID from config before creation.
                        # The app profile config specifies a forwarding_profile_name (e.g. "POV - No Forwarding").
                        # processed_fwds was built earlier in this run and maps name → tenant ID.
                        create_fwd_id = 0
                        create_fwd_ref = ap_cfg.update.forwarding_profile_name if ap_cfg.update else None
                        if create_fwd_ref:
                            ref_names = {
                                create_fwd_ref.lower(),
                                apply_prefix_and_truncate(create_fwd_ref, prefix, 50).lower()
                            }
                            for ref_n in ref_names:
                                if ref_n in processed_fwds:
                                    create_fwd_id = int(processed_fwds[ref_n])
                                    logger.info(f"Resolved forwarding profile '{create_fwd_ref}' -> ID {create_fwd_id} for App Profile creation.")
                                    break
                            if not create_fwd_id:
                                # Fallback: search the tenant directly
                                fwd_list, _, _ = client.zcc.forwarding_profile.list_by_company()
                                for fp in (fwd_list or []):
                                    if fp.name and fp.name.lower() in ref_names:
                                        create_fwd_id = int(fp.id)
                                        logger.info(f"Resolved forwarding profile '{create_fwd_ref}' -> ID {create_fwd_id} (from tenant lookup) for App Profile creation.")
                                        break
                            if not create_fwd_id:
                                # Fallback 2: search for template profile on tenant
                                fwd_list, _, _ = client.zcc.forwarding_profile.list_by_company()
                                for fp in (fwd_list or []):
                                    if fp.name and fp.name.strip().lower() == fwd_template_name_lower:
                                        create_fwd_id = int(fp.id)
                                        logger.info(f"Resolved forwarding profile '{create_fwd_ref}' -> ID {create_fwd_id} (fallback to {fwd_template_name}) for App Profile creation.")
                                        break
                            if not create_fwd_id:
                                logger.warning(
                                    f"Forwarding profile '{create_fwd_ref}' could not be resolved to an ID. "
                                    f"Falling back to Default Forwarding Profile (ID 0) for App Profile '{prefixed_name}'."
                                )
                                create_fwd_id = 0

                        # Also resolve the actual name on the tenant so forwardingProfile label is correct
                        create_fwd_name = ""
                        fwd_list_for_name, _, _ = client.zcc.forwarding_profile.list_by_company()
                        for fp in (fwd_list_for_name or []):
                            if fp.id and int(fp.id) == create_fwd_id:
                                create_fwd_name = fp.name or ""
                                break

                        created_ok = False
                        if not dry_run:
                            created_ok = _create_app_profile_oneapi(client, prefixed_name, platform, logger, forwarding_profile_id=create_fwd_id, forwarding_profile_name=create_fwd_name)
                        
                        if not created_ok:
                            if dry_run:
                                logger.warning(f"[DRY-RUN] App Profile '{prefixed_name}' must be created manually.")
                                results["app_profiles"].append({"name": prefixed_name, "status": "Manual Creation Required"})
                                continue
                            else:
                                logger.warning(f"\n[ACTION REQUIRED] App Profiles cannot be reliably created via the API on this tenant.")
                                print(f"\nPlease log in to the Zscaler Client Connector (ZCC) Portal UI and manually create an App Profile with the EXACT name:")
                                print(f"   Name: {prefixed_name}")
                                print(f"   Platform: {platform}")
                                
                                while True:
                                    user_input = input(f"\nHave you created the App Profile '{prefixed_name}' in the UI? (y/n/exit): ").strip().lower()
                                    if user_input == 'exit':
                                        logger.error("User exited during App Profile creation step.")
                                        raise Exception("Script aborted by user.")
                                    elif user_input in ['y', 'yes']:
                                        print("Verifying App Profile exists...")
                                        v_profiles, _, v_err = client.zcc.web_policy.list_by_company(query_params={"device_type": platform.lower()})
                                        if not v_err and v_profiles:
                                            found_verify = next((p for p in v_profiles if getattr(p, 'name', '') and p.name.lower() == prefixed_name.lower()), None)
                                            if found_verify:
                                                logger.info(f"Verified! App Profile '{prefixed_name}' found with ID {found_verify.id}.")
                                                break
                                            else:
                                                logger.warning(f"Could not find App Profile '{prefixed_name}'. Please ensure the name matches exactly.")
                                        else:
                                            logger.warning("Failed to fetch app profiles for verification. Please try again.")
                                    else:
                                        print("Waiting for you to create it...")
                            
                        # Re-fetch profiles to get the newly created ID
                        profiles, _, err = client.zcc.web_policy.list_by_company(query_params={"device_type": platform.lower()})
                        if err:
                            raise Exception(f"Failed to list app profiles after creation: {err}")
                        
                        target_plat = platform.lower()
                        if target_plat == "mac":
                            target_plat = "macos"
                        
                        search_names = {raw_name.lower(), prefixed_name.lower(), ap_cfg.search_name.lower()}
                        for p in profiles:
                            p_dict = p.as_dict() if hasattr(p, "as_dict") else dict(p)
                            if p_dict.get("name", "").lower() in search_names:
                                found_ap = p
                                break
                                
                        if not found_ap:
                            raise Exception(f"Failed to find Application Profile '{prefixed_name}' after successful OneAPI creation.")
                
                if found_ap:
                    ap_id = found_ap.id
                    logger.info(f"Found Application Profile. ID: {ap_id}. Preparing update.")
                    
                    if str(ap_id) == "0":
                        logger.info("Application Profile with ID 0 is the read-only system default profile. Skipping update.")
                        results["app_profiles"].append({"id": ap_id, "name": prefixed_name, "status": "skipped_default"})
                        continue
                
                    # Resolve Forwarding Profile ID linkage
                    target_fwd_id = None
                    fwd_profile_ref_name = ap_cfg.update.forwarding_profile_name
                    if fwd_profile_ref_name:
                        # Look up by name in the mapped forwarding profiles
                        ref_names = {
                            fwd_profile_ref_name.lower(),
                            apply_prefix_and_truncate(fwd_profile_ref_name, prefix, 50).lower()
                        }
                        for ref_n in ref_names:
                            if ref_n in processed_fwds:
                                target_fwd_id = processed_fwds[ref_n]
                                break
                    
                        # Otherwise look it up on the target Zscaler tenant directly
                        if not target_fwd_id:
                            fwd_profiles, _, err = client.zcc.forwarding_profile.list_by_company()
                            if not err:
                                for fp in fwd_profiles:
                                    if fp.name and fp.name.lower() in ref_names:
                                        target_fwd_id = fp.id
                                        break
                        if not target_fwd_id:
                            fwd_profiles, _, err = client.zcc.forwarding_profile.list_by_company()
                            if not err:
                                for fp in fwd_profiles:
                                    if fp.name and fp.name.strip().lower() == fwd_template_name_lower:
                                        target_fwd_id = fp.id
                                        logger.info(f"Resolved Forwarding Profile '{fwd_profile_ref_name}' -> ID {target_fwd_id} (fallback to {fwd_template_name}) for App Profile update.")
                                        break
                        if not target_fwd_id:
                            logger.warning(f"Referenced Forwarding Profile '{fwd_profile_ref_name}' could not be resolved.")
                        else:
                            logger.info(f"Resolved Forwarding Profile '{fwd_profile_ref_name}' to ID: {target_fwd_id}")

                    # Prepare payload
                    update_params = ap_cfg.update.model_dump(exclude_none=True)
                    update_params["name"] = prefixed_name
                    update_params.pop("forwarding_profile_name", None)
                    update_params.pop("description", None)
                
                    policy_ext = update_params.pop("policy_extension", None)
                    if policy_ext and isinstance(policy_ext, dict):
                        for ext_k, ext_v in policy_ext.items():
                            if ext_v is not None:
                                update_params[ext_k] = ext_v

                    # Exclude read-only/invalid/blacklisted payload attributes
                    blacklisted_keys = [
                        'on_net_policy', 'onNetPolicy', 'install_ssl_certs', 'installSslCerts',
                        'notification_template_contract', 'policy_token', 'app_services',
                        'users', 'user_ids', 'userIds', 
                        'groups', 'group_ids', 'groupIds', 
                        'departments', 'department_ids', 'departmentIds',
                        'bypass_custom_apps', 'bypassCustomApps', 
                        'bypass_custom_app_ids', 'bypassCustomAppIds',
                        'policyId', 'policy_id', 'deviceTypeName', 
                        'lastModification', 'last_modified_by', 'last_modified_time', 
                        'creation_time', 'created_by', 'company_id', 'companyId',
                        'ziaPostureConfig', 'zia_posture_config', 'ziaPostureConfigId', 'zia_posture_config_id'
                    ]
                    for k in blacklisted_keys:
                        update_params.pop(k, None)
                                
                    # Convert to camel case to avoid "Blacklisted parameters" errors from snake_case keys
                    update_params = to_camel_wire_dict(update_params)
                
                    # ZCC API uses policyId in PATCH body and forwardingProfileId
                    update_params["policyId"] = ap_id
                    if target_fwd_id:
                        update_params["forwardingProfileId"] = target_fwd_id

                    # Resolve ZIA posture config ID if posture_profile_name is present
                    posture_prof_name = update_params.pop("postureProfileName", None) or update_params.pop("posture_profile_name", None)
                    if posture_prof_name:
                        target_posture_id = posture_map.get(posture_prof_name.lower())
                        if not target_posture_id:
                            # Fallback check on current profile
                            curr_pc = getattr(found_ap, "zia_posture_config", None)
                            if curr_pc and isinstance(curr_pc, dict) and curr_pc.get("name", "").lower() == posture_prof_name.lower():
                                target_posture_id = curr_pc.get("id")
                        
                        if target_posture_id:
                            # We must pass the field name EXACTLY as ziaPostureConfigId in camelCase to client
                            update_params["ziaPostureConfigId"] = target_posture_id
                            logger.info(f"Resolved posture profile '{posture_prof_name}' to ID: {target_posture_id}")
                        else:
                            logger.warning(f"Referenced posture profile '{posture_prof_name}' could not be resolved to an ID on the tenant.")
                
                    # Ensure deviceType is normalized and set to existing value if not provided
                    dev_type = update_params.get("deviceType") or update_params.get("device_type")
                    if not dev_type:
                        if hasattr(found_ap, "device_type") and found_ap.device_type:
                            dev_type = found_ap.device_type
                    
                    if dev_type:
                        if isinstance(dev_type, str):
                            dev_type = dev_type.replace("DEVICE_TYPE_", "").lower()
                            if dev_type == "mac":
                                dev_type = "macos"
                        # Keep it as device_type so the SDK's zcc_param_mapper can convert it correctly
                        update_params.pop("deviceType", None)
                        update_params["device_type"] = dev_type

                    if dry_run:
                        update_params_resolved = resolve_pac_urls_recursive(update_params, target_pacs)
                        logger.info(f"[DRY-RUN] Would update ZCC Application Profile '{prefixed_name}' (ID: {ap_id})")
                        results["app_profiles"].append({"id": ap_id, "name": prefixed_name})
                    else:
                        update_params = resolve_pac_urls_recursive(update_params, target_pacs)
                        # Clean None values recursively
                        update_params = remove_none_recursive(update_params)

                        # Build a comparable snapshot of the existing profile's relevant fields
                        import copy
                        existing_ap_dict = to_camel_wire_dict(found_ap)
                        existing_ap_cleaned = clean_web_policy_payload_recursive(
                            remove_none_recursive(copy.deepcopy(existing_ap_dict))
                        )

                        # Build a comparable snapshot of the new payload (excluding policyId which is always added)
                        new_params_for_compare = {k: v for k, v in update_params.items() if k != "policyId"}
                        new_params_cleaned = clean_web_policy_payload_recursive(
                            remove_none_recursive(copy.deepcopy(new_params_for_compare))
                        )

                        # Check whether each key we intend to update matches the existing value
                        needs_update = any(
                            existing_ap_cleaned.get(k) != v
                            for k, v in new_params_cleaned.items()
                        )

                        if not needs_update:
                            logger.info(f"Application Profile '{prefixed_name}' is already up-to-date. Skipping API update.")
                            results["app_profiles"].append({"id": ap_id, "name": prefixed_name, "action": "skipped_no_change"})
                        else:
                            _, _, err = client.zcc.application_profiles.update_application_profile(profile_id=ap_id, **update_params)
                            if err:
                                if "NOTIFICATION_TEMPLATE_NOT_PRESENT" in str(err) and "notificationTemplateId" in update_params:
                                    logger.warning(
                                        f"Notification Template ID '{update_params['notificationTemplateId']}' is not present on the target tenant. "
                                        f"Retrying Application Profile '{prefixed_name}' update without this template linkage."
                                    )
                                    update_params.pop("notificationTemplateId", None)
                                    _, _, err = client.zcc.application_profiles.update_application_profile(profile_id=ap_id, **update_params)
                                if err:
                                    if "INTERNAL_SERVER_ERROR" in str(err):
                                        logger.error(
                                            f"[ACTION REQUIRED] The ZCC Public API returned a 500 Internal Server Error while attempting to update App Profile '{prefixed_name}'. "
                                            "This is a known Zscaler backend bug on certain tenants where valid update payloads cause the API to crash. "
                                            "You must manually verify or configure this App Profile in the ZCC Portal UI."
                                        )
                                        results["app_profiles"].append({"id": ap_id, "name": prefixed_name, "action": "manual_update_required_due_to_api_bug"})
                                    else:
                                        logger.error(f"Failed to update Application Profile: {err}")
                                        raise Exception(f"Failed to update Application Profile: {err}")
                                else:
                                    logger.info(f"Application Profile '{ap_cfg.search_name}' updated successfully to '{prefixed_name}'.")
                                    results["app_profiles"].append({"id": ap_id, "name": prefixed_name, "action": "update"})
                    
    return results
