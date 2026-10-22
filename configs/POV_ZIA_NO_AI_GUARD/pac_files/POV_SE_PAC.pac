// Strict Enforcement PAC for ZCC + Z-Tunnel 2.0

function FindProxyForURL(url, host) {
  host = host.toLowerCase();

  // Block plain hostnames and RFC 1918 unless explicitly allowed
  if (isPlainHostName(host)) return "PROXY 127.0.0.1:9000";
  var ip = dnsResolve(host);
  if (ip) {
    if (isInNet(ip, "10.0.0.0", "255.0.0.0")) return "PROXY 127.0.0.1:9000";
    if (isInNet(ip, "172.16.0.0", "255.240.0.0")) return "PROXY 127.0.0.1:9000";
    if (isInNet(ip, "192.168.0.0", "255.255.0.0")) return "PROXY 127.0.0.1:9000";
    // Avoid false DIRECT via CGNAT
    if (isInNet(ip, "100.64.0.0", "255.255.0.0")) return "PROXY 127.0.0.1:9000";
  }

  // Zscaler trust/health/login (keep proxied for visibility)
  var zscalerInfra = [
    "login.zscloud.net", 
    "login.zscalerbeta.net", 
    "login.zscalertwo.net", 
    "login.zscalerthree.net",
    "trust.zscaler.net", 
    "trust.zscalertwo.net", 
    "trust.zscalerthree.net",
    "ips.zscaler.net", 
    "ips.zscalertwo.net", 
    "ips.zscalerthree.net",
    "api.zsapi.net", 
    "api.zsapi.ca"
  ];
  for (var i = 0; i < zscalerInfra.length; i++) {
    if (host == zscalerInfra[i] || dnsDomainIs(host, "." + zscalerInfra[i])) {
      return "PROXY 127.0.0.1:9000";
    }
  }

  // Microsoft Entra ID / Intune / OOBE allowlist (expand as needed)
  var MS_AUTH = [
    "login.microsoftonline.com", 
    "device.login.microsoftonline.com",
    "login.windows.net", 
    "login.microsoft.com", 
    "account.live.com", 
    "login.live.com",
    "enterpriseregistration.windows.net", 
    "certauth.enterpriseregistration.windows.net",
    "aadcdn.msftauth.net", 
    "aadcdn.msauth.net", 
    "msauth.net", 
    "msftauth.net",
    "graph.microsoft.com", 
    "graph.windows.net"
  ];
  
  var INTUNE = [
    "manage.microsoft.com", 
    "enrollment.manage.microsoft.com", 
    "intune.microsoft.com",
    "device.management.microsoft.com", 
    "microsoft.com", 
    "microsoftonline.com"
  ];
  
  var OOBE_CDN = [
    "azureedge.net", 
    "akamaiedge.net", 
    "edgesuite.net", 
    "akamaized.net"
  ];
  
  var WINDOWS_UPDATE = [
    "windowsupdate.com", 
    "update.microsoft.com"
  ];

  function inList(h, list) {
    for (var j = 0; j < list.length; j++) {
      var d = list[j];
      if (h === d || dnsDomainIs(h, "." + d)) return true;
    }
    return false;
  }

  if (inList(host, MS_AUTH) || 
      inList(host, INTUNE) || 
      inList(host, OOBE_CDN) || 
      inList(host, WINDOWS_UPDATE)) {
      
    // Allowed web → listener proxy → Z-Tunnel 2.0 → ZIA (logs, CA edges via policy)
    return "PROXY 127.0.0.1:9000";
  }

  // Optional: tenant vanity-specific endpoints (replace YOUR_VANITY)
  var tenant = "zdemo-ca";
  if (dnsDomainIs(host, tenant + ".zslogin.net") || dnsDomainIs(host, tenant + ".zdxcloud.net")) {
    return "PROXY 127.0.0.1:9000";
  }

}