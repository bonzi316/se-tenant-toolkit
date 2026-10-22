// Check if url or host match wildcard domain or exact domain
function isWildcard(url, host, pattern) {
    if (dnsDomainIs(host, "." + pattern) || dnsDomainIs(url, "://" + pattern))
        return true;
    else
        return false;
}

function FindProxyForURL(url, host) {

    var h = (host || "").toLowerCase();
    var u = (url || "").toLowerCase();
    var privateIP = /^(0|10|127|192\.168|172\.1[6789]|172\.2[0-9]|172\.3[01]|169\.254|192\.88\.99)\.[0-9.]+$/;
    var resolved_ip = dnsResolve(host);
    var country = "${COUNTRY}";

    /* Don't send non-FQDN or private IP auths to us */
    if (isPlainHostName(host) || isInNet(resolved_ip, "192.0.2.0", "255.255.255.0"))
        return "DIRECT";

    /* test with ZPA */
    if (isInNet(resolved_ip, "172.16.100.1", "255.255.255.255") ||
        isInNet(resolved_ip, "172.16.99.1", "255.255.255.255")
    )
        return "DIRECT";


    // Go direct for queries about Zscaler infrastructure status
    var trust = /^(trust|ips)\.(zscaler|zscalerone|zscalertwo|zscalerthree|zsdemo|zscalergov|zscloud|zsfalcon|zdxcloud|zdxpreview|zdxbeta|zspreview|zsdevel|zsbetagov|zscalerten|zdxten|zdxdevel|zdxgov|zsqa|zscaleranalytics|zsprotect|zdxqa|zscalerrisk|zscalergscm|zscalermscm|zscascm|ztwcloud|zsca|zsqatwo|ztwdevel|ztwgov|ztwpreview|ztwbeta|zscalerfour|zscalerfive|zscalerbetatwo|zsdk14|zsdkcloud|zscmeleven|zscalereleven|zdxeleven|fcceleven|zscaleranalyticspreview|zscalerriskpreview|zscaleranalyticsbeta|zscalerriskbeta|zscaleranalyticsgov|zscalerriskgov|zscaleranalyticsten|zscalerriskten|zsst1|zsst2|zsst3|zsst4|zsst5|zsuxp|ztwqa|zsystest|zsenvaa)\.(com|net)$/;
    var iam = /^.*\.(zslogin|zsloginbeta|zslogindemo|zsloginalpha).net$/;

    if (trust.test(h) || iam.test(h) || /^trust.zscaler.us$/.test(h))
        return "DIRECT";


    /* Internal DNS servers */
    if (isInNet(resolved_ip, "100.64.0.0", "255.255.0.0"))
        return "DIRECT";


    //custom domain bypass
    // Google Meet bypass
    // https://knowledge.workspace.google.com/admin/meet/prepare-your-network-for-meet-meetings-and-live-streams?hl=en
    if (
        isWildcard(host, ".meet.google.com") ||
        isWildcard(host, ".stream.google.com")
    )
        return "DIRECT";

    //This will match any subdomain of ipchiken.com or ident.me
    if (isWildcard(u, h, "ipchicken.com") ||
        isWildcard(u, h, "ident.me")
    )
        return "DIRECT";

    return "PROXY ${GATEWAY_FX}:80; PROXY ${SECONDARY_GATEWAY_FX}:80; DIRECT";
}