from urllib.parse import urlsplit
import ipaddress
import requests

from email_analyzer.domain_checker import get_dns_records


def is_ip_address(hostname):
    """
    Check whether the hostname is an IPv4 or IPv6 address.
    """

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False

def analyze_redirects(url):
    """
    Check whether a URL redirects to another URL.
    """

    result = {
        "redirected": False,
        "redirect_count": 0,
        "redirect_chain": [],
        "final_url": url,
        "error": None
    }

    try:

        response = requests.get(
            url,
            allow_redirects=True,
            timeout=5,
            stream=True
        )

        # --------------------------------
        # Record redirect history
        # --------------------------------

        if response.history:

            result["redirected"] = True

            for redirect in response.history:

                result["redirect_chain"].append(
                    {
                        "url": redirect.url,
                        "status_code": redirect.status_code,
                        "location": redirect.headers.get(
                            "Location"
                        )
                    }
                )

            result["redirect_count"] = len(
                response.history
            )

        # --------------------------------
        # Final destination
        # --------------------------------

        result["final_url"] = response.url

        # Close connection without downloading
        # the response body.
        response.close()

    except requests.RequestException as error:

        result["error"] = str(error)

    return result

def analyze_url(url):
    """
    Analyze one URL and return security-related findings.
    """

    findings = []

    # --------------------------------
    # Parse URL
    # --------------------------------

    try:
        parsed = urlsplit(url)

    except ValueError:

        return {
            "url": url,
            "valid": False,
            "findings": [
                {
                    "type": "invalid_url",
                    "message": "Invalid URL format",
                    "severity": "high"
                }
            ]
        }

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    path = parsed.path
    query = parsed.query

    # --------------------------------
    # Domain / DNS check
    # --------------------------------

    domain_info = None

    if hostname and not is_ip_address(hostname):

        domain_info = get_dns_records(hostname)

        # --------------------------------
        # Check if domain resolves
        # --------------------------------

        if domain_info and not domain_info["exists"]:

            findings.append({
                "type": "domain_not_resolved",
                "message": "Domain could not be resolved through DNS",
                "severity": "medium"
            })

    # --------------------------------
    # Basic information
    # --------------------------------

        # --------------------------------
    # Redirect analysis
    # --------------------------------

    redirect_info = analyze_redirects(url)

    if redirect_info["redirected"]:

        findings.append({
            "type": "url_redirect",
            "message": (
                f"URL redirects "
                f"{redirect_info['redirect_count']} time(s)"
            ),
            "severity": "low"
        })

    if redirect_info["redirect_count"] >= 3:

        findings.append({
            "type": "multiple_redirects",
            "message": (
                "URL uses multiple redirects"
            ),
            "severity": "medium"
        })

    result = {
        "url": url,
        "valid": True,
        "scheme": scheme,
        "hostname": hostname,
        "path": path,
        "query": query,
        "domain_info": domain_info,
        "redirect_info": redirect_info,
        "findings": findings
    }

    # --------------------------------
    # Check 1: HTTP / HTTPS
    # --------------------------------

    if scheme == "http":

        findings.append({
            "type": "insecure_protocol",
            "message": "URL uses HTTP instead of HTTPS",
            "severity": "low"
        })

    elif scheme == "https":

        findings.append({
            "type": "secure_protocol",
            "message": "URL uses HTTPS",
            "severity": "info"
        })

    else:

        findings.append({
            "type": "unusual_protocol",
            "message": f"URL uses unusual protocol: {scheme}",
            "severity": "medium"
        })

    # --------------------------------
    # Check 2: IP address
    # --------------------------------

    if is_ip_address(hostname):

        findings.append({
            "type": "ip_address",
            "message": "URL uses an IP address instead of a domain name",
            "severity": "medium"
        })

    # --------------------------------
    # Check 3: @ symbol
    # --------------------------------

    if "@" in url:

        findings.append({
            "type": "at_symbol",
            "message": "URL contains an @ symbol",
            "severity": "medium"
        })

    # --------------------------------
    # Check 4: URL length
    # --------------------------------

    if len(url) > 200:

        findings.append({
            "type": "long_url",
            "message": "URL is unusually long",
            "severity": "low"
        })

    # --------------------------------
    # Check 5: Suspicious keywords
    # --------------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "account",
        "password",
        "update",
        "secure",
        "signin",
        "confirm"
    ]

    url_lower = url.lower()

    found_keywords = []

    for keyword in suspicious_keywords:

        if keyword in url_lower:

            found_keywords.append(keyword)

    if found_keywords:

        findings.append({
            "type": "suspicious_keywords",
            "message": "URL contains security-related keywords",
            "keywords": found_keywords,
            "severity": "low"
        })

    # --------------------------------
    # Check 6: Too many subdomains
    # --------------------------------

    if hostname:

        domain_parts = hostname.split(".")

        if len(domain_parts) >= 5:

            findings.append({
                "type": "many_subdomains",
                "message": "URL contains an unusually large number of subdomains",
                "severity": "medium"
            })

    # --------------------------------
    # Check 7: Punycode / IDN
    # --------------------------------

    if hostname and hostname.lower().startswith("xn--"):

        findings.append({
            "type": "punycode",
            "message": "Domain uses Punycode/IDN encoding",
            "severity": "medium"
        })

    # --------------------------------
    # Check 8: URL encoding
    # --------------------------------

    if "%" in url:

        findings.append({
            "type": "url_encoding",
            "message": "URL contains percent-encoded characters",
            "severity": "low"
        })

    # --------------------------------
    # Check 9: Embedded username/password
    # --------------------------------

    if parsed.username or parsed.password:

        findings.append({
            "type": "embedded_credentials",
            "message": "URL contains embedded username or password information",
            "severity": "medium"
        })

    # --------------------------------
    # Check 10: Non-standard port
    # --------------------------------

    try:

        if parsed.port is not None:

            if parsed.port not in [80, 443]:

                findings.append({
                    "type": "non_standard_port",
                    "message": f"URL uses non-standard port {parsed.port}",
                    "severity": "medium"
                })

    except ValueError:

        findings.append({
            "type": "invalid_port",
            "message": "URL contains an invalid port",
            "severity": "medium"
        })

    # --------------------------------
    # Return result
    # --------------------------------

    return result


def analyze_urls(urls):
    """
    Analyze multiple URLs.
    """

    results = []

    for url in urls:

        results.append(
            analyze_url(url)
        )

    return results