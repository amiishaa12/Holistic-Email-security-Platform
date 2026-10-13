import dns.resolver


def get_dns_records(domain):
    """
    Retrieve basic DNS information for a domain.
    """

    result = {
        "domain": domain,
        "exists": False,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "txt_records": [],
        "errors": []
    }

    # --------------------------------
    # A Record
    # --------------------------------

    try:

        answers = dns.resolver.resolve(domain, "A")

        for answer in answers:
            result["a_records"].append(str(answer))

        result["exists"] = True

    except Exception as error:

        result["errors"].append(
            f"A record lookup failed: {error}"
        )

    # --------------------------------
    # AAAA Record
    # --------------------------------

    try:

        answers = dns.resolver.resolve(domain, "AAAA")

        for answer in answers:
            result["aaaa_records"].append(str(answer))

        result["exists"] = True

    except Exception as error:

        result["errors"].append(
            f"AAAA record lookup failed: {error}"
        )

    # --------------------------------
    # MX Record
    # --------------------------------

    try:

        answers = dns.resolver.resolve(domain, "MX")

        for answer in answers:
            result["mx_records"].append(
                str(answer.exchange).rstrip(".")
            )

    except Exception as error:

        result["errors"].append(
            f"MX record lookup failed: {error}"
        )

    # --------------------------------
    # TXT Record
    # --------------------------------

    try:

        answers = dns.resolver.resolve(domain, "TXT")

        for answer in answers:

            txt_value = "".join(
                part.decode("utf-8", errors="ignore")
                if isinstance(part, bytes)
                else part
                for part in answer.strings
            )

            result["txt_records"].append(txt_value)

    except Exception as error:

        result["errors"].append(
            f"TXT record lookup failed: {error}"
        )

    return result