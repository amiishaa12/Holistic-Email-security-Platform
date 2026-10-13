from email_analyzer.url_analyzer import analyze_urls


# --------------------------------
# Test URLs
# --------------------------------

test_urls = [
    "http://192.168.1.10/login",
    "https://example.com@malicious.example/login",
    "https://login.account.verify.security.example.com",
    "https://xn--example-dma.com",
    "https://example.com/login%2Fverify",
    "https://example.com:8080/login",
]


# --------------------------------
# Analyze URLs
# --------------------------------

results = analyze_urls(test_urls)


# --------------------------------
# Display Results
# --------------------------------

for result in results:

    print("\n========================================")
    print("URL:", result["url"])
    print("Valid:", result["valid"])
    print("Scheme:", result["scheme"])
    print("Hostname:", result["hostname"])
    print("Path:", result["path"])

    # --------------------------------
    # DNS Information
    # --------------------------------

    print("\nDNS Information:")

    domain_info = result["domain_info"]

    if domain_info:

        print("Domain Exists:", domain_info["exists"])

        print("A Records:")

        for record in domain_info["a_records"]:
            print("  -", record)

        print("AAAA Records:")

        for record in domain_info["aaaa_records"]:
            print("  -", record)

        print("MX Records:")

        for record in domain_info["mx_records"]:
            print("  -", record)

        print("TXT Records:")

        for record in domain_info["txt_records"]:
            print("  -", record)

    else:

        print("No DNS information available.")

    # --------------------------------
    # Redirect Information
    # --------------------------------

    print("\nRedirect Information:")

    redirect_info = result["redirect_info"]

    print("Redirected:", redirect_info["redirected"])
    print("Redirect Count:", redirect_info["redirect_count"])
    print("Final URL:", redirect_info["final_url"])

    if redirect_info["error"]:

        print("Redirect Error:", redirect_info["error"])

    # --------------------------------
    # Findings
    # --------------------------------

    print("\nFindings:")

    for finding in result["findings"]:

        print(
            f"  - {finding['message']} "
            f"[{finding['severity']}]"
        )