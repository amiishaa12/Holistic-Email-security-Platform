from email_analyzer.domain_checker import get_dns_records


domain = "example.com"


result = get_dns_records(domain)


print("========== DOMAIN ANALYSIS ==========")

print("Domain:", result["domain"])

print("Exists:", result["exists"])


print("\nA Records:")

for record in result["a_records"]:
    print("-", record)


print("\nAAAA Records:")

for record in result["aaaa_records"]:
    print("-", record)


print("\nMX Records:")

for record in result["mx_records"]:
    print("-", record)


print("\nTXT Records:")

for record in result["txt_records"]:
    print("-", record)


print("\nErrors:")

for error in result["errors"]:
    print("-", error)