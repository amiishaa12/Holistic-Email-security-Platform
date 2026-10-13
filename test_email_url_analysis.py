from email_analyzer.parser import parse_email
from email_analyzer.url_analyzer import analyze_urls


# --------------------------------
# Parse the email
# --------------------------------

email = parse_email(
    "samples/test_email_with_attachment.eml"
)


# --------------------------------
# Get URLs from the parser
# --------------------------------

urls = email["urls"]


# --------------------------------
# Analyze URLs
# --------------------------------

results = analyze_urls(urls)


print("========== EMAIL URL ANALYSIS ==========")

print("Subject:", email["subject"])

print("\nURLs found:")

for url in urls:
    print("-", url)


print("\n========== SECURITY FINDINGS ==========")

for result in results:

    print("\nURL:", result["url"])

    for finding in result["findings"]:

        print(
            f"- {finding['message']} "
            f"[{finding['severity']}]"
        )