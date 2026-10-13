from email_analyzer.parser import parse_email


email = parse_email(
    "samples/test_email_with_attachment.eml"
)


print("========== EMAIL ANALYSIS ==========")

print("Sender:", email["sender"])
print("Receiver:", email["receiver"])
print("Subject:", email["subject"])
print("Date:", email["date"])


print("\n========== URLS ==========")

for url in email["urls"]:
    print(url)


print("\n========== ATTACHMENTS ==========")

for attachment in email["attachments"]:

    print("Filename:", attachment["filename"])
    print("Content Type:", attachment["content_type"])
    print("Size:", attachment["size"], "bytes")


print("\n========== HEADERS ==========")

for name, value in email["headers"].items():
    print(f"{name}: {value}")