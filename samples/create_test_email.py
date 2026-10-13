from email.message import EmailMessage
from pathlib import Path
import base64


message = EmailMessage()

message["From"] = "Netflix Support <support@example.com>"
message["To"] = "testuser@gmail.com"
message["Subject"] = "Urgent: Verify Your Account"

message.set_content(
    """
Dear Customer,

Your account requires verification.

Please visit:
https://example.com/login

Thank you,
Netflix Support
"""
)


# Create a small dummy PDF-like file for testing
attachment_content = b"%PDF-1.4\nDummy test PDF file for email security testing."


message.add_attachment(
    attachment_content,
    maintype="application",
    subtype="pdf",
    filename="invoice.pdf"
)


output_file = Path("samples/test_email_with_attachment.eml")

output_file.write_bytes(message.as_bytes())

print(f"Test email created: {output_file}")