from email import policy
from email.parser import BytesParser
import re


def extract_urls(text):
    """
    Extract URLs from email text.
    """

    if not text:
        return []

    url_pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(url_pattern, text)

    # Remove common punctuation from the end of URLs
    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,;:!?)]}")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


def parse_email(file_path):
    """
    Reads an .eml file and extracts email information.
    """

    with open(file_path, "rb") as file:
        email_message = BytesParser(
            policy=policy.default
        ).parse(file)

    # --------------------------------
    # Basic email information
    # --------------------------------

    sender = email_message.get("From")
    receiver = email_message.get("To")
    subject = email_message.get("Subject")
    date = email_message.get("Date")

    # --------------------------------
    # Body
    # --------------------------------

    body = ""

    if email_message.is_multipart():

        for part in email_message.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":
                body = part.get_content()
                break

            elif content_type == "text/html" and not body:
                body = part.get_content()

    else:
        body = email_message.get_content()

    # --------------------------------
    # Extract URLs
    # --------------------------------

    urls = extract_urls(body)

    # --------------------------------
    # Extract attachments
    # --------------------------------

    attachments = []

    for part in email_message.walk():

        if part.get_content_disposition() == "attachment":

            filename = part.get_filename()

            attachment_data = {
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(part.get_payload(decode=True) or b""),
                "data": part.get_payload(decode=True)
            }

            attachments.append(attachment_data)

    # --------------------------------
    # Return all information
    # --------------------------------

    return {
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "date": date,
        "body": body,
        "urls": urls,
        "attachments": attachments,
        "headers": dict(email_message.items())
    }