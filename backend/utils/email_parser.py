import re
from email import message_from_string
from email.policy import default as default_policy
from urllib.parse import urlparse
import base64
from bs4 import BeautifulSoup


def parse_email(raw_email: str) -> dict:
    msg = message_from_string(raw_email, policy=default_policy)
    return {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "received_headers": _get_received_headers(msg),
        "headers": dict(msg.items()),
    }


def extract_sender_ip(headers: dict) -> str | None:
    received = headers.get("received_headers", [])
    for line in received:
        match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', line)
        if match:
            return match.group(1)
    return None


def extract_sender_domain(sender_email: str) -> str:
    match = re.search(r'@([\w\.-]+)', sender_email)
    return match.group(1).lower() if match else ""


def extract_links(body: str) -> list[str]:
    links = re.findall(r'href=["\']?(https?://[^\s"\'<>]+)', body)
    soup = BeautifulSoup(body, "html.parser")
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        if href.startswith("http") and href not in links:
            links.append(href)
    text_links = re.findall(r'(https?://[^\s<>"]+)', body)
    for link in text_links:
        if link not in links:
            links.append(link)
    return links


def extract_attachments(raw_email: str) -> list[dict]:
    msg = message_from_string(raw_email, policy=default_policy)
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            content_type = part.get_content_type()
            size = len(part.get_payload(decode=True) or b"")
            attachments.append({
                "filename": filename or "unknown",
                "content_type": content_type,
                "size": size,
            })
    return attachments


def decode_encoded_subject(subject: str) -> str:
    if subject and ("=?" in subject):
        from email.header import decode_header
        decoded_parts = decode_header(subject)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                result.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                result.append(part)
        return " ".join(result)
    return subject


def extract_display_name(sender: str) -> str:
    match = re.match(r'^"?([^"<]+)"?\s*<', sender)
    return match.group(1).strip() if match else ""


def check_display_name_spoofing(sender: str) -> dict:
    display_name = extract_display_name(sender)
    email_match = re.search(r'<([^>]+)>', sender)
    email_addr = email_match.group(1) if email_match else sender

    issues = []

    if display_name and "@" in display_name:
        name_email = extract_sender_domain(display_name)
        actual_domain = extract_sender_domain(email_addr)
        if name_email and actual_domain and name_email != actual_domain:
            issues.append(f"Display name contains different domain: {name_email} vs {actual_domain}")

    suspicious_words = ["admin", "support", "helpdesk", "security", "bank", "service", "noreply", "no-reply"]
    if display_name:
        for word in suspicious_words:
            if word.lower() in display_name.lower() and word.lower() not in email_addr.lower():
                issues.append(f"Display name impersonates '{word}' but email does not match")

    return {"has_issues": len(issues) > 0, "issues": issues, "display_name": display_name}


def check_url_shorteners(links: list[str]) -> list[dict]:
    shortener_domains = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at",
    ]
    results = []
    for link in links:
        parsed = urlparse(link)
        domain = parsed.netloc.lower()
        is_shortener = any(s in domain for s in shortener_domains)
        results.append({
            "url": link,
            "domain": domain,
            "is_shortener": is_shortener,
        })
    return results


def extract_email_text(body: str) -> str:
    soup = BeautifulSoup(body, "html.parser")
    for script in soup(["script", "style"]):
        script.decompose()
    text = soup.get_text(separator=" ", strip=True)
    return text


def _get_received_headers(msg) -> list[str]:
    received = []
    for key, value in msg.items():
        if key.lower() == "received":
            received.append(value)
    return received
