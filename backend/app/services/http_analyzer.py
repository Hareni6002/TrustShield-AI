from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from app.utils.security import PrivateNetworkError, resolve_public_host


PAYMENT_KEYWORDS = {"card", "credit card", "debit card", "cvv", "checkout", "payment", "upi", "wallet"}
MAX_REDIRECTS = 5
MAX_HTML_BYTES = 1_000_000


def _empty_result() -> dict:
    return {
        "http_status": None,
        "final_url": None,
        "redirect_count": 0,
        "redirect_chain": [],
        "page_title": None,
        "meta_description": None,
        "has_password_field": False,
        "has_login_form": False,
        "has_payment_keywords": False,
        "external_links": 0,
        "internal_links": 0,
        "error": None,
    }


def _analyze_html(content: bytes, final_url: str) -> dict:
    soup = BeautifulSoup(content, "html.parser")
    text = soup.get_text(" ", strip=True).lower()
    host = (urlsplit(final_url).hostname or "").lower()
    links = [tag.get("href") for tag in soup.find_all("a") if tag.get("href")]
    internal = 0
    external = 0
    for link in links:
        link_host = (urlsplit(urljoin(final_url, link)).hostname or "").lower()
        if link_host and link_host == host:
            internal += 1
        elif link_host:
            external += 1
    description = soup.find("meta", attrs={"name": lambda value: value and value.lower() == "description"})
    has_password = bool(soup.find("input", attrs={"type": lambda value: value and value.lower() == "password"}))
    forms = soup.find_all("form")
    has_login_form = any(
        any(term in form.get_text(" ", strip=True).lower() for term in ("login", "sign in", "signin"))
        or form.find("input", attrs={"type": "password"})
        for form in forms
    )
    return {
        "page_title": soup.title.get_text(strip=True) if soup.title else None,
        "meta_description": description.get("content") if description else None,
        "has_password_field": has_password,
        "has_login_form": has_login_form,
        "has_payment_keywords": any(keyword in text for keyword in PAYMENT_KEYWORDS),
        "external_links": external,
        "internal_links": internal,
    }


def analyze_http(normalized_url: str) -> dict:
    result = _empty_result()
    current_url = normalized_url
    result["redirect_chain"] = [current_url]
    headers = {"User-Agent": "TrustShieldAI/0.1 (security analysis; no JavaScript)"}
    try:
        with httpx.Client(timeout=8, follow_redirects=False, headers=headers) as client:
            for _ in range(MAX_REDIRECTS + 1):
                parts = urlsplit(current_url)
                resolve_public_host(parts.hostname or "")
                with client.stream("GET", current_url) as response:
                    result["http_status"] = response.status_code
                    location = response.headers.get("location")
                    if location and response.status_code in {301, 302, 303, 307, 308}:
                        if result["redirect_count"] >= MAX_REDIRECTS:
                            result["error"] = "Maximum redirect limit reached."
                            break
                        next_url = urljoin(current_url, location)
                        next_parts = urlsplit(next_url)
                        if next_parts.scheme not in {"http", "https"} or not next_parts.hostname:
                            result["error"] = "Redirect target uses an unsupported URL scheme."
                            break
                        resolve_public_host(next_parts.hostname)
                        current_url = next_url
                        result["redirect_count"] += 1
                        result["redirect_chain"].append(current_url)
                        continue

                    result["final_url"] = current_url
                    content_type = response.headers.get("content-type", "").lower()
                    content_length = int(response.headers.get("content-length", "0") or 0)
                    if "text/html" in content_type and content_length <= MAX_HTML_BYTES:
                        chunks = []
                        size = 0
                        for chunk in response.iter_bytes():
                            remaining = MAX_HTML_BYTES - size
                            if remaining <= 0:
                                break
                            chunks.append(chunk[:remaining])
                            size += len(chunks[-1])
                        body = b"".join(chunks)
                        result.update(_analyze_html(body, current_url))
                    break
    except PrivateNetworkError:
        raise
    except (httpx.HTTPError, ValueError, OSError) as error:
        result["error"] = str(error)
        result["final_url"] = current_url
    return result
