import socket
import ssl
from datetime import datetime, timezone


def _certificate_value(certificate: dict, key: str) -> str | None:
    values = certificate.get(key, ())
    if not values:
        return None
    return values[0][0][1]


def _parse_certificate_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def analyze_ssl(hostname: str, port: int | None = None, timeout_seconds: float = 5) -> dict:
    result = {
        "ssl_available": False,
        "ssl_valid": False,
        "certificate_subject": None,
        "certificate_issuer": None,
        "valid_from": None,
        "valid_until": None,
        "days_until_expiry": None,
        "error": None,
    }
    target_port = port or 443
    try:
        with socket.create_connection((hostname, target_port), timeout=timeout_seconds) as raw:
            result["ssl_available"] = True
            context = ssl.create_default_context()
            try:
                with context.wrap_socket(raw, server_hostname=hostname) as connection:
                    certificate = connection.getpeercert()
                    result["ssl_valid"] = True
            except ssl.SSLCertVerificationError as error:
                result["error"] = "Certificate verification failed."
                raw.close()
                with socket.create_connection((hostname, target_port), timeout=timeout_seconds) as retry:
                    with ssl._create_unverified_context().wrap_socket(
                        retry, server_hostname=hostname
                    ) as connection:
                        certificate = connection.getpeercert()
            except ssl.SSLError as error:
                result["error"] = str(error)
                return result
    except (OSError, TimeoutError) as error:
        result["error"] = str(error)
        return result

    valid_from = _parse_certificate_date(certificate.get("notBefore"))
    valid_until = _parse_certificate_date(certificate.get("notAfter"))
    now = datetime.now(timezone.utc)
    result.update(
        {
            "certificate_subject": _certificate_value(certificate, "subject"),
            "certificate_issuer": _certificate_value(certificate, "issuer"),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "days_until_expiry": (valid_until - now).days if valid_until else None,
        }
    )
    return result
