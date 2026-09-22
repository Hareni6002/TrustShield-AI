import ipaddress
import socket


BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


class PrivateNetworkError(ValueError):
    pass


def is_public_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def resolve_public_host(hostname: str) -> list[str]:
    normalized = hostname.rstrip(".").lower()
    if normalized in BLOCKED_HOSTNAMES or normalized.endswith(".localhost"):
        raise PrivateNetworkError("Local or private network URLs cannot be scanned.")

    try:
        literal = ipaddress.ip_address(normalized)
    except ValueError:
        literal = None

    if literal is not None:
        if not is_public_ip(str(literal)):
            raise PrivateNetworkError("Local or private network URLs cannot be scanned.")
        return [str(literal)]

    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as error:
        raise PrivateNetworkError("The domain could not be resolved safely.") from error

    if not addresses:
        raise PrivateNetworkError("The domain could not be resolved safely.")
    if any(not is_public_ip(address) for address in addresses):
        raise PrivateNetworkError("Local or private network URLs cannot be scanned.")
    return sorted(addresses)
