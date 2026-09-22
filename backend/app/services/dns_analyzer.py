import dns.exception
import dns.resolver


def _query(resolver: dns.resolver.Resolver, domain: str, record_type: str) -> list[str]:
    try:
        return [str(answer) for answer in resolver.resolve(domain, record_type)]
    except (dns.exception.DNSException, OSError):
        return []


def analyze_dns(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 4
    ip_addresses = _query(resolver, domain, "A")
    ipv6_addresses = _query(resolver, domain, "AAAA")
    mx_records = _query(resolver, domain, "MX")
    name_servers = _query(resolver, domain, "NS")
    return {
        "dns_resolves": bool(ip_addresses or ipv6_addresses),
        "ip_addresses": ip_addresses,
        "ipv6_addresses": ipv6_addresses,
        "mx_records": mx_records,
        "name_servers": name_servers,
    }
