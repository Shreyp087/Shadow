from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address


IPAddress = IPv4Address | IPv6Address


def parse_ip_literal(hostname: str) -> IPAddress | None:
    normalized_hostname = hostname.strip().removeprefix("[").removesuffix("]")
    try:
        return ip_address(normalized_hostname)
    except ValueError:
        return None


def require_global_ip_address(address: str | IPAddress) -> None:
    parsed_address = ip_address(address) if isinstance(address, str) else address
    if not parsed_address.is_global or parsed_address.is_multicast:
        raise ValueError(
            f"Target endpoint resolves to a private or non-global IP address: {parsed_address}"
        )
