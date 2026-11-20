"""Scope enforcement: the tool only touches targets the user is authorised to test.

Rule: a target is allowed if it is in the SAFE_DEFAULTS list, or it matches
something the user explicitly passed with --scope (IP, CIDR range or hostname).
The check runs BEFORE any network connection is made.
"""
import ipaddress
import socket

# Safe defaults required by the brief: localhost, 127.0.0.1, example.com, test ranges.
SAFE_DEFAULT_HOSTS = {"localhost", "127.0.0.1", "::1", "example.com"}
# RFC 5737 documentation ranges (reserved for testing, never real networks).
SAFE_DEFAULT_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


class ScopeError(Exception):
    """Raised when a target is outside the authorised scope."""


def parse_scope(scope_args):
    """Turn --scope strings into a list of ip_network objects and hostnames.

    Each entry can be a hostname ('db.lab.local'), an IP ('10.0.0.5')
    or a CIDR range ('10.0.0.0/24'). Bad entries raise ScopeError.
    """
    networks, hostnames = [], set()
    for entry in scope_args or []:
        entry = entry.strip().lower()
        if not entry:
            continue
        if entry in ("*", "0.0.0.0/0", "::/0"):
            raise ScopeError("Scope '%s' is too broad. Name the exact target or a small range." % entry)
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            if not all(c.isalnum() or c in ".-" for c in entry):
                raise ScopeError("Invalid scope entry: %r" % entry)
            hostnames.add(entry)
    return networks, hostnames


def _resolve(host):
    """Resolve a hostname to an IP so the network check can't be dodged with DNS names."""
    try:
        return ipaddress.ip_address(socket.gethostbyname(host))
    except (socket.gaierror, UnicodeError):
        return None


def is_in_scope(host, scope_args=None):
    """Return True if host is a safe default or covered by --scope."""
    host = host.strip().lower()
    networks, hostnames = parse_scope(scope_args)

    if host in SAFE_DEFAULT_HOSTS or host in hostnames:
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = _resolve(host)  # hostname: check where it actually points
        if ip is None:
            return False

    allowed = SAFE_DEFAULT_NETWORKS + networks
    return any(ip in net for net in allowed)


def enforce_scope(host, scope_args=None):
    """Raise ScopeError with a helpful message if host is out of scope."""
    if not is_in_scope(host, scope_args):
        raise ScopeError(
            "Target '%s' is NOT in the authorised scope.\n"
            "  Default scope: localhost, 127.0.0.1, example.com, test ranges.\n"
            "  If you have WRITTEN authorisation, add it explicitly, e.g. --scope %s"
            % (host, host)
        )
