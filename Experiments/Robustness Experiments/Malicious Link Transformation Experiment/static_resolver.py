"""
Static URL resolver (the "static detector" added to Evilog).

Decides whether a value is a suspected SSRF from
  (1) URL structure  : parse scheme / host with urllib
  (2) URL scheme     : dangerous schemes (gopher, dict, file, ftp, ldap)
  (3) destination    : normalize the host to a canonical IP (decimal, hex, octal,
                       IPv4-mapped IPv6, IP embedded in a hostname such as nip.io)
                       and block loopback / private / link-local / reserved ranges.

Purely static: it never resolves DNS or fetches the URL.
"""
import re
import ipaddress
from urllib.parse import urlsplit

SPECIAL_HOSTS = {"localhost": "127.0.0.1", "metadata.google.internal": "169.254.169.254"}
DANGER_SCHEMES = {"gopher", "dict", "file", "ftp", "ldap"}
_DOTTED = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def host_to_ip(host):
    """Normalize a hostname to an ip_address, or None if it is not an IP form."""
    if not host:
        return None
    h = SPECIAL_HOSTS.get(host.strip().lower(), host.strip().lower())
    m = _DOTTED.search(h)
    for cand in (h, m.group(1) if m else None):
        if not cand:
            continue
        try:
            return ipaddress.ip_address(cand)                 # dotted v4, v6, ::1, ::ffff:x
        except ValueError:
            pass
        if cand.isdigit():                                    # decimal: 2852039166
            try:
                return ipaddress.ip_address(int(cand))
            except ValueError:
                pass
        if cand.startswith("0x"):                             # hex: 0xA9FEA9FE
            try:
                return ipaddress.ip_address(int(cand, 16))
            except ValueError:
                pass
        parts = cand.split(".")
        if len(parts) == 4 and any(p[:1] == "0" and len(p) > 1 for p in parts):
            try:                                              # octal octets: 0177.0.0.1
                octets = [int(p, 8) if p[:1] == "0" and len(p) > 1 else int(p) for p in parts]
                if all(0 <= o <= 255 for o in octets):
                    return ipaddress.ip_address(".".join(map(str, octets)))
            except ValueError:
                pass
    return None


def is_internal(ip):
    if ip is None:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified


def explain(url):
    """Return (blocked: bool, reason: str)."""
    p = urlsplit(url)
    if p.scheme in DANGER_SCHEMES:
        return True, f"dangerous scheme '{p.scheme}'"
    ip = host_to_ip(p.hostname)
    if is_internal(ip):
        return True, f"internal destination {ip}"
    return False, "external or unresolvable host"


def is_ssrf(url):
    return explain(url)[0]
