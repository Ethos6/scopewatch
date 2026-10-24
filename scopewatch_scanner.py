"""Bounded passive checks for one explicitly authorized website."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

USER_AGENT = "ScopeWatch/0.1 (+passive defensive assessment)"
MAX_BODY_BYTES = 64 * 1024
CHECK_PATHS = ("/", "/robots.txt", "/.well-known/security.txt", "/security.txt")


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    status: str
    detail: str
    recommendation: str = ""


@dataclass
class ScanResult:
    target: str
    scanned_at: str
    resolved_ip: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    requests_made: int = 0

    def to_dict(self) -> dict:
        data = asdict(self)
        data["findings"] = [asdict(item) for item in self.findings]
        return data


def normalize_target(raw: str) -> tuple[str, str, int, str]:
    candidate = raw.strip()
    if "://" not in candidate:
        candidate = "https://" + candidate
    parts = urlsplit(candidate)
    if parts.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// targets are supported.")
    if not parts.hostname or parts.username or parts.password:
        raise ValueError("Provide a hostname without embedded credentials.")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("Provide only an origin (scheme and hostname), without a path or query.")
    host = parts.hostname.rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("The hostname is not valid IDNA.") from exc
    port = parts.port or (443 if parts.scheme == "https" else 80)
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if parts.scheme == "https" else 80
    return parts.scheme, host, port, f"{parts.scheme}://{display_host}" + (f":{port}" if port != default_port else "")


def resolve_public_address(host: str, port: int, allow_private: bool) -> str:
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ValueError(f"DNS lookup failed: {exc}") from exc
        addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise ValueError("The hostname did not resolve to an address.")
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if not allow_private and (not parsed.is_global or parsed.is_multicast or parsed.is_unspecified):
            raise ValueError(f"Resolved address {address} is not public. Use --allow-private only for an authorized lab target.")
    return addresses[0]


def _request(ip: str, host: str, scheme: str, port: int, path: str, timeout: float) -> tuple[int, dict[str, str], bytes, dict | None]:
    raw = socket.create_connection((ip, port), timeout=timeout)
    conn = None
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            wrapped = context.wrap_socket(raw, server_hostname=host)
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
            conn.sock = wrapped
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.sock = raw
        host_header = f"[{host}]" if ":" in host else host
        if port not in (80, 443):
            host_header = f"{host_header}:{port}"
        conn.request("GET", path, headers={"Host": host_header, "User-Agent": USER_AGENT, "Accept": "text/html,text/plain;q=0.9,*/*;q=0.5", "Connection": "close"})
        response = conn.getresponse()
        body = response.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]
        cert = None
        if scheme == "https" and conn.sock:
            cert = conn.sock.getpeercert()
        headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, headers, body, cert
    finally:
        if conn is not None:
            conn.close()
        else:
            raw.close()


def _finding(fid: str, title: str, severity: str, status: str, detail: str, recommendation: str = "") -> Finding:
    return Finding(fid, title, severity, status, detail, recommendation)


def scan(raw_target: str, timeout: float = 5.0, allow_private: bool = False) -> ScanResult:
    scheme, host, port, target = normalize_target(raw_target)
    address = resolve_public_address(host, port, allow_private)
    result = ScanResult(target=target, scanned_at=datetime.now(timezone.utc).isoformat(), resolved_ip=address)
    responses: dict[str, tuple[int, dict[str, str], bytes, dict | None]] = {}
    for path in CHECK_PATHS:
        try:
            responses[path] = _request(address, host, scheme, port, path, timeout)
            result.requests_made += 1
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
            result.errors.append(f"{path}: {type(exc).__name__}: {exc}")

    home = responses.get("/")
    if not home:
        result.findings.append(_finding("site-unreachable", "Website response", "info", "unknown", "The homepage could not be read."))
        return result
    status, headers, body, cert = home
    result.findings.append(_finding("http-response", "Homepage response", "info", "observed", f"Received HTTP {status}."))

    if scheme == "http":
        result.findings.append(_finding("https", "HTTPS transport", "high", "missing", "The target was requested over plain HTTP.", "Serve the site over HTTPS and redirect HTTP to HTTPS."))
    else:
        result.findings.append(_finding("https", "HTTPS transport", "info", "present", "The homepage was reached over HTTPS."))
        if cert:
            expires = cert.get("notAfter")
            if expires:
                try:
                    expiry = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    state = "expired" if days_left < 0 else "expiring" if days_left <= 30 else "valid"
                    severity = "high" if days_left < 0 else "medium" if days_left <= 30 else "info"
                    recommendation = "Renew the certificate and verify automated renewal." if days_left <= 30 else ""
                    result.findings.append(_finding("certificate-expiry", "TLS certificate expiry", severity, state, f"Certificate expires in {days_left} day(s).", recommendation))
                except ValueError:
                    result.errors.append(f"certificate: unrecognized expiry date {expires!r}")
        if "strict-transport-security" not in headers:
            result.findings.append(_finding("hsts", "HTTP Strict Transport Security", "medium", "missing", "The homepage response did not include HSTS.", "After confirming HTTPS works for all subdomains, add a suitable Strict-Transport-Security policy."))

    checks = [
        ("content-security-policy", "Content Security Policy", "medium", "Add a policy suited to the site's scripts, styles, and embedded content."),
        ("x-content-type-options", "MIME sniffing protection", "low", "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Referrer policy", "low", "Set a Referrer-Policy that limits cross-site referrer details."),
        ("permissions-policy", "Browser permissions policy", "low", "Set a Permissions-Policy for browser features the site does not use."),
    ]
    for header, title, severity, recommendation in checks:
        present = header in headers
        result.findings.append(_finding(header, title, severity if not present else "info", "present" if present else "missing", f"{header} is {'present' if present else 'absent'} on the homepage response.", "" if present else recommendation))
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
        result.findings.append(_finding("clickjacking", "Framing restriction", "medium", "missing", "No X-Frame-Options or CSP frame-ancestors directive was observed.", "Restrict framing with CSP frame-ancestors or X-Frame-Options where appropriate."))

    cookies = headers.get("set-cookie", "")
    if cookies:
        low = cookies.lower()
        missing = [name for name, token in (("Secure", "; secure"), ("HttpOnly", "; httponly"), ("SameSite", "samesite=")) if token not in low]
        result.findings.append(_finding("cookie-flags", "Cookie security attributes", "medium" if missing else "info", "review" if missing else "present", "Missing attributes: " + ", ".join(missing) + "." if missing else "Observed Set-Cookie values include Secure, HttpOnly, and SameSite attributes.", "Set appropriate Secure, HttpOnly, and SameSite attributes on session cookies." if missing else ""))

    robots = responses.get("/robots.txt")
    result.findings.append(_finding("robots-txt", "robots.txt", "info", "present" if robots and robots[0] == 200 else "absent", "robots.txt returned HTTP 200." if robots and robots[0] == 200 else "No successful robots.txt response was observed."))
    security_candidates = (responses.get("/.well-known/security.txt"), responses.get("/security.txt"))
    security_found = any(response and response[0] == 200 for response in security_candidates)
    result.findings.append(_finding("security-txt", "security.txt", "info", "present" if security_found else "absent", "A security.txt location returned HTTP 200." if security_found else "No successful security.txt response was observed.", "Consider publishing a security.txt with a monitored vulnerability-reporting contact." if not security_found else ""))

    content_sample = (headers.get("x-powered-by", "") + " " + headers.get("server", "") + " " + body[:MAX_BODY_BYTES].decode("utf-8", "ignore")).lower()
    cms = next((name for token, name in (("wp-content", "WordPress"), ("/sites/default/", "Drupal"), ("joomla", "Joomla"), ("shopify", "Shopify"), ("wix.com", "Wix"), ("squarespace", "Squarespace")) if token in content_sample), None)
    result.findings.append(_finding("platform-hint", "Public platform hint", "info", "detected" if cms else "unknown", f"The limited homepage response contains a hint for {cms}." if cms else "No supported platform hint was found in the limited homepage response."))
    result.findings.append(_finding("scope-note", "Assessment scope", "info", "bounded", f"Read-only GET requests were limited to {len(CHECK_PATHS)} fixed paths; no links were followed."))
    return result

