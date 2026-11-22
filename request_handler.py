import hmac
import html
import ipaddress
import json
import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.utils import formatdate
from functools import lru_cache
from http.server import BaseHTTPRequestHandler
from typing import Any
from urllib.parse import parse_qs, urlparse

SERVER_VERSION = "BannerServer"
# All CSS/JS is inline and self-contained (no external fetches), so a
# restrictive policy is possible. 'unsafe-inline' is still required for
# the inline <style>/<script> blocks; everything else is locked down.
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    (
        "Content-Security-Policy",
        (
            "default-src 'none'; "
            "img-src 'self' data:; "
            "style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; "
            "base-uri 'none'; "
            "form-action 'none'; "
            "frame-ancestors 'none'"
        ),
    ),
)
NO_STORE_HEADERS: tuple[tuple[str, str], ...] = (
    ("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"),
    ("Pragma", "no-cache"),
    ("Expires", "0"),
)

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
_TEMPLATE_TOKEN_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_PORT_RE = re.compile(r"^[1-9][0-9]{0,4}\Z")
_BRACKETED_IPV6_RE = re.compile(r"^\[([^\]]+)\](?::([0-9]+))?\Z")
_LOG_CONTROL_ESCAPES = {
    "\r": "\\r",
    "\n": "\\n",
    "\t": "\\t",
    "\u2028": "\\u2028",
    "\u2029": "\\u2029",
}


def sanitize_for_log(value: object) -> str:
    """Escape CR/LF, control chars (0x00-0x1f, 0x7f), and Unicode line separators."""
    text = value if isinstance(value, str) else str(value)
    out: list[str] = []
    for ch in text:
        escaped = _LOG_CONTROL_ESCAPES.get(ch)
        if escaped is not None:
            out.append(escaped)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def _is_valid_port(port_str: str) -> bool:
    return bool(_PORT_RE.match(port_str)) and 1 <= int(port_str) <= 65535


def _is_valid_host_port(value: str) -> bool:
    """Validate an RFC 1123 hostname, IPv4 literal, or bracketed IPv6 literal with optional :port."""
    if not isinstance(value, str) or not value:
        return False
    if not value.isascii() or any(
        ord(ch) < 32 or ord(ch) == 127 or ch.isspace() for ch in value
    ):
        return False

    if value.startswith("["):
        match = _BRACKETED_IPV6_RE.match(value)
        if not match:
            return False
        ipv6_str, port_str = match.groups()
        if "%" in ipv6_str:
            return False
        try:
            ipaddress.IPv6Address(ipv6_str)
        except ValueError:
            return False
        return port_str is None or _is_valid_port(port_str)

    if value.count(":") > 1:
        return False
    if ":" in value:
        host, port_str = value.split(":", 1)
        if not _is_valid_port(port_str):
            return False
    else:
        host = value

    if not host or len(host) > 253:
        return False

    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        pass

    labels = host.split(".")
    if any(not _HOST_LABEL_RE.match(label) for label in labels):
        return False
    return not labels[-1].isdigit()


def is_valid_dashboard_url(url: str) -> bool:
    """Return True if url is a safe https:// URL without userinfo, whitespace, or control chars."""
    if not isinstance(url, str) or not url:
        return False
    if any(ord(ch) < 32 or ord(ch) == 127 or ch.isspace() for ch in url):
        return False
    if not url.startswith("https://"):
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.netloc:
        return False
    if (
        "@" in parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    return _is_valid_host_port(parsed.netloc)


def _format_retention(minutes: int) -> str:
    if minutes >= 1440 and minutes % 1440 == 0:
        days = minutes // 1440
        return f"{days} day" if days == 1 else f"{days} days"
    if minutes >= 60 and minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"


_EXTERNAL_LINK_ICON = (
    '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>'
    '<polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>'
)
_HOME_ICON = (
    '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'
    '<polyline points="9 22 9 12 15 12 15 22"/>'
)
_BOOKMARK_ICON = '<path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/>'
_ARROW_SVG_INNER = (
    '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>'
)


@lru_cache(maxsize=16)
def _read_template_file(template_dir: str, name: str) -> str:
    """Read and cache raw template or CSS fragments keyed by (template_dir, name)."""
    with open(os.path.join(template_dir, name), encoding="utf-8") as f:
        return f.read()


def _load_template(name: str, tokens: dict[str, str]) -> str:
    content = _read_template_file(_TEMPLATE_DIR, name)
    if "{{BASE_CSS}}" in content and "BASE_CSS" not in tokens:
        render_tokens = {
            **tokens,
            "BASE_CSS": _read_template_file(_TEMPLATE_DIR, "_base.css"),
        }
    else:
        render_tokens = tokens
    return _TEMPLATE_TOKEN_RE.sub(
        lambda m: render_tokens.get(m.group(1), m.group(0)),
        content,
    )


def _render_action_row(
    *,
    tag: str,
    css_class: str,
    icon_paths: str,
    label: str,
    subtitle: str,
    href: str | None = None,
    onclick: str | None = None,
    style: str = "",
    accent_icon: bool = False,
    label_style: str = "",
    subtitle_style: str = "",
    indent: str = "      ",
) -> str:
    """Render an access-link anchor or action button with consistent markup."""
    attrs = [f'class="{html.escape(css_class, quote=True)}"']
    if href is not None:
        attrs.append(f'href="{html.escape(href, quote=True)}"')
        attrs.append('target="_blank" rel="noopener noreferrer"')
    if onclick is not None:
        attrs.append(f'onclick="{html.escape(onclick, quote=True)}"')
    if style:
        attrs.append(f'style="{html.escape(style, quote=True)}"')

    icon_style = (
        "flex-shrink:0; color: var(--accent);" if accent_icon else "flex-shrink:0;"
    )
    arrow_style = ' style="color: var(--accent);"' if accent_icon else ""
    label_attr = f' style="{label_style}"' if label_style else ""
    subtitle_attr = f' style="{subtitle_style}"' if subtitle_style else ""

    return (
        f"{indent}<{tag} {' '.join(attrs)}>\n"
        f'{indent}  <span class="access-link-left">\n'
        f'{indent}    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="2" style="{icon_style}">'
        f"{icon_paths}</svg>\n"
        f'{indent}    <span class="access-link-text">\n'
        f'{indent}      <span class="access-link-label"{label_attr}>{html.escape(label)}</span>\n'
        f'{indent}      <span class="access-link-url"{subtitle_attr}>{html.escape(subtitle)}</span>\n'
        f"{indent}    </span>\n"
        f"{indent}  </span>\n"
        f'{indent}  <svg class="access-link-arrow" width="14" height="14" viewBox="0 0 24 24" '
        f'fill="none" stroke="currentColor" stroke-width="2"{arrow_style}>'
        f"{_ARROW_SVG_INNER}</svg>\n"
        f"{indent}</{tag}>"
    )


def _render_resource_rows(resources: list, overall_ok: bool) -> str:
    if not (overall_ok and resources):
        return ""
    rows = []
    for r in resources:
        name = r.get("name", "Resource")
        domain = r.get("fullDomain", "")
        ssl = r.get("ssl", True)
        if not domain:
            continue
        if not isinstance(domain, str) or not _is_valid_host_port(domain):
            print(
                "[warn] Skipping resource with invalid fullDomain: "
                f"{sanitize_for_log(domain)!r}"
            )
            continue
        protocol = "https" if ssl else "http"
        raw_url = f"{protocol}://{domain}"
        rows.append(
            _render_action_row(
                tag="a",
                css_class="access-link",
                href=raw_url,
                icon_paths=_EXTERNAL_LINK_ICON,
                label=f"Open {name}",
                subtitle=raw_url,
            )
        )
    return "\n".join(rows)


def _build_checkin_html(
    ip: str,
    results: dict,
    retention_minutes: int,
    last_seen: str,
    crowdsec_enabled: bool,
    resources: list | None = None,
    site_name: str = "",
    dashboard_url: str = "",
    redirect_to_launcher: bool = False,
    redirect_delay_seconds: int = 3,
) -> str:
    try:
        seen_dt = datetime.fromisoformat(last_seen)
        expires_dt = seen_dt + timedelta(minutes=retention_minutes)
        expires_str = expires_dt.strftime(f"%B {expires_dt.day}, %Y at %H:%M")
        expires_iso = expires_dt.isoformat()
    except (ValueError, TypeError, AttributeError):
        expires_str = "unknown"
        expires_iso = "unknown"

    pangolin_ok = results.get("pangolin", {}).get("ok", False)
    pangolin_detail = results.get("pangolin", {}).get("detail", "unknown")
    crowdsec_ok = results.get("crowdsec", {}).get("ok", False)
    crowdsec_detail = results.get("crowdsec", {}).get("detail", "disabled")
    overall_ok = pangolin_ok
    success = pangolin_ok and (not crowdsec_enabled or crowdsec_ok)

    # Determine status presentation (success, warning, or error)
    if success:
        dot_class = "status-dot"
        if site_name:
            hero = f"Access granted to <strong>{html.escape(site_name)}</strong>."
        else:
            hero = "Your IP address has <strong>access</strong>."
        details_label = "Technical details"
        details_expanded = "false"
        details_open_class = ""
    elif pangolin_ok:
        dot_class = "status-dot warn"
        if site_name:
            hero = f"Access granted to <strong>{html.escape(site_name)}</strong>, but security rules failed."
        else:
            hero = "Access granted, but security rules failed."
        details_label = "What went wrong?"
        details_expanded = "true"
        details_open_class = "open"
    else:
        dot_class = "status-dot err"
        hero = "Access may not work right now."
        details_label = "What went wrong?"
        details_expanded = "true"
        details_open_class = "open"

    pangolin_badge = (
        '<span class="badge ok">Added</span>'
        if pangolin_ok
        else '<span class="badge err">Failed</span>'
    )

    if not crowdsec_enabled:
        crowdsec_badge = '<span class="badge skip">Not enabled</span>'
    elif crowdsec_ok:
        crowdsec_badge = '<span class="badge ok">Added</span>'
    else:
        crowdsec_badge = '<span class="badge err">Failed</span>'

    pangolin_detail_class = "ok" if pangolin_ok else "bad"
    if crowdsec_enabled:
        crowdsec_detail_class = "ok" if crowdsec_ok else "bad"
        crowdsec_detail_display = crowdsec_detail
    else:
        crowdsec_detail_class = "val"
        crowdsec_detail_display = "disabled"

    valid_dashboard_url = dashboard_url if is_valid_dashboard_url(dashboard_url) else ""
    if dashboard_url and not valid_dashboard_url:
        print(
            "[warn] Ignoring invalid dashboard_url: "
            f"{sanitize_for_log(dashboard_url)!r}"
        )

    # Only show individual allowed resources if not redirecting successfully
    show_individual_resources = not (
        redirect_to_launcher and success and bool(valid_dashboard_url)
    )
    resource_rows = ""
    if show_individual_resources:
        resource_rows = _render_resource_rows(resources or [], overall_ok)

    # Build the redirection banner if redirecting on success
    redirect_banner_html = ""
    if (
        success
        and redirect_to_launcher
        and valid_dashboard_url
        and isinstance(redirect_delay_seconds, int)
        and not isinstance(redirect_delay_seconds, bool)
        and redirect_delay_seconds > 0
    ):
        safe_url = html.escape(valid_dashboard_url, quote=True)
        safe_delay = html.escape(str(redirect_delay_seconds), quote=True)
        redirect_banner_html = (
            f'      <div class="redirect-banner" data-redirect-url="{safe_url}" data-redirect-delay="{safe_delay}" style="background: var(--accent-hover-bg); border: 1px solid var(--accent); padding: 12px 16px; border-radius: calc(var(--radius) - 2px); margin-bottom: 12px; font-size: 13px; text-align: center; color: var(--text);">\n'
            f'        Redirecting to Resource Launcher in <strong id="countdown">{safe_delay}</strong> seconds...\n'
            "      </div>"
        )

    # Build the central launcher button if valid_dashboard_url is set, redirection is enabled, and overall_ok is True
    launcher_row = ""
    if overall_ok and valid_dashboard_url and redirect_to_launcher:
        launcher_row = _render_action_row(
            tag="a",
            css_class="access-link launcher-link",
            href=valid_dashboard_url,
            style="border-color: var(--accent); background: var(--accent-hover-bg); margin-bottom: 8px;",
            icon_paths=_HOME_ICON,
            accent_icon=True,
            label="Open Resource Launcher",
            label_style="font-weight:600;",
            subtitle=valid_dashboard_url,
            subtitle_style="color: var(--text); opacity: 0.85;",
        )

    # Combine launcher row and resource rows
    combined_rows = []
    if redirect_banner_html:
        combined_rows.append(redirect_banner_html)
    if launcher_row:
        combined_rows.append(launcher_row)
    if resource_rows:
        combined_rows.append(resource_rows)

    combined_html = "\n".join(combined_rows)

    bookmark_html = (
        _render_action_row(
            tag="button",
            css_class="bookmark-btn",
            onclick="bookmarkPage()",
            icon_paths=_BOOKMARK_ICON,
            label="Bookmark this page",
            subtitle="Save for one-tap access next time",
            indent="  ",
        )
        if overall_ok
        else ""
    )

    if combined_html:
        actions_section = (
            '    <div class="action-list">\n' + combined_html + "\n    </div>\n"
            '    <hr class="section-divider">'
        )
    else:
        actions_section = ""

    site_name_sub = (
        f'      <div class="sub">{html.escape(site_name)}</div>\n' if site_name else ""
    )

    safe_ip = html.escape(str(ip))

    return _load_template(
        "checkin.html",
        {
            "DOT_CLASS": dot_class,
            "SITE_NAME_SUB": site_name_sub,
            "HERO": hero,
            "IP": safe_ip,
            "PANGOLIN_BADGE": pangolin_badge,
            "CROWDSEC_BADGE": crowdsec_badge,
            "ACTIONS_SECTION": actions_section,
            "BOOKMARK_SECTION": bookmark_html,
            "EXPIRY_STR": expires_str,
            "RETENTION_LABEL": _format_retention(retention_minutes),
            "RETENTION_MINUTES": str(retention_minutes),
            "DETAILS_LABEL": details_label,
            "DETAILS_EXPANDED": details_expanded,
            "DETAILS_OPEN_CLASS": details_open_class,
            "PANGOLIN_DETAIL_CLASS": pangolin_detail_class,
            "PANGOLIN_DETAIL": html.escape(str(pangolin_detail)),
            "CROWDSEC_DETAIL_CLASS": crowdsec_detail_class,
            "CROWDSEC_DETAIL": html.escape(str(crowdsec_detail_display)),
            "EXPIRES_ISO": expires_iso,
            "LAST_SEEN": last_seen,
        },
    )


def _build_error_html(title: str, message: str, site_name: str = "") -> str:
    site_name_sub = (
        f'      <div class="sub">{html.escape(site_name)}</div>\n' if site_name else ""
    )
    site_name_footer = (
        f"{html.escape(site_name)} &nbsp;&middot;&nbsp; " if site_name else ""
    )
    return _load_template(
        "error.html",
        {
            "ERROR_TITLE": title,
            "ERROR_MESSAGE": message,
            "SITE_NAME_SUB": site_name_sub,
            "SITE_NAME_FOOTER": site_name_footer,
        },
    )


def build_plain_http_response(
    status: int,
    reason: str,
    body: str,
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> bytes:
    """Serialize a self-contained plain-text HTTP/1.1 response."""
    encoded = body.encode("utf-8")
    headers = [
        ("Server", SERVER_VERSION),
        ("Date", formatdate(usegmt=True)),
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Content-Length", str(len(encoded))),
        *NO_STORE_HEADERS,
        *SECURITY_HEADERS,
        *extra_headers,
    ]
    header_lines = "".join(f"{name}: {value}\r\n" for name, value in headers)
    head = f"HTTP/1.1 {status} {reason}\r\n{header_lines}\r\n".encode("latin-1")
    return head + encoded


@dataclass
class RequestHandlerContext:
    """Typed runtime dependencies injected into ImageRequestHandler."""

    update_enabled: bool
    retention_minutes: int
    crowdsec_enabled: bool
    site_name: str
    proxy_shared_secret: str
    state: dict[str, Any]
    state_lock: threading.Lock
    now_utc_iso: Callable[[], str]
    save_state: Callable[[], None]
    add_ip_to_targets: Callable[..., dict[str, Any]]
    banner_png: bytes
    banner_gif: bytes
    redact_headers_for_log: Callable[[Any], Any]
    debug_log_headers: bool = False
    redirect_to_launcher: bool = False
    redirect_delay_seconds: int = 3
    pangolin_dashboard_url: str = ""


def create_image_request_handler(ctx: RequestHandlerContext):
    """Return an ImageRequestHandler class bound to the provided RequestHandlerContext."""

    class ImageRequestHandler(BaseHTTPRequestHandler):
        server_version = SERVER_VERSION
        sys_version = ""
        timeout = 10

        def version_string(self) -> str:
            return f"{self.server_version} {self.sys_version}".strip()

        def log_message(self, fmt, *args):
            message = fmt % args if args else str(fmt)
            print(
                "[http]",
                sanitize_for_log(self.address_string()),
                "-",
                sanitize_for_log(message),
            )

        def _get_real_ip(self) -> str:
            # precedence: X-Real-IP, X-Forwarded-For (first), fallback to client addr
            # Each candidate is validated: must be a parseable, globally-routable IP.
            # Non-global addresses (loopback, private, link-local, multicast) are
            # rejected and the next candidate is tried. Falls back to socket address
            # (not validated, as it is controlled by the OS/kernel, not the caller).
            def _parse_global_ip(raw: str) -> str | None:
                try:
                    ip_obj = ipaddress.ip_address(raw.strip())
                    if not ip_obj.is_global:
                        print(
                            "[warn] Rejected non-global IP from header: "
                            f"{sanitize_for_log(raw.strip())!r}"
                        )
                        return None
                    return str(ip_obj)
                except ValueError:
                    print(
                        "[warn] Rejected unparseable IP from header: "
                        f"{sanitize_for_log(raw.strip())!r}"
                    )
                    return None

            xr = self.headers.get("X-Real-IP")
            if xr:
                parsed = _parse_global_ip(xr)
                if parsed:
                    return parsed

            xff = self.headers.get("X-Forwarded-For")
            if xff:
                parsed = _parse_global_ip(xff.split(",")[0])
                if parsed:
                    return parsed

            return self.client_address[0]

        def _wants_html(self) -> bool:
            accept = self.headers.get("Accept", "")
            return "text/html" in accept

        def _proxy_secret_ok(self) -> bool:
            """Require the Pangolin-injected X-Proxy-Secret value."""
            expected = ctx.proxy_shared_secret
            if not expected:
                return False
            values = self.headers.get_all("X-Proxy-Secret", []) or []
            if len(values) != 1:
                return False
            provided = values[0]
            return hmac.compare_digest(provided, expected)

        def _get_identity_header(self, name: str) -> str:
            """Return one canonical identity header value or an empty string.

            Duplicate, blank, whitespace-padded, and excessively long values are
            rejected so intermediaries cannot choose a different identity value.
            """
            values = self.headers.get_all(name, []) or []
            if len(values) != 1:
                if values:
                    print(
                        f"[error] Rejected duplicate {sanitize_for_log(name)} headers"
                    )
                return ""
            value = values[0]
            if not value or value != value.strip() or len(value) > 512:
                print(f"[error] Rejected invalid {sanitize_for_log(name)} header")
                return ""
            return value

        def _send_security_headers(self) -> None:
            for name, value in SECURITY_HEADERS:
                self.send_header(name, value)

        def _send_no_store_and_security_headers(self) -> None:
            for name, value in NO_STORE_HEADERS:
                self.send_header(name, value)
            self._send_security_headers()

        def _send_bytes(
            self,
            status: int,
            content_type: str,
            payload: bytes,
            extra_headers: tuple[tuple[str, str], ...] = (),
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self._send_no_store_and_security_headers()
            for name, value in extra_headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(payload)

        def _send_plain(
            self,
            status: int,
            body: str,
            extra_headers: tuple[tuple[str, str], ...] = (),
        ) -> None:
            self._send_bytes(
                status,
                "text/plain; charset=utf-8",
                body.encode("utf-8"),
                extra_headers=extra_headers,
            )

        def _send_html(self, status: int, body: str) -> None:
            self._send_bytes(status, "text/html; charset=utf-8", body.encode("utf-8"))

        def _send_json(self, status: int, body: dict) -> None:
            self._send_bytes(
                status,
                "application/json; charset=utf-8",
                json.dumps(body).encode("utf-8"),
            )

        def _try_immediate_redirect(self, success: bool) -> bool:
            redirect_enabled = ctx.redirect_to_launcher
            redirect_delay = ctx.redirect_delay_seconds
            dashboard_url = ctx.pangolin_dashboard_url
            if (
                redirect_enabled
                and success
                and dashboard_url
                and not isinstance(redirect_delay, bool)
                and redirect_delay == 0
            ):
                if not is_valid_dashboard_url(dashboard_url):
                    print(
                        "[warn] Refusing 302 redirect to invalid dashboard_url: "
                        f"{sanitize_for_log(dashboard_url)!r}"
                    )
                    return False
                self.send_response(302)
                self.send_header("Location", dashboard_url)
                self._send_no_store_and_security_headers()
                self.end_headers()
                return True
            return False

        def _perform_checkin(
            self,
            target_ip: str,
            remote_user_id: str,
            remote_user: str,
        ) -> tuple[str, dict[str, Any]]:
            # Record last_seen before auth/targets so rejected requests stay audited
            # with an empty resources mapping.
            now_iso = ctx.now_utc_iso()
            with ctx.state_lock:
                rec = ctx.state.setdefault(
                    target_ip, {"last_seen": now_iso, "resources": {}}
                )
                rec["last_seen"] = now_iso
            ctx.save_state()

            try:
                results = ctx.add_ip_to_targets(
                    target_ip,
                    remote_user_id=remote_user_id,
                    remote_user=remote_user,
                )
            except Exception as e:  # noqa: BLE001
                print(
                    "[error] add_ip_to_targets failed for "
                    f"{sanitize_for_log(target_ip)}: {sanitize_for_log(e)}"
                )
                results = {
                    "error_kind": "upstream",
                    "pangolin": {"ok": False, "detail": str(e), "enabled": True},
                    "crowdsec": {
                        "ok": False,
                        "detail": "not reached",
                        "enabled": ctx.crowdsec_enabled,
                    },
                }
            return now_iso, results

        def _send_checkin_html_or_redirect(
            self,
            target_ip: str,
            now_iso: str,
            results: dict[str, Any],
        ) -> None:
            pangolin_ok = results.get("pangolin", {}).get("ok", False)
            crowdsec_ok = results.get("crowdsec", {}).get("ok", False)
            success = pangolin_ok and (not ctx.crowdsec_enabled or crowdsec_ok)

            if self._try_immediate_redirect(success):
                return

            self._send_html(
                200,
                _build_checkin_html(
                    ip=target_ip,
                    results=results,
                    retention_minutes=ctx.retention_minutes,
                    last_seen=now_iso,
                    crowdsec_enabled=ctx.crowdsec_enabled,
                    resources=results.get("resources", []),
                    site_name=ctx.site_name,
                    dashboard_url=ctx.pangolin_dashboard_url,
                    redirect_to_launcher=ctx.redirect_to_launcher,
                    redirect_delay_seconds=ctx.redirect_delay_seconds,
                ),
            )

        def do_GET(self):
            parsed_path = urlparse(self.path)
            path = parsed_path.path or "/"

            # Liveness probe — intentionally before the proxy-secret gate so container
            # health checks work regardless of PROXY_SHARED_SECRET. Touches no state and
            # makes no upstream calls.
            if path == "/healthz":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", "2")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(b"ok")
                return

            # Browsers request /favicon.ico automatically after loading the check-in
            # page. Answer with an empty 204 before the .png/.gif routing so it does
            # not land in the invalid-path error branch and pollute the logs. Touches
            # no state and makes no upstream calls.
            if path.lower() == "/favicon.ico":
                self.send_response(204)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                return

            # Defense-in-depth: reject anything that did not transit the proxy before
            # touching state or the Pangolin/CrowdSec APIs. Bare 403, no body detail.
            if not self._proxy_secret_ok():
                self._send_plain(403, "Forbidden")
                print(
                    "[error] Rejected request with missing/invalid X-Proxy-Secret: "
                    f"{sanitize_for_log(self.path)}"
                )
                return

            ip = self._get_real_ip()
            remote_user_id = self._get_identity_header("Remote-User-Id")
            remote_user = self._get_identity_header("Remote-User")

            print(
                f"New request from {sanitize_for_log(ip)}  "
                f"user_id: {sanitize_for_log(remote_user_id)} "
                f"user: {sanitize_for_log(remote_user)}  "
                f"path: {sanitize_for_log(path)}"
            )

            if ctx.debug_log_headers and ctx.redact_headers_for_log:
                print(
                    "[http] headers:", ctx.redact_headers_for_log(self.headers.items())
                )

            lower_path = path.lower()

            # /update?ip=1.2.3.4 endpoint (guarded by UPDATE_ENDPOINT_ENABLED)
            if lower_path == "/update":
                if not ctx.update_enabled:
                    # Intentionally bare — do not reveal the endpoint exists
                    self._send_plain(404, "Not found")
                    print(
                        f"[error] Update endpoint disabled: {sanitize_for_log(self.path)}"
                    )
                    return

                qs = parse_qs(parsed_path.query or "")
                raw_ip = (qs.get("ip", [""])[0] or "").strip()
                if not raw_ip:
                    print(
                        "[error] Missing 'ip' query parameter: "
                        f"{sanitize_for_log(self.path)}"
                    )
                    if self._wants_html():
                        self._send_html(
                            400,
                            _build_error_html(
                                "Bad request",
                                "Missing required <code>ip</code> query parameter. "
                                "Expected format: /update?ip=1.2.3.4",
                                site_name=ctx.site_name,
                            ),
                        )
                    else:
                        self._send_json(
                            400,
                            {
                                "ok": False,
                                "error": "Missing required 'ip' query parameter.",
                            },
                        )
                    return

                try:
                    normalized_ip = str(ipaddress.ip_address(raw_ip))
                except ValueError:
                    print(f"[error] Invalid IP address: {sanitize_for_log(raw_ip)}")
                    if self._wants_html():
                        self._send_html(
                            400,
                            _build_error_html(
                                "Bad request",
                                f"&#39;{html.escape(raw_ip)}&#39; is not a valid IP address.",
                                site_name=ctx.site_name,
                            ),
                        )
                    else:
                        self._send_json(
                            400,
                            {"ok": False, "error": "Invalid IP address."},
                        )
                    return

                if not ipaddress.ip_address(normalized_ip).is_global:
                    print(
                        "[error] Rejected non-global IP in /update: "
                        f"{sanitize_for_log(normalized_ip)!r}"
                    )
                    if self._wants_html():
                        self._send_html(
                            400,
                            _build_error_html(
                                "Bad request",
                                f"&#39;{html.escape(normalized_ip)}&#39; is a non-routable IP address and cannot be allowlisted.",
                                site_name=ctx.site_name,
                            ),
                        )
                    else:
                        self._send_json(
                            400,
                            {
                                "ok": False,
                                "error": "Non-routable IP address cannot be allowlisted.",
                            },
                        )
                    return

                now_iso, update_results = self._perform_checkin(
                    normalized_ip, remote_user_id, remote_user
                )

                if self._wants_html():
                    self._send_checkin_html_or_redirect(
                        normalized_ip, now_iso, update_results
                    )
                else:
                    pangolin_res = update_results.get("pangolin", {})
                    crowdsec_res = update_results.get("crowdsec", {})
                    pangolin_ok = bool(pangolin_res.get("ok", False))
                    if pangolin_ok:
                        crowdsec_enabled = bool(
                            crowdsec_res.get("enabled", ctx.crowdsec_enabled)
                        )
                        crowdsec_ok = bool(crowdsec_res.get("ok", False))
                        self._send_json(
                            200,
                            {
                                "ok": True,
                                "ip": normalized_ip,
                                "retention_minutes": ctx.retention_minutes,
                                "pangolin": {"ok": True},
                                "crowdsec": {
                                    "ok": crowdsec_ok,
                                    "enabled": crowdsec_enabled,
                                },
                            },
                        )
                    else:
                        error_kind = update_results.get("error_kind")
                        if error_kind == "auth":
                            status = 403
                            error_msg = "Access denied"
                        else:
                            status = 502
                            error_msg = "Upstream target failure"
                        self._send_json(
                            status,
                            {
                                "ok": False,
                                "ip": normalized_ip,
                                "error": error_msg,
                            },
                        )
                return

            # Forbid root path
            if path == "/":
                self._send_plain(403, "Forbidden")
                print(f"[error] Root path forbidden: {sanitize_for_log(self.path)}")
                return

            # Only handle .png and .gif paths
            is_png = lower_path.endswith(".png")
            is_gif = lower_path.endswith(".gif")
            if not (is_png or is_gif):
                print(
                    "[error] Invalid path (not .png/.gif): "
                    f"{sanitize_for_log(self.path)}"
                )
                if self._wants_html():
                    self._send_html(
                        404,
                        _build_error_html(
                            "Page not found",
                            "This URL isn&#39;t a valid check-in path. "
                            "Make sure you&#39;re using the correct link ending in .png or .gif.",
                            site_name=ctx.site_name,
                        ),
                    )
                else:
                    self._send_plain(404, "Not found")
                return

            now_iso, results = self._perform_checkin(ip, remote_user_id, remote_user)

            # Browser gets the HTML page; everything else gets the transparent image
            if self._wants_html():
                self._send_checkin_html_or_redirect(ip, now_iso, results)
            else:
                body = ctx.banner_gif if is_gif else ctx.banner_png
                ctype = "image/gif" if is_gif else "image/png"
                self._send_bytes(200, ctype, body)

    return ImageRequestHandler
